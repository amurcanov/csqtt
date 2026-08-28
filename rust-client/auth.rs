// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    captcha::{CaptchaSolver, VkCaptchaError},
    dns,
    namegen::generate_name,
    profiles::{Profile, load_saved_profile, random_profile},
    vk_js_calls::{CredentialBroker, MAX_ACCOUNT_CREDENTIALS},
};
use anyhow::{Context, Result, bail};
use primp::{Client, Impersonate, ImpersonateOS, PseudoId, PseudoOrder, cookie::Jar, header};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

const VK_CONNECT_CLIENT_ID: &str = "8093730";
const VK_CALLS_API_HOST: &str = "api.vk.me";
const VK_CALLS_API_VERSION: &str = "5.276";

#[derive(Clone)]
struct VkCredentials {
    client_id: Arc<str>,
    client_secret: Arc<str>,
}

#[derive(Clone)]
pub struct TurnCredentials {
    pub username: Arc<str>,
    pub password: Arc<str>,
    pub server_addresses: Arc<[Arc<str>]>,
}

#[derive(Debug)]
pub struct CallUnavailable {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VkHashCheck {
    Valid,
    Invalid { code: i64, message: String },
    Unavailable { message: String },
}

impl std::fmt::Display for CallUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(
                formatter,
                "VK call is unavailable (error_code={})",
                self.code
            )
        } else {
            write!(
                formatter,
                "VK returns error: {} (error_code={})",
                self.message, self.code
            )
        }
    }
}

impl std::error::Error for CallUnavailable {}

pub struct VkAuth {
    mode: Arc<str>,
    auto_js: Option<Arc<CredentialBroker>>,
    profile: Profile,
    credentials: Arc<[VkCredentials]>,
    captcha: Arc<CaptchaSolver>,
    captcha_lockout_until: AtomicI64,
}

struct LegacyAttempt<'a> {
    client: &'a Client,
    captcha_client: &'a Client,
    profile: Profile,
    saved_profile: Option<&'a crate::profiles::SavedProfile>,
}

impl VkAuth {
    pub fn new(
        mode: &str,
        profile: Profile,
        client_ids: &[String],
        captcha: Arc<CaptchaSolver>,
        auto_js: Option<Arc<CredentialBroker>>,
    ) -> Self {
        let mode = if mode.eq_ignore_ascii_case("auto_js") {
            "auto_js"
        } else if mode.eq_ignore_ascii_case("legacy") {
            "legacy"
        } else {
            "vkcalls"
        };
        Self {
            mode: Arc::from(mode),
            auto_js,
            profile,
            credentials: load_credentials(client_ids).into(),
            captcha,
            captcha_lockout_until: AtomicI64::new(0),
        }
    }

    pub fn client_ids(&self) -> String {
        self.credentials
            .iter()
            .map(|value| value.client_id.as_ref())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub async fn get_credentials(&self, link: &str, stream_id: usize) -> Result<TurnCredentials> {
        if self.mode.as_ref() == "auto_js" {
            let credential_id = stream_id / 100;
            let auto_js_result = match self.auto_js.as_ref() {
                Some(broker) => broker.get_credentials(credential_id).await,
                None => Err(anyhow::anyhow!("Auto JS credential broker отсутствует")),
            };
            return match auto_js_result {
                Ok(credentials) => Ok(credentials),
                Err(auto_js_error) => {
                    crate::log_error!(
                        "[VK JS] Креды аккаунта {credential_id}/{MAX_ACCOUNT_CREDENTIALS} недоступны: {auto_js_error:#} · переход на Авто"
                    );
                    match self.vk_calls_with_retries(link, stream_id).await {
                        Ok(credentials) => {
                            crate::log_error!("[VK JS] Переход на Авто #{credential_id} выполнен");
                            Ok(credentials)
                        }
                        Err(auto_error) => {
                            crate::log_error!(
                                "[VK JS] Переход на Авто #{credential_id} не выполнен: {auto_error:#}"
                            );
                            Err(anyhow::anyhow!(
                                "Auto JS: {auto_js_error:#}; fallback Авто: {auto_error:#}"
                            ))
                        }
                    }
                }
            };
        }
        if unix_seconds() < self.captcha_lockout_until.load(Ordering::Acquire) {
            bail!("CAPTCHA_WAIT_REQUIRED: global lockout active");
        }
        if self.mode.as_ref() == "vkcalls" {
            match self.vk_calls_with_retries(link, stream_id).await {
                Ok(credentials) => return Ok(credentials),
                Err(error) if error.downcast_ref::<CallUnavailable>().is_some() => {
                    return Err(error);
                }
                Err(error) => crate::log_error!(
                    "[STREAM {stream_id}] [VK Auth] VK Calls path failed after 2 attempts ({error}), falling back to auto captcha"
                ),
            }
        } else {
            crate::log_error!(
                "[STREAM {stream_id}] [VK Auth] Legacy mode selected, skipping VK Calls path"
            );
        }
        let cookie_jar = Arc::new(Jar::default());
        let mut last_error = None;
        for attempt in 0..4 {
            let Some(credential) = self
                .credentials
                .get(attempt % self.credentials.len().max(1))
            else {
                break;
            };
            crate::log_error!(
                "[STREAM {stream_id}] [VK Auth] Trying credentials: client_id={} (attempt {}/4)",
                credential.client_id,
                attempt + 1
            );
            let profile = self.profile.clone();
            let client = browser_client_for_profile(cookie_jar.clone(), &profile)?;
            let captcha_client = captcha_client_for_profile(cookie_jar.clone(), &profile)?;
            let saved_profile = load_saved_profile();
            match self
                .legacy_path(
                    link,
                    stream_id,
                    credential,
                    LegacyAttempt {
                        client: &client,
                        captcha_client: &captcha_client,
                        profile,
                        saved_profile: saved_profile.as_ref(),
                    },
                )
                .await
            {
                Ok(value) => {
                    crate::log_error!(
                        "[STREAM {stream_id}] [VK Auth] Success with client_id={}",
                        credential.client_id
                    );
                    return Ok(value);
                }
                Err(error) if error.downcast_ref::<CallUnavailable>().is_some() => {
                    return Err(error);
                }
                Err(error) => {
                    crate::log_error!(
                        "[STREAM {stream_id}] [VK Auth] Failed with client_id={}: {error}",
                        credential.client_id
                    );
                    if error.to_string().contains("CAPTCHA_WAIT_REQUIRED") {
                        self.captcha_lockout_until
                            .store(unix_seconds() + 60, Ordering::Release);
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
            if attempt % self.credentials.len() == self.credentials.len() - 1 && attempt < 3 {
                let wait = rand::random::<u64>() % 900 + 900;
                crate::log_error!(
                    "[STREAM {stream_id}] [VK Auth] Both VK credentials failed, retrying stable pair after {wait}ms..."
                );
                tokio::time::sleep(Duration::from_millis(wait)).await;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all VK credentials failed")))
    }

    async fn vk_calls_with_retries(&self, link: &str, stream_id: usize) -> Result<TurnCredentials> {
        let mut last_error = None;
        for attempt in 1..=2 {
            match self.vk_calls_path(link, stream_id).await {
                Ok(credentials) => {
                    crate::log_error!(
                        "[STREAM {stream_id}] [VK Auth] Success via VK Calls path (attempt {attempt}/2)"
                    );
                    return Ok(credentials);
                }
                Err(error) if error.downcast_ref::<CallUnavailable>().is_some() => {
                    return Err(error);
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt < 2 {
                        random_delay(300, 500).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("VK Calls path failed")))
    }

    async fn vk_calls_path(&self, link: &str, stream_id: usize) -> Result<TurnCredentials> {
        if std::env::var("VK_SKIP_VKCALLS").as_deref() == Ok("1") {
            bail!("step=preflight kind=skipped: disabled by VK_SKIP_VKCALLS=1");
        }
        let profile = self.profile.clone();
        let client = browser_client_for_profile(Arc::new(Jar::default()), &profile)?;
        let device_id = Uuid::new_v4().to_string();
        let name = generate_name();
        let link_url = query_escape(&format!("https://vk.com/call/join/{link}"));
        let name_encoded = query_escape(&name);
        crate::log_error!(
            "[STREAM {stream_id}] [VKCalls] Identity - Name: {name} | device_id={device_id} | Fingerprint: {:?}/{:?}",
            profile.impersonate,
            profile.os
        );
        let step1 = format!(
            "https://{VK_CALLS_API_HOST}/method/auth.getAnonymToken?v={VK_CALLS_API_VERSION}&client_id={VK_CONNECT_CLIENT_ID}&link={link_url}&device_id={device_id}&anonymName={name_encoded}&lang=en"
        );
        let response1 = post_empty(&client, &step1, &profile).await?;
        let anonymous_token = json_string(&response1, &["response", "token"])?;
        let anonymous_token_encoded = query_escape(anonymous_token);
        crate::log_error!(
            "[STREAM {stream_id}] [VKCalls] step1 OK, anonymous_token ({} chars)",
            anonymous_token.len()
        );
        let step2 = format!(
            "https://{VK_CALLS_API_HOST}/method/messages.getCallPreview?v={VK_CALLS_API_VERSION}&anonymous_token={anonymous_token_encoded}&device_id={device_id}&extended=1&fields=first_name,last_name,photo_200&lang=en&link={link_url}"
        );
        let response2 = post_empty(&client, &step2, &profile).await?;
        check_vk_error(&response2)?;
        let user_id = json_number(&response2, &["response", "user_id"])? as i64;
        let secret = json_string(&response2, &["response", "secret"])?;
        crate::log_error!(
            "[STREAM {stream_id}] [VKCalls] step2 OK, user_id={user_id}, secret ({} chars)",
            secret.len()
        );
        let step3 = format!(
            "https://{VK_CALLS_API_HOST}/method/messages.getAnonymCallToken?v={VK_CALLS_API_VERSION}&anonymous_token={anonymous_token_encoded}&device_id={device_id}&link={link_url}&name={name_encoded}&user_id={user_id}&secret={}&lang=en",
            query_escape(secret)
        );
        let response3 = post_empty(&client, &step3, &profile).await?;
        check_vk_error(&response3)?;
        let ok_anonymous_token = json_string(&response3, &["response", "token"])?;
        crate::log_error!(
            "[STREAM {stream_id}] [VKCalls] step3 OK, OK anonymToken ({} chars)",
            ok_anonymous_token.len()
        );
        let ok_device_id = Uuid::new_v4();
        let session_data = query_escape(&format!(
            r#"{{"version":2,"device_id":"{ok_device_id}","client_version":"1.0.1"}}"#
        ));
        let step4 = format!(
            "https://calls.okcdn.ru/fb.do?session_data={session_data}&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA"
        );
        let response4 = post_empty(&client, &step4, &profile).await?;
        let session_key = json_string(&response4, &["session_key"])?;
        crate::log_error!(
            "[STREAM {stream_id}] [VKCalls] step4 OK, OK session_key ({} chars)",
            session_key.len()
        );
        let step5 = format!(
            "https://calls.okcdn.ru/fb.do?joinLink={link}&isVideo=false&protocolVersion=5&anonymToken={ok_anonymous_token}&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key={session_key}"
        );
        let response5 = post_empty(&client, &step5, &profile).await?;
        check_ok_error(&response5)?;
        let credentials = parse_turn_credentials(&response5)?;
        crate::log_error!(
            "[STREAM {stream_id}] [VKCalls] SUCCESS, TURN urls={}",
            credentials.server_addresses.len()
        );
        Ok(credentials)
    }

    async fn legacy_path(
        &self,
        link: &str,
        stream_id: usize,
        credential: &VkCredentials,
        attempt: LegacyAttempt<'_>,
    ) -> Result<TurnCredentials> {
        let LegacyAttempt {
            client,
            captcha_client,
            profile,
            saved_profile,
        } = attempt;
        let name = generate_name();
        let escaped_name = query_escape(&name);
        crate::log_error!(
            "[STREAM {stream_id}] [VK Auth] Identity - Name: {name} | Fingerprint: {:?}/{:?}",
            profile.impersonate,
            profile.os
        );
        let data = format!(
            "client_id={}&token_type=messages&client_secret={}&version=1&app_id={}",
            credential.client_id, credential.client_secret, credential.client_id
        );
        let response = post_form(
            client,
            "https://login.vk.ru/?act=get_anonym_token",
            &data,
            &profile,
        )
        .await?;
        let token1 = json_string(&response, &["data", "access_token"])?;
        random_delay(100, 150).await;
        let preview = format!(
            "vk_join_link=https://vk.com/call/join/{link}&fields=photo_200&access_token={token1}"
        );
        let preview_url = format!(
            "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id={}",
            credential.client_id
        );
        match post_form(client, &preview_url, &preview, &profile).await {
            Ok(value) => check_fatal_call(&value)?,
            Err(error) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [VK Auth] Warning: getCallPreview failed: {error}"
                )
            }
        }
        random_delay(200, 400).await;
        let mut anonymous_data = format!(
            "vk_join_link=https://vk.com/call/join/{link}&name={escaped_name}&access_token={token1}"
        );
        let anonymous_url = format!(
            "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id={}",
            credential.client_id
        );
        let mut captcha_attempts = 0usize;
        let token2 = loop {
            let response = post_form(client, &anonymous_url, &anonymous_data, &profile).await?;
            if let Some(error) = response.get("error") {
                check_fatal_call(&response)?;
                let captcha = VkCaptchaError::from_json(error)?;
                if captcha.redirect_uri.is_empty() || captcha.session_token.is_empty() {
                    bail!("VK API error: {error}");
                }
                if captcha_attempts >= 3 {
                    bail!("CAPTCHA_WAIT_REQUIRED");
                }
                captcha_attempts += 1;
                let success = self
                    .captcha
                    .solve(captcha_client, &profile, saved_profile, stream_id, &captcha)
                    .await
                    .map_err(|error| anyhow::anyhow!("CAPTCHA_WAIT_REQUIRED: {error}"))?;
                let attempt =
                    if captcha.captcha_attempt.is_empty() || captcha.captcha_attempt == "0" {
                        "1"
                    } else {
                        &captcha.captcha_attempt
                    };
                anonymous_data = format!(
                    "vk_join_link=https://vk.com/call/join/{link}&name={escaped_name}&captcha_key=&captcha_sid={}&is_sound_captcha=0&success_token={}&captcha_ts={}&captcha_attempt={attempt}&access_token={token1}",
                    captcha.captcha_sid,
                    query_escape(&success),
                    captcha.captcha_timestamp
                );
                continue;
            }
            break json_string(&response, &["response", "token"])?.to_owned();
        };
        random_delay(100, 150).await;
        let session_data = format!(
            r#"{{"version":2,"device_id":"{}","client_version":1.1,"client_type":"SDK_JS"}}"#,
            Uuid::new_v4()
        );
        let login_data = format!(
            "session_data={}&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
            query_escape(&session_data)
        );
        let login = post_form(
            client,
            "https://calls.okcdn.ru/fb.do",
            &login_data,
            &profile,
        )
        .await?;
        let session_key = json_string(&login, &["session_key"])?;
        random_delay(100, 150).await;
        let join = format!(
            "joinLink={link}&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken={token2}&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key={session_key}"
        );
        let response = post_form(client, "https://calls.okcdn.ru/fb.do", &join, &profile).await?;
        parse_turn_credentials(&response)
    }
}

pub async fn check_vk_hashes(
    fingerprint: &str,
    _client_ids: &[String],
    hashes: &[String],
) -> Vec<(String, VkHashCheck)> {
    let profile = random_profile(fingerprint);
    let mut results = Vec::with_capacity(hashes.len());
    for (index, hash) in hashes.iter().enumerate() {
        let result = check_vk_hash(&profile, hash).await;
        results.push((hash.clone(), result));
        if index + 1 < hashes.len() {
            random_delay(180, 260).await;
        }
    }
    results
}

async fn check_vk_hash(profile: &Profile, hash: &str) -> VkHashCheck {
    let mut last_error = None;
    for _ in 0..2 {
        match check_vk_hash_attempt(profile, hash).await {
            Ok(result) => return result,
            Err(error) => last_error = Some(format!("{error:#}")),
        }
        random_delay(180, 260).await;
    }
    VkHashCheck::Unavailable {
        message: last_error.unwrap_or_else(|| "VK client credentials are unavailable".to_owned()),
    }
}

async fn check_vk_hash_attempt(profile: &Profile, hash: &str) -> Result<VkHashCheck> {
    let client = browser_client_for_profile(Arc::new(Jar::default()), profile)?;
    let device_id = Uuid::new_v4().to_string();
    let name = generate_name();
    let link_url = query_escape(&format!("https://vk.com/call/join/{hash}"));
    let name_encoded = query_escape(&name);
    let token_url = format!(
        "https://{VK_CALLS_API_HOST}/method/auth.getAnonymToken?v={VK_CALLS_API_VERSION}&client_id={VK_CONNECT_CLIENT_ID}&link={link_url}&device_id={device_id}&anonymName={name_encoded}&lang=en"
    );
    let token_response = post_empty(&client, &token_url, profile).await?;
    if let Some(result) = classify_vk_hash_error(&token_response)? {
        return Ok(result);
    }
    let anonymous_token = query_escape(json_string(&token_response, &["response", "token"])?);
    let preview_url = format!(
        "https://{VK_CALLS_API_HOST}/method/messages.getCallPreview?v={VK_CALLS_API_VERSION}&anonymous_token={anonymous_token}&device_id={device_id}&extended=1&fields=first_name,last_name,photo_200&lang=en&link={link_url}"
    );
    let preview_response = post_empty(&client, &preview_url, profile).await?;
    if let Some(result) = classify_vk_hash_error(&preview_response)? {
        return Ok(result);
    }
    json_number(&preview_response, &["response", "user_id"])?;
    json_string(&preview_response, &["response", "secret"])?;
    Ok(VkHashCheck::Valid)
}

fn classify_vk_hash_error(response: &Value) -> Result<Option<VkHashCheck>> {
    let Some(error) = response.get("error") else {
        return Ok(None);
    };
    let code = error_code(error.get("error_code"));
    let message = vk_error_message(error).to_owned();
    if is_fatal_call_error(code, &message) {
        return Ok(Some(VkHashCheck::Invalid { code, message }));
    }
    if code == 14 {
        return Ok(Some(VkHashCheck::Valid));
    }
    bail!("VK API error: error_code={code} {message}")
}

fn browser_client_for_profile(cookie_jar: Arc<Jar>, profile: &Profile) -> Result<Client> {
    let (browser, os) = browser_identity(profile);
    build_browser_client(cookie_jar, browser, os, false)
}

fn captcha_client_for_profile(cookie_jar: Arc<Jar>, profile: &Profile) -> Result<Client> {
    let (browser, os) = browser_identity(profile);
    let custom_order = matches!(
        browser,
        Impersonate::ChromeV144
            | Impersonate::ChromeV145
            | Impersonate::ChromeV146
            | Impersonate::ChromeV147
            | Impersonate::ChromeV148
            | Impersonate::Chrome
    );
    build_browser_client(cookie_jar, browser, os, custom_order)
}

fn browser_identity(profile: &Profile) -> (Impersonate, ImpersonateOS) {
    (profile.impersonate, profile.os)
}

fn build_browser_client(
    cookie_jar: Arc<Jar>,
    browser: Impersonate,
    os: ImpersonateOS,
    captcha_order: bool,
) -> Result<Client> {
    let mut builder = Client::builder()
        .impersonate(browser)
        .impersonate_os(os)
        .timeout(Duration::from_secs(20))
        .cookie_provider(cookie_jar)
        .redirect(primp::redirect::Policy::limited(10))
        .dns_resolver(dns::global());
    if captcha_order {
        let pseudo = PseudoOrder::builder()
            .push(PseudoId::Method)
            .push(PseudoId::Path)
            .push(PseudoId::Authority)
            .push(PseudoId::Scheme)
            .build();
        let order = [
            "host",
            "content-length",
            "sec-ch-ua-platform",
            "accept-language",
            "sec-ch-ua",
            "content-type",
            "sec-ch-ua-mobile",
            "user-agent",
            "accept",
            "origin",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "priority",
        ]
        .into_iter()
        .map(header::HeaderName::from_static)
        .collect();
        builder = builder
            .http2_headers_pseudo_order(pseudo)
            .http2_headers_order(order);
    }
    let mut client = builder
        .build()
        .context("failed to initialize HTTP client")?;
    client.headers_mut().clear();
    Ok(client)
}

fn browser_headers(profile: &Profile) -> Result<header::HeaderMap> {
    let mut headers = header::HeaderMap::with_capacity(14);
    if !profile.user_agent.is_empty() {
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&profile.user_agent)?,
        );
    }
    if !profile.sec_ch_ua.is_empty() {
        headers.insert(
            "sec-ch-ua",
            header::HeaderValue::from_str(&profile.sec_ch_ua)?,
        );
    }
    if !profile.sec_ch_ua_mobile.is_empty() {
        headers.insert(
            "sec-ch-ua-mobile",
            header::HeaderValue::from_str(&profile.sec_ch_ua_mobile)?,
        );
    }
    if !profile.sec_ch_ua_platform.is_empty() {
        headers.insert(
            "sec-ch-ua-platform",
            header::HeaderValue::from_str(&profile.sec_ch_ua_platform)?,
        );
    }
    headers.insert(header::ACCEPT, header::HeaderValue::from_static("*/*"));
    headers.insert(
        header::ACCEPT_LANGUAGE,
        header::HeaderValue::from_static("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"),
    );
    headers.insert("dnt", header::HeaderValue::from_static("1"));
    Ok(headers)
}

async fn post_empty(client: &Client, endpoint: &str, profile: &Profile) -> Result<Value> {
    let mut headers = header::HeaderMap::with_capacity(4);
    if !profile.user_agent.is_empty() {
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&profile.user_agent)?,
        );
    }
    headers.insert(header::ACCEPT, header::HeaderValue::from_static("*/*"));
    headers.insert(
        header::ACCEPT_ENCODING,
        header::HeaderValue::from_static("gzip, deflate, br, zstd"),
    );
    headers.insert(
        header::ACCEPT_LANGUAGE,
        header::HeaderValue::from_static("en-GB,en;q=0.9"),
    );
    let response = client.post(endpoint).headers(headers).send().await?;
    let body = response.bytes().await?;
    serde_json::from_slice(&body).with_context(|| {
        format!(
            "unmarshal JSON: {}",
            String::from_utf8_lossy(body.get(..body.len().min(200)).unwrap_or_default())
        )
    })
}

async fn post_form(
    client: &Client,
    endpoint: &str,
    data: &str,
    profile: &Profile,
) -> Result<Value> {
    let mut headers = browser_headers(profile)?;
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(
        header::ORIGIN,
        header::HeaderValue::from_static("https://vk.ru"),
    );
    headers.insert(
        header::REFERER,
        header::HeaderValue::from_static("https://vk.ru/"),
    );
    headers.insert(
        "sec-fetch-site",
        header::HeaderValue::from_static("same-site"),
    );
    headers.insert("sec-fetch-mode", header::HeaderValue::from_static("cors"));
    headers.insert("sec-fetch-dest", header::HeaderValue::from_static("empty"));
    headers.insert("priority", header::HeaderValue::from_static("u=1, i"));
    let response = client
        .post(endpoint)
        .headers(headers)
        .body(data.to_owned())
        .send()
        .await?;
    let body = response.bytes().await?;
    serde_json::from_slice(&body).with_context(|| {
        format!(
            "decode response: {}",
            String::from_utf8_lossy(body.get(..body.len().min(200)).unwrap_or_default())
        )
    })
}

fn check_vk_error(response: &Value) -> Result<()> {
    let Some(error) = response.get("error") else {
        return Ok(());
    };
    check_fatal_call(response)?;
    if error_code(error.get("error_code")) == 14 {
        return Err(VkCaptchaError::from_json(error)?.into());
    }
    let code = error_code(error.get("error_code"));
    bail!(
        "VK API error: error_code={} {}",
        code,
        error
            .get("error_msg")
            .and_then(Value::as_str)
            .unwrap_or_default()
    )
}

fn check_fatal_call(response: &Value) -> Result<()> {
    let Some(error) = response.get("error") else {
        return Ok(());
    };
    let code = error_code(error.get("error_code"));
    let message = vk_error_message(error);
    if is_fatal_call_error(code, message) {
        return Err(CallUnavailable {
            code,
            message: message.to_owned(),
        }
        .into());
    }
    Ok(())
}

fn is_fatal_call_code(code: i64) -> bool {
    code == 951 || code == 954 || (9000..=9999).contains(&code)
}

fn is_fatal_call_error(code: i64, message: &str) -> bool {
    let normalized = message.trim().to_ascii_lowercase();
    is_fatal_call_code(code)
        || normalized.contains("call not found")
        || normalized.contains("invalid call join link")
}

fn vk_error_message(error: &Value) -> &str {
    error
        .get("error_msg")
        .or_else(|| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn check_ok_error(response: &Value) -> Result<()> {
    let code = error_code(response.get("error_code"));
    if code != 0 {
        let message = vk_error_message(response);
        if is_fatal_call_error(code, message) {
            return Err(CallUnavailable {
                code,
                message: message.to_owned(),
            }
            .into());
        }
        bail!("OK CDN API error: error_code={code} {}", message);
    }
    Ok(())
}

fn error_code(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or_default(),
        Some(Value::String(value)) => value.parse().unwrap_or_default(),
        _ => 0,
    }
}

pub(crate) fn parse_turn_credentials(response: &Value) -> Result<TurnCredentials> {
    let turn = response
        .get("turn_server")
        .context("missing turn_server in response")?;
    let username: Arc<str> = Arc::from(
        turn.get("username")
            .and_then(Value::as_str)
            .context("missing username in turn_server")?,
    );
    let password: Arc<str> = Arc::from(
        turn.get("credential")
            .and_then(Value::as_str)
            .context("missing credential in turn_server")?,
    );
    let addresses: Vec<Arc<str>> = turn
        .get("urls")
        .and_then(Value::as_array)
        .context("missing or empty urls in turn_server")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| crate::turn_endpoint::is_supported_turn_uri(value))
        .map(Arc::from)
        .collect();
    if addresses.is_empty() {
        bail!("no valid TURN addresses found");
    }
    Ok(TurnCredentials {
        username,
        password,
        server_addresses: addresses.into(),
    })
}

fn json_string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .with_context(|| format!("missing key {key}"))?;
    }
    current.as_str().context("expected string")
}

fn json_number(value: &Value, path: &[&str]) -> Result<f64> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .with_context(|| format!("missing key {key}"))?;
    }
    current.as_f64().context("expected number")
}

fn query_escape(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b' ' => output.push('+'),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => {
                output.push('%');
                output.push(HEX.get((byte >> 4) as usize).copied().unwrap_or(b'0') as char);
                output.push(HEX.get((byte & 0x0f) as usize).copied().unwrap_or(b'0') as char);
            }
        }
    }
    output
}

async fn random_delay(minimum_ms: u64, maximum_ms: u64) {
    let delay = minimum_ms + rand::random::<u64>() % (maximum_ms - minimum_ms + 1);
    tokio::time::sleep(Duration::from_millis(delay)).await;
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn load_credentials(client_ids: &[String]) -> Vec<VkCredentials> {
    let known = |id: &str| match id {
        "8202606" => Some("lMRsTiMCyPnp5vfoldmn"),
        "6287487" => Some("MuAxFaKDYDOICzGnEOhp"),
        _ => None,
    };
    let from_ids: Vec<_> = client_ids
        .iter()
        .filter_map(|id| known(id.trim()).map(|secret| (id.trim(), secret)))
        .map(|(id, secret)| VkCredentials {
            client_id: Arc::from(id),
            client_secret: Arc::from(secret),
        })
        .collect();
    if !from_ids.is_empty() {
        return from_ids;
    }
    if let Ok(value) = std::env::var("CSQTT_VK_CREDENTIALS") {
        let parsed: Vec<_> = value
            .split(',')
            .filter_map(|pair| pair.trim().split_once(':'))
            .filter(|(id, secret)| !id.trim().is_empty() && !secret.trim().is_empty())
            .map(|(id, secret)| VkCredentials {
                client_id: Arc::from(id.trim()),
                client_secret: Arc::from(secret.trim()),
            })
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![
        VkCredentials {
            client_id: Arc::from("8202606"),
            client_secret: Arc::from("lMRsTiMCyPnp5vfoldmn"),
        },
        VkCredentials {
            client_id: Arc::from("6287487"),
            client_secret: Arc::from("MuAxFaKDYDOICzGnEOhp"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_escape_matches_go() {
        assert_eq!(query_escape("x y*~тест"), "x+y%2A~%D1%82%D0%B5%D1%81%D1%82");
    }

    #[test]
    fn error_code_matches_go_number_and_string_values() {
        assert_eq!(error_code(Some(&serde_json::json!(951))), 951);
        assert_eq!(error_code(Some(&serde_json::json!("954"))), 954);
        assert_eq!(error_code(Some(&serde_json::json!(14.0))), 14);
    }

    #[test]
    fn hash_check_accepts_captcha_without_solving_it() {
        let response = serde_json::json!({
            "error": {
                "error_code": 14,
                "error_msg": "Captcha needed"
            }
        });
        assert_eq!(
            classify_vk_hash_error(&response).unwrap(),
            Some(VkHashCheck::Valid)
        );
    }

    #[test]
    fn hash_check_rejects_dead_call_link() {
        let response = serde_json::json!({
            "error": {
                "error_code": 9008,
                "error_msg": "invalid call join link"
            }
        });
        assert_eq!(
            classify_vk_hash_error(&response).unwrap(),
            Some(VkHashCheck::Invalid {
                code: 9008,
                message: "invalid call join link".to_owned()
            })
        );
    }

    #[test]
    fn hash_check_rejects_call_not_found_951() {
        let response = serde_json::json!({
            "error": {
                "error_code": 951,
                "error_msg": "Call not found"
            }
        });
        assert_eq!(
            classify_vk_hash_error(&response).unwrap(),
            Some(VkHashCheck::Invalid {
                code: 951,
                message: "Call not found".to_owned()
            })
        );
    }

    #[test]
    fn hash_check_rejects_call_not_found_text_with_unknown_code() {
        let response = serde_json::json!({
            "error": {
                "error_code": 1,
                "error_msg": "Requested call not found for this link"
            }
        });
        assert_eq!(
            classify_vk_hash_error(&response).unwrap(),
            Some(VkHashCheck::Invalid {
                code: 1,
                message: "Requested call not found for this link".to_owned()
            })
        );
    }

    #[test]
    fn hash_check_keeps_transient_vk_errors_unclassified() {
        let response = serde_json::json!({
            "error": {
                "error_code": 6,
                "error_msg": "Too many requests"
            }
        });
        assert!(classify_vk_hash_error(&response).is_err());
    }

    #[test]
    fn ok_join_call_not_found_is_non_retryable() {
        let response = serde_json::json!({
            "error_code": 951,
            "error_msg": "Call not found"
        });
        let error = check_ok_error(&response).unwrap_err();
        assert!(error.downcast_ref::<CallUnavailable>().is_some());
    }

    #[test]
    fn browser_headers_omit_user_agent_when_profile_has_no_override() {
        let profile = random_profile("chrome");
        let headers = browser_headers(&profile).unwrap();
        assert!(
            headers.get(header::USER_AGENT).is_none(),
            "UA should not be set in browser_headers when profile.user_agent is empty"
        );
        assert!(headers.get(header::ACCEPT_LANGUAGE).is_some());
        assert!(headers.get("dnt").is_some());
    }

    #[test]
    fn selected_profiles_keep_tls_and_http_identity_aligned() {
        let firefox = random_profile("firefox");
        let safari = random_profile("safari");
        let chrome = random_profile("chrome");
        let edge = random_profile("edge");
        let opera = random_profile("opera");
        let (fb, _fo) = browser_identity(&firefox);
        let (sb, _so) = browser_identity(&safari);
        let (cb, _co) = browser_identity(&chrome);
        let (eb, _eo) = browser_identity(&edge);
        let (ob, _oo) = browser_identity(&opera);
        assert!(
            matches!(
                fb,
                Impersonate::FirefoxV140
                    | Impersonate::FirefoxV146
                    | Impersonate::FirefoxV147
                    | Impersonate::FirefoxV148
            ),
            "Firefox profile should have Firefox impersonate, got {:?}",
            fb
        );
        assert!(
            matches!(
                sb,
                Impersonate::SafariV18_5 | Impersonate::SafariV26 | Impersonate::SafariV26_3
            ),
            "Safari profile should have Safari impersonate, got {:?}",
            sb
        );
        assert!(
            matches!(
                cb,
                Impersonate::ChromeV144
                    | Impersonate::ChromeV145
                    | Impersonate::ChromeV146
                    | Impersonate::ChromeV147
                    | Impersonate::ChromeV148
            ),
            "Chrome profile should have Chrome impersonate, got {:?}",
            cb
        );
        assert!(
            matches!(
                eb,
                Impersonate::EdgeV144
                    | Impersonate::EdgeV145
                    | Impersonate::EdgeV146
                    | Impersonate::EdgeV147
                    | Impersonate::EdgeV148
            ),
            "Edge profile should have Edge impersonate, got {:?}",
            eb
        );
        assert!(
            matches!(
                ob,
                Impersonate::OperaV126
                    | Impersonate::OperaV127
                    | Impersonate::OperaV128
                    | Impersonate::OperaV129
                    | Impersonate::OperaV130
                    | Impersonate::OperaV131
            ),
            "Opera profile should have Opera impersonate, got {:?}",
            ob
        );
        assert!(
            browser_headers(&firefox)
                .unwrap()
                .get("sec-ch-ua")
                .is_none()
        );
        assert!(
            browser_headers(&safari)
                .unwrap()
                .get("sec-ch-ua-platform")
                .is_none()
        );
        assert!(
            matches!(_so, ImpersonateOS::MacOS | ImpersonateOS::IOS),
            "Safari profile should use an Apple platform, got {:?}",
            _so
        );
    }

    #[test]
    fn invalid_saved_profile_header_returns_error() {
        let profile = Profile {
            user_agent: "valid\r\ninjected: value".into(),
            ..Profile::default()
        };
        assert!(browser_headers(&profile).is_err());
    }

    #[test]
    fn turn_credentials_keep_all_standard_turn_endpoints_from_mixed_vk_list() {
        let credentials = parse_turn_credentials(&serde_json::json!({
            "turn_server": {
                "username": "user",
                "credential": "pass",
                "urls": [
                    "turn:udp-one.example:3478?transport=udp",
                    "turn:tcp.example:3478?transport=tcp",
                    "turns:tls.example:5349?transport=tcp",
                    "udp-two.example:3478",
                    "TURN:udp-three.example:3478?TRANSPORT=UDP"
                ]
            }
        }))
        .unwrap();
        assert_eq!(
            credentials
                .server_addresses
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>(),
            vec![
                "turn:udp-one.example:3478?transport=udp",
                "turn:tcp.example:3478?transport=tcp",
                "turns:tls.example:5349?transport=tcp",
                "udp-two.example:3478",
                "TURN:udp-three.example:3478?TRANSPORT=UDP"
            ]
        );
    }

    #[test]
    fn turn_credentials_accept_tcp_tls_only_turn_lists() {
        let result = parse_turn_credentials(&serde_json::json!({
            "turn_server": {
                "username": "user",
                "credential": "pass",
                "urls": [
                    "turn:tcp.example:3478?transport=tcp",
                    "turns:tls.example:5349"
                ]
            }
        }));
        assert!(result.is_ok());
    }
}
