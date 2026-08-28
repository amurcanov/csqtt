// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::auth::{TurnCredentials, parse_turn_credentials};
use crate::profiles::Profile;
use anyhow::{Context, Result, bail};
use primp::{
    Client,
    header::{self, HeaderMap, HeaderValue},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use url::{Url, form_urlencoded};
use uuid::Uuid;

const VK_API_VERSION: &str = "5.285";
const VK_CLIENT_ID: &str = "6287487";
const OK_APPLICATION_KEY: &str = "CGMMEJLGDIHBABABA";
const DEFAULT_OK_API: &str = "https://calls.okcdn.ru/fb.do";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
pub const MAX_ACCOUNT_CREDENTIALS: usize = 9;

#[derive(Deserialize)]
pub struct Bootstrap {
    pub token: String,
}

#[derive(Clone)]
pub struct ActiveCalls {
    client: Client,
    api_url: String,
    access_token: String,
    session_key: String,
    conversation_ids: Vec<String>,
}

pub struct CredentialBroker {
    client: Client,
    access_token: String,
    conversation_id: String,
    issued_credentials: Arc<Mutex<HashSet<[u8; 32]>>>,
}

pub struct StartedCalls {
    pub hashes: Vec<String>,
    pub active: ActiveCalls,
    pub credential_broker: Arc<CredentialBroker>,
}

#[derive(Clone)]
struct ApiSession {
    api_url: String,
    session_key: String,
}

enum RequestSite {
    Vk,
    Ok,
}

pub async fn start(
    bootstrap: Bootstrap,
    device_id: &str,
    multiple_devices: bool,
    profile: &Profile,
) -> Result<StartedCalls> {
    if bootstrap.token.trim().is_empty() {
        bail!("VK access token отсутствует");
    }
    let client = Client::builder()
        .impersonate(profile.impersonate)
        .impersonate_os(profile.os)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(8))
        .redirect(primp::redirect::Policy::limited(5))
        .dns_resolver(crate::dns::global())
        .build()
        .context("инициализация браузерного HTTP-клиента")?;
    let access_token = bootstrap.token;
    let creator_session = open_account_session(&client, &access_token, device_id).await?;
    let api_url = creator_session.api_url;
    let session_key = creator_session.session_key;
    let info = post_form(
        &client,
        &api_url,
        &[
            ("method", "system.getInfo"),
            ("format", "JSON"),
            ("application_key", OK_APPLICATION_KEY),
            ("session_key", session_key.as_str()),
        ],
        RequestSite::Ok,
    )
    .await
    .context("system.getInfo")?;
    check_api_error(&info)?;
    if info.get("serverTime").is_none() {
        bail!("system.getInfo: нет serverTime");
    }
    crate::log_error!("[VK JS] Сессия Calls подтверждена");

    let conversation_id = Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "is_video": true,
        "with_join_link": true,
        "join_by_link": true,
        "community_user_id": 0,
        "caller_app_id": 6287487
    })
    .to_string();
    let protocol_version = if multiple_devices { "6" } else { "5" };
    let call = retry(3, || async {
        post_form(
            &client,
            &api_url,
            &[
                ("conversationId", conversation_id.as_str()),
                ("isVideo", "true"),
                ("protocolVersion", protocol_version),
                ("createJoinLink", "true"),
                ("payload", payload.as_str()),
                ("onlyAdminCanShareMovie", "false"),
                ("externalIds", ""),
                ("method", "vchat.startConversation"),
                ("format", "JSON"),
                ("application_key", OK_APPLICATION_KEY),
                ("session_key", session_key.as_str()),
            ],
            RequestSite::Ok,
        )
        .await
    })
    .await;
    let hash = match call {
        Ok(call) => check_api_error(&call).and_then(|()| {
            call.get("join_link")
                .and_then(Value::as_str)
                .and_then(join_hash)
                .map(str::to_owned)
                .context("нет join_link")
        }),
        Err(error) => Err(error),
    };
    let active = ActiveCalls {
        client,
        api_url,
        access_token: access_token.clone(),
        session_key,
        conversation_ids: vec![conversation_id.clone()],
    };
    let credential_broker = Arc::new(CredentialBroker {
        client: active.client.clone(),
        access_token,
        conversation_id,
        issued_credentials: Arc::new(Mutex::new(HashSet::new())),
    });
    match hash {
        Ok(hash) => {
            crate::log_error!("[VK JS] Звонок создан");
            Ok(StartedCalls {
                hashes: vec![hash],
                active,
                credential_broker,
            })
        }
        Err(error) => {
            crate::log_error!("[VK JS] Звонок не создан: {error}");
            let _ = tokio::time::timeout(Duration::from_secs(8), active.leave_creator()).await;
            Err(error).context("vchat.startConversation")
        }
    }
}

impl CredentialBroker {
    pub async fn get_credentials(&self, credential_id: usize) -> Result<TurnCredentials> {
        if !(1..=MAX_ACCOUNT_CREDENTIALS).contains(&credential_id) {
            bail!("Auto JS credential id вне диапазона: {credential_id}");
        }
        let device_id = Uuid::new_v4().to_string();
        let session = open_account_session(&self.client, &self.access_token, &device_id)
            .await
            .with_context(|| format!("Auto JS session #{credential_id}"))?;
        let params = retry(3, || async {
            let value = post_form(
                &self.client,
                &session.api_url,
                &conversation_params_fields(
                    self.conversation_id.as_str(),
                    session.session_key.as_str(),
                ),
                RequestSite::Ok,
            )
            .await?;
            check_api_error(&value)?;
            Ok(value)
        })
        .await
        .with_context(|| format!("vchat.getConversationParams #{credential_id}"))?;
        let credentials = parse_turn_credentials(&params)?;
        let fingerprint = credential_fingerprint(&credentials);
        {
            let mut issued = self.issued_credentials.lock().await;
            if !issued.insert(fingerprint) {
                bail!("Auto JS вернул повторный TURN-набор для сессии #{credential_id}");
            }
        }
        crate::log_error!(
            "[VK JS] Креды аккаунта {credential_id}/{MAX_ACCOUNT_CREDENTIALS} готовы · независимая сессия"
        );
        Ok(credentials)
    }
}

async fn open_account_session(
    client: &Client,
    access_token: &str,
    device_id: &str,
) -> Result<ApiSession> {
    let token_response = retry(3, || async {
        post_form(
            client,
            &format!(
                "https://api.vk.ru/method/messages.getCallToken?v={VK_API_VERSION}&client_id={VK_CLIENT_ID}"
            ),
            &[("env", "production"), ("access_token", access_token)],
            RequestSite::Vk,
        )
        .await
    })
    .await
    .context("messages.getCallToken")?;
    check_api_error(&token_response)?;
    let response = token_response
        .get("response")
        .context("messages.getCallToken: нет response")?;
    let call_token = required_string(response, "token")?;
    let api_url = validated_api_url(
        response
            .get("api_base_url")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_OK_API),
    )?;
    let session_data = serde_json::json!({
        "auth_token": call_token,
        "version": 3,
        "device_id": device_id,
        "client_version": "1.0.1"
    })
    .to_string();
    let login = retry(3, || async {
        post_form(
            client,
            &api_url,
            &[
                ("session_data", session_data.as_str()),
                ("device_id", device_id),
                ("verification_supported", "true"),
                ("verification_supported_v", "1"),
                ("client", "test"),
                ("gen_token", "true"),
                ("method", "auth.anonymLogin"),
                ("format", "JSON"),
                ("application_key", OK_APPLICATION_KEY),
            ],
            RequestSite::Ok,
        )
        .await
    })
    .await
    .context("auth.anonymLogin")?;
    check_api_error(&login)?;
    Ok(ApiSession {
        api_url,
        session_key: required_string(&login, "session_key")?.to_owned(),
    })
}

fn credential_fingerprint(credentials: &TurnCredentials) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(credentials.username.as_bytes());
    digest.update([0]);
    digest.update(credentials.password.as_bytes());
    for address in credentials.server_addresses.iter() {
        digest.update([0]);
        digest.update(address.as_bytes());
    }
    digest.finalize().into()
}

fn conversation_params_fields<'a>(
    conversation_id: &'a str,
    session_key: &'a str,
) -> [(&'static str, &'a str); 5] {
    [
        ("conversationId", conversation_id),
        ("method", "vchat.getConversationParams"),
        ("format", "JSON"),
        ("application_key", OK_APPLICATION_KEY),
        ("session_key", session_key),
    ]
}

impl ActiveCalls {
    pub async fn leave_creator(self) {
        let total = self.conversation_ids.len();
        let mut finished = 0usize;
        let mut tasks = tokio::task::JoinSet::new();
        for conversation_id in self.conversation_ids {
            let client = self.client.clone();
            let api_url = self.api_url.clone();
            let session_key = self.session_key.clone();
            tasks.spawn(async move {
                retry(3, || async {
                    let value = post_form(
                        &client,
                        &api_url,
                        &[
                            ("conversationId", conversation_id.as_str()),
                            ("reason", "HUNGUP"),
                            ("method", "vchat.hangupConversation"),
                            ("format", "JSON"),
                            ("application_key", OK_APPLICATION_KEY),
                            ("session_key", session_key.as_str()),
                        ],
                        RequestSite::Ok,
                    )
                    .await?;
                    check_api_error(&value)?;
                    Ok(value)
                })
                .await
                .map(|_| ())
            });
        }
        while let Some(result) = tasks.join_next().await {
            if result.is_ok_and(|result| result.is_ok()) {
                finished += 1;
            }
        }
        crate::log_error!("[VK JS] Создатель вышел из звонков {finished}/{total}");
    }

    pub async fn finish(self) {
        let total = self.conversation_ids.len();
        let client = self.client;
        let access_token = self.access_token;
        let conversation_ids = self.conversation_ids;
        let finished = tokio::time::timeout(Duration::from_secs(2), async move {
            let mut finished = 0usize;
            let mut tasks = tokio::task::JoinSet::new();
            for conversation_id in conversation_ids {
                let client = client.clone();
                let access_token = access_token.clone();
                tasks.spawn(async move {
                    retry(3, || async {
                        let value = post_form(
                            &client,
                            &format!(
                                "https://api.vk.ru/method/calls.forceFinish?v={VK_API_VERSION}&client_id={VK_CLIENT_ID}"
                            ),
                            &[
                                ("call_id", conversation_id.as_str()),
                                ("access_token", access_token.as_str()),
                            ],
                            RequestSite::Vk,
                        )
                        .await?;
                        check_api_error(&value)?;
                        Ok(value)
                    })
                    .await
                    .map(|_| ())
                });
            }
            while let Some(result) = tasks.join_next().await {
                if result.is_ok_and(|result| result.is_ok()) {
                    finished += 1;
                }
            }
            finished
        })
        .await
        .unwrap_or(0);
        crate::log_error!("[VK JS] Звонки завершены {finished}/{total}");
    }
}

async fn retry<F, Fut>(attempts: usize, mut request: F) -> Result<Value>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    let mut last_error = None;
    for attempt in 0..attempts {
        match request().await {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("запрос не выполнен")))
}

async fn post_form(
    client: &Client,
    endpoint: &str,
    fields: &[(&str, &str)],
    site: RequestSite,
) -> Result<Value> {
    let body = form(fields);
    let response = client
        .post(endpoint)
        .headers(headers(site)?)
        .body(body)
        .send()
        .await
        .context("HTTP-запрос")?;
    let status = response.status();
    let bytes = response.bytes().await.context("чтение HTTP-ответа")?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        bail!("слишком большой HTTP-ответ");
    }
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    serde_json::from_slice(&bytes).context("некорректный JSON-ответ")
}

fn headers(site: RequestSite) -> Result<HeaderMap> {
    let mut headers = HeaderMap::with_capacity(10);
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br, zstd"),
    );
    headers.insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.7"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(header::ORIGIN, HeaderValue::from_static("https://vk.ru"));
    headers.insert(header::REFERER, HeaderValue::from_static("https://vk.ru/"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    headers.insert("priority", HeaderValue::from_static("u=1, i"));
    headers.insert(
        "sec-fetch-site",
        HeaderValue::from_static(match site {
            RequestSite::Vk => "same-site",
            RequestSite::Ok => "cross-site",
        }),
    );
    Ok(headers)
}

fn form(fields: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(fields.iter().copied());
    serializer.finish()
}

fn check_api_error(value: &Value) -> Result<()> {
    if let Some(error) = value.get("error")
        && !error.is_null()
        && error != false
    {
        let code = error
            .get("error_code")
            .or_else(|| error.get("code"))
            .and_then(json_scalar_string)
            .unwrap_or_else(|| "unknown".to_owned());
        let message = error
            .get("error_msg")
            .or_else(|| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("API error");
        bail!("API {code}: {message}");
    }
    if let Some(code) = value.get("error_code").and_then(json_scalar_string)
        && code != "0"
    {
        let message = value
            .get("error_msg")
            .and_then(Value::as_str)
            .unwrap_or("API error");
        bail!("API {code}: {message}");
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("нет поля {key}"))
}

fn json_scalar_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_i64().map(|value| value.to_string()))
        .or_else(|| value.as_u64().map(|value| value.to_string()))
}

fn validated_api_url(value: &str) -> Result<String> {
    let mut parsed = Url::parse(value).context("некорректный api_base_url")?;
    let host = parsed.host_str().unwrap_or_default();
    let allowed_host = host == "api.ok.ru" || host == "okcdn.ru" || host.ends_with(".okcdn.ru");
    let allowed_path = matches!(parsed.path(), "" | "/" | "/fb.do");
    if parsed.scheme() != "https"
        || !allowed_host
        || !allowed_path
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.port_or_known_default() != Some(443)
        || parsed.fragment().is_some()
        || parsed.query().is_some()
    {
        bail!(
            "небезопасный api_base_url: host={}, path={}",
            host,
            parsed.path()
        );
    }
    parsed.set_path("/fb.do");
    Ok(parsed.to_string())
}

fn join_hash(value: &str) -> Option<&str> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.rsplit('/').next().unwrap_or(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_url_accepts_only_calls_backend() {
        for value in [
            "https://calls.okcdn.ru",
            "https://calls.okcdn.ru/",
            "https://calls.okcdn.ru/fb.do",
            "https://api.okcdn.ru",
            "https://api.okcdn.ru/fb.do",
            "https://api.ok.ru",
            "https://api.ok.ru/fb.do",
        ] {
            assert_eq!(
                validated_api_url(value).unwrap(),
                format!(
                    "https://{}/fb.do",
                    Url::parse(value).unwrap().host_str().unwrap()
                )
            );
        }
        assert!(validated_api_url("http://calls.okcdn.ru/fb.do").is_err());
        assert!(validated_api_url("https://calls.okcdn.ru/other").is_err());
        assert!(validated_api_url("https://okcdn.ru.example/fb.do").is_err());
        assert!(validated_api_url("https://calls.ok.ru/fb.do").is_err());
        assert!(validated_api_url("https://api.ok.ru:8443/fb.do").is_err());
        assert!(validated_api_url("https://user@api.ok.ru/fb.do").is_err());
        assert!(validated_api_url("https://api.ok.ru/?next=https://evil.example").is_err());
        assert!(validated_api_url("https://api.ok.ru/#fragment").is_err());
    }

    #[test]
    fn join_hash_supports_raw_and_full_links() {
        assert_eq!(join_hash("hash"), Some("hash"));
        assert_eq!(join_hash("https://vk.ru/call/join/hash/"), Some("hash"));
        assert_eq!(join_hash(""), None);
    }

    #[test]
    fn account_credentials_are_bounded_to_nine_sessions() {
        assert_eq!(MAX_ACCOUNT_CREDENTIALS, 9);
    }

    #[test]
    fn account_credentials_payload_matches_sdk_request() {
        let fields = conversation_params_fields("call-id", "session-key");
        assert_eq!(
            form(&fields),
            "conversationId=call-id&method=vchat.getConversationParams&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=session-key"
        );
    }

    #[test]
    fn chained_api_error_exposes_code_and_message() {
        let error = check_api_error(&serde_json::json!({
            "error": {"error_code": 951, "error_msg": "Call not found"}
        }))
        .context("vchat.getConversationParams #1")
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "vchat.getConversationParams #1: API 951: Call not found"
        );
    }

    #[test]
    fn credential_fingerprint_covers_identity_secret_and_endpoints() {
        let credentials = TurnCredentials {
            username: Arc::from("user-a"),
            password: Arc::from("secret-a"),
            server_addresses: vec![Arc::from("192.0.2.1:19302")].into(),
        };
        let mut changed = credentials.clone();
        changed.username = Arc::from("user-b");
        assert_ne!(
            credential_fingerprint(&credentials),
            credential_fingerprint(&changed)
        );
        changed = credentials.clone();
        changed.password = Arc::from("secret-b");
        assert_ne!(
            credential_fingerprint(&credentials),
            credential_fingerprint(&changed)
        );
        changed = credentials.clone();
        changed.server_addresses = vec![Arc::from("192.0.2.2:19302")].into();
        assert_ne!(
            credential_fingerprint(&credentials),
            credential_fingerprint(&changed)
        );
    }
}
