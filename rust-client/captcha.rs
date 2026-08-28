// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::profiles::{Profile, SavedProfile};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use primp::{Client, Method, header};
use rand::RngExt;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

const API_VERSION: &str = "5.131";
const SCRIPT_VERSION: &str = "1.1.1370";
const DEVICE_INFO: &str = r#"{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":970,"devicePixelRatio":1,"language":"ru-RU","languages":["ru-RU","ru","en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"default"}"#;
static POW_INPUT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"const\s+powInput\s*=\s*["']([^"']+)["']"#).ok());
static POW_DIFFICULTY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"const\s+difficulty\s*=\s*(\d+)").ok());
static POW_OBFUSCATED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"["']([A-Za-z0-9+/=_-]{6,})["']\s*,\s*(\d+)\s*,\s*["'](?:pow_timeout|pow[a-zA-Z0-9_-]*)["']"#).ok()
});
static SCRIPT_SOURCE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"src=["']([^"']*not_robot_captcha[^"']*)["']"#).ok());
static DEBUG_UUID: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"[a-zA-Z0-9_]{6,}:\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']"#).ok()
});
static SCRIPT_VERSION_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"vkid/([0-9.]*)/not_robot_captcha\.js").ok());
static WINDOW_INIT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)window\.init\s*=\s*(\{.*?})\s*;").ok());

#[derive(Debug, Clone)]
pub struct VkCaptchaError {
    pub error_code: i64,
    pub error_msg: String,
    pub captcha_sid: String,
    pub captcha_img: String,
    pub redirect_uri: String,
    pub session_token: String,
    pub captcha_timestamp: String,
    pub captcha_attempt: String,
}

impl VkCaptchaError {
    pub fn from_json(raw: &Value) -> Result<Self> {
        if !raw.is_object() {
            bail!("invalid VK captcha response: {raw}");
        }
        let redirect_uri = string_value(raw.get("redirect_uri"));
        let session_token = Url::parse(&redirect_uri)
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(key, _)| key == "session_token")
                    .map(|(_, value)| value.into_owned())
            })
            .unwrap_or_default();
        Ok(Self {
            error_code: match raw.get("error_code") {
                Some(Value::Number(value)) => value
                    .as_i64()
                    .or_else(|| value.as_f64().map(|value| value as i64))
                    .unwrap_or_default(),
                Some(Value::String(value)) => value.parse().unwrap_or_default(),
                _ => 0,
            },
            error_msg: string_value(raw.get("error_msg")),
            captcha_sid: string_value(raw.get("captcha_sid")),
            captcha_img: string_value(raw.get("captcha_img")),
            redirect_uri,
            session_token,
            captcha_timestamp: string_value(raw.get("captcha_ts")),
            captcha_attempt: string_value(raw.get("captcha_attempt")),
        })
    }
}

impl fmt::Display for VkCaptchaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.error_code != 0 && self.error_code != 14 {
            if self.error_msg.is_empty() {
                return write!(formatter, "VK API error {}", self.error_code);
            }
            return write!(
                formatter,
                "VK API error {}: {}",
                self.error_code, self.error_msg
            );
        }
        if !self.redirect_uri.is_empty() {
            return write!(
                formatter,
                "VK captcha required: redirect_uri, sid={:?}",
                self.captcha_sid
            );
        }
        if !self.captcha_img.is_empty() {
            return write!(
                formatter,
                "VK captcha required: captcha_img, sid={:?}",
                self.captcha_sid
            );
        }
        if !self.captcha_sid.is_empty() {
            return write!(formatter, "VK captcha required: sid={:?}", self.captcha_sid);
        }
        if !self.error_msg.is_empty() {
            return write!(formatter, "VK captcha required: {}", self.error_msg);
        }
        formatter.write_str("VK captcha required")
    }
}

impl std::error::Error for VkCaptchaError {}

#[derive(Debug)]
pub(crate) struct RateLimit;

impl fmt::Display for RateLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("captcha session rate limit reached")
    }
}

impl std::error::Error for RateLimit {}

#[derive(Debug)]
struct BotChallenge;

impl fmt::Display for BotChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("captcha bot challenge")
    }
}

impl std::error::Error for BotChallenge {}

#[derive(Debug)]
struct ShowTypeMismatch(String);

impl fmt::Display for ShowTypeMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "captcha show type mismatch: {}", self.0)
    }
}

impl std::error::Error for ShowTypeMismatch {}

pub struct CaptchaSolver {
    mode: Arc<str>,
    result_tx: mpsc::Sender<String>,
    result_rx: Mutex<mpsc::Receiver<String>>,
    cancel: CancellationToken,
}

impl CaptchaSolver {
    pub fn new(mode: &str, cancel: CancellationToken) -> Arc<Self> {
        let (result_tx, result_rx) = mpsc::channel(1);
        Arc::new(Self {
            mode: Arc::from(match mode.trim().to_ascii_lowercase().as_str() {
                "wv" => "wv",
                "rjs" => "rjs",
                _ => "auto",
            }),
            result_tx,
            result_rx: Mutex::new(result_rx),
            cancel,
        })
    }

    pub fn submit_result(&self, result: String) -> bool {
        self.result_tx.try_send(result).is_ok()
    }

    pub async fn solve(
        &self,
        client: &Client,
        profile: &Profile,
        saved_profile: Option<&SavedProfile>,
        stream_id: usize,
        captcha: &VkCaptchaError,
    ) -> Result<String> {
        match self.mode.as_ref() {
            "wv" => {
                crate::log_error!("[STREAM {stream_id}] [КАПЧА] WBV: режим из настроек Android");
                self.webview(stream_id, captcha, "selected", Duration::from_secs(120))
                    .await
            }
            "rjs" => {
                crate::log_error!("[STREAM {stream_id}] [КАПЧА] RJS: Rust v2 выбран в настройках");
                match self
                    .solve_attempts(client, profile, saved_profile, captcha, 2)
                    .await
                {
                    Ok(token) => Ok(token),
                    Err(error) => {
                        crate::log_error!(
                            "[STREAM {stream_id}] [КАПЧА] RJS: ошибка, fallback на WBV Auto: {error}"
                        );
                        self.webview(stream_id, captcha, "auto", Duration::from_secs(10))
                            .await
                    }
                }
            }
            _ => {
                self.solve_auto(client, profile, saved_profile, stream_id, captcha)
                    .await
            }
        }
    }

    async fn solve_auto(
        &self,
        client: &Client,
        profile: &Profile,
        saved_profile: Option<&SavedProfile>,
        stream_id: usize,
        captcha: &VkCaptchaError,
    ) -> Result<String> {
        crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: старт цепочки");
        match self
            .solve_attempts(client, profile, saved_profile, captcha, 2)
            .await
        {
            Ok(token) => {
                crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: Rust v2 решил капчу");
                return Ok(token);
            }
            Err(error) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [КАПЧА] AUTO: Rust v2 не решил за 2 попытки: {error}"
                );
                error
            }
        };
        for attempt in 1..=2 {
            crate::log_error!(
                "[STREAM {stream_id}] [КАПЧА] AUTO: WBV Auto попытка {attempt}/2 (timeout 10s)"
            );
            match self
                .webview(stream_id, captcha, "auto", Duration::from_secs(10))
                .await
            {
                Ok(token) => {
                    crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: WBV Auto решил капчу");
                    return Ok(token);
                }
                Err(error) => {
                    crate::log_error!(
                        "[STREAM {stream_id}] [КАПЧА] AUTO: WBV Auto ошибка {attempt}/2: {error}"
                    );
                }
            }
            let delay = rand::rng().random_range(250..500);
            tokio::select! {
                _ = self.cancel.cancelled() => bail!("captcha cancelled"),
                _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
            }
        }
        crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: финальная Rust v2 попытка после WBV");
        let last_error = match self
            .solve_attempts(client, profile, saved_profile, captcha, 1)
            .await
        {
            Ok(token) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [КАПЧА] AUTO: финальная Rust v2 решила капчу"
                );
                return Ok(token);
            }
            Err(error) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [КАПЧА] AUTO: финальная Rust v2 ошибка: {error}"
                );
                error
            }
        };
        crate::log_error!(
            "[STREAM {stream_id}] [КАПЧА] AUTO: автоцепочка не прошла, открыт ручной WebView"
        );
        self.webview(stream_id, captcha, "manual", Duration::from_secs(60))
            .await
            .with_context(|| {
                format!("automatic captcha chain failed: {last_error}; manual fallback failed")
            })
    }

    async fn webview(
        &self,
        stream_id: usize,
        captcha: &VkCaptchaError,
        mode: &str,
        timeout: Duration,
    ) -> Result<String> {
        if captcha.redirect_uri.is_empty() || captcha.session_token.is_empty() {
            bail!("webview captcha data is incomplete");
        }
        let mut receiver = self.result_rx.lock().await;
        while receiver.try_recv().is_ok() {}
        crate::log_output!(
            "CAPTCHA_SOLVE|{mode}|{}|{}",
            captcha.redirect_uri,
            captcha.session_token
        );
        let result = tokio::select! {
            _ = self.cancel.cancelled() => bail!("webview captcha cancelled"),
            result = tokio::time::timeout(timeout, receiver.recv()) => {
                result
                    .map_err(|_| anyhow!("webview captcha timed out"))?
                    .ok_or_else(|| anyhow!("webview captcha result channel closed"))?
            }
        };
        let result = result.trim();
        if result.is_empty() {
            bail!("webview captcha returned empty result");
        }
        let lower = result.to_ascii_lowercase();
        if lower == "error:timeout" {
            bail!("webview captcha timed out");
        }
        if lower.starts_with("error:") {
            bail!("webview captcha failed: {result}");
        }
        crate::log_error!("[STREAM {stream_id}] [КАПЧА] WBV: {mode} solve succeeded");
        Ok(result.to_owned())
    }

    async fn solve_attempts(
        &self,
        client: &Client,
        profile: &Profile,
        saved_profile: Option<&SavedProfile>,
        captcha: &VkCaptchaError,
        attempts: usize,
    ) -> Result<String> {
        if captcha.session_token.is_empty() {
            bail!("no session_token in redirect_uri");
        }
        crate::log_error!(
            "[КАПЧА] Решаю VK Smart Captcha автоматически (v2, попыток={attempts})..."
        );
        let session = CaptchaSession {
            client,
            profile,
            saved_profile,
            cancel: self.cancel.clone(),
        };
        let mut last_error = None;
        for attempt in 1..=attempts {
            match session.solve_once(captcha).await {
                Ok(token) => return Ok(token),
                Err(error) => {
                    crate::log_error!("[КАПЧА] v2 попытка {attempt} ошибка: {error}");
                    if error.downcast_ref::<RateLimit>().is_some() {
                        crate::log_error!(
                            "[КАПЧА] Превышен лимит сессии капчи. Ожидаю 5 секунд..."
                        );
                        tokio::select! {
                            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        }
                    } else {
                        let delay = 1500 + rand::rng().random_range(0..1200);
                        tokio::select! {
                            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
                            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
                        }
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("v2 captcha attempts exhausted ({attempts})")))
    }
}

pub(crate) struct CaptchaSession<'a> {
    client: &'a Client,
    profile: &'a Profile,
    saved_profile: Option<&'a SavedProfile>,
    cancel: CancellationToken,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CaptchaInit {
    data: CaptchaInitData,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CaptchaInitData {
    show_captcha_type: String,
    captcha_settings: Vec<CaptchaSetting>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CaptchaSetting {
    #[serde(rename = "type")]
    kind: String,
    settings: String,
    settings_key: String,
}

struct CaptchaPage {
    pow_input: String,
    pow_difficulty: usize,
    script_url: String,
    init: Option<CaptchaInit>,
    debug_info: String,
}

struct CaptchaCheck {
    status: String,
    success_token: String,
    show_type: String,
}

impl CaptchaSession<'_> {
    async fn solve_once(&self, captcha: &VkCaptchaError) -> Result<String> {
        crate::log_error!("[КАПЧА] solveOnce URL: {}", captcha.redirect_uri);
        if std::env::var_os("ONLY_PRINT_URL").is_some() {
            bail!("ONLY_PRINT_URL active, skipping solve");
        }
        let html = self.fetch_html(&captcha.redirect_uri).await?;
        let mut page = parse_page(&html)?;
        if !page.script_url.starts_with("http://") && !page.script_url.starts_with("https://") {
            if let Ok(base) = Url::parse(&captcha.redirect_uri) {
                page.script_url = base
                    .join(&page.script_url)
                    .map(|url| url.to_string())
                    .unwrap_or_else(|_| format!("https://id.vk.com{}", page.script_url));
            } else {
                page.script_url = format!("https://id.vk.com{}", page.script_url);
            }
        }
        if page.pow_input.is_empty() {
            bail!("failed to find PoW settings");
        }
        crate::log_error!("[КАПЧА] v2 solving pow difficulty={}", page.pow_difficulty);
        let input = page.pow_input.clone();
        let difficulty = page.pow_difficulty;
        let cancel = self.cancel.clone();
        let hash = crate::cpu_task::run("csqtt-captcha-pow", move || {
            solve_pow(&input, difficulty, &cancel)
        })
        .await?;
        crate::log_error!("[КАПЧА] v2 pow solved");
        let base = base_values(&captcha.session_token);
        self.request("captchaNotRobot.settings", &base)
            .await
            .context("captcha settings failed")?;
        let browser_fp = self
            .saved_profile
            .filter(|saved| !saved.browser_fp.trim().is_empty())
            .map(|saved| saved.browser_fp.clone())
            .unwrap_or_else(|| hex::encode(rand::rng().random::<[u8; 16]>()));
        if let Some(captures) = SCRIPT_VERSION_RE
            .as_ref()
            .and_then(|regex| regex.captures(&page.script_url))
        {
            let latest = &captures[1];
            if latest != SCRIPT_VERSION {
                crate::log_error!(
                    "[КАПЧА] v2 script version drift: known={SCRIPT_VERSION} latest={latest}"
                );
            }
        }
        let debug_info = if page.debug_info.is_empty() {
            let value = Uuid::new_v4().to_string();
            crate::log_error!(
                "[КАПЧА] debug_info UUID не найден в HTML, сгенерирован fallback: {value}"
            );
            value
        } else {
            page.debug_info
        };
        let (mut show_type, mut slider_settings) = initial_captcha_state(page.init);
        if show_type.is_empty() {
            let domain = Url::parse(&captcha.redirect_uri)
                .ok()
                .and_then(|url| {
                    url.query_pairs()
                        .find(|(key, _)| key == "domain")
                        .map(|(_, value)| value.into_owned())
                })
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "vk.com".to_owned());
            match self
                .request(
                    "captchaNotRobot.initSession",
                    &[
                        ("session_token", captcha.session_token.as_str()),
                        ("domain", domain.as_str()),
                        ("lang", "0"),
                    ],
                )
                .await
            {
                Ok(value) => {
                    if let Some(response) = value.get("response") {
                        show_type = string_value(response.get("show_captcha_type"));
                        if let Some(settings) =
                            response.get("content_settings").and_then(Value::as_array)
                        {
                            for setting in settings {
                                if string_value(setting.get("type")) == "slider" {
                                    slider_settings = string_value(setting.get("settings"));
                                    if slider_settings.is_empty() {
                                        slider_settings = string_value(setting.get("settings_key"));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(error) => crate::log_error!("[КАПЧА] Ошибка вызова initSession: {error}"),
            }
        }
        loop {
            crate::log_error!("[КАПЧА] v2 solving show_type={show_type}");
            let solved = match show_type.as_str() {
                "slider" => {
                    self.solve_slider(
                        &captcha.session_token,
                        &browser_fp,
                        &hash,
                        &slider_settings,
                        &debug_info,
                    )
                    .await
                }
                "checkbox" | "" => {
                    self.solve_checkbox(&captcha.session_token, &browser_fp, &hash, &debug_info)
                        .await
                }
                _ => bail!("unsupported captcha type: {show_type}"),
            };
            match solved {
                Ok(token) => {
                    if let Err(error) = self.request("captchaNotRobot.endSession", &base).await {
                        crate::log_error!("[КАПЧА] v2 endSession failed: {error}");
                    }
                    return Ok(token);
                }
                Err(error)
                    if error.downcast_ref::<BotChallenge>().is_some()
                        && show_type != "slider"
                        && !slider_settings.is_empty() =>
                {
                    crate::log_error!("[КАПЧА] v2 checkbox returned BOT, trying slider");
                    show_type = "slider".to_owned();
                }
                Err(error) => {
                    if let Some(mismatch) = error.downcast_ref::<ShowTypeMismatch>()
                        && !mismatch.0.is_empty()
                    {
                        show_type = mismatch.0.clone();
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    async fn fetch_html(&self, endpoint: &str) -> Result<String> {
        let body = self
            .raw(
                Method::GET,
                endpoint,
                None,
                &[
                    (
                        "accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ),
                    ("sec-fetch-dest", "document"),
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-site", "cross-site"),
                ],
            )
            .await?;
        String::from_utf8(body.to_vec()).context("captcha HTML is not UTF-8")
    }

    async fn request(&self, method: &str, values: &[(&str, &str)]) -> Result<Value> {
        let endpoint = format!("https://api.vk.ru/method/{method}?v={API_VERSION}");
        let body = self
            .raw(
                Method::POST,
                &endpoint,
                Some(values),
                &[
                    ("origin", "https://id.vk.com"),
                    ("referer", "https://id.vk.com/"),
                    ("priority", "u=1, i"),
                ],
            )
            .await?;
        serde_json::from_slice(&body).context("captcha api decode")
    }

    async fn raw(
        &self,
        method: Method,
        endpoint: &str,
        form: Option<&[(&str, &str)]>,
        extra: &[(&str, &str)],
    ) -> Result<bytes::Bytes> {
        let mut headers = header::HeaderMap::with_capacity(18);
        if !self.profile.user_agent.is_empty() {
            headers.insert(
                header::USER_AGENT,
                header::HeaderValue::from_str(&self.profile.user_agent)?,
            );
        }
        if !self.profile.sec_ch_ua.is_empty() {
            insert_header(&mut headers, "sec-ch-ua", &self.profile.sec_ch_ua)?;
        }
        if !self.profile.sec_ch_ua_mobile.is_empty() {
            insert_header(
                &mut headers,
                "sec-ch-ua-mobile",
                &self.profile.sec_ch_ua_mobile,
            )?;
        }
        if !self.profile.sec_ch_ua_platform.is_empty() {
            insert_header(
                &mut headers,
                "sec-ch-ua-platform",
                &self.profile.sec_ch_ua_platform,
            )?;
        }
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("*/*"));
        headers.insert(
            header::ACCEPT_LANGUAGE,
            header::HeaderValue::from_static("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"),
        );
        headers.insert("dnt", header::HeaderValue::from_static("1"));
        headers.insert(
            "sec-fetch-site",
            header::HeaderValue::from_static("same-site"),
        );
        headers.insert("sec-fetch-mode", header::HeaderValue::from_static("cors"));
        headers.insert("sec-fetch-dest", header::HeaderValue::from_static("empty"));
        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://vk.com"),
        );
        headers.insert(
            header::REFERER,
            header::HeaderValue::from_static("https://vk.com/"),
        );
        for (name, value) in extra {
            insert_header(&mut headers, name, value)?;
        }
        let mut request = self.client.request(method, endpoint).headers(headers);
        if let Some(values) = form {
            request = request
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(encode_form(values));
        }
        let response = request.send().await?;
        response.bytes().await.map_err(Into::into)
    }

    async fn perform_check(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        answer: &str,
        cursor: &str,
        debug_info: &str,
    ) -> Result<CaptchaCheck> {
        let encoded_answer = STANDARD.encode(answer);
        let response = self
            .request(
                "captchaNotRobot.check",
                &[
                    ("session_token", session_token),
                    ("domain", "vk.com"),
                    ("adFp", ""),
                    ("accelerometer", "[]"),
                    ("gyroscope", "[]"),
                    ("motion", "[]"),
                    ("cursor", cursor),
                    ("taps", "[]"),
                    ("connectionRtt", "[]"),
                    ("connectionDownlink", "[]"),
                    ("browser_fp", browser_fp),
                    ("hash", hash),
                    ("answer", &encoded_answer),
                    ("debug_info", debug_info),
                    ("access_token", ""),
                ],
            )
            .await
            .context("captcha check failed")?;
        let raw = response
            .get("response")
            .ok_or_else(|| anyhow!("invalid captcha check response: {response}"))?;
        let check = CaptchaCheck {
            status: string_value(raw.get("status")),
            success_token: string_value(raw.get("success_token")),
            show_type: string_value(raw.get("show_captcha_type")),
        };
        if check.status.is_empty() {
            bail!("captcha check status missing: {response}");
        }
        if check.show_type.is_empty() {
            crate::log_error!("[КАПЧА] v2 check status={}", check.status);
        } else {
            crate::log_error!(
                "[КАПЧА] v2 check status={} show_type={}",
                check.status,
                check.show_type
            );
        }
        Ok(check)
    }

    async fn solve_checkbox(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        debug_info: &str,
    ) -> Result<String> {
        let device = self
            .saved_profile
            .filter(|saved| !saved.device_json.trim().is_empty())
            .map(|saved| saved.device_json.as_str())
            .unwrap_or(DEVICE_INFO);
        self.request(
            "captchaNotRobot.componentDone",
            &[
                ("session_token", session_token),
                ("domain", "vk.com"),
                ("adFp", ""),
                ("browser_fp", browser_fp),
                ("device", device),
                ("access_token", ""),
            ],
        )
        .await
        .context("captcha componentDone failed")?;
        let delay = rand::rng().random_range(400..650);
        tokio::select! {
            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
        }
        let check = self
            .perform_check(session_token, browser_fp, hash, "{}", "[]", debug_info)
            .await?;
        if !check.show_type.is_empty() && !check.show_type.eq_ignore_ascii_case("checkbox") {
            return Err(ShowTypeMismatch(check.show_type).into());
        }
        if check.status.eq_ignore_ascii_case("error_limit") {
            return Err(RateLimit.into());
        }
        if check.status.eq_ignore_ascii_case("bot") {
            return Err(BotChallenge.into());
        }
        if !check.status.eq_ignore_ascii_case("ok") {
            bail!("checkbox captcha rejected: status={}", check.status);
        }
        if check.success_token.is_empty() {
            bail!("captcha success token not found");
        }
        Ok(check.success_token)
    }

    async fn solve_slider(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        settings: &str,
        debug_info: &str,
    ) -> Result<String> {
        crate::captcha_slider::solve_slider(
            self,
            session_token,
            browser_fp,
            hash,
            settings,
            debug_info,
        )
        .await
    }
}

fn parse_page(html: &str) -> Result<CaptchaPage> {
    let init: Option<CaptchaInit> = match extract_window_init(html) {
        Ok(raw) => Some(serde_json::from_str(&raw).context("captcha init json parse")?),
        Err(_) => WINDOW_INIT
            .as_ref()
            .and_then(|regex| regex.captures(html))
            .and_then(|captures| serde_json::from_str(&captures[1]).ok()),
    };
    let debug_info = DEBUG_UUID
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .map(|captures| captures[1].to_owned())
        .unwrap_or_default();
    let script_url = SCRIPT_SOURCE
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .map(|captures| captures[1].to_owned())
        .unwrap_or_else(|| "https://id.vk.com/js/api/oauth.js".to_owned());
    let mut pow_input = POW_INPUT
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .map(|captures| captures[1].to_owned())
        .unwrap_or_default();
    let mut pow_difficulty = POW_DIFFICULTY
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .and_then(|captures| captures[1].parse().ok())
        .unwrap_or_default();
    if pow_input.is_empty()
        && let Some(captures) = POW_OBFUSCATED
            .as_ref()
            .and_then(|regex| regex.captures(html))
    {
        pow_input = captures[1].to_owned();
        pow_difficulty = captures[2].parse().unwrap_or(4);
    }
    if let Some(init) = &init
        && pow_input.is_empty()
        && let Some(setting) = init
            .data
            .captcha_settings
            .iter()
            .find(|setting| setting.kind == "pow")
    {
        pow_input = if setting.settings.is_empty() {
            setting.settings_key.clone()
        } else {
            setting.settings.clone()
        };
    }
    if !pow_input.is_empty() && pow_difficulty == 0 {
        pow_difficulty = 4;
    }
    Ok(CaptchaPage {
        pow_input,
        pow_difficulty,
        script_url,
        init,
        debug_info,
    })
}

fn initial_captcha_state(init: Option<CaptchaInit>) -> (String, String) {
    let Some(init) = init else {
        return (String::new(), String::new());
    };
    let mut slider_settings = String::new();
    for setting in init.data.captcha_settings {
        if setting.kind == "slider" {
            slider_settings = setting.settings;
        }
    }
    (init.data.show_captcha_type, slider_settings)
}

fn extract_window_init(html: &str) -> Result<String> {
    let token = html
        .find("window.init")
        .ok_or_else(|| anyhow!("window.init token not found"))?;
    let start = html[token + "window.init".len()..]
        .find('{')
        .map(|offset| token + "window.init".len() + offset)
        .ok_or_else(|| anyhow!("captcha init json start brace not found"))?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, character) in html[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
        } else if character == '{' {
            depth += 1;
        } else if character == '}' {
            depth -= 1;
            if depth == 0 {
                return Ok(html[start..=start + offset].to_owned());
            }
        }
    }
    bail!("unbalanced braces in captcha init json")
}

// Difficulty comes from server HTML; a hostile value would otherwise build a
// multi-megabyte target string before burning the full nonce range.
const MAX_POW_DIFFICULTY: usize = 8;

fn hash_meets_target(digest: &[u8], difficulty: usize) -> bool {
    // Hex target is `difficulty` leading '0' chars == that many leading
    // zero bits (high nibble first), checked without per-nonce allocation.
    let full_bytes = difficulty / 2;
    if digest[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    difficulty.is_multiple_of(2) || digest[full_bytes] & 0xF0 == 0
}

fn solve_pow(input: &str, difficulty: usize, cancel: &CancellationToken) -> Result<String> {
    std::thread::sleep(Duration::from_millis(rand::rng().random_range(200..500)));
    if input.is_empty() || difficulty == 0 {
        bail!("captcha pow failed");
    }
    if difficulty > MAX_POW_DIFFICULTY {
        bail!("captcha pow difficulty too high: {difficulty}");
    }
    let mut source = Vec::with_capacity(input.len() + 8);
    for nonce in 0..=10_000_000u32 {
        if nonce % 4096 == 0 && cancel.is_cancelled() {
            bail!("captcha pow cancelled");
        }
        source.clear();
        source.extend_from_slice(input.as_bytes());
        source.extend_from_slice(nonce.to_string().as_bytes());
        let digest = Sha256::digest(&source);
        if hash_meets_target(&digest, difficulty) {
            return Ok(hex::encode(digest));
        }
    }
    bail!("captcha pow failed")
}

fn base_values(session_token: &str) -> Vec<(&str, &str)> {
    vec![
        ("session_token", session_token),
        ("domain", "vk.com"),
        ("adFp", ""),
        ("access_token", ""),
    ]
}

fn encode_form(values: &[(&str, &str)]) -> String {
    let mut output = String::new();
    for (index, (key, value)) in values.iter().enumerate() {
        if index != 0 {
            output.push('&');
        }
        encode_component(&mut output, key);
        output.push('=');
        encode_component(&mut output, value);
    }
    output
}

fn encode_component(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
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
}

fn insert_header(headers: &mut header::HeaderMap, name: &str, value: &str) -> Result<()> {
    headers.insert(
        header::HeaderName::from_bytes(name.as_bytes())?,
        header::HeaderValue::from_str(value)?,
    );
    Ok(())
}

fn string_value(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(value) => value.to_string(),
    }
}

pub(crate) fn response_object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .get("response")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("invalid slider content response: {value}"))
}

pub(crate) fn device_info(saved: Option<&SavedProfile>) -> &str {
    saved
        .filter(|profile| !profile.device_json.trim().is_empty())
        .map(|profile| profile.device_json.as_str())
        .unwrap_or(DEVICE_INFO)
}

pub(crate) fn value_string(value: Option<&Value>) -> String {
    string_value(value)
}

pub(crate) async fn slider_request<'a>(
    session: &CaptchaSession<'a>,
    method: &str,
    values: &[(&str, &str)],
) -> Result<Value> {
    session.request(method, values).await
}

pub(crate) async fn slider_check<'a>(
    session: &CaptchaSession<'a>,
    session_token: &str,
    browser_fp: &str,
    hash: &str,
    answer: &str,
    cursor: &str,
    debug_info: &str,
) -> Result<(String, String)> {
    let check = session
        .perform_check(session_token, browser_fp, hash, answer, cursor, debug_info)
        .await?;
    Ok((check.status, check.success_token))
}

pub(crate) fn slider_saved_profile<'a>(session: &CaptchaSession<'a>) -> Option<&'a SavedProfile> {
    session.saved_profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_balanced_window_init() {
        let html = r#"<script>window.init = {"data":{"text":"}"},"next":{"x":1}};</script>"#;
        assert_eq!(
            extract_window_init(html).unwrap(),
            r#"{"data":{"text":"}"},"next":{"x":1}}"#
        );
    }

    #[test]
    fn preserves_form_order_and_escaping() {
        assert_eq!(
            encode_form(&[("a", "x y*~"), ("b", "тест")]),
            "a=x+y%2A~&b=%D1%82%D0%B5%D1%81%D1%82"
        );
    }

    #[test]
    fn parses_captcha_error_numbers() {
        let error = VkCaptchaError::from_json(&serde_json::json!({
            "error_code": 14,
            "captcha_sid": 123,
            "captcha_ts": 99,
            "redirect_uri": "https://id.vk.com/captcha?session_token=abc"
        }))
        .unwrap();
        assert_eq!(error.captcha_sid, "123");
        assert_eq!(error.captcha_timestamp, "99");
        assert_eq!(error.session_token, "abc");
    }

    #[test]
    fn accepts_partial_window_init_like_go_json() {
        let html = r#"<script>window.init={"data":{"captcha_settings":[{"type":"pow","settings_key":"pow-value"},{"type":"slider","settings":"slider-value"}]}};</script>"#;
        let page = parse_page(html).unwrap();
        assert_eq!(page.pow_input, "pow-value");
        assert_eq!(page.pow_difficulty, 4);
        let (show_type, settings) = initial_captcha_state(page.init);
        assert_eq!(show_type, "");
        assert_eq!(settings, "slider-value");
    }

    #[test]
    fn slider_init_uses_settings_not_settings_key() {
        let init = serde_json::from_value(serde_json::json!({
            "data": {
                "show_captcha_type": "slider",
                "captcha_settings": [{"type": "slider", "settings_key": "key"}]
            }
        }))
        .unwrap();
        let (show_type, settings) = initial_captcha_state(Some(init));
        assert_eq!(show_type, "slider");
        assert_eq!(settings, "");
    }

    #[test]
    fn parses_obfuscated_pow_settings() {
        let html = r#"<script>(function(_0x1be24c,_0x543e3e,_0x23e37e){})("qEM5I4OpTkTmPKFL",2,"pow_timeout");</script>"#;
        let page = parse_page(html).unwrap();
        assert_eq!(page.pow_input, "qEM5I4OpTkTmPKFL");
        assert_eq!(page.pow_difficulty, 2);
    }

    #[test]
    fn invalid_balanced_window_init_is_not_silently_ignored() {
        assert!(parse_page(r#"<script>window.init={"data":]};</script>"#).is_err());
    }
}
