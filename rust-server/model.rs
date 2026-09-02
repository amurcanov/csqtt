// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_PASSWORDS: usize = 20;
pub const PASSWORD_LEN: usize = 16;
pub const PASS_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
pub const DEFAULT_AUTO_RESTART_INTERVAL_HOURS: u8 = 0;
static DATABASE_SAVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientDevice {
    pub device_id: String,
    pub ip: String,
    pub priv_key: String,
    pub pub_key: String,
    pub up_bytes: i64,
    pub down_bytes: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordEntry {
    pub device_id: String,
    pub expires_at: i64,
    pub down_bytes: i64,
    pub up_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vk_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ports: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_deactivated: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vk_hashes: String,
    pub dtls_port: u16,
    pub wg_port: u16,
    pub local_port: u16,
}

pub const DEFAULT_LOCAL_PROXY_PORT: u16 = 45000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProxyProfile {
    pub id: String,
    pub name: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

impl LocalProxyProfile {
    pub fn new_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LocalProxyState {
    pub active_profile_id: String,
    pub profiles: Vec<LocalProxyProfile>,
}

impl LocalProxyState {
    pub fn normalize(&mut self) {
        for profile in &mut self.profiles {
            if profile.port == 0 {
                profile.port = DEFAULT_LOCAL_PROXY_PORT;
            }
        }
        if !self.active_profile_id.is_empty()
            && !self.profiles.iter().any(|p| p.id == self.active_profile_id)
        {
            self.active_profile_id.clear();
        }
    }

    pub fn active_profile(&self) -> Option<&LocalProxyProfile> {
        if self.active_profile_id.is_empty() {
            return None;
        }
        self.profiles
            .iter()
            .find(|p| p.id == self.active_profile_id)
    }

    pub fn find_profile(&self, id: &str) -> Option<&LocalProxyProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn find_profile_mut(&mut self, id: &str) -> Option<&mut LocalProxyProfile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    pub fn remove_profile(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.active_profile_id == id {
            self.active_profile_id.clear();
        }
        self.profiles.len() < before
    }
}

impl<'de> serde::Deserialize<'de> for LocalProxyState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(profiles) = value.get("profiles") {
            let active_profile_id = value
                .get("active_profile_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let profiles: Vec<LocalProxyProfile> =
                serde_json::from_value(profiles.clone()).unwrap_or_default();
            Ok(Self {
                active_profile_id,
                profiles,
            })
        } else if value.is_object() && value.get("port").is_some() {
            let enabled = value
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let port = value
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_LOCAL_PROXY_PORT as u64) as u16;
            let username = value
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let id = LocalProxyProfile::new_id();
            let profile = LocalProxyProfile {
                id: id.clone(),
                name: format!("SOCKS5 :{port}"),
                port: if port == 0 {
                    DEFAULT_LOCAL_PROXY_PORT
                } else {
                    port
                },
                username,
                password,
            };
            Ok(Self {
                active_profile_id: if enabled { id } else { String::new() },
                profiles: vec![profile],
            })
        } else {
            Ok(Self::default())
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    pub main_password: String,
    #[serde(default)]
    pub main_device_id: String,
    pub dns: String,
    /// `None` is the pre-setting database format and deliberately means the
    /// default disabled interval. `Some(0)` explicitly disables restarts.
    #[serde(default)]
    pub auto_restart_interval_hours: Option<u8>,
    pub main_up_bytes: i64,
    pub main_down_bytes: i64,
    pub admin_id: String,
    pub bot_token: String,
    pub passwords: BTreeMap<String, PasswordEntry>,
    pub devices: BTreeMap<String, ClientDevice>,
    pub web_sessions: BTreeMap<String, i64>,
    pub logging_active: Option<bool>,
    #[serde(default)]
    pub local_proxy: LocalProxyState,
}

/// Absolute traffic counters captured while the in-memory database lock is
/// held.  They are intentionally absolute rather than deltas: several
/// pending flushes may be coalesced without losing a counter increment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficCounters {
    pub up_bytes: i64,
    pub down_bytes: i64,
}

/// The small, high-frequency portion of the database that changes while
/// sessions transfer traffic.  Keeping it separate from a full `Database`
/// snapshot prevents the five-second traffic flush from cloning and rewriting
/// credentials, keys, profiles, and devices that did not change.
#[derive(Debug, Default)]
pub struct TrafficSnapshot {
    pub main: Option<TrafficCounters>,
    pub passwords: BTreeMap<String, TrafficCounters>,
    pub devices: BTreeMap<String, TrafficCounters>,
}

impl TrafficSnapshot {
    fn merge_from(&mut self, mut newer: Self) {
        if newer.main.is_some() {
            self.main = newer.main;
        }
        self.passwords.append(&mut newer.passwords);
        self.devices.append(&mut newer.devices);
    }

    fn is_empty(&self) -> bool {
        self.main.is_none() && self.passwords.is_empty() && self.devices.is_empty()
    }
}

impl Database {
    pub fn auto_restart_interval_hours(&self) -> u8 {
        self.auto_restart_interval_hours
            .unwrap_or(DEFAULT_AUTO_RESTART_INTERVAL_HOURS)
    }

    pub fn set_auto_restart_interval_hours(&mut self, hours: u8) {
        self.auto_restart_interval_hours = Some(hours);
    }

    pub fn repair_stale_password_bindings(&mut self) -> bool {
        let mut changed = false;
        let devices = &self.devices;
        for entry in self.passwords.values_mut() {
            if !entry.device_id.is_empty() && !devices.contains_key(&entry.device_id) {
                entry.device_id.clear();
                changed = true;
            }
        }
        changed
    }
}

#[derive(Clone)]
pub struct DatabasePersistence {
    inner: Arc<DatabasePersistenceInner>,
}

struct DatabasePersistenceInner {
    config_dir: PathBuf,
    state: Mutex<DatabasePersistenceState>,
    queue_ready: Condvar,
    notify: tokio::sync::Notify,
}

#[derive(Default)]
struct DatabasePersistenceState {
    queue: PersistenceQueue,
    last_error: Option<String>,
}

#[derive(Debug)]
enum PersistenceUpdate {
    Snapshot(Database),
    Traffic(TrafficSnapshot),
}

#[derive(Default)]
struct PersistenceQueue {
    next_revision: u64,
    processed_revision: u64,
    successful_revision: u64,
    pending: VecDeque<(u64, PersistenceUpdate)>,
    worker_running: bool,
}

impl PersistenceQueue {
    fn next_revision(&mut self) -> u64 {
        self.next_revision = self.next_revision.saturating_add(1);
        self.next_revision
    }

    fn submit_snapshot(&mut self, snapshot: Database) -> (u64, bool) {
        let revision = self.next_revision();
        // A snapshot is captured under App.db and therefore already includes
        // all preceding in-memory changes.  Superseding queued work preserves
        // the latest state while bounding memory during a slow disk write.
        self.pending.clear();
        self.pending
            .push_back((revision, PersistenceUpdate::Snapshot(snapshot)));
        let start_worker = !self.worker_running;
        self.worker_running = true;
        (revision, start_worker)
    }

    fn submit_traffic(&mut self, traffic: TrafficSnapshot) -> (u64, bool) {
        let revision = self.next_revision();
        // Traffic updates contain absolute counters.  Merge adjacent updates
        // per entity so a busy server retains one bounded pending operation
        // instead of a growing queue of five-second flushes.
        if let Some((pending_revision, PersistenceUpdate::Traffic(pending))) =
            self.pending.back_mut()
        {
            pending.merge_from(traffic);
            *pending_revision = revision;
        } else {
            self.pending
                .push_back((revision, PersistenceUpdate::Traffic(traffic)));
        }
        let start_worker = !self.worker_running;
        self.worker_running = true;
        (revision, start_worker)
    }

    fn take_pending(&mut self) -> Option<(u64, PersistenceUpdate)> {
        self.pending.pop_front()
    }

    fn complete(&mut self, revision: u64, successful: bool) {
        if revision >= self.processed_revision {
            self.processed_revision = revision;
        }
        if successful && revision >= self.successful_revision {
            self.successful_revision = revision;
        }
    }
}

impl DatabasePersistence {
    pub fn new(config_dir: PathBuf) -> Result<Self> {
        let inner = Arc::new(DatabasePersistenceInner {
            config_dir,
            state: Mutex::new(DatabasePersistenceState::default()),
            queue_ready: Condvar::new(),
            notify: tokio::sync::Notify::new(),
        });
        let worker = inner.clone();
        std::thread::Builder::new()
            .name("csqtt-db-writer".to_owned())
            .spawn(move || database_persistence_worker(worker))
            .context("start database persistence worker")?;
        Ok(Self { inner })
    }

    pub fn submit(&self, snapshot: Database) -> u64 {
        let (revision, _) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.queue.submit_snapshot(snapshot)
        };
        self.inner.queue_ready.notify_one();
        revision
    }

    /// Queue only the counters changed by a traffic flush.  This preserves
    /// ordering with structural snapshots while avoiding a full `Database`
    /// clone on the dataplane's five-second persistence path.
    pub fn submit_traffic(&self, traffic: TrafficSnapshot) -> u64 {
        if traffic.is_empty() {
            return 0;
        }
        let (revision, _) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.queue.submit_traffic(traffic)
        };
        self.inner.queue_ready.notify_one();
        revision
    }

    pub async fn wait(&self, revision: u64) -> Result<()> {
        loop {
            let notified = self.inner.notify.notified();
            let outcome = {
                let state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.queue.successful_revision >= revision {
                    Some(Ok(()))
                } else if state.queue.processed_revision >= revision {
                    Some(Err(anyhow::anyhow!(
                        "{}",
                        state
                            .last_error
                            .as_deref()
                            .unwrap_or("database persistence failed")
                    )))
                } else {
                    None
                }
            };
            if let Some(outcome) = outcome {
                return outcome;
            }
            notified.await;
        }
    }
}

fn database_persistence_worker(inner: Arc<DatabasePersistenceInner>) {
    let mut connection = None;
    loop {
        let (revision, update) = {
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            while state.queue.pending.is_empty() {
                state = inner
                    .queue_ready
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            state.queue.take_pending().expect("pending database update")
        };
        let result = persist_database_update(&inner.config_dir, &mut connection, update);
        let error = result.err().map(|error| format!("{error:#}"));
        if error.is_some() {
            connection = None;
        }
        {
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.queue.complete(revision, error.is_none());
            if let Some(error) = error {
                state.last_error = Some(error);
            } else if state.queue.successful_revision >= revision {
                state.last_error = None;
            }
        }
        inner.notify.notify_waiters();
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

static CACHED_NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline(always)]
pub fn cached_now() -> u64 {
    let cached = CACHED_NOW.load(std::sync::atomic::Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    refresh_cached_now()
}

pub fn refresh_cached_now() -> u64 {
    let ts = now() as u64;
    CACHED_NOW.store(ts, std::sync::atomic::Ordering::Relaxed);
    ts
}

pub fn random_password() -> String {
    let mut data = [0u8; PASSWORD_LEN];
    OsRng.fill_bytes(&mut data);
    data.iter()
        .map(|v| PASS_CHARS[*v as usize % PASS_CHARS.len()] as char)
        .collect()
}

pub fn random_token(size: usize) -> String {
    let mut data = vec![0u8; size];
    OsRng.fill_bytes(&mut data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn derive_wrap_key(password: &str) -> Result<[u8; 32]> {
    if password.is_empty() {
        bail!("empty password");
    }
    let hk = Hkdf::<Sha256>::new(Some(b"CSQTT-WRAP-v1"), password.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"rtp-obfs/chacha20poly1305", &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    Ok(key)
}

pub fn is_expired(entry: &PasswordEntry) -> bool {
    entry.expires_at != 0 && now() > entry.expires_at
}

pub fn get_next_ip(db: &Database) -> Option<String> {
    let mut buf = String::with_capacity(16);
    for i in 2..=250u8 {
        buf.clear();
        use std::fmt::Write;
        let _ = write!(buf, "10.66.67.{i}");
        let is_used = db.devices.values().any(|d| d.ip == buf);
        if !is_used {
            return Some(buf);
        }
    }
    None
}

pub fn resolve_session_ip(
    db: &Database,
    session_password: &str,
    device_id: &str,
) -> Option<String> {
    if !device_id.is_empty()
        && let Some(device) = db.devices.get(device_id)
    {
        return Some(device.ip.clone());
    }
    if session_password != db.main_password
        && let Some(entry) = db.passwords.get(session_password)
        && !entry.device_id.is_empty()
    {
        return db.devices.get(&entry.device_id).map(|d| d.ip.clone());
    }
    None
}

pub fn generate_key_pair() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] = (bytes[31] & 127) | 64;
    let private = StaticSecret::from(bytes);
    let public = PublicKey::from(&private);
    (
        STANDARD.encode(private.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    )
}

const DATABASE_FILE: &str = "csqtt.db";
const LEGACY_DATABASE_FILE: &str = "passwords.json";
const LEGACY_DATABASE_IMPORTED_FILE: &str = "passwords.json.imported";
const LEGACY_DATABASE_FILES: [&str; 2] = [LEGACY_DATABASE_FILE, LEGACY_DATABASE_IMPORTED_FILE];

const DATABASE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    main_up_bytes   INTEGER NOT NULL DEFAULT 0,
    main_down_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS passwords (
    password       TEXT PRIMARY KEY,
    device_id      TEXT    NOT NULL DEFAULT '',
    expires_at     INTEGER NOT NULL DEFAULT 0,
    down_bytes     INTEGER NOT NULL DEFAULT 0,
    up_bytes       INTEGER NOT NULL DEFAULT 0,
    vk_hash        TEXT    NOT NULL DEFAULT '',
    ports          TEXT    NOT NULL DEFAULT '',
    is_deactivated INTEGER NOT NULL DEFAULT 0,
    name           TEXT    NOT NULL DEFAULT '',
    vk_hashes      TEXT    NOT NULL DEFAULT '',
    dtls_port      INTEGER NOT NULL DEFAULT 0,
    wg_port        INTEGER NOT NULL DEFAULT 0,
    local_port     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
    device_id          TEXT PRIMARY KEY,
    ip                 TEXT    NOT NULL,
    priv_key           TEXT    NOT NULL,
    pub_key            TEXT    NOT NULL,
    up_bytes           INTEGER NOT NULL DEFAULT 0,
    down_bytes         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS local_proxy_profiles (
    id         TEXT PRIMARY KEY,
    sort_order INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    port       INTEGER NOT NULL,
    username   TEXT    NOT NULL DEFAULT '',
    password   TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS local_proxy_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    active_profile_id TEXT NOT NULL DEFAULT ''
);
";

fn open_database_connection(config_dir: &Path) -> Result<Connection> {
    fs::create_dir_all(config_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))?;
    }
    let path = config_dir.join(DATABASE_FILE);
    let connection = Connection::open(&path).with_context(|| format!("open {}", path.display()))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .context("enable WAL journal mode")?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .context("set synchronous FULL")?;
    connection
        .execute_batch(DATABASE_SCHEMA)
        .with_context(|| format!("schema {}", path.display()))?;
    Ok(connection)
}

fn existing_row_keys(transaction: &rusqlite::Transaction<'_>, select: &str) -> Result<Vec<String>> {
    let mut statement = transaction
        .prepare(select)
        .with_context(|| format!("prepare {select}"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .with_context(|| format!("query {select}"))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("read {select}"))
}

fn write_database_snapshot(connection: &mut Connection, db: &Database) -> Result<()> {
    let transaction = connection
        .transaction()
        .context("begin database transaction")?;
    let auto_restart_interval_hours = db.auto_restart_interval_hours().to_string();
    for (key, value) in [
        ("main_password", db.main_password.as_str()),
        ("main_device_id", db.main_device_id.as_str()),
        ("dns", db.dns.as_str()),
        (
            "auto_restart_interval_hours",
            auto_restart_interval_hours.as_str(),
        ),
        ("admin_id", db.admin_id.as_str()),
        ("bot_token", db.bot_token.as_str()),
    ] {
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value],
            )
            .context("write meta")?;
    }
    if let Some(active) = db.logging_active {
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES ('logging_active', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![if active { "1" } else { "0" }],
            )
            .context("write logging_active")?;
    } else {
        transaction
            .execute("DELETE FROM meta WHERE key = 'logging_active'", [])
            .context("clear logging_active")?;
    }
    transaction
        .execute(
            "INSERT INTO counters (id, main_up_bytes, main_down_bytes) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                main_up_bytes = excluded.main_up_bytes,
                main_down_bytes = excluded.main_down_bytes",
            rusqlite::params![db.main_up_bytes, db.main_down_bytes],
        )
        .context("write counters")?;
    for password in existing_row_keys(&transaction, "SELECT password FROM passwords")? {
        if !db.passwords.contains_key(&password) {
            transaction
                .execute(
                    "DELETE FROM passwords WHERE password = ?1",
                    rusqlite::params![password],
                )
                .with_context(|| format!("remove password {password}"))?;
        }
    }
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO passwords (
                    password, device_id, expires_at, down_bytes, up_bytes,
                    vk_hash, ports, is_deactivated, name, vk_hashes,
                    dtls_port, wg_port, local_port
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(password) DO UPDATE SET
                    device_id = excluded.device_id,
                    expires_at = excluded.expires_at,
                    down_bytes = excluded.down_bytes,
                    up_bytes = excluded.up_bytes,
                    vk_hash = excluded.vk_hash,
                    ports = excluded.ports,
                    is_deactivated = excluded.is_deactivated,
                    name = excluded.name,
                    vk_hashes = excluded.vk_hashes,
                    dtls_port = excluded.dtls_port,
                    wg_port = excluded.wg_port,
                    local_port = excluded.local_port",
            )
            .context("prepare passwords insert")?;
        for (password, entry) in &db.passwords {
            insert
                .execute(rusqlite::params![
                    password,
                    entry.device_id,
                    entry.expires_at,
                    entry.down_bytes,
                    entry.up_bytes,
                    entry.vk_hash,
                    entry.ports,
                    i64::from(entry.is_deactivated),
                    entry.name,
                    entry.vk_hashes,
                    entry.dtls_port,
                    entry.wg_port,
                    entry.local_port,
                ])
                .with_context(|| format!("write password {}", password))?;
        }
    }
    for device_id in existing_row_keys(&transaction, "SELECT device_id FROM devices")? {
        if !db.devices.contains_key(&device_id) {
            transaction
                .execute(
                    "DELETE FROM devices WHERE device_id = ?1",
                    rusqlite::params![device_id],
                )
                .with_context(|| format!("remove device {device_id}"))?;
        }
    }
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO devices (
                    device_id, ip, priv_key, pub_key, up_bytes, down_bytes
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(device_id) DO UPDATE SET
                    ip = excluded.ip,
                    priv_key = excluded.priv_key,
                    pub_key = excluded.pub_key,
                    up_bytes = excluded.up_bytes,
                    down_bytes = excluded.down_bytes",
            )
            .context("prepare devices insert")?;
        for device in db.devices.values() {
            insert
                .execute(rusqlite::params![
                    device.device_id,
                    device.ip,
                    device.priv_key,
                    device.pub_key,
                    device.up_bytes,
                    device.down_bytes,
                ])
                .with_context(|| format!("write device {}", device.device_id))?;
        }
    }
    for profile_id in existing_row_keys(&transaction, "SELECT id FROM local_proxy_profiles")? {
        if !db
            .local_proxy
            .profiles
            .iter()
            .any(|profile| profile.id == profile_id)
        {
            transaction
                .execute(
                    "DELETE FROM local_proxy_profiles WHERE id = ?1",
                    rusqlite::params![profile_id],
                )
                .with_context(|| format!("remove local proxy profile {profile_id}"))?;
        }
    }
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO local_proxy_profiles (id, sort_order, name, port, username, password)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                    sort_order = excluded.sort_order,
                    name = excluded.name,
                    port = excluded.port,
                    username = excluded.username,
                    password = excluded.password",
            )
            .context("prepare local proxy profiles insert")?;
        for (sort_order, profile) in db.local_proxy.profiles.iter().enumerate() {
            insert
                .execute(rusqlite::params![
                    profile.id,
                    sort_order as i64,
                    profile.name,
                    profile.port,
                    profile.username,
                    profile.password,
                ])
                .context("write local proxy profile")?;
        }
    }
    transaction
        .execute(
            "INSERT INTO local_proxy_state (id, active_profile_id) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET active_profile_id = excluded.active_profile_id",
            rusqlite::params![db.local_proxy.active_profile_id],
        )
        .context("write local proxy state")?;
    transaction
        .commit()
        .context("commit database transaction")?;
    Ok(())
}

fn read_database_snapshot(config_dir: &Path) -> Result<Database> {
    let connection = open_database_connection(config_dir)?;
    let mut db = Database::default();
    {
        let mut meta = connection
            .prepare("SELECT key, value FROM meta")
            .context("prepare meta select")?;
        let mut rows = meta.query([]).context("read meta")?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(0).context("read meta key")?;
            let value: String = row.get(1).context("read meta value")?;
            match key.as_str() {
                "main_password" => db.main_password = value,
                "main_device_id" => db.main_device_id = value,
                "dns" => db.dns = value,
                "auto_restart_interval_hours" => {
                    if let Ok(hours) = value.parse::<u8>() {
                        db.auto_restart_interval_hours = Some(hours);
                    }
                }
                "admin_id" => db.admin_id = value,
                "bot_token" => db.bot_token = value,
                "logging_active" => db.logging_active = Some(value == "1"),
                _ => {}
            }
        }
    }
    if let Ok((up_bytes, down_bytes)) = connection.query_row(
        "SELECT main_up_bytes, main_down_bytes FROM counters WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    ) {
        db.main_up_bytes = up_bytes;
        db.main_down_bytes = down_bytes;
    }
    {
        let mut select = connection
            .prepare(
                "SELECT password, device_id, expires_at, down_bytes, up_bytes,
                        vk_hash, ports, is_deactivated, name, vk_hashes,
                        dtls_port, wg_port, local_port
                 FROM passwords",
            )
            .context("prepare passwords select")?;
        let mut rows = select.query([]).context("read passwords")?;
        while let Some(row) = rows.next()? {
            let password: String = row.get(0).context("read password key")?;
            let entry = PasswordEntry {
                device_id: row.get(1).context("read password device_id")?,
                expires_at: row.get(2).context("read password expires_at")?,
                down_bytes: row.get(3).context("read password down_bytes")?,
                up_bytes: row.get(4).context("read password up_bytes")?,
                vk_hash: row.get(5).context("read password vk_hash")?,
                ports: row.get(6).context("read password ports")?,
                is_deactivated: row
                    .get::<_, i64>(7)
                    .context("read password is_deactivated")?
                    != 0,
                name: row.get(8).context("read password name")?,
                vk_hashes: row.get(9).context("read password vk_hashes")?,
                dtls_port: row.get(10).context("read password dtls_port")?,
                wg_port: row.get(11).context("read password wg_port")?,
                local_port: row.get(12).context("read password local_port")?,
            };
            db.passwords.insert(password, entry);
        }
    }
    {
        let mut select = connection
            .prepare("SELECT device_id, ip, priv_key, pub_key, up_bytes, down_bytes FROM devices")
            .context("prepare devices select")?;
        let mut rows = select.query([]).context("read devices")?;
        while let Some(row) = rows.next()? {
            let device = ClientDevice {
                device_id: row.get(0).context("read device_id")?,
                ip: row.get(1).context("read device ip")?,
                priv_key: row.get(2).context("read device priv_key")?,
                pub_key: row.get(3).context("read device pub_key")?,
                up_bytes: row.get(4).context("read device up_bytes")?,
                down_bytes: row.get(5).context("read device down_bytes")?,
            };
            db.devices.insert(device.device_id.clone(), device);
        }
    }
    {
        let mut select = connection
            .prepare(
                "SELECT id, name, port, username, password
                 FROM local_proxy_profiles ORDER BY sort_order",
            )
            .context("prepare local proxy profiles select")?;
        let mut rows = select.query([]).context("read local proxy profiles")?;
        while let Some(row) = rows.next()? {
            db.local_proxy.profiles.push(LocalProxyProfile {
                id: row.get(0).context("read profile id")?,
                name: row.get(1).context("read profile name")?,
                port: row.get(2).context("read profile port")?,
                username: row.get(3).context("read profile username")?,
                password: row.get(4).context("read profile password")?,
            });
        }
    }
    if let Ok(active_profile_id) = connection.query_row(
        "SELECT active_profile_id FROM local_proxy_state WHERE id = 1",
        [],
        |row| row.get::<_, String>(0),
    ) {
        db.local_proxy.active_profile_id = active_profile_id;
    }
    db.local_proxy.normalize();
    db.bot_token.clear();
    db.admin_id.clear();
    Ok(db)
}

pub fn load_database(config_dir: &Path) -> Result<Database> {
    let _guard = DATABASE_SAVE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let database_exists = config_dir.join(DATABASE_FILE).exists();
    let legacy_paths: Vec<PathBuf> = LEGACY_DATABASE_FILES
        .iter()
        .map(|name| config_dir.join(name))
        .filter(|path| path.exists())
        .collect();
    if database_exists {
        let mut db = read_database_snapshot(config_dir)?;
        repair_loaded_database(config_dir, &mut db)?;
        if !legacy_paths.is_empty() {
            eprintln!(
                "[DB] Ignoring {} retired JSON database file(s); {DATABASE_FILE} is authoritative",
                legacy_paths.len()
            );
        }
        return Ok(db);
    }
    if legacy_paths.is_empty() {
        return Ok(Database::default());
    }

    let mut legacy_databases = Vec::with_capacity(legacy_paths.len());
    for legacy_path in &legacy_paths {
        let data =
            fs::read(legacy_path).with_context(|| format!("read {}", legacy_path.display()))?;
        let mut legacy: Database = serde_json::from_slice(&data)
            .with_context(|| format!("parse {}", legacy_path.display()))?;
        legacy.bot_token.clear();
        legacy.admin_id.clear();
        legacy.web_sessions.clear();
        legacy.local_proxy.normalize();
        legacy_databases.push(legacy);
    }

    let mut connection = open_database_connection(config_dir)?;
    for legacy in &legacy_databases {
        import_legacy_database_rows(&mut connection, legacy)
            .context("commit legacy JSON rows into SQLite")?;
    }
    drop(connection);

    let mut db = read_database_snapshot(config_dir)?;
    for legacy in &legacy_databases {
        verify_legacy_database_rows(&db, legacy)
            .context("verify legacy JSON import into SQLite")?;
    }
    repair_loaded_database(config_dir, &mut db)?;

    for legacy_path in &legacy_paths {
        fs::remove_file(legacy_path)
            .with_context(|| format!("remove retired legacy database {}", legacy_path.display()))?;
    }
    eprintln!(
        "[DB] Imported {} retired JSON database file(s) into {DATABASE_FILE} and removed them",
        legacy_paths.len()
    );
    Ok(db)
}

fn repair_loaded_database(config_dir: &Path, db: &mut Database) -> Result<()> {
    if !db.repair_stale_password_bindings() {
        return Ok(());
    }
    let mut connection = open_database_connection(config_dir)?;
    write_database_snapshot(&mut connection, db)?;
    eprintln!("[DB] Repaired stale password and device bindings in {DATABASE_FILE}");
    Ok(())
}

fn import_legacy_database_rows(connection: &mut Connection, legacy: &Database) -> Result<()> {
    let transaction = connection
        .transaction()
        .context("begin legacy JSON import transaction")?;

    for (key, value) in [
        ("main_password", legacy.main_password.as_str()),
        ("main_device_id", legacy.main_device_id.as_str()),
        ("dns", legacy.dns.as_str()),
    ] {
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value =
                    CASE WHEN meta.value = '' THEN excluded.value ELSE meta.value END",
                rusqlite::params![key, value],
            )
            .with_context(|| format!("merge legacy meta {key}"))?;
    }
    if let Some(active) = legacy.logging_active {
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES ('logging_active', ?1)
                 ON CONFLICT(key) DO NOTHING",
                rusqlite::params![if active { "1" } else { "0" }],
            )
            .context("merge legacy logging_active")?;
    }
    transaction
        .execute(
            "INSERT INTO counters (id, main_up_bytes, main_down_bytes) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                main_up_bytes = MAX(counters.main_up_bytes, excluded.main_up_bytes),
                main_down_bytes = MAX(counters.main_down_bytes, excluded.main_down_bytes)",
            rusqlite::params![legacy.main_up_bytes, legacy.main_down_bytes],
        )
        .context("merge legacy main traffic counters")?;

    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO passwords (
                    password, device_id, expires_at, down_bytes, up_bytes,
                    vk_hash, ports, is_deactivated, name, vk_hashes,
                    dtls_port, wg_port, local_port
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(password) DO NOTHING",
            )
            .context("prepare legacy passwords import")?;
        for (password, entry) in &legacy.passwords {
            insert
                .execute(rusqlite::params![
                    password,
                    entry.device_id,
                    entry.expires_at,
                    entry.down_bytes,
                    entry.up_bytes,
                    entry.vk_hash,
                    entry.ports,
                    i64::from(entry.is_deactivated),
                    entry.name,
                    entry.vk_hashes,
                    entry.dtls_port,
                    entry.wg_port,
                    entry.local_port,
                ])
                .with_context(|| format!("merge legacy password {password}"))?;
        }
    }
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO devices (
                    device_id, ip, priv_key, pub_key, up_bytes, down_bytes
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(device_id) DO NOTHING",
            )
            .context("prepare legacy devices import")?;
        for device in legacy.devices.values() {
            insert
                .execute(rusqlite::params![
                    device.device_id,
                    device.ip,
                    device.priv_key,
                    device.pub_key,
                    device.up_bytes,
                    device.down_bytes,
                ])
                .with_context(|| format!("merge legacy device {}", device.device_id))?;
        }
    }
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO local_proxy_profiles (id, sort_order, name, port, username, password)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO NOTHING",
            )
            .context("prepare legacy proxy profiles import")?;
        for (sort_order, profile) in legacy.local_proxy.profiles.iter().enumerate() {
            insert
                .execute(rusqlite::params![
                    profile.id,
                    sort_order as i64,
                    profile.name,
                    profile.port,
                    profile.username,
                    profile.password,
                ])
                .with_context(|| format!("merge legacy proxy profile {}", profile.id))?;
        }
    }
    if !legacy.local_proxy.active_profile_id.is_empty() {
        transaction
            .execute(
                "INSERT INTO local_proxy_state (id, active_profile_id) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET active_profile_id =
                    CASE WHEN local_proxy_state.active_profile_id = ''
                         THEN excluded.active_profile_id
                         ELSE local_proxy_state.active_profile_id END",
                rusqlite::params![legacy.local_proxy.active_profile_id],
            )
            .context("merge legacy active proxy profile")?;
    }
    transaction
        .commit()
        .context("commit legacy JSON import transaction")?;
    Ok(())
}

fn verify_legacy_database_rows(sqlite: &Database, legacy: &Database) -> Result<()> {
    if !legacy.main_password.is_empty()
        && !sqlite.main_password.is_empty()
        && sqlite.main_password != legacy.main_password
    {
        bail!("legacy main password conflicts with existing SQLite state");
    }
    if !legacy.main_device_id.is_empty()
        && !sqlite.main_device_id.is_empty()
        && sqlite.main_device_id != legacy.main_device_id
    {
        bail!("legacy main device conflicts with existing SQLite state");
    }
    for (password, legacy_entry) in &legacy.passwords {
        let Some(sqlite_entry) = sqlite.passwords.get(password) else {
            bail!("legacy password {password} is missing after import");
        };
        if !legacy_password_matches(sqlite_entry, legacy_entry) {
            bail!("legacy password {password} conflicts with existing SQLite state");
        }
    }
    for (device_id, legacy_device) in &legacy.devices {
        let Some(sqlite_device) = sqlite.devices.get(device_id) else {
            bail!("legacy device {device_id} is missing after import");
        };
        if !legacy_device_matches(sqlite_device, legacy_device) {
            bail!("legacy device {device_id} conflicts with existing SQLite state");
        }
    }
    Ok(())
}

fn legacy_password_matches(sqlite: &PasswordEntry, legacy: &PasswordEntry) -> bool {
    sqlite.device_id == legacy.device_id
        && sqlite.expires_at == legacy.expires_at
        && sqlite.vk_hash == legacy.vk_hash
        && sqlite.ports == legacy.ports
        && sqlite.is_deactivated == legacy.is_deactivated
        && sqlite.name == legacy.name
        && sqlite.vk_hashes == legacy.vk_hashes
        && sqlite.dtls_port == legacy.dtls_port
        && sqlite.wg_port == legacy.wg_port
        && sqlite.local_port == legacy.local_port
}

fn legacy_device_matches(sqlite: &ClientDevice, legacy: &ClientDevice) -> bool {
    sqlite.device_id == legacy.device_id
        && sqlite.ip == legacy.ip
        && sqlite.priv_key == legacy.priv_key
        && sqlite.pub_key == legacy.pub_key
}

fn persist_database_update(
    config_dir: &Path,
    connection: &mut Option<Connection>,
    update: PersistenceUpdate,
) -> Result<()> {
    let _guard = DATABASE_SAVE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if connection.is_none() {
        *connection = Some(open_database_connection(config_dir)?);
    }
    let connection = connection
        .as_mut()
        .expect("database connection initialized");
    match update {
        PersistenceUpdate::Snapshot(snapshot) => write_database_snapshot(connection, &snapshot),
        PersistenceUpdate::Traffic(traffic) => write_traffic(connection, &traffic),
    }
}

pub fn save_database(config_dir: &Path, db: &Database) -> Result<()> {
    let _guard = DATABASE_SAVE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut connection = open_database_connection(config_dir)?;
    write_database_snapshot(&mut connection, db)
}

fn write_traffic(connection: &mut Connection, traffic: &TrafficSnapshot) -> Result<()> {
    if traffic.is_empty() {
        return Ok(());
    }
    let transaction = connection
        .transaction()
        .context("begin traffic persistence transaction")?;

    if let Some(main) = traffic.main {
        transaction
            .execute(
                "INSERT INTO counters (id, main_up_bytes, main_down_bytes) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                    main_up_bytes = excluded.main_up_bytes,
                    main_down_bytes = excluded.main_down_bytes",
                rusqlite::params![main.up_bytes, main.down_bytes],
            )
            .context("write main traffic counters")?;
    }
    for (password, counters) in &traffic.passwords {
        // A client can be removed after its session was closed.  A missing row
        // is therefore an expected no-op, not a reason to resurrect a deleted
        // credential with incomplete data.
        transaction
            .execute(
                "UPDATE passwords SET up_bytes = ?2, down_bytes = ?3 WHERE password = ?1",
                rusqlite::params![password, counters.up_bytes, counters.down_bytes],
            )
            .with_context(|| format!("write traffic for password {password}"))?;
    }
    for (device_id, counters) in &traffic.devices {
        transaction
            .execute(
                "UPDATE devices SET up_bytes = ?2, down_bytes = ?3 WHERE device_id = ?1",
                rusqlite::params![device_id, counters.up_bytes, counters.down_bytes],
            )
            .with_context(|| format!("write traffic for device {device_id}"))?;
    }
    transaction
        .commit()
        .context("commit traffic persistence transaction")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClientDevice, Database, DatabasePersistence, PasswordEntry, PersistenceQueue,
        PersistenceUpdate, TrafficCounters, TrafficSnapshot, load_database, save_database,
    };

    #[test]
    fn dns_survives_database_restart() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-dns-test-{unique}"));
        let database = Database {
            dns: "9.9.9.9,149.112.112.112".to_owned(),
            ..Database::default()
        };

        save_database(&directory, &database).expect("save database");
        let restored = load_database(&directory).expect("load database");

        assert_eq!(restored.dns, database.dns);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn auto_restart_interval_defaults_to_disabled_and_persists_disabled() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-auto-restart-test-{unique}"));

        let database = Database::default();
        assert_eq!(database.auto_restart_interval_hours(), 0);
        save_database(&directory, &database).expect("save default interval");

        let connection = rusqlite::Connection::open(directory.join(super::DATABASE_FILE)).unwrap();
        connection
            .execute(
                "DELETE FROM meta WHERE key = 'auto_restart_interval_hours'",
                [],
            )
            .unwrap();
        drop(connection);
        let mut restored = load_database(&directory).expect("load old sqlite database");
        assert_eq!(restored.auto_restart_interval_hours(), 0);

        restored.set_auto_restart_interval_hours(0);
        save_database(&directory, &restored).expect("save disabled interval");
        let disabled = load_database(&directory).expect("load disabled interval");
        assert_eq!(disabled.auto_restart_interval_hours(), 0);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn legacy_json_is_imported_into_sqlite_and_removed() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-json-import-test-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let mut legacy = Database {
            main_password: "legacy-main".to_owned(),
            main_device_id: "legacy-device".to_owned(),
            dns: "9.9.9.9".to_owned(),
            main_up_bytes: 11,
            main_down_bytes: 12,
            ..Database::default()
        };
        legacy.passwords.insert(
            "legacy-client".to_owned(),
            PasswordEntry {
                device_id: "legacy-device".to_owned(),
                up_bytes: 13,
                down_bytes: 14,
                ..PasswordEntry::default()
            },
        );
        legacy.devices.insert(
            "legacy-device".to_owned(),
            ClientDevice {
                device_id: "legacy-device".to_owned(),
                ip: "10.66.67.2".to_owned(),
                ..ClientDevice::default()
            },
        );
        let legacy_path = directory.join(super::LEGACY_DATABASE_FILE);
        std::fs::write(&legacy_path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_password, "legacy-main");
        assert_eq!(restored.main_up_bytes, 11);
        assert!(restored.passwords.contains_key("legacy-client"));
        assert!(restored.devices.contains_key("legacy-device"));
        assert!(directory.join(super::DATABASE_FILE).exists());
        assert!(!legacy_path.exists());
        assert!(
            !directory
                .join(super::LEGACY_DATABASE_IMPORTED_FILE)
                .exists()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn legacy_json_import_preserves_passwords_devices_and_bindings() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-json-full-import-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();

        let mut legacy = Database {
            main_password: "old-main-password".to_owned(),
            main_device_id: "owner-device".to_owned(),
            dns: "77.88.8.8,77.88.8.1".to_owned(),
            main_up_bytes: 900,
            main_down_bytes: 1_800,
            ..Database::default()
        };
        legacy.passwords.insert(
            "client-password-1".to_owned(),
            PasswordEntry {
                device_id: "device-1".to_owned(),
                expires_at: 1_900_000_000,
                name: "first legacy user".to_owned(),
                vk_hashes: "hash-a\nhash-b".to_owned(),
                up_bytes: 11,
                down_bytes: 22,
                dtls_port: 46000,
                wg_port: 51820,
                local_port: 1080,
                ..PasswordEntry::default()
            },
        );
        legacy.passwords.insert(
            "client-password-2".to_owned(),
            PasswordEntry {
                device_id: "device-2".to_owned(),
                is_deactivated: true,
                name: "disabled legacy user".to_owned(),
                up_bytes: 33,
                down_bytes: 44,
                ..PasswordEntry::default()
            },
        );
        legacy.devices.insert(
            "device-1".to_owned(),
            ClientDevice {
                device_id: "device-1".to_owned(),
                ip: "10.66.67.2".to_owned(),
                priv_key: "priv-1".to_owned(),
                pub_key: "pub-1".to_owned(),
                up_bytes: 55,
                down_bytes: 66,
            },
        );
        legacy.devices.insert(
            "device-2".to_owned(),
            ClientDevice {
                device_id: "device-2".to_owned(),
                ip: "10.66.67.3".to_owned(),
                priv_key: "priv-2".to_owned(),
                pub_key: "pub-2".to_owned(),
                up_bytes: 88,
                down_bytes: 99,
            },
        );

        let legacy_path = directory.join(super::LEGACY_DATABASE_FILE);
        std::fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_password, "old-main-password");
        assert_eq!(restored.main_device_id, "owner-device");
        assert_eq!(restored.dns, "77.88.8.8,77.88.8.1");
        assert_eq!(
            (restored.main_up_bytes, restored.main_down_bytes),
            (900, 1_800)
        );

        let first = restored.passwords.get("client-password-1").unwrap();
        assert_eq!(first.device_id, "device-1");
        assert_eq!(first.name, "first legacy user");
        assert_eq!(first.vk_hashes, "hash-a\nhash-b");
        assert_eq!(
            (first.dtls_port, first.wg_port, first.local_port),
            (46000, 51820, 1080)
        );

        let second = restored.passwords.get("client-password-2").unwrap();
        assert!(second.is_deactivated);
        assert_eq!(second.device_id, "device-2");

        let device = restored.devices.get("device-1").unwrap();
        assert_eq!(device.ip, "10.66.67.2");
        assert!(directory.join(super::DATABASE_FILE).exists());
        assert!(!legacy_path.exists());

        let reloaded = load_database(&directory).unwrap();
        assert_eq!(reloaded.passwords.len(), 2);
        assert_eq!(reloaded.devices.len(), 2);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn load_repairs_stale_password_and_device_bindings() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-binding-repair-{unique}"));
        let mut database = Database {
            main_password: "main-password".to_owned(),
            main_device_id: "owner-device".to_owned(),
            ..Database::default()
        };
        database.passwords.insert(
            "orphaned".to_owned(),
            PasswordEntry {
                device_id: "missing-device".to_owned(),
                ..PasswordEntry::default()
            },
        );
        database.passwords.insert(
            "one-sided".to_owned(),
            PasswordEntry {
                device_id: "device-1".to_owned(),
                ..PasswordEntry::default()
            },
        );
        database.devices.insert(
            "device-1".to_owned(),
            ClientDevice {
                device_id: "device-1".to_owned(),
                ip: "10.66.67.2".to_owned(),
                ..ClientDevice::default()
            },
        );
        database.devices.insert(
            "stale-device".to_owned(),
            ClientDevice {
                device_id: "stale-device".to_owned(),
                ip: "10.66.67.3".to_owned(),
                ..ClientDevice::default()
            },
        );
        database.devices.insert(
            "owner-device".to_owned(),
            ClientDevice {
                device_id: "owner-device".to_owned(),
                ip: "10.66.67.4".to_owned(),
                ..ClientDevice::default()
            },
        );
        save_database(&directory, &database).unwrap();

        let restored = load_database(&directory).unwrap();
        assert!(restored.passwords["orphaned"].device_id.is_empty());

        let reloaded = load_database(&directory).unwrap();
        assert!(reloaded.passwords["orphaned"].device_id.is_empty());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn existing_sqlite_ignores_legacy_json() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-json-merge-test-{unique}"));
        let mut sqlite = Database {
            main_password: "sqlite-main".to_owned(),
            main_up_bytes: 50,
            ..Database::default()
        };
        sqlite.passwords.insert(
            "sqlite-client".to_owned(),
            PasswordEntry {
                name: "current".to_owned(),
                device_id: "sqlite-device".to_owned(),
                ..PasswordEntry::default()
            },
        );
        sqlite.devices.insert(
            "sqlite-device".to_owned(),
            ClientDevice {
                device_id: "sqlite-device".to_owned(),
                ip: "10.66.67.10".to_owned(),
                ..ClientDevice::default()
            },
        );
        save_database(&directory, &sqlite).unwrap();

        let mut legacy = Database {
            main_password: "sqlite-main".to_owned(),
            main_up_bytes: 10,
            ..Database::default()
        };
        legacy.passwords.insert(
            "legacy-client".to_owned(),
            PasswordEntry {
                name: "imported".to_owned(),
                device_id: "legacy-device".to_owned(),
                ..PasswordEntry::default()
            },
        );
        legacy.devices.insert(
            "legacy-device".to_owned(),
            ClientDevice {
                device_id: "legacy-device".to_owned(),
                ip: "10.66.67.11".to_owned(),
                ..ClientDevice::default()
            },
        );
        legacy.passwords.insert(
            "sqlite-client".to_owned(),
            PasswordEntry {
                name: "current".to_owned(),
                device_id: "sqlite-device".to_owned(),
                up_bytes: 1,
                ..PasswordEntry::default()
            },
        );
        legacy.devices.insert(
            "sqlite-device".to_owned(),
            ClientDevice {
                device_id: "sqlite-device".to_owned(),
                ip: "10.66.67.10".to_owned(),
                up_bytes: 1,
                ..ClientDevice::default()
            },
        );
        let legacy_path = directory.join(super::LEGACY_DATABASE_FILE);
        std::fs::write(&legacy_path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_password, "sqlite-main");
        assert_eq!(restored.main_up_bytes, 50);
        assert_eq!(restored.passwords.len(), 1);
        assert_eq!(restored.devices.len(), 1);
        assert_eq!(restored.passwords["sqlite-client"].name, "current");
        assert_eq!(restored.devices["sqlite-device"].ip, "10.66.67.10");
        assert!(legacy_path.exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn existing_sqlite_ignores_conflicting_legacy_password() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-json-password-conflict-{unique}"));
        let mut sqlite = Database::default();
        sqlite.passwords.insert(
            "shared-password".to_owned(),
            PasswordEntry {
                device_id: "sqlite-device".to_owned(),
                ..PasswordEntry::default()
            },
        );
        sqlite.devices.insert(
            "sqlite-device".to_owned(),
            ClientDevice {
                device_id: "sqlite-device".to_owned(),
                ip: "10.66.67.2".to_owned(),
                ..ClientDevice::default()
            },
        );
        save_database(&directory, &sqlite).unwrap();

        let mut legacy = Database::default();
        legacy.passwords.insert(
            "shared-password".to_owned(),
            PasswordEntry {
                device_id: "legacy-device".to_owned(),
                ..PasswordEntry::default()
            },
        );
        let legacy_path = directory.join(super::LEGACY_DATABASE_FILE);
        std::fs::write(&legacy_path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let restored = load_database(&directory).unwrap();
        assert_eq!(
            restored.passwords["shared-password"].device_id,
            "sqlite-device"
        );
        assert!(legacy_path.exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn existing_sqlite_ignores_conflicting_legacy_device() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-json-device-conflict-{unique}"));
        let mut sqlite = Database::default();
        sqlite.devices.insert(
            "shared-device".to_owned(),
            ClientDevice {
                device_id: "shared-device".to_owned(),
                ip: "10.66.67.2".to_owned(),
                priv_key: "sqlite-private".to_owned(),
                pub_key: "sqlite-public".to_owned(),
                ..ClientDevice::default()
            },
        );
        save_database(&directory, &sqlite).unwrap();

        let mut legacy = Database::default();
        legacy.devices.insert(
            "shared-device".to_owned(),
            ClientDevice {
                device_id: "shared-device".to_owned(),
                ip: "10.66.67.2".to_owned(),
                priv_key: "legacy-private".to_owned(),
                pub_key: "sqlite-public".to_owned(),
                ..ClientDevice::default()
            },
        );
        let legacy_path = directory.join(super::LEGACY_DATABASE_FILE);
        std::fs::write(&legacy_path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.devices["shared-device"].priv_key, "sqlite-private");
        assert!(legacy_path.exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn persistence_queue_coalesces_traffic_and_ignores_late_completion() {
        let mut queue = PersistenceQueue::default();
        let mut first = TrafficSnapshot::default();
        first.passwords.insert(
            "first".to_owned(),
            TrafficCounters {
                up_bytes: 1,
                down_bytes: 2,
            },
        );
        let (first_revision, start_first) = queue.submit_traffic(first);
        assert!(start_first);
        let mut second = TrafficSnapshot::default();
        second.devices.insert(
            "second".to_owned(),
            TrafficCounters {
                up_bytes: 3,
                down_bytes: 4,
            },
        );
        let (second_revision, start_second) = queue.submit_traffic(second);
        assert!(!start_second);
        assert!(second_revision > first_revision);
        let Some((pending_revision, PersistenceUpdate::Traffic(pending))) = queue.take_pending()
        else {
            panic!("expected a merged traffic operation");
        };
        assert_eq!(pending_revision, second_revision);
        assert_eq!(pending.passwords["first"].up_bytes, 1);
        assert_eq!(pending.devices["second"].down_bytes, 4);

        queue.complete(second_revision, true);
        queue.complete(first_revision, false);
        assert_eq!(queue.processed_revision, second_revision);
        assert_eq!(queue.successful_revision, second_revision);
    }

    #[test]
    fn persistence_snapshot_supersedes_queued_traffic() {
        let mut queue = PersistenceQueue::default();
        let (traffic_revision, _) = queue.submit_traffic(TrafficSnapshot::default());
        let (snapshot_revision, _) = queue.submit_snapshot(Database {
            main_up_bytes: 42,
            ..Database::default()
        });
        assert!(snapshot_revision > traffic_revision);
        let Some((revision, PersistenceUpdate::Snapshot(snapshot))) = queue.take_pending() else {
            panic!("expected latest database snapshot");
        };
        assert_eq!(revision, snapshot_revision);
        assert_eq!(snapshot.main_up_bytes, 42);
    }

    #[tokio::test]
    async fn database_persistence_finishes_with_latest_coalesced_snapshot() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-persistence-test-{unique}"));
        let persistence = DatabasePersistence::new(directory.clone()).unwrap();
        let mut final_revision = 0;
        for mutation in 1..=512 {
            final_revision = persistence.submit(Database {
                main_up_bytes: mutation,
                ..Database::default()
            });
        }
        persistence.wait(final_revision).await.unwrap();
        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_up_bytes, 512);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn traffic_persistence_updates_only_changed_counter_rows() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-traffic-test-{unique}"));
        let mut database = Database {
            main_up_bytes: 1,
            main_down_bytes: 2,
            ..Database::default()
        };
        database.passwords.insert(
            "client".to_owned(),
            PasswordEntry {
                device_id: "device".to_owned(),
                up_bytes: 3,
                down_bytes: 4,
                ..PasswordEntry::default()
            },
        );
        database.devices.insert(
            "device".to_owned(),
            ClientDevice {
                device_id: "device".to_owned(),
                up_bytes: 5,
                down_bytes: 6,
                ..ClientDevice::default()
            },
        );
        save_database(&directory, &database).unwrap();

        let persistence = DatabasePersistence::new(directory.clone()).unwrap();
        let mut traffic = TrafficSnapshot {
            main: Some(TrafficCounters {
                up_bytes: 101,
                down_bytes: 102,
            }),
            ..TrafficSnapshot::default()
        };
        traffic.passwords.insert(
            "client".to_owned(),
            TrafficCounters {
                up_bytes: 103,
                down_bytes: 104,
            },
        );
        traffic.devices.insert(
            "device".to_owned(),
            TrafficCounters {
                up_bytes: 105,
                down_bytes: 106,
            },
        );
        let revision = persistence.submit_traffic(traffic);
        persistence.wait(revision).await.unwrap();

        let restored = load_database(&directory).unwrap();
        assert_eq!(
            (restored.main_up_bytes, restored.main_down_bytes),
            (101, 102)
        );
        let password = restored.passwords.get("client").unwrap();
        assert_eq!((password.up_bytes, password.down_bytes), (103, 104));
        let device = restored.devices.get("device").unwrap();
        assert_eq!((device.up_bytes, device.down_bytes), (105, 106));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_database_mutations_persist_the_highest_revision() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("csqtt-persistence-stress-test-{unique}"));
        let persistence = DatabasePersistence::new(directory.clone()).unwrap();
        let database = std::sync::Arc::new(tokio::sync::Mutex::new(Database::default()));
        let final_revision = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let database = database.clone();
            let persistence = persistence.clone();
            let final_revision = final_revision.clone();
            tasks.spawn(async move {
                for _ in 0..256 {
                    let mut database = database.lock().await;
                    database.main_up_bytes = database.main_up_bytes.saturating_add(1);
                    let revision = persistence.submit(database.clone());
                    final_revision.fetch_max(revision, std::sync::atomic::Ordering::AcqRel);
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let final_revision = final_revision.load(std::sync::atomic::Ordering::Acquire);
        persistence.wait(final_revision).await.unwrap();
        let restored = load_database(&directory).unwrap();
        assert_eq!(restored.main_up_bytes, 4096);
        let _ = std::fs::remove_dir_all(directory);
    }
}
