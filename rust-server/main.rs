// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![allow(linker_messages)]
#![recursion_limit = "256"]

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL_ALLOCATOR: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

pub const fn allocator_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "snmalloc"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "system"
    }
}

pub(crate) fn collect_allocator_thread_heap() -> bool {
    false
}

mod dataplane;
mod downlink_queue;
#[path = "../shared/flow_frame.rs"]
mod flow_frame;
mod memory_metrics;
mod model;
mod net_setup;
mod packet;
mod perf;
mod protocol;
mod proxy_route;
#[path = "../shared/selective_fec.rs"]
mod selective_fec;
#[path = "../shared/striped_scheduler.rs"]
mod striped_scheduler;
mod tokio_io;
mod tproxy;
mod tun_device;
#[cfg(test)]
mod udp_supervisor;
mod web_panel;
#[path = "../shared/wire_protocol.rs"]
mod wire_protocol;

use anyhow::{Context, Result, bail};
use clap::Parser;
use dashmap::DashMap;
use model::{
    DEFAULT_AUTO_RESTART_INTERVAL_HOURS, Database, DatabasePersistence, load_database, now,
    random_password, save_database,
};
use protocol::Session;
use std::{
    collections::HashMap,
    io::Read,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

#[derive(Parser, Debug)]
#[command(name = "csqtt", version, about = "Сервер и консоль управления CSQTT")]
struct Args {
    #[arg(long, hide = true)]
    protocol_revision: bool,

    #[arg(long, default_value = "0.0.0.0:46000", help = "UDP-адрес сервера")]
    listen: SocketAddr,

    #[arg(long, default_value_t = 46002, help = "HTTPS-порт веб-панели")]
    web_port: u16,

    #[arg(long, default_value = "/etc/csqtt", help = "Каталог конфигурации")]
    config_dir: std::path::PathBuf,

    #[arg(
        long,
        env = "CSQTT_MAIN_PASSWORD",
        default_value = "",
        help = "Основной пароль CSQTT"
    )]
    password: String,

    #[arg(
        long,
        env = "CSQTT_DEVICE_ID",
        default_value = "",
        help = "Идентификатор устройства"
    )]
    device_id: String,

    #[arg(
        long,
        env = "CSQTT_WEB_USER",
        default_value = "admin",
        help = "Логин веб-панели"
    )]
    web_user: String,

    #[arg(
        long,
        env = "CSQTT_WEB_PASS",
        default_value = "",
        help = "Пароль веб-панели"
    )]
    web_pass: String,

    #[arg(
        long,
        env = "CSQTT_DNS",
        help = "Один или два DNS IPv4-адреса через запятую"
    )]
    dns: Option<String>,

    #[arg(
        long,
        env = "CSQTT_SECURE_COOKIE",
        default_value_t = false,
        help = "Выдавать cookie только по HTTPS"
    )]
    secure_cookie: bool,

    #[arg(
        long,
        env = "CSQTT_FEC",
        value_enum,
        default_value_t = protocol::FecProfile::Safe,
        help = "Профиль selective FEC: safe или off"
    )]
    fec: protocol::FecProfile,

    #[arg(long, help = "Запустить службу CSQTT")]
    start: bool,

    #[arg(long, help = "Остановить службу CSQTT")]
    stop: bool,

    #[arg(long, help = "Перезапустить службу CSQTT")]
    restart: bool,

    #[arg(long, short = 'd', help = "Открыть DPI-монитор")]
    dpi: bool,

    #[arg(long, hide = true)]
    tproxy_child: bool,

    #[arg(long, hide = true)]
    tproxy_port: Option<u16>,

    #[arg(long, hide = true)]
    tproxy_status: Option<std::path::PathBuf>,

    #[arg(
        long,
        short = 's',
        default_value_t = 0,
        help = "Число последних DPI-записей"
    )]
    samples: usize,
}

#[derive(Debug, Default, serde::Deserialize)]
struct DeployOverrides {
    #[serde(default)]
    main_password: String,
    #[serde(default)]
    device_id: String,
}

fn normalize_dns(value: &str) -> Result<String> {
    let addresses: Vec<_> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if addresses.is_empty() || addresses.len() > 2 {
        bail!("DNS must contain one or two IPv4 addresses");
    }
    for address in &addresses {
        address
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("invalid DNS IPv4 address: {address}"))?;
    }
    Ok(addresses.join(","))
}

pub struct App {
    pub db: RwLock<Database>,
    pub db_persistence: DatabasePersistence,
    pub dns: RwLock<String>,
    pub startup_main_password: String,
    pub config_dir: std::path::PathBuf,
    pub listen: SocketAddr,
    pub web_port: u16,
    pub web_user: String,
    pub web_pass: String,
    pub secure_cookie: bool,
    pub fec_profile: protocol::FecProfile,
    pub sessions: DashMap<u64, Arc<Session>>,
    pub device_epochs: DashMap<String, Arc<protocol::DeviceEpochSlot>>,
    pub web_sessions: DashMap<String, i64>,
    pub login_limits: DashMap<String, (u32, i64)>,
    pub web_auth_admission: std::sync::Mutex<()>,
    pub bytes_from_client: Arc<AtomicU64>,
    pub bytes_to_client: Arc<AtomicU64>,
    pub total_connections: AtomicU64,
    pub cpu_percent: AtomicU64,
    pub cpu_cores: AtomicU64,
    pub started: i64,
    pub derived_keys: DashMap<String, [u8; 32]>,
    pub logs: std::sync::Mutex<std::collections::VecDeque<String>>,
    pub logging_active: std::sync::atomic::AtomicBool,
    pub stream_debug_active: Arc<AtomicBool>,
    pub log_file_path: std::path::PathBuf,
    pub proxy_route: RwLock<Option<Arc<proxy_route::ProxyRoute>>>,
    pub proxy_operation: tokio::sync::Mutex<()>,
    pub proxy_trigger: tokio::sync::Notify,
    pub proxy_port_listening: std::sync::atomic::AtomicBool,
    pub proxy_health_error: std::sync::RwLock<Option<String>>,
    pub memory_trim_gate: tokio::sync::Mutex<()>,
    pub memory_trim_count: AtomicU64,
    pub memory_trim_last_unix: AtomicU64,
    pub auto_restart_interval_tx: tokio::sync::watch::Sender<u8>,
    pub restart_pending: AtomicBool,
    pub(crate) dataplane:
        std::sync::OnceLock<dataplane::DataplaneHandle<protocol::ProtocolCommand>>,
}

#[inline]
pub fn lock_unpoison<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[inline]
pub fn read_unpoison<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[inline]
pub fn write_unpoison<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub async fn trim_memory(app: &Arc<App>) -> Result<bool> {
    let _trim_guard = app.memory_trim_gate.lock().await;
    let allocator_collected = protocol::compact_memory(app).await?;
    app.memory_trim_count.fetch_add(1, Ordering::Relaxed);
    app.memory_trim_last_unix
        .store(now().max(0) as u64, Ordering::Relaxed);
    Ok(allocator_collected)
}

fn schedule_proxy_shutdown_compaction(app: &Arc<App>) {
    let app = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if app.proxy_route.read().await.is_none() {
            let _ = trim_memory(&app).await;
        }
    });
}

pub(crate) const MAX_LOG_RECORD_BYTES: usize = 2_048;
pub(crate) const LOG_RING_CAPACITY: usize = 600;
const LOG_TRUNCATION_SUFFIX: &str = "...[truncated]";

fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn append_utf8_prefix(target: &mut String, value: &str) {
    let remaining = MAX_LOG_RECORD_BYTES.saturating_sub(target.len());
    target.push_str(utf8_prefix(value, remaining));
}

fn format_log_record(time_str: &str, level: &str, msg: &str) -> String {
    let mut formatted = String::with_capacity(MAX_LOG_RECORD_BYTES);
    append_utf8_prefix(&mut formatted, "[");
    append_utf8_prefix(&mut formatted, time_str);
    append_utf8_prefix(&mut formatted, "] [");
    append_utf8_prefix(&mut formatted, level);
    append_utf8_prefix(&mut formatted, "] ");

    let remaining = MAX_LOG_RECORD_BYTES.saturating_sub(formatted.len());
    if msg.len() <= remaining {
        formatted.push_str(msg);
    } else if remaining > LOG_TRUNCATION_SUFFIX.len() {
        formatted.push_str(utf8_prefix(msg, remaining - LOG_TRUNCATION_SUFFIX.len()));
        formatted.push_str(LOG_TRUNCATION_SUFFIX);
    } else {
        formatted.push_str(utf8_prefix(msg, remaining));
    }

    debug_assert!(formatted.len() <= MAX_LOG_RECORD_BYTES);
    formatted
}

fn enqueue_log_write(path: std::path::PathBuf, line: String) {
    static SENDER: std::sync::OnceLock<std::sync::mpsc::SyncSender<(std::path::PathBuf, String)>> =
        std::sync::OnceLock::new();
    let sender = SENDER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(512);
        let _ = std::thread::Builder::new()
            .name("csqtt-log-writer".to_owned())
            .spawn(move || {
                while let Ok((path, line)) = receiver.recv() {
                    use std::io::Write;
                    if let Ok(metadata) = std::fs::metadata(&path)
                        && metadata.len() > 8 * 1024 * 1024
                    {
                        let _ = std::fs::remove_file(&path);
                    }
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        let _ = writeln!(file, "{line}");
                    }
                }
            });
        sender
    });
    let _ = sender.try_send((path, line));
}

pub fn log_event(app: &Arc<App>, level: &str, _module: &str, msg: &str) {
    if !app.logging_active.load(Ordering::Relaxed) {
        return;
    }
    let time_str = chrono::Local::now().format("%d %b %y %H:%M").to_string();
    let formatted = format_log_record(&time_str, level, msg);

    eprintln!("{}", formatted);

    let mut logs = lock_unpoison(&app.logs);
    logs.push_back(formatted.clone());
    if logs.len() > LOG_RING_CAPACITY {
        logs.pop_front();
    }
    drop(logs);

    let path = app.log_file_path.clone();
    enqueue_log_write(path, formatted);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuSnapshot {
    total: u64,
    process: u64,
    cores: u64,
}

fn parse_cpu_total(line: &str) -> Option<u64> {
    let mut values = line.split_whitespace().skip(1);
    let mut total = 0_u64;
    for _ in 0..4 {
        total = total.checked_add(values.next()?.parse().ok()?)?;
    }
    for value in values {
        total = total.checked_add(value.parse().ok()?)?;
    }
    Some(total)
}

fn parse_host_cpu(stat: &str) -> Option<(u64, u64)> {
    let aggregate = stat.lines().next()?;
    if !aggregate.starts_with("cpu ") {
        return None;
    }
    let total = parse_cpu_total(aggregate)?;
    let cores = stat
        .lines()
        .skip(1)
        .filter(|line| {
            line.strip_prefix("cpu")
                .and_then(|suffix| suffix.split_whitespace().next())
                .is_some_and(|cpu| !cpu.is_empty() && cpu.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .count()
        .max(1) as u64;
    Some((total, cores))
}

fn parse_process_cpu(stat: &str) -> Option<u64> {
    let mut fields = stat.get(stat.rfind(')')? + 1..)?.split_whitespace();
    let user: u64 = fields.nth(11)?.parse().ok()?;
    let system: u64 = fields.next()?.parse().ok()?;
    Some(user.saturating_add(system))
}

fn read_proc_text<'a>(path: &str, buffer: &'a mut [u8]) -> Option<&'a str> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.read(buffer).ok()?;
    std::str::from_utf8(&buffer[..len]).ok()
}

fn cpu_percentage(previous: CpuSnapshot, current: CpuSnapshot) -> Option<u64> {
    let total_delta = current.total.checked_sub(previous.total)?;
    if total_delta == 0 {
        return None;
    }
    let process_delta = current.process.saturating_sub(previous.process);
    let process =
        (process_delta as f64 * current.cores as f64 * 100.0 / total_delta as f64).round() as u64;
    Some(process.min(current.cores.saturating_mul(100)))
}

async fn cpu_loop(app: Arc<App>) {
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    let mut previous = None;
    let mut host_stat_buffer = [0_u8; 8192];
    let mut process_stat_buffer = [0_u8; 1024];
    loop {
        timer.tick().await;
        model::refresh_cached_now();
        protocol::refresh_monotonic_millis();
        if let (Some(host_stat), Some(process_stat)) = (
            read_proc_text("/proc/stat", &mut host_stat_buffer),
            read_proc_text("/proc/self/stat", &mut process_stat_buffer),
        ) && let Some((total, cores)) = parse_host_cpu(host_stat)
            && let Some(process) = parse_process_cpu(process_stat)
        {
            let current = CpuSnapshot {
                total,
                process,
                cores,
            };
            if let Some(previous) = previous
                && let Some(process_percent) = cpu_percentage(previous, current)
            {
                app.cpu_percent.store(process_percent, Ordering::Relaxed);
            }
            app.cpu_cores.store(cores, Ordering::Relaxed);
            previous = Some(current);
        }
    }
}

const DEVICE_EPOCH_IDLE_TTL_MS: u64 = 60 * 60 * 1_000;
const DEVICE_EPOCH_SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

async fn device_epoch_sweeper(app: Arc<App>) {
    let mut ticker = tokio::time::interval(DEVICE_EPOCH_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let now_ms = protocol::unix_time_ms();
        let candidates: Vec<String> = app
            .device_epochs
            .iter()
            .filter(|entry| {
                now_ms.saturating_sub(entry.value().last_used_ms.load(Ordering::Relaxed))
                    >= DEVICE_EPOCH_IDLE_TTL_MS
            })
            .map(|entry| entry.key().clone())
            .collect();
        for device_id in candidates {
            app.device_epochs.remove_if(&device_id, |_, slot| {
                if now_ms.saturating_sub(slot.last_used_ms.load(Ordering::Relaxed))
                    < DEVICE_EPOCH_IDLE_TTL_MS
                {
                    return false;
                }
                !app.sessions
                    .iter()
                    .any(|session| *lock_unpoison(&session.device_id) == device_id)
            });
        }
        if app.device_epochs.len().saturating_mul(4) < app.device_epochs.capacity() {
            app.device_epochs.shrink_to_fit();
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                eprintln!("[SIGNAL] SIGTERM handler unavailable: {error}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(unix)]
async fn web_tls_reload_loop(
    tls_config: axum_server::tls_rustls::RustlsConfig,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
) {
    use tokio::signal::unix::{SignalKind, signal};

    let Ok(mut reload) = signal(SignalKind::user_defined1()) else {
        eprintln!("[WEB] SIGUSR1 TLS reload handler unavailable");
        return;
    };
    while reload.recv().await.is_some() {
        match tls_config.reload_from_pem_file(&cert_path, &key_path).await {
            Ok(()) => println!("[WEB] TLS certificate reloaded"),
            Err(error) => eprintln!("[WEB] TLS certificate reload failed: {error}"),
        }
    }
}

fn run_systemctl(action: &str) -> Result<()> {
    if std::env::var("CSQTT_SERVICE_MANAGER").is_ok_and(|value| value == "docker") {
        if action != "restart" {
            bail!("для управления контейнером используйте docker start/stop csqtt");
        }
        #[cfg(unix)]
        {
            if unsafe { libc::kill(1, libc::SIGTERM) } == 0 {
                println!("[CLI] Docker-контейнер перезапускается");
                return Ok(());
            }
            return Err(std::io::Error::last_os_error().into());
        }
        #[cfg(not(unix))]
        bail!("Docker service manager поддерживается только на Unix");
    }
    #[cfg(unix)]
    {
        if unsafe { libc_geteuid() } != 0 {
            bail!("для управления службой csqtt нужны права root");
        }
    }
    println!("[CLI] Выполняется systemctl {action} csqtt...");
    let mut command = std::process::Command::new("systemctl");
    if action == "restart" {
        command.arg("--no-block");
    }
    let status = command.args([action, "csqtt"]).status();
    match status {
        Ok(s) if s.success() => {
            println!("[CLI] Готово");
            Ok(())
        }
        Ok(s) => {
            bail!("[CLI] systemctl завершился с ошибкой: {}", s);
        }
        Err(e) => {
            bail!("[CLI] не удалось запустить systemctl: {}", e);
        }
    }
}

const PANEL_RESTART_DELAY_MILLIS: u64 = 750;
static PANEL_RESTART_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn request_service_restart() -> Result<()> {
    if std::env::var("CSQTT_SERVICE_MANAGER").is_ok_and(|value| value == "systemd") {
        let sequence = PANEL_RESTART_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let unit = format!("csqtt-panel-restart-{}-{sequence}", std::process::id());
        let status = std::process::Command::new("systemd-run")
            .arg("--quiet")
            .arg(format!("--unit={unit}"))
            .arg(format!("--on-active={PANEL_RESTART_DELAY_MILLIS}ms"))
            .arg("--timer-property=AccuracySec=100ms")
            .arg("--collect")
            .arg("/usr/bin/systemctl")
            .args(["--no-block", "restart", "csqtt"])
            .status()
            .context("schedule delayed systemd restart with systemd-run")?;
        if status.success() {
            return Ok(());
        }
        bail!("systemd-run delayed restart failed: {status}");
    }
    #[cfg(unix)]
    {
        std::thread::Builder::new()
            .name("csqtt-panel-restart".to_owned())
            .spawn(|| {
                std::thread::sleep(Duration::from_millis(PANEL_RESTART_DELAY_MILLIS));
                let pid = unsafe { libc::getpid() };
                if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
                    eprintln!(
                        "[SYSTEM] delayed self-restart signal failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            })
            .context("schedule delayed self restart")?;
        Ok(())
    }
    #[cfg(not(unix))]
    bail!("managed restart is supported only on Unix");
}

pub(crate) fn request_managed_restart(app: &Arc<App>, source: &str) -> Result<()> {
    if let Err(error) = protocol::notify_panel_restart(app) {
        log_event(
            app,
            "WARN",
            "SYSTEM",
            &format!("Restart notification was not queued: {error:#}"),
        );
    }

    match request_service_restart() {
        Ok(()) => {
            log_event(
                app,
                "INFO",
                "SYSTEM",
                &format!("Managed restart scheduled from {source}"),
            );
            Ok(())
        }
        Err(error) => {
            log_event(
                app,
                "ERROR",
                "SYSTEM",
                &format!("Managed restart request from {source} failed: {error:#}"),
            );
            Err(error)
        }
    }
}

async fn auto_restart_loop(app: Arc<App>, mut interval_rx: tokio::sync::watch::Receiver<u8>) {
    const RETRY_DELAY: Duration = Duration::from_secs(5 * 60);

    loop {
        let hours = *interval_rx.borrow_and_update();
        if hours == 0 {
            if interval_rx.changed().await.is_err() {
                return;
            }
            continue;
        }

        let interval = Duration::from_secs(u64::from(hours) * 60 * 60);
        let uptime_seconds = now().saturating_sub(app.started) as u64;
        let wait = interval.saturating_sub(Duration::from_secs(uptime_seconds));

        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                if app.restart_pending.swap(true, Ordering::AcqRel) {
                    return;
                }

                log_event(
                    &app,
                    "INFO",
                    "SYSTEM",
                    &format!(
                        "Automatic restart interval reached: {hours}h uptime target"
                    ),
                );
                if request_managed_restart(&app, "automatic uptime interval").is_ok() {
                    return;
                }

                app.restart_pending.store(false, Ordering::Release);
                tokio::select! {
                    _ = tokio::time::sleep(RETRY_DELAY) => {}
                    changed = interval_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            }
            changed = interval_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

fn acquire_instance_lock(config_dir: &std::path::Path) -> Result<std::fs::File> {
    let path = config_dir.join(".server.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open instance lock {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another CSQTT server instance owns {}", path.display());
        }
    }
    Ok(file)
}

fn diagnostic_heartbeat(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        let mut timer = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(60),
            Duration::from_secs(60),
        );
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            timer.tick().await;
            if writer.write_all(b"PING\n").await.is_err() {
                break;
            }
        }
    })
}

async fn run_dpi_client(samples: usize) -> Result<()> {
    if !cfg!(feature = "diagnostics") {
        bail!("csqtt was built without diagnostics; rebuild with --diagnostics");
    }
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    println!(
        "\x1b[1;33m               CSQTT DEEP PACKET INSPECTION (DPI) LIVE TRAFFIC SNIFFER               \x1b[0m"
    );
    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );

    let mut stream = match tokio::net::TcpStream::connect("127.0.0.1:46003").await {
        Ok(s) => s,
        Err(e) => {
            bail!(
                "Could not connect to running CSQTT server DPI socket (127.0.0.1:46003): {e}. Ensure csqtt is active!"
            );
        }
    };

    let req = format!("GET_DPI:{samples}\n");
    stream.write_all(req.as_bytes()).await?;

    let (reader, writer) = stream.into_split();
    let _heartbeat = diagnostic_heartbeat(writer);
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(frame) = serde_json::from_str::<protocol::DpiFrame>(&line) {
                    let dt =
                        chrono::DateTime::from_timestamp((frame.timestamp_ms / 1000) as i64, 0)
                            .map(|t| t.format("%H:%M:%S").to_string())
                            .unwrap_or_else(|| "00:00:00".to_string());

                    let dir_str = if frame.direction == "INBOUND" {
                        "\x1b[1;32m▲ INBOUND \x1b[0m"
                    } else {
                        "\x1b[1;34m▼ OUTBOUND\x1b[0m"
                    };

                    let pt_str = if frame.pt == 111 {
                        "\x1b[1;33mRTP-Audio (PT=111)\x1b[0m".to_string()
                    } else if frame.pt == 96 {
                        "\x1b[1;35mRTP-Video (PT=96)\x1b[0m".to_string()
                    } else {
                        format!("\x1b[1;36m{}\x1b[0m", frame.proto)
                    };

                    println!(
                        "[\x1b[2m{}\x1b[0m] {} | \x1b[1;33m{}\x1b[0m -> \x1b[1;36m{}\x1b[0m | Size: {} B (Wire: {} B)",
                        dt, dir_str, frame.src, frame.dst, frame.len, frame.wire_len
                    );
                    println!(
                        "  Proto: {} | Seq: #\x1b[1m{}\x1b[0m | Device: \x1b[1;32m{}\x1b[0m | Gen: \x1b[1;33m{}\x1b[0m | Salt: \x1b[1;35m{}\x1b[0m",
                        pt_str, frame.seq, frame.device_id, frame.gen_id, frame.salt
                    );
                    println!("  Detail: \x1b[1;37m{}\x1b[0m", frame.detail);
                    if !frame.hex_preview.is_empty() {
                        println!(
                            "  Hex & ASCII Preview:\n\x1b[2m{}\x1b[0m",
                            frame.hex_preview
                        );
                    }
                    println!(
                        "\x1b[2m────────────────────────────────────────────────────────────────────────────────────\x1b[0m"
                    );
                }
            }
        }
    }

    Ok(())
}

async fn syscalls_broadcast_loop() {
    if !cfg!(feature = "diagnostics") {
        return;
    }
    let mut last_counters = *read_unpoison(&crate::protocol::GLOBAL_IO_COUNTERS);
    let mut last_crypto = crate::protocol::CRYPTO_OPS_COUNTER.load(Ordering::Relaxed);
    let mut last_crypto_perf = *read_unpoison(&crate::protocol::GLOBAL_CRYPTO_PERF);
    let mut last_all_perf = read_unpoison(&crate::perf::GLOBAL_DATAPLANE)
        .merge(*read_unpoison(&crate::perf::GLOBAL_PROTOCOL));
    let mut last_process_cpu = perf::process_cpu_time_ns();
    let (mut last_process_user_cpu, mut last_process_system_cpu) = perf::process_cpu_split_ns();
    let mut last_dataplane_cpu = perf::DATAPLANE_CPU_NS.load(Ordering::Acquire);
    let mut last_dataplane_sequence = perf::DATAPLANE_CPU_SEQUENCE.load(Ordering::Acquire);
    let mut last_threads: HashMap<u32, perf::ThreadCpuSnapshot> = HashMap::new();
    let mut last_sample = std::time::Instant::now();
    let mut monitoring = false;
    let mut thread_sampling = false;
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        if protocol::SYSCALLS_BROADCAST.receiver_count() == 0 {
            monitoring = false;
            thread_sampling = false;
            last_threads.clear();
            continue;
        }

        let all_active = perf::ALL_CLIENTS.load(Ordering::Acquire) != 0;
        if !monitoring {
            last_counters = *read_unpoison(&crate::protocol::GLOBAL_IO_COUNTERS);
            last_crypto = crate::protocol::CRYPTO_OPS_COUNTER.load(Ordering::Relaxed);
            last_crypto_perf = *read_unpoison(&crate::protocol::GLOBAL_CRYPTO_PERF);
            last_all_perf = crate::perf::GLOBAL_DATAPLANE
                .read()
                .unwrap()
                .merge(*read_unpoison(&crate::perf::GLOBAL_PROTOCOL));
            last_process_cpu = perf::process_cpu_time_ns();
            (last_process_user_cpu, last_process_system_cpu) = perf::process_cpu_split_ns();
            last_dataplane_cpu = perf::DATAPLANE_CPU_NS.load(Ordering::Acquire);
            last_dataplane_sequence = perf::DATAPLANE_CPU_SEQUENCE.load(Ordering::Acquire);
            last_threads = if all_active {
                perf::process_thread_cpu_snapshot()
                    .into_iter()
                    .map(|thread| (thread.tid, thread))
                    .collect()
            } else {
                HashMap::new()
            };
            last_sample = std::time::Instant::now();
            monitoring = true;
            thread_sampling = all_active;
            continue;
        }

        let sample_now = std::time::Instant::now();
        let sample_window_ns = sample_now
            .saturating_duration_since(last_sample)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let current_process_cpu = perf::process_cpu_time_ns();
        let process_cpu_ns = current_process_cpu.saturating_sub(last_process_cpu);
        let (current_process_user_cpu, current_process_system_cpu) = perf::process_cpu_split_ns();
        let process_user_cpu_ns = current_process_user_cpu.saturating_sub(last_process_user_cpu);
        let process_system_cpu_ns =
            current_process_system_cpu.saturating_sub(last_process_system_cpu);
        let current_dataplane_cpu = perf::DATAPLANE_CPU_NS.load(Ordering::Acquire);
        let current_dataplane_sequence = perf::DATAPLANE_CPU_SEQUENCE.load(Ordering::Acquire);
        let current_threads = if all_active {
            perf::process_thread_cpu_snapshot()
                .into_iter()
                .map(|thread| (thread.tid, thread))
                .collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };
        let mut threads = current_threads
            .values()
            .map(|thread| {
                let previous = last_threads.get(&thread.tid);
                protocol::ThreadCpuFrame {
                    tid: thread.tid,
                    name: thread.name.clone(),
                    user_cpu_ns: previous
                        .map_or(0, |value| thread.user_ns.saturating_sub(value.user_ns)),
                    system_cpu_ns: previous
                        .map_or(0, |value| thread.system_ns.saturating_sub(value.system_ns)),
                }
            })
            .collect::<Vec<_>>();
        threads.sort_unstable_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.tid.cmp(&right.tid))
        });
        let dataplane_cpu_ns = if thread_sampling
            && all_active
            && current_dataplane_sequence != last_dataplane_sequence
        {
            current_dataplane_cpu.saturating_sub(last_dataplane_cpu)
        } else {
            0
        };

        let current_counters = *read_unpoison(&crate::protocol::GLOBAL_IO_COUNTERS);
        let current_crypto = crate::protocol::CRYPTO_OPS_COUNTER.load(Ordering::Relaxed);
        let current_crypto_perf = *read_unpoison(&crate::protocol::GLOBAL_CRYPTO_PERF);
        let crypto_perf = current_crypto_perf.delta(last_crypto_perf);
        let current_all_perf = crate::perf::GLOBAL_DATAPLANE
            .read()
            .unwrap()
            .merge(*read_unpoison(&crate::perf::GLOBAL_PROTOCOL));
        let all_perf = current_all_perf.delta(last_all_perf);
        let active_sessions = crate::protocol::ACTIVE_SESSIONS_GAUGE.load(Ordering::Relaxed);

        let frame = protocol::SyscallsFrame {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_millis() as u64,
            sample_window_ns,
            process_cpu_ns,
            process_user_cpu_ns,
            process_system_cpu_ns,
            dataplane_cpu_ns,
            dataplane_tid: perf::DATAPLANE_TID.load(Ordering::Acquire) as u32,
            threads,
            udp_rx_pps: current_counters
                .udp_rx_packets
                .saturating_sub(last_counters.udp_rx_packets),
            udp_rx_bps: current_counters
                .udp_rx_bytes
                .saturating_sub(last_counters.udp_rx_bytes),
            udp_rx_errors_s: current_counters
                .udp_rx_errors
                .saturating_sub(last_counters.udp_rx_errors),
            udp_tx_pps: current_counters
                .udp_tx_packets
                .saturating_sub(last_counters.udp_tx_packets),
            udp_tx_bps: current_counters
                .udp_tx_bytes
                .saturating_sub(last_counters.udp_tx_bytes),
            udp_tx_errors_s: current_counters
                .udp_tx_errors
                .saturating_sub(last_counters.udp_tx_errors),
            udp_tx_drops_s: current_counters
                .udp_tx_drops
                .saturating_sub(last_counters.udp_tx_drops),
            tun_rx_pps: current_counters
                .tun_rx_packets
                .saturating_sub(last_counters.tun_rx_packets),
            tun_rx_bps: current_counters
                .tun_rx_bytes
                .saturating_sub(last_counters.tun_rx_bytes),
            tun_rx_errors_s: current_counters
                .tun_rx_errors
                .saturating_sub(last_counters.tun_rx_errors),
            tun_tx_pps: current_counters
                .tun_tx_packets
                .saturating_sub(last_counters.tun_tx_packets),
            tun_tx_bps: current_counters
                .tun_tx_bytes
                .saturating_sub(last_counters.tun_tx_bytes),
            tun_tx_errors_s: current_counters
                .tun_tx_errors
                .saturating_sub(last_counters.tun_tx_errors),
            tun_tx_drops_s: current_counters
                .tun_tx_drops
                .saturating_sub(last_counters.tun_tx_drops),
            readiness_wakeups_s: current_counters
                .readiness_wakeups
                .saturating_sub(last_counters.readiness_wakeups),
            recv_syscalls_s: current_counters
                .udp_recv_syscalls
                .saturating_sub(last_counters.udp_recv_syscalls),
            send_syscalls_s: current_counters
                .udp_send_syscalls
                .saturating_sub(last_counters.udp_send_syscalls),
            rx_eagain_s: current_counters
                .udp_rx_eagain
                .saturating_sub(last_counters.udp_rx_eagain),
            tx_eagain_s: current_counters
                .udp_tx_eagain
                .saturating_sub(last_counters.udp_tx_eagain),
            partial_sendmmsg_s: current_counters
                .partial_sendmmsg
                .saturating_sub(last_counters.partial_sendmmsg),
            crypto_ops_s: current_crypto.saturating_sub(last_crypto),
            active_sessions,
            free_udp_tx_slots: current_counters.free_udp_tx_slots,
            free_tun_tx_slots: current_counters.free_tun_tx_slots,
            recv_batch_max: current_counters.udp_recv_batch_max,
            udp_rx_enobufs_s: current_counters
                .udp_rx_enobufs
                .saturating_sub(last_counters.udp_rx_enobufs),
            udp_tx_enobufs_s: current_counters
                .udp_tx_enobufs
                .saturating_sub(last_counters.udp_tx_enobufs),
            total_udp_rx_packets: current_counters.udp_rx_packets,
            total_udp_tx_packets: current_counters.udp_tx_packets,
            total_tun_rx_packets: current_counters.tun_rx_packets,
            total_tun_tx_packets: current_counters.tun_tx_packets,
            crypto_sample_interval: protocol::CRYPTO_PERF_SAMPLE_INTERVAL,
            chacha: crypto_perf.chacha,
            srtp: crypto_perf.srtp,
            unwrap_crypto: crypto_perf.unwrap_crypto,
            wrap_crypto: crypto_perf.wrap_crypto,
            all_sample_interval: perf::SAMPLE_INTERVAL,
            all: all_perf,
        };

        let _ = protocol::SYSCALLS_BROADCAST.send(frame);

        last_counters = current_counters;
        last_crypto = current_crypto;
        last_crypto_perf = current_crypto_perf;
        last_all_perf = current_all_perf;
        last_process_cpu = current_process_cpu;
        last_process_user_cpu = current_process_user_cpu;
        last_process_system_cpu = current_process_system_cpu;
        last_dataplane_cpu = current_dataplane_cpu;
        last_dataplane_sequence = current_dataplane_sequence;
        last_threads = current_threads;
        thread_sampling = all_active;
        last_sample = sample_now;
    }
}

async fn run_syscalls_client() -> Result<()> {
    if !cfg!(feature = "diagnostics") {
        bail!("csqtt was built without diagnostics; rebuild with --diagnostics");
    }
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    println!(
        "\x1b[1;33m                   CSQTT I/O & SYSCALL MONITOR (1 update/sec)                      \x1b[0m"
    );
    println!(
        "\x1b[1;36m════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );

    let mut stream = match tokio::net::TcpStream::connect("127.0.0.1:46004").await {
        Ok(s) => s,
        Err(e) => {
            bail!(
                "Could not connect to CSQTT syscalls socket (127.0.0.1:46004): {e}. Ensure csqtt is active!"
            );
        }
    };

    stream.write_all(b"SUBSCRIBE\n").await?;

    let (reader, writer) = stream.into_split();
    let _heartbeat = diagnostic_heartbeat(writer);
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(f) = serde_json::from_str::<protocol::SyscallsFrame>(&line) {
                    print!("\x1b[2J\x1b[H");
                    println!(
                        "\x1b[1;36m═══════════════ CSQTT SYSCALL MONITOR ═══════════════\x1b[0m"
                    );
                    println!(
                        "\x1b[1;33m Sessions: \x1b[1;37m{}\x1b[0m",
                        f.active_sessions
                    );
                    println!();
                    println!(
                        "\x1b[1;32m  ▲ UDP RX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}",
                        f.udp_rx_pps, f.udp_rx_bps, f.udp_rx_errors_s
                    );
                    println!(
                        "\x1b[1;34m  ▼ UDP TX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}  drops: {}",
                        f.udp_tx_pps, f.udp_tx_bps, f.udp_tx_errors_s, f.udp_tx_drops_s
                    );
                    println!(
                        "\x1b[1;32m  ▲ TUN RX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}",
                        f.tun_rx_pps, f.tun_rx_bps, f.tun_rx_errors_s
                    );
                    println!(
                        "\x1b[1;34m  ▼ TUN TX  \x1b[0m {:>8} pps  {:>10} B/s  err: {}  drops: {}",
                        f.tun_tx_pps, f.tun_tx_bps, f.tun_tx_errors_s, f.tun_tx_drops_s
                    );
                    println!();
                    println!(
                        "\x1b[1;35m  syscalls  \x1b[0m recv/s: {:>8}  send/s: {:>8}",
                        f.recv_syscalls_s, f.send_syscalls_s
                    );
                    println!(
                        "\x1b[1;35m  wakeups   \x1b[0m {:>8}  max batch: {:>8}",
                        f.readiness_wakeups_s, f.recv_batch_max
                    );
                    println!(
                        "\x1b[1;35m  eagain    \x1b[0m RX: {:>8}  TX: {:>8}  partial: {}",
                        f.rx_eagain_s, f.tx_eagain_s, f.partial_sendmmsg_s
                    );
                    println!("\x1b[1;35m  crypto/s  \x1b[0m {:>8}", f.crypto_ops_s);
                    println!();
                    println!(
                        "\x1b[2m  free slots │ UDP TX: {}  TUN TX: {}\x1b[0m",
                        f.free_udp_tx_slots, f.free_tun_tx_slots
                    );
                    println!(
                        "\x1b[2m  totals    │ UDP RX: {}  UDP TX: {}  TUN RX: {}  TUN TX: {}\x1b[0m",
                        f.total_udp_rx_packets,
                        f.total_udp_tx_packets,
                        f.total_tun_rx_packets,
                        f.total_tun_tx_packets
                    );
                    println!(
                        "\x1b[1;36m═════════════════════════════════════════════════════\x1b[0m"
                    );
                }
            }
        }
    }
    Ok(())
}

fn perf_estimated_ns(counters: perf::Counters) -> f64 {
    if counters.samples == 0 {
        return 0.0;
    }
    counters.sampled_ns as f64 / counters.samples as f64 * counters.operations as f64
}

fn write_all_perf_row(
    out: &mut String,
    name: &str,
    counters: perf::Counters,
    sample_window_ns: u64,
) {
    use std::fmt::Write;
    let estimated_ns = perf_estimated_ns(counters);
    let average_ns = if counters.operations == 0 {
        0.0
    } else {
        estimated_ns / counters.operations as f64
    };
    let operations_per_sec =
        counters.operations as f64 * 1_000_000_000.0 / sample_window_ns.max(1) as f64;
    let _ = writeln!(
        out,
        "{name:<24} {:>9.0} оп/с  {:>9.0} нс/оп  {:>7.2}% ядра  выборок: {}",
        operations_per_sec,
        average_ns,
        estimated_ns * 100.0 / sample_window_ns.max(1) as f64,
        counters.samples
    );
}

fn write_derived_perf_row(
    out: &mut String,
    name: &str,
    operations: u64,
    estimated_ns: f64,
    sample_window_ns: u64,
) {
    use std::fmt::Write;
    let average_ns = if operations == 0 {
        0.0
    } else {
        estimated_ns / operations as f64
    };
    let operations_per_sec = operations as f64 * 1_000_000_000.0 / sample_window_ns.max(1) as f64;
    let _ = writeln!(
        out,
        "{name:<24} {:>9.0} оп/с  {:>9.0} нс/оп  {:>7.2}% ядра  расчёт",
        operations_per_sec,
        average_ns,
        estimated_ns * 100.0 / sample_window_ns.max(1) as f64
    );
}

fn render_perf_all(frame: &protocol::SyscallsFrame) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(4096);
    let all = frame.all;
    let dispatch_ns = perf_estimated_ns(all.dispatch);
    let flush_ns = perf_estimated_ns(all.flush);
    let bookkeeping_ns = perf_estimated_ns(all.bookkeeping);
    let wrap_ns = if frame.wrap_crypto.samples == 0 {
        0.0
    } else {
        frame.wrap_crypto.sampled_ns as f64 / frame.wrap_crypto.samples as f64
            * frame.wrap_crypto.operations as f64
    };
    let unwrap_ns = if frame.unwrap_crypto.samples == 0 {
        0.0
    } else {
        frame.unwrap_crypto.sampled_ns as f64 / frame.unwrap_crypto.samples as f64
            * frame.unwrap_crypto.operations as f64
    };
    let udp_queue_ns = perf_estimated_ns(all.udp_queue);
    let total_ns = dispatch_ns + flush_ns + bookkeeping_ns;
    let sample_window_ns = frame.sample_window_ns.max(1);
    let process_percent = frame.process_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let sampled_top_percent = total_ns * 100.0 / sample_window_ns as f64;
    let dataplane_percent = frame.dataplane_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let user_percent = frame.process_user_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let system_percent = frame.process_system_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
    let threads_cpu_ns = frame.threads.iter().fold(0u64, |total, thread| {
        total.saturating_add(thread.user_cpu_ns.saturating_add(thread.system_cpu_ns))
    });
    let dataplane_proc_ns = frame
        .threads
        .iter()
        .find(|thread| thread.tid == frame.dataplane_tid)
        .map_or(0, |thread| {
            thread.user_cpu_ns.saturating_add(thread.system_cpu_ns)
        });
    let other_threads_ns = threads_cpu_ns.saturating_sub(dataplane_proc_ns);
    let unattributed_ns = frame.process_cpu_ns.saturating_sub(threads_cpu_ns);
    let other_threads_percent = other_threads_ns as f64 * 100.0 / sample_window_ns as f64;
    let unattributed_percent = unattributed_ns as f64 * 100.0 / sample_window_ns as f64;

    let _ = writeln!(
        out,
        "CSQTT PERF ALL — профиль dataplane за последнюю секунду"
    );
    let _ = writeln!(
        out,
        "Сессий: {} · UDP RX/TX: {}/{} pps · TUN RX/TX: {}/{} pps · выборка 1/{}\n",
        frame.active_sessions,
        frame.udp_rx_pps,
        frame.udp_tx_pps,
        frame.tun_rx_pps,
        frame.tun_tx_pps,
        frame.all_sample_interval
    );
    let _ = writeln!(
        out,
        "epoll wakeups: {}/с · recvmmsg: {}/с · sendmmsg: {}/с · макс батч: {}\n",
        frame.readiness_wakeups_s,
        frame.recv_syscalls_s,
        frame.send_syscalls_s,
        frame.recv_batch_max
    );
    let _ = writeln!(
        out,
        "EAGAIN RX/TX: {}/{} · частичных sendmmsg: +{}/с · ENOBUFS RX/TX: {}/{}\n",
        frame.rx_eagain_s,
        frame.tx_eagain_s,
        frame.partial_sendmmsg_s,
        frame.udp_rx_enobufs_s,
        frame.udp_tx_enobufs_s
    );
    let _ = writeln!(
        out,
        "I/O ошибки: UDP RX/TX {}/{} · TUN RX/TX {}/{} · drops UDP/TUN {}/{}\n",
        frame.udp_rx_errors_s,
        frame.udp_tx_errors_s,
        frame.tun_rx_errors_s,
        frame.tun_tx_errors_s,
        frame.udp_tx_drops_s,
        frame.tun_tx_drops_s
    );
    let _ = writeln!(out, "Верхний уровень, независимая sampled-оценка:");
    write_all_perf_row(&mut out, "Dispatch (всего)", all.dispatch, sample_window_ns);
    write_all_perf_row(&mut out, "sendmmsg/flush", all.flush, sample_window_ns);
    write_all_perf_row(
        &mut out,
        "loop bookkeeping",
        all.bookkeeping,
        sample_window_ns,
    );
    let _ = writeln!(
        out,
        "{:<24} {:>31.2}% ядра",
        "СУММА SAMPLED СТАДИЙ", sampled_top_percent
    );
    let _ = writeln!(
        out,
        "{:<24} {:>31.2}% ядра",
        "DATAPLANE THREAD ТОЧНО", dataplane_percent
    );
    let _ = writeln!(
        out,
        "{:<24} {:>31.2}% ядра",
        "ПРОЦЕСС CSQTT ТОЧНО", process_percent
    );
    let _ = writeln!(
        out,
        "{:<24} {:>20.2}% user · {:>6.2}% system",
        "ПРОЦЕСС CPU SPLIT", user_percent, system_percent
    );
    let _ = writeln!(
        out,
        "{:<24} {:>31.2}% ядра",
        "ПРОЧИЕ ПОТОКИ CSQTT", other_threads_percent
    );
    let _ = writeln!(
        out,
        "{:<24} {:>31.2}% ядра\n",
        "НЕ АТРИБУТИРОВАНО /PROC", unattributed_percent
    );

    if !frame.threads.is_empty() {
        let _ = writeln!(out, "Стабильная разбивка живых потоков по /proc:");
        for thread in frame.threads.iter().take(16) {
            let thread_user = thread.user_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
            let thread_system = thread.system_cpu_ns as f64 * 100.0 / sample_window_ns as f64;
            let _ = writeln!(
                out,
                "{:<18} tid {:>7} {:>7.2}% · {:>6.2}% user · {:>6.2}% system",
                thread.name,
                thread.tid,
                thread_user + thread_system,
                thread_user,
                thread_system
            );
        }
        if frame.threads.len() > 16 {
            let _ = writeln!(out, "ещё потоков: {}", frame.threads.len() - 16);
        }
        let _ = writeln!(out);
    }

    if dataplane_percent > 0.0 && sampled_top_percent > dataplane_percent * 1.25 {
        let _ = writeln!(
            out,
            "Sampled-оценка смещена периодической выборкой; для итога используй точные строки процесса и потоков.\n"
        );
    }

    let _ = writeln!(out, "\nПриблизительная sampled-атрибуция внутри Dispatch:");
    write_all_perf_row(&mut out, "UDP RX overhead", all.udp_rx, sample_window_ns);
    write_derived_perf_row(
        &mut out,
        "parse+unwrap+crypto",
        frame.unwrap_crypto.operations,
        unwrap_ns,
        sample_window_ns,
    );
    write_all_perf_row(&mut out, "route/replay", all.route_replay, sample_window_ns);
    write_all_perf_row(&mut out, "TUN write", all.tun_write, sample_window_ns);
    write_all_perf_row(&mut out, "TUN RX overhead", all.tun_rx, sample_window_ns);
    write_derived_perf_row(
        &mut out,
        "prepare+wrap+crypto",
        frame.wrap_crypto.operations,
        wrap_ns,
        sample_window_ns,
    );
    write_derived_perf_row(
        &mut out,
        "UDP queue inclusive",
        all.udp_queue.operations,
        udp_queue_ns,
        sample_window_ns,
    );
    let _ = writeln!(
        out,
        "\nВнутренние строки sampled независимо и не складываются в точный итог. Истинный общий расход показывает «DATAPLANE THREAD ТОЧНО»; CPU ожидания не включает wall-сон."
    );
    out
}

fn format_metric_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn format_metric_kib(kib: u64) -> String {
    format_metric_bytes(kib.saturating_mul(1024))
}

fn format_metric_limit(limit: Option<u64>) -> String {
    limit
        .map(format_metric_bytes)
        .unwrap_or_else(|| "без лимита / н/д".to_owned())
}

fn render_metric_all(frame: &memory_metrics::MetricFrame) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(12_288);
    let _ = writeln!(
        out,
        "CSQTT METRIC ALL — снимок памяти сервера (PID {})",
        frame.pid
    );
    let _ = writeln!(
        out,
        "Обновление раз в 2 с. RSS/PSS, cgroup и kernel socket memory пересекаются — их нельзя складывать.\n"
    );

    if frame.process.available {
        let _ = writeln!(out, "[Процесс /proc/self/status]");
        let _ = writeln!(
            out,
            "RSS {} · пик VmHWM {} · потоки {} · swap {}",
            format_metric_kib(frame.process.rss_kib),
            format_metric_kib(frame.process.peak_rss_kib),
            frame.process.threads,
            format_metric_kib(frame.process.swap_kib)
        );
        let _ = writeln!(
            out,
            "RSS-состав: anon {} · file {} · shmem {}\n",
            format_metric_kib(frame.process.anonymous_kib),
            format_metric_kib(frame.process.file_kib),
            format_metric_kib(frame.process.shmem_kib)
        );
    } else {
        let _ = writeln!(out, "[Процесс] /proc/self/status недоступен\n");
    }

    if frame.smaps_rollup.available {
        let rollup = &frame.smaps_rollup;
        let _ = writeln!(out, "[smaps_rollup — более честная доля памяти процесса]");
        let _ = writeln!(
            out,
            "Rss {} · Pss {} · private {} · shared {} · Swap {} / SwapPss {}",
            format_metric_kib(rollup.rss_kib),
            format_metric_kib(rollup.pss_kib),
            format_metric_kib(rollup.private_kib),
            format_metric_kib(rollup.shared_kib),
            format_metric_kib(rollup.swap_kib),
            format_metric_kib(rollup.swap_pss_kib)
        );
        let _ = writeln!(
            out,
            "PSS-состав: anon {} · file {} · shmem {} · Anonymous RSS-like {}\n",
            format_metric_kib(rollup.pss_anon_kib),
            format_metric_kib(rollup.pss_file_kib),
            format_metric_kib(rollup.pss_shmem_kib),
            format_metric_kib(rollup.anonymous_kib)
        );
    } else {
        let _ = writeln!(out, "[smaps_rollup] недоступен\n");
    }

    if frame.mappings.available {
        let _ = writeln!(out, "[Карта отображений smaps, top по RSS]");
        for mapping in frame.mappings.categories.iter().take(12) {
            let _ = writeln!(
                out,
                "{:<24} RSS {:>10} · PSS {:>10} · private {:>10} · shared {:>10}",
                mapping.category,
                format_metric_kib(mapping.rss_kib),
                format_metric_kib(mapping.pss_kib),
                format_metric_kib(mapping.private_kib),
                format_metric_kib(mapping.shared_kib)
            );
        }
        let _ = writeln!(out);
    }

    if frame.cgroup.available {
        let cgroup = &frame.cgroup;
        let _ = writeln!(
            out,
            "[cgroup memory.{} — группа, не только Rust heap]",
            cgroup.version
        );
        let _ = writeln!(
            out,
            "current {} · peak {} · max {} · swap current {} · swap max {}",
            format_metric_bytes(cgroup.current_bytes),
            format_metric_bytes(cgroup.peak_bytes),
            format_metric_limit(cgroup.max_bytes),
            format_metric_limit(cgroup.swap_current_bytes),
            format_metric_limit(cgroup.swap_max_bytes)
        );
        let _ = writeln!(
            out,
            "anon {} · file {} · shmem {} · sock {} · kernel_stack {} · pagetables {} · percpu {}",
            format_metric_bytes(cgroup.anon_bytes),
            format_metric_bytes(cgroup.file_bytes),
            format_metric_bytes(cgroup.shmem_bytes),
            format_metric_bytes(cgroup.sock_bytes),
            format_metric_bytes(cgroup.kernel_stack_bytes),
            format_metric_bytes(cgroup.pagetables_bytes),
            format_metric_bytes(cgroup.percpu_bytes)
        );
        let _ = writeln!(
            out,
            "slab reclaimable {} · slab unreclaimable {} · file_mapped {} · file_dirty {}\n",
            format_metric_bytes(cgroup.slab_reclaimable_bytes),
            format_metric_bytes(cgroup.slab_unreclaimable_bytes),
            format_metric_bytes(cgroup.file_mapped_bytes),
            format_metric_bytes(cgroup.file_dirty_bytes)
        );
    } else {
        let _ = writeln!(out, "[cgroup memory] недоступна\n");
    }

    if frame.sockets.available {
        let sockets = &frame.sockets;
        let _ = writeln!(out, "[Сокеты процесса — только текущие очереди payload]");
        let _ = writeln!(
            out,
            "FD socket {} · UDP {} (TX {} / RX {}) · TCP {} (TX {} / RX {})",
            sockets.socket_fds,
            sockets.udp_sockets,
            format_metric_bytes(sockets.udp_tx_queue_bytes),
            format_metric_bytes(sockets.udp_rx_queue_bytes),
            sockets.tcp_sockets,
            format_metric_bytes(sockets.tcp_tx_queue_bytes),
            format_metric_bytes(sockets.tcp_rx_queue_bytes)
        );
        let _ = writeln!(
            out,
            "Полное kernel socket allocation смотри выше в cgroup `sock`, а не в этой очереди.\n"
        );
    }

    let buffers = &frame.fixed_buffers;
    let _ = writeln!(out, "[Пул пакетов CSQTT — live payload, не утечка]");
    let _ = writeln!(
        out,
        "Packet pool capacity {} · выделено {} ({}) · удерживается {}",
        buffers.packet_pool_capacity_slots,
        buffers.packet_pool_allocated_slots,
        format_metric_bytes(buffers.packet_pool_allocated_payload_bytes),
        buffers.packet_pool_retained_slots
    );
    let _ = writeln!(
        out,
        "UDP TX capacity {} × {} = {} · занято {}/{}",
        buffers.udp_tx_slots,
        format_metric_bytes(buffers.packet_capacity_bytes),
        format_metric_bytes(buffers.udp_tx_payload_bytes),
        buffers.udp_tx_in_use_slots,
        buffers.udp_tx_slots
    );
    let _ = writeln!(
        out,
        "TUN TX capacity {} × {} = {} · занято {}/{}",
        buffers.tun_tx_slots,
        format_metric_bytes(buffers.packet_capacity_bytes),
        format_metric_bytes(buffers.tun_tx_payload_bytes),
        buffers.tun_tx_in_use_slots,
        buffers.tun_tx_slots
    );
    let _ = writeln!(
        out,
        "UDP RX {}: {} × {} = {} · TUN RX {} · всего payload {}",
        buffers.udp_rx_mode,
        buffers.udp_rx_slots,
        format_metric_bytes(buffers.udp_rx_slot_bytes),
        format_metric_bytes(buffers.udp_rx_payload_bytes),
        format_metric_bytes(buffers.tun_rx_payload_bytes),
        format_metric_bytes(buffers.fixed_payload_bytes)
    );
    let _ = writeln!(
        out,
        "UDP SO_RCVBUF request {} · SO_SNDBUF request {}\n",
        format_metric_bytes(buffers.udp_socket_rcvbuf_request_bytes),
        format_metric_bytes(buffers.udp_socket_sndbuf_request_bytes)
    );

    let runtime = &frame.runtime;
    let _ = writeln!(
        out,
        "[Удерживаемые структуры runtime — allocator {}]",
        runtime.allocator
    );
    let _ = writeln!(
        out,
        "hot transport sessions {}/{} (жёсткий {}) · public sessions {} / capacity {} · streams/device до {}",
        runtime.hot_sessions,
        runtime.hot_session_capacity,
        runtime.hot_session_limit,
        runtime.public_sessions,
        runtime.public_session_capacity,
        runtime.max_stream_workers_per_device
    );
    let _ = writeln!(
        out,
        "epochs engine/device {}/{} (capacity {}) · derived keys {} (key strings {})",
        runtime.engine_epochs,
        runtime.device_epochs,
        runtime.device_epoch_capacity,
        runtime.derived_keys,
        format_metric_bytes(runtime.derived_key_string_capacity_bytes)
    );
    let _ = writeln!(
        out,
        "web sessions {}/{} (keys {}) · login limits {}/{} (keys {})",
        runtime.web_sessions,
        runtime.web_session_limit,
        format_metric_bytes(runtime.web_session_key_capacity_bytes),
        runtime.login_limits,
        runtime.login_limit_limit,
        format_metric_bytes(runtime.login_limit_key_capacity_bytes)
    );
    let _ = writeln!(
        out,
        "logs {}/{} (strings {}, metadata {}) · DPI {}/{} (retained {})",
        runtime.log_entries,
        runtime.log_entry_limit,
        format_metric_bytes(runtime.log_string_capacity_bytes),
        format_metric_bytes(runtime.log_ring_metadata_capacity_bytes),
        runtime.dpi_entries,
        runtime.dpi_entry_capacity,
        format_metric_bytes(runtime.dpi_retained_bytes)
    );
    let _ = writeln!(
        out,
        "stream repair/inventory {}/{} · dataplane commands {}/{} · memory trim {}",
        runtime.stream_repairs,
        runtime.stream_inventory,
        runtime.dataplane_commands_queued,
        runtime.dataplane_command_capacity,
        runtime.memory_trim_count
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "[Local SOCKS / TPROXY]");
    let _ = writeln!(
        out,
        "{} · TCP {}/{} · UDP {}/{} · payload выделено {} · удерживается {}",
        if runtime.local_proxy_active {
            "активен"
        } else {
            "не активен"
        },
        runtime.local_proxy_tcp_sessions,
        runtime.local_proxy_tcp_limit,
        runtime.local_proxy_udp_flows,
        runtime.local_proxy_udp_limit,
        format_metric_bytes(runtime.local_proxy_payload_allocated_bytes),
        format_metric_bytes(runtime.local_proxy_payload_retained_bytes)
    );
    let _ = writeln!(
        out,
        "opening buffers {} · payload upper bound на полном лимите {} · kernel TCP/UDP buffers — cgroup sock выше\n",
        format_metric_bytes(runtime.local_proxy_opening_buffer_allocated_bytes),
        format_metric_bytes(runtime.local_proxy_payload_upper_bound_at_limit_bytes)
    );

    let storage = &frame.storage;
    let _ = writeln!(out, "[Persistent storage — диск, не RSS]");
    let _ = writeln!(
        out,
        "SQLite db {} · WAL {} · SHM {} · log {}",
        format_metric_bytes(storage.sqlite_db_bytes),
        format_metric_bytes(storage.sqlite_wal_bytes),
        format_metric_bytes(storage.sqlite_shm_bytes),
        format_metric_bytes(storage.log_file_bytes)
    );
    let _ = writeln!(
        out,
        "\nИнтерпретация: растут VmRSS/PSS/RssAnon — ищем удержание в процессе; RSS низкий, а cgroup sock/slab/file высокий — это ядро/cache/другие PID той же группы."
    );
    out
}

async fn run_perf_client() -> Result<()> {
    if !cfg!(feature = "diagnostics") {
        bail!("csqtt was built without diagnostics; rebuild with --diagnostics");
    }
    use std::io::Write;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:46004")
        .await
        .with_context(
            || "не удалось подключиться к CSQTT на 127.0.0.1:46004; убедитесь, что служба запущена",
        )?;
    stream.write_all(b"PERF ALL\n").await?;

    let (reader, writer) = stream.into_split();
    let _heartbeat = diagnostic_heartbeat(writer);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let Ok(frame) = serde_json::from_str::<protocol::SyscallsFrame>(&line) else {
            continue;
        };
        let mut output = String::with_capacity(8192);
        output.push_str("\x1b[2J\x1b[H");
        output.push_str(&render_perf_all(&frame));
        output.push_str("Ctrl+C — выход.\n");
        let mut stdout = std::io::stdout();
        if let Err(error) = stdout
            .write_all(output.as_bytes())
            .and_then(|_| stdout.flush())
        {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error.into());
        }
    }
    Ok(())
}

async fn run_metric_client() -> Result<()> {
    use std::io::Write;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:46004")
        .await
        .with_context(
            || "не удалось подключиться к CSQTT на 127.0.0.1:46004; убедитесь, что служба запущена",
        )?;
    stream.write_all(b"METRIC ALL\n").await?;

    let (reader, writer) = stream.into_split();
    let _heartbeat = diagnostic_heartbeat(writer);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let Ok(frame) = serde_json::from_str::<memory_metrics::MetricFrame>(&line) else {
            continue;
        };
        if !frame.error.is_empty() {
            println!("CSQTT METRIC ALL: {}", frame.error);
            return Ok(());
        }
        let mut output = String::with_capacity(16_384);
        output.push_str("\x1b[2J\x1b[H");
        output.push_str(&render_metric_all(&frame));
        output.push_str("Ctrl+C — выход.\n");
        let mut stdout = std::io::stdout();
        if let Err(error) = stdout
            .write_all(output.as_bytes())
            .and_then(|_| stdout.flush())
        {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error.into());
        }
    }
    Ok(())
}

fn print_cli_help() {
    println!(
        "CSQTT — сервер и консоль управления\n\n\
Использование:\n  \
  csqtt start                 Запустить службу\n  \
  csqtt stop                  Остановить службу\n  \
  csqtt restart               Перезапустить службу\n  \
  csqtt dpi                   Открыть DPI-монитор\n  \
  csqtt dpi s 50              Показать последние 50 DPI-записей и выйти\n  \
  csqtt syscalls              Открыть монитор I/O и системных вызовов\n  \
  csqtt perf all              Разложить весь dataplane по этапам\n  \
  csqtt metric all            Подробный live-снимок памяти сервера\n  \
  csqtt help                  Показать эту справку\n\n\
Ручной запуск сервера:\n  \
  --listen АДРЕС              UDP-адрес, по умолчанию 0.0.0.0:46000\n  \
  --web-port ПОРТ             HTTPS-порт панели, по умолчанию 46002\n  \
  --config-dir ПУТЬ           Каталог конфигурации, по умолчанию /etc/csqtt\n  \
  --password ПАРОЛЬ           Основной пароль CSQTT\n  \
  --device-id ID              Идентификатор устройства\n  \
  --web-user ЛОГИН            Логин веб-панели\n  \
  --web-pass ПАРОЛЬ           Пароль веб-панели\n  \
  --dns IP[,IP]               Один или два DNS IPv4-адреса\n  \
  --secure-cookie             Выдавать cookie только по HTTPS\n"
    );
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("create tokio runtime")?;
    let result = runtime.block_on(async_main());
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn async_main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let args_vec: Vec<String> = std::env::args().collect();
    if args_vec.len() == 1
        || (args_vec.len() == 2 && matches!(args_vec[1].as_str(), "help" | "--help" | "-h"))
    {
        print_cli_help();
        return Ok(());
    }

    if args_vec.len() >= 2 {
        let cmd = args_vec[1].as_str();
        match cmd {
            "start" | "stop" | "restart" => {
                return run_systemctl(cmd);
            }
            "dpi" => {
                let mut samples = 0;
                if args_vec.len() >= 4 && args_vec[2] == "s" {
                    samples = args_vec[3].parse::<usize>().unwrap_or(0);
                }
                return run_dpi_client(samples).await;
            }
            "syscalls" => {
                return run_syscalls_client().await;
            }
            "perf" => {
                if args_vec.get(2).map(String::as_str) != Some("all") {
                    println!("Использование:\n  csqtt perf all");
                    return Ok(());
                }
                return run_perf_client().await;
            }
            "metric" => {
                if args_vec.get(2).map(String::as_str) != Some("all") {
                    println!("Использование:\n  csqtt metric all");
                    return Ok(());
                }
                return run_metric_client().await;
            }
            _ => {}
        }
    }

    let args = Args::parse();

    if args.protocol_revision {
        println!("{}", wire_protocol::WIRE_PROTOCOL_REVISION);
        return Ok(());
    }

    if args.start {
        return run_systemctl("start");
    }
    if args.stop {
        return run_systemctl("stop");
    }
    if args.restart {
        return run_systemctl("restart");
    }

    if args.dpi || args.samples > 0 {
        return run_dpi_client(args.samples).await;
    }

    if unsafe { libc_geteuid() } != 0 {
        bail!("csqtt-server must run as root");
    }

    if args.tproxy_child {
        let tproxy_status = args.tproxy_status.clone();
        return match run_tproxy_child(args.tproxy_port, args.tproxy_status).await {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Some(path) = tproxy_status.as_deref() {
                    proxy_route::write_tproxy_child_error(path, &format!("{error:#}"));
                }
                Err(error)
            }
        };
    }

    tokio::fs::create_dir_all(&args.config_dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&args.config_dir, std::fs::Permissions::from_mode(0o700))
            .await?;
    }

    let _instance_lock = acquire_instance_lock(&args.config_dir)?;
    match tokio::time::timeout(
        Duration::from_secs(1),
        proxy_route::ProxyRoute::cleanup_orphaned_policy(),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("[PROXY] startup policy cleanup: {error:#}"),
        Err(_) => eprintln!("[PROXY] startup policy cleanup timed out"),
    }

    let mut db = load_database(&args.config_dir)?;
    db.admin_id.clear();
    db.bot_token.clear();
    db.web_sessions.clear();

    let deploy_overrides_path = args.config_dir.join("deploy-overrides.json");
    let deploy_overrides_present = deploy_overrides_path.exists();
    let deploy_overrides = if deploy_overrides_present {
        let text = std::fs::read_to_string(&deploy_overrides_path)
            .with_context(|| format!("read {}", deploy_overrides_path.display()))?;
        serde_json::from_str::<DeployOverrides>(&text)
            .with_context(|| format!("parse {}", deploy_overrides_path.display()))?
    } else {
        DeployOverrides::default()
    };

    if !args.password.is_empty() {
        db.main_password = args.password.clone();
    } else if !deploy_overrides.main_password.is_empty() {
        db.main_password = deploy_overrides.main_password.clone();
    }
    if !args.device_id.is_empty() {
        db.main_device_id = args.device_id.clone();
    } else if !deploy_overrides.device_id.is_empty() {
        db.main_device_id = deploy_overrides.device_id.clone();
    }
    if db.main_password.is_empty() {
        db.main_password = random_password() + &random_password();
        println!("[INIT] generated main password: {}", db.main_password);
    }

    let runtime_dns =
        if let Some(configured) = args.dns.as_deref().filter(|value| !value.trim().is_empty()) {
            normalize_dns(configured)?
        } else if deploy_overrides_present {
            web_panel::deploy_dns_profile_or_yandex(&db.dns)
        } else if !db.dns.trim().is_empty() {
            normalize_dns(db.dns.trim())?
        } else {
            "77.88.8.8,77.88.8.1".to_owned()
        };
    db.dns = runtime_dns.clone();
    if !matches!(db.auto_restart_interval_hours(), 0 | 12 | 24 | 48 | 72) {
        db.set_auto_restart_interval_hours(DEFAULT_AUTO_RESTART_INTERVAL_HOURS);
    }

    let web_pass = if args.web_pass.is_empty() {
        let value = random_password() + &random_password();
        println!("[INIT] generated web password: {value}");
        value
    } else {
        args.web_pass
    };

    save_database(&args.config_dir, &db)?;
    if deploy_overrides_path.exists() {
        std::fs::remove_file(&deploy_overrides_path).with_context(|| {
            format!(
                "remove consumed deploy overrides {}",
                deploy_overrides_path.display()
            )
        })?;
    }

    let web_sessions = DashMap::new();

    let logging_active_val = db.logging_active.unwrap_or(true);
    let (auto_restart_interval_tx, auto_restart_interval_rx) =
        tokio::sync::watch::channel(db.auto_restart_interval_hours());
    let startup_main_password = db.main_password.clone();
    let app = Arc::new(App {
        db_persistence: DatabasePersistence::new(args.config_dir.clone())?,
        db: RwLock::new(db),
        dns: RwLock::new(runtime_dns),
        startup_main_password,
        config_dir: args.config_dir.clone(),
        listen: args.listen,
        web_port: args.web_port,
        web_user: args.web_user,
        web_pass,
        secure_cookie: args.secure_cookie,
        fec_profile: args.fec,
        sessions: DashMap::new(),
        device_epochs: DashMap::new(),
        web_sessions,
        login_limits: DashMap::new(),
        web_auth_admission: std::sync::Mutex::new(()),
        bytes_from_client: Arc::new(AtomicU64::new(0)),
        bytes_to_client: Arc::new(AtomicU64::new(0)),
        total_connections: AtomicU64::new(0),
        cpu_percent: AtomicU64::new(0),
        cpu_cores: AtomicU64::new(1),
        started: now(),
        derived_keys: DashMap::new(),
        logs: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(LOG_RING_CAPACITY)),
        logging_active: std::sync::atomic::AtomicBool::new(logging_active_val),
        stream_debug_active: Arc::new(AtomicBool::new(false)),
        log_file_path: args.config_dir.join("csqtt.log"),
        proxy_route: RwLock::new(None),
        proxy_operation: tokio::sync::Mutex::new(()),
        proxy_trigger: tokio::sync::Notify::new(),
        proxy_port_listening: std::sync::atomic::AtomicBool::new(true),
        proxy_health_error: std::sync::RwLock::new(None),
        memory_trim_gate: tokio::sync::Mutex::new(()),
        memory_trim_count: AtomicU64::new(0),
        memory_trim_last_unix: AtomicU64::new(0),
        auto_restart_interval_tx,
        restart_pending: AtomicBool::new(false),
        dataplane: std::sync::OnceLock::new(),
    });

    log_event(&app, "INFO", "SYSTEM", " CSQTT Server 2.1.9");
    log_event(
        &app,
        "INFO",
        "SYSTEM",
        &format!(" RTP AEAD: {}", app.listen),
    );
    log_event(&app, "INFO", "SYSTEM", " Tunnel: Userspace TUN (CSQTT)");
    log_event(
        &app,
        "INFO",
        "SYSTEM",
        &format!(" Web: 0.0.0.0:{}", app.web_port),
    );

    let web_app = app.clone();
    let diagnostic_app = app.clone();

    tokio::spawn(async move {
        if let Err(e) = protocol::run_dpi_server().await {
            eprintln!("[DPI] Server listener error: {e}");
        }
    });

    tokio::spawn(async move {
        if let Err(e) = protocol::run_syscalls_server(diagnostic_app).await {
            eprintln!("[SYSCALLS] Server listener error: {e}");
        }
    });

    tokio::spawn(syscalls_broadcast_loop());
    tokio::spawn(auto_restart_loop(app.clone(), auto_restart_interval_rx));

    let cert_path = app.config_dir.join("web_cert.pem");
    let key_path = app.config_dir.join("web_key.pem");
    if !cert_path.exists() && !key_path.exists() {
        let mut subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
            let hostname = hostname.trim().to_string();
            if !hostname.is_empty() {
                subject_alt_names.push(hostname);
            }
        }
        if let Ok(probe) = std::net::UdpSocket::bind("0.0.0.0:0") {
            let _ = probe.set_nonblocking(true);
            if probe.connect("8.8.8.8:53").is_ok()
                && let Ok(addr) = probe.local_addr()
                && !addr.ip().is_loopback()
            {
                subject_alt_names.push(addr.ip().to_string());
            }
        }
        if let Ok(cert) = rcgen::generate_simple_self_signed(subject_alt_names) {
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();
            let _ = tokio::fs::write(&cert_path, cert_pem).await;
            let _ = tokio::fs::write(&key_path, key_pem).await;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                        .await;
            }
        }
    } else if !cert_path.exists() || !key_path.exists() {
        anyhow::bail!(
            "incomplete WEB TLS certificate pair in {}; restore both web_cert.pem and web_key.pem",
            app.config_dir.display()
        );
    }

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .context("load web cert")?;

    #[cfg(unix)]
    tokio::spawn(web_tls_reload_loop(
        tls_config.clone(),
        cert_path.clone(),
        key_path.clone(),
    ));

    let protocol_runtime = protocol::start(app.clone()).await?;
    let mut protocol_status = protocol_runtime.status_receiver();
    let mut web_task = tokio::spawn(async move { web_panel::run(web_app, tls_config).await });
    tokio::spawn(protocol::session_janitor(app.clone()));
    tokio::spawn(protocol::password_janitor(app.clone()));
    tokio::spawn(device_epoch_sweeper(app.clone()));

    tokio::spawn(cpu_loop(app.clone()));

    let monitor_app = app.clone();
    tokio::spawn(local_proxy_monitor_loop(monitor_app));

    let mut web_completed = false;
    let mut terminal_error = None;
    tokio::select! {
        _ = shutdown_signal() => {}
        result = &mut web_task => {
            web_completed = true;
            terminal_error = Some(match result {
                Ok(Ok(())) => anyhow::anyhow!("web server stopped unexpectedly"),
                Ok(Err(error)) => anyhow::anyhow!("web server failed: {error:#}"),
                Err(error) => anyhow::anyhow!("web server task failed: {error}"),
            });
        }
        changed = protocol_status.changed() => {
            terminal_error = Some(match changed {
                Ok(()) => protocol_status
                    .borrow()
                    .clone()
                    .map(anyhow::Error::msg)
                    .unwrap_or_else(|| anyhow::anyhow!("tokio dataplane stopped unexpectedly")),
                Err(_) => anyhow::anyhow!("tokio dataplane status channel closed"),
            });
        }
    }

    if !web_completed {
        web_task.abort();
        let _ = web_task.await;
    }
    if let Err(error) = protocol_runtime.shutdown().await
        && terminal_error.is_none()
    {
        terminal_error = Some(error);
    }

    log_event(&app, "INFO", "SHUTDOWN", "Stopping server...");

    let proxy_cleanup = async {
        let _proxy_operation = app.proxy_operation.lock().await;
        let proxy_route = app.proxy_route.write().await.take();
        if let Some(route) = proxy_route {
            route.deactivate().await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(6), proxy_cleanup)
        .await
        .is_err()
    {
        eprintln!("[PROXY] shutdown cleanup timed out");
    }

    protocol::flush_traffic(&app).await;
    let final_revision = {
        let db = app.db.read().await;
        app.db_persistence.submit(db.clone())
    };
    match tokio::time::timeout(
        Duration::from_secs(1),
        app.db_persistence.wait(final_revision),
    )
    .await
    {
        Ok(Err(error)) => eprintln!("[DB] final save: {error:#}"),
        Err(_) => eprintln!("[DB] final save timed out"),
        Ok(Ok(())) => {}
    }

    protocol::drop_all_sessions(&app);
    match terminal_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn run_tproxy_child(
    port: Option<u16>,
    status_path: Option<std::path::PathBuf>,
) -> Result<()> {
    let port = port.context("TPROXY child port is missing")?;
    let status_path = status_path.context("TPROXY child status path is missing")?;
    let mut payload = String::new();
    std::io::stdin()
        .read_to_string(&mut payload)
        .context("read TPROXY child bootstrap")?;
    let profile: model::LocalProxyProfile =
        serde_json::from_str(&payload).context("decode TPROXY child bootstrap")?;
    proxy_route::validate_config(&profile)?;
    arm_tproxy_child_parent_death()?;
    let sockets =
        tproxy::bind_sockets(port).with_context(|| format!("bind TPROXY child {port}"))?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let child_log: proxy_route::LogFn = Arc::new(|level: &str, message: &str| {
        eprintln!("[TPROXY] [{level}] {message}");
    });
    let stats = Arc::new(tproxy::TproxyStats::default());
    let quotas = tproxy::DeviceQuotaRegistry::new();
    let mut status = tokio::spawn(serve_tproxy_status(
        status_path,
        cancel.clone(),
        stats.clone(),
    ));
    let engine = tproxy::run(
        sockets,
        Arc::new(profile),
        cancel.clone(),
        child_log,
        stats,
        quotas,
    );
    tokio::pin!(engine);
    let result = tokio::select! {
        result = &mut engine => {
            cancel.cancel();
            let _ = (&mut status).await;
            result
        },
        result = &mut status => {
            cancel.cancel();
            let _ = engine.await;
            result.context("TPROXY child status worker")??;
            bail!("TPROXY child status worker stopped")
        },
        _ = shutdown_signal() => {
            cancel.cancel();
            let result = engine.await;
            let _ = (&mut status).await;
            result
        }
    };
    let (tcp_sessions, udp_flows, udp_datagrams) = result;
    eprintln!(
        "[TPROXY] child exited ({tcp_sessions} TCP sessions, {udp_flows} UDP flows, {udp_datagrams} UDP datagrams served)"
    );
    Ok(())
}

#[cfg(unix)]
async fn serve_tproxy_status(
    path: std::path::PathBuf,
    cancel: tokio_util::sync::CancellationToken,
    stats: Arc<tproxy::TproxyStats>,
) -> Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).context("bind TPROXY status socket")?;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((mut stream, _)) = accepted else {
                    continue;
                };
                let mut request = [0u8; 1];
                let received = tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut request)).await;
                if !matches!(received, Ok(Ok(_))) || request[0] != 0x53 {
                    continue;
                }
                let Ok(payload) = serde_json::to_vec(&stats.snapshot()) else {
                    continue;
                };
                let _ = tokio::time::timeout(Duration::from_millis(100), stream.write_all(&payload)).await;
            }
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[cfg(not(unix))]
async fn serve_tproxy_status(
    _path: std::path::PathBuf,
    _cancel: tokio_util::sync::CancellationToken,
    _stats: Arc<tproxy::TproxyStats>,
) -> Result<()> {
    bail!("TPROXY status socket is supported only on Unix")
}

#[cfg(target_os = "linux")]
fn arm_tproxy_child_parent_death() -> Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("arm TPROXY parent-death signal");
    }
    let docker_mode = std::env::var("CSQTT_SERVICE_MANAGER").is_ok_and(|value| value == "docker");
    if tproxy_parent_exited_during_startup(unsafe { libc::getppid() }, docker_mode) {
        bail!("TPROXY parent exited before child startup");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn tproxy_parent_exited_during_startup(parent_pid: libc::pid_t, docker_mode: bool) -> bool {
    // In a container csqtt itself is normally PID 1, so its healthy TPROXY
    // child legitimately sees PPID=1. PR_SET_PDEATHSIG above still handles
    // real parent termination in both service-manager modes.
    parent_pid == 1 && !docker_mode
}

#[cfg(not(target_os = "linux"))]
fn arm_tproxy_child_parent_death() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(target_os = "linux"))]
unsafe fn libc_geteuid() -> u32 {
    0
}

async fn local_proxy_monitor_loop(app: Arc<App>) {
    const PORT_CHECK: Duration = Duration::from_secs(3);
    const STRIKES_BEFORE_PAUSE: u32 = 5;
    const PAUSE_SCHEDULE: [u64; 4] = [30, 90, 120, 120];

    let mut port_failures: u32 = 0;
    let mut pause_round: u32 = 0;
    let mut wait = Some(Duration::from_millis(200));

    loop {
        if let Some(delay) = wait {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = app.proxy_trigger.notified() => {
                    port_failures = 0;
                    pause_round = 0;
                }
            }
        } else {
            app.proxy_trigger.notified().await;
            port_failures = 0;
            pause_round = 0;
        }

        let _operation = app.proxy_operation.lock().await;
        let profile = {
            let db = app.db.read().await;
            db.local_proxy.active_profile().cloned()
        };

        let Some(profile) = profile else {
            *write_unpoison(&app.proxy_health_error) = None;
            let old = app.proxy_route.write().await.take();
            if let Some(route) = old {
                route.deactivate().await;
                log_event(
                    &app,
                    "INFO",
                    "PROXY",
                    "Local SOCKS5 routing disabled; direct VPS route restored",
                );
                schedule_proxy_shutdown_compaction(&app);
            }
            port_failures = 0;
            pause_round = 0;
            wait = None;
            continue;
        };

        let current = {
            let guard = app.proxy_route.read().await;
            guard.clone()
        };
        if let Some(route) = current {
            if route.is_alive() && route.matches(&profile) {
                if !proxy_route::port_is_listening(profile.port).await {
                    *write_unpoison(&app.proxy_health_error) =
                        Some(format!("Порт {} не отвечает", profile.port));
                    app.proxy_port_listening
                        .store(false, std::sync::atomic::Ordering::Release);
                    let failed = app.proxy_route.write().await.take();
                    if let Some(failed) = failed {
                        failed.deactivate().await;
                    }
                    log_event(
                        &app,
                        "WARNING",
                        "PROXY",
                        &format!(
                            "SOCKS5 port {} is no longer listening; clients switched to the direct route",
                            profile.port
                        ),
                    );
                    schedule_proxy_shutdown_compaction(&app);
                    port_failures = 1;
                    pause_round = 0;
                    wait = Some(PORT_CHECK);
                } else {
                    app.proxy_port_listening
                        .store(true, std::sync::atomic::Ordering::Release);
                    *write_unpoison(&app.proxy_health_error) = None;
                    port_failures = 0;
                    pause_round = 0;
                    wait = Some(PORT_CHECK);
                }
                continue;
            }

            let stale = app.proxy_route.write().await.take();
            if let Some(stale) = stale {
                stale.deactivate().await;
                schedule_proxy_shutdown_compaction(&app);
            }
            wait = Some(Duration::from_millis(100));
            continue;
        }

        let listening = proxy_route::port_is_listening(profile.port).await;
        app.proxy_port_listening
            .store(listening, std::sync::atomic::Ordering::Release);
        if !listening {
            *write_unpoison(&app.proxy_health_error) =
                Some(format!("Порт {} не отвечает", profile.port));
            if port_failures == 0 {
                log_event(
                    &app,
                    "WARNING",
                    "PROXY",
                    &format!(
                        "SOCKS5 port {} is not listening; traffic goes direct, port re-check every 3s",
                        profile.port
                    ),
                );
            }
            port_failures = port_failures.saturating_add(1);
            if port_failures >= STRIKES_BEFORE_PAUSE {
                port_failures = 0;
                let pause = PAUSE_SCHEDULE[(pause_round as usize).min(PAUSE_SCHEDULE.len() - 1)];
                pause_round = pause_round.saturating_add(1);
                wait = Some(Duration::from_secs(pause));
            } else {
                wait = Some(PORT_CHECK);
            }
            continue;
        }

        port_failures = 0;
        pause_round = 0;
        log_event(
            &app,
            "INFO",
            "PROXY",
            &format!(
                "Connecting SOCKS5 forwarder to local SOCKS5 127.0.0.1:{}...",
                profile.port
            ),
        );
        let proxy_log_app = app.clone();
        let proxy_log: proxy_route::LogFn = Arc::new(move |level: &str, msg: &str| {
            log_event(&proxy_log_app, level, "PROXY", msg);
        });
        match proxy_route::ProxyRoute::connect(&profile, proxy_log).await {
            Ok(route) => {
                *write_unpoison(&app.proxy_health_error) = None;
                app.proxy_route.write().await.replace(route);
                log_event(
                    &app,
                    "INFO",
                    "PROXY",
                    &format!(
                        "Local SOCKS5 route 127.0.0.1:{} is active (TCP and UDP)",
                        profile.port
                    ),
                );
                wait = Some(PORT_CHECK);
            }
            Err(error) => {
                *write_unpoison(&app.proxy_health_error) = Some(format!("{error:#}"));
                log_event(
                    &app,
                    "ERROR",
                    "PROXY",
                    &format!(
                        "Local SOCKS5 is not ready: {error:#}. Direct VPS route is active; retry in 3s"
                    ),
                );
                wait = Some(PORT_CHECK);
            }
        }
    }
}

#[cfg(test)]
mod lock_tests {
    use super::{
        CpuSnapshot, LOG_TRUNCATION_SUFFIX, MAX_LOG_RECORD_BYTES, cpu_percentage,
        format_log_record, normalize_dns, parse_host_cpu, parse_process_cpu,
    };

    #[cfg(target_os = "linux")]
    #[test]
    fn docker_tproxy_child_accepts_a_healthy_pid_one_parent() {
        assert!(super::tproxy_parent_exited_during_startup(1, false));
        assert!(!super::tproxy_parent_exited_during_startup(1, true));
        assert!(!super::tproxy_parent_exited_during_startup(42, false));
    }

    #[test]
    fn log_record_is_utf8_safe_and_byte_bounded() {
        let record =
            format_log_record("22 Aug 26 12:00", "INFO", &"\u{0451}\u{0436}".repeat(2_000));

        assert!(record.len() <= MAX_LOG_RECORD_BYTES);
        assert!(std::str::from_utf8(record.as_bytes()).is_ok());
        assert!(record.ends_with(LOG_TRUNCATION_SUFFIX));
    }

    #[test]
    fn log_record_caps_an_oversized_level() {
        let record = format_log_record("22 Aug 26 12:00", &"\u{041b}".repeat(2_000), "ok");

        assert!(record.len() <= MAX_LOG_RECORD_BYTES);
        assert!(std::str::from_utf8(record.as_bytes()).is_ok());
    }

    #[test]
    fn dns_override_accepts_one_or_two_ipv4_addresses() {
        assert_eq!(normalize_dns("8.8.8.8").unwrap(), "8.8.8.8");
        assert_eq!(
            normalize_dns(" 8.8.8.8, 8.8.4.4 ").unwrap(),
            "8.8.8.8,8.8.4.4"
        );
    }

    #[test]
    fn dns_override_rejects_invalid_or_excess_addresses() {
        assert!(normalize_dns("").is_err());
        assert!(normalize_dns("example.org").is_err());
        assert!(normalize_dns("1.1.1.1,1.0.0.1,8.8.8.8").is_err());
    }

    #[test]
    fn poisoned_mutex_recovers_without_process_failure() {
        let mutex = std::sync::Arc::new(std::sync::Mutex::new(1u64));
        let poisoned = mutex.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("poison");
        })
        .join();
        *super::lock_unpoison(&mutex) = 2;
        assert_eq!(*super::lock_unpoison(&mutex), 2);
    }

    #[test]
    fn parses_linux_cpu_counters_and_process_name_with_spaces() {
        let host = "cpu  100 2 30 400 10 0 0 0 0 0\ncpu0 50 1 15 200\ncpu1 50 1 15 200\n";
        assert_eq!(parse_host_cpu(host), Some((542, 2)));
        let process = "77 (csqtt worker) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14";
        assert_eq!(parse_process_cpu(process), Some(23));
    }

    #[test]
    fn calculates_process_cpu_in_one_core_percent() {
        let previous = CpuSnapshot {
            total: 2_000,
            process: 100,
            cores: 4,
        };
        let current = CpuSnapshot {
            total: 2_100,
            process: 120,
            cores: 4,
        };
        assert_eq!(cpu_percentage(previous, current), Some(80));
    }
}
