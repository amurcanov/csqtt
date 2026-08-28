// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::model::LocalProxyProfile;
use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LEGACY_POLICY_TABLE: &str = "1066";
const LEGACY_POLICY_PRIORITY: &str = "1066";
const NAT_COMMENT: &str = "CSQTT_LOCAL_SOCKS";
const MARK_COMMENT: &str = "CSQTT_LOCAL_SOCKS_MARK";
const POLICY_MARK: &str = "0x422";
const LEGACY_NAT_COMMENT: &str = "CSQTT_SOCKS";
const LEGACY_QUIC_COMMENT: &str = "CSQTT_CASCADE_NO_QUIC";
const TPROXY_TABLE: &str = "30001";
const TPROXY_PRIORITY: &str = "30001";
const TPROXY_RULE_MARK: &str = "0x7531/0x7531";
const TPROXY_START_ATTEMPTS: u64 = 8;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKS_COMMAND_TIMEOUT: Duration = Duration::from_secs(8);

static RUNTIME_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_RUNTIME: AtomicU64 = AtomicU64::new(0);
static POLICY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub type LogFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct ProxyRoute {
    config: LocalProxyProfile,
    runtime_id: u64,
    port: u16,
    status_path: PathBuf,
    pub cancel: tokio_util::sync::CancellationToken,
    child: Mutex<Option<Child>>,
}

impl Drop for ProxyRoute {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(mut child) = self
            .child
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = child.kill();
        }
        remove_tproxy_status_file(&self.status_path);
    }
}

impl ProxyRoute {
    pub async fn connect(config: &LocalProxyProfile, log: LogFn) -> Result<Arc<Self>> {
        validate_config(config)?;
        ensure_linux_platform()?;
        if !port_is_listening(config.port).await {
            bail!("SOCKS5 port {} is not listening", config.port);
        }
        verify_socks5_udp_associate(config).await?;

        let (runtime_id, port, status_path, child) = start_tproxy_child_with_retry(config).await?;

        if let Err(error) = activate_tproxy(runtime_id, port).await {
            stop_tproxy_child(child).await;
            remove_tproxy_status_file(&status_path);
            let _guard = POLICY_LOCK.lock().await;
            cleanup_shared_policy().await;
            cleanup_legacy_proxy_policy().await;
            return Err(error);
        }

        let cancel = tokio_util::sync::CancellationToken::new();
        let route = Arc::new(Self {
            config: config.clone(),
            runtime_id,
            port,
            status_path,
            cancel,
            child: Mutex::new(Some(child)),
        });
        spawn_rule_watchdog(port, route.cancel.clone(), log.clone());
        println!(
            "[LOCAL-PROXY] SOCKS5 route ready on 127.0.0.1:{} via TPROXY port {}",
            route.config.port, route.port
        );
        Ok(route)
    }

    pub fn is_alive(&self) -> bool {
        if self.cancel.is_cancelled() {
            return false;
        }
        let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
        let alive = child
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_none()));
        if !alive {
            child.take();
            self.cancel.cancel();
        }
        alive
    }

    pub fn matches(&self, config: &LocalProxyProfile) -> bool {
        self.config == *config
    }

    pub fn stats_snapshot(&self) -> (usize, usize) {
        let stats = self.diagnostic_snapshot();
        (stats.tcp_active, stats.udp_active)
    }

    pub fn diagnostic_snapshot(&self) -> crate::tproxy::TproxyStatsSnapshot {
        request_tproxy_status(&self.status_path).unwrap_or_default()
    }

    pub async fn deactivate(&self) {
        self.cancel.cancel();
        let child = self
            .child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(child) = child {
            stop_tproxy_child(child).await;
        }
        remove_tproxy_status_file(&self.status_path);
        let _guard = POLICY_LOCK.lock().await;
        if ACTIVE_RUNTIME
            .compare_exchange(self.runtime_id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            cleanup_shared_policy().await;
        }
    }

    pub async fn cleanup_orphaned_policy() -> Result<()> {
        let _guard = POLICY_LOCK.lock().await;
        ACTIVE_RUNTIME.store(0, Ordering::Release);
        cleanup_shared_policy().await;
        cleanup_legacy_proxy_policy().await;
        verify_proxy_policy_clean().await
    }
}

async fn start_tproxy_child_with_retry(
    config: &LocalProxyProfile,
) -> Result<(u64, u16, PathBuf, Child)> {
    let mut last_retry_error = None;
    for _ in 0..TPROXY_START_ATTEMPTS {
        let runtime_id = RUNTIME_COUNTER.fetch_add(1, Ordering::Relaxed);
        let port = crate::tproxy::tproxy_port(runtime_id);
        let status_path = tproxy_status_path(runtime_id);
        remove_tproxy_status_file(&status_path);
        let mut child = spawn_tproxy_child(config, port, &status_path)?;
        match wait_for_tproxy_child(&mut child, &status_path).await {
            Ok(()) => return Ok((runtime_id, port, status_path, child)),
            Err(error) => {
                let message = format!("{error:#}");
                stop_tproxy_child(child).await;
                remove_tproxy_status_file(&status_path);
                if tproxy_start_error_is_retryable(&message) {
                    last_retry_error = Some(message);
                    continue;
                }
                return Err(error);
            }
        }
    }
    bail!(
        "TPROXY child could not reserve an internal listener after {TPROXY_START_ATTEMPTS} attempts: {}",
        last_retry_error.unwrap_or_else(|| "unknown startup error".to_owned())
    )
}

fn spawn_tproxy_child(config: &LocalProxyProfile, port: u16, status_path: &Path) -> Result<Child> {
    let executable =
        std::env::current_exe().context("resolve csqtt executable for TPROXY child")?;
    let payload = serde_json::to_vec(config).context("serialize TPROXY child configuration")?;
    let mut child = Command::new(executable)
        .arg("--tproxy-child")
        .arg("--tproxy-port")
        .arg(port.to_string())
        .arg("--tproxy-status")
        .arg(status_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("start TPROXY child")?;
    let write_result = child
        .stdin
        .as_mut()
        .context("open TPROXY child bootstrap pipe")?
        .write_all(&payload)
        .context("send TPROXY child configuration");
    drop(child.stdin.take());
    if let Err(error) = write_result {
        let _ = child.kill();
        return Err(error);
    }
    Ok(child)
}

fn tproxy_start_error_is_retryable(error: &str) -> bool {
    error.contains("Address already in use") || error.contains("os error 98")
}

async fn wait_for_tproxy_child(child: &mut Child, status_path: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if request_tproxy_status(status_path).is_some() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("check TPROXY child status")? {
            if let Some(error) = read_tproxy_child_error(status_path) {
                bail!("TPROXY child exited before readiness: {status}; {error}");
            }
            bail!("TPROXY child exited before readiness: {status}");
        }
        if Instant::now() >= deadline {
            if let Some(error) = read_tproxy_child_error(status_path) {
                bail!("TPROXY child did not report readiness before deadline; {error}");
            }
            bail!("TPROXY child did not report readiness before deadline");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn tproxy_status_path(runtime_id: u64) -> PathBuf {
    std::env::temp_dir().join(format!("csqtt-tproxy-{runtime_id}.sock"))
}

fn remove_tproxy_status_file(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(tproxy_error_path(path));
}

fn tproxy_error_path(status_path: &Path) -> PathBuf {
    let mut path = status_path.to_path_buf();
    path.set_extension("err");
    path
}

pub(crate) fn write_tproxy_child_error(status_path: &Path, error: &str) {
    let error = trim_tproxy_child_error(error);
    if error.is_empty() {
        return;
    }
    let _ = std::fs::write(tproxy_error_path(status_path), error);
}

fn read_tproxy_child_error(status_path: &Path) -> Option<String> {
    let error = std::fs::read_to_string(tproxy_error_path(status_path)).ok()?;
    let error = trim_tproxy_child_error(&error);
    (!error.is_empty()).then_some(error)
}

fn trim_tproxy_child_error(error: &str) -> String {
    const MAX_ERROR_BYTES: usize = 1536;
    let mut compact = error
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if compact.len() <= MAX_ERROR_BYTES {
        return compact;
    }
    let mut end = MAX_ERROR_BYTES;
    while end > 0 && !compact.is_char_boundary(end) {
        end -= 1;
    }
    compact.truncate(end);
    compact.push_str("...");
    compact
}

#[cfg(unix)]
fn request_tproxy_status(path: &Path) -> Option<crate::tproxy::TproxyStatsSnapshot> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(path).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    stream.write_all(&[0x53]).ok()?;
    let mut payload = Vec::with_capacity(256);
    stream.read_to_end(&mut payload).ok()?;
    serde_json::from_slice(&payload).ok()
}

#[cfg(not(unix))]
fn request_tproxy_status(_path: &Path) -> Option<crate::tproxy::TproxyStatsSnapshot> {
    None
}

async fn stop_tproxy_child(mut child: Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait().ok().flatten().is_some() || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub(crate) async fn port_is_listening(port: u16) -> bool {
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    matches!(
        tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(target)).await,
        Ok(Ok(_))
    )
}

async fn verify_socks5_udp_associate(config: &LocalProxyProfile) -> Result<()> {
    let destination = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let (_control_stream, relay_addr) = socks_command(config, 0x03, destination)
        .await
        .context("SOCKS5 UDP ASSOCIATE preflight failed")?;
    if !matches!(relay_addr, SocketAddr::V4(_)) {
        bail!("SOCKS5 UDP ASSOCIATE returned an IPv6 relay address; CSQTT TPROXY is IPv4-only");
    }
    Ok(())
}

pub fn validate_config(config: &LocalProxyProfile) -> Result<()> {
    if config.port == 0 {
        bail!("SOCKS5 port must be in range 1-65535");
    }
    if config.username.len() > u8::MAX as usize || config.password.len() > u8::MAX as usize {
        bail!("SOCKS5 username and password must not exceed 255 bytes");
    }
    if config.username.is_empty() && !config.password.is_empty() {
        bail!("SOCKS5 username is required when a password is set");
    }
    if config
        .username
        .chars()
        .chain(config.password.chars())
        .any(char::is_control)
    {
        bail!("SOCKS5 credentials must not contain control characters");
    }
    Ok(())
}

fn ensure_linux_platform() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("local SOCKS5 policy routing is supported only on Linux servers");
    #[cfg(target_os = "linux")]
    Ok(())
}

pub(crate) async fn socks_command(
    config: &LocalProxyProfile,
    command: u8,
    destination: SocketAddr,
) -> Result<(TcpStream, SocketAddr)> {
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    let mut stream = tokio::time::timeout(SOCKS_COMMAND_TIMEOUT, TcpStream::connect(proxy))
        .await
        .context("local SOCKS5 connection timed out")??;
    stream.set_nodelay(true).ok();

    let method = if config.username.is_empty() {
        0x00
    } else {
        0x02
    };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, method] {
        bail!("SOCKS5 authentication method was rejected");
    }

    if method == 0x02 {
        let username = config.username.as_bytes();
        let password = config.password.as_bytes();
        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.extend_from_slice(&[0x01, username.len() as u8]);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream.write_all(&auth).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response != [0x01, 0x00] {
            bail!("SOCKS5 username or password is incorrect");
        }
    }

    let mut request = vec![0x05, command, 0x00];
    append_socks_address(&mut request, destination);
    stream.write_all(&request).await?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 || response[2] != 0x00 {
        bail!("SOCKS5 command {command} failed with reply {}", response[1]);
    }
    let mut bound = read_socks_address(&mut stream, response[3]).await?;
    if bound.ip().is_unspecified() {
        bound.set_ip(proxy.ip());
    }
    Ok((stream, bound))
}

pub(crate) fn append_socks_address(target: &mut Vec<u8>, address: SocketAddr) {
    match address {
        SocketAddr::V4(value) => {
            target.push(0x01);
            target.extend_from_slice(&value.ip().octets());
        }
        SocketAddr::V6(value) => {
            target.push(0x04);
            target.extend_from_slice(&value.ip().octets());
        }
    }
    target.extend_from_slice(&address.port().to_be_bytes());
}

async fn read_socks_address(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut bytes = [0u8; 6];
            stream.read_exact(&mut bytes).await?;
            Ok(SocketAddr::from((
                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
            )))
        }
        0x04 => {
            let mut bytes = [0u8; 18];
            stream.read_exact(&mut bytes).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[..16]);
            Ok(SocketAddr::from((
                std::net::Ipv6Addr::from(ip),
                u16::from_be_bytes([bytes[16], bytes[17]]),
            )))
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0u8; length + 2];
            stream.read_exact(&mut bytes).await?;
            let host =
                std::str::from_utf8(&bytes[..length]).context("invalid SOCKS5 relay host")?;
            let port = u16::from_be_bytes([bytes[length], bytes[length + 1]]);
            tokio::net::lookup_host((host, port))
                .await?
                .next()
                .context("SOCKS5 relay host did not resolve")
        }
        _ => bail!("invalid SOCKS5 address type {atyp}"),
    }
}

pub(crate) fn socks_udp_response(packet: &[u8]) -> Result<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        bail!("invalid SOCKS5 UDP response header");
    }
    let address_len = match packet[3] {
        0x01 => 4usize,
        0x04 => 16,
        0x03 => bail!("SOCKS5 UDP responses must carry an IP address"),
        atyp => bail!("invalid SOCKS5 UDP address type {atyp}"),
    };
    let header_end = 4 + address_len + 2;
    if header_end > packet.len() {
        bail!("short SOCKS5 UDP response");
    }
    let address = &packet[4..4 + address_len];
    let ip = if address_len == 4 {
        std::net::IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))
    } else {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(address);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
    };
    let port = u16::from_be_bytes([packet[4 + address_len], packet[5 + address_len]]);
    Ok((SocketAddr::new(ip, port), &packet[header_end..]))
}

async fn activate_tproxy(runtime_id: u64, port: u16) -> Result<()> {
    let _guard = POLICY_LOCK.lock().await;
    cleanup_legacy_proxy_policy().await;
    let _ = command_output("sysctl", &["-w", "net.ipv4.conf.csqtt1.rp_filter=2"]).await;
    add_tproxy_shared_rules().await?;
    add_tproxy_rules(port).await?;
    let _ = command_output("ip", &["route", "flush", "cache"]).await;
    ACTIVE_RUNTIME.store(runtime_id, Ordering::Release);
    Ok(())
}

async fn add_tproxy_shared_rules() -> Result<()> {
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "fwmark",
            TPROXY_RULE_MARK,
            "priority",
            TPROXY_PRIORITY,
            "table",
            TPROXY_TABLE,
        ],
    )
    .await
    {}
    command_required(
        "ip",
        &[
            "rule",
            "add",
            "fwmark",
            TPROXY_RULE_MARK,
            "priority",
            TPROXY_PRIORITY,
            "table",
            TPROXY_TABLE,
        ],
    )
    .await?;
    command_required(
        "ip",
        &[
            "route",
            "replace",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            TPROXY_TABLE,
        ],
    )
    .await?;
    Ok(())
}

fn tproxy_comment(port: u16) -> String {
    format!("CSQTT_TPROXY:{port}")
}

async fn tproxy_interception_present(port: u16) -> bool {
    let port_arg = port.to_string();
    let comment = tproxy_comment(port);
    let iface = crate::tun_device::TUN_IFACE;
    let subnet = crate::tun_device::TUN_SUBNET;
    for protocol in ["tcp", "udp"] {
        if !command_success(
            "iptables",
            &[
                "-t",
                "mangle",
                "-C",
                "PREROUTING",
                "-i",
                iface,
                "-s",
                subnet,
                "-p",
                protocol,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "TPROXY",
                "--tproxy-mark",
                TPROXY_RULE_MARK,
                "--on-port",
                &port_arg,
            ],
        )
        .await
        {
            return false;
        }
    }
    match command_output("ip", &["rule", "show"]).await {
        Ok(rules) => {
            let mark = TPROXY_RULE_MARK
                .split('/')
                .next()
                .unwrap_or(TPROXY_RULE_MARK);
            rules
                .lines()
                .any(|line| line.contains(&format!("fwmark {mark}")) && line.contains(TPROXY_TABLE))
        }
        // Cannot verify: avoid repair churn on transient failures.
        Err(_) => true,
    }
}

fn spawn_rule_watchdog(port: u16, engine: tokio_util::sync::CancellationToken, log: LogFn) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = engine.cancelled() => break,
                _ = ticker.tick() => {
                    if !tproxy_interception_present(port).await {
                        log(
                            "WARNING",
                            "TPROXY interception rules vanished (firewalld reload?); re-installing",
                        );
                        let _guard = POLICY_LOCK.lock().await;
                        if add_tproxy_shared_rules().await.is_err()
                            || add_tproxy_rules(port).await.is_err()
                        {
                            log("ERROR", "Failed to re-install TPROXY interception rules");
                        }
                    }
                }
            }
        }
    });
}

async fn add_tproxy_rules(port: u16) -> Result<()> {
    cleanup_stale_tproxy_rules().await;
    let port_arg = port.to_string();
    let comment = tproxy_comment(port);
    for protocol in ["tcp", "udp"] {
        command_required(
            "iptables",
            &[
                "-t",
                "mangle",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                crate::tun_device::TUN_IFACE,
                "-s",
                crate::tun_device::TUN_SUBNET,
                "-p",
                protocol,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "TPROXY",
                "--tproxy-mark",
                TPROXY_RULE_MARK,
                "--on-port",
                &port_arg,
            ],
        )
        .await?;
    }
    command_required(
        "iptables",
        &[
            "-t",
            "raw",
            "-I",
            "PREROUTING",
            "1",
            "-i",
            crate::tun_device::TUN_IFACE,
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "comment",
            "--comment",
            &comment,
            "-j",
            "NOTRACK",
        ],
    )
    .await?;
    command_required(
        "iptables",
        &[
            "-t",
            "filter",
            "-I",
            "INPUT",
            "1",
            "-i",
            crate::tun_device::TUN_IFACE,
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "comment",
            "--comment",
            &comment,
            "-j",
            "ACCEPT",
        ],
    )
    .await?;
    Ok(())
}

async fn cleanup_stale_tproxy_rules() {
    for (table, chain) in [
        ("mangle", "PREROUTING"),
        ("raw", "PREROUTING"),
        ("filter", "INPUT"),
    ] {
        for _ in 0..8 {
            let Ok(rules) = command_output("iptables", &["-t", table, "-S", chain]).await else {
                break;
            };
            let numbers = marked_rule_numbers(&rules, chain, &["CSQTT_TPROXY"]);
            if numbers.is_empty() {
                break;
            }
            for number in numbers.into_iter().rev() {
                let number = number.to_string();
                let _ = command_output("iptables", &["-t", table, "-D", chain, &number]).await;
            }
        }
    }
}

fn marked_rule_numbers(rules: &str, chain: &str, markers: &[&str]) -> Vec<usize> {
    let prefix = format!("-A {chain}");
    let mut number = 0;
    let mut matches = Vec::new();
    for line in rules.lines() {
        if line == prefix || line.starts_with(&format!("{prefix} ")) {
            number += 1;
            if markers.iter().any(|marker| line.contains(marker)) {
                matches.push(number);
            }
        }
    }
    matches
}

async fn remove_from_subnet_rule() {
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "from",
            crate::tun_device::TUN_SUBNET,
            "priority",
            LEGACY_POLICY_PRIORITY,
            "table",
            LEGACY_POLICY_TABLE,
        ],
    )
    .await
    {}
}

async fn drop_new_flow_mark_rules() {
    while command_success(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "comment",
            "--comment",
            MARK_COMMENT,
            "-j",
            "CONNMARK",
            "--set-xmark",
            POLICY_MARK,
        ],
    )
    .await
    {}
}

async fn cleanup_mark_rules() {
    drop_new_flow_mark_rules().await;
    while command_success(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-m",
            "comment",
            "--comment",
            MARK_COMMENT,
            "-j",
            "CONNMARK",
            "--restore-mark",
        ],
    )
    .await
    {}
    while command_success(
        "ip",
        &[
            "rule",
            "del",
            "fwmark",
            POLICY_MARK,
            "priority",
            LEGACY_POLICY_PRIORITY,
            "table",
            LEGACY_POLICY_TABLE,
        ],
    )
    .await
    {}
}

async fn cleanup_nat_exemption(tun_name: &str) {
    for comment in [NAT_COMMENT, LEGACY_NAT_COMMENT] {
        while command_success(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                crate::tun_device::TUN_SUBNET,
                "-o",
                tun_name,
                "-m",
                "comment",
                "--comment",
                comment,
                "-j",
                "ACCEPT",
            ],
        )
        .await
        {}
    }
}

async fn cleanup_all_nat_exemptions() {
    let rules = command_output("iptables", &["-t", "nat", "-S", "POSTROUTING"])
        .await
        .unwrap_or_default();
    let mut interfaces = std::collections::BTreeSet::new();
    for line in rules.lines() {
        if (line.contains(NAT_COMMENT) || line.contains(LEGACY_NAT_COMMENT))
            && let Some(index) = line.find(" -o ")
            && let Some(interface) = line[index + 4..].split_whitespace().next()
        {
            interfaces.insert(interface.to_owned());
        }
    }
    for interface in interfaces {
        cleanup_nat_exemption(&interface).await;
    }
}

async fn cleanup_legacy_quic_rule() {
    while command_success(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-s",
            crate::tun_device::TUN_SUBNET,
            "-p",
            "udp",
            "--dport",
            "443",
            "-m",
            "comment",
            "--comment",
            LEGACY_QUIC_COMMENT,
            "-j",
            "REJECT",
            "--reject-with",
            "icmp-port-unreachable",
        ],
    )
    .await
    {}
}

async fn cleanup_legacy_proxy_policy() {
    // Independent legacy rule groups delete concurrently.
    tokio::join!(
        cleanup_legacy_quic_rule(),
        cleanup_mark_rules(),
        remove_from_subnet_rule(),
        cleanup_all_nat_exemptions()
    );
    let _ = command_output("ip", &["route", "flush", "table", LEGACY_POLICY_TABLE]).await;
}

async fn cleanup_shared_policy() {
    let stale_rules = cleanup_stale_tproxy_rules();
    let policy_rule = async {
        while command_success(
            "ip",
            &[
                "rule",
                "del",
                "fwmark",
                TPROXY_RULE_MARK,
                "priority",
                TPROXY_PRIORITY,
                "table",
                TPROXY_TABLE,
            ],
        )
        .await
        {}
    };
    tokio::join!(stale_rules, policy_rule);
    let _ = command_output("ip", &["route", "flush", "table", TPROXY_TABLE]).await;
    let _ = command_output("ip", &["route", "flush", "cache"]).await;
}

async fn verify_proxy_policy_clean() -> Result<()> {
    let mut rules = String::new();
    for (table, chain) in [
        ("filter", "INPUT"),
        ("filter", "FORWARD"),
        ("mangle", "PREROUTING"),
        ("mangle", "FORWARD"),
        ("raw", "PREROUTING"),
        ("nat", "POSTROUTING"),
    ] {
        if let Ok(chunk) = command_output("iptables", &["-t", table, "-S", chain]).await {
            rules.push_str(&chunk);
        }
    }
    for marker in [
        "CSQTT_TPROXY",
        NAT_COMMENT,
        MARK_COMMENT,
        LEGACY_NAT_COMMENT,
        LEGACY_QUIC_COMMENT,
    ] {
        if rules.contains(marker) {
            bail!("stale netfilter rule remains: {marker}");
        }
    }
    let rules = command_output("ip", &["-4", "rule", "show"]).await?;
    for line in rules.lines() {
        let owned_tproxy = line.trim_start().starts_with("30001:")
            && line.contains("fwmark 0x7531")
            && line.contains("lookup 30001");
        let owned_legacy = line.trim_start().starts_with("1066:")
            && (line.contains("lookup 1066") || line.contains("fwmark 0x422"));
        if owned_tproxy || owned_legacy {
            bail!("stale policy rule remains: {}", line.trim());
        }
    }
    Ok(())
}

async fn command_success(program: &str, args: &[&str]) -> bool {
    command_output(program, args).await.is_ok()
}

async fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let mut command = tokio::process::Command::new(program);
    command.kill_on_drop(true);
    if program == "iptables" {
        command.args(["-w", "2"]);
    }
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.args(args).output())
        .await
        .with_context(|| format!("timeout running {program} {}", args.join(" ")))?
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn command_required(program: &str, args: &[&str]) -> Result<()> {
    command_output(program, args).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{
        marked_rule_numbers, read_tproxy_child_error, remove_tproxy_status_file,
        socks_udp_response, tproxy_error_path, tproxy_start_error_is_retryable, validate_config,
        write_tproxy_child_error,
    };
    use crate::model::LocalProxyProfile;

    fn config() -> LocalProxyProfile {
        LocalProxyProfile {
            id: "test".to_owned(),
            name: "Test".to_owned(),
            port: 45000,
            username: String::new(),
            password: String::new(),
        }
    }

    #[test]
    fn validates_proxy_credentials() {
        assert!(validate_config(&config()).is_ok());
        let mut value = config();
        value.password = "password".to_owned();
        assert!(validate_config(&value).is_err());
        value.username = "user\nname".to_owned();
        assert!(validate_config(&value).is_err());
    }

    #[test]
    fn parses_socks5_udp_ipv4_response() {
        let mut packet = vec![0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
        packet.extend_from_slice(b"dns");
        let (source, payload) = socks_udp_response(&packet).unwrap();
        assert_eq!(payload, b"dns");
        assert_eq!(source, "1.1.1.1:53".parse().unwrap());
    }

    #[test]
    fn locates_quoted_tproxy_rules_by_chain_position() {
        let rules = concat!(
            "-P PREROUTING ACCEPT\n",
            "-A PREROUTING -i csqtt1 -p udp -m comment --comment \"CSQTT_TPROXY:10669\" -j TPROXY\n",
            "-A PREROUTING -p tcp -j ACCEPT\n",
            "-A PREROUTING -i csqtt1 -p tcp -m comment --comment \"CSQTT_TPROXY:10669\" -j TPROXY\n",
        );
        assert_eq!(
            marked_rule_numbers(rules, "PREROUTING", &["CSQTT_TPROXY"]),
            vec![1, 3]
        );
    }

    #[test]
    fn ignores_other_chains_and_is_idempotent_after_cleanup() {
        let rules = concat!(
            "-A INPUT -m comment --comment \"CSQTT_TPROXY:10669\" -j ACCEPT\n",
            "-A PREROUTING -p tcp -j ACCEPT\n",
        );
        assert!(marked_rule_numbers(rules, "PREROUTING", &["CSQTT_TPROXY"]).is_empty());
        assert!(marked_rule_numbers("", "PREROUTING", &["CSQTT_TPROXY"]).is_empty());
    }

    #[test]
    fn tproxy_child_startup_error_is_compact_and_cleaned_with_status() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let status_path = std::env::temp_dir().join(format!("csqtt-tproxy-test-{unique}.sock"));
        let error_path = tproxy_error_path(&status_path);

        write_tproxy_child_error(
            &status_path,
            "bind TPROXY child 10667\n\nCaused by:\n    transparent UDP socket: Address already in use",
        );
        let error = read_tproxy_child_error(&status_path).unwrap();
        assert!(error.contains("bind TPROXY child 10667"));
        assert!(error.contains("transparent UDP socket: Address already in use"));
        assert!(!error.contains("\n"));

        std::fs::write(&status_path, b"status").unwrap();
        remove_tproxy_status_file(&status_path);
        assert!(!status_path.exists());
        assert!(!error_path.exists());
    }

    #[test]
    fn tproxy_start_retry_is_limited_to_busy_internal_ports() {
        assert!(tproxy_start_error_is_retryable(
            "bind TPROXY child 10667: Address already in use (os error 98)"
        ));
        assert!(!tproxy_start_error_is_retryable(
            "bind TPROXY child 10667: Operation not permitted (os error 1)"
        ));
    }
}
