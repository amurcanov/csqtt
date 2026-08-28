// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#[cfg(feature = "diagnostics")]
use crate::perf::thread_cpu_time_ns;
use crate::{
    App,
    dataplane::{self, DataplaneConfig, DataplaneLogic},
    downlink_queue::DownlinkQueue,
    lock_unpoison, log_event,
    model::{
        ClientDevice, Database, TrafficCounters, TrafficSnapshot, cached_now, derive_wrap_key,
        generate_key_pair, get_next_ip, is_expired, now, resolve_session_ip,
    },
    packet::{PACKET_CAPACITY, PacketBuf, PacketBuffer},
    perf::{self, Profiler as AllProfiler, Stage as PerfStage},
    selective_fec,
    tokio_io::{IoCounters, PacketSink},
    tun_device::RouteTable,
};
use anyhow::{Context, Result, anyhow, bail};
use ctr::cipher::{InnerIvInit, KeyInit, StreamCipher};
use rand::{Rng, RngCore, SeedableRng, rngs::OsRng, rngs::StdRng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{
    Mutex, OwnedMutexGuard, RwLockReadGuard, RwLockWriteGuard, Semaphore, mpsc, oneshot,
};
use tokio_util::sync::CancellationToken;

type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;
type Aes128CtrCore = ctr::CtrCore<aes::Aes128, ctr::flavors::Ctr128BE>;

pub(crate) const MAX_ACTIVE_SESSIONS: usize = 3072;
const CONTROL_EVENT_CAPACITY: usize = 1024;
const CONTROL_TASK_CAPACITY: usize = 128;
const DB_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const TRAFFIC_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
const SESSION_SETUP_IDLE_MS: u64 = 15_000;
const SESSION_AUTH_IDLE_MS: u64 = 10 * 60 * 60 * 1_000;
const PUBLIC_SETUP_GHOST_IDLE_SECS: u64 = 30;
const PUBLIC_AUTH_GHOST_IDLE_SECS: u64 = 2 * 60;
const PUBLIC_SESSION_LIMIT: usize = MAX_ACTIVE_SESSIONS + 256;
const DIAGNOSTIC_CLIENT_LIMIT: usize = 8;
const DIAGNOSTIC_REQUEST_MAX_BYTES: usize = 128;
const DIAGNOSTIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const DIAGNOSTIC_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const DIAGNOSTIC_LEASE: Duration = Duration::from_secs(5 * 60);
const SESSION_LEASE: &[u8] = b"\xffCSQTT_LEASE";
pub const PANEL_RESTART_NOTICE: &[u8] = b"\xffCSQTT_PANEL_RESTART_V1\x00\x91\x7d\x03\xa8";
const STREAM_REPAIR_PREFIX: &[u8] = b"\xffCSQTT_STREAM_REPAIR_V1";
const STREAM_ALIVE_PREFIX: &[u8] = b"\xffCSQTT_STREAM_ALIVE_V1";
pub(crate) const MAX_STREAM_WORKERS: usize = 126;
const MAX_STREAM_WORKERS_U16: u16 = MAX_STREAM_WORKERS as u16;
const STREAM_RECONCILE_INTERVAL_MS: u64 = 3_000;
const STREAM_REPAIR_GRACE_MS: u64 = 30_000;
const STREAM_REPAIR_ESCALATE_MS: u64 = 60_000;
const STREAM_ALIVE_INTERVAL_MS: u64 = 10_000;
const STREAM_ALIVE_REPEAT: u8 = 2;
const STREAM_CONTROL_CARRIERS: usize = 3;
const STREAM_ROUND_ORPHAN_TTL_MS: u64 = 60_000;
const STREAM_INVENTORY_RESYNC_MS: u64 = 60_000;
const EPOCH_SWEEP_INTERVAL_MS: u64 = 5 * 60_000;
const DOWNLINK_DRAIN_PACKET_LIMIT: usize = 128;
const EPOCH_IDLE_TTL_MS: u64 = 60 * 60_000;
const HOT_TABLE_RESERVE: usize = 128;
const MEMORY_COMPACT_INTERVAL_MS: u64 = 5_000;
const SESSION_MAINTENANCE_INTERVAL_MS: u64 = 1_000;
const SETUP_BUDGET_PER_TICK: usize = 1024;
pub(crate) static SESSION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static ROUTE_REGISTRATION_COUNTER: AtomicU64 = AtomicU64::new(1);
static CACHED_MONOTONIC_MS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DpiFrame {
    pub timestamp_ms: u64,
    pub direction: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub pt: u8,
    pub seq: u64,
    pub len: usize,
    pub wire_len: usize,
    pub device_id: String,
    pub gen_id: u64,
    pub salt: String,
    pub detail: String,
    pub hex_preview: String,
}

pub static DPI_RING: std::sync::LazyLock<RwLock<VecDeque<DpiFrame>>> =
    std::sync::LazyLock::new(|| RwLock::new(VecDeque::with_capacity(100)));

pub static DPI_BROADCAST: std::sync::LazyLock<tokio::sync::broadcast::Sender<DpiFrame>> =
    std::sync::LazyLock::new(|| {
        let (tx, _) = tokio::sync::broadcast::channel(64);
        tx
    });

#[derive(Clone, Copy, Debug, Default)]
pub struct DpiRingMemorySnapshot {
    pub entries: usize,
    pub entry_capacity: usize,
    pub retained_bytes: usize,
}

pub fn record_dpi(frame: DpiFrame) {
    if let Ok(mut ring) = DPI_RING.try_write() {
        if ring.len() >= 100 {
            ring.pop_front();
        }
        ring.push_back(frame.clone());
    }
    let _ = DPI_BROADCAST.send(frame);
}

pub fn epoch_snapshot_len() -> usize {
    ENGINE_EPOCHS_GAUGE.load(Ordering::Relaxed) as usize
}

pub fn dpi_ring_len() -> usize {
    DPI_RING.read().map(|ring| ring.len()).unwrap_or(0)
}

pub fn dpi_ring_memory_snapshot() -> DpiRingMemorySnapshot {
    let Ok(ring) = DPI_RING.try_read() else {
        return DpiRingMemorySnapshot::default();
    };
    let strings = ring.iter().fold(0usize, |total, frame| {
        total
            .saturating_add(frame.direction.capacity())
            .saturating_add(frame.src.capacity())
            .saturating_add(frame.dst.capacity())
            .saturating_add(frame.proto.capacity())
            .saturating_add(frame.device_id.capacity())
            .saturating_add(frame.salt.capacity())
            .saturating_add(frame.detail.capacity())
            .saturating_add(frame.hex_preview.capacity())
    });
    DpiRingMemorySnapshot {
        entries: ring.len(),
        entry_capacity: ring.capacity(),
        retained_bytes: ring
            .capacity()
            .saturating_mul(std::mem::size_of::<DpiFrame>())
            .saturating_add(strings),
    }
}

pub fn hex_and_ascii_dump(data: &[u8]) -> String {
    let limit = data.len().min(64);
    let mut out = String::with_capacity(limit * 4);
    for chunk in data.get(..limit).unwrap_or_default().chunks(16) {
        for byte in chunk {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x} ");
        }
        if chunk.len() < 16 {
            for _ in 0..16 - chunk.len() {
                out.push_str("   ");
            }
        }
        out.push_str(" | ");
        for byte in chunk {
            if (32..=126).contains(byte) {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
    if data.len() > limit {
        use std::fmt::Write;
        let _ = writeln!(out, "... (+{} more bytes)", data.len() - limit);
    }
    out
}

#[inline(always)]
fn is_dpi_control(plain: &[u8]) -> bool {
    plain.starts_with(b"GETCONF:")
        || plain.starts_with(b"TUNCONF:")
        || plain == PANEL_RESTART_NOTICE
        || plain.starts_with(b"DENIED:")
        || plain.starts_with(b"DISCONNECT:")
        || (plain.len() >= 5 && matches!(plain.first(), Some(20..=22)))
}

#[inline(always)]
#[cfg(feature = "diagnostics")]
fn should_record_dpi(
    enabled: bool,
    now_ms: u64,
    payload_counter: &mut u64,
    last_sample_ms: &mut u64,
    plain: &[u8],
) -> bool {
    if !enabled {
        return false;
    }
    if !is_dpi_control(plain) {
        *payload_counter = payload_counter.wrapping_add(1);
        if *payload_counter & 511 != 0 {
            return false;
        }
    }
    if now_ms.saturating_sub(*last_sample_ms) < 200 {
        return false;
    }
    *last_sample_ms = now_ms;
    true
}

#[inline(always)]
#[cfg(not(feature = "diagnostics"))]
fn should_record_dpi(
    enabled: bool,
    now_ms: u64,
    payload_counter: &mut u64,
    last_sample_ms: &mut u64,
    plain: &[u8],
) -> bool {
    let _ = (enabled, now_ms, payload_counter, last_sample_ms, plain);
    false
}

fn display_control_payload(plain: &[u8]) -> String {
    let text = String::from_utf8_lossy(plain);
    let Some(payload) = text.strip_prefix("GETCONF:") else {
        return text.into_owned();
    };
    let parts = payload.splitn(6, '|').collect::<Vec<_>>();
    let [first, second, _, fourth, fifth, sixth] = parts.as_slice() else {
        return "GETCONF:[REDACTED]".to_owned();
    };
    format!("GETCONF:{first}|{second}|[REDACTED]|{fourth}|{fifth}|{sixth}")
}

#[allow(clippy::too_many_arguments)]
pub fn record_packet_dpi(
    direction: &'static str,
    src: &str,
    dst: &str,
    pt: u8,
    seq: u64,
    plain: &[u8],
    wire_len: usize,
    device_id: &str,
    gen_id: u64,
    salt: &str,
) {
    let control = is_dpi_control(plain);
    let proto = match pt {
        111 => "RTP-OBFS Audio (PT=111)",
        96 => "RTP-OBFS Video (PT=96)",
        _ => "RTP-OBFS (Custom)",
    };
    let detail = if [
        b"GETCONF:".as_slice(),
        b"TUNCONF:".as_slice(),
        b"DENIED:".as_slice(),
        b"DISCONNECT:".as_slice(),
    ]
    .iter()
    .any(|prefix| plain.starts_with(prefix))
    {
        display_control_payload(plain)
    } else if plain.iter().all(|byte| *byte == 0xff) {
        format!("KeepAlive Ping ({} bytes)", plain.len())
    } else {
        format!("Payload ({} bytes)", plain.len())
    };
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let hex_preview = if control {
        hex_and_ascii_dump(detail.as_bytes())
    } else {
        String::new()
    };
    record_dpi(DpiFrame {
        timestamp_ms,
        direction: direction.to_owned(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        proto: proto.to_owned(),
        pt,
        seq,
        len: plain.len(),
        wire_len,
        device_id: device_id.to_owned(),
        gen_id,
        salt: salt.to_owned(),
        detail,
        hex_preview,
    });
}

pub async fn run_dpi_server() -> Result<()> {
    if !cfg!(feature = "diagnostics") {
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:46003").await?;
    let clients = Arc::new(Semaphore::new(DIAGNOSTIC_CLIENT_LIMIT));
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = clients.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            serve_dpi_client(socket).await;
        });
    }
}

async fn serve_dpi_client(socket: tokio::net::TcpStream) {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let request = match tokio::time::timeout(
        DIAGNOSTIC_HANDSHAKE_TIMEOUT,
        read_diagnostic_request(&mut reader),
    )
    .await
    {
        Ok(Ok(Some(request))) => request,
        _ => return,
    };
    let requested = if request.starts_with("GET_DPI:") {
        request
            .strip_prefix("GET_DPI:")
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap_or(0)
    } else {
        0
    };
    let samples = if requested > 0 {
        if let Ok(ring) = DPI_RING.try_read() {
            let count = requested.min(ring.len());
            ring.iter()
                .skip(ring.len() - count)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    for frame in samples {
        if let Ok(json) = serde_json::to_string(&frame)
            && !write_diagnostic_line(&mut writer, &json).await
        {
            return;
        }
    }
    if requested > 0 {
        return;
    }
    let mut rx = DPI_BROADCAST.subscribe();
    let mut control = [0_u8; 64];
    let lease = tokio::time::sleep(DIAGNOSTIC_LEASE);
    tokio::pin!(lease);
    loop {
        tokio::select! {
            received = tokio::io::AsyncReadExt::read(&mut reader, &mut control) => {
                match received {
                    Ok(0) | Err(_) => break,
                    Ok(_) => lease.as_mut().reset(tokio::time::Instant::now() + DIAGNOSTIC_LEASE),
                }
            }
            _ = &mut lease => break,
            frame = rx.recv() => match frame {
                Ok(frame) => {
                    if let Ok(json) = serde_json::to_string(&frame)
                        && !write_diagnostic_line(&mut writer, &json).await
                    {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    drop(rx);
    if DPI_BROADCAST.receiver_count() == 0
        && let Ok(mut ring) = DPI_RING.write()
    {
        ring.clear();
        ring.shrink_to_fit();
    }
}

async fn read_diagnostic_request<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut bytes = [0u8; DIAGNOSTIC_REQUEST_MAX_BYTES + 1];
    let mut length = 0usize;
    loop {
        let read = reader.read(&mut bytes[length..]).await?;
        if read == 0 {
            if length == 0 {
                return Ok(None);
            }
            break;
        }
        let end = length + read;
        if let Some(newline) = bytes[length..end].iter().position(|byte| *byte == b'\n') {
            length += newline;
            break;
        }
        length = end;
        if length == bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "diagnostic request exceeds maximum length",
            ));
        }
    }
    let request = std::str::from_utf8(&bytes[..length]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "diagnostic request is not UTF-8",
        )
    })?;
    Ok(Some(request.trim().to_owned()))
}

async fn write_diagnostic_line<W>(writer: &mut W, line: &str) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    matches!(
        tokio::time::timeout(DIAGNOSTIC_WRITE_TIMEOUT, async {
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await
        })
        .await,
        Ok(Ok(()))
    )
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ThreadCpuFrame {
    pub tid: u32,
    pub name: String,
    pub user_cpu_ns: u64,
    pub system_cpu_ns: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SyscallsFrame {
    pub timestamp_ms: u64,
    #[serde(default)]
    pub sample_window_ns: u64,
    #[serde(default)]
    pub process_cpu_ns: u64,
    #[serde(default)]
    pub process_user_cpu_ns: u64,
    #[serde(default)]
    pub process_system_cpu_ns: u64,
    #[serde(default)]
    pub dataplane_cpu_ns: u64,
    #[serde(default)]
    pub dataplane_tid: u32,
    #[serde(default)]
    pub threads: Vec<ThreadCpuFrame>,
    pub udp_rx_pps: u64,
    pub udp_rx_bps: u64,
    pub udp_rx_errors_s: u64,
    pub udp_tx_pps: u64,
    pub udp_tx_bps: u64,
    pub udp_tx_errors_s: u64,
    pub udp_tx_drops_s: u64,
    pub tun_rx_pps: u64,
    pub tun_rx_bps: u64,
    pub tun_rx_errors_s: u64,
    pub tun_tx_pps: u64,
    pub tun_tx_bps: u64,
    pub tun_tx_errors_s: u64,
    pub tun_tx_drops_s: u64,
    pub readiness_wakeups_s: u64,
    pub recv_syscalls_s: u64,
    pub send_syscalls_s: u64,
    pub rx_eagain_s: u64,
    pub tx_eagain_s: u64,
    pub partial_sendmmsg_s: u64,
    pub crypto_ops_s: u64,
    pub active_sessions: u64,
    pub free_udp_tx_slots: u64,
    pub free_tun_tx_slots: u64,
    #[serde(default)]
    pub recv_batch_max: u64,
    #[serde(default)]
    pub udp_rx_enobufs_s: u64,
    #[serde(default)]
    pub udp_tx_enobufs_s: u64,
    pub total_udp_rx_packets: u64,
    pub total_udp_tx_packets: u64,
    pub total_tun_rx_packets: u64,
    pub total_tun_tx_packets: u64,
    #[serde(default)]
    pub crypto_sample_interval: u64,
    #[serde(default)]
    pub chacha: CryptoPerfCounters,
    #[serde(default)]
    pub srtp: CryptoPerfCounters,
    #[serde(default)]
    pub unwrap_crypto: CryptoPerfCounters,
    #[serde(default)]
    pub wrap_crypto: CryptoPerfCounters,
    #[serde(default)]
    pub all_sample_interval: u64,
    #[serde(default)]
    pub all: perf::Snapshot,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CryptoPerfCounters {
    pub operations: u64,
    pub bytes: u64,
    pub samples: u64,
    pub sampled_ns: u64,
}

impl CryptoPerfCounters {
    pub fn delta(self, previous: Self) -> Self {
        Self {
            operations: self.operations.saturating_sub(previous.operations),
            bytes: self.bytes.saturating_sub(previous.bytes),
            samples: self.samples.saturating_sub(previous.samples),
            sampled_ns: self.sampled_ns.saturating_sub(previous.sampled_ns),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoPerfSnapshot {
    pub chacha: CryptoPerfCounters,
    pub srtp: CryptoPerfCounters,
    pub unwrap_crypto: CryptoPerfCounters,
    pub wrap_crypto: CryptoPerfCounters,
}

impl CryptoPerfSnapshot {
    pub fn delta(self, previous: Self) -> Self {
        Self {
            chacha: self.chacha.delta(previous.chacha),
            srtp: self.srtp.delta(previous.srtp),
            unwrap_crypto: self.unwrap_crypto.delta(previous.unwrap_crypto),
            wrap_crypto: self.wrap_crypto.delta(previous.wrap_crypto),
        }
    }
}

pub const CRYPTO_PERF_SAMPLE_INTERVAL: u64 = perf::SAMPLE_INTERVAL;

pub static SYSCALLS_BROADCAST: std::sync::LazyLock<tokio::sync::broadcast::Sender<SyscallsFrame>> =
    std::sync::LazyLock::new(|| {
        let (tx, _) = tokio::sync::broadcast::channel(16);
        tx
    });

pub static GLOBAL_IO_COUNTERS: std::sync::LazyLock<std::sync::RwLock<crate::tokio_io::IoCounters>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(crate::tokio_io::IoCounters::default()));

pub static CRYPTO_OPS_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_SESSIONS_GAUGE: AtomicU64 = AtomicU64::new(0);
pub static HOT_SESSION_CAPACITY_GAUGE: AtomicU64 = AtomicU64::new(0);
pub static ENGINE_EPOCHS_GAUGE: AtomicU64 = AtomicU64::new(0);
pub static STREAM_REPAIRS_GAUGE: AtomicU64 = AtomicU64::new(0);
pub static STREAM_INVENTORY_GAUGE: AtomicU64 = AtomicU64::new(0);
pub static SYSCALLS_CLIENTS: AtomicU64 = AtomicU64::new(0);
static METRIC_CLIENTS: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_CRYPTO_PERF: std::sync::LazyLock<RwLock<CryptoPerfSnapshot>> =
    std::sync::LazyLock::new(|| RwLock::new(CryptoPerfSnapshot::default()));

#[derive(Clone, Copy)]
enum CryptoKind {
    Chacha,
    Srtp,
}

#[derive(Clone, Copy)]
enum CryptoDirection {
    Unwrap,
    Wrap,
}

#[derive(Default)]
struct CryptoProfiler {
    #[cfg(feature = "diagnostics")]
    enabled: bool,
    #[cfg(feature = "diagnostics")]
    cursors: [u64; 2],
    #[cfg(feature = "diagnostics")]
    counters: CryptoPerfSnapshot,
    all: AllProfiler,
}

impl CryptoProfiler {
    #[inline(always)]
    fn begin(&mut self, kind: CryptoKind, direction: CryptoDirection, bytes: usize) -> Option<u64> {
        #[cfg(feature = "diagnostics")]
        {
            if !self.enabled {
                return None;
            }
            let index = kind as usize;
            {
                let counter = match kind {
                    CryptoKind::Chacha => &mut self.counters.chacha,
                    CryptoKind::Srtp => &mut self.counters.srtp,
                };
                counter.operations = counter.operations.saturating_add(1);
                counter.bytes = counter.bytes.saturating_add(bytes as u64);
            }
            {
                let counter = match direction {
                    CryptoDirection::Unwrap => &mut self.counters.unwrap_crypto,
                    CryptoDirection::Wrap => &mut self.counters.wrap_crypto,
                };
                counter.operations = counter.operations.saturating_add(1);
                counter.bytes = counter.bytes.saturating_add(bytes as u64);
            }
            let cursor = self.cursors[index];
            self.cursors[index] = cursor.wrapping_add(1);
            if cursor.is_multiple_of(CRYPTO_PERF_SAMPLE_INTERVAL) {
                let counter = match kind {
                    CryptoKind::Chacha => &mut self.counters.chacha,
                    CryptoKind::Srtp => &mut self.counters.srtp,
                };
                counter.samples = counter.samples.saturating_add(1);
                let direction_counter = match direction {
                    CryptoDirection::Unwrap => &mut self.counters.unwrap_crypto,
                    CryptoDirection::Wrap => &mut self.counters.wrap_crypto,
                };
                direction_counter.samples = direction_counter.samples.saturating_add(1);
                Some(thread_cpu_time_ns())
            } else {
                None
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (kind, direction, bytes);
            None
        }
    }

    #[inline(always)]
    fn finish(&mut self, kind: CryptoKind, direction: CryptoDirection, started: Option<u64>) {
        #[cfg(feature = "diagnostics")]
        {
            let Some(started) = started else {
                return;
            };
            let elapsed = thread_cpu_time_ns().saturating_sub(started);
            let counter = match kind {
                CryptoKind::Chacha => &mut self.counters.chacha,
                CryptoKind::Srtp => &mut self.counters.srtp,
            };
            counter.sampled_ns = counter.sampled_ns.saturating_add(elapsed);
            let direction_counter = match direction {
                CryptoDirection::Unwrap => &mut self.counters.unwrap_crypto,
                CryptoDirection::Wrap => &mut self.counters.wrap_crypto,
            };
            direction_counter.sampled_ns = direction_counter.sampled_ns.saturating_add(elapsed);
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (kind, direction, started);
        }
    }

    #[cfg(feature = "diagnostics")]
    fn publish(&self) {
        if self.enabled
            && let Ok(mut global) = GLOBAL_CRYPTO_PERF.write()
        {
            *global = self.counters;
        }
        self.all.publish_protocol();
    }
}

#[inline(always)]
fn record_crypto_op(enabled: bool) {
    #[cfg(feature = "diagnostics")]
    {
        if enabled {
            CRYPTO_OPS_COUNTER.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[cfg(not(feature = "diagnostics"))]
    {
        let _ = enabled;
    }
}

pub async fn run_syscalls_server(app: Arc<App>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:46004").await?;
    let clients = Arc::new(Semaphore::new(DIAGNOSTIC_CLIENT_LIMIT));
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = clients.clone().try_acquire_owned() else {
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_syscalls_client(socket, app).await;
        });
    }
}

async fn serve_syscalls_client(socket: tokio::net::TcpStream, app: Arc<App>) {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let request = match tokio::time::timeout(
        DIAGNOSTIC_HANDSHAKE_TIMEOUT,
        read_diagnostic_request(&mut reader),
    )
    .await
    {
        Ok(Ok(Some(request))) => request,
        _ => return,
    };
    if request.eq_ignore_ascii_case("METRIC ALL") {
        serve_metric_client(reader, writer, app).await;
        return;
    }
    if !cfg!(feature = "diagnostics") {
        return;
    }
    let perf_all = request.eq_ignore_ascii_case("PERF")
        || request.eq_ignore_ascii_case("PERF CRYPTO")
        || request.eq_ignore_ascii_case("PERF ALL");
    let _perf_all = perf_all.then(AllPerfClient::new);
    let _syscalls = (!perf_all).then(SyscallsClient::new);
    let mut rx = SYSCALLS_BROADCAST.subscribe();
    let mut control = [0_u8; 64];
    let lease = tokio::time::sleep(DIAGNOSTIC_LEASE);
    tokio::pin!(lease);
    loop {
        tokio::select! {
            received = tokio::io::AsyncReadExt::read(&mut reader, &mut control) => {
                match received {
                    Ok(0) | Err(_) => break,
                    Ok(_) => lease.as_mut().reset(tokio::time::Instant::now() + DIAGNOSTIC_LEASE),
                }
            }
            _ = &mut lease => break,
            frame = rx.recv() => match frame {
                Ok(frame) => {
                    if let Ok(json) = serde_json::to_string(&frame)
                        && !write_diagnostic_line(&mut writer, &json).await
                    {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

async fn serve_metric_client<R, W>(mut reader: R, mut writer: W, app: Arc<App>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(_client) = MetricClient::try_new() else {
        let frame = crate::memory_metrics::MetricFrame {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64,
            error: "another `csqtt metric all` observer is already active".to_owned(),
            ..crate::memory_metrics::MetricFrame::default()
        };
        if let Ok(json) = serde_json::to_string(&frame) {
            let _ = write_diagnostic_line(&mut writer, &json).await;
        }
        return;
    };

    let mut timer = tokio::time::interval(crate::memory_metrics::METRIC_SAMPLE_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut control = [0_u8; 64];
    let lease = tokio::time::sleep(DIAGNOSTIC_LEASE);
    tokio::pin!(lease);
    loop {
        tokio::select! {
            received = tokio::io::AsyncReadExt::read(&mut reader, &mut control) => {
                match received {
                    Ok(0) | Err(_) => break,
                    Ok(_) => lease.as_mut().reset(tokio::time::Instant::now() + DIAGNOSTIC_LEASE),
                }
            }
            _ = &mut lease => break,
            _ = timer.tick() => {
                let frame = crate::memory_metrics::collect_metric_frame(&app).await;
                let Ok(json) = serde_json::to_string(&frame) else {
                    continue;
                };
                if !write_diagnostic_line(&mut writer, &json).await {
                    break;
                }
            }
        }
    }
}

struct AllPerfClient;

struct SyscallsClient;

struct MetricClient;

impl AllPerfClient {
    fn new() -> Self {
        perf::ALL_CLIENTS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for AllPerfClient {
    fn drop(&mut self) {
        perf::ALL_CLIENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SyscallsClient {
    fn new() -> Self {
        SYSCALLS_CLIENTS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for SyscallsClient {
    fn drop(&mut self) {
        SYSCALLS_CLIENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

impl MetricClient {
    fn try_new() -> Option<Self> {
        METRIC_CLIENTS
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(Self)
    }
}

impl Drop for MetricClient {
    fn drop(&mut self) {
        METRIC_CLIENTS.store(0, Ordering::Release);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceEpochDecision {
    Current,
    Advanced,
    Stale,
    SaltConflict,
}

pub struct DeviceEpochSlot {
    pub epoch: Arc<Mutex<DeviceEpochState>>,
    pub last_used_ms: AtomicU64,
}

impl DeviceEpochSlot {
    pub fn new(epoch: DeviceEpochState, now_ms: u64) -> Self {
        Self {
            epoch: Arc::new(Mutex::new(epoch)),
            last_used_ms: AtomicU64::new(now_ms),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceEpochState {
    generation_id: u64,
    session_salt: String,
}

impl DeviceEpochState {
    pub fn new(generation_id: u64, session_salt: String) -> Self {
        Self {
            generation_id,
            session_salt,
        }
    }

    fn admit(&mut self, generation_id: u64, session_salt: &str) -> DeviceEpochDecision {
        if self.generation_id == 0 && self.session_salt.is_empty() {
            self.generation_id = generation_id;
            self.session_salt = session_salt.to_owned();
            return if generation_id == 0 && session_salt.is_empty() {
                DeviceEpochDecision::Current
            } else {
                DeviceEpochDecision::Advanced
            };
        }
        if generation_id < self.generation_id {
            return DeviceEpochDecision::Stale;
        }
        if generation_id > self.generation_id {
            self.generation_id = generation_id;
            self.session_salt = session_salt.to_owned();
            return DeviceEpochDecision::Advanced;
        }
        if session_salt == self.session_salt {
            DeviceEpochDecision::Current
        } else {
            DeviceEpochDecision::SaltConflict
        }
    }

    fn matches(&self, generation_id: u64, session_salt: &str) -> bool {
        self.generation_id == generation_id && self.session_salt == session_salt
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialAccess {
    Main,
    Bound,
    Unbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionEpochIdentity {
    device_id: String,
    generation_id: u64,
    session_salt: String,
}

pub struct StreamDebugMetrics {
    active: Arc<AtomicBool>,
    generation: AtomicU64,
    started_at: AtomicU64,
    up_bytes: AtomicU64,
    down_bytes: AtomicU64,
    up_packets: AtomicU64,
    down_packets: AtomicU64,
}

impl StreamDebugMetrics {
    pub fn new(active: Arc<AtomicBool>) -> Self {
        let started_at = if active.load(Ordering::Relaxed) {
            cached_now()
        } else {
            0
        };
        Self {
            active,
            generation: AtomicU64::new(1),
            started_at: AtomicU64::new(started_at),
            up_bytes: AtomicU64::new(0),
            down_bytes: AtomicU64::new(0),
            up_packets: AtomicU64::new(0),
            down_packets: AtomicU64::new(0),
        }
    }

    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.started_at.store(cached_now(), Ordering::Relaxed);
        self.up_bytes.store(0, Ordering::Relaxed);
        self.down_bytes.store(0, Ordering::Relaxed);
        self.up_packets.store(0, Ordering::Relaxed);
        self.down_packets.store(0, Ordering::Relaxed);
    }

    #[cfg(feature = "diagnostics")]
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[cfg(feature = "diagnostics")]
    fn publish(&self, up_bytes: u64, down_bytes: u64, up_packets: u64, down_packets: u64) {
        if !self.active.load(Ordering::Acquire) {
            return;
        }
        self.up_bytes.store(up_bytes, Ordering::Relaxed);
        self.down_bytes.store(down_bytes, Ordering::Relaxed);
        self.up_packets.store(up_packets, Ordering::Relaxed);
        self.down_packets.store(down_packets, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StreamDebugSnapshot {
        let active = self.active.load(Ordering::Acquire);
        let mut started_at = self.started_at.load(Ordering::Relaxed);
        if active && started_at == 0 {
            let current = cached_now();
            let _ =
                self.started_at
                    .compare_exchange(0, current, Ordering::Relaxed, Ordering::Relaxed);
            started_at = self.started_at.load(Ordering::Relaxed);
        }
        StreamDebugSnapshot {
            active,
            started_at,
            up_bytes: self.up_bytes.load(Ordering::Relaxed),
            down_bytes: self.down_bytes.load(Ordering::Relaxed),
            up_packets: self.up_packets.load(Ordering::Relaxed),
            down_packets: self.down_packets.load(Ordering::Relaxed),
        }
    }
}

pub struct StreamDebugSnapshot {
    pub active: bool,
    pub started_at: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub up_packets: u64,
    pub down_packets: u64,
}

pub struct Session {
    pub id: u64,
    pub address: SocketAddr,
    pub password: String,
    pub device_id: std::sync::Mutex<String>,
    pub generation_id: AtomicU64,
    pub session_salt: std::sync::Mutex<String>,
    pub worker_id: AtomicU64,
    pub desired_stream_count: AtomicU64,
    pub tunnel_ip: std::sync::Mutex<Option<[u8; 4]>>,
    pub last_seen: AtomicU64,
    pub up_bytes: AtomicU64,
    pub down_bytes: AtomicU64,
    pub created_at: u64,
    pub is_srtp: bool,
    pub handshake_done: AtomicBool,
    pub has_tunnel: AtomicBool,
    pub stream_debug: StreamDebugMetrics,
    pub cancel_token: CancellationToken,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u64,
        address: SocketAddr,
        password: &str,
        device_id: &str,
        generation_id: u64,
        session_salt: &str,
        is_srtp: bool,
        stream_debug_active: Arc<AtomicBool>,
        wall_now: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            address,
            password: password.to_owned(),
            device_id: std::sync::Mutex::new(device_id.to_owned()),
            generation_id: AtomicU64::new(generation_id),
            session_salt: std::sync::Mutex::new(session_salt.to_owned()),
            worker_id: AtomicU64::new(u64::MAX),
            desired_stream_count: AtomicU64::new(0),
            tunnel_ip: std::sync::Mutex::new(None),
            last_seen: AtomicU64::new(wall_now),
            up_bytes: AtomicU64::new(0),
            down_bytes: AtomicU64::new(0),
            created_at: wall_now,
            is_srtp,
            handshake_done: AtomicBool::new(true),
            has_tunnel: AtomicBool::new(false),
            stream_debug: StreamDebugMetrics::new(stream_debug_active),
            cancel_token: CancellationToken::new(),
        })
    }
}

struct Credential {
    password: Arc<str>,
    key: [u8; 32],
    aes: aes::Aes128,
    hmac: aws_lc_rs::hmac::Key,
    chacha: aws_lc_rs::aead::LessSafeKey,
}

pub struct CredentialSet {
    entries: Vec<Credential>,
}

impl CredentialSet {
    fn contains_password(&self, password: &str) -> bool {
        self.entries
            .iter()
            .any(|credential| credential.password.as_ref() == password)
    }
}

#[derive(Clone)]
struct EpochValue {
    generation_id: u64,
    session_salt: String,
    last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct EndpointKey {
    peer: SocketAddr,
    local_ip: Option<IpAddr>,
}

impl EndpointKey {
    #[inline(always)]
    fn new(peer: SocketAddr, local_ip: Option<IpAddr>) -> Self {
        Self { peer, local_ip }
    }
}

#[derive(Clone, Copy)]
struct OutState {
    ssrc: u32,
    initial_seq: u16,
    initial_ts: u32,
    initial_abs_send_time: u32,
    started: Instant,
    count: u64,
    payload_type: u8,
    transport_seq: u16,
}

impl OutState {
    fn new(payload_type: u8) -> Self {
        let mut random = [0u8; 12];
        OsRng.fill_bytes(&mut random);
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            ssrc: u32::from_be_bytes(random[0..4].try_into().unwrap_or_default()),
            initial_seq: u16::from_be_bytes(random[4..6].try_into().unwrap_or_default()),
            initial_ts: u32::from_be_bytes(random[6..10].try_into().unwrap_or_default()),
            initial_abs_send_time: (((wall_ms * 262_144) / 1_000) as u32) & 0x00ff_ffff,
            started: Instant::now(),
            count: 0,
            payload_type,
            transport_seq: u16::from_be_bytes(random[10..12].try_into().unwrap_or_default()),
        }
    }

    #[inline(always)]
    fn clocks(&self, now: Instant) -> (u32, u32) {
        let elapsed = now.saturating_duration_since(self.started);
        (
            self.initial_ts
                .wrapping_add(duration_ticks(elapsed, rtp_clock_rate(self.payload_type))),
            self.initial_abs_send_time
                .wrapping_add(duration_ticks(elapsed, 262_144))
                & 0x00ff_ffff,
        )
    }
}

pub struct ReplayState {
    initialized: bool,
    highest: u16,
    bitmap: Option<Box<[u64; 256]>>,
}

impl ReplayState {
    pub(crate) fn new() -> Self {
        Self {
            initialized: false,
            highest: 0,
            bitmap: None,
        }
    }

    fn accept(&mut self, seq: u16) -> bool {
        self.bitmap.get_or_insert_with(|| Box::new([0; 256]));
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.set_srtp_bit(seq);
            return true;
        }
        let forward = seq.wrapping_sub(self.highest);
        if forward != 0 && forward < 32768 {
            if forward >= 16384 {
                if let Some(bitmap) = self.bitmap.as_mut() {
                    bitmap.fill(0);
                }
            } else {
                for offset in 1..=forward {
                    self.clear_srtp_bit(self.highest.wrapping_add(offset));
                }
            }
            self.highest = seq;
            self.set_srtp_bit(seq);
            return true;
        }
        let behind = self.highest.wrapping_sub(seq);
        if behind >= 16384 || self.test_srtp_bit(seq) {
            return false;
        }
        self.set_srtp_bit(seq);
        true
    }

    fn set_srtp_bit(&mut self, counter: u16) {
        let index = (counter % 16384) as usize;
        if let Some(bitmap) = self.bitmap.as_mut() {
            bitmap[index / 64] |= 1 << (index % 64);
        }
    }

    fn clear_srtp_bit(&mut self, counter: u16) {
        let index = (counter % 16384) as usize;
        if let Some(bitmap) = self.bitmap.as_mut() {
            bitmap[index / 64] &= !(1 << (index % 64));
        }
    }

    fn test_srtp_bit(&self, counter: u16) -> bool {
        let index = (counter % 16384) as usize;
        self.bitmap
            .as_ref()
            .is_some_and(|bitmap| bitmap[index / 64] & (1 << (index % 64)) != 0)
    }
}

#[cfg(feature = "diagnostics")]
struct HotDebug {
    generation: u64,
    up_bytes: u64,
    down_bytes: u64,
    up_packets: u64,
    down_packets: u64,
}

#[cfg(feature = "diagnostics")]
impl HotDebug {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            up_bytes: 0,
            down_bytes: 0,
            up_packets: 0,
            down_packets: 0,
        }
    }

    fn reset(&mut self, generation: u64) {
        self.generation = generation;
        self.up_bytes = 0;
        self.down_bytes = 0;
        self.up_packets = 0;
        self.down_packets = 0;
    }
}

struct HotSession {
    id: u64,
    peer: SocketAddr,
    local_ip: Option<IpAddr>,
    password: Arc<str>,
    device_id: String,
    generation_id: u64,
    session_salt: String,
    key: [u8; 32],
    aes: aes::Aes128,
    hmac: aws_lc_rs::hmac::Key,
    chacha: aws_lc_rs::aead::LessSafeKey,
    output: OutState,
    replay: ReplayState,
    tunnel_ip: Option<[u8; 4]>,
    registration_id: Option<u64>,
    desired_stream_count: u16,
    last_inbound_ms: u64,
    up_total: u64,
    down_total: u64,
    reported_up: u64,
    reported_down: u64,
    is_srtp: bool,
    pending_tunnel: bool,
    public: Arc<Session>,
    #[cfg(feature = "diagnostics")]
    debug: HotDebug,
    fec_profile: FecProfile,
    fec_budget: selective_fec::Budget,
}

impl HotSession {
    #[allow(clippy::too_many_arguments)]
    fn legacy(
        id: u64,
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        password: Arc<str>,
        key: [u8; 32],
        payload_type: u8,
        is_srtp: bool,
        device_id: &str,
        generation_id: u64,
        session_salt: &str,
        fec_profile: FecProfile,
        stream_debug_active: Arc<AtomicBool>,
        monotonic_ms: u64,
        wall_now: u64,
    ) -> Self {
        let public = Session::new(
            id,
            peer,
            &password,
            device_id,
            generation_id,
            session_salt,
            is_srtp,
            stream_debug_active,
            wall_now,
        );
        #[cfg(feature = "diagnostics")]
        let debug_generation = public.stream_debug.generation();
        Self {
            id,
            peer,
            local_ip,
            password,
            device_id: device_id.to_owned(),
            generation_id,
            session_salt: session_salt.to_owned(),
            key,
            aes: make_aes_key(&key),
            hmac: make_hmac_key(&key),
            chacha: aws_lc_rs::aead::LessSafeKey::new(
                aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &key)
                    .unwrap(),
            ),
            output: OutState::new(payload_type),
            replay: ReplayState::new(),
            tunnel_ip: None,
            registration_id: None,
            desired_stream_count: 0,
            last_inbound_ms: monotonic_ms,
            up_total: 0,
            down_total: 0,
            reported_up: 0,
            reported_down: 0,
            is_srtp,
            pending_tunnel: false,
            public,
            #[cfg(feature = "diagnostics")]
            debug: HotDebug::new(debug_generation),
            fec_profile,
            fec_budget: selective_fec::Budget::new(),
        }
    }

    #[inline(always)]
    fn record_debug_up(&mut self, bytes: u64, enabled: bool) {
        #[cfg(feature = "diagnostics")]
        {
            if enabled {
                self.debug.up_bytes = self.debug.up_bytes.saturating_add(bytes);
                self.debug.up_packets = self.debug.up_packets.saturating_add(1);
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (bytes, enabled);
        }
    }

    #[inline(always)]
    fn record_debug_down(&mut self, bytes: u64, enabled: bool) {
        #[cfg(feature = "diagnostics")]
        {
            if enabled {
                self.debug.down_bytes = self.debug.down_bytes.saturating_add(bytes);
                self.debug.down_packets = self.debug.down_packets.saturating_add(1);
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (bytes, enabled);
        }
    }

    fn publish_counters(
        &mut self,
        global_up: &AtomicU64,
        global_down: &AtomicU64,
        wall_now: u64,
        debug_enabled: bool,
    ) {
        let up_delta = self.up_total.saturating_sub(self.reported_up);
        let down_delta = self.down_total.saturating_sub(self.reported_down);
        if up_delta != 0 {
            self.public.up_bytes.fetch_add(up_delta, Ordering::Relaxed);
            global_up.fetch_add(up_delta, Ordering::Relaxed);
            self.reported_up = self.up_total;
        }
        if down_delta != 0 {
            self.public
                .down_bytes
                .fetch_add(down_delta, Ordering::Relaxed);
            global_down.fetch_add(down_delta, Ordering::Relaxed);
            self.reported_down = self.down_total;
        }
        self.public.last_seen.store(wall_now, Ordering::Relaxed);
        #[cfg(feature = "diagnostics")]
        {
            let generation = self.public.stream_debug.generation();
            if generation != self.debug.generation {
                self.debug.reset(generation);
            }
            if debug_enabled {
                self.public.stream_debug.publish(
                    self.debug.up_bytes,
                    self.debug.down_bytes,
                    self.debug.up_packets,
                    self.debug.down_packets,
                );
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = debug_enabled;
        }
    }
}

#[derive(Clone, Copy)]
struct DecodedPacket {
    range: RangePair,
    seq: u16,
    payload_type: u8,
    is_srtp: bool,
}

#[derive(Clone, Copy)]
struct RangePair {
    start: usize,
    end: usize,
}

impl RangePair {
    fn get<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        &packet[self.start..self.end]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetconfReconnectAction {
    Process,
    Replace,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct StreamIdentity {
    device_id: String,
    generation_id: u64,
    session_salt: String,
}

struct StreamInventory {
    desired_count: u16,
    desired_session_id: u64,
    present: [bool; MAX_STREAM_WORKERS + 1],
    carriers: Vec<usize>,
    seen: bool,
}

impl StreamInventory {
    fn new() -> Self {
        Self {
            desired_count: 0,
            desired_session_id: 0,
            present: [false; MAX_STREAM_WORKERS + 1],
            carriers: Vec::with_capacity(STREAM_CONTROL_CARRIERS),
            seen: false,
        }
    }

    fn reset(&mut self) {
        self.desired_count = 0;
        self.desired_session_id = 0;
        self.present.fill(false);
        self.carriers.clear();
        self.seen = false;
    }

    fn observe(&mut self, slot: usize, session: &HotSession, worker_id: usize) {
        if session.id >= self.desired_session_id {
            self.desired_count = session.desired_stream_count;
            self.desired_session_id = session.id;
        }
        self.present[worker_id] = true;
        self.seen = true;
        if self.carriers.len() < STREAM_CONTROL_CARRIERS {
            self.carriers.push(slot);
        }
    }

    fn fill_missing(&self, out: &mut Vec<u16>) {
        let desired = usize::from(self.desired_count).min(MAX_STREAM_WORKERS);
        for worker in 1..=desired {
            if !self.present[worker] {
                out.push(worker as u16);
            }
        }
    }
}

#[derive(Default)]
struct StreamRepairRound {
    sequence: u64,
    last_missing: Vec<u16>,
    first_missing_ms: u64,
    last_sent_ms: u64,
    alive_ids: Vec<u16>,
    alive_desired_count: u16,
    alive_sent_ms: u64,
    alive_sent: u8,
    last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum FecProfile {
    #[default]
    Safe,
    Off,
}

impl StreamRepairRound {
    fn repair_payload(
        &mut self,
        missing: &[u16],
        desired_count: u16,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        if missing != self.last_missing.as_slice() {
            self.sequence = self.sequence.wrapping_add(1).max(1);
            self.last_missing.clear();
            self.last_missing.extend_from_slice(missing);
            self.first_missing_ms = now_ms;
            self.last_sent_ms = 0;
            self.alive_ids.clear();
            self.alive_sent = 0;
        }
        if now_ms.saturating_sub(self.first_missing_ms) < STREAM_REPAIR_GRACE_MS {
            return None;
        }
        if self.last_sent_ms != 0
            && now_ms.saturating_sub(self.last_sent_ms) < STREAM_REPAIR_ESCALATE_MS
        {
            return None;
        }
        if self.last_sent_ms != 0 {
            self.sequence = self.sequence.wrapping_add(1).max(1);
        }
        self.last_sent_ms = now_ms;
        Some(stream_control_payload(
            STREAM_REPAIR_PREFIX,
            self.sequence,
            desired_count,
            &self.last_missing,
        ))
    }

    fn recovered(&mut self, desired_count: u16, now_ms: u64) {
        if self.last_missing.is_empty() {
            return;
        }
        self.alive_ids = std::mem::take(&mut self.last_missing);
        self.alive_desired_count = desired_count;
        self.alive_sent_ms = 0;
        self.alive_sent = 0;
        self.first_missing_ms = now_ms;
        self.last_sent_ms = 0;
    }

    fn alive_payload(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        if self.alive_ids.is_empty()
            || self.alive_sent >= STREAM_ALIVE_REPEAT
            || (self.alive_sent_ms != 0
                && now_ms.saturating_sub(self.alive_sent_ms) < STREAM_ALIVE_INTERVAL_MS)
        {
            return None;
        }
        self.alive_sent = self.alive_sent.saturating_add(1);
        self.alive_sent_ms = now_ms;
        Some(stream_control_payload(
            STREAM_ALIVE_PREFIX,
            self.sequence,
            self.alive_desired_count,
            &self.alive_ids,
        ))
    }

    fn active(&self) -> bool {
        !self.last_missing.is_empty()
            || (!self.alive_ids.is_empty() && self.alive_sent < STREAM_ALIVE_REPEAT)
    }
}

pub enum ProtocolCommand {
    SendPlain {
        session_id: u64,
        payload: Vec<u8>,
    },
    BroadcastPlain {
        payload: Vec<u8>,
    },
    ActivateTunnel {
        session_id: u64,
        ip: [u8; 4],
        registration_id: u64,
        worker_id: u16,
        desired_count: u16,
    },
    DeactivateTunnel {
        session_id: u64,
    },
    InjectTun {
        session_id: u64,
        payload: Vec<u8>,
    },
    UpdateEpoch {
        session_id: u64,
        device_id: String,
        generation_id: u64,
        session_salt: String,
    },
    SetAuthoritativeEpoch {
        device_id: String,
        generation_id: u64,
        session_salt: String,
    },
    DisconnectDevice {
        device_id: String,
        requester_session_id: u64,
    },
    ReplaceCredentials(Arc<CredentialSet>),
    DropSession {
        session_id: u64,
    },
    DropPassword {
        password: String,
    },
    CompactMemory {
        completed: oneshot::Sender<bool>,
    },
}

enum ControlEvent {
    SessionCreated(Arc<Session>),
    SessionClosed {
        address: SocketAddr,
        session_id: u64,
        reason: &'static str,
    },
    Payload {
        address: SocketAddr,
        session_id: u64,
        payload: Vec<u8>,
    },
    IngressBeforeTunnel {
        address: SocketAddr,
        session_id: u64,
        payload: Vec<u8>,
    },
    StreamRepair {
        device_id: String,
        generation_id: u64,
        desired_count: u16,
        sequence: u64,
        missing: Vec<u16>,
        selected_carriers: usize,
        sent_carriers: usize,
    },
    IoCounters(IoCounters),
}

pub struct ProtocolRuntime {
    dataplane: Option<dataplane::DataplaneRuntime<ProtocolCommand>>,
    control_task: tokio::task::JoinHandle<()>,
    status: tokio::sync::watch::Receiver<Option<String>>,
}

impl ProtocolRuntime {
    pub fn status_receiver(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.status.clone()
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.control_task.abort();
        let _ = tokio::time::timeout(Duration::from_millis(500), &mut self.control_task).await;
        if let Some(runtime) = self.dataplane.take() {
            runtime.shutdown()?;
        }
        Ok(())
    }
}

static CREDENTIALS_SNAPSHOT: std::sync::OnceLock<std::sync::Mutex<Arc<CredentialSet>>> =
    std::sync::OnceLock::new();
static EPOCHS_SNAPSHOT: std::sync::OnceLock<std::sync::Mutex<HashMap<String, EpochValue>>> =
    std::sync::OnceLock::new();

fn publish_credentials_snapshot(credentials: &Arc<CredentialSet>) {
    match CREDENTIALS_SNAPSHOT.get() {
        Some(snapshot) => *lock_unpoison(snapshot) = credentials.clone(),
        None => {
            let _ = CREDENTIALS_SNAPSHOT.set(std::sync::Mutex::new(credentials.clone()));
        }
    }
}

fn publish_epochs_snapshot(epochs: HashMap<String, EpochValue>) {
    match EPOCHS_SNAPSHOT.get() {
        Some(snapshot) => *lock_unpoison(snapshot) = epochs,
        None => {
            let _ = EPOCHS_SNAPSHOT.set(std::sync::Mutex::new(epochs));
        }
    }
}

fn latest_engine_state() -> (Arc<CredentialSet>, HashMap<String, EpochValue>) {
    let credentials = CREDENTIALS_SNAPSHOT
        .get()
        .expect("credential snapshot published before dataplane spawn");
    let epochs = EPOCHS_SNAPSHOT
        .get()
        .expect("epoch snapshot published before dataplane spawn");
    (
        lock_unpoison(credentials).clone(),
        lock_unpoison(epochs).clone(),
    )
}

pub async fn start(app: Arc<App>) -> Result<ProtocolRuntime> {
    let credentials = build_credentials(&app).await?;
    publish_credentials_snapshot(&credentials);
    publish_epochs_snapshot(HashMap::new());
    let (control_tx, control_rx) = mpsc::channel(CONTROL_EVENT_CAPACITY);
    let engine_factory = {
        let control_tx = control_tx.clone();
        let fec_profile = app.fec_profile;
        let stream_debug_active = app.stream_debug_active.clone();
        let shared = EngineShared {
            global_up: app.bytes_from_client.clone(),
            global_down: app.bytes_to_client.clone(),
        };
        move || {
            let (credentials, epochs) = latest_engine_state();
            ProtocolEngine::new(
                credentials,
                epochs,
                control_tx.clone(),
                fec_profile,
                stream_debug_active.clone(),
                shared.clone(),
            )
        }
    };
    let runtime = dataplane::spawn(DataplaneConfig::new(app.listen), engine_factory)
        .context("start tokio protocol dataplane")?;
    let status = runtime.status_receiver();
    app.dataplane
        .set(runtime.handle())
        .map_err(|_| anyhow!("dataplane handle already initialized"))?;
    let control_app = app.clone();
    let control_task = tokio::spawn(async move {
        control_loop(control_app, control_rx).await;
    });
    Ok(ProtocolRuntime {
        dataplane: Some(runtime),
        control_task,
        status,
    })
}

pub async fn refresh_credentials(app: &Arc<App>) -> Result<()> {
    let credentials = build_credentials(app).await?;
    publish_credentials_snapshot(&credentials);
    command(app, ProtocolCommand::ReplaceCredentials(credentials))
}

pub fn drop_password_sessions(app: &Arc<App>, password: &str) {
    let _ = command(
        app,
        ProtocolCommand::DropPassword {
            password: password.to_owned(),
        },
    );
    let candidates = app
        .sessions
        .iter()
        .filter(|entry| entry.value().password == password)
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for session_id in candidates {
        if let Some((_, session)) = app
            .sessions
            .remove_if(&session_id, |_, current| current.id == session_id)
        {
            session.cancel_token.cancel();
        }
    }
}

pub fn drop_all_sessions(app: &Arc<App>) {
    let ids = app
        .sessions
        .iter()
        .map(|entry| entry.value().id)
        .collect::<Vec<_>>();
    for session_id in ids {
        let _ = command(app, ProtocolCommand::DropSession { session_id });
    }
    for entry in app.sessions.iter() {
        entry.value().cancel_token.cancel();
    }
    app.sessions.clear();
}

pub fn notify_panel_restart(app: &Arc<App>) -> Result<()> {
    command(
        app,
        ProtocolCommand::BroadcastPlain {
            payload: PANEL_RESTART_NOTICE.to_vec(),
        },
    )
}

pub async fn compact_memory(app: &Arc<App>) -> Result<bool> {
    let (completed, confirmation) = oneshot::channel();
    command(app, ProtocolCommand::CompactMemory { completed })?;
    tokio::time::timeout(Duration::from_secs(3), confirmation)
        .await
        .map_err(|_| anyhow!("dataplane memory compaction timed out"))?
        .map_err(|_| anyhow!("dataplane stopped before memory compaction"))
}

fn command(app: &Arc<App>, command_value: ProtocolCommand) -> Result<()> {
    app.dataplane
        .get()
        .ok_or_else(|| anyhow!("dataplane is not initialized"))?
        .try_send(command_value)
}

async fn db_read<'a>(app: &'a Arc<App>) -> Result<RwLockReadGuard<'a, Database>> {
    tokio::time::timeout(DB_LOCK_TIMEOUT, app.db.read())
        .await
        .map_err(|_| anyhow!("database read lock timed out"))
}

async fn db_write<'a>(app: &'a Arc<App>) -> Result<RwLockWriteGuard<'a, Database>> {
    tokio::time::timeout(DB_LOCK_TIMEOUT, app.db.write())
        .await
        .map_err(|_| anyhow!("database write lock timed out"))
}

async fn build_credentials(app: &Arc<App>) -> Result<Arc<CredentialSet>> {
    let passwords = {
        let db = db_read(app).await?;
        let mut passwords = Vec::with_capacity(db.passwords.len() + 1);
        if !db.main_password.is_empty() {
            passwords.push(db.main_password.clone());
        }
        for (password, entry) in &db.passwords {
            if !entry.is_deactivated && !is_expired(entry) {
                passwords.push(password.clone());
            }
        }
        passwords
    };
    let active_passwords: HashSet<&str> = passwords.iter().map(String::as_str).collect();
    app.derived_keys
        .retain(|password, _| active_passwords.contains(password.as_str()));
    let mut entries = Vec::with_capacity(passwords.len());
    for password in passwords {
        let key = if let Some(existing) = app.derived_keys.get(&password) {
            *existing.value()
        } else {
            let key = derive_wrap_key(&password)?;
            app.derived_keys.insert(password.clone(), key);
            key
        };
        let cipher = aws_lc_rs::aead::LessSafeKey::new(
            aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &key).unwrap(),
        );
        entries.push(Credential {
            password: Arc::<str>::from(password),
            key,
            aes: make_aes_key(&key),
            hmac: make_hmac_key(&key),
            chacha: cipher,
        });
    }
    Ok(Arc::new(CredentialSet { entries }))
}

struct ProtocolEngine {
    credentials: Arc<CredentialSet>,
    epochs: HashMap<String, EpochValue>,
    sessions: slab::Slab<HotSession>,
    by_peer: HashMap<EndpointKey, usize>,
    by_id: HashMap<u64, usize>,
    routes: RouteTable,
    downlink: DownlinkQueue,
    control_tx: mpsc::Sender<ControlEvent>,
    fec_profile: FecProfile,
    stream_debug_active: Arc<AtomicBool>,
    global_up: Arc<AtomicU64>,
    global_down: Arc<AtomicU64>,
    rng: StdRng,
    setup_scratch: PacketBuffer,
    stale_slots: Vec<usize>,
    started: Instant,
    monotonic_ms: u64,
    wall_now: u64,
    debug_enabled: bool,
    dpi_enabled: bool,
    dpi_sample_counter: u64,
    dpi_last_sample_ms: u64,
    syscalls_enabled: bool,
    io_metrics_enabled: bool,
    setup_budget: usize,
    last_io_counters: IoCounters,
    memory_compact_pending: bool,
    last_memory_compact_ms: u64,
    last_stream_reconcile_ms: u64,
    last_stream_inventory_resync_ms: u64,
    last_session_maintenance_ms: u64,
    stream_inventory_dirty: bool,
    stream_repairs: HashMap<StreamIdentity, StreamRepairRound>,
    stream_inventory: HashMap<StreamIdentity, StreamInventory>,
    stream_actions: Vec<StreamControlAction>,
    stream_missing_scratch: Vec<u16>,
    epoch_sweep_active: HashSet<String>,
    last_epoch_sweep_ms: u64,
    batch_now: Instant,
    crypto_profiler: CryptoProfiler,
}

struct StreamControlAction {
    carriers: Vec<usize>,
    payload: Vec<u8>,
    repair: Option<StreamRepairLog>,
}

struct StreamRepairLog {
    device_id: String,
    generation_id: u64,
    desired_count: u16,
    sequence: u64,
    missing: Vec<u16>,
}

#[derive(Clone)]
struct EngineShared {
    global_up: Arc<AtomicU64>,
    global_down: Arc<AtomicU64>,
}

impl ProtocolEngine {
    fn new(
        credentials: Arc<CredentialSet>,
        epochs: HashMap<String, EpochValue>,
        control_tx: mpsc::Sender<ControlEvent>,
        fec_profile: FecProfile,
        stream_debug_active: Arc<AtomicBool>,
        shared: EngineShared,
    ) -> Self {
        let wall_now = wall_clock();
        let engine = Self {
            credentials,
            epochs,
            sessions: slab::Slab::with_capacity(HOT_TABLE_RESERVE),
            by_peer: HashMap::with_capacity(HOT_TABLE_RESERVE),
            by_id: HashMap::with_capacity(HOT_TABLE_RESERVE),
            routes: RouteTable::new(),
            downlink: DownlinkQueue::default(),
            control_tx,
            fec_profile,
            stream_debug_active,
            global_up: shared.global_up,
            global_down: shared.global_down,
            rng: StdRng::from_entropy(),
            setup_scratch: PacketBuffer::new(),
            stale_slots: Vec::with_capacity(256),
            started: Instant::now(),
            monotonic_ms: 1,
            wall_now,
            debug_enabled: false,
            dpi_enabled: false,
            dpi_sample_counter: 0,
            dpi_last_sample_ms: 0,
            syscalls_enabled: false,
            io_metrics_enabled: false,
            setup_budget: SETUP_BUDGET_PER_TICK * 2,
            last_io_counters: IoCounters::default(),
            memory_compact_pending: false,
            last_memory_compact_ms: 0,
            last_stream_reconcile_ms: 0,
            last_stream_inventory_resync_ms: 0,
            last_session_maintenance_ms: 0,
            stream_inventory_dirty: true,
            stream_repairs: HashMap::new(),
            stream_inventory: HashMap::new(),
            stream_actions: Vec::new(),
            stream_missing_scratch: Vec::new(),
            epoch_sweep_active: HashSet::new(),
            last_epoch_sweep_ms: 0,
            batch_now: Instant::now(),
            crypto_profiler: CryptoProfiler::default(),
        };
        engine.publish_session_gauges();
        engine.publish_memory_gauges();
        engine
    }

    fn publish_session_gauges(&self) {
        ACTIVE_SESSIONS_GAUGE.store(self.sessions.len() as u64, Ordering::Relaxed);
        HOT_SESSION_CAPACITY_GAUGE.store(self.sessions.capacity() as u64, Ordering::Relaxed);
    }

    fn publish_memory_gauges(&self) {
        ENGINE_EPOCHS_GAUGE.store(self.epochs.len() as u64, Ordering::Relaxed);
        STREAM_REPAIRS_GAUGE.store(self.stream_repairs.len() as u64, Ordering::Relaxed);
        STREAM_INVENTORY_GAUGE.store(self.stream_inventory.len() as u64, Ordering::Relaxed);
    }

    fn publish_epoch_state(&self) {
        publish_epochs_snapshot(self.epochs.clone());
        self.publish_memory_gauges();
    }

    fn compact_memory(&mut self, force: bool) {
        let session_count = self.sessions.len();
        let session_capacity = self.sessions.capacity();
        if !force
            && (session_capacity <= HOT_TABLE_RESERVE
                || session_count.saturating_mul(2) > session_capacity)
        {
            self.memory_compact_pending = false;
            return;
        }
        self.stream_inventory_dirty = true;
        let by_peer = &mut self.by_peer;
        let by_id = &mut self.by_id;
        let routes = &mut self.routes;
        self.sessions.compact(|session, _, new_slot| {
            by_peer.insert(EndpointKey::new(session.peer, session.local_ip), new_slot);
            by_id.insert(session.id, new_slot);
            if let (Some(ip), Some(registration_id)) = (session.tunnel_ip, session.registration_id)
            {
                routes.update_slot(ip, session.id, registration_id, new_slot);
            }
            true
        });
        self.sessions.shrink_to_fit();
        if self.sessions.capacity() < HOT_TABLE_RESERVE {
            self.sessions
                .reserve(HOT_TABLE_RESERVE.saturating_sub(self.sessions.len()));
        }
        self.by_peer.shrink_to(HOT_TABLE_RESERVE.max(session_count));
        self.by_id.shrink_to(HOT_TABLE_RESERVE.max(session_count));
        self.epochs.shrink_to_fit();
        self.stream_repairs.shrink_to_fit();
        self.stream_inventory.shrink_to_fit();
        self.stale_slots.shrink_to(256);
        self.memory_compact_pending = false;
        self.last_memory_compact_ms = self.monotonic_ms;
        self.publish_session_gauges();
        self.publish_memory_gauges();
    }

    fn shrink_stream_bookkeeping(&mut self) {
        const RETAINED_CAPACITY: usize = 32;
        if self.stream_repairs.capacity() > RETAINED_CAPACITY
            && self.stream_repairs.len().saturating_mul(4) < self.stream_repairs.capacity()
        {
            self.stream_repairs
                .shrink_to(RETAINED_CAPACITY.max(self.stream_repairs.len()));
        }
        if self.stream_inventory.capacity() > RETAINED_CAPACITY
            && self.stream_inventory.len().saturating_mul(4) < self.stream_inventory.capacity()
        {
            self.stream_inventory
                .shrink_to(RETAINED_CAPACITY.max(self.stream_inventory.len()));
        }
        if self.stream_actions.capacity() > RETAINED_CAPACITY
            && self.stream_actions.len().saturating_mul(4) < self.stream_actions.capacity()
        {
            self.stream_actions
                .shrink_to(RETAINED_CAPACITY.max(self.stream_actions.len()));
        }
    }

    fn shrink_epoch_bookkeeping(&mut self) {
        const RETAINED_CAPACITY: usize = 32;
        if self.epochs.capacity() > RETAINED_CAPACITY
            && self.epochs.len().saturating_mul(4) < self.epochs.capacity()
        {
            self.epochs
                .shrink_to(RETAINED_CAPACITY.max(self.epochs.len()));
        }
        if self.epoch_sweep_active.capacity() > RETAINED_CAPACITY
            && self.epoch_sweep_active.len().saturating_mul(4) < self.epoch_sweep_active.capacity()
        {
            self.epoch_sweep_active
                .shrink_to(RETAINED_CAPACITY.max(self.epoch_sweep_active.len()));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_legacy_session(
        &mut self,
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        password: Arc<str>,
        key: [u8; 32],
        payload_type: u8,
        is_srtp: bool,
        device_id: &str,
        generation_id: u64,
        session_salt: &str,
        replay_seq: u16,
    ) -> usize {
        let endpoint_key = EndpointKey::new(peer, local_ip);
        if let Some(old_slot) = self.by_peer.get(&endpoint_key).copied() {
            self.remove_slot_with_reason(old_slot, "peer-replaced");
        }
        let id = SESSION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut session = HotSession::legacy(
            id,
            peer,
            local_ip,
            password,
            key,
            payload_type,
            is_srtp,
            device_id,
            generation_id,
            session_salt,
            self.fec_profile,
            self.stream_debug_active.clone(),
            self.monotonic_ms,
            self.wall_now,
        );
        let _ = session.replay.accept(replay_seq);
        let public = session.public.clone();
        let slot = self.sessions.insert(session);
        self.by_peer.insert(endpoint_key, slot);
        self.by_id.insert(id, slot);
        self.stream_inventory_dirty = true;
        self.publish_session_gauges();
        let _ = self
            .control_tx
            .try_send(ControlEvent::SessionCreated(public));
        slot
    }

    fn remove_slot_with_reason(&mut self, slot: usize, reason: &'static str) {
        if !self.sessions.contains(slot) {
            return;
        }
        let mut session = self.sessions.remove(slot);
        self.memory_compact_pending = true;
        self.stream_inventory_dirty = true;
        self.publish_session_gauges();
        session.publish_counters(
            &self.global_up,
            &self.global_down,
            self.wall_now,
            self.debug_enabled,
        );
        self.by_peer
            .remove(&EndpointKey::new(session.peer, session.local_ip));
        self.by_id.remove(&session.id);
        if let (Some(ip), Some(registration_id)) = (session.tunnel_ip, session.registration_id) {
            let removed_active_route = self.routes.unregister(ip, registration_id);
            if removed_active_route {
                let worker_id = session.public.worker_id.load(Ordering::Acquire);
                let fallback = self
                    .sessions
                    .iter()
                    .filter(|(_, candidate)| {
                        candidate.tunnel_ip == Some(ip)
                            && candidate.registration_id.is_some()
                            && candidate.device_id == session.device_id
                            && candidate.generation_id == session.generation_id
                            && candidate.session_salt == session.session_salt
                            && candidate.public.worker_id.load(Ordering::Acquire) == worker_id
                    })
                    .max_by_key(|(_, candidate)| candidate.id)
                    .map(|(candidate_slot, candidate)| {
                        (
                            candidate_slot,
                            candidate.id,
                            candidate.registration_id.unwrap_or_default(),
                            candidate.public.clone(),
                        )
                    });
                if let Some((fallback_slot, fallback_id, fallback_registration, public)) = fallback
                    && let Ok(worker_id) = u16::try_from(worker_id)
                {
                    self.routes.register(
                        ip,
                        fallback_id,
                        fallback_registration,
                        worker_id,
                        fallback_slot,
                    );
                    public.has_tunnel.store(true, Ordering::Release);
                }
            }
            self.sync_downlink_profile(ip);
        }
        session.public.has_tunnel.store(false, Ordering::Release);
        session.public.cancel_token.cancel();
        let _ = self.control_tx.try_send(ControlEvent::SessionClosed {
            address: session.peer,
            session_id: session.id,
            reason,
        });
    }

    fn handle_unknown_legacy(
        &mut self,
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        wire: &[u8],
        sink: &mut PacketSink<'_>,
    ) {
        if self.sessions.len() >= MAX_ACTIVE_SESSIONS
            || wire.len() > PACKET_CAPACITY
            || self.setup_budget == 0
        {
            return;
        }
        self.setup_budget -= 1;
        let mut found = None;
        for credential in &self.credentials.entries {
            if !self.setup_scratch.copy_from(wire) {
                return;
            }
            let decoded = {
                let packet = self.setup_scratch.as_mut_slice();
                unwrap_legacy_in_place(
                    &credential.aes,
                    &credential.hmac,
                    &credential.chacha,
                    packet,
                    None,
                    self.syscalls_enabled,
                )
            };
            let Ok(decoded) = decoded else {
                continue;
            };
            let plain = decoded.range.get(self.setup_scratch.as_slice());
            let Some((device_id, generation_id, session_salt)) = parse_getconf_epoch(plain) else {
                continue;
            };
            found = Some((
                credential.password.clone(),
                credential.key,
                decoded,
                device_id.to_owned(),
                generation_id,
                session_salt.to_owned(),
                plain.to_vec(),
            ));
            break;
        }
        let Some((password, key, decoded, device_id, generation_id, session_salt, plain)) = found
        else {
            if wire.len() >= 30 {
                let _ = sink.send_udp(peer, local_ip, b"DENIED:wrong_password");
            }
            return;
        };
        let slot = self.create_legacy_session(
            peer,
            local_ip,
            password,
            key,
            decoded.payload_type,
            decoded.is_srtp,
            &device_id,
            generation_id,
            &session_salt,
            decoded.seq,
        );
        let record_dpi = should_record_dpi(
            self.dpi_enabled,
            self.monotonic_ms,
            &mut self.dpi_sample_counter,
            &mut self.dpi_last_sample_ms,
            &plain,
        );
        let Some(session) = self.sessions.get(slot) else {
            return;
        };
        if record_dpi {
            record_packet_dpi(
                "INBOUND",
                &peer.to_string(),
                "TUN-Server",
                decoded.payload_type,
                decoded.seq as u64,
                &plain,
                wire.len(),
                &session.device_id,
                session.generation_id,
                &session.session_salt,
            );
        }
        let session_id = session.id;
        let _ = self.control_tx.try_send(ControlEvent::Payload {
            address: peer,
            session_id,
            payload: plain,
        });
    }

    fn handle_existing(
        &mut self,
        slot: usize,
        local_ip: Option<IpAddr>,
        packet: &mut [u8],
        sink: &mut PacketSink<'_>,
    ) {
        if !self.sessions.contains(slot) {
            return;
        }
        let kind = if self.sessions[slot].is_srtp {
            CryptoKind::Srtp
        } else {
            CryptoKind::Chacha
        };
        let started = self
            .crypto_profiler
            .begin(kind, CryptoDirection::Unwrap, packet.len());
        let decoded = {
            let session = &mut self.sessions[slot];
            unwrap_legacy_in_place(
                &session.aes,
                &session.hmac,
                &session.chacha,
                packet,
                Some(session.is_srtp),
                self.syscalls_enabled,
            )
            .ok()
        };
        self.crypto_profiler
            .finish(kind, CryptoDirection::Unwrap, started);
        let Some(decoded) = decoded else {
            return;
        };
        let plain = decoded.range.get(packet);
        let is_getconf = plain.starts_with(b"GETCONF:");
        if is_getconf {
            let Some((incoming_device, incoming_generation, incoming_salt)) =
                parse_getconf_epoch(plain)
            else {
                return;
            };
            let session = &self.sessions[slot];
            if let Some(epoch) = self.epochs.get_mut(incoming_device) {
                epoch.last_seen_ms = self.monotonic_ms;
            }
            let authoritative = self.epochs.get(incoming_device);
            match getconf_reconnect_action_hot(
                authoritative,
                &session.device_id,
                session.generation_id,
                &session.session_salt,
                incoming_device,
                incoming_generation,
                incoming_salt,
            ) {
                GetconfReconnectAction::Reject => return,
                GetconfReconnectAction::Replace => {
                    let peer = session.peer;
                    let local_ip = local_ip.or(session.local_ip);
                    let password = session.password.clone();
                    let key = session.key;
                    let payload_type = decoded.payload_type;
                    let is_srtp = decoded.is_srtp;
                    let payload = plain.to_vec();
                    let device_id = incoming_device.to_owned();
                    let session_salt = incoming_salt.to_owned();
                    self.remove_slot_with_reason(slot, "epoch-replaced");
                    let new_slot = self.create_legacy_session(
                        peer,
                        local_ip,
                        password,
                        key,
                        payload_type,
                        is_srtp,
                        &device_id,
                        incoming_generation,
                        &session_salt,
                        decoded.seq,
                    );
                    if let Some(new_session) = self.sessions.get(new_slot) {
                        let _ = self.control_tx.try_send(ControlEvent::Payload {
                            address: new_session.peer,
                            session_id: new_session.id,
                            payload,
                        });
                    }
                    return;
                }
                GetconfReconnectAction::Process => {}
            }
        }
        let route_started = self
            .crypto_profiler
            .all
            .begin(PerfStage::RouteReplay, plain.len());
        let accepted = {
            let session = &mut self.sessions[slot];
            session.replay.accept(decoded.seq)
        };
        self.crypto_profiler
            .all
            .finish(PerfStage::RouteReplay, route_started);
        if !accepted {
            return;
        }
        let mut endpoint_key_update = None;
        {
            let session = &mut self.sessions[slot];
            session.last_inbound_ms = self.monotonic_ms;
            if local_ip.is_some() && session.local_ip != local_ip {
                endpoint_key_update = Some((session.peer, session.local_ip, local_ip));
                session.local_ip = local_ip;
            }
        }
        if let Some((peer, old_local_ip, new_local_ip)) = endpoint_key_update {
            self.by_peer.remove(&EndpointKey::new(peer, old_local_ip));
            self.by_peer
                .insert(EndpointKey::new(peer, new_local_ip), slot);
        }
        if plain == SESSION_LEASE {
            return;
        }
        let record_dpi = should_record_dpi(
            self.dpi_enabled,
            self.monotonic_ms,
            &mut self.dpi_sample_counter,
            &mut self.dpi_last_sample_ms,
            plain,
        );
        let session = &mut self.sessions[slot];
        if record_dpi {
            record_packet_dpi(
                "INBOUND",
                &session.peer.to_string(),
                "TUN-Server",
                decoded.payload_type,
                decoded.seq as u64,
                plain,
                packet.len(),
                &session.device_id,
                session.generation_id,
                &session.session_salt,
            );
        }
        if plain == b"READY" {
            send_plain(
                session,
                b"READY_OK",
                &mut self.rng,
                sink,
                &mut self.crypto_profiler,
                self.batch_now,
                SendObservability {
                    record_dpi,
                    count_crypto: self.syscalls_enabled,
                },
            );
            return;
        }
        if is_idle_keepalive(plain) {
            return;
        }
        if is_control_payload(plain) {
            let event = ControlEvent::Payload {
                address: session.peer,
                session_id: session.id,
                payload: plain.to_vec(),
            };
            let _ = self.control_tx.try_send(event);
            return;
        }
        if session.tunnel_ip.is_some() && session.registration_id.is_some() {
            let write_started = self
                .crypto_profiler
                .all
                .begin(PerfStage::TunWrite, plain.len());
            let class = crate::striped_scheduler::packet_class(plain);
            let written = sink.write_tun_priority(plain, class);
            self.crypto_profiler
                .all
                .finish(PerfStage::TunWrite, write_started);
            if written {
                session.up_total = session.up_total.saturating_add(plain.len() as u64);
                session.record_debug_up(plain.len() as u64, self.debug_enabled);
            }
            return;
        }
        if !session.pending_tunnel {
            session.pending_tunnel = true;
            let event = ControlEvent::IngressBeforeTunnel {
                address: session.peer,
                session_id: session.id,
                payload: plain.to_vec(),
            };
            if self.control_tx.try_send(event).is_err() {
                session.pending_tunnel = false;
            }
        }
    }

    fn activate_tunnel(
        &mut self,
        session_id: u64,
        ip: [u8; 4],
        registration_id: u64,
        worker_id: u16,
        desired_count: u16,
    ) -> bool {
        let Some(slot) = self.by_id.get(&session_id).copied() else {
            return false;
        };
        let mut old_ip = None;
        let activated = {
            let session = &mut self.sessions[slot];
            if let (Some(previous_ip), Some(old_registration)) =
                (session.tunnel_ip, session.registration_id)
            {
                self.routes.unregister(previous_ip, old_registration);
                old_ip = Some(previous_ip);
            }
            if self
                .routes
                .register(ip, session_id, registration_id, worker_id, slot)
            {
                session.tunnel_ip = Some(ip);
                session.registration_id = Some(registration_id);
                session.desired_stream_count = desired_count;
                session.pending_tunnel = false;
                *lock_unpoison(&session.public.tunnel_ip) = Some(ip);
                session
                    .public
                    .desired_stream_count
                    .store(u64::from(desired_count), Ordering::Release);
                session.public.has_tunnel.store(true, Ordering::Release);
                self.stream_inventory_dirty = true;
                true
            } else {
                false
            }
        };
        if let Some(old_ip) = old_ip {
            self.sync_downlink_profile(old_ip);
        }
        if activated {
            self.sync_downlink_profile(ip);
        }
        activated
    }

    fn remove_tunnel(&mut self, session_id: u64) {
        let Some(slot) = self.by_id.get(&session_id).copied() else {
            return;
        };
        let ip = {
            let session = &mut self.sessions[slot];
            let ip = session.tunnel_ip;
            if let (Some(ip), Some(registration_id)) = (ip, session.registration_id) {
                self.routes.unregister(ip, registration_id);
            }
            session.tunnel_ip = None;
            session.registration_id = None;
            session.pending_tunnel = false;
            *lock_unpoison(&session.public.tunnel_ip) = None;
            session.public.has_tunnel.store(false, Ordering::Release);
            ip
        };
        if let Some(ip) = ip {
            self.sync_downlink_profile(ip);
        }
        self.stream_inventory_dirty = true;
    }

    fn update_epoch(
        &mut self,
        session_id: u64,
        device_id: String,
        generation_id: u64,
        session_salt: String,
    ) {
        let Some(slot) = self.by_id.get(&session_id).copied() else {
            return;
        };
        let replaced_ip = {
            let session = &mut self.sessions[slot];
            let identity_changed = session.device_id != device_id
                || session.generation_id != generation_id
                || session.session_salt != session_salt;
            let ip = identity_changed.then_some(session.tunnel_ip).flatten();
            session.device_id = device_id.clone();
            session.generation_id = generation_id;
            session.session_salt = session_salt.clone();
            *lock_unpoison(&session.public.device_id) = device_id;
            session
                .public
                .generation_id
                .store(generation_id, Ordering::Release);
            *lock_unpoison(&session.public.session_salt) = session_salt;
            ip
        };
        if let Some(ip) = replaced_ip
            && let Some(key) = RouteTable::tunnel_key(ip)
        {
            self.downlink.clear(key);
        }
        self.stream_inventory_dirty = true;
    }

    fn sync_downlink_profile(&mut self, ip: [u8; 4]) {
        let Some(key) = RouteTable::tunnel_key(ip) else {
            return;
        };
        self.downlink
            .configure(key, self.routes.active_path_count(key));
    }

    fn send_down_endpoint(
        &mut self,
        endpoint: crate::tun_device::RouteEndpoint,
        packet: &[u8],
        class: crate::striped_scheduler::PacketClass,
        sink: &mut PacketSink<'_>,
    ) -> DownlinkSend {
        let Some(session) = self.sessions.get_mut(endpoint.slot) else {
            return DownlinkSend::Stale;
        };
        if session.id != endpoint.session_id
            || session.registration_id != Some(endpoint.registration_id)
        {
            return DownlinkSend::Stale;
        }
        let record_dpi = should_record_dpi(
            self.dpi_enabled,
            self.monotonic_ms,
            &mut self.dpi_sample_counter,
            &mut self.dpi_last_sample_ms,
            packet,
        );
        let sent = send_plain_mode(
            session,
            packet,
            &mut self.rng,
            sink,
            &mut self.crypto_profiler,
            self.batch_now,
            SendMode {
                class,
                observability: SendObservability {
                    record_dpi,
                    count_crypto: self.syscalls_enabled,
                },
            },
        );
        if sent {
            session.down_total = session.down_total.saturating_add(packet.len() as u64);
            session.record_debug_down(packet.len() as u64, self.debug_enabled);
            DownlinkSend::Sent
        } else {
            DownlinkSend::Backpressured
        }
    }

    fn send_down_key(
        &mut self,
        key: usize,
        packet: &[u8],
        class: crate::striped_scheduler::PacketClass,
        sink: &mut PacketSink<'_>,
    ) -> DownlinkSend {
        let Some(selection) = self.routes.select_key_window(key, class) else {
            return DownlinkSend::Stale;
        };
        for offset in 0..selection.len() {
            let Some(endpoint) = self.routes.endpoint_at(key, selection, offset) else {
                break;
            };
            match self.send_down_endpoint(endpoint, packet, class, sink) {
                DownlinkSend::Stale => continue,
                result => return result,
            }
        }
        DownlinkSend::Stale
    }

    fn drain_downlink(&mut self, sink: &mut PacketSink<'_>) {
        let mut remaining = DOWNLINK_DRAIN_PACKET_LIMIT;
        for class in [
            crate::striped_scheduler::PacketClass::Latency,
            crate::striped_scheduler::PacketClass::Priority,
            crate::striped_scheduler::PacketClass::Bulk,
        ] {
            while remaining != 0 {
                if !sink.has_udp_tx_slot() {
                    return;
                }
                let Some((key, packet)) = self.downlink.dequeue(class) else {
                    break;
                };
                match self.send_down_key(key, packet.as_slice(), class, sink) {
                    DownlinkSend::Backpressured => {
                        self.downlink.requeue_front(key, class, packet);
                        return;
                    }
                    DownlinkSend::Sent | DownlinkSend::Stale => {
                        self.downlink.recycle(key, class, packet);
                        remaining -= 1;
                    }
                }
            }
        }
    }

    fn send_stream_control(
        &mut self,
        carriers: &[usize],
        payload: &[u8],
        sink: &mut PacketSink<'_>,
    ) -> usize {
        let mut sent = 0usize;
        for slot in carriers.iter().copied() {
            if sent >= STREAM_CONTROL_CARRIERS {
                return sent;
            }
            let Some(session) = self.sessions.get_mut(slot) else {
                continue;
            };
            if send_plain(
                session,
                payload,
                &mut self.rng,
                sink,
                &mut self.crypto_profiler,
                self.batch_now,
                SendObservability {
                    record_dpi: false,
                    count_crypto: self.syscalls_enabled,
                },
            ) {
                sent += 1;
            }
        }
        sent
    }

    fn reconcile_streams(&mut self, sink: &mut PacketSink<'_>) {
        if self
            .monotonic_ms
            .saturating_sub(self.last_stream_reconcile_ms)
            < STREAM_RECONCILE_INTERVAL_MS
        {
            return;
        }
        self.last_stream_reconcile_ms = self.monotonic_ms;
        let rebuild_inventory = self.stream_inventory_dirty
            || self
                .monotonic_ms
                .saturating_sub(self.last_stream_inventory_resync_ms)
                >= STREAM_INVENTORY_RESYNC_MS;
        let mut inventory = std::mem::take(&mut self.stream_inventory);
        if rebuild_inventory {
            for streams in inventory.values_mut() {
                streams.reset();
            }
            for (slot, session) in self.sessions.iter() {
                let desired_count = usize::from(session.desired_stream_count);
                if desired_count == 0
                    || desired_count > MAX_STREAM_WORKERS
                    || session.registration_id.is_none()
                {
                    continue;
                }
                let worker_id = session.public.worker_id.load(Ordering::Acquire) as usize;
                if worker_id == 0 || worker_id > desired_count || worker_id > MAX_STREAM_WORKERS {
                    continue;
                }
                inventory
                    .entry(StreamIdentity {
                        device_id: session.device_id.clone(),
                        generation_id: session.generation_id,
                        session_salt: session.session_salt.clone(),
                    })
                    .or_insert_with(StreamInventory::new)
                    .observe(slot, session, worker_id);
            }
            inventory.retain(|_, streams| streams.seen);
            self.stream_inventory_dirty = false;
            self.last_stream_inventory_resync_ms = self.monotonic_ms;
        }
        let now_ms = self.monotonic_ms;
        let mut actions = std::mem::take(&mut self.stream_actions);
        for (identity, streams) in inventory.iter() {
            let round = match self.stream_repairs.get_mut(identity) {
                Some(round) => round,
                None => self.stream_repairs.entry(identity.clone()).or_default(),
            };
            round.last_seen_ms = now_ms;
            self.stream_missing_scratch.clear();
            streams.fill_missing(&mut self.stream_missing_scratch);
            let missing = self.stream_missing_scratch.as_slice();
            if missing.is_empty() {
                round.recovered(streams.desired_count, now_ms);
                if let Some(payload) = round.alive_payload(now_ms) {
                    actions.push(StreamControlAction {
                        carriers: streams.carriers.clone(),
                        payload,
                        repair: None,
                    });
                }
            } else if let Some(payload) =
                round.repair_payload(missing, streams.desired_count, now_ms)
            {
                actions.push(StreamControlAction {
                    carriers: streams.carriers.clone(),
                    payload,
                    repair: Some(StreamRepairLog {
                        device_id: identity.device_id.clone(),
                        generation_id: identity.generation_id,
                        desired_count: streams.desired_count,
                        sequence: round.sequence,
                        missing: missing.to_vec(),
                    }),
                });
            }
        }
        self.stream_repairs.retain(|identity, round| {
            inventory.contains_key(identity)
                || !round.active()
                || now_ms.saturating_sub(round.last_seen_ms) < STREAM_ROUND_ORPHAN_TTL_MS
        });
        for action in actions.drain(..) {
            let selected_carriers = action.carriers.len();
            let sent_carriers = self.send_stream_control(&action.carriers, &action.payload, sink);
            if let Some(repair) = action.repair {
                let _ = self.control_tx.try_send(ControlEvent::StreamRepair {
                    device_id: repair.device_id,
                    generation_id: repair.generation_id,
                    desired_count: repair.desired_count,
                    sequence: repair.sequence,
                    missing: repair.missing,
                    selected_carriers,
                    sent_carriers,
                });
            }
        }
        self.stream_inventory = inventory;
        self.stream_actions = actions;
        self.shrink_stream_bookkeeping();
        self.publish_memory_gauges();
    }

    fn sweep_idle_epochs(&mut self) {
        if self.monotonic_ms.saturating_sub(self.last_epoch_sweep_ms) < EPOCH_SWEEP_INTERVAL_MS {
            return;
        }
        self.last_epoch_sweep_ms = self.monotonic_ms;
        self.epoch_sweep_active.clear();
        for (_, session) in self.sessions.iter() {
            if !session.device_id.is_empty() {
                self.epoch_sweep_active.insert(session.device_id.clone());
            }
        }
        let before = self.epochs.len();
        self.epochs.retain(|device_id, epoch| {
            self.epoch_sweep_active.contains(device_id)
                || self.monotonic_ms.saturating_sub(epoch.last_seen_ms) < EPOCH_IDLE_TTL_MS
        });
        self.shrink_epoch_bookkeeping();
        if self.epochs.len() != before {
            self.publish_epoch_state();
        } else {
            self.publish_memory_gauges();
        }
    }

    fn handle_tun_packet(&mut self, packet: &[u8], _sink: &mut PacketSink<'_>) {
        let route_started = self
            .crypto_profiler
            .all
            .begin(PerfStage::RouteReplay, packet.len());
        let Some(key) = RouteTable::packet_key(packet) else {
            self.crypto_profiler
                .all
                .finish(PerfStage::RouteReplay, route_started);
            return;
        };
        let class = crate::striped_scheduler::packet_class(packet);
        self.crypto_profiler
            .all
            .finish(PerfStage::RouteReplay, route_started);
        let _ = self.downlink.enqueue(key, class, packet);
    }
}

impl DataplaneLogic for ProtocolEngine {
    type Command = ProtocolCommand;

    fn on_udp(
        &mut self,
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        packet: &mut [u8],
        sink: &mut PacketSink<'_>,
    ) {
        let key = EndpointKey::new(peer, local_ip);
        if let Some(slot) = self.by_peer.get(&key).copied() {
            self.handle_existing(slot, local_ip, packet, sink);
            return;
        }
        if local_ip.is_some()
            && let Some(slot) = self.by_peer.get(&EndpointKey::new(peer, None)).copied()
        {
            self.handle_existing(slot, local_ip, packet, sink);
            return;
        }
        self.handle_unknown_legacy(peer, local_ip, packet, sink);
    }

    fn on_tun(&mut self, packet: &mut [u8], sink: &mut PacketSink<'_>) {
        self.handle_tun_packet(packet, sink);
    }

    fn on_tun_batch_end(&mut self, sink: &mut PacketSink<'_>) {
        self.drain_downlink(sink);
    }

    fn begin_batch(&mut self, now: Instant) {
        self.batch_now = now;
    }

    fn on_command(&mut self, command_value: Self::Command, sink: &mut PacketSink<'_>) {
        match command_value {
            ProtocolCommand::SendPlain {
                session_id,
                payload,
            } => {
                if let Some(slot) = self.by_id.get(&session_id).copied() {
                    let record_dpi = should_record_dpi(
                        self.dpi_enabled,
                        self.monotonic_ms,
                        &mut self.dpi_sample_counter,
                        &mut self.dpi_last_sample_ms,
                        &payload,
                    );
                    let session = &mut self.sessions[slot];
                    let _ = send_plain(
                        session,
                        &payload,
                        &mut self.rng,
                        sink,
                        &mut self.crypto_profiler,
                        self.batch_now,
                        SendObservability {
                            record_dpi,
                            count_crypto: self.syscalls_enabled,
                        },
                    );
                }
            }
            ProtocolCommand::BroadcastPlain { payload } => {
                let record_dpi = should_record_dpi(
                    self.dpi_enabled,
                    self.monotonic_ms,
                    &mut self.dpi_sample_counter,
                    &mut self.dpi_last_sample_ms,
                    &payload,
                );
                let rng = &mut self.rng;
                let profiler = &mut self.crypto_profiler;
                let batch_now = self.batch_now;
                let count_crypto = self.syscalls_enabled;
                for (_, session) in self.sessions.iter_mut() {
                    let _ = send_plain(
                        session,
                        &payload,
                        rng,
                        sink,
                        profiler,
                        batch_now,
                        SendObservability {
                            record_dpi,
                            count_crypto,
                        },
                    );
                }
            }
            ProtocolCommand::ActivateTunnel {
                session_id,
                ip,
                registration_id,
                worker_id,
                desired_count,
            } => {
                self.activate_tunnel(session_id, ip, registration_id, worker_id, desired_count);
            }
            ProtocolCommand::DeactivateTunnel { session_id } => self.remove_tunnel(session_id),
            ProtocolCommand::InjectTun {
                session_id,
                payload,
            } => {
                if let Some(slot) = self.by_id.get(&session_id).copied()
                    && sink.write_tun_priority(
                        &payload,
                        crate::striped_scheduler::packet_class(&payload),
                    )
                {
                    let session = &mut self.sessions[slot];
                    session.up_total = session.up_total.saturating_add(payload.len() as u64);
                    session.record_debug_up(payload.len() as u64, self.debug_enabled);
                }
            }
            ProtocolCommand::UpdateEpoch {
                session_id,
                device_id,
                generation_id,
                session_salt,
            } => self.update_epoch(session_id, device_id, generation_id, session_salt),
            ProtocolCommand::SetAuthoritativeEpoch {
                device_id,
                generation_id,
                session_salt,
            } => {
                self.stale_slots.clear();
                for (slot, session) in self.sessions.iter() {
                    if session_is_retired_by_epoch(
                        &session.device_id,
                        session.generation_id,
                        &session.session_salt,
                        &device_id,
                        generation_id,
                        &session_salt,
                    ) {
                        self.stale_slots.push(slot);
                    }
                }
                while let Some(slot) = self.stale_slots.pop() {
                    self.remove_slot_with_reason(slot, "authoritative-epoch-replaced");
                }
                self.epochs.insert(
                    device_id,
                    EpochValue {
                        generation_id,
                        session_salt,
                        last_seen_ms: self.monotonic_ms,
                    },
                );
                self.publish_epoch_state();
            }
            ProtocolCommand::DisconnectDevice {
                device_id,
                requester_session_id,
            } => {
                if let Some(slot) = self.by_id.get(&requester_session_id).copied() {
                    let payload = b"OK:disconnected";
                    let record_dpi = should_record_dpi(
                        self.dpi_enabled,
                        self.monotonic_ms,
                        &mut self.dpi_sample_counter,
                        &mut self.dpi_last_sample_ms,
                        payload,
                    );
                    let session = &mut self.sessions[slot];
                    let _ = send_plain(
                        session,
                        payload,
                        &mut self.rng,
                        sink,
                        &mut self.crypto_profiler,
                        self.batch_now,
                        SendObservability {
                            record_dpi,
                            count_crypto: self.syscalls_enabled,
                        },
                    );
                }
                self.stale_slots.clear();
                for (slot, session) in self.sessions.iter() {
                    if session_is_disconnected_device(
                        session.id,
                        &session.device_id,
                        requester_session_id,
                        &device_id,
                    ) {
                        self.stale_slots.push(slot);
                    }
                }
                while let Some(slot) = self.stale_slots.pop() {
                    self.remove_slot_with_reason(slot, "device-disconnect");
                }
            }
            ProtocolCommand::ReplaceCredentials(credentials) => {
                self.stale_slots.clear();
                for (slot, session) in self.sessions.iter() {
                    if !credentials.contains_password(&session.password) {
                        self.stale_slots.push(slot);
                    }
                }
                while let Some(slot) = self.stale_slots.pop() {
                    self.remove_slot_with_reason(slot, "credential-removed");
                }
                self.credentials = credentials;
            }
            ProtocolCommand::DropSession { session_id } => {
                if let Some(slot) = self.by_id.get(&session_id).copied() {
                    self.remove_slot_with_reason(slot, "requested-session-drop");
                }
            }
            ProtocolCommand::DropPassword { password } => {
                self.stale_slots.clear();
                for (slot, session) in self.sessions.iter() {
                    if session.password.as_ref() == password {
                        self.stale_slots.push(slot);
                    }
                }
                while let Some(slot) = self.stale_slots.pop() {
                    self.remove_slot_with_reason(slot, "credential-removed");
                }
            }
            ProtocolCommand::CompactMemory { completed } => {
                self.compact_memory(true);
                let _ = completed.send(crate::collect_allocator_thread_heap());
            }
        }
    }

    fn on_tick(&mut self, _sink: &mut PacketSink<'_>) {
        self.monotonic_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64 + 1;
        self.wall_now = wall_clock();
        #[cfg(feature = "diagnostics")]
        {
            self.debug_enabled = self.stream_debug_active.load(Ordering::Acquire);
            self.dpi_enabled = DPI_BROADCAST.receiver_count() != 0;
            self.syscalls_enabled = SYSCALLS_CLIENTS.load(Ordering::Acquire) != 0;
            self.crypto_profiler.all.refresh_enabled();
            self.crypto_profiler.enabled = self.crypto_profiler.all.enabled();
            self.io_metrics_enabled = self.syscalls_enabled || self.crypto_profiler.all.enabled();
            self.crypto_profiler.publish();
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            self.debug_enabled = false;
            self.dpi_enabled = false;
            self.syscalls_enabled = false;
            self.io_metrics_enabled = false;
        }
        self.setup_budget = SETUP_BUDGET_PER_TICK;
        if self
            .monotonic_ms
            .saturating_sub(self.last_session_maintenance_ms)
            >= SESSION_MAINTENANCE_INTERVAL_MS
        {
            self.last_session_maintenance_ms = self.monotonic_ms;
            self.stale_slots.clear();
            let global_up = &self.global_up;
            let global_down = &self.global_down;
            let monotonic_ms = self.monotonic_ms;
            let wall_now = self.wall_now;
            let debug_enabled = self.debug_enabled;
            for (slot, session) in self.sessions.iter_mut() {
                session.publish_counters(global_up, global_down, wall_now, debug_enabled);
                let idle_ms = monotonic_ms.saturating_sub(session.last_inbound_ms);
                if (session.registration_id.is_none() && idle_ms >= SESSION_SETUP_IDLE_MS)
                    || (session.registration_id.is_some() && idle_ms >= SESSION_AUTH_IDLE_MS)
                {
                    self.stale_slots.push(slot);
                }
            }
            while let Some(slot) = self.stale_slots.pop() {
                let reason = hot_session_idle_reason(
                    self.sessions
                        .get(slot)
                        .is_some_and(|session| session.registration_id.is_some()),
                );
                self.remove_slot_with_reason(slot, reason);
            }
        }
        self.reconcile_streams(_sink);
        self.sweep_idle_epochs();
        if self.memory_compact_pending
            && self
                .monotonic_ms
                .saturating_sub(self.last_memory_compact_ms)
                >= MEMORY_COMPACT_INTERVAL_MS
        {
            self.compact_memory(false);
        }
    }

    fn on_io_counters(&mut self, counters: IoCounters) {
        if let Ok(mut global) = GLOBAL_IO_COUNTERS.write() {
            *global = counters;
        }
        let errors_changed = counters.udp_rx_errors != self.last_io_counters.udp_rx_errors
            || counters.udp_tx_errors != self.last_io_counters.udp_tx_errors
            || counters.tun_rx_errors != self.last_io_counters.tun_rx_errors
            || counters.tun_tx_errors != self.last_io_counters.tun_tx_errors
            || counters.udp_tx_drops != self.last_io_counters.udp_tx_drops
            || counters.tun_tx_drops != self.last_io_counters.tun_tx_drops
            || counters.partial_sendmmsg != self.last_io_counters.partial_sendmmsg
            || counters.udp_rx_enobufs != self.last_io_counters.udp_rx_enobufs
            || counters.udp_tx_enobufs != self.last_io_counters.udp_tx_enobufs;
        if errors_changed {
            let _ = self.control_tx.try_send(ControlEvent::IoCounters(counters));
        }
        self.last_io_counters = counters;
    }
}

fn wall_clock() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    duration.as_secs()
}

pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn make_aes_key(key: &[u8; 32]) -> aes::Aes128 {
    let mut value = [0u8; 16];
    value.copy_from_slice(&key[..16]);
    aes::Aes128::new(&value.into())
}

fn make_hmac_key(key: &[u8; 32]) -> aws_lc_rs::hmac::Key {
    aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key[16..])
}

#[inline(always)]
fn aes_ctr(cipher: &aes::Aes128, iv: &[u8; 16]) -> Aes128Ctr128BE {
    Aes128Ctr128BE::from_core(Aes128CtrCore::inner_iv_init(cipher.clone(), iv.into()))
}

fn nonce(ssrc: u32, seq: u16, timestamp: u32) -> [u8; 12] {
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&ssrc.to_be_bytes());
    value[4..6].copy_from_slice(&seq.to_be_bytes());
    value[8..12].copy_from_slice(&timestamp.to_be_bytes());
    value
}

fn build_srtp_iv(ssrc: u32, seq: u16, timestamp: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&ssrc.to_be_bytes());
    iv[4..6].copy_from_slice(&seq.to_be_bytes());
    iv[8..12].copy_from_slice(&timestamp.to_be_bytes());
    iv
}

#[inline(always)]
fn rtp_clock_rate(payload_type: u8) -> u32 {
    if payload_type == 96 { 90_000 } else { 48_000 }
}

#[inline(always)]
fn duration_ticks(elapsed: Duration, clock_rate: u32) -> u32 {
    let rate = u64::from(clock_rate);
    elapsed
        .as_secs()
        .wrapping_mul(rate)
        .wrapping_add(u64::from(elapsed.subsec_nanos()).wrapping_mul(rate) / 1_000_000_000)
        as u32
}

fn rtp_header_len(wire: &[u8]) -> Result<usize> {
    if wire.len() < 13 || wire[0] >> 6 != 2 {
        bail!("invalid RTP packet");
    }
    let mut header_len = 12usize;
    if wire[0] & 0x10 != 0 {
        if wire.len() < 16 {
            bail!("packet too short for extension header");
        }
        let words = u16::from_be_bytes(wire[14..16].try_into()?) as usize;
        header_len = header_len
            .checked_add(4 + words * 4)
            .ok_or_else(|| anyhow!("RTP header length overflow"))?;
    }
    if wire.len() < header_len {
        bail!("packet too short for calculated RTP header");
    }
    Ok(header_len)
}

fn unwrap_legacy_in_place(
    aes: &aes::Aes128,
    hmac: &aws_lc_rs::hmac::Key,
    chacha: &aws_lc_rs::aead::LessSafeKey,
    wire: &mut [u8],
    expected_srtp: Option<bool>,
    count_crypto: bool,
) -> Result<DecodedPacket> {
    let header_len = rtp_header_len(wire)?;
    let payload_type = wire[1] & 0x7f;
    if payload_type != 111 && payload_type != 96 && payload_type != 6 {
        bail!("unsupported RTP payload type");
    }
    let seq = u16::from_be_bytes([wire[2], wire[3]]);
    let timestamp = u32::from_be_bytes(wire[4..8].try_into()?);
    let ssrc = u32::from_be_bytes(wire[8..12].try_into()?);
    if expected_srtp != Some(false) && wire.len() >= header_len + 10 {
        let message_len = wire.len() - 10;
        let mut context = aws_lc_rs::hmac::Context::with_key(hmac);
        context.update(&wire[..message_len]);
        let expected = context.sign();
        if expected.as_ref()[..10].ct_eq(&wire[message_len..]).into() {
            let mut end = message_len;
            if wire[0] & 0x20 != 0 {
                let padding = wire[end - 1] as usize;
                if padding == 0 || padding > end.saturating_sub(header_len) {
                    bail!("invalid RTP padding in SRTP mode");
                }
                end -= padding;
            }
            if end < header_len {
                bail!("invalid SRTP payload bounds");
            }
            let iv = build_srtp_iv(ssrc, seq, timestamp);
            let mut cipher = aes_ctr(aes, &iv);
            cipher.apply_keystream(&mut wire[header_len..end]);
            if end.saturating_sub(header_len) >= 13 && (20..=23).contains(&wire[header_len]) {
                let mut offset = header_len;
                while offset + 13 <= end {
                    if !(20..=23).contains(&wire[offset]) || wire[offset + 1] != 0xfe {
                        break;
                    }
                    let record_len =
                        13 + (((wire[offset + 11] as usize) << 8) | wire[offset + 12] as usize);
                    if offset + record_len > end {
                        break;
                    }
                    offset += record_len;
                }
                if offset > header_len {
                    end = offset;
                }
            }
            record_crypto_op(count_crypto);
            return Ok(DecodedPacket {
                range: RangePair {
                    start: header_len,
                    end,
                },
                seq,
                payload_type,
                is_srtp: true,
            });
        }
        if expected_srtp == Some(true) {
            bail!("SRTP authentication failed");
        }
    } else if expected_srtp == Some(true) {
        bail!("SRTP packet is too short");
    }
    let mut end = wire.len();
    if wire[0] & 0x20 != 0 {
        let padding = wire
            .last()
            .copied()
            .ok_or_else(|| anyhow!("missing RTP padding"))? as usize;
        if padding == 0 || padding > end.saturating_sub(header_len) {
            bail!("invalid RTP padding");
        }
        end -= padding;
    }
    if end <= header_len + 16 {
        bail!("empty encrypted payload");
    }
    if payload_type != 111 {
        bail!("expected audio (PT=111) for non-SRTP packet");
    }
    let tag_offset = end - 16;
    let tag: [u8; 16] = wire[tag_offset..end].try_into()?;
    let (aad, encrypted_and_tag) = wire.split_at_mut(header_len);
    let ciphertext_len = tag_offset - header_len;
    chacha
        .open_in_place_separate_tag(
            aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce(ssrc, seq, timestamp)),
            aws_lc_rs::aead::Aad::from(aad),
            &tag,
            &mut encrypted_and_tag[..ciphertext_len],
        )
        .map_err(|_| anyhow!("authentication failed (ChaCha20-Poly1305)"))?;
    record_crypto_op(count_crypto);
    Ok(DecodedPacket {
        range: RangePair {
            start: header_len,
            end: tag_offset,
        },
        seq,
        payload_type,
        is_srtp: false,
    })
}

#[derive(Clone, Copy)]
struct SendObservability {
    record_dpi: bool,
    count_crypto: bool,
}

#[derive(Clone, Copy)]
struct SendMode {
    class: crate::striped_scheduler::PacketClass,
    observability: SendObservability,
}

enum DownlinkSend {
    Sent,
    Stale,
    Backpressured,
}

fn send_plain(
    session: &mut HotSession,
    plain: &[u8],
    rng: &mut StdRng,
    sink: &mut PacketSink<'_>,
    profiler: &mut CryptoProfiler,
    batch_now: Instant,
    observability: SendObservability,
) -> bool {
    send_plain_mode(
        session,
        plain,
        rng,
        sink,
        profiler,
        batch_now,
        SendMode {
            class: crate::striped_scheduler::PacketClass::Bulk,
            observability,
        },
    )
}

fn send_plain_mode(
    session: &mut HotSession,
    plain: &[u8],
    rng: &mut StdRng,
    sink: &mut PacketSink<'_>,
    profiler: &mut CryptoProfiler,
    batch_now: Instant,
    mode: SendMode,
) -> bool {
    send_legacy_plain(session, plain, rng, sink, profiler, batch_now, mode)
}

fn send_legacy_plain(
    session: &mut HotSession,
    plain: &[u8],
    rng: &mut StdRng,
    sink: &mut PacketSink<'_>,
    profiler: &mut CryptoProfiler,
    batch_now: Instant,
    mode: SendMode,
) -> bool {
    let peer = session.peer;
    let local_ip = session.local_ip;
    let duplicate = session.fec_profile == FecProfile::Safe
        && selective_fec::should_duplicate(plain)
        && session.fec_budget.allow();
    let mut wire_len = 0usize;
    let kind = if session.is_srtp {
        CryptoKind::Srtp
    } else {
        CryptoKind::Chacha
    };
    let queue_started = profiler.all.begin(PerfStage::UdpQueue, plain.len());
    let sent =
        sink.send_udp_with_duplicate_priority(peer, local_ip, duplicate, mode.class, |output| {
            let started = profiler.begin(kind, CryptoDirection::Wrap, plain.len());
            let wrapped = match wrap_legacy_into(
                session,
                plain,
                rng,
                output,
                batch_now,
                mode.observability.count_crypto,
            ) {
                Ok(length) => {
                    wire_len = length;
                    true
                }
                Err(_) => false,
            };
            profiler.finish(kind, CryptoDirection::Wrap, started);
            wrapped
        });
    profiler.all.finish(PerfStage::UdpQueue, queue_started);
    if sent
        && (mode.class == crate::striped_scheduler::PacketClass::Latency
            || should_flush_udp_immediately(plain))
    {
        sink.request_udp_flush();
    }
    if sent && mode.observability.record_dpi {
        record_packet_dpi(
            "OUTBOUND",
            "TUN-Server",
            &peer.to_string(),
            session.output.payload_type,
            u64::from(
                session
                    .output
                    .initial_seq
                    .wrapping_add(session.output.count.wrapping_sub(1) as u16),
            ),
            plain,
            wire_len,
            &session.device_id,
            session.generation_id,
            &session.session_salt,
        );
    }
    sent
}

fn wrap_legacy_into(
    session: &mut HotSession,
    plain: &[u8],
    rng: &mut StdRng,
    output: &mut PacketBuf,
    batch_now: Instant,
    count_crypto: bool,
) -> Result<usize> {
    let count = session.output.count;
    session.output.count = session.output.count.wrapping_add(1);
    let seq = session.output.initial_seq.wrapping_add(count as u16);
    let (timestamp, abs_send_time) = session.output.clocks(batch_now);
    let transport_seq = session.output.transport_seq;
    session.output.transport_seq = session.output.transport_seq.wrapping_add(1);
    let payload_type = session.output.payload_type;
    let mut header = [0u8; 24];
    header[0] = 0xb0;
    header[1] = payload_type & 0x7f;
    if payload_type == 96 && rng.gen_range(0..5u8) == 0 {
        header[1] |= 0x80;
    }
    header[2..4].copy_from_slice(&seq.to_be_bytes());
    header[4..8].copy_from_slice(&timestamp.to_be_bytes());
    header[8..12].copy_from_slice(&session.output.ssrc.to_be_bytes());
    header[12..14].copy_from_slice(&[0xbe, 0xde]);
    header[14..16].copy_from_slice(&2u16.to_be_bytes());
    header[16] = 0x32;
    let abs_bytes = abs_send_time.to_be_bytes();
    header[17..20].copy_from_slice(&abs_bytes[1..4]);
    header[20] = 0x51;
    header[21..23].copy_from_slice(&transport_seq.to_be_bytes());
    header[23] = 0;
    let storage = output.storage_mut();
    if session.is_srtp {
        let padding_max = if payload_type == 96 { 60 } else { 24 };
        let random_padding = rng.gen_range(0..padding_max);
        let padding = random_padding + 1;
        let ciphertext_len = plain
            .len()
            .checked_add(padding)
            .ok_or_else(|| anyhow!("SRTP length overflow"))?;
        let total = 24usize
            .checked_add(ciphertext_len)
            .and_then(|value| value.checked_add(10))
            .ok_or_else(|| anyhow!("SRTP length overflow"))?;
        if total > storage.len() {
            bail!("SRTP output exceeds packet capacity");
        }
        storage[..24].copy_from_slice(&header);
        storage[24..24 + plain.len()].copy_from_slice(plain);
        let iv = build_srtp_iv(session.output.ssrc, seq, timestamp);
        let mut cipher = aes_ctr(&session.aes, &iv);
        cipher.apply_keystream(&mut storage[24..24 + plain.len()]);
        if random_padding != 0 {
            rng.fill_bytes(&mut storage[24 + plain.len()..24 + plain.len() + random_padding]);
        }
        storage[24 + ciphertext_len - 1] = padding as u8;
        let mut context = aws_lc_rs::hmac::Context::with_key(&session.hmac);
        context.update(&storage[..24 + ciphertext_len]);
        let tag = context.sign();
        storage[24 + ciphertext_len..total].copy_from_slice(&tag.as_ref()[..10]);
        if !output.set_len(total) {
            bail!("SRTP output length rejected");
        }
        record_crypto_op(count_crypto);
        return Ok(total);
    }
    let random_padding = if payload_type == 111 {
        rng.gen_range(0..24usize)
    } else {
        rng.gen_range(0..60usize)
    };
    let padding = random_padding + 1;
    let total = 24usize
        .checked_add(plain.len())
        .and_then(|value| value.checked_add(16))
        .and_then(|value| value.checked_add(padding))
        .ok_or_else(|| anyhow!("RTP AEAD length overflow"))?;
    if total > storage.len() {
        bail!("RTP AEAD output exceeds packet capacity");
    }
    storage[..24].copy_from_slice(&header);
    storage[24..24 + plain.len()].copy_from_slice(plain);
    let tag = session
        .chacha
        .seal_in_place_separate_tag(
            aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce(
                session.output.ssrc,
                seq,
                timestamp,
            )),
            aws_lc_rs::aead::Aad::from(&header[..]),
            &mut storage[24..24 + plain.len()],
        )
        .map_err(|_| anyhow!("encryption failed (ChaCha20-Poly1305)"))?;
    let tag_start = 24 + plain.len();
    storage[tag_start..tag_start + 16].copy_from_slice(tag.as_ref());
    let padding_start = tag_start + 16;
    if random_padding != 0 {
        rng.fill_bytes(&mut storage[padding_start..padding_start + random_padding]);
    }
    storage[total - 1] = padding as u8;
    if !output.set_len(total) {
        bail!("RTP AEAD output length rejected");
    }
    record_crypto_op(count_crypto);
    Ok(total)
}

fn stream_control_payload(
    prefix: &[u8],
    sequence: u64,
    desired_count: u16,
    worker_ids: &[u16],
) -> Vec<u8> {
    let count = worker_ids.len().min(u8::MAX as usize);
    let mut payload = Vec::with_capacity(prefix.len() + 11 + count * 2);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&desired_count.to_be_bytes());
    payload.push(count as u8);
    for worker_id in worker_ids.iter().take(count) {
        payload.extend_from_slice(&worker_id.to_be_bytes());
    }
    payload
}

fn parse_generation_id(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok()
}

fn parse_getconf_epoch(payload: &[u8]) -> Option<(&str, u64, &str)> {
    let text = std::str::from_utf8(payload).ok()?;
    let content = text.strip_prefix("GETCONF:")?.trim();
    let mut parts = content.splitn(6, '|');
    parts.next()?;
    let device_id = parts.next()?.trim();
    parts.next()?;
    let generation_id = parse_generation_id(parts.next()?.trim())?;
    let session_salt = parts.next().unwrap_or("").trim();
    if device_id.is_empty() || device_id.len() > 128 || session_salt.len() > 128 {
        return None;
    }
    Some((device_id, generation_id, session_salt))
}

fn is_control_payload(payload: &[u8]) -> bool {
    payload.starts_with(b"GETCONF:")
        || payload.starts_with(b"DISCONNECT:")
        || payload == b"READY"
        || payload.first().is_some_and(|byte| *byte == 0xff)
}

#[inline(always)]
fn is_idle_keepalive(payload: &[u8]) -> bool {
    (!payload.is_empty() && payload.iter().all(|byte| *byte == 0xff))
        || ((4..=9).contains(&payload.len()) && payload.first() == Some(&0xff))
}

#[inline(always)]
fn should_flush_udp_immediately(payload: &[u8]) -> bool {
    payload.starts_with(b"GETCONF:")
        || payload.starts_with(b"TUNCONF:")
        || payload.starts_with(b"DENIED:")
        || payload.starts_with(b"DISCONNECT:")
        || payload.starts_with(STREAM_REPAIR_PREFIX)
        || payload.starts_with(STREAM_ALIVE_PREFIX)
        || payload == b"READY"
        || payload == b"READY_OK"
        || payload == PANEL_RESTART_NOTICE
}

fn session_is_retired_by_epoch(
    session_device_id: &str,
    session_generation_id: u64,
    session_salt: &str,
    authoritative_device_id: &str,
    authoritative_generation_id: u64,
    authoritative_salt: &str,
) -> bool {
    session_device_id == authoritative_device_id
        && (session_generation_id < authoritative_generation_id
            || (session_generation_id == authoritative_generation_id
                && session_salt != authoritative_salt))
}

fn session_is_disconnected_device(
    session_id: u64,
    session_device_id: &str,
    requester_session_id: u64,
    target_device_id: &str,
) -> bool {
    session_id == requester_session_id || session_device_id == target_device_id
}

fn getconf_reconnect_action_hot(
    authoritative: Option<&EpochValue>,
    session_device_id: &str,
    session_generation_id: u64,
    session_salt: &str,
    incoming_device_id: &str,
    incoming_generation_id: u64,
    incoming_salt: &str,
) -> GetconfReconnectAction {
    if !session_device_id.is_empty()
        && (session_device_id != incoming_device_id
            || incoming_generation_id < session_generation_id
            || (incoming_generation_id == session_generation_id && incoming_salt != session_salt))
    {
        return GetconfReconnectAction::Reject;
    }
    if let Some(epoch) = authoritative {
        if incoming_generation_id < epoch.generation_id
            || (incoming_generation_id == epoch.generation_id
                && incoming_salt != epoch.session_salt)
        {
            return GetconfReconnectAction::Reject;
        }
        if incoming_generation_id == epoch.generation_id && incoming_salt == epoch.session_salt {
            return if session_device_id == incoming_device_id
                && session_generation_id == incoming_generation_id
                && session_salt == incoming_salt
            {
                GetconfReconnectAction::Process
            } else {
                GetconfReconnectAction::Replace
            };
        }
        return GetconfReconnectAction::Replace;
    }
    if session_device_id.is_empty() {
        return GetconfReconnectAction::Process;
    }
    if session_device_id != incoming_device_id
        || incoming_generation_id < session_generation_id
        || (incoming_generation_id == session_generation_id && incoming_salt != session_salt)
    {
        return GetconfReconnectAction::Reject;
    }
    if incoming_generation_id == session_generation_id {
        GetconfReconnectAction::Process
    } else {
        GetconfReconnectAction::Replace
    }
}

async fn control_loop(app: Arc<App>, mut receiver: mpsc::Receiver<ControlEvent>) {
    let mut last_io = IoCounters::default();
    let jobs = Arc::new(Semaphore::new(CONTROL_TASK_CAPACITY));
    while let Some(event) = receiver.recv().await {
        match event {
            ControlEvent::SessionCreated(session) => {
                prune_public_sessions(&app, now().max(0) as u64);
                if let Some((_, old)) = app.sessions.remove(&session.id) {
                    old.cancel_token.cancel();
                }
                if app.sessions.len() < PUBLIC_SESSION_LIMIT {
                    app.total_connections.fetch_add(1, Ordering::Relaxed);
                    log_event(
                        &app,
                        "INFO",
                        "SESSION",
                        &format!(
                            "Created {} session for {}",
                            if session.is_srtp { "SRTP" } else { "RTP" },
                            session.address
                        ),
                    );
                    app.sessions.insert(session.id, session);
                }
            }
            ControlEvent::SessionClosed {
                address,
                session_id,
                reason,
            } => {
                if let Some((_, session)) = app
                    .sessions
                    .remove_if(&session_id, |_, current| current.id == session_id)
                {
                    session.cancel_token.cancel();
                    log_event(
                        &app,
                        "INFO",
                        "SESSION",
                        &format!("Closed session for {address}: {reason}"),
                    );
                }
            }
            ControlEvent::Payload {
                address,
                session_id,
                payload,
            } => {
                let Ok(permit) = jobs.clone().acquire_owned().await else {
                    return;
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    process_control_payload_event(app, address, session_id, payload).await;
                });
            }
            ControlEvent::IngressBeforeTunnel {
                address,
                session_id,
                payload,
            } => {
                let Ok(permit) = jobs.clone().acquire_owned().await else {
                    return;
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    process_ingress_before_tunnel_event(app, address, session_id, payload).await;
                });
            }
            ControlEvent::StreamRepair {
                device_id,
                generation_id,
                desired_count,
                sequence,
                missing,
                selected_carriers,
                sent_carriers,
            } => {
                log_event(
                    &app,
                    "WARN",
                    "STREAM",
                    &format!(
                        "Repair requested: device={device_id} gen={generation_id} missing={missing:?}/{desired_count} sequence={sequence} carriers={sent_carriers}/{selected_carriers}",
                    ),
                );
            }
            ControlEvent::IoCounters(counters) => {
                let delta_errors = counters
                    .udp_rx_errors
                    .saturating_sub(last_io.udp_rx_errors)
                    .saturating_add(counters.udp_tx_errors.saturating_sub(last_io.udp_tx_errors))
                    .saturating_add(counters.tun_rx_errors.saturating_sub(last_io.tun_rx_errors))
                    .saturating_add(counters.tun_tx_errors.saturating_sub(last_io.tun_tx_errors));
                let delta_udp_drops = counters.udp_tx_drops.saturating_sub(last_io.udp_tx_drops);
                let delta_tun_drops = counters.tun_tx_drops.saturating_sub(last_io.tun_tx_drops);
                if delta_errors != 0 || delta_udp_drops != 0 || delta_tun_drops != 0 {
                    log_event(
                        &app,
                        "WARN",
                        "DATAPLANE",
                        &format!(
                            "I/O errors +{delta_errors}, UDP TX drops +{delta_udp_drops}, TUN TX drops +{delta_tun_drops}; udp_rx={}, udp_tx={}, tun_rx={}, tun_tx={}",
                            counters.udp_rx_packets,
                            counters.udp_tx_packets,
                            counters.tun_rx_packets,
                            counters.tun_tx_packets
                        ),
                    );
                }
                last_io = counters;
            }
        }
    }
}

async fn process_control_payload_event(
    app: Arc<App>,
    address: SocketAddr,
    session_id: u64,
    payload: Vec<u8>,
) {
    let session = app
        .sessions
        .get(&session_id)
        .and_then(|entry| (entry.value().id == session_id).then(|| entry.value().clone()));
    if let Some(session) = session
        && let Err(error) = process_control_payload(&app, &session, &payload).await
    {
        log_event(
            &app,
            "WARN",
            "SESSION",
            &format!("{address}: control payload rejected: {error}"),
        );
    }
}

async fn process_ingress_before_tunnel_event(
    app: Arc<App>,
    address: SocketAddr,
    session_id: u64,
    payload: Vec<u8>,
) {
    let session = app
        .sessions
        .get(&session_id)
        .and_then(|entry| (entry.value().id == session_id).then(|| entry.value().clone()));
    if let Some(session) = session {
        if let Err(error) = ensure_control_tunnel(&app, &session).await {
            log_event(
                &app,
                "WARN",
                "TUN",
                &format!("{address}: tunnel setup failed: {error}"),
            );
            drop_exact_session(&app, &session);
        } else {
            let _ = command(
                &app,
                ProtocolCommand::InjectTun {
                    session_id,
                    payload,
                },
            );
        }
    }
}

struct ControlWriter<'a> {
    app: &'a Arc<App>,
    session_id: u64,
}

impl ControlWriter<'_> {
    async fn write(&self, payload: &[u8]) -> Result<()> {
        command(
            self.app,
            ProtocolCommand::SendPlain {
                session_id: self.session_id,
                payload: payload.to_vec(),
            },
        )
    }
}

async fn process_control_payload(
    app: &Arc<App>,
    session: &Arc<Session>,
    payload: &[u8],
) -> Result<()> {
    let writer = ControlWriter {
        app,
        session_id: session.id,
    };
    if payload.starts_with(b"GETCONF:") {
        let text = std::str::from_utf8(payload)?;
        return handle_getconf(app, &writer, session, text).await;
    }
    if payload.starts_with(b"DISCONNECT:") {
        let text = std::str::from_utf8(payload)?;
        let content = text.strip_prefix("DISCONNECT:").unwrap_or_default().trim();
        let mut parts = content.splitn(2, '|');
        let device_id = parts.next().unwrap_or("").trim();
        let salt = parts.next().unwrap_or("").trim();
        match handle_disconnect(app, session, device_id, salt).await {
            Ok(_) => {}
            Err(response) => writer.write(response.as_bytes()).await?,
        }
        return Ok(());
    }
    Ok(())
}

fn getconf_credential_access(
    db: &Database,
    password: &str,
    device_id: &str,
) -> std::result::Result<CredentialAccess, &'static str> {
    if !db.main_password.is_empty() && password == db.main_password {
        if !db.main_device_id.is_empty() && db.main_device_id != device_id {
            return Err("DENIED:device_mismatch");
        }
        return Ok(CredentialAccess::Main);
    }
    let Some(entry) = db.passwords.get(password) else {
        return Err("DENIED:expired");
    };
    if is_expired(entry) {
        return Err("DENIED:expired");
    }
    if entry.is_deactivated {
        return Err("DENIED:deactivated");
    }
    if !entry.device_id.is_empty() && entry.device_id != device_id {
        return Err("DENIED:device_mismatch");
    }
    if let Some(device) = db.devices.get(device_id)
        && !device.bound_password.is_empty()
        && device.bound_password != password
    {
        let owner_password = &device.bound_password;
        let owner_claims = if !db.main_password.is_empty() && owner_password == &db.main_password {
            db.main_device_id == device_id
        } else {
            db.passwords
                .get(owner_password)
                .is_some_and(|owner| owner.device_id == device_id)
        };
        if owner_claims {
            return Err("DENIED:device_mismatch");
        }
    }
    if entry.device_id.is_empty() {
        Ok(CredentialAccess::Unbound)
    } else {
        Ok(CredentialAccess::Bound)
    }
}

fn device_control_authorized(db: &Database, password: &str, device_id: &str) -> bool {
    if device_id.is_empty() {
        return false;
    }
    if !db.main_password.is_empty() && password == db.main_password {
        if !db.main_device_id.is_empty() && db.main_device_id != device_id {
            return false;
        }
        return db.devices.contains_key(device_id);
    }
    let password_authorized = db.passwords.get(password).is_some_and(|entry| {
        !is_expired(entry)
            && !entry.is_deactivated
            && !entry.device_id.is_empty()
            && entry.device_id == device_id
    });
    password_authorized
        && db
            .devices
            .get(device_id)
            .is_some_and(|device| device.bound_password == password)
}

fn session_epoch_identity(session: &Session) -> SessionEpochIdentity {
    SessionEpochIdentity {
        device_id: lock_unpoison(&session.device_id).clone(),
        generation_id: session.generation_id.load(Ordering::Acquire),
        session_salt: lock_unpoison(&session.session_salt).clone(),
    }
}

fn set_public_epoch(session: &Session, device_id: &str, generation_id: u64, session_salt: &str) {
    *lock_unpoison(&session.device_id) = device_id.to_owned();
    session
        .generation_id
        .store(generation_id, Ordering::Release);
    *lock_unpoison(&session.session_salt) = session_salt.to_owned();
}

fn current_device_epoch(app: &Arc<App>, device_id: &str, slot: &Arc<DeviceEpochSlot>) -> bool {
    app.device_epochs
        .get(device_id)
        .is_some_and(|entry| Arc::ptr_eq(entry.value(), slot))
}

async fn fresh_device_epoch_slot(app: &Arc<App>, device_id: &str) -> DeviceEpochSlot {
    let state = match db_read(app).await {
        Ok(db) => db
            .devices
            .get(device_id)
            .map(|device| {
                DeviceEpochState::new(device.last_generation_id, device.last_session_salt.clone())
            })
            .unwrap_or_default(),
        Err(_) => DeviceEpochState::default(),
    };
    DeviceEpochSlot::new(state, unix_time_ms())
}

async fn lock_device_epoch(
    app: &Arc<App>,
    device_id: &str,
) -> (
    Arc<DeviceEpochSlot>,
    OwnedMutexGuard<DeviceEpochState>,
    bool,
) {
    loop {
        let (slot, created) =
            if let Some(existing) = app.device_epochs.get(device_id).map(|e| e.value().clone()) {
                (existing, false)
            } else {
                let fresh = Arc::new(fresh_device_epoch_slot(app, device_id).await);
                match app.device_epochs.entry(device_id.to_owned()) {
                    dashmap::mapref::entry::Entry::Occupied(entry) => (entry.get().clone(), false),
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert(fresh.clone());
                        (fresh, true)
                    }
                }
            };
        let guard = slot.epoch.clone().lock_owned().await;
        slot.last_used_ms.store(unix_time_ms(), Ordering::Relaxed);
        if current_device_epoch(app, device_id, &slot) {
            return (slot, guard, created);
        }
    }
}

async fn lock_existing_device_epoch(
    app: &Arc<App>,
    device_id: &str,
) -> Option<(Arc<DeviceEpochSlot>, OwnedMutexGuard<DeviceEpochState>)> {
    loop {
        let slot = app
            .device_epochs
            .get(device_id)
            .map(|entry| entry.value().clone())?;
        let guard = slot.epoch.clone().lock_owned().await;
        slot.last_used_ms.store(unix_time_ms(), Ordering::Relaxed);
        if current_device_epoch(app, device_id, &slot) {
            return Some((slot, guard));
        }
    }
}

fn rejected_session_is_request(
    session: &Session,
    device_id: &str,
    generation_id: u64,
    session_salt: &str,
) -> bool {
    let identity = session_epoch_identity(session);
    identity.device_id.is_empty()
        || (identity.device_id == device_id
            && identity.generation_id == generation_id
            && identity.session_salt == session_salt)
}

fn drop_exact_session(app: &Arc<App>, session: &Arc<Session>) {
    let _ = command(
        app,
        ProtocolCommand::DropSession {
            session_id: session.id,
        },
    );
    if let Some((_, removed)) = app
        .sessions
        .remove_if(&session.id, |_, current| current.id == session.id)
    {
        removed.cancel_token.cancel();
    }
}

fn getconf_log_status(response: &str) -> &str {
    if response.starts_with("TUNCONF:") {
        "TUNCONF"
    } else {
        response
    }
}

fn log_getconf_result(
    app: &Arc<App>,
    session: &Arc<Session>,
    device_id: &str,
    generation_id: Option<u64>,
    worker_id: Option<u16>,
    desired_count: Option<u16>,
    response: &str,
) {
    let generation = generation_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_owned());
    let worker = worker_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_owned());
    let desired = desired_count
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_owned());
    log_event(
        app,
        "INFO",
        "GETCONF",
        &format!(
            "GETCONF {} device={} gen={} worker={}/{} -> {}",
            session.address,
            device_id,
            generation,
            worker,
            desired,
            getconf_log_status(response)
        ),
    );
}

pub fn purge_stale_device_sessions(
    app: &Arc<App>,
    device_id: &str,
    generation_id: u64,
    session_salt: &str,
    current_session_id: u64,
) {
    let candidates = app
        .sessions
        .iter()
        .filter_map(|entry| {
            let session = entry.value();
            if session.id == current_session_id {
                return None;
            }
            let identity = session_epoch_identity(session);
            (identity.device_id == device_id
                && (identity.generation_id != generation_id
                    || identity.session_salt != session_salt))
                .then_some((session.id, session.address))
        })
        .collect::<Vec<_>>();
    for (session_id, address) in candidates {
        let _ = command(app, ProtocolCommand::DropSession { session_id });
        if let Some((_, removed)) = app
            .sessions
            .remove_if(&session_id, |_, current| current.id == session_id)
        {
            removed.cancel_token.cancel();
            log_event(
                app,
                "INFO",
                "SESSION",
                &format!("Purged stale session for device {device_id} at {address}"),
            );
        }
    }
}

fn purge_replaced_worker_sessions(
    app: &Arc<App>,
    device_id: &str,
    generation_id: u64,
    session_salt: &str,
    worker_id: u64,
    current_session_id: u64,
) {
    let candidates = app
        .sessions
        .iter()
        .filter_map(|entry| {
            let session = entry.value();
            if session.id == current_session_id
                || session.worker_id.load(Ordering::Acquire) != worker_id
            {
                return None;
            }
            let identity = session_epoch_identity(session);
            (identity.device_id == device_id
                && identity.generation_id == generation_id
                && identity.session_salt == session_salt)
                .then_some(session.id)
        })
        .collect::<Vec<_>>();
    for session_id in candidates {
        let _ = command(app, ProtocolCommand::DropSession { session_id });
        if let Some((_, removed)) = app
            .sessions
            .remove_if(&session_id, |_, current| current.id == session_id)
        {
            removed.cancel_token.cancel();
        }
    }
}

async fn handle_getconf(
    app: &Arc<App>,
    writer: &ControlWriter<'_>,
    session: &Arc<Session>,
    text: &str,
) -> Result<()> {
    let content = text.strip_prefix("GETCONF:").unwrap_or_default().trim();
    let mut parts = content.splitn(7, '|');
    let client_port = parts.next().unwrap_or("9000").trim();
    let device_id = parts.next().unwrap_or("unknown").trim();
    let password = parts.next().unwrap_or("").trim();
    let generation_text = parts.next().unwrap_or("").trim();
    let session_salt = parts.next().unwrap_or("").trim();
    let worker_text = parts.next().unwrap_or("").trim();
    let desired_text = parts.next().unwrap_or("").trim();
    let Some(generation_id) = parse_generation_id(generation_text) else {
        log_getconf_result(
            app,
            session,
            device_id,
            None,
            None,
            None,
            "DENIED:invalid_epoch",
        );
        writer.write(b"DENIED:invalid_epoch").await?;
        return Ok(());
    };
    if password != session.password {
        log_getconf_result(
            app,
            session,
            device_id,
            Some(generation_id),
            None,
            None,
            "DENIED:wrong_password",
        );
        writer.write(b"DENIED:wrong_password").await?;
        return Ok(());
    }
    if device_id.is_empty() || device_id.len() > 128 {
        log_getconf_result(
            app,
            session,
            device_id,
            Some(generation_id),
            None,
            None,
            "DENIED:invalid_device",
        );
        writer.write(b"DENIED:invalid_device").await?;
        return Ok(());
    }
    if client_port.parse::<u16>().is_err() {
        log_getconf_result(
            app,
            session,
            device_id,
            Some(generation_id),
            None,
            None,
            "DENIED:invalid_port",
        );
        writer.write(b"DENIED:invalid_port").await?;
        return Ok(());
    }
    if session_salt.len() > 128 {
        log_getconf_result(
            app,
            session,
            device_id,
            Some(generation_id),
            None,
            None,
            "DENIED:invalid_epoch",
        );
        writer.write(b"DENIED:invalid_epoch").await?;
        return Ok(());
    }
    let Ok(worker_id @ 1..=MAX_STREAM_WORKERS_U16) = worker_text.parse::<u16>() else {
        log_getconf_result(
            app,
            session,
            device_id,
            Some(generation_id),
            None,
            None,
            "DENIED:invalid_worker",
        );
        writer.write(b"DENIED:invalid_worker").await?;
        return Ok(());
    };
    let desired_count = if desired_text.is_empty() {
        0
    } else {
        let Ok(count @ 1..=MAX_STREAM_WORKERS_U16) = desired_text.parse::<u16>() else {
            log_getconf_result(
                app,
                session,
                device_id,
                Some(generation_id),
                Some(worker_id),
                None,
                "DENIED:invalid_worker_count",
            );
            writer.write(b"DENIED:invalid_worker_count").await?;
            return Ok(());
        };
        if worker_id > count {
            log_getconf_result(
                app,
                session,
                device_id,
                Some(generation_id),
                Some(worker_id),
                Some(count),
                "DENIED:invalid_worker_count",
            );
            writer.write(b"DENIED:invalid_worker_count").await?;
            return Ok(());
        }
        count
    };
    let preliminary = {
        let db = db_read(app).await?;
        getconf_credential_access(&db, password, device_id)
    };
    if let Err(response) = preliminary {
        log_getconf_result(
            app,
            session,
            device_id,
            Some(generation_id),
            Some(worker_id),
            Some(desired_count),
            response,
        );
        writer.write(response.as_bytes()).await?;
        if rejected_session_is_request(session, device_id, generation_id, session_salt) {
            drop_exact_session(app, session);
        }
        return Ok(());
    }
    let (epoch_lock, mut epoch, created_epoch) = lock_device_epoch(app, device_id).await;
    let dns = app.dns.read().await.clone();
    let (response, reject_session, authorization_rejected, tunnel_ip, changed) = {
        let mut db = db_write(app).await?;
        let mut changed = false;
        let mut reject_session = false;
        let access = getconf_credential_access(&db, password, device_id);
        let authorization_rejected = access.is_err();
        let mut tunnel_ip = None;
        let response = match access {
            Err(response) => {
                reject_session = true;
                response.to_owned()
            }
            Ok(access) => match epoch.admit(generation_id, session_salt) {
                DeviceEpochDecision::Stale => {
                    reject_session = true;
                    "DENIED:stale_generation".to_owned()
                }
                DeviceEpochDecision::SaltConflict => {
                    reject_session = true;
                    "DENIED:session_conflict".to_owned()
                }
                DeviceEpochDecision::Current | DeviceEpochDecision::Advanced => {
                    set_public_epoch(session, device_id, generation_id, session_salt);
                    session
                        .worker_id
                        .store(u64::from(worker_id), Ordering::Release);
                    session
                        .desired_stream_count
                        .store(u64::from(desired_count), Ordering::Release);
                    purge_stale_device_sessions(
                        app,
                        device_id,
                        generation_id,
                        session_salt,
                        session.id,
                    );
                    purge_replaced_worker_sessions(
                        app,
                        device_id,
                        generation_id,
                        session_salt,
                        u64::from(worker_id),
                        session.id,
                    );
                    if access == CredentialAccess::Unbound
                        && let Some(entry) = db.passwords.get_mut(password)
                    {
                        entry.device_id = device_id.to_owned();
                        changed = true;
                    }
                    if access == CredentialAccess::Main && db.main_device_id.is_empty() {
                        db.main_device_id = device_id.to_owned();
                        changed = true;
                    }
                    if !db.devices.contains_key(device_id) {
                        if let Some(ip) = get_next_ip(&db) {
                            let (private, public) = generate_key_pair();
                            db.devices.insert(
                                device_id.to_owned(),
                                ClientDevice {
                                    device_id: device_id.to_owned(),
                                    ip,
                                    priv_key: private,
                                    pub_key: public,
                                    up_bytes: 0,
                                    down_bytes: 0,
                                    bound_password: password.to_owned(),
                                    last_session_salt: session_salt.to_owned(),
                                    last_generation_id: generation_id,
                                },
                            );
                            changed = true;
                        }
                    } else if let Some(device) = db.devices.get_mut(device_id) {
                        if device.bound_password != password {
                            device.bound_password = password.to_owned();
                            changed = true;
                        }
                        if device.last_session_salt != session_salt {
                            device.last_session_salt = session_salt.to_owned();
                            changed = true;
                        }
                        if device.last_generation_id != generation_id {
                            device.last_generation_id = generation_id;
                            changed = true;
                        }
                    }
                    if let Some(device) = db.devices.get(device_id).cloned() {
                        tunnel_ip = crate::tun_device::parse_ipv4(&device.ip);
                        format!("TUNCONF:{}:{}:{}", device.ip, dns, client_port)
                    } else {
                        "NOCONF".to_owned()
                    }
                }
            },
        };
        if changed {
            app.db_persistence.submit(db.clone());
        }
        (
            response,
            reject_session,
            authorization_rejected,
            tunnel_ip,
            changed,
        )
    };
    if authorization_rejected && created_epoch {
        app.device_epochs
            .remove_if(device_id, |_, current| Arc::ptr_eq(current, &epoch_lock));
    }
    if !reject_session {
        command(
            app,
            ProtocolCommand::UpdateEpoch {
                session_id: session.id,
                device_id: device_id.to_owned(),
                generation_id,
                session_salt: session_salt.to_owned(),
            },
        )?;
        command(
            app,
            ProtocolCommand::SetAuthoritativeEpoch {
                device_id: device_id.to_owned(),
                generation_id,
                session_salt: session_salt.to_owned(),
            },
        )?;
    }
    log_getconf_result(
        app,
        session,
        device_id,
        Some(generation_id),
        Some(worker_id),
        Some(desired_count),
        &response,
    );
    writer.write(response.as_bytes()).await?;
    if !reject_session && let Some(ip) = tunnel_ip {
        *lock_unpoison(&session.tunnel_ip) = Some(ip);
        let registration_id = ROUTE_REGISTRATION_COUNTER.fetch_add(1, Ordering::Relaxed);
        session.has_tunnel.store(true, Ordering::Release);
        command(
            app,
            ProtocolCommand::ActivateTunnel {
                session_id: session.id,
                ip,
                registration_id,
                worker_id,
                desired_count,
            },
        )?;
    }
    drop(epoch);
    if reject_session
        && rejected_session_is_request(session, device_id, generation_id, session_salt)
    {
        drop_exact_session(app, session);
    }
    if changed {
        let _ = refresh_credentials(app).await;
    }
    Ok(())
}

async fn ensure_control_tunnel(app: &Arc<App>, session: &Arc<Session>) -> Result<()> {
    if session.has_tunnel.load(Ordering::Acquire) {
        return Ok(());
    }
    let ip = if let Some(ip) = *lock_unpoison(&session.tunnel_ip) {
        ip
    } else {
        let identity = session_epoch_identity(session);
        let ip = {
            let db = db_read(app).await?;
            resolve_session_ip(&db, &session.password, &identity.device_id)
        }
        .ok_or_else(|| anyhow!("no device IP assigned for this session"))?;
        let parsed =
            crate::tun_device::parse_ipv4(&ip).ok_or_else(|| anyhow!("invalid tunnel IP: {ip}"))?;
        *lock_unpoison(&session.tunnel_ip) = Some(parsed);
        parsed
    };
    let registration_id = ROUTE_REGISTRATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let worker_id = u16::try_from(session.worker_id.load(Ordering::Acquire))
        .ok()
        .filter(|worker| (1..=MAX_STREAM_WORKERS_U16).contains(worker))
        .ok_or_else(|| anyhow!("session has no valid worker id"))?;
    let desired_count = u16::try_from(session.desired_stream_count.load(Ordering::Acquire))
        .ok()
        .filter(|count| (1..=MAX_STREAM_WORKERS_U16).contains(count) && worker_id <= *count)
        .unwrap_or_default();
    command(
        app,
        ProtocolCommand::ActivateTunnel {
            session_id: session.id,
            ip,
            registration_id,
            worker_id,
            desired_count,
        },
    )?;
    session.has_tunnel.store(true, Ordering::Release);
    Ok(())
}

fn disconnect_request_authorized(
    db: &Database,
    password: &str,
    requester: &SessionEpochIdentity,
    device_id: &str,
    target_salt: &str,
    epoch: &DeviceEpochState,
) -> bool {
    !target_salt.is_empty()
        && requester.device_id == device_id
        && requester.session_salt == target_salt
        && epoch.matches(requester.generation_id, target_salt)
        && device_control_authorized(db, password, device_id)
}

pub async fn handle_disconnect(
    app: &Arc<App>,
    requester: &Arc<Session>,
    device_id: &str,
    target_salt: &str,
) -> std::result::Result<usize, &'static str> {
    if device_id.is_empty() || device_id.len() > 128 {
        return Err("DENIED:invalid_device");
    }
    if target_salt.is_empty() || target_salt.len() > 128 {
        return Err("DENIED:invalid_epoch");
    }
    let preliminary = session_epoch_identity(requester);
    let preliminary_authorized = {
        match db_read(app).await {
            Ok(db) => {
                device_control_authorized(&db, &requester.password, device_id)
                    && preliminary.device_id == device_id
                    && preliminary.session_salt == target_salt
            }
            Err(_) => false,
        }
    };
    if !preliminary_authorized {
        return Err("DENIED:not_owner");
    }
    let Some((_epoch_lock, epoch)) = lock_existing_device_epoch(app, device_id).await else {
        return Err("DENIED:not_owner");
    };
    let db = db_read(app).await.map_err(|_| "DENIED:server_busy")?;
    let requester_identity = session_epoch_identity(requester);
    if !disconnect_request_authorized(
        &db,
        &requester.password,
        &requester_identity,
        device_id,
        target_salt,
        &epoch,
    ) {
        return Err("DENIED:not_owner");
    }
    drop(db);
    let candidates = app
        .sessions
        .iter()
        .filter_map(|entry| {
            let session = entry.value();
            (session.id == requester.id || session_epoch_identity(session).device_id == device_id)
                .then_some(session.id)
        })
        .collect::<Vec<_>>();
    command(
        app,
        ProtocolCommand::DisconnectDevice {
            device_id: device_id.to_owned(),
            requester_session_id: requester.id,
        },
    )
    .map_err(|_| "DENIED:server_busy")?;
    let mut removed = 0usize;
    for session_id in candidates {
        if let Some((_, session)) = app.sessions.remove_if(&session_id, |_, current| {
            current.id == session_id
                && (current.id == requester.id
                    || session_epoch_identity(current).device_id == device_id)
        }) {
            session.cancel_token.cancel();
            removed += 1;
        }
    }
    Ok(removed)
}

#[inline(always)]
pub async fn flush_traffic(app: &Arc<App>) {
    let Ok(mut db) = db_write(app).await else {
        return;
    };
    let mut traffic = TrafficSnapshot::default();
    for entry in app.sessions.iter() {
        let session = entry.value();
        let up = session.up_bytes.swap(0, Ordering::Relaxed);
        let down = session.down_bytes.swap(0, Ordering::Relaxed);
        if up == 0 && down == 0 {
            continue;
        }
        if let Some(password) = db.passwords.get_mut(&session.password) {
            password.up_bytes = password.up_bytes.saturating_add(up as i64);
            password.down_bytes = password.down_bytes.saturating_add(down as i64);
            traffic.passwords.insert(
                session.password.clone(),
                TrafficCounters {
                    up_bytes: password.up_bytes,
                    down_bytes: password.down_bytes,
                },
            );
            let device_id = password.device_id.clone();
            if let Some(device) = db.devices.get_mut(&device_id) {
                device.up_bytes = device.up_bytes.saturating_add(up as i64);
                device.down_bytes = device.down_bytes.saturating_add(down as i64);
                traffic.devices.insert(
                    device_id,
                    TrafficCounters {
                        up_bytes: device.up_bytes,
                        down_bytes: device.down_bytes,
                    },
                );
            }
        } else if session.password == db.main_password {
            db.main_up_bytes = db.main_up_bytes.saturating_add(up as i64);
            db.main_down_bytes = db.main_down_bytes.saturating_add(down as i64);
            traffic.main = Some(TrafficCounters {
                up_bytes: db.main_up_bytes,
                down_bytes: db.main_down_bytes,
            });
            let device_id = lock_unpoison(&session.device_id).clone();
            if !device_id.is_empty()
                && let Some(device) = db.devices.get_mut(&device_id)
            {
                device.up_bytes = device.up_bytes.saturating_add(up as i64);
                device.down_bytes = device.down_bytes.saturating_add(down as i64);
                traffic.devices.insert(
                    device_id,
                    TrafficCounters {
                        up_bytes: device.up_bytes,
                        down_bytes: device.down_bytes,
                    },
                );
            }
        }
    }
    drop(db);
    app.db_persistence.submit_traffic(traffic);
}

pub(crate) fn refresh_monotonic_millis() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let current = START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
        + 1;
    CACHED_MONOTONIC_MS.store(current, Ordering::Relaxed);
    current
}

#[inline]
fn hot_session_idle_reason(is_authenticated: bool) -> &'static str {
    if is_authenticated {
        "authenticated-idle-10h"
    } else {
        "setup-idle-15s"
    }
}

#[inline]
fn public_session_is_stale(has_tunnel: bool, last_seen: u64, current_wall: u64) -> bool {
    let idle_limit = if has_tunnel {
        PUBLIC_AUTH_GHOST_IDLE_SECS
    } else {
        PUBLIC_SETUP_GHOST_IDLE_SECS
    };
    current_wall.saturating_sub(last_seen) >= idle_limit
}

pub async fn session_janitor(app: Arc<App>) {
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_traffic_flush = Instant::now() - TRAFFIC_FLUSH_INTERVAL;
    loop {
        timer.tick().await;
        if last_traffic_flush.elapsed() >= TRAFFIC_FLUSH_INTERVAL {
            flush_traffic(&app).await;
            last_traffic_flush = Instant::now();
        }
        let current_wall = wall_clock();
        prune_public_sessions(&app, current_wall);
        if app.sessions.len().saturating_mul(4) < app.sessions.capacity() {
            app.sessions.shrink_to_fit();
        }
    }
}

fn prune_public_sessions(app: &Arc<App>, current_wall: u64) {
    let stale_public = app
        .sessions
        .iter()
        .filter_map(|entry| {
            let session = entry.value();
            public_session_is_stale(
                session.has_tunnel.load(Ordering::Acquire),
                session.last_seen.load(Ordering::Acquire),
                current_wall,
            )
            .then_some(session.id)
        })
        .collect::<Vec<_>>();
    for session_id in stale_public {
        let _ = command(app, ProtocolCommand::DropSession { session_id });
        if let Some((_, removed)) = app
            .sessions
            .remove_if(&session_id, |_, session| session.id == session_id)
        {
            removed.cancel_token.cancel();
        }
    }
    let overflow = app.sessions.len().saturating_sub(PUBLIC_SESSION_LIMIT);
    if overflow == 0 {
        return;
    }
    let mut inactive = app
        .sessions
        .iter()
        .filter(|entry| !entry.value().has_tunnel.load(Ordering::Acquire))
        .map(|entry| {
            (
                entry.value().last_seen.load(Ordering::Acquire),
                entry.value().id,
            )
        })
        .collect::<Vec<_>>();
    inactive.sort_unstable();
    for (_, session_id) in inactive.into_iter().take(overflow) {
        if let Some((_, removed)) = app
            .sessions
            .remove_if(&session_id, |_, session| session.id == session_id)
        {
            removed.cancel_token.cancel();
        }
    }
}

async fn run_password_janitor_cycle(app: &Arc<App>) {
    let expired = {
        let Ok(db) = db_read(app).await else {
            return;
        };
        db.passwords
            .iter()
            .filter(|(_, entry)| is_expired(entry))
            .map(|(password, _)| password.clone())
            .collect::<Vec<String>>()
    };
    let mut credentials_changed = false;
    for password in expired {
        {
            let Ok(mut db) = db_write(app).await else {
                continue;
            };
            if !db.passwords.get(&password).is_some_and(is_expired) {
                continue;
            }
            db.passwords.remove(&password);
            db.clear_device_binding(&password);
            app.db_persistence.submit(db.clone());
        }
        app.derived_keys.remove(&password);
        drop_password_sessions(app, &password);
        credentials_changed = true;
    }
    if credentials_changed {
        let _ = refresh_credentials(app).await;
    }
}

pub async fn password_janitor(app: Arc<App>) {
    let mut timer = tokio::time::interval(Duration::from_secs(3600));
    loop {
        timer.tick().await;
        run_password_janitor_cycle(&app).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_json_client_remains_authorized_after_runtime_epoch_reset() {
        use crate::model::{ClientDevice, Database, PasswordEntry, load_database};

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("csqtt-legacy-getconf-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();

        let mut legacy = Database::default();
        legacy.passwords.insert(
            "legacy-password".to_owned(),
            PasswordEntry {
                device_id: "legacy-device".to_owned(),
                ..PasswordEntry::default()
            },
        );
        legacy.devices.insert(
            "legacy-device".to_owned(),
            ClientDevice {
                device_id: "legacy-device".to_owned(),
                ip: "10.66.67.2".to_owned(),
                bound_password: "legacy-password".to_owned(),
                last_generation_id: 1_786_000_000_000,
                last_session_salt: "retired-salt".to_owned(),
                ..ClientDevice::default()
            },
        );
        std::fs::write(
            directory.join("passwords.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let migrated = load_database(&directory).unwrap();
        assert_eq!(
            getconf_credential_access(&migrated, "legacy-password", "legacy-device"),
            Ok(CredentialAccess::Bound)
        );
        let device = &migrated.devices["legacy-device"];
        assert_eq!(device.last_generation_id, 0);
        assert!(device.last_session_salt.is_empty());

        let mut epoch =
            DeviceEpochState::new(device.last_generation_id, device.last_session_salt.clone());
        assert_eq!(
            epoch.admit(1_786_000_000, "fresh-session-salt"),
            DeviceEpochDecision::Advanced
        );
        assert!(!directory.join("passwords.json").exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn diagnostic_request_reader_accepts_128_bytes_and_rejects_more() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, mut reader) = tokio::io::duplex(512);
        let expected = "x".repeat(DIAGNOSTIC_REQUEST_MAX_BYTES);
        writer
            .write_all(format!("{expected}\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_diagnostic_request(&mut reader).await.unwrap(),
            Some(expected)
        );

        let (mut writer, mut reader) = tokio::io::duplex(512);
        writer
            .write_all("x".repeat(DIAGNOSTIC_REQUEST_MAX_BYTES + 1).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_diagnostic_request(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn public_auth_ghost_ttl_is_two_minutes_and_does_not_underflow() {
        assert!(!public_session_is_stale(true, 1_000, 1_119));
        assert!(public_session_is_stale(true, 1_000, 1_120));
        assert!(!public_session_is_stale(true, 1_000, 999));
        assert!(public_session_is_stale(false, 1_000, 1_030));
    }

    #[test]
    fn hot_authenticated_idle_timeout_is_ten_hours() {
        assert_eq!(SESSION_AUTH_IDLE_MS, 10 * 60 * 60 * 1_000);
        assert_eq!(hot_session_idle_reason(true), "authenticated-idle-10h");
        assert_eq!(hot_session_idle_reason(false), "setup-idle-15s");
    }

    #[test]
    fn idle_keepalives_are_ignored_after_refreshing_session_activity() {
        assert!(is_idle_keepalive(&[0xff; 16]));
        assert!(is_idle_keepalive(&[0xff, 0x11, 0x22, 0x33]));
        assert!(is_idle_keepalive(&[0xff, 1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(!is_idle_keepalive(&[]));
        assert!(!is_idle_keepalive(&[0xff, 1, 2]));
    }

    #[test]
    fn epoch_cache_is_swept_regularly_and_expires_after_one_hour() {
        assert_eq!(EPOCH_SWEEP_INTERVAL_MS, 5 * 60_000);
        assert_eq!(EPOCH_IDLE_TTL_MS, 60 * 60_000);
    }

    #[test]
    fn rtp_clocks_follow_elapsed_media_time() {
        let frame = Duration::from_millis(20);
        assert_eq!(duration_ticks(frame, rtp_clock_rate(111)), 960);
        assert_eq!(duration_ticks(frame, rtp_clock_rate(96)), 1_800);
        assert_eq!(duration_ticks(Duration::from_secs(1), 48_000), 48_000);
        assert_eq!(duration_ticks(Duration::from_secs(1), 90_000), 90_000);
    }

    #[test]
    fn replay_window_handles_u16_wrap_and_duplicates() {
        let mut replay = ReplayState::new();
        assert!(replay.accept(65_534));
        assert!(replay.accept(65_535));
        assert!(replay.accept(0));
        assert!(replay.accept(1));
        assert!(!replay.accept(1));
        assert!(!replay.accept(65_535));
    }

    #[test]
    fn getconf_epoch_parser_is_strict() {
        let max = format!("GETCONF:9000|device|password|{}|salt", u64::MAX);
        assert_eq!(
            parse_getconf_epoch(max.as_bytes()),
            Some(("device", u64::MAX, "salt"))
        );
        let max_with_count = format!("GETCONF:9000|device|password|{}|salt|4|36", u64::MAX);
        assert_eq!(
            parse_getconf_epoch(max_with_count.as_bytes()),
            Some(("device", u64::MAX, "salt"))
        );
        assert!(parse_getconf_epoch(b"GETCONF:9000|device|password|-1|salt").is_none());
        assert!(parse_getconf_epoch(b"GETCONF:9000|device|password|+1|salt").is_none());
        assert!(parse_getconf_epoch(b"GETCONF:9000||password|1|salt").is_none());
    }

    #[test]
    fn stream_control_payload_is_compact_and_deterministic() {
        let payload = stream_control_payload(STREAM_REPAIR_PREFIX, 7, 36, &[14, 28]);
        assert!(payload.starts_with(STREAM_REPAIR_PREFIX));
        let offset = STREAM_REPAIR_PREFIX.len();
        assert_eq!(&payload[offset..offset + 8], &7u64.to_be_bytes());
        assert_eq!(&payload[offset + 8..offset + 10], &36u16.to_be_bytes());
        assert_eq!(payload[offset + 10], 2);
        assert_eq!(&payload[offset + 11..offset + 13], &14u16.to_be_bytes());
        assert_eq!(&payload[offset + 13..offset + 15], &28u16.to_be_bytes());
        assert_eq!(payload.len(), STREAM_REPAIR_PREFIX.len() + 15);
    }

    #[test]
    fn stream_repair_round_deduplicates_and_escalates_by_sequence() {
        let mut round = StreamRepairRound::default();
        assert!(round.repair_payload(&[14, 28], 36, 0).is_none());
        let first = round.repair_payload(&[14, 28], 36, 30_000).unwrap();
        assert!(round.repair_payload(&[14, 28], 36, 31_000).is_none());
        let next = round.repair_payload(&[14, 28], 36, 90_000).unwrap();
        assert_ne!(first, next);
    }

    #[test]
    fn stream_repair_round_emits_alive_after_recovery() {
        let mut round = StreamRepairRound::default();
        assert!(round.repair_payload(&[14], 36, 0).is_none());
        let repair = round.repair_payload(&[14], 36, 30_000).unwrap();
        round.recovered(36, 30_100);
        let alive = round.alive_payload(30_100).unwrap();
        assert!(alive.starts_with(STREAM_ALIVE_PREFIX));
        assert_ne!(repair, alive);
        assert!(round.alive_payload(5_500).is_none());
        assert!(round.alive_payload(10_100).is_some());
        assert!(round.alive_payload(15_100).is_none());
    }

    #[test]
    fn session_lease_is_control() {
        assert!(is_control_payload(SESSION_LEASE));
    }

    #[test]
    fn udp_flushes_control_without_flushing_regular_data() {
        assert!(should_flush_udp_immediately(b"GETCONF:9000|device"));
        assert!(should_flush_udp_immediately(STREAM_REPAIR_PREFIX));
        assert!(should_flush_udp_immediately(b"READY"));
        assert!(!should_flush_udp_immediately(&[0x45, 0, 0, 28]));
    }

    #[test]
    fn fec_profile_is_safe_by_default_and_can_be_disabled() {
        assert_eq!(FecProfile::default(), FecProfile::Safe);
        assert_ne!(FecProfile::Off, FecProfile::Safe);
    }

    #[test]
    fn reconnect_epoch_rejects_stale_and_conflicting_salt() {
        let epoch = EpochValue {
            generation_id: 77,
            session_salt: "salt-a".to_owned(),
            last_seen_ms: 0,
        };
        assert_eq!(
            getconf_reconnect_action_hot(Some(&epoch), "device", 77, "salt-a", "device", 76, "old",),
            GetconfReconnectAction::Reject
        );
        assert_eq!(
            getconf_reconnect_action_hot(
                Some(&epoch),
                "device",
                77,
                "salt-a",
                "device",
                77,
                "salt-b",
            ),
            GetconfReconnectAction::Reject
        );
    }

    #[test]
    fn authoritative_epoch_retires_every_lower_generation() {
        assert!(session_is_retired_by_epoch(
            "device", 41, "old-a", "device", 42, "current"
        ));
        assert!(session_is_retired_by_epoch(
            "device", 1, "old-b", "device", 42, "current"
        ));
        assert!(session_is_retired_by_epoch(
            "device", 42, "conflict", "device", 42, "current"
        ));
        assert!(!session_is_retired_by_epoch(
            "device", 42, "current", "device", 42, "current"
        ));
        assert!(!session_is_retired_by_epoch(
            "device", 43, "future", "device", 42, "current"
        ));
        assert!(!session_is_retired_by_epoch(
            "other", 1, "old", "device", 42, "current"
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_epoch_admission_converges_to_highest_generation() {
        let state = Arc::new(Mutex::new(DeviceEpochState::default()));
        let mut tasks = Vec::new();
        for generation in (1..=128u64).rev().chain(1..=128) {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut state = state.lock().await;
                state.admit(generation, &format!("salt-{generation}"))
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let mut state = state.lock().await;
        assert_eq!(state.generation_id, 128);
        assert_eq!(state.session_salt, "salt-128");
        assert_eq!(state.admit(127, "salt-127"), DeviceEpochDecision::Stale);
        assert_eq!(
            state.admit(128, "conflict"),
            DeviceEpochDecision::SaltConflict
        );
        assert_eq!(state.admit(129, "salt-129"), DeviceEpochDecision::Advanced);
    }

    #[test]
    fn disconnect_targets_requester_and_all_device_sessions() {
        assert!(session_is_disconnected_device(7, "", 7, "device"));
        assert!(session_is_disconnected_device(8, "device", 7, "device"));
        assert!(!session_is_disconnected_device(8, "other", 7, "device"));
    }
}
