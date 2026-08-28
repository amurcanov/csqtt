// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    App,
    packet::{PACKET_CAPACITY, TUN_TX_SLOTS, UDP_TX_SLOTS},
    protocol,
    tokio_io::{self, MAX_DATAGRAMS},
    tproxy,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const METRIC_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MetricFrame {
    pub timestamp_ms: u64,
    pub pid: u32,
    pub error: String,
    pub process: ProcessMemory,
    pub smaps_rollup: SmapsRollup,
    pub mappings: MappingMemorySnapshot,
    pub cgroup: CgroupMemory,
    pub sockets: SocketMemory,
    pub fixed_buffers: FixedBufferMemory,
    pub storage: PersistentStorage,
    pub runtime: RuntimeMemory,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ProcessMemory {
    pub available: bool,
    pub rss_kib: u64,
    pub peak_rss_kib: u64,
    pub anonymous_kib: u64,
    pub file_kib: u64,
    pub shmem_kib: u64,
    pub swap_kib: u64,
    pub threads: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SmapsRollup {
    pub available: bool,
    pub rss_kib: u64,
    pub pss_kib: u64,
    pub pss_anon_kib: u64,
    pub pss_file_kib: u64,
    pub pss_shmem_kib: u64,
    pub anonymous_kib: u64,
    pub private_kib: u64,
    pub shared_kib: u64,
    pub swap_kib: u64,
    pub swap_pss_kib: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MappingMemory {
    pub category: String,
    pub rss_kib: u64,
    pub pss_kib: u64,
    pub private_kib: u64,
    pub shared_kib: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MappingMemorySnapshot {
    pub available: bool,
    pub categories: Vec<MappingMemory>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CgroupMemory {
    pub available: bool,
    pub version: String,
    pub current_bytes: u64,
    pub peak_bytes: u64,
    pub max_bytes: Option<u64>,
    pub swap_current_bytes: Option<u64>,
    pub swap_max_bytes: Option<u64>,
    pub anon_bytes: u64,
    pub file_bytes: u64,
    pub shmem_bytes: u64,
    pub sock_bytes: u64,
    pub kernel_stack_bytes: u64,
    pub pagetables_bytes: u64,
    pub percpu_bytes: u64,
    pub slab_reclaimable_bytes: u64,
    pub slab_unreclaimable_bytes: u64,
    pub file_mapped_bytes: u64,
    pub file_dirty_bytes: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SocketMemory {
    pub available: bool,
    pub socket_fds: u64,
    pub udp_sockets: u64,
    pub udp_tx_queue_bytes: u64,
    pub udp_rx_queue_bytes: u64,
    pub tcp_sockets: u64,
    pub tcp_tx_queue_bytes: u64,
    pub tcp_rx_queue_bytes: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FixedBufferMemory {
    pub packet_capacity_bytes: u64,
    pub packet_pool_capacity_slots: u64,
    pub packet_pool_allocated_slots: u64,
    pub packet_pool_retained_slots: u64,
    pub packet_pool_allocated_payload_bytes: u64,
    pub udp_tx_slots: u64,
    pub udp_tx_payload_bytes: u64,
    pub udp_tx_in_use_slots: u64,
    pub tun_tx_slots: u64,
    pub tun_tx_payload_bytes: u64,
    pub tun_tx_in_use_slots: u64,
    pub udp_rx_mode: String,
    pub udp_rx_slots: u64,
    pub udp_rx_slot_bytes: u64,
    pub udp_rx_payload_bytes: u64,
    pub tun_rx_payload_bytes: u64,
    pub fixed_payload_bytes: u64,
    pub udp_socket_rcvbuf_request_bytes: u64,
    pub udp_socket_sndbuf_request_bytes: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PersistentStorage {
    pub sqlite_db_bytes: u64,
    pub sqlite_wal_bytes: u64,
    pub sqlite_shm_bytes: u64,
    pub log_file_bytes: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeMemory {
    pub allocator: String,
    pub public_sessions: u64,
    pub public_session_capacity: u64,
    pub hot_sessions: u64,
    pub hot_session_capacity: u64,
    pub hot_session_limit: u64,
    pub max_stream_workers_per_device: u64,
    pub engine_epochs: u64,
    pub device_epochs: u64,
    pub device_epoch_capacity: u64,
    pub derived_keys: u64,
    pub derived_key_string_capacity_bytes: u64,
    pub web_sessions: u64,
    pub web_session_limit: u64,
    pub web_session_key_capacity_bytes: u64,
    pub login_limits: u64,
    pub login_limit_limit: u64,
    pub login_limit_key_capacity_bytes: u64,
    pub log_entries: u64,
    pub log_entry_limit: u64,
    pub log_string_capacity_bytes: u64,
    pub log_ring_metadata_capacity_bytes: u64,
    pub dpi_entries: u64,
    pub dpi_entry_capacity: u64,
    pub dpi_retained_bytes: u64,
    pub stream_repairs: u64,
    pub stream_inventory: u64,
    pub dataplane_commands_queued: u64,
    pub dataplane_command_capacity: u64,
    pub local_proxy_active: bool,
    pub local_proxy_tcp_sessions: u64,
    pub local_proxy_udp_flows: u64,
    pub local_proxy_tcp_limit: u64,
    pub local_proxy_udp_limit: u64,
    pub local_proxy_payload_allocated_bytes: u64,
    pub local_proxy_payload_retained_bytes: u64,
    pub local_proxy_opening_buffer_allocated_bytes: u64,
    pub local_proxy_payload_upper_bound_at_limit_bytes: u64,
    pub memory_trim_count: u64,
    pub memory_trim_last_unix: u64,
}

#[derive(Default)]
struct OsMetrics {
    process: ProcessMemory,
    smaps_rollup: SmapsRollup,
    mappings: MappingMemorySnapshot,
    cgroup: CgroupMemory,
    sockets: SocketMemory,
    storage: PersistentStorage,
}

#[derive(Clone, Default)]
struct SlowOsMetrics {
    cgroup: CgroupMemory,
    sockets: SocketMemory,
    storage: PersistentStorage,
}

pub async fn collect_metric_frame(app: &Arc<App>) -> MetricFrame {
    let os = collect_os_metrics(&app.config_dir);
    let runtime = collect_runtime_memory(app).await;

    MetricFrame {
        timestamp_ms: unix_ms(),
        pid: std::process::id(),
        error: String::new(),
        process: os.process,
        smaps_rollup: os.smaps_rollup,
        mappings: os.mappings,
        cgroup: os.cgroup,
        sockets: os.sockets,
        fixed_buffers: fixed_buffer_memory(),
        storage: os.storage,
        runtime,
    }
}

fn collect_os_metrics(config_dir: &Path) -> OsMetrics {
    let process = collect_proc_metric::<4096, _>("/proc/self/status", parse_process_memory);
    let smaps_rollup =
        collect_proc_metric::<8192, _>("/proc/self/smaps_rollup", parse_smaps_rollup);
    let slow = collect_slow_os_metrics(config_dir);

    OsMetrics {
        mappings: mapping_memory_snapshot(&process, &smaps_rollup),
        process,
        smaps_rollup,
        cgroup: slow.cgroup,
        sockets: slow.sockets,
        storage: slow.storage,
    }
}

fn mapping_memory_snapshot(process: &ProcessMemory, rollup: &SmapsRollup) -> MappingMemorySnapshot {
    let anonymous_private = rollup.anonymous_kib.min(rollup.private_kib);
    let mut categories = Vec::with_capacity(2);
    if process.file_kib != 0 || rollup.pss_file_kib != 0 {
        categories.push(MappingMemory {
            category: "file-backed-mappings".to_owned(),
            rss_kib: process.file_kib,
            pss_kib: rollup.pss_file_kib,
            private_kib: rollup.private_kib.saturating_sub(anonymous_private),
            shared_kib: rollup.shared_kib,
        });
    }
    if process.anonymous_kib != 0 || rollup.pss_anon_kib != 0 {
        categories.push(MappingMemory {
            category: "anonymous-mappings".to_owned(),
            rss_kib: process.anonymous_kib,
            pss_kib: rollup.pss_anon_kib,
            private_kib: anonymous_private,
            shared_kib: 0,
        });
    }
    categories.sort_by(|left, right| {
        right
            .rss_kib
            .cmp(&left.rss_kib)
            .then_with(|| left.category.cmp(&right.category))
    });
    MappingMemorySnapshot {
        available: true,
        categories,
    }
}

fn collect_proc_metric<const CAPACITY: usize, T>(path: &str, parse: impl FnOnce(&str) -> T) -> T
where
    T: Default,
{
    let mut buffer = [0_u8; CAPACITY];
    let Ok(mut file) = fs::File::open(path) else {
        return T::default();
    };
    let Ok(len) = file.read(&mut buffer) else {
        return T::default();
    };
    let Ok(text) = std::str::from_utf8(&buffer[..len]) else {
        return T::default();
    };
    parse(text)
}

fn collect_slow_os_metrics(config_dir: &Path) -> SlowOsMetrics {
    SlowOsMetrics {
        cgroup: collect_cgroup_memory(),
        sockets: collect_socket_memory(),
        storage: collect_persistent_storage(config_dir),
    }
}

async fn collect_runtime_memory(app: &Arc<App>) -> RuntimeMemory {
    let (log_entries, log_string_capacity_bytes, log_ring_metadata_capacity_bytes) = {
        let logs = crate::lock_unpoison(&app.logs);
        let strings = logs.iter().fold(0u64, |total, line| {
            total.saturating_add(line.capacity() as u64)
        });
        (
            logs.len() as u64,
            strings,
            logs.capacity()
                .saturating_mul(std::mem::size_of::<String>()) as u64,
        )
    };
    let (local_proxy_active, proxy_stats) = {
        let route = app.proxy_route.read().await;
        let active = route.as_ref().is_some_and(|route| route.is_alive());
        let stats = route
            .as_ref()
            .map(|route| route.diagnostic_snapshot())
            .unwrap_or_default();
        (active, stats)
    };
    let proxy_budget = tproxy::memory_budget();
    let proxy_payload_allocated_bytes = (proxy_stats.tcp_buffer_allocated as u64)
        .saturating_mul(proxy_budget.tcp_relay_bytes_per_session / 2)
        .saturating_add(
            (proxy_stats.udp_normal_buffer_allocated as u64)
                .saturating_mul(proxy_budget.udp_normal_buffer_bytes),
        )
        .saturating_add(
            (proxy_stats.udp_jumbo_buffer_allocated as u64)
                .saturating_mul(proxy_budget.udp_jumbo_buffer_bytes),
        );
    let proxy_payload_retained_bytes = (proxy_stats.tcp_buffer_retained as u64)
        .saturating_mul(proxy_budget.tcp_relay_bytes_per_session / 2)
        .saturating_add(
            (proxy_stats.udp_normal_buffer_retained as u64)
                .saturating_mul(proxy_budget.udp_normal_buffer_bytes),
        )
        .saturating_add(
            (proxy_stats.udp_jumbo_buffer_retained as u64)
                .saturating_mul(proxy_budget.udp_jumbo_buffer_bytes),
        );
    let queue = app
        .dataplane
        .get()
        .map(|handle| handle.command_queue_snapshot())
        .unwrap_or_default();
    let dpi = protocol::dpi_ring_memory_snapshot();

    RuntimeMemory {
        allocator: crate::allocator_name().to_owned(),
        public_sessions: app.sessions.len() as u64,
        public_session_capacity: app.sessions.capacity() as u64,
        hot_sessions: protocol::ACTIVE_SESSIONS_GAUGE.load(Ordering::Relaxed),
        hot_session_capacity: protocol::HOT_SESSION_CAPACITY_GAUGE.load(Ordering::Relaxed),
        hot_session_limit: protocol::MAX_ACTIVE_SESSIONS as u64,
        max_stream_workers_per_device: protocol::MAX_STREAM_WORKERS as u64,
        engine_epochs: protocol::epoch_snapshot_len() as u64,
        device_epochs: app.device_epochs.len() as u64,
        device_epoch_capacity: app.device_epochs.capacity() as u64,
        derived_keys: app.derived_keys.len() as u64,
        derived_key_string_capacity_bytes: app.derived_keys.iter().fold(0u64, |total, entry| {
            total.saturating_add(entry.key().capacity() as u64)
        }),
        web_sessions: app.web_sessions.len() as u64,
        web_session_limit: crate::web_panel::MAX_WEB_SESSIONS as u64,
        web_session_key_capacity_bytes: app.web_sessions.iter().fold(0u64, |total, entry| {
            total.saturating_add(entry.key().capacity() as u64)
        }),
        login_limits: app.login_limits.len() as u64,
        login_limit_limit: crate::web_panel::MAX_LOGIN_LIMITS as u64,
        login_limit_key_capacity_bytes: app.login_limits.iter().fold(0u64, |total, entry| {
            total.saturating_add(entry.key().capacity() as u64)
        }),
        log_entries,
        log_entry_limit: crate::LOG_RING_CAPACITY as u64,
        log_string_capacity_bytes,
        log_ring_metadata_capacity_bytes,
        dpi_entries: dpi.entries as u64,
        dpi_entry_capacity: dpi.entry_capacity as u64,
        dpi_retained_bytes: dpi.retained_bytes as u64,
        stream_repairs: protocol::STREAM_REPAIRS_GAUGE.load(Ordering::Relaxed),
        stream_inventory: protocol::STREAM_INVENTORY_GAUGE.load(Ordering::Relaxed),
        dataplane_commands_queued: queue.queued as u64,
        dataplane_command_capacity: queue.capacity as u64,
        local_proxy_active,
        local_proxy_tcp_sessions: proxy_stats.tcp_active as u64,
        local_proxy_udp_flows: proxy_stats.udp_active as u64,
        local_proxy_tcp_limit: proxy_stats.tcp_limit as u64,
        local_proxy_udp_limit: proxy_stats.udp_limit as u64,
        local_proxy_payload_allocated_bytes: proxy_payload_allocated_bytes,
        local_proxy_payload_retained_bytes: proxy_payload_retained_bytes,
        local_proxy_opening_buffer_allocated_bytes: proxy_stats.opening_buffer_allocated_bytes
            as u64,
        local_proxy_payload_upper_bound_at_limit_bytes: (proxy_stats.tcp_limit as u64)
            .saturating_mul(proxy_budget.tcp_relay_bytes_per_session)
            .saturating_add(proxy_budget.udp_response_bytes_at_limit),
        memory_trim_count: app.memory_trim_count.load(Ordering::Relaxed),
        memory_trim_last_unix: app.memory_trim_last_unix.load(Ordering::Relaxed),
    }
}

fn fixed_buffer_memory() -> FixedBufferMemory {
    let io = *crate::read_unpoison(&protocol::GLOBAL_IO_COUNTERS);
    let packet_capacity = PACKET_CAPACITY as u64;
    let udp_tx_slots = UDP_TX_SLOTS as u64;
    let tun_tx_slots = TUN_TX_SLOTS as u64;
    let udp_rx_mode = "recvmmsg/batch".to_owned();
    let udp_rx_slots = MAX_DATAGRAMS as u64;
    let udp_rx_slot_bytes = PACKET_CAPACITY as u64;
    let udp_tx_payload_bytes = udp_tx_slots.saturating_mul(packet_capacity);
    let tun_tx_payload_bytes = tun_tx_slots.saturating_mul(packet_capacity);
    let udp_rx_payload_bytes = udp_rx_slots.saturating_mul(udp_rx_slot_bytes);
    let tun_rx_payload_bytes = packet_capacity;
    let packet_pool_allocated_payload_bytes =
        io.packet_pool_allocated.saturating_mul(packet_capacity);

    FixedBufferMemory {
        packet_capacity_bytes: packet_capacity,
        packet_pool_capacity_slots: io.packet_pool_capacity,
        packet_pool_allocated_slots: io.packet_pool_allocated,
        packet_pool_retained_slots: io.packet_pool_retained,
        packet_pool_allocated_payload_bytes,
        udp_tx_slots,
        udp_tx_payload_bytes,
        udp_tx_in_use_slots: udp_tx_slots.saturating_sub(io.free_udp_tx_slots.min(udp_tx_slots)),
        tun_tx_slots,
        tun_tx_payload_bytes,
        tun_tx_in_use_slots: tun_tx_slots.saturating_sub(io.free_tun_tx_slots.min(tun_tx_slots)),
        udp_rx_mode,
        udp_rx_slots,
        udp_rx_slot_bytes,
        udp_rx_payload_bytes,
        tun_rx_payload_bytes,
        fixed_payload_bytes: packet_pool_allocated_payload_bytes
            .saturating_add(udp_rx_payload_bytes)
            .saturating_add(tun_rx_payload_bytes),
        udp_socket_rcvbuf_request_bytes: tokio_io::UDP_RECV_BUFFER_BYTES as u64,
        udp_socket_sndbuf_request_bytes: tokio_io::UDP_SEND_BUFFER_BYTES as u64,
    }
}

fn parse_process_memory(text: &str) -> ProcessMemory {
    ProcessMemory {
        available: true,
        rss_kib: proc_kib(text, "VmRSS:").unwrap_or(0),
        peak_rss_kib: proc_kib(text, "VmHWM:").unwrap_or(0),
        anonymous_kib: proc_kib(text, "RssAnon:").unwrap_or(0),
        file_kib: proc_kib(text, "RssFile:").unwrap_or(0),
        shmem_kib: proc_kib(text, "RssShmem:").unwrap_or(0),
        swap_kib: proc_kib(text, "VmSwap:").unwrap_or(0),
        threads: proc_kib(text, "Threads:").unwrap_or(0),
    }
}

fn parse_smaps_rollup(text: &str) -> SmapsRollup {
    let private_clean = proc_kib(text, "Private_Clean:").unwrap_or(0);
    let private_dirty = proc_kib(text, "Private_Dirty:").unwrap_or(0);
    let shared_clean = proc_kib(text, "Shared_Clean:").unwrap_or(0);
    let shared_dirty = proc_kib(text, "Shared_Dirty:").unwrap_or(0);
    SmapsRollup {
        available: true,
        rss_kib: proc_kib(text, "Rss:").unwrap_or(0),
        pss_kib: proc_kib(text, "Pss:").unwrap_or(0),
        pss_anon_kib: proc_kib(text, "Pss_Anon:").unwrap_or(0),
        pss_file_kib: proc_kib(text, "Pss_File:").unwrap_or(0),
        pss_shmem_kib: proc_kib(text, "Pss_Shmem:").unwrap_or(0),
        anonymous_kib: proc_kib(text, "Anonymous:").unwrap_or(0),
        private_kib: private_clean.saturating_add(private_dirty),
        shared_kib: shared_clean.saturating_add(shared_dirty),
        swap_kib: proc_kib(text, "Swap:").unwrap_or(0),
        swap_pss_kib: proc_kib(text, "SwapPss:").unwrap_or(0),
    }
}

fn collect_cgroup_memory() -> CgroupMemory {
    let Ok(groups) = fs::read_to_string("/proc/self/cgroup") else {
        return CgroupMemory::default();
    };
    let mut v1_relative = None::<String>;
    for line in groups.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields.next().unwrap_or_default();
        let relative = fields.next().unwrap_or_default();
        if hierarchy == "0" && controllers.is_empty() {
            let Some(dir) = cgroup_directory(Path::new("/sys/fs/cgroup"), relative) else {
                return CgroupMemory::default();
            };
            return collect_cgroup_v2(&dir);
        }
        if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            v1_relative = Some(relative.to_owned());
        }
    }
    let Some(relative) = v1_relative else {
        return CgroupMemory::default();
    };
    let Some(dir) = cgroup_directory(Path::new("/sys/fs/cgroup/memory"), &relative) else {
        return CgroupMemory::default();
    };
    collect_cgroup_v1(&dir)
}

pub(crate) fn available_memory_bytes() -> Option<u64> {
    let host_available = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| proc_kib(&text, "MemAvailable:"))
        .map(|kib| kib.saturating_mul(1024));
    let cgroup = collect_cgroup_memory();
    let cgroup_available = cgroup
        .max_bytes
        .map(|limit| limit.saturating_sub(cgroup.current_bytes));
    match (host_available, cgroup_available) {
        (Some(host), Some(group)) => Some(host.min(group)),
        (Some(host), None) => Some(host),
        (None, Some(group)) => Some(group),
        (None, None) => None,
    }
}

fn cgroup_directory(root: &Path, relative: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for component in relative
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if matches!(component, "." | "..") {
            return None;
        }
        path.push(component);
    }
    Some(path)
}

fn collect_cgroup_v2(directory: &Path) -> CgroupMemory {
    let current = read_number_file(&directory.join("memory.current"));
    let stat = read_stat_file(&directory.join("memory.stat"));
    CgroupMemory {
        available: current.is_some() || !stat.is_empty(),
        version: "v2".to_owned(),
        current_bytes: current.unwrap_or(0),
        peak_bytes: read_number_file(&directory.join("memory.peak")).unwrap_or(0),
        max_bytes: read_limit_file(&directory.join("memory.max")),
        swap_current_bytes: read_number_file(&directory.join("memory.swap.current")),
        swap_max_bytes: read_limit_file(&directory.join("memory.swap.max")),
        anon_bytes: stat_value(&stat, &["anon"]),
        file_bytes: stat_value(&stat, &["file"]),
        shmem_bytes: stat_value(&stat, &["shmem"]),
        sock_bytes: stat_value(&stat, &["sock"]),
        kernel_stack_bytes: stat_value(&stat, &["kernel_stack"]),
        pagetables_bytes: stat_value(&stat, &["pagetables"]),
        percpu_bytes: stat_value(&stat, &["percpu"]),
        slab_reclaimable_bytes: stat_value(&stat, &["slab_reclaimable"]),
        slab_unreclaimable_bytes: stat_value(&stat, &["slab_unreclaimable"]),
        file_mapped_bytes: stat_value(&stat, &["file_mapped"]),
        file_dirty_bytes: stat_value(&stat, &["file_dirty"]),
    }
}

fn collect_cgroup_v1(directory: &Path) -> CgroupMemory {
    let current = read_number_file(&directory.join("memory.usage_in_bytes"));
    let stat = read_stat_file(&directory.join("memory.stat"));
    let max_bytes = read_number_file(&directory.join("memory.limit_in_bytes"))
        .filter(|limit| *limit < (1u64 << 60));
    CgroupMemory {
        available: current.is_some() || !stat.is_empty(),
        version: "v1".to_owned(),
        current_bytes: current.unwrap_or(0),
        peak_bytes: read_number_file(&directory.join("memory.max_usage_in_bytes")).unwrap_or(0),
        max_bytes,
        swap_current_bytes: read_number_file(&directory.join("memory.memsw.usage_in_bytes")),
        swap_max_bytes: read_number_file(&directory.join("memory.memsw.limit_in_bytes"))
            .filter(|limit| *limit < (1u64 << 60)),
        anon_bytes: stat_value(&stat, &["rss", "total_rss"]),
        file_bytes: stat_value(&stat, &["cache", "total_cache"]),
        shmem_bytes: stat_value(&stat, &["shmem", "total_shmem"]),
        sock_bytes: stat_value(&stat, &["sock", "total_sock"]),
        kernel_stack_bytes: stat_value(&stat, &["kernel_stack", "total_kernel_stack"]),
        pagetables_bytes: stat_value(&stat, &["pagetables", "total_pagetables"]),
        percpu_bytes: 0,
        slab_reclaimable_bytes: stat_value(&stat, &["slab_reclaimable", "total_slab_reclaimable"]),
        slab_unreclaimable_bytes: stat_value(
            &stat,
            &["slab_unreclaimable", "total_slab_unreclaimable"],
        ),
        file_mapped_bytes: stat_value(&stat, &["mapped_file", "total_mapped_file"]),
        file_dirty_bytes: 0,
    }
}

fn collect_socket_memory() -> SocketMemory {
    let Some((socket_fds, socket_inodes)) = own_socket_inodes() else {
        return SocketMemory::default();
    };
    let mut available = false;
    let mut udp_sockets = 0u64;
    let mut udp_tx_queue_bytes = 0u64;
    let mut udp_rx_queue_bytes = 0u64;
    let mut tcp_sockets = 0u64;
    let mut tcp_tx_queue_bytes = 0u64;
    let mut tcp_rx_queue_bytes = 0u64;

    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(table) = fs::read_to_string(path) {
            available = true;
            let (count, tx, rx) = parse_socket_table(&table, &socket_inodes);
            udp_sockets = udp_sockets.saturating_add(count);
            udp_tx_queue_bytes = udp_tx_queue_bytes.saturating_add(tx);
            udp_rx_queue_bytes = udp_rx_queue_bytes.saturating_add(rx);
        }
    }
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(table) = fs::read_to_string(path) {
            available = true;
            let (count, tx, rx) = parse_socket_table(&table, &socket_inodes);
            tcp_sockets = tcp_sockets.saturating_add(count);
            tcp_tx_queue_bytes = tcp_tx_queue_bytes.saturating_add(tx);
            tcp_rx_queue_bytes = tcp_rx_queue_bytes.saturating_add(rx);
        }
    }

    SocketMemory {
        available,
        socket_fds,
        udp_sockets,
        udp_tx_queue_bytes,
        udp_rx_queue_bytes,
        tcp_sockets,
        tcp_tx_queue_bytes,
        tcp_rx_queue_bytes,
    }
}

fn own_socket_inodes() -> Option<(u64, BTreeSet<u64>)> {
    let entries = fs::read_dir("/proc/self/fd").ok()?;
    let mut fds = 0u64;
    let mut inodes = BTreeSet::new();
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        fds = fds.saturating_add(1);
        inodes.insert(inode);
    }
    Some((fds, inodes))
}

fn parse_socket_table(table: &str, inodes: &BTreeSet<u64>) -> (u64, u64, u64) {
    let mut count = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_bytes = 0u64;
    for line in table.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let inode = fields
            .get(9)
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| fields.get(10).and_then(|value| value.parse::<u64>().ok()));
        let Some(inode) = inode else {
            continue;
        };
        if !inodes.contains(&inode) {
            continue;
        }
        let Some((tx, rx)) = fields.get(4).and_then(|value| parse_hex_pair(value)) else {
            continue;
        };
        count = count.saturating_add(1);
        tx_bytes = tx_bytes.saturating_add(tx);
        rx_bytes = rx_bytes.saturating_add(rx);
    }
    (count, tx_bytes, rx_bytes)
}

fn parse_hex_pair(value: &str) -> Option<(u64, u64)> {
    let (tx, rx) = value.split_once(':')?;
    Some((
        u64::from_str_radix(tx, 16).ok()?,
        u64::from_str_radix(rx, 16).ok()?,
    ))
}

fn collect_persistent_storage(config_dir: &Path) -> PersistentStorage {
    PersistentStorage {
        sqlite_db_bytes: file_len(&config_dir.join("csqtt.db")),
        sqlite_wal_bytes: file_len(&config_dir.join("csqtt.db-wal")),
        sqlite_shm_bytes: file_len(&config_dir.join("csqtt.db-shm")),
        log_file_bytes: file_len(&config_dir.join("csqtt.log")),
    }
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn read_number_file(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_limit_file(path: &Path) -> Option<u64> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    if value == "max" {
        None
    } else {
        value.parse().ok()
    }
}

fn read_stat_file(path: &Path) -> BTreeMap<String, u64> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            let value = fields.next()?.parse::<u64>().ok()?;
            Some((key.to_owned(), value))
        })
        .collect()
}

fn stat_value(stat: &BTreeMap<String, u64>, names: &[&str]) -> u64 {
    names
        .iter()
        .find_map(|name| stat.get(*name).copied())
        .unwrap_or(0)
}

fn proc_kib(text: &str, field: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == field)
            .then(|| fields.next()?.parse::<u64>().ok())
            .flatten()
    })
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smaps_rollup_keeps_pss_and_anonymous_semantics_separate() {
        let snapshot = parse_smaps_rollup(
            "Rss:                100 kB\nPss:                 80 kB\nPss_Anon:            40 kB\nPss_File:            30 kB\nPss_Shmem:           10 kB\nAnonymous:           55 kB\nPrivate_Clean:        3 kB\nPrivate_Dirty:        4 kB\nShared_Clean:         5 kB\nShared_Dirty:         6 kB\nSwap:                 7 kB\nSwapPss:              8 kB\n",
        );
        assert_eq!(snapshot.pss_kib, 80);
        assert_eq!(snapshot.pss_anon_kib, 40);
        assert_eq!(snapshot.pss_file_kib, 30);
        assert_eq!(snapshot.pss_shmem_kib, 10);
        assert_eq!(snapshot.anonymous_kib, 55);
        assert_eq!(snapshot.private_kib, 7);
        assert_eq!(snapshot.shared_kib, 11);
    }

    #[test]
    fn socket_queue_parser_uses_own_socket_inode_and_hex_values() {
        let table = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n  0: 0100007F:0001 00000000:0000 07 0000000A:0000000B 00:00000000 00000000 0 0 12345\n";
        let mut inodes = BTreeSet::new();
        inodes.insert(12_345);
        assert_eq!(parse_socket_table(table, &inodes), (1, 10, 11));
    }
}
