// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#[cfg(not(target_os = "linux"))]
use crate::model::LocalProxyProfile;
#[cfg(not(target_os = "linux"))]
use crate::proxy_route::LogFn;
#[cfg(not(target_os = "linux"))]
use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use std::time::Duration;

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
pub const UDP_FLOW_IDLE: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const TPROXY_BASE_PORT: u16 = 10666;
const GLOBAL_TCP_SESSION_LIMIT: usize = 384;
const GLOBAL_UDP_FLOW_LIMIT: usize = 784;
const EXPANDED_TCP_SESSION_LIMIT: usize = 1_512;
const EXPANDED_UDP_FLOW_LIMIT: usize = 2_048;
const MEMORY_EXPANDED_TCP_SESSION_LIMIT: usize = 1_784;
const MEMORY_EXPANDED_UDP_FLOW_LIMIT: usize = 2_384;
const MAX_TCP_SESSION_LIMIT: usize = 2_384;
const MAX_UDP_FLOW_LIMIT: usize = 4_096;
const MEMORY_EXPANSION_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MEMORY_EXPANSION_THRESHOLD_BYTES: u64 = 1_200 * 1024 * 1024;
const DEVICE_TCP_SESSION_LIMIT: usize = 160;
const DEVICE_UDP_FLOW_LIMIT: usize = 320;
const DEVICE_TCP_FLOOR: usize = 20;
const DEVICE_UDP_FLOOR: usize = 40;
const DEVICE_NORMAL_BUFFER_LIMIT: usize = 4;
const DEVICE_JUMBO_BUFFER_LIMIT: usize = 1;
const GLOBAL_NORMAL_BUFFER_LIMIT: usize = 32;
const GLOBAL_JUMBO_BUFFER_LIMIT: usize = 16;
const PROXY_TCP_BUFFER_BYTES: usize = 16 * 1024;
const PROXY_NORMAL_BUFFER_BYTES: usize = 4 * 1024;
const PROXY_JUMBO_BUFFER_BYTES: usize = 65_535;
const PROXY_TCP_RETAINED_LIMIT: usize = 0;
const PROXY_NORMAL_RETAINED_LIMIT: usize = 0;
const PROXY_JUMBO_RETAINED_LIMIT: usize = 0;
const PROXY_OPENING_BUFFER_LIMIT: usize = 512 * 1024;

#[derive(Default)]
struct AdmissionState {
    tcp_active: usize,
    udp_active: usize,
    normal_buffers: usize,
    jumbo_buffers: usize,
}

struct ProxyCapacity {
    tcp_limit: AtomicUsize,
    udp_limit: AtomicUsize,
    update: Mutex<()>,
}

impl ProxyCapacity {
    fn new() -> Self {
        Self {
            tcp_limit: AtomicUsize::new(GLOBAL_TCP_SESSION_LIMIT),
            udp_limit: AtomicUsize::new(GLOBAL_UDP_FLOW_LIMIT),
            update: Mutex::new(()),
        }
    }

    fn limits(&self) -> (usize, usize) {
        (
            self.tcp_limit.load(Ordering::Acquire),
            self.udp_limit.load(Ordering::Acquire),
        )
    }

    fn reset(&self) {
        let _guard = self
            .update
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.tcp_limit
            .store(GLOBAL_TCP_SESSION_LIMIT, Ordering::Release);
        self.udp_limit
            .store(GLOBAL_UDP_FLOW_LIMIT, Ordering::Release);
    }

    fn try_expand(&self) -> bool {
        let _guard = self
            .update
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let current = self.limits();
        let next = if current.0 < EXPANDED_TCP_SESSION_LIMIT || current.1 < EXPANDED_UDP_FLOW_LIMIT
        {
            (EXPANDED_TCP_SESSION_LIMIT, EXPANDED_UDP_FLOW_LIMIT)
        } else {
            Self::next_limits(current, crate::memory_metrics::available_memory_bytes())
        };
        if next == current {
            return false;
        }
        self.tcp_limit.store(next.0, Ordering::Release);
        self.udp_limit.store(next.1, Ordering::Release);
        true
    }

    fn next_limits(current: (usize, usize), available_memory: Option<u64>) -> (usize, usize) {
        if current.0 < EXPANDED_TCP_SESSION_LIMIT || current.1 < EXPANDED_UDP_FLOW_LIMIT {
            return (EXPANDED_TCP_SESSION_LIMIT, EXPANDED_UDP_FLOW_LIMIT);
        }
        if available_memory.is_some_and(|bytes| bytes >= MAX_MEMORY_EXPANSION_THRESHOLD_BYTES)
            && (current.0 < MAX_TCP_SESSION_LIMIT || current.1 < MAX_UDP_FLOW_LIMIT)
        {
            return (MAX_TCP_SESSION_LIMIT, MAX_UDP_FLOW_LIMIT);
        }
        if available_memory.is_some_and(|bytes| bytes >= MEMORY_EXPANSION_THRESHOLD_BYTES)
            && (current.0 < MEMORY_EXPANDED_TCP_SESSION_LIMIT
                || current.1 < MEMORY_EXPANDED_UDP_FLOW_LIMIT)
        {
            return (
                MEMORY_EXPANDED_TCP_SESSION_LIMIT,
                MEMORY_EXPANDED_UDP_FLOW_LIMIT,
            );
        }
        current
    }
}

struct TcpEvictionSlot {
    cancel: CancellationToken,
    evicting: bool,
}

#[derive(Debug)]
enum AdmissionError {
    Inactive,
    DeviceLimit,
    GlobalLimit,
}

struct DeviceQuota {
    tcp_active: AtomicUsize,
    udp_active: AtomicUsize,
    normal_buffers: AtomicUsize,
    jumbo_buffers: AtomicUsize,
    cancel: CancellationToken,
}

impl DeviceQuota {
    fn new() -> Self {
        Self {
            tcp_active: AtomicUsize::new(0),
            udp_active: AtomicUsize::new(0),
            normal_buffers: AtomicUsize::new(0),
            jumbo_buffers: AtomicUsize::new(0),
            cancel: CancellationToken::new(),
        }
    }
}

pub struct DeviceQuotaRegistry {
    by_ip: DashMap<Ipv4Addr, Arc<DeviceQuota>>,
    admission: Mutex<AdmissionState>,
    capacity: ProxyCapacity,
    tcp_evictions: Mutex<HashMap<u64, TcpEvictionSlot>>,
    next_tcp_eviction: AtomicU64,
    tcp_capacity_changed: tokio::sync::Notify,
}

impl DeviceQuotaRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_ip: DashMap::new(),
            admission: Mutex::new(AdmissionState::default()),
            capacity: ProxyCapacity::new(),
            tcp_evictions: Mutex::new(HashMap::new()),
            next_tcp_eviction: AtomicU64::new(1),
            tcp_capacity_changed: tokio::sync::Notify::new(),
        })
    }

    fn reset_capacity(&self) {
        self.capacity.reset();
    }

    fn release_runtime_state(&self) {
        self.capacity.reset();
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *admission = AdmissionState::default();
        drop(admission);
        let mut evictions = self
            .tcp_evictions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        evictions.clear();
        evictions.shrink_to_fit();
    }

    fn limits(&self) -> (usize, usize) {
        self.capacity.limits()
    }

    fn try_expand_capacity(&self) -> bool {
        self.capacity.try_expand()
    }

    pub fn activate_tunnel_ip(&self, tun_ip: Ipv4Addr) {
        self.by_ip
            .entry(tun_ip)
            .or_insert_with(|| Arc::new(DeviceQuota::new()));
    }

    fn quota_for_ip(&self, ip: Ipv4Addr) -> Option<Arc<DeviceQuota>> {
        self.by_ip
            .get(&ip)
            .filter(|quota| !quota.cancel.is_cancelled())
            .map(|quota| quota.value().clone())
    }

    fn active_tcp_devices(&self, current: &Arc<DeviceQuota>) -> usize {
        self.by_ip
            .iter()
            .filter(|entry| {
                Arc::ptr_eq(entry.value(), current)
                    || entry.value().tcp_active.load(Ordering::Acquire) != 0
            })
            .count()
            .max(1)
    }

    fn active_udp_devices(&self, current: &Arc<DeviceQuota>) -> usize {
        self.by_ip
            .iter()
            .filter(|entry| {
                Arc::ptr_eq(entry.value(), current)
                    || entry.value().udp_active.load(Ordering::Acquire) != 0
            })
            .count()
            .max(1)
    }

    fn try_acquire_tcp(
        self: &Arc<Self>,
        ip: Ipv4Addr,
    ) -> std::result::Result<TcpQuotaLease, AdmissionError> {
        let quota = self.quota_for_ip(ip).ok_or(AdmissionError::Inactive)?;
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tcp_limit = self.capacity.limits().0;
        let device_limit = adaptive_device_limit(
            tcp_limit,
            DEVICE_TCP_SESSION_LIMIT,
            DEVICE_TCP_FLOOR,
            self.active_tcp_devices(&quota),
        );
        if quota.tcp_active.load(Ordering::Acquire) >= device_limit {
            return Err(AdmissionError::DeviceLimit);
        }
        if admission.tcp_active >= tcp_limit {
            return Err(AdmissionError::GlobalLimit);
        }
        quota.tcp_active.fetch_add(1, Ordering::AcqRel);
        admission.tcp_active += 1;
        drop(admission);
        let session_id = self.next_tcp_eviction.fetch_add(1, Ordering::Relaxed);
        let session_cancel = CancellationToken::new();
        self.tcp_evictions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                session_id,
                TcpEvictionSlot {
                    cancel: session_cancel.clone(),
                    evicting: false,
                },
            );
        Ok(TcpQuotaLease {
            registry: self.clone(),
            quota,
            session_id,
            session_cancel,
        })
    }

    fn try_acquire_udp(
        self: &Arc<Self>,
        ip: Ipv4Addr,
    ) -> std::result::Result<UdpQuotaLease, AdmissionError> {
        let quota = self.quota_for_ip(ip).ok_or(AdmissionError::Inactive)?;
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let udp_limit = self.capacity.limits().1;
        let device_limit = adaptive_device_limit(
            udp_limit,
            DEVICE_UDP_FLOW_LIMIT,
            DEVICE_UDP_FLOOR,
            self.active_udp_devices(&quota),
        );
        if quota.udp_active.load(Ordering::Acquire) >= device_limit {
            return Err(AdmissionError::DeviceLimit);
        }
        if admission.udp_active >= udp_limit {
            return Err(AdmissionError::GlobalLimit);
        }
        quota.udp_active.fetch_add(1, Ordering::AcqRel);
        admission.udp_active += 1;
        Ok(UdpQuotaLease {
            registry: self.clone(),
            quota,
        })
    }

    fn cancel_oldest_tcp(&self) -> bool {
        let mut sessions = self
            .tcp_evictions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let oldest = sessions
            .iter()
            .filter(|(_, slot)| !slot.evicting)
            .map(|(id, _)| *id)
            .min();
        let Some(id) = oldest else {
            return false;
        };
        let Some(slot) = sessions.get_mut(&id) else {
            return false;
        };
        slot.evicting = true;
        slot.cancel.cancel();
        true
    }

    #[cfg(target_os = "linux")]
    async fn evict_oldest_tcp_and_wait(&self) -> bool {
        let released = self.tcp_capacity_changed.notified();
        if !self.cancel_oldest_tcp() {
            return false;
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), released).await;
        true
    }

    fn try_acquire_normal_buffer(
        self: &Arc<Self>,
        quota: Arc<DeviceQuota>,
    ) -> Option<BufferQuotaLease> {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if quota.normal_buffers.load(Ordering::Acquire) >= DEVICE_NORMAL_BUFFER_LIMIT
            || admission.normal_buffers >= GLOBAL_NORMAL_BUFFER_LIMIT
        {
            return None;
        }
        quota.normal_buffers.fetch_add(1, Ordering::AcqRel);
        admission.normal_buffers += 1;
        Some(BufferQuotaLease {
            registry: self.clone(),
            quota,
            jumbo: false,
        })
    }

    fn try_acquire_jumbo_buffer(
        self: &Arc<Self>,
        quota: Arc<DeviceQuota>,
    ) -> Option<BufferQuotaLease> {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if quota.jumbo_buffers.load(Ordering::Acquire) >= DEVICE_JUMBO_BUFFER_LIMIT
            || admission.jumbo_buffers >= GLOBAL_JUMBO_BUFFER_LIMIT
        {
            return None;
        }
        quota.jumbo_buffers.fetch_add(1, Ordering::AcqRel);
        admission.jumbo_buffers += 1;
        Some(BufferQuotaLease {
            registry: self.clone(),
            quota,
            jumbo: true,
        })
    }
}

fn adaptive_device_limit(
    global_limit: usize,
    device_limit: usize,
    device_floor: usize,
    active_devices: usize,
) -> usize {
    (global_limit / active_devices.max(1))
        .max(device_floor)
        .min(device_limit)
}

struct TcpQuotaLease {
    registry: Arc<DeviceQuotaRegistry>,
    quota: Arc<DeviceQuota>,
    session_id: u64,
    session_cancel: CancellationToken,
}

impl TcpQuotaLease {
    fn cancel(&self) -> CancellationToken {
        self.quota.cancel.clone()
    }

    fn session_cancel(&self) -> CancellationToken {
        self.session_cancel.clone()
    }
}

impl Drop for TcpQuotaLease {
    fn drop(&mut self) {
        let mut evictions = self
            .registry
            .tcp_evictions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        evictions.remove(&self.session_id);
        if evictions.len().saturating_mul(4) < evictions.capacity() {
            evictions.shrink_to(16);
        }
        drop(evictions);
        let mut admission = self
            .registry
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.quota.tcp_active.fetch_sub(1, Ordering::AcqRel);
        admission.tcp_active = admission.tcp_active.saturating_sub(1);
        drop(admission);
        self.registry.tcp_capacity_changed.notify_one();
    }
}

struct UdpQuotaLease {
    registry: Arc<DeviceQuotaRegistry>,
    quota: Arc<DeviceQuota>,
}

impl UdpQuotaLease {
    fn quota(&self) -> Arc<DeviceQuota> {
        self.quota.clone()
    }

    fn cancel(&self) -> CancellationToken {
        self.quota.cancel.child_token()
    }
}

impl Drop for UdpQuotaLease {
    fn drop(&mut self) {
        let mut admission = self
            .registry
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.quota.udp_active.fetch_sub(1, Ordering::AcqRel);
        admission.udp_active = admission.udp_active.saturating_sub(1);
    }
}

struct BufferQuotaLease {
    registry: Arc<DeviceQuotaRegistry>,
    quota: Arc<DeviceQuota>,
    jumbo: bool,
}

impl Drop for BufferQuotaLease {
    fn drop(&mut self) {
        let mut admission = self
            .registry
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.jumbo {
            self.quota.jumbo_buffers.fetch_sub(1, Ordering::AcqRel);
            admission.jumbo_buffers = admission.jumbo_buffers.saturating_sub(1);
        } else {
            self.quota.normal_buffers.fetch_sub(1, Ordering::AcqRel);
            admission.normal_buffers = admission.normal_buffers.saturating_sub(1);
        }
    }
}

struct BufferClassPool {
    queue: Option<ArrayQueue<BytesMut>>,
    allocated: AtomicUsize,
    retained: AtomicUsize,
    retained_limit: usize,
    limit: usize,
    size: usize,
}

impl BufferClassPool {
    fn new(limit: usize, retained: usize, size: usize) -> Self {
        let retained_limit = retained.min(limit);
        Self {
            queue: (retained_limit != 0).then(|| ArrayQueue::new(retained_limit)),
            allocated: AtomicUsize::new(0),
            retained: AtomicUsize::new(0),
            retained_limit,
            limit,
            size,
        }
    }

    fn acquire(&self) -> Option<BytesMut> {
        if let Some(queue) = &self.queue
            && let Some(buffer) = queue.pop()
        {
            self.retained.fetch_sub(1, Ordering::AcqRel);
            return Some(buffer);
        }
        self.allocated
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |allocated| {
                (allocated < self.limit).then_some(allocated + 1)
            })
            .ok()?;
        Some(BytesMut::zeroed(self.size))
    }

    fn release(&self, buffer: BytesMut) {
        if buffer.len() != self.size || self.retained_limit == 0 {
            self.allocated.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        if self
            .retained
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |retained| {
                (retained < self.retained_limit).then_some(retained + 1)
            })
            .is_err()
        {
            self.allocated.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let Some(queue) = &self.queue else {
            self.retained.fetch_sub(1, Ordering::AcqRel);
            self.allocated.fetch_sub(1, Ordering::AcqRel);
            return;
        };
        if queue.push(buffer).is_err() {
            self.retained.fetch_sub(1, Ordering::AcqRel);
            self.allocated.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn trim(&self) {
        let Some(queue) = &self.queue else {
            return;
        };
        while queue.pop().is_some() {
            self.retained.fetch_sub(1, Ordering::AcqRel);
            self.allocated.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn snapshot(&self) -> (usize, usize) {
        (
            self.allocated.load(Ordering::Acquire),
            self.retained.load(Ordering::Acquire),
        )
    }
}

struct ProxyBufferPool {
    tcp: BufferClassPool,
    normal: BufferClassPool,
    jumbo: BufferClassPool,
}

impl ProxyBufferPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tcp: BufferClassPool::new(
                MAX_TCP_SESSION_LIMIT * 2,
                PROXY_TCP_RETAINED_LIMIT,
                PROXY_TCP_BUFFER_BYTES,
            ),
            normal: BufferClassPool::new(
                GLOBAL_NORMAL_BUFFER_LIMIT,
                PROXY_NORMAL_RETAINED_LIMIT,
                PROXY_NORMAL_BUFFER_BYTES,
            ),
            jumbo: BufferClassPool::new(
                GLOBAL_JUMBO_BUFFER_LIMIT,
                PROXY_JUMBO_RETAINED_LIMIT,
                PROXY_JUMBO_BUFFER_BYTES,
            ),
        })
    }

    fn acquire_tcp(self: &Arc<Self>) -> Option<ProxyBufferLease> {
        self.tcp.acquire().map(|buffer| ProxyBufferLease {
            pool: self.clone(),
            buffer: Some(buffer),
            class: BufferClass::Tcp,
            permit: None,
        })
    }

    fn acquire_udp(
        self: &Arc<Self>,
        registry: &Arc<DeviceQuotaRegistry>,
        quota: Arc<DeviceQuota>,
        jumbo: bool,
    ) -> Option<ProxyBufferLease> {
        let permit = if jumbo {
            registry.try_acquire_jumbo_buffer(quota)
        } else {
            registry.try_acquire_normal_buffer(quota)
        }?;
        let class = if jumbo {
            BufferClass::Jumbo
        } else {
            BufferClass::Normal
        };
        let buffer = match class {
            BufferClass::Normal => self.normal.acquire(),
            BufferClass::Jumbo => self.jumbo.acquire(),
            BufferClass::Tcp => None,
        }?;
        Some(ProxyBufferLease {
            pool: self.clone(),
            buffer: Some(buffer),
            class,
            permit: Some(permit),
        })
    }

    fn snapshot(&self) -> ProxyBufferPoolSnapshot {
        let (tcp_allocated, tcp_retained) = self.tcp.snapshot();
        let (normal_allocated, normal_retained) = self.normal.snapshot();
        let (jumbo_allocated, jumbo_retained) = self.jumbo.snapshot();
        ProxyBufferPoolSnapshot {
            tcp_allocated,
            tcp_retained,
            normal_allocated,
            normal_retained,
            jumbo_allocated,
            jumbo_retained,
        }
    }

    fn trim(&self) {
        self.tcp.trim();
        self.normal.trim();
        self.jumbo.trim();
    }
}

#[derive(Clone, Copy, Default)]
struct ProxyBufferPoolSnapshot {
    tcp_allocated: usize,
    tcp_retained: usize,
    normal_allocated: usize,
    normal_retained: usize,
    jumbo_allocated: usize,
    jumbo_retained: usize,
}

enum BufferClass {
    Tcp,
    Normal,
    Jumbo,
}

struct ProxyBufferLease {
    pool: Arc<ProxyBufferPool>,
    buffer: Option<BytesMut>,
    class: BufferClass,
    permit: Option<BufferQuotaLease>,
}

impl ProxyBufferLease {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_deref_mut().unwrap_or_default()
    }
}

impl Drop for ProxyBufferLease {
    fn drop(&mut self) {
        let Some(buffer) = self.buffer.take() else {
            return;
        };
        match self.class {
            BufferClass::Tcp => self.pool.tcp.release(buffer),
            BufferClass::Normal => self.pool.normal.release(buffer),
            BufferClass::Jumbo => self.pool.jumbo.release(buffer),
        }
        self.permit.take();
    }
}

struct OpeningBufferPool {
    allocated_bytes: AtomicUsize,
}

impl OpeningBufferPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            allocated_bytes: AtomicUsize::new(0),
        })
    }

    fn acquire(self: &Arc<Self>, len: usize) -> Option<OpeningBufferLease> {
        let storage = BytesMut::zeroed(len);
        let capacity = storage.capacity();
        self.allocated_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |allocated| {
                allocated
                    .checked_add(capacity)
                    .filter(|next| *next <= PROXY_OPENING_BUFFER_LIMIT)
            })
            .ok()?;
        Some(OpeningBufferLease {
            pool: self.clone(),
            storage: Some(storage),
        })
    }

    fn release(&self, storage: BytesMut) {
        let capacity = storage.capacity();
        self.allocated_bytes.fetch_sub(capacity, Ordering::AcqRel);
        drop(storage);
    }

    fn allocated_bytes(&self) -> usize {
        self.allocated_bytes.load(Ordering::Acquire)
    }
}

struct OpeningBufferLease {
    pool: Arc<OpeningBufferPool>,
    storage: Option<BytesMut>,
}

impl OpeningBufferLease {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.storage.as_deref_mut().unwrap_or_default()
    }

    fn as_slice(&self) -> &[u8] {
        self.storage.as_deref().unwrap_or_default()
    }
}

impl Drop for OpeningBufferLease {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.take() {
            self.pool.release(storage);
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TproxyMemoryBudget {
    pub tcp_relay_bytes_per_session: u64,
    pub udp_normal_buffer_bytes: u64,
    pub udp_jumbo_buffer_bytes: u64,
    pub udp_response_bytes_at_limit: u64,
}

#[cfg(target_os = "linux")]
pub const fn memory_budget() -> TproxyMemoryBudget {
    let tcp_relay_bytes_per_session = (linux::RELAY_BUF * 2) as u64;
    let udp_normal_buffer_bytes = 4 * 1024;
    let udp_jumbo_buffer_bytes = linux::UDP_RECV_BUF as u64;
    TproxyMemoryBudget {
        tcp_relay_bytes_per_session,
        udp_normal_buffer_bytes,
        udp_jumbo_buffer_bytes,
        udp_response_bytes_at_limit: (GLOBAL_NORMAL_BUFFER_LIMIT as u64) * udp_normal_buffer_bytes
            + (GLOBAL_JUMBO_BUFFER_LIMIT as u64) * udp_jumbo_buffer_bytes,
    }
}

#[cfg(not(target_os = "linux"))]
pub const fn memory_budget() -> TproxyMemoryBudget {
    TproxyMemoryBudget {
        tcp_relay_bytes_per_session: 0,
        udp_normal_buffer_bytes: 0,
        udp_jumbo_buffer_bytes: 0,
        udp_response_bytes_at_limit: 0,
    }
}

pub struct TproxyStats {
    pub tcp_active: std::sync::atomic::AtomicUsize,
    pub udp_active: std::sync::atomic::AtomicUsize,
    tcp_peak: std::sync::atomic::AtomicUsize,
    udp_peak: std::sync::atomic::AtomicUsize,
    tcp_total: std::sync::atomic::AtomicU64,
    udp_total: std::sync::atomic::AtomicU64,
    tcp_budget_rejects: std::sync::atomic::AtomicU64,
    udp_budget_rejects: std::sync::atomic::AtomicU64,
    tcp_limit: std::sync::atomic::AtomicUsize,
    udp_limit: std::sync::atomic::AtomicUsize,
    buffer_pools: Mutex<TproxyBufferPools>,
}

struct TproxyBufferPools {
    proxy: Weak<ProxyBufferPool>,
    opening: Weak<OpeningBufferPool>,
}

impl Default for TproxyBufferPools {
    fn default() -> Self {
        Self {
            proxy: Weak::new(),
            opening: Weak::new(),
        }
    }
}

impl Default for TproxyStats {
    fn default() -> Self {
        Self {
            tcp_active: std::sync::atomic::AtomicUsize::new(0),
            udp_active: std::sync::atomic::AtomicUsize::new(0),
            tcp_peak: std::sync::atomic::AtomicUsize::new(0),
            udp_peak: std::sync::atomic::AtomicUsize::new(0),
            tcp_total: std::sync::atomic::AtomicU64::new(0),
            udp_total: std::sync::atomic::AtomicU64::new(0),
            tcp_budget_rejects: std::sync::atomic::AtomicU64::new(0),
            udp_budget_rejects: std::sync::atomic::AtomicU64::new(0),
            tcp_limit: std::sync::atomic::AtomicUsize::new(GLOBAL_TCP_SESSION_LIMIT),
            udp_limit: std::sync::atomic::AtomicUsize::new(GLOBAL_UDP_FLOW_LIMIT),
            buffer_pools: Mutex::new(TproxyBufferPools::default()),
        }
    }
}

#[derive(Clone, Copy, Default, serde::Deserialize, serde::Serialize)]
pub struct TproxyStatsSnapshot {
    pub tcp_active: usize,
    pub udp_active: usize,
    pub tcp_peak: usize,
    pub udp_peak: usize,
    pub tcp_total: u64,
    pub udp_total: u64,
    pub tcp_budget_rejects: u64,
    pub udp_budget_rejects: u64,
    pub tcp_limit: usize,
    pub udp_limit: usize,
    pub tcp_buffer_allocated: usize,
    pub tcp_buffer_retained: usize,
    pub udp_normal_buffer_allocated: usize,
    pub udp_normal_buffer_retained: usize,
    pub udp_jumbo_buffer_allocated: usize,
    pub udp_jumbo_buffer_retained: usize,
    pub opening_buffer_allocated_bytes: usize,
}

impl TproxyStats {
    fn tcp_started(&self) {
        let active = self
            .tcp_active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.tcp_peak
            .fetch_max(active, std::sync::atomic::Ordering::Relaxed);
        self.tcp_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn tcp_finished(&self) {
        self.tcp_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn udp_started(&self) {
        let active = self
            .udp_active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.udp_peak
            .fetch_max(active, std::sync::atomic::Ordering::Relaxed);
        self.udp_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn udp_finished(&self) {
        self.udp_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn tcp_budget_rejected(&self) {
        self.tcp_budget_rejects
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn udp_budget_rejected(&self) {
        self.udp_budget_rejects
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn set_limits(&self, limits: (usize, usize)) {
        self.tcp_limit
            .store(limits.0, std::sync::atomic::Ordering::Relaxed);
        self.udp_limit
            .store(limits.1, std::sync::atomic::Ordering::Relaxed);
    }

    fn bind_proxy_buffers(&self, buffers: &Arc<ProxyBufferPool>) {
        self.buffer_pools
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .proxy = Arc::downgrade(buffers);
    }

    fn bind_opening_buffers(&self, buffers: &Arc<OpeningBufferPool>) {
        self.buffer_pools
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .opening = Arc::downgrade(buffers);
    }

    fn clear_buffer_pools(&self) {
        *self
            .buffer_pools
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = TproxyBufferPools::default();
    }

    fn buffer_snapshot(&self) -> (ProxyBufferPoolSnapshot, usize) {
        let (proxy, opening) = {
            let pools = self
                .buffer_pools
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            (pools.proxy.clone(), pools.opening.clone())
        };
        let proxy = proxy
            .upgrade()
            .map(|buffers| buffers.snapshot())
            .unwrap_or_default();
        let opening = opening
            .upgrade()
            .map(|buffers| buffers.allocated_bytes())
            .unwrap_or_default();
        (proxy, opening)
    }

    pub fn snapshot(&self) -> TproxyStatsSnapshot {
        let (buffers, opening_buffer_allocated_bytes) = self.buffer_snapshot();
        TproxyStatsSnapshot {
            tcp_active: self.tcp_active.load(std::sync::atomic::Ordering::Relaxed),
            udp_active: self.udp_active.load(std::sync::atomic::Ordering::Relaxed),
            tcp_peak: self.tcp_peak.load(std::sync::atomic::Ordering::Relaxed),
            udp_peak: self.udp_peak.load(std::sync::atomic::Ordering::Relaxed),
            tcp_total: self.tcp_total.load(std::sync::atomic::Ordering::Relaxed),
            udp_total: self.udp_total.load(std::sync::atomic::Ordering::Relaxed),
            tcp_budget_rejects: self
                .tcp_budget_rejects
                .load(std::sync::atomic::Ordering::Relaxed),
            udp_budget_rejects: self
                .udp_budget_rejects
                .load(std::sync::atomic::Ordering::Relaxed),
            tcp_limit: self.tcp_limit.load(std::sync::atomic::Ordering::Relaxed),
            udp_limit: self.udp_limit.load(std::sync::atomic::Ordering::Relaxed),
            tcp_buffer_allocated: buffers.tcp_allocated,
            tcp_buffer_retained: buffers.tcp_retained,
            udp_normal_buffer_allocated: buffers.normal_allocated,
            udp_normal_buffer_retained: buffers.normal_retained,
            udp_jumbo_buffer_allocated: buffers.jumbo_allocated,
            udp_jumbo_buffer_retained: buffers.jumbo_retained,
            opening_buffer_allocated_bytes,
        }
    }
}

pub fn tproxy_port(runtime_id: u64) -> u16 {
    TPROXY_BASE_PORT + (runtime_id % 50_000) as u16
}

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::{TproxySockets, bind_sockets, run};

#[cfg(not(target_os = "linux"))]
pub struct TproxySockets {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
pub fn bind_sockets(_port: u16) -> Result<TproxySockets> {
    bail!("TPROXY forwarding is supported only on Linux servers")
}

#[cfg(not(target_os = "linux"))]
pub async fn run(
    _sockets: TproxySockets,
    _config: Arc<LocalProxyProfile>,
    _cancel: tokio_util::sync::CancellationToken,
    _log: LogFn,
    _stats: Arc<TproxyStats>,
    _quotas: Arc<DeviceQuotaRegistry>,
) -> (u64, u64, u64) {
    (0, 0, 0)
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::model::LocalProxyProfile;
    use crate::proxy_route::{LogFn, socks_command, socks_udp_response};
    use anyhow::{Context, Result};
    use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, SockAddr, Socket, Type};
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::{AsRawFd, RawFd};
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    const IP_TRANSPARENT: libc::c_int = 19;
    pub(super) const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const LISTEN_BACKLOG: libc::c_int = 4096;
    pub(super) const UDP_RECV_BUF: usize = 65_535;
    const UDP_CONTROL_BUF: usize = 64;
    const ASSOCIATION_BACKOFF: Duration = Duration::from_secs(2);
    const ASSOCIATION_POOL_TARGET: usize = 4;
    const OPENING_PENDING_LIMIT: usize = 64;
    const OPENING_PENDING_BYTES: usize = 64 * 1024;
    const MAX_CONCURRENT_OPENINGS: usize = 64;
    const UDP_INGRESS_SOCKET_BUFFER: usize = 256 * 1024;
    const UDP_RELAY_SOCKET_BUFFER: usize = 32 * 1024;
    const UDP_ASSOCIATION_CONTROL_BUFFER: usize = 16 * 1024;
    const RAW_REPLY_SOCKET_BUFFER: usize = 128 * 1024;

    pub struct TproxySockets {
        tcp: TcpListener,
        udp: Arc<UdpTproxy>,
    }

    pub fn bind_sockets(port: u16) -> Result<TproxySockets> {
        let tcp = bind_tcp_listener(port).context("bind transparent TCP listener")?;
        let udp = Arc::new(UdpTproxy::bind(port).context("bind transparent UDP socket")?);
        verify_raw_reply_socket().context("verify transparent UDP raw reply socket")?;
        Ok(TproxySockets { tcp, udp })
    }

    pub async fn run(
        sockets: TproxySockets,
        config: Arc<LocalProxyProfile>,
        cancel: CancellationToken,
        log: LogFn,
        stats: Arc<super::TproxyStats>,
        quotas: Arc<super::DeviceQuotaRegistry>,
    ) -> (u64, u64, u64) {
        quotas.reset_capacity();
        stats.set_limits(quotas.limits());
        let buffers = super::ProxyBufferPool::new();
        stats.bind_proxy_buffers(&buffers);
        let udp_task = tokio::spawn(run_udp(
            sockets.udp.clone(),
            config.clone(),
            cancel.clone(),
            log.clone(),
            stats.clone(),
            quotas.clone(),
            buffers.clone(),
        ));
        let tcp_sessions = run_tcp(
            sockets.tcp,
            config,
            cancel,
            log,
            stats.clone(),
            quotas.clone(),
            buffers.clone(),
        )
        .await;
        let (udp_flows, udp_datagrams) = udp_task.await.unwrap_or((0, 0));
        buffers.trim();
        drop(buffers);
        stats.clear_buffer_pools();
        quotas.release_runtime_state();
        (tcp_sessions, udp_flows, udp_datagrams)
    }

    fn set_int_option(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn bind_tcp_listener(port: u16) -> Result<TcpListener> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("open transparent TCP listener socket")?;
        socket
            .set_reuse_address(true)
            .context("enable SO_REUSEADDR on transparent TCP listener")?;
        set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, IP_TRANSPARENT, 1)
            .context("enable IP_TRANSPARENT on transparent TCP listener")?;
        socket
            .set_nonblocking(true)
            .context("set transparent TCP listener nonblocking")?;
        socket
            .bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                port,
            ))))
            .with_context(|| format!("bind transparent TCP listener on 0.0.0.0:{port}"))?;
        socket
            .listen(LISTEN_BACKLOG)
            .context("listen on transparent TCP listener")?;
        let listener: std::net::TcpListener = socket.into();
        TcpListener::from_std(listener).context("register transparent TCP listener with Tokio")
    }

    async fn acquire_tcp_quota(
        quotas: &Arc<super::DeviceQuotaRegistry>,
        client_ip: Ipv4Addr,
        stats: &Arc<super::TproxyStats>,
    ) -> Option<super::TcpQuotaLease> {
        loop {
            match quotas.try_acquire_tcp(client_ip) {
                Ok(quota) => {
                    stats.set_limits(quotas.limits());
                    return Some(quota);
                }
                Err(super::AdmissionError::Inactive | super::AdmissionError::DeviceLimit) => {
                    return None;
                }
                Err(super::AdmissionError::GlobalLimit) => {}
            }
            if quotas.try_expand_capacity() {
                stats.set_limits(quotas.limits());
                continue;
            }
            if !quotas.evict_oldest_tcp_and_wait().await {
                return None;
            }
            if let Ok(quota) = quotas.try_acquire_tcp(client_ip) {
                stats.set_limits(quotas.limits());
                return Some(quota);
            }
            return None;
        }
    }

    async fn run_tcp(
        listener: TcpListener,
        config: Arc<LocalProxyProfile>,
        cancel: CancellationToken,
        _log: LogFn,
        stats: Arc<super::TproxyStats>,
        quotas: Arc<super::DeviceQuotaRegistry>,
        buffers: Arc<super::ProxyBufferPool>,
    ) -> u64 {
        let mut sessions: JoinSet<()> = JoinSet::new();
        let mut served: u64 = 0;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = sessions.join_next(), if !sessions.is_empty() => {
                    if sessions.is_empty() {
                        sessions = JoinSet::new();
                    }
                },
                accept = listener.accept() => match accept {
                    Ok((connection, peer)) => {
                        let SocketAddr::V4(client) = peer else {
                            continue;
                        };
                        if !allowed_client(client) {
                            continue;
                        }
                        quotas.activate_tunnel_ip(*client.ip());
                        let Ok(destination) = connection.local_addr() else {
                            continue;
                        };
                        let Some(quota) = acquire_tcp_quota(&quotas, *client.ip(), &stats).await else {
                            stats.tcp_budget_rejected();
                            continue;
                        };
                        stats.tcp_started();
                        served += 1;
                        sessions.spawn(handle_tcp_session(
                            connection,
                            destination,
                            config.clone(),
                            stats.clone(),
                            quota,
                            buffers.clone(),
                        ));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                },
            }
        }
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        served
    }

    const TCP_IDLE_LIMIT_MS: i64 = 600_000;
    const TCP_HARD_LIMIT_MS: i64 = 7_200_000;
    const TCP_WATCHDOG_TICK: Duration = Duration::from_secs(30);
    pub(super) const RELAY_BUF: usize = super::PROXY_TCP_BUFFER_BYTES;
    const _: () = assert!(super::MAX_TCP_SESSION_LIMIT * 2 * RELAY_BUF <= 80 * 1024 * 1024);

    struct TcpActiveGuard(Arc<super::TproxyStats>);

    impl Drop for TcpActiveGuard {
        fn drop(&mut self) {
            self.0.tcp_finished();
        }
    }

    pub(super) fn session_expired(last_ms: i64, start_ms: i64, now_ms: i64) -> bool {
        now_ms.saturating_sub(last_ms) > TCP_IDLE_LIMIT_MS
            || now_ms.saturating_sub(start_ms) > TCP_HARD_LIMIT_MS
    }

    async fn handle_tcp_session(
        client: TcpStream,
        destination: SocketAddr,
        config: Arc<LocalProxyProfile>,
        stats: Arc<super::TproxyStats>,
        quota: super::TcpQuotaLease,
        buffers: Arc<super::ProxyBufferPool>,
    ) {
        let _active = TcpActiveGuard(stats);
        let device_cancel = quota.cancel();
        let session_cancel = quota.session_cancel();
        let Some(to_upstream_buffer) = buffers.acquire_tcp() else {
            return;
        };
        let Some(to_client_buffer) = buffers.acquire_tcp() else {
            return;
        };
        let _quota = quota;
        client.set_nodelay(true).ok();
        let client_socket = socket2::SockRef::from(&client);
        let _ = client_socket.set_keepalive(true);
        let handshake = tokio::select! {
            biased;
            _ = session_cancel.cancelled() => return,
            result = tokio::time::timeout(
                super::SOCKS_HANDSHAKE_TIMEOUT,
                socks_command(&config, 0x01, destination),
            ) => result,
        };
        let upstream = match handshake {
            Ok(Ok((stream, _bound))) => stream,
            _ => return,
        };
        upstream.set_nodelay(true).ok();

        let start_ms = now_ms();
        let last = Arc::new(AtomicI64::new(start_ms));

        let (mut client_rx, mut client_tx) = tokio::io::split(client);
        let (mut upstream_rx, mut upstream_tx) = tokio::io::split(upstream);
        let to_upstream = relay_direction(
            &mut client_rx,
            &mut upstream_tx,
            &last,
            &session_cancel,
            &device_cancel,
            to_upstream_buffer,
        );
        let to_client = relay_direction(
            &mut upstream_rx,
            &mut client_tx,
            &last,
            &session_cancel,
            &device_cancel,
            to_client_buffer,
        );
        let relay = async {
            tokio::join!(to_upstream, to_client);
        };
        tokio::pin!(relay);
        let watchdog = async {
            loop {
                tokio::select! {
                    biased;
                    _ = session_cancel.cancelled() => break,
                    _ = tokio::time::sleep(TCP_WATCHDOG_TICK) => {}
                }
                if session_expired(last.load(Ordering::Relaxed), start_ms, now_ms()) {
                    break;
                }
            }
        };
        tokio::select! {
            _ = &mut relay => {}
            _ = watchdog => {
                session_cancel.cancel();
                (&mut relay).await;
            }
        }
        session_cancel.cancel();
    }

    async fn relay_direction<R, W>(
        reader: &mut R,
        writer: &mut W,
        last: &AtomicI64,
        cancel: &CancellationToken,
        device_cancel: &CancellationToken,
        mut buffer: super::ProxyBufferLease,
    ) where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let read = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = device_cancel.cancelled() => break,
                result = reader.read(buffer.as_mut_slice()) => result,
            };
            let received = match read {
                Ok(0) | Err(_) => break,
                Ok(received) => received,
            };
            let written = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = device_cancel.cancelled() => break,
                result = writer.write_all(&buffer.as_mut_slice()[..received]) => result,
            };
            if written.is_err() {
                break;
            }
            last.store(now_ms(), Ordering::Relaxed);
        }
        let _ = writer.shutdown().await;
    }

    struct UdpTproxy {
        socket: Socket,
    }

    impl UdpTproxy {
        fn bind(port: u16) -> Result<Self> {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .context("open transparent UDP socket")?;
            socket
                .set_reuse_address(true)
                .context("enable SO_REUSEADDR on transparent UDP socket")?;
            set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, IP_TRANSPARENT, 1)
                .context("enable IP_TRANSPARENT on transparent UDP socket")?;
            set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, IP_RECVORIGDSTADDR, 1)
                .context("enable IP_RECVORIGDSTADDR on transparent UDP socket")?;
            let _ = socket.set_recv_buffer_size(UDP_INGRESS_SOCKET_BUFFER);
            let _ = socket.set_send_buffer_size(UDP_INGRESS_SOCKET_BUFFER);
            socket
                .set_nonblocking(true)
                .context("set transparent UDP socket nonblocking")?;
            socket
                .bind(&SockAddr::from(SocketAddr::from((
                    Ipv4Addr::UNSPECIFIED,
                    port,
                ))))
                .with_context(|| format!("bind transparent UDP socket on 0.0.0.0:{port}"))?;
            Ok(Self { socket })
        }

        fn try_recv(
            &self,
            buf: &mut [mem::MaybeUninit<u8>],
            control: &mut [mem::MaybeUninit<u8>],
        ) -> io::Result<(usize, SocketAddrV4, SocketAddrV4)> {
            let mut addr =
                SockAddr::from(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
            let (received, control_len) = {
                let mut slices = [MaybeUninitSlice::new(buf)];
                let mut msg = MsgHdrMut::new()
                    .with_addr(&mut addr)
                    .with_buffers(&mut slices)
                    .with_control(control);
                let received = self.socket.recvmsg(&mut msg, 0)?;
                (received, msg.control_len().min(control.len()))
            };
            let client = addr.as_socket_ipv4().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-IPv4 client datagram")
            })?;
            let control_bytes =
                unsafe { std::slice::from_raw_parts(control.as_ptr() as *const u8, control_len) };
            let destination = parse_orig_dst(control_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing IP_RECVORIGDSTADDR")
            })?;
            Ok((received, client, destination))
        }
    }

    impl AsRawFd for UdpTproxy {
        fn as_raw_fd(&self) -> RawFd {
            self.socket.as_raw_fd()
        }
    }

    // Only clients inside the TUN subnet may use the transparent listeners;
    // remote packets hitting the public IP must not create proxy circuits.
    fn allowed_client(client: SocketAddrV4) -> bool {
        static SUBNET: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
        let prefix = SUBNET.get_or_init(|| {
            crate::tun_device::TUN_SUBNET
                .split_once('/')
                .and_then(|(base, bits)| {
                    let base: Ipv4Addr = base.parse().ok()?;
                    let bits: u32 = bits.parse().ok()?;
                    if bits == 0 || bits > 32 {
                        return None;
                    }
                    Some((u32::from(base), bits))
                })
        });
        let Some((base, bits)) = prefix else {
            return true;
        };
        let mask = if *bits == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - *bits)
        };
        u32::from(*client.ip()) & mask == base & mask
    }

    pub(super) fn parse_orig_dst(mut control: &[u8]) -> Option<SocketAddrV4> {
        while control.len() >= mem::size_of::<libc::cmsghdr>() {
            let header: &libc::cmsghdr = unsafe { &*(control.as_ptr() as *const libc::cmsghdr) };
            #[allow(clippy::unnecessary_cast)]
            let length = header.cmsg_len as usize;
            if length < mem::size_of::<libc::cmsghdr>() || length > control.len() {
                break;
            }
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == IP_RECVORIGDSTADDR {
                let data = &control[mem::size_of::<libc::cmsghdr>()..length];
                if data.len() >= mem::size_of::<libc::sockaddr_in>() {
                    let sockaddr: libc::sockaddr_in =
                        unsafe { ptr::read(data.as_ptr() as *const libc::sockaddr_in) };
                    if sockaddr.sin_family == libc::AF_INET as libc::sa_family_t {
                        return Some(SocketAddrV4::new(
                            Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes()),
                            u16::from_be(sockaddr.sin_port),
                        ));
                    }
                }
            }
            let advance = (length + 3) & !3;
            if advance == 0 {
                break;
            }
            control = &control[advance.min(control.len())..];
        }
        None
    }

    struct RawReplySocket {
        socket: Socket,
        send_errors: AtomicU64,
    }

    impl RawReplySocket {
        fn new() -> Result<Self> {
            let socket = Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_RAW)),
            )
            .context("open raw UDP reply socket")?;
            socket
                .set_nonblocking(true)
                .context("set raw UDP reply socket nonblocking")?;
            set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, 1)
                .context("enable IP_HDRINCL on raw UDP reply socket")?;
            let _ = socket.set_send_buffer_size(RAW_REPLY_SOCKET_BUFFER);
            Ok(Self {
                socket,
                send_errors: AtomicU64::new(0),
            })
        }

        fn send_reply(
            &self,
            source_ip: Ipv4Addr,
            dest_ip: Ipv4Addr,
            source_port: u16,
            dest_port: u16,
            payload: &[u8],
        ) {
            let total_len = 20 + 8 + payload.len();
            if total_len > 65535 {
                return;
            }
            let mut packet = [0u8; 28];
            // IPv4 header (20 bytes)
            packet[0] = 0x45; // Version 4, IHL 5
            packet[1] = 0x00; // DSCP / ECN
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID
            packet[6..8].copy_from_slice(&0u16.to_be_bytes()); // No DF: allow fragmentation
            packet[8] = 64; // TTL
            packet[9] = libc::IPPROTO_UDP as u8; // Protocol 17
            // Checksum will be computed
            packet[12..16].copy_from_slice(&source_ip.octets());
            packet[16..20].copy_from_slice(&dest_ip.octets());
            let ip_checksum = calc_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

            // UDP header (8 bytes)
            let udp_len = (8 + payload.len()) as u16;
            packet[20..22].copy_from_slice(&source_port.to_be_bytes());
            packet[22..24].copy_from_slice(&dest_port.to_be_bytes());
            packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
            packet[26..28].copy_from_slice(&0u16.to_be_bytes()); // Checksum optional in IPv4 UDP

            // Send using sendmsg with 2 iovecs: header (28 bytes) + payload
            let iov = [
                libc::iovec {
                    iov_base: packet.as_ptr() as *mut libc::c_void,
                    iov_len: 28,
                },
                libc::iovec {
                    iov_base: payload.as_ptr() as *mut libc::c_void,
                    iov_len: payload.len(),
                },
            ];
            let raw_dest = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dest_ip.octets()),
                },
                sin_zero: [0; 8],
            };
            let sent = unsafe {
                let mut msg: libc::msghdr = mem::zeroed();
                msg.msg_name = &raw_dest as *const libc::sockaddr_in as *mut libc::c_void;
                msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
                msg.msg_iovlen = 2;
                libc::sendmsg(self.socket.as_raw_fd(), &msg, 0)
            };
            if sent < 0 {
                let errors = self.send_errors.fetch_add(1, Ordering::Relaxed) + 1;
                // Log the first failure and every thousandth after it.
                if errors == 1 || errors.is_multiple_of(1000) {
                    eprintln!(
                        "[TPROXY] raw UDP reply send failed ({errors} total): {}",
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }

    fn verify_raw_reply_socket() -> Result<()> {
        drop(RawReplySocket::new()?);
        Ok(())
    }

    fn calc_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..header.len()).step_by(2) {
            let word = u16::from_be_bytes([header[i], header[i + 1]]);
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }

    struct Association {
        relay: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        _control: TcpStream,
    }

    type AssociationResult = std::result::Result<Association, String>;

    async fn create_association(config: &LocalProxyProfile) -> Result<Association> {
        let associate = tokio::time::timeout(
            super::SOCKS_HANDSHAKE_TIMEOUT,
            socks_command(config, 0x03, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        )
        .await
        .context("SOCKS5 UDP ASSOCIATE timed out")?;
        let (control_stream, relay_addr) =
            associate.context("SOCKS5 UDP ASSOCIATE command failed")?;
        let control_socket = socket2::SockRef::from(&control_stream);
        let _ = control_socket.set_recv_buffer_size(UDP_ASSOCIATION_CONTROL_BUFFER);
        let _ = control_socket.set_send_buffer_size(UDP_ASSOCIATION_CONTROL_BUFFER);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("open SOCKS5 UDP relay socket")?;
        socket
            .set_reuse_address(true)
            .context("enable SO_REUSEADDR on SOCKS5 UDP relay socket")?;
        let _ = socket.set_recv_buffer_size(UDP_RELAY_SOCKET_BUFFER);
        let _ = socket.set_send_buffer_size(UDP_RELAY_SOCKET_BUFFER);
        socket
            .set_nonblocking(true)
            .context("set SOCKS5 UDP relay socket nonblocking")?;
        socket
            .bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                0,
            ))))
            .context("bind SOCKS5 UDP relay socket")?;
        let std_socket: std::net::UdpSocket = socket.into();
        let relay = UdpSocket::from_std(std_socket)
            .context("register SOCKS5 UDP relay socket with Tokio")?;
        Ok(Association {
            relay: Arc::new(relay),
            relay_addr,
            _control: control_stream,
        })
    }

    fn spawn_refill(
        tasks: &mut JoinSet<()>,
        config: Arc<LocalProxyProfile>,
        tx: tokio::sync::mpsc::Sender<AssociationResult>,
        delay: Option<Duration>,
        cancel: CancellationToken,
    ) {
        tasks.spawn(async move {
            if let Some(delay) = delay {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            let association = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                result = create_association(&config) => {
                    result.map_err(|error| format!("{error:#}"))
                },
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                result = tx.send(association) => { let _ = result; }
            }
        });
    }

    fn send_frame(flow: &UdpFlow, destination: SocketAddrV4, payload: &[u8]) {
        // Zero-allocation SOCKS5 UDP send using stack buffer or sendmsg
        // SOCKS5 UDP IPv4 header: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + PORT(2) = 10 bytes
        let mut header = [0u8; 10];
        header[0] = 0x00; // RSV
        header[1] = 0x00; // RSV
        header[2] = 0x00; // FRAG
        header[3] = 0x01; // ATYP IPv4
        header[4..8].copy_from_slice(&destination.ip().octets());
        header[8..10].copy_from_slice(&destination.port().to_be_bytes());

        let raw_dest = match flow.relay_addr {
            SocketAddr::V4(v4) => libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            },
            SocketAddr::V6(_) => return,
        };

        let iov = [
            libc::iovec {
                iov_base: header.as_ptr() as *mut libc::c_void,
                iov_len: 10,
            },
            libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            },
        ];
        unsafe {
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_name = &raw_dest as *const libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
            msg.msg_iovlen = 2;
            libc::sendmsg(flow.relay.as_raw_fd(), &msg, 0);
        }
    }

    struct OpeningDatagram {
        destination: SocketAddrV4,
        buffer: super::OpeningBufferLease,
    }

    impl OpeningDatagram {
        fn payload(&self) -> &[u8] {
            self.buffer.as_slice()
        }
    }

    #[derive(Default)]
    struct OpeningQueue {
        pending: Vec<OpeningDatagram>,
        bytes: usize,
    }

    impl OpeningQueue {
        fn push(
            &mut self,
            destination: SocketAddrV4,
            payload: &[u8],
            buffers: &Arc<super::OpeningBufferPool>,
        ) -> bool {
            if self.pending.len() >= OPENING_PENDING_LIMIT
                || self.bytes + payload.len() > OPENING_PENDING_BYTES
            {
                return false;
            }
            let Some(mut buffer) = buffers.acquire(payload.len()) else {
                return false;
            };
            buffer.as_mut_slice()[..payload.len()].copy_from_slice(payload);
            self.bytes += payload.len();
            self.pending.push(OpeningDatagram {
                destination,
                buffer,
            });
            true
        }

        fn take(&mut self) -> Vec<OpeningDatagram> {
            self.bytes = 0;
            std::mem::take(&mut self.pending)
        }
    }

    fn evict_oldest_udp_flow(
        flows: &mut HashMap<SocketAddr, UdpFlow>,
        stats: &super::TproxyStats,
    ) -> bool {
        let oldest = flows
            .iter()
            .min_by_key(|(_, flow)| flow.last_seen.load(Ordering::Relaxed))
            .map(|(key, _)| *key);
        let Some(key) = oldest else {
            return false;
        };
        let Some(flow) = flows.remove(&key) else {
            return false;
        };
        flow.cancel.cancel();
        drop(flow);
        stats.udp_finished();
        true
    }

    struct UdpFlow {
        relay: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        _control: TcpStream,
        last_seen: Arc<AtomicI64>,
        finished: Arc<AtomicBool>,
        cancel: CancellationToken,
        _quota: super::UdpQuotaLease,
    }

    struct UdpResponseContext {
        last_seen: Arc<AtomicI64>,
        finished: Arc<AtomicBool>,
        cancel: CancellationToken,
        raw_socket: Arc<RawReplySocket>,
        quota: Arc<super::DeviceQuota>,
        quotas: Arc<super::DeviceQuotaRegistry>,
        buffers: Arc<super::ProxyBufferPool>,
    }

    #[derive(Clone)]
    struct UdpRuntime {
        raw_socket: Arc<RawReplySocket>,
        quotas: Arc<super::DeviceQuotaRegistry>,
        buffers: Arc<super::ProxyBufferPool>,
    }

    impl UdpFlow {
        fn start(
            client: SocketAddrV4,
            association: Association,
            stats: &Arc<super::TproxyStats>,
            quota: super::UdpQuotaLease,
            runtime: UdpRuntime,
            response_tasks: &mut JoinSet<()>,
        ) -> Self {
            let last_seen = Arc::new(AtomicI64::new(now_ms()));
            let finished = Arc::new(AtomicBool::new(false));
            let cancel = quota.cancel();
            response_tasks.spawn(relay_responses(
                association.relay.clone(),
                client,
                UdpResponseContext {
                    last_seen: last_seen.clone(),
                    finished: finished.clone(),
                    cancel: cancel.clone(),
                    raw_socket: runtime.raw_socket,
                    quota: quota.quota(),
                    quotas: runtime.quotas,
                    buffers: runtime.buffers,
                },
            ));
            stats.udp_started();
            Self {
                relay: association.relay,
                relay_addr: association.relay_addr,
                _control: association._control,
                last_seen,
                finished,
                cancel,
                _quota: quota,
            }
        }

        fn touch(&self) {
            self.last_seen.store(now_ms(), Ordering::Relaxed);
        }

        fn idle(&self) -> bool {
            now_ms().saturating_sub(self.last_seen.load(Ordering::Relaxed))
                > super::UDP_FLOW_IDLE.as_millis() as i64
        }
    }

    fn acquire_udp_quota(
        quotas: &Arc<super::DeviceQuotaRegistry>,
        client_ip: Ipv4Addr,
        flows: &mut HashMap<SocketAddr, UdpFlow>,
        stats: &Arc<super::TproxyStats>,
    ) -> Option<super::UdpQuotaLease> {
        loop {
            match quotas.try_acquire_udp(client_ip) {
                Ok(quota) => {
                    stats.set_limits(quotas.limits());
                    return Some(quota);
                }
                Err(super::AdmissionError::Inactive | super::AdmissionError::DeviceLimit) => {
                    return None;
                }
                Err(super::AdmissionError::GlobalLimit) => {}
            }
            if quotas.try_expand_capacity() {
                stats.set_limits(quotas.limits());
                continue;
            }
            if !evict_oldest_udp_flow(flows, stats) {
                return None;
            }
        }
    }

    fn now_ms() -> i64 {
        // Monotonic process clock: wall-clock jumps (NTP) would freeze or mass-expire flows.
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as i64
    }

    async fn run_udp(
        socket: Arc<UdpTproxy>,
        config: Arc<LocalProxyProfile>,
        cancel: CancellationToken,
        log: LogFn,
        stats: Arc<super::TproxyStats>,
        quotas: Arc<super::DeviceQuotaRegistry>,
        buffers: Arc<super::ProxyBufferPool>,
    ) -> (u64, u64) {
        let raw_socket = match RawReplySocket::new() {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log("ERROR", &format!("Failed to bind TPROXY raw socket: {e}"));
                return (0, 0);
            }
        };
        let runtime = UdpRuntime {
            raw_socket,
            quotas: quotas.clone(),
            buffers: buffers.clone(),
        };
        let async_fd = match AsyncFd::new(socket.clone()) {
            Ok(fd) => fd,
            Err(error) => {
                log(
                    "ERROR",
                    &format!("TPROXY UDP socket is not pollable: {error}"),
                );
                return (0, 0);
            }
        };
        let mut flows: HashMap<SocketAddr, UdpFlow> = HashMap::new();
        let mut opening: HashMap<SocketAddr, OpeningQueue> = HashMap::new();
        let opening_buffers = super::OpeningBufferPool::new();
        stats.bind_opening_buffers(&opening_buffers);
        let mut pool: VecDeque<Association> = VecDeque::new();
        let (pool_tx, mut pool_rx) =
            tokio::sync::mpsc::channel::<AssociationResult>(ASSOCIATION_POOL_TARGET * 2);
        let (open_tx, mut open_rx) =
            tokio::sync::mpsc::channel::<(SocketAddr, AssociationResult)>(256);
        let mut response_tasks: JoinSet<()> = JoinSet::new();
        let mut refill_tasks: JoinSet<()> = JoinSet::new();
        let mut opening_tasks: JoinSet<()> = JoinSet::new();
        let mut refills_in_flight = 0usize;
        for _ in 0..ASSOCIATION_POOL_TARGET {
            spawn_refill(
                &mut refill_tasks,
                config.clone(),
                pool_tx.clone(),
                None,
                cancel.clone(),
            );
            refills_in_flight += 1;
        }
        let mut sweep = tokio::time::interval(Duration::from_secs(15));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut buf: Vec<mem::MaybeUninit<u8>> = vec![mem::MaybeUninit::uninit(); UDP_RECV_BUF];
        let mut control: Vec<mem::MaybeUninit<u8>> =
            vec![mem::MaybeUninit::uninit(); UDP_CONTROL_BUF];
        let mut association_failure = None::<(Instant, String)>;
        let mut served: u64 = 0;
        let mut datagrams: u64 = 0;
        let mut recv_errors_logged = false;
        let mut recv_error_backoff_ms = 0u64;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = response_tasks.join_next(), if !response_tasks.is_empty() => {
                    flows.retain(|_, flow| {
                        if flow.cancel.is_cancelled()
                            || flow.idle()
                            || flow.finished.load(Ordering::Relaxed)
                        {
                            flow.cancel.cancel();
                            stats.udp_finished();
                            false
                        } else {
                            true
                        }
                    });
                    if flows.len().saturating_mul(4) < flows.capacity() {
                        flows.shrink_to(16);
                    }
                    if response_tasks.is_empty() {
                        response_tasks = JoinSet::new();
                    }
                }
                _ = refill_tasks.join_next(), if !refill_tasks.is_empty() => {
                    if refill_tasks.is_empty() {
                        refill_tasks = JoinSet::new();
                    }
                }
                _ = opening_tasks.join_next(), if !opening_tasks.is_empty() => {
                    if opening_tasks.is_empty() {
                        opening_tasks = JoinSet::new();
                    }
                }
                _ = sweep.tick() => {
                    flows.retain(|_, flow| {
                        if flow.cancel.is_cancelled()
                            || flow.idle()
                            || flow.finished.load(Ordering::Relaxed)
                        {
                            flow.cancel.cancel();
                            stats.udp_finished();
                            false
                        } else {
                            true
                        }
                    });
                    if flows.len().saturating_mul(4) < flows.capacity() {
                        flows.shrink_to(16);
                    }
                    if opening.len().saturating_mul(4) < opening.capacity() {
                        opening.shrink_to(16);
                    }
                }
                received_pool = pool_rx.recv() => {
                    let Some(received) = received_pool else { break };
                    refills_in_flight = refills_in_flight.saturating_sub(1);
                    let failed = received.is_err();
                    if let Ok(association) = received
                        && pool.len() < ASSOCIATION_POOL_TARGET
                    {
                        pool.push_back(association);
                    }
                    while pool.len() + refills_in_flight < ASSOCIATION_POOL_TARGET {
                        spawn_refill(
                            &mut refill_tasks,
                            config.clone(),
                            pool_tx.clone(),
                            if failed { Some(ASSOCIATION_BACKOFF) } else { None },
                            cancel.clone(),
                        );
                        refills_in_flight += 1;
                    }
                }
                opened = open_rx.recv() => {
                    let Some((key, association)) = opened else { break };
                    let pending = match opening.remove(&key) {
                        Some(mut queue) => queue.take(),
                        None => Vec::new(),
                    };
                    let SocketAddr::V4(client) = key else { continue };
                    match association {
                        Ok(association) => {
                            association_failure = None;
                            let Some(quota) = acquire_udp_quota(
                                &quotas,
                                *client.ip(),
                                &mut flows,
                                &stats,
                            ) else {
                                stats.udp_budget_rejected();
                                continue;
                            };
                            let flow = UdpFlow::start(
                                client,
                                association,
                                &stats,
                                quota,
                                runtime.clone(),
                                &mut response_tasks,
                            );
                            served += 1;
                            for datagram in pending {
                                send_frame(&flow, datagram.destination, datagram.payload());
                            }
                            flows.insert(key, flow);
                        }
                        Err(error) => {
                            let should_log = match association_failure.as_ref() {
                                Some((_at, previous)) => previous != &error,
                                None => true,
                            };
                            if should_log {
                                log(
                                    "WARNING",
                                    &format!(
                                        "SOCKS5 UDP association failed for {client}: {error}; datagrams are dropped until the proxy recovers"
                                    ),
                                );
                            }
                            association_failure = Some((Instant::now(), error));
                        }
                    }
                }
                ready = async_fd.readable() => {
                    let Ok(mut guard) = ready else { break };
                    loop {
                        match socket.try_recv(&mut buf, &mut control) {
                            Ok((received, client, destination)) => {
                                if !allowed_client(client) {
                                    continue;
                                }
                                quotas.activate_tunnel_ip(*client.ip());
                                recv_error_backoff_ms = 0;
                                datagrams += 1;
                                let payload = unsafe {
                                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, received)
                                };
                                let key = SocketAddr::V4(client);
                                let existing_ok = flows
                                    .get(&key)
                                    .map(|flow| !flow.finished.load(Ordering::Relaxed))
                                    .unwrap_or(false);
                                if existing_ok {
                                    let flow = &flows[&key];
                                    flow.touch();
                                    send_frame(flow, destination, payload);
                                    continue;
                                }
                                if let Some(stale) = flows.remove(&key) {
                                    stale.cancel.cancel();
                                    stats.udp_finished();
                                }
                                if let Some(queue) = opening.get_mut(&key) {
                                    queue.push(destination, payload, &opening_buffers);
                                    continue;
                                }
                                if let Some((at, _error)) = &association_failure {
                                    if at.elapsed() < ASSOCIATION_BACKOFF {
                                        continue;
                                    }
                                    association_failure = None;
                                }
                                if opening.len() >= MAX_CONCURRENT_OPENINGS {
                                    continue;
                                }
                                if let Some(association) = pool.pop_front() {
                                    let Some(quota) = acquire_udp_quota(
                                        &quotas,
                                        *client.ip(),
                                        &mut flows,
                                        &stats,
                                    ) else {
                                        stats.udp_budget_rejected();
                                        continue;
                                    };
                                    let flow = UdpFlow::start(
                                        client,
                                        association,
                                        &stats,
                                        quota,
                                        runtime.clone(),
                                        &mut response_tasks,
                                    );
                                    served += 1;
                                    send_frame(&flow, destination, payload);
                                    flows.insert(key, flow);
                                } else {
                                    let task_tx = open_tx.clone();
                                    let task_config = config.clone();
                                    let task_cancel = cancel.clone();
                                    opening_tasks.spawn(async move {
                                        let association = tokio::select! {
                                            biased;
                                            _ = task_cancel.cancelled() => return,
                                            result = create_association(&task_config) => {
                                                result.map_err(|error| format!("{error:#}"))
                                            },
                                        };
                                        tokio::select! {
                                            biased;
                                            _ = task_cancel.cancelled() => {}
                                            result = task_tx.send((key, association)) => { let _ = result; }
                                        }
                                    });
                                    let mut queue = OpeningQueue::default();
                                    queue.push(destination, payload, &opening_buffers);
                                    opening.insert(key, queue);
                                }
                                while pool.len() + refills_in_flight < ASSOCIATION_POOL_TARGET {
                                    spawn_refill(
                                        &mut refill_tasks,
                                        config.clone(),
                                        pool_tx.clone(),
                                        None,
                                        cancel.clone(),
                                    );
                                    refills_in_flight += 1;
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                guard.clear_ready();
                                break;
                            }
                            Err(error) => {
                                if !recv_errors_logged {
                                    recv_errors_logged = true;
                                    log(
                                        "WARNING",
                                        &format!("TPROXY UDP receive error: {error}"),
                                    );
                                }
                                // Exponential 1ms..50ms backoff instead of a fixed
                                // stall inside the shared select loop.
                                recv_error_backoff_ms =
                                    (recv_error_backoff_ms.max(1) * 2).min(50);
                                guard.clear_ready();
                                tokio::time::sleep(Duration::from_millis(recv_error_backoff_ms))
                                    .await;
                                break;
                            }
                        }
                    }
                }
            }
        }
        for (_, flow) in flows.drain() {
            flow.cancel.cancel();
            stats.udp_finished();
        }
        opening.clear();
        response_tasks.abort_all();
        while response_tasks.join_next().await.is_some() {}
        refill_tasks.abort_all();
        while refill_tasks.join_next().await.is_some() {}
        opening_tasks.abort_all();
        while opening_tasks.join_next().await.is_some() {}
        (served, datagrams)
    }

    async fn relay_responses(
        relay: Arc<UdpSocket>,
        client: SocketAddrV4,
        context: UdpResponseContext,
    ) {
        let UdpResponseContext {
            last_seen,
            finished,
            cancel,
            raw_socket,
            quota,
            quotas,
            buffers,
        } = context;
        loop {
            let received = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = tokio::time::timeout(super::UDP_FLOW_IDLE, relay.readable()) => result,
            };
            match received {
                Ok(Ok(())) => loop {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let jumbo = next_udp_datagram_len(relay.as_raw_fd())
                        .map(|length| length > 4 * 1024)
                        .unwrap_or(true);
                    let Some(mut buffer) = buffers.acquire_udp(&quotas, quota.clone(), jumbo)
                    else {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        break;
                    };
                    match relay.try_recv_from(buffer.as_mut_slice()) {
                        Ok((length, _source)) => {
                            last_seen.store(now_ms(), Ordering::Relaxed);
                            if let Ok((source, payload)) =
                                socks_udp_response(&buffer.as_mut_slice()[..length])
                                && let SocketAddr::V4(v4) = source
                            {
                                raw_socket.send_reply(
                                    *v4.ip(),
                                    *client.ip(),
                                    v4.port(),
                                    client.port(),
                                    payload,
                                );
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                },
                _ => break,
            }
        }
        finished.store(true, Ordering::Relaxed);
    }

    fn next_udp_datagram_len(fd: RawFd) -> Option<usize> {
        let mut length = 0i32;
        let result = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut length) };
        (result == 0 && length > 0).then_some(length as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceQuotaRegistry, TproxyStats, tproxy_port};

    #[cfg(target_os = "linux")]
    #[test]
    fn default_proxy_limits_keep_relay_memory_bounded() {
        assert_eq!(super::GLOBAL_TCP_SESSION_LIMIT, 384);
        assert_eq!(super::GLOBAL_UDP_FLOW_LIMIT, 784);
        assert_eq!(super::UDP_FLOW_IDLE, std::time::Duration::from_secs(60));
    }

    #[test]
    fn adaptive_device_limit_keeps_burst_and_fair_share() {
        assert_eq!(super::adaptive_device_limit(384, 160, 20, 1), 160);
        assert_eq!(super::adaptive_device_limit(384, 160, 20, 2), 160);
        assert_eq!(super::adaptive_device_limit(384, 160, 20, 6), 64);
        assert_eq!(super::adaptive_device_limit(384, 160, 20, 20), 20);
        assert_eq!(super::adaptive_device_limit(784, 320, 40, 1), 320);
        assert_eq!(super::adaptive_device_limit(784, 320, 40, 2), 320);
        assert_eq!(super::adaptive_device_limit(784, 320, 40, 6), 130);
        assert_eq!(super::adaptive_device_limit(784, 320, 40, 20), 40);
    }

    #[test]
    fn proxy_capacity_expands_only_at_pressure_boundaries() {
        assert_eq!(
            super::ProxyCapacity::next_limits((384, 784), None),
            (1_512, 2_048)
        );
        assert_eq!(
            super::ProxyCapacity::next_limits((1_512, 2_048), None),
            (1_512, 2_048)
        );
        assert_eq!(
            super::ProxyCapacity::next_limits((1_512, 2_048), Some(512 * 1024 * 1024)),
            (1_784, 2_384)
        );
        assert_eq!(
            super::ProxyCapacity::next_limits((1_512, 2_048), Some(1_200 * 1024 * 1024)),
            (2_384, 4_096)
        );
    }

    #[test]
    fn ports_are_unique_per_runtime_and_in_range() {
        let first = tproxy_port(1);
        let second = tproxy_port(2);
        assert_ne!(first, second);
        assert!(first >= 10666);
        assert_eq!(tproxy_port(1), first);
    }

    #[test]
    fn runtime_stats_track_active_peak_and_total() {
        let stats = TproxyStats::default();
        stats.tcp_started();
        stats.tcp_started();
        stats.tcp_finished();
        stats.udp_started();
        stats.udp_finished();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_active, 1);
        assert_eq!(snapshot.tcp_peak, 2);
        assert_eq!(snapshot.tcp_total, 2);
        assert_eq!(snapshot.udp_active, 0);
        assert_eq!(snapshot.udp_peak, 1);
        assert_eq!(snapshot.udp_total, 1);
    }

    #[test]
    fn proxy_buffers_are_released_when_unused() {
        let pool = super::ProxyBufferPool::new();
        let mut tcp = Vec::new();
        for _ in 0..=super::PROXY_TCP_RETAINED_LIMIT {
            tcp.push(pool.acquire_tcp().expect("TCP pool has capacity"));
        }
        drop(tcp);
        assert_eq!(pool.tcp.snapshot(), (0, 0));
    }

    #[test]
    fn opening_packets_have_a_fixed_global_ceiling() {
        let pool = super::OpeningBufferPool::new();
        let opening = pool
            .acquire(super::PROXY_OPENING_BUFFER_LIMIT)
            .expect("opening pool has capacity");
        assert!(pool.acquire(1).is_none());
        drop(opening);
        assert_eq!(pool.allocated_bytes(), 0);
        assert!(pool.acquire(super::PROXY_OPENING_BUFFER_LIMIT).is_some());
    }

    #[test]
    fn tunnel_ip_quota_is_available_after_activation() {
        let registry = DeviceQuotaRegistry::new();
        let ip = std::net::Ipv4Addr::new(10, 66, 67, 2);
        registry.activate_tunnel_ip(ip);
        let lease = registry
            .try_acquire_tcp(ip)
            .expect("tunnel client gets a TCP quota");
        drop(lease);
        assert!(registry.quota_for_ip(ip).is_some());
    }

    #[test]
    fn udp_flow_keys_do_not_collide_between_clients() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let client_a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 66, 67, 1), 5353));
        let client_b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 66, 67, 2), 5353));
        let mut flows = std::collections::HashMap::new();
        flows.insert(client_a, 1u8);
        flows.insert(client_b, 2u8);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows.get(&client_a).copied(), Some(1));
        assert_eq!(flows.get(&client_b).copied(), Some(2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_expiry_respects_idle_and_hard_limits() {
        use super::linux::session_expired;
        let start = 1_000_000i64;
        assert!(!session_expired(start + 1, start, start + 600_001));
        assert!(session_expired(start + 1, start, start + 600_002));
        assert!(session_expired(start + 7_200_001, start, start + 7_200_001));
        assert!(!session_expired(start, start, start));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_original_destination_from_control_message() {
        use std::mem;
        use std::net::Ipv4Addr;
        use std::ptr;
        let mut control = vec![0u8; 64];
        unsafe {
            let header = control.as_mut_ptr() as *mut libc::cmsghdr;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in>() as u32) as _;
            (*header).cmsg_level = libc::IPPROTO_IP;
            (*header).cmsg_type = super::linux::IP_RECVORIGDSTADDR;
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 443u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([93, 184, 216, 34]),
                },
                sin_zero: [0; 8],
            };
            ptr::copy_nonoverlapping(
                &sockaddr as *const libc::sockaddr_in as *const u8,
                libc::CMSG_DATA(header),
                mem::size_of::<libc::sockaddr_in>(),
            );
        }
        let parsed = match super::linux::parse_orig_dst(&control) {
            Some(parsed) => parsed,
            None => panic!("control message should contain the original destination"),
        };
        assert_eq!(*parsed.ip(), Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(parsed.port(), 443);
    }
}
