// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    auth::TurnCredentials,
    client_perf::{self, Stage as PerfStage},
    dispatcher::{Dispatcher, PacketReceiver, WorkerChannels, packet_channel},
    events::Events,
    obfs::{ObfsCipher, ObfsConfig, ObfsMode, ObfsState, is_rtp_packet},
    packet::{PacketBuf, PacketPool},
    protocol::{
        ConfigResponse, config_request, disconnect_request, is_config_response,
        is_control_response, is_panel_restart_notice, parse_config_response, parse_stream_alive,
        parse_stream_repair,
    },
    repair::RepairState,
    selective_fec,
    stats::Stats,
    striped_scheduler::PacketClass,
    turn::{TurnAllocation, TurnConnectTarget, TurnReceiver, TurnRequestError},
    turn_endpoint::{TurnTransportMode, resolve_turn_endpoints},
};
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
#[cfg(test)]
use std::time::Instant;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const CONFIG_RESPONSE_TIMEOUT_MS: [u64; 3] = [750, 1_500, 3_000];
const DEALLOCATE_TIMEOUT: Duration = Duration::from_millis(700);
const CONNECT_CANCEL_GRACE: Duration = Duration::from_secs(1);
const SESSION_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const DISCONNECT_SEND_TIMEOUT: Duration = Duration::from_millis(300);
const DISCONNECT_ACK_TIMEOUT: Duration = Duration::from_millis(350);
const DISCONNECT_CONTROL_ATTEMPTS: usize = 2;
const WORKER_LATENCY_CAPACITY: usize = crate::striped_scheduler::SMALL_DATAGRAM_BATCH;
const WORKER_PRIORITY_CAPACITY: usize = crate::striped_scheduler::MEDIUM_DATAGRAM_BATCH;
const WORKER_BULK_CAPACITY: usize = crate::striped_scheduler::BULK_DATAGRAM_BATCH;
const WRITER_COMMAND_CAPACITY: usize = 16;
const WRITER_LATENCY_BATCH_LIMIT: usize = crate::striped_scheduler::SMALL_DATAGRAM_BATCH;
const WRITER_PRIORITY_BATCH_LIMIT: usize = crate::striped_scheduler::MEDIUM_DATAGRAM_BATCH;
const WRITER_BULK_BATCH_LIMIT: usize = crate::striped_scheduler::BULK_DATAGRAM_BATCH;
static NEXT_INCARNATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct TurnAllocateError(anyhow::Error);

impl TurnAllocateError {
    pub fn stun_code(&self) -> Option<i32> {
        self.0.chain().find_map(|cause| {
            cause
                .downcast_ref::<TurnRequestError>()
                .map(TurnRequestError::stun_code)
        })
    }
}

impl std::fmt::Display for TurnAllocateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "TURN Allocate: {:#}", self.0)
    }
}

impl std::error::Error for TurnAllocateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub struct SessionConfig {
    pub id: usize,
    pub peer: SocketAddr,
    pub turn_host: Option<Arc<str>>,
    pub turn_port: Option<Arc<str>>,
    pub turn_transport: TurnTransportMode,
    pub local_port: Arc<str>,
    pub device_id: Arc<str>,
    pub password: Arc<str>,
    pub generation: u64,
    pub turn_endpoint_cursor: usize,
    pub salt: Arc<str>,
    pub mode: ObfsMode,
    pub wrap_key: [u8; 32],
    pub get_config: bool,
    pub desired_count: usize,
    pub server_stream_repair: Arc<AtomicBool>,
    pub repair: Arc<RepairState>,
}

pub struct SessionRuntime {
    pub dispatcher: Arc<Dispatcher>,
    pub pool: Arc<PacketPool>,
    pub stats: Arc<Stats>,
    pub events: Events,
    pub config_tx: mpsc::Sender<String>,
    pub config_delivery: Option<ConfigDeliveryState>,
    pub cancel: CancellationToken,
    pub shutdown: Arc<ShutdownCoordinator>,
    pub ready_tx: Option<oneshot::Sender<()>>,
    pub allocation_started: Option<oneshot::Sender<()>>,
    pub allocation_ready: Option<oneshot::Sender<()>>,
}

fn build_registration_payload(config: &SessionConfig) -> Bytes {
    Bytes::from(config_request(
        &config.local_port,
        &config.device_id,
        &config.password,
        config.generation,
        &config.salt,
        config.id,
        Some(config.desired_count),
    ))
}

pub struct ConfigDeliveryState {
    pub sent: Arc<AtomicBool>,
    pub in_flight: Arc<AtomicBool>,
}

impl ConfigDeliveryState {
    fn complete(&self, delivered: bool) {
        if delivered {
            self.sent.store(true, Ordering::Release);
        }
        self.in_flight.store(false, Ordering::Release);
    }
}

struct TransportShared {
    allocation: Arc<TurnAllocation>,
    cipher: ObfsCipher,
    config: ObfsConfig,
    pool: Arc<PacketPool>,
}

struct TransportWriter {
    shared: Arc<TransportShared>,
    write_state: ObfsState,
    fec_budget: selective_fec::Budget,
    pending_data: VecDeque<PacketBuf>,
    mmsg_data: Vec<PacketBuf>,
}

struct TransportReader {
    shared: Arc<TransportShared>,
    receiver: TurnReceiver,
    replay: ReplayProtection,
}

enum WriterCommand {
    SendBytes {
        data: Bytes,
        completion: oneshot::Sender<Result<()>>,
    },
}

struct WriterRuntime {
    latency: PacketReceiver,
    priority: PacketReceiver,
    bulk: PacketReceiver,
    commands: mpsc::Receiver<WriterCommand>,
    shutdown: Arc<ShutdownCoordinator>,
    activity: Arc<AtomicU64>,
}

struct WriterPacket {
    packet: PacketBuf,
    class: PacketClass,
}

struct ReaderRuntime {
    dispatcher: Arc<Dispatcher>,
    events: Events,
    repair: Arc<RepairState>,
    shutdown: Arc<ShutdownCoordinator>,
    config_tx: mpsc::Sender<String>,
}

pub struct ShutdownCoordinator {
    state: Mutex<ShutdownState>,
    changed: tokio::sync::Notify,
    next_activity: AtomicU64,
}

struct ShutdownState {
    active: bool,
    completed: bool,
    streams: Vec<ShutdownControlStream>,
}

struct ShutdownControlStream {
    incarnation_id: u64,
    writer: mpsc::Sender<WriterCommand>,
    activity: Arc<AtomicU64>,
}

struct ShutdownRegistration {
    coordinator: Arc<ShutdownCoordinator>,
    incarnation_id: u64,
    activity: Arc<AtomicU64>,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ShutdownState {
                active: false,
                completed: false,
                streams: Vec::new(),
            }),
            changed: tokio::sync::Notify::new(),
            next_activity: AtomicU64::new(1),
        }
    }

    fn register(
        self: &Arc<Self>,
        incarnation_id: u64,
        writer: mpsc::Sender<WriterCommand>,
    ) -> ShutdownRegistration {
        let activity = Arc::new(AtomicU64::new(self.next_activity()));
        let mut state = self.lock_state();
        if !state.active {
            state.streams.push(ShutdownControlStream {
                incarnation_id,
                writer,
                activity: activity.clone(),
            });
        }
        ShutdownRegistration {
            coordinator: self.clone(),
            incarnation_id,
            activity,
        }
    }

    fn mark_activity(&self, activity: &AtomicU64) {
        activity.store(self.next_activity(), Ordering::Release);
    }

    async fn request_disconnect(&self, device_id: &str, salt: &str) {
        let leader = {
            let mut state = self.lock_state();
            if state.active {
                false
            } else {
                state.active = true;
                state.completed = false;
                true
            }
        };
        if !leader {
            self.wait_until_completed(Duration::from_secs(2)).await;
            return;
        }

        let request = disconnect_request(device_id, salt);
        for writer in self
            .control_streams()
            .into_iter()
            .take(DISCONNECT_CONTROL_ATTEMPTS)
        {
            if self.is_completed() {
                break;
            }
            let delivered = tokio::time::timeout(
                DISCONNECT_SEND_TIMEOUT,
                send_writer_bytes(&writer, request.as_bytes()),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            if delivered && self.wait_until_completed(DISCONNECT_ACK_TIMEOUT).await {
                break;
            }
        }
        self.complete();
    }

    fn observe_control_response(&self, response: &[u8]) -> bool {
        if response != b"OK:disconnected" && !response.starts_with(b"DENIED:") {
            return false;
        }
        let mut state = self.lock_state();
        if !state.active || state.completed {
            return false;
        }
        state.completed = true;
        drop(state);
        self.changed.notify_waiters();
        true
    }

    fn control_streams(&self) -> Vec<mpsc::Sender<WriterCommand>> {
        let state = self.lock_state();
        let mut streams: Vec<_> = state
            .streams
            .iter()
            .map(|stream| {
                (
                    stream.activity.load(Ordering::Acquire),
                    stream.incarnation_id,
                    stream.writer.clone(),
                )
            })
            .collect();
        streams.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1))
        });
        streams.into_iter().map(|(_, _, writer)| writer).collect()
    }

    fn complete(&self) {
        let mut state = self.lock_state();
        if state.completed {
            return;
        }
        state.completed = true;
        drop(state);
        self.changed.notify_waiters();
    }

    fn is_completed(&self) -> bool {
        self.lock_state().completed
    }

    async fn wait_until_completed(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.changed.notified();
            if self.is_completed() {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.is_completed();
            }
        }
    }

    fn unregister(&self, incarnation_id: u64) {
        let mut state = self.lock_state();
        state
            .streams
            .retain(|stream| stream.incarnation_id != incarnation_id);
    }

    fn next_activity(&self) -> u64 {
        self.next_activity.fetch_add(1, Ordering::Relaxed).max(1)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ShutdownState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for ShutdownRegistration {
    fn drop(&mut self) {
        self.coordinator.unregister(self.incarnation_id);
    }
}

struct ReplayWindow {
    highest: Option<u64>,
    seen: Box<[u64; 256]>,
}

#[derive(Default)]
struct ReplayProtection {
    rtp: ReplayWindow,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: Box::new([0; 256]),
        }
    }
}

impl ReplayWindow {
    fn accept(&mut self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.set_bit(counter);
            return true;
        };
        if counter > highest {
            let shift = counter - highest;
            if shift >= 16384 {
                self.seen.fill(0);
            } else {
                for i in 1..=shift {
                    self.clear_bit(highest + i);
                }
            }
            self.highest = Some(counter);
            self.set_bit(counter);
            return true;
        }
        let age = highest - counter;
        if age >= 16384 {
            return false;
        }
        if self.test_bit(counter) {
            return false;
        }
        self.set_bit(counter);
        true
    }

    fn set_bit(&mut self, counter: u64) {
        let idx = (counter % 16384) as usize;
        self.seen[idx / 64] |= 1 << (idx % 64);
    }

    fn clear_bit(&mut self, counter: u64) {
        let idx = (counter % 16384) as usize;
        self.seen[idx / 64] &= !(1 << (idx % 64));
    }

    fn test_bit(&self, counter: u64) -> bool {
        let idx = (counter % 16384) as usize;
        (self.seen[idx / 64] & (1 << (idx % 64))) != 0
    }

    fn accept_rtp(&mut self, sequence: u16) -> bool {
        let Some(highest) = self.highest else {
            return self.accept(sequence as u64);
        };
        let base = highest & !(u16::MAX as u64);
        let mut extended = base | sequence as u64;
        if extended.saturating_add(1 << 15) < highest {
            extended = extended.saturating_add(1 << 16);
        } else if extended > highest.saturating_add(1 << 15) && extended >= 1 << 16 {
            extended -= 1 << 16;
        }
        self.accept(extended)
    }
}

fn authenticate_inbound(
    cipher: &ObfsCipher,
    config: &ObfsConfig,
    replay: &mut ReplayProtection,
    packet: &mut PacketBuf,
) -> bool {
    is_rtp_packet(packet.as_slice())
        && cipher
            .unwrap(packet, config.mode)
            .is_ok_and(|sequence| replay.rtp.accept_rtp(sequence))
}

struct ActiveConnection {
    stats: Arc<Stats>,
    events: Events,
}

struct WorkerRegistration {
    dispatcher: Arc<Dispatcher>,
    id: usize,
    incarnation_id: u64,
}

impl WorkerRegistration {
    fn new(dispatcher: Arc<Dispatcher>, id: usize, incarnation_id: u64) -> Self {
        Self {
            dispatcher,
            id,
            incarnation_id,
        }
    }
}

impl Drop for WorkerRegistration {
    fn drop(&mut self) {
        self.dispatcher.unregister(self.id, self.incarnation_id);
    }
}

impl ActiveConnection {
    fn new(stats: Arc<Stats>, events: Events) -> Self {
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { stats, events }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        if self.stats.active_connections.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.events.active_zero();
        }
    }
}

impl TransportWriter {
    fn new(shared: Arc<TransportShared>) -> Self {
        Self {
            shared,
            write_state: ObfsState::new(),
            fec_budget: selective_fec::Budget::new(),
            pending_data: VecDeque::with_capacity(WRITER_BULK_BATCH_LIMIT),
            mmsg_data: Vec::with_capacity(WRITER_BULK_BATCH_LIMIT),
        }
    }

    async fn send_data(&mut self, packet: PacketBuf) -> Result<()> {
        self.send_packet(packet).await?;
        Ok(())
    }

    async fn send_packet(&mut self, mut packet: PacketBuf) -> Result<()> {
        let duplicate = self.prepare_packet(&mut packet)?;
        self.shared
            .allocation
            .send_with_duplicate(packet, duplicate)
            .await?;
        Ok(())
    }

    fn prepare_packet(&mut self, packet: &mut PacketBuf) -> Result<bool> {
        let duplicate =
            selective_fec::should_duplicate(packet.as_slice()) && self.fec_budget.allow();
        client_perf::measure_sampled(PerfStage::CryptoObfs, 64, || {
            self.shared
                .cipher
                .wrap(packet, &self.shared.config, &mut self.write_state)
        })?;
        Ok(duplicate)
    }

    fn queue_data(&mut self, packet: PacketBuf) {
        debug_assert!(self.pending_data.len() < WRITER_BULK_BATCH_LIMIT);
        self.pending_data.push_back(packet);
    }

    async fn flush_queued_data(&mut self) -> Result<()> {
        if self.pending_data.len() == 1
            && let Some(packet) = self.pending_data.pop_front()
        {
            return self.send_data(packet).await;
        }

        while let Some(mut packet) = self.pending_data.pop_front() {
            if self.prepare_packet(&mut packet)? {
                self.flush_mmsg_data().await?;
                self.shared
                    .allocation
                    .send_with_duplicate(packet, true)
                    .await?;
                continue;
            }

            self.mmsg_data.push(packet);
            if self.mmsg_data.len() == WRITER_BULK_BATCH_LIMIT {
                self.flush_mmsg_data().await?;
            }
        }
        self.flush_mmsg_data().await
    }

    async fn flush_mmsg_data(&mut self) -> Result<()> {
        if self.mmsg_data.is_empty() {
            return Ok(());
        }
        self.shared
            .allocation
            .send_data_batch(&mut self.mmsg_data)
            .await?;
        self.mmsg_data.clear();
        Ok(())
    }

    async fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        let pool = self.shared.pool.clone();
        self.send_bytes_with_pool(data, &pool).await
    }

    async fn send_bytes_with_pool(&mut self, data: &[u8], pool: &Arc<PacketPool>) -> Result<()> {
        let mut packet = pool.try_acquire().context("packet budget exhausted")?;
        if data.len() > packet.read_area().len() {
            bail!("transport payload too large: {}", data.len());
        }
        packet.read_area()[..data.len()].copy_from_slice(data);
        packet.set_read_len(data.len())?;
        self.send_packet(packet).await
    }
}

impl TransportReader {
    fn new(shared: Arc<TransportShared>, receiver: TurnReceiver) -> Self {
        Self {
            shared,
            receiver,
            replay: ReplayProtection::default(),
        }
    }

    async fn recv(&mut self) -> Result<PacketBuf> {
        loop {
            let mut packet = self
                .receiver
                .recv()
                .await
                .context("TURN allocation receive")?;
            client_perf::observe(PerfStage::TurnRx);
            let accepted = client_perf::measure_sampled(PerfStage::CryptoObfs, 64, || {
                authenticate_inbound(
                    &self.shared.cipher,
                    &self.shared.config,
                    &mut self.replay,
                    &mut packet,
                )
            });
            if accepted {
                return Ok(packet);
            }
        }
    }
}

pub async fn run_session(
    config: SessionConfig,
    credentials: TurnCredentials,
    mut runtime: SessionRuntime,
) -> Result<bool> {
    if credentials.server_addresses.is_empty() {
        bail!("нет TURN URL в учётных данных");
    }
    let turn_address = select_turn_address(&credentials.server_addresses, &config)?;
    let turn_path = turn_path_key(turn_address, &config)?;
    crate::log_error!("[TURN] Подключение к {turn_address}");
    let cancel = runtime.cancel.clone();
    let turn_host = config.turn_host.clone();
    let turn_port = config.turn_port.clone();
    let turn_transport = config.turn_transport;
    if let Some(started) = runtime.allocation_started.take() {
        let _ = started.send(());
    }
    let mut connect = Box::pin(TurnAllocation::connect(
        TurnConnectTarget {
            address: turn_address,
            override_host: turn_host.as_deref(),
            override_port: turn_port.as_deref(),
            transport_mode: turn_transport,
        },
        credentials.username,
        credentials.password,
        config.peer,
        runtime.pool.clone(),
    ));
    let allocation = tokio::select! {
        biased;
        result = &mut connect => result.map_err(TurnAllocateError)?,
        _ = cancel.cancelled() => {
            if let Ok(Ok(allocation)) = tokio::time::timeout(CONNECT_CANCEL_GRACE, &mut connect).await {
                let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
            }
            return Ok(false);
        },
    };
    drop(connect);
    if let Some(ready) = runtime.allocation_ready.take() {
        let _ = ready.send(());
    }
    crate::log_error!("[СЕССИЯ #{}] Relay: {}", config.id, allocation.local_addr());
    let channel = tokio::select! {
        biased;
        result = allocation.prepare_channel() => result,
        _ = cancel.cancelled() => {
            let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
            return Ok(false);
        },
    };
    if let Err(error) = channel {
        let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
        return Err(error.context("TURN ChannelBind обязателен"));
    }
    let session = tokio::spawn(run_allocated_session(
        config,
        runtime,
        allocation.clone(),
        turn_path,
    ));
    let result = await_session_task(&cancel, session).await;
    let _ = tokio::time::timeout(DEALLOCATE_TIMEOUT, allocation.deallocate()).await;
    result
}

async fn await_session_task(
    cancel: &CancellationToken,
    mut session: JoinHandle<Result<bool>>,
) -> Result<bool> {
    tokio::select! {
        biased;
        result = &mut session => match result {
            Ok(result) => result,
            Err(error) if error.is_panic() => Err(anyhow!("паника сессии изолирована: {error}")),
            Err(error) => Err(anyhow!("задача сессии завершена аварийно: {error}")),
        },
        _ = cancel.cancelled() => {
            match tokio::time::timeout(SESSION_SHUTDOWN_GRACE, &mut session).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) if error.is_panic() => {
                    Err(anyhow!("session panicked during graceful shutdown: {error}"))
                }
                Ok(Err(error)) => {
                    Err(anyhow!("session stopped during graceful shutdown: {error}"))
                }
                Err(_) => {
                    session.abort();
                    let _ = session.await;
                    Ok(false)
                }
            }
        }
    }
}

async fn run_allocated_session(
    config: SessionConfig,
    mut runtime: SessionRuntime,
    allocation: Arc<TurnAllocation>,
    turn_path: Arc<str>,
) -> Result<bool> {
    let session_cancel = CancellationToken::new();
    let turn_receiver = allocation.take_receiver()?;
    crate::log_error!(
        "[СЕССИЯ #{}] [DIRECT] Прямой режим обфускации ({:?})",
        config.id,
        config.mode
    );
    let shared = Arc::new(TransportShared {
        allocation,
        cipher: ObfsCipher::new(config.wrap_key)?,
        config: ObfsConfig::new(config.mode),
        pool: runtime.pool.clone(),
    });
    let mut writer_transport = TransportWriter::new(shared.clone());
    let mut reader_transport = TransportReader::new(shared, turn_receiver);
    let incarnation_id = NEXT_INCARNATION_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let config_tx = config.get_config.then(|| runtime.config_tx.clone());
    let config_delivered = match request_configuration(
        &mut writer_transport,
        &mut reader_transport,
        &config,
        &runtime.events,
        config_tx,
    )
    .await
    {
        Ok(delivered) => {
            let delivered = config.get_config && delivered;
            if let Some(state) = &runtime.config_delivery {
                state.complete(delivered);
            }
            delivered
        }
        Err(error) => {
            if let Some(state) = &runtime.config_delivery {
                state.complete(false);
            }
            return Err(error);
        }
    };
    let (latency_tx, latency_rx) = packet_channel(WORKER_LATENCY_CAPACITY, true);
    let (priority_tx, priority_rx) = packet_channel(WORKER_PRIORITY_CAPACITY, true);
    let (bulk_tx, bulk_rx) = packet_channel(WORKER_BULK_CAPACITY, true);
    let worker_channels = WorkerChannels {
        id: config.id,
        incarnation_id,
        turn_path,
        latency: latency_tx,
        priority: priority_tx,
        bulk: bulk_tx,
    };
    let (writer_command_tx, writer_command_rx) = mpsc::channel(WRITER_COMMAND_CAPACITY);
    let shutdown_registration = runtime
        .shutdown
        .register(incarnation_id, writer_command_tx.clone());
    let writer_activity = shutdown_registration.activity.clone();
    runtime.dispatcher.register(worker_channels.clone());
    let _registration =
        WorkerRegistration::new(runtime.dispatcher.clone(), config.id, incarnation_id);
    if let Some(ready_tx) = runtime.ready_tx.take() {
        let _ = ready_tx.send(());
    }
    crate::log_error!("[ВОРКЕР #{}] [READY] Поток готов ✓", config.id);
    runtime.events.ready(config.id);
    config.repair.mark_ready(config.id);
    let _active = ActiveConnection::new(runtime.stats.clone(), runtime.events.clone());
    let mut writer = tokio::spawn(writer_loop(
        writer_transport,
        WriterRuntime {
            latency: latency_rx,
            priority: priority_rx,
            bulk: bulk_rx,
            commands: writer_command_rx,
            shutdown: runtime.shutdown.clone(),
            activity: writer_activity,
        },
        session_cancel.clone(),
    ));
    let mut reader = tokio::spawn(reader_loop(
        reader_transport,
        ReaderRuntime {
            dispatcher: runtime.dispatcher.clone(),
            events: runtime.events.clone(),
            repair: config.repair.clone(),
            shutdown: runtime.shutdown.clone(),
            config_tx: runtime.config_tx.clone(),
        },
        session_cancel.clone(),
    ));
    let repair_generation = config.repair.restart_generation(config.id);
    let (session_result, completed): (Result<()>, u8) = tokio::select! {
        biased;
        _ = runtime.cancel.cancelled() => {
            runtime
                .shutdown
                .request_disconnect(&config.device_id, &config.salt)
                .await;
            (Ok(()), 0)
        }
        _ = config.repair.changed(config.id, repair_generation) => {
            (Err(anyhow!("TARGET_REPAIR")), 0)
        }
        result = &mut writer => {
            (result.map_err(anyhow::Error::from).and_then(|value| value), 1)
        }
        result = &mut reader => {
            (result.map_err(anyhow::Error::from).and_then(|value| value), 2)
        }
    };
    session_cancel.cancel();
    stop_session_tasks(completed, writer, reader).await;
    crate::log_error!("[СЕССИЯ #{}] Завершена", config.id);
    session_result?;
    Ok(config_delivered)
}

async fn stop_session_tasks(
    completed: u8,
    writer: JoinHandle<Result<()>>,
    reader: JoinHandle<Result<()>>,
) {
    match completed {
        0 => {
            writer.abort();
            reader.abort();
            let _ = writer.await;
            let _ = reader.await;
        }
        1 => {
            reader.abort();
            let _ = reader.await;
        }
        _ => {
            writer.abort();
            let _ = writer.await;
        }
    }
}

async fn request_configuration(
    writer: &mut TransportWriter,
    reader: &mut TransportReader,
    config: &SessionConfig,
    events: &Events,
    config_tx: Option<mpsc::Sender<String>>,
) -> Result<bool> {
    let request = build_registration_payload(config);
    'attempts: for (attempt, timeout_ms) in CONFIG_RESPONSE_TIMEOUT_MS.into_iter().enumerate() {
        writer
            .send_bytes(request.as_ref())
            .await
            .context("отправка GETCONF")?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let packet = loop {
            match tokio::time::timeout_at(deadline, reader.recv()).await {
                Ok(result) => {
                    let packet = result.context("GETCONF чтение ответа конфига")?;
                    if is_panel_restart_notice(packet.as_slice()) {
                        events.panel_restart();
                        continue;
                    }
                    if !is_config_response(packet.as_slice()) {
                        continue;
                    }
                    break packet;
                }
                Err(_) if attempt + 1 < CONFIG_RESPONSE_TIMEOUT_MS.len() => continue 'attempts,
                Err(_) => {
                    let message = format!(
                        "FATAL_HANDSHAKE: сервер не подтвердил конфигурацию после {} попыток; проверьте пароль подключения и совместимость клиента с сервером",
                        CONFIG_RESPONSE_TIMEOUT_MS.len()
                    );
                    if config.get_config {
                        events.error("handshake_timeout", &message, true);
                    }
                    bail!(message)
                }
            }
        };
        let response = parse_config_response(packet.as_slice()).inspect_err(|error| {
            let message = error.to_string();
            if config.get_config && message.contains("FATAL_") {
                events.error("handshake_rejected", &message, true);
            }
        })?;
        match response {
            ConfigResponse::NoConfig => return Ok(false),
            ConfigResponse::Config(value) => {
                if value.ends_with(":stream-v1") || value.ends_with(":stream-v2") {
                    config.server_stream_repair.store(true, Ordering::Release);
                }
                if let Some(sender) = &config_tx {
                    let _ = sender.try_send(value);
                }
                crate::log_error!("[ВОРКЕР #{}] Конфиг получен", config.id);
                return Ok(true);
            }
        }
    }
    let message = "FATAL_HANDSHAKE: сервер не подтвердил конфигурацию";
    if config.get_config {
        events.error("handshake_timeout", message, true);
    }
    bail!(message)
}

async fn writer_loop(
    mut transport: TransportWriter,
    runtime: WriterRuntime,
    cancel: CancellationToken,
) -> Result<()> {
    let WriterRuntime {
        latency,
        priority,
        bulk,
        mut commands,
        shutdown,
        activity,
    } = runtime;
    loop {
        if let Ok(command) = commands.try_recv() {
            handle_writer_command(&mut transport, command).await?;
            continue;
        }
        let next = if let Some(packet) = next_writer_packet(&latency, &priority, &bulk) {
            Some(packet)
        } else if latency.is_closed() && priority.is_closed() && bulk.is_closed() {
            None
        } else {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                command = commands.recv() => {
                    if let Some(command) = command {
                        handle_writer_command(&mut transport, command).await?;
                    }
                    continue;
                }
                packet = latency.recv(&cancel) => packet.map(|packet| WriterPacket {
                    packet,
                    class: PacketClass::Small,
                }),
                packet = priority.recv(&cancel) => packet.map(|packet| WriterPacket {
                    packet,
                    class: PacketClass::Medium,
                }),
                packet = bulk.recv(&cancel) => packet.map(|packet| WriterPacket {
                    packet,
                    class: PacketClass::Bulk,
                }),
            }
        };
        let Some(next) = next else {
            if cancel.is_cancelled()
                || (latency.is_closed() && priority.is_closed() && bulk.is_closed())
            {
                return Ok(());
            }
            continue;
        };
        let sent = send_writer_batch(&mut transport, next, &latency, &priority, &bulk).await?;
        if sent != 0 {
            shutdown.mark_activity(&activity);
        }
    }
}

async fn send_writer_batch(
    transport: &mut TransportWriter,
    first: WriterPacket,
    latency: &PacketReceiver,
    priority: &PacketReceiver,
    bulk: &PacketReceiver,
) -> Result<usize> {
    client_perf::observe(PerfStage::WriterBatch);
    let (receiver, limit) = match first.class {
        PacketClass::Small => (latency, WRITER_LATENCY_BATCH_LIMIT),
        PacketClass::Medium => (priority, WRITER_PRIORITY_BATCH_LIMIT),
        PacketClass::Bulk => (bulk, WRITER_BULK_BATCH_LIMIT),
    };
    transport.queue_data(first.packet);
    let mut sent = 1usize;
    while sent < limit {
        if !writer_batch_can_extend(
            first.class,
            latency.has_queued_packet(),
            priority.has_queued_packet(),
        ) {
            break;
        }
        if let Some(packet) = receiver.try_recv() {
            transport.queue_data(packet);
            sent += 1;
        } else {
            break;
        }
    }
    transport.flush_queued_data().await?;
    Ok(sent)
}

#[inline]
fn writer_batch_can_extend(
    class: PacketClass,
    latency_pending: bool,
    priority_pending: bool,
) -> bool {
    match class {
        PacketClass::Small => true,
        PacketClass::Medium => !latency_pending,
        PacketClass::Bulk => !latency_pending && !priority_pending,
    }
}

async fn handle_writer_command(
    transport: &mut TransportWriter,
    command: WriterCommand,
) -> Result<()> {
    match command {
        WriterCommand::SendBytes { data, completion } => {
            let result = transport.send_bytes(&data).await;
            let _ = completion.send(result);
            Ok(())
        }
    }
}

async fn send_writer_bytes(sender: &mpsc::Sender<WriterCommand>, data: &[u8]) -> Result<()> {
    let (completion, result) = oneshot::channel();
    sender
        .try_send(WriterCommand::SendBytes {
            data: Bytes::copy_from_slice(data),
            completion,
        })
        .context("writer command queue closed")?;
    result.await.context("writer command response closed")?
}

fn next_writer_packet(
    latency: &PacketReceiver,
    priority: &PacketReceiver,
    bulk: &PacketReceiver,
) -> Option<WriterPacket> {
    latency
        .try_recv()
        .map(|packet| WriterPacket {
            packet,
            class: PacketClass::Small,
        })
        .or_else(|| {
            priority.try_recv().map(|packet| WriterPacket {
                packet,
                class: PacketClass::Medium,
            })
        })
        .or_else(|| {
            bulk.try_recv().map(|packet| WriterPacket {
                packet,
                class: PacketClass::Bulk,
            })
        })
}

async fn reader_loop(
    mut transport: TransportReader,
    runtime: ReaderRuntime,
    cancel: CancellationToken,
) -> Result<()> {
    let ReaderRuntime {
        dispatcher,
        events,
        repair,
        shutdown,
        config_tx,
    } = runtime;
    loop {
        let packet = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            result = transport.recv() => result?,
        };
        if is_panel_restart_notice(packet.as_slice()) {
            events.panel_restart();
            continue;
        }
        if let Some(command) = parse_stream_repair(packet.as_slice()) {
            let result = repair.apply_repair(&command);
            if result.restarts != 0 {
                crate::log_error!(
                    "[REPAIR] Сервер запросил перезапуск потоков {:?}, sequence {}, resets {}",
                    command.worker_ids,
                    command.sequence,
                    result.credential_resets
                );
            }
            continue;
        }
        if let Some(command) = parse_stream_alive(packet.as_slice()) {
            repair.apply_alive(&command);
            continue;
        }
        if shutdown.observe_control_response(packet.as_slice()) {
            continue;
        }
        if packet.as_slice().starts_with(b"TUNCONF:") {
            if let Ok(ConfigResponse::Config(config)) = parse_config_response(packet.as_slice()) {
                let _ = config_tx.try_send(config);
            }
            continue;
        }
        if is_control_response(packet.as_slice()) {
            continue;
        }
        deliver_inbound_packet(&dispatcher, packet);
    }
}

fn deliver_inbound_packet(dispatcher: &Dispatcher, packet: PacketBuf) {
    dispatcher.return_packet(packet);
}

fn turn_endpoint_index(id: usize, cursor: usize, endpoint_count: usize) -> usize {
    debug_assert!(endpoint_count > 0);
    (id % endpoint_count + cursor % endpoint_count) % endpoint_count
}

fn select_turn_address<'a>(addresses: &'a [Arc<str>], config: &SessionConfig) -> Result<&'a str> {
    let count = addresses.len();
    let start = turn_endpoint_index(config.id, config.turn_endpoint_cursor, count);
    for offset in 0..count {
        let address = addresses[(start + offset) % count].as_ref();
        if resolve_turn_endpoints(
            address,
            config.turn_host.as_deref(),
            config.turn_port.as_deref(),
            config.turn_transport,
        )
        .is_ok()
        {
            return Ok(address);
        }
    }
    bail!("Нет TURN endpoint для выбранного транспорта")
}

fn turn_path_key(address: &str, config: &SessionConfig) -> Result<Arc<str>> {
    let endpoint = resolve_turn_endpoints(
        address,
        config.turn_host.as_deref(),
        config.turn_port.as_deref(),
        config.turn_transport,
    )
    .context("TURN endpoint is invalid")?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow!("TURN endpoint list is empty"))?;
    Ok(Arc::from(endpoint.socket_authority()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::future::pending;

    #[test]
    fn transport_selection_skips_incompatible_turn_endpoints() {
        let addresses: Arc<[Arc<str>]> = [
            Arc::from("turn:relay.example:3478?transport=udp"),
            Arc::from("turn:relay.example:3478?transport=tcp"),
        ]
        .into();
        let config = SessionConfig {
            id: 0,
            peer: "127.0.0.1:46000".parse().unwrap(),
            turn_host: None,
            turn_port: None,
            turn_transport: TurnTransportMode::TcpTls,
            local_port: Arc::from("9000"),
            device_id: Arc::from("device"),
            password: Arc::from("password"),
            generation: 0,
            turn_endpoint_cursor: 0,
            salt: Arc::from(""),
            mode: ObfsMode::Audio,
            wrap_key: [0; 32],
            get_config: false,
            desired_count: 18,
            server_stream_repair: Arc::new(AtomicBool::new(false)),
            repair: RepairState::new(18),
        };
        assert_eq!(
            select_turn_address(&addresses, &config).unwrap(),
            "turn:relay.example:3478?transport=tcp"
        );
    }

    #[test]
    fn first_registration_announces_the_full_stream_set_before_the_feature_reply() {
        let config = SessionConfig {
            id: 1,
            peer: "127.0.0.1:46000".parse().unwrap(),
            turn_host: None,
            turn_port: None,
            turn_transport: TurnTransportMode::Udp,
            local_port: Arc::from("9000"),
            device_id: Arc::from("device"),
            password: Arc::from("password"),
            generation: 7,
            turn_endpoint_cursor: 0,
            salt: Arc::from("generation-id"),
            mode: ObfsMode::Audio,
            wrap_key: [0; 32],
            get_config: true,
            desired_count: 9,
            server_stream_repair: Arc::new(AtomicBool::new(false)),
            repair: RepairState::new(9),
        };
        assert_eq!(
            build_registration_payload(&config).as_ref(),
            b"GETCONF:9000|device|password|7|generation-id|1|9|CSQTT-WIRE-3"
        );
    }

    #[tokio::test]
    async fn shutdown_uses_the_most_recently_active_control_stream_once() {
        let shutdown = Arc::new(ShutdownCoordinator::new());
        let (older_tx, mut older_rx) = mpsc::channel(1);
        let older = shutdown.register(1, older_tx);
        let (newer_tx, mut newer_rx) = mpsc::channel(1);
        let newer = shutdown.register(2, newer_tx);
        shutdown.mark_activity(&older.activity);

        let coordinator = shutdown.clone();
        let task = tokio::spawn(async move {
            coordinator.request_disconnect("device", "salt").await;
        });
        let command = tokio::time::timeout(Duration::from_millis(100), older_rx.recv())
            .await
            .unwrap_or(None);
        let completion = match command {
            Some(WriterCommand::SendBytes { data, completion }) => {
                assert_eq!(data.as_ref(), b"DISCONNECT:device|salt");
                completion
            }
            None => panic!("shutdown did not select the active control stream"),
        };
        assert!(completion.send(Ok(())).is_ok());
        assert!(shutdown.observe_control_response(b"OK:disconnected"));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_ok()
        );
        assert!(newer_rx.try_recv().is_err());
        drop(older);
        drop(newer);
    }

    #[tokio::test]
    async fn shutdown_never_uses_a_dropped_control_stream() {
        let shutdown = Arc::new(ShutdownCoordinator::new());
        let (stale_tx, mut stale_rx) = mpsc::channel(1);
        let stale = shutdown.register(1, stale_tx);
        drop(stale);
        let (active_tx, mut active_rx) = mpsc::channel(1);
        let active = shutdown.register(2, active_tx);

        let coordinator = shutdown.clone();
        let task = tokio::spawn(async move {
            coordinator.request_disconnect("device", "salt").await;
        });
        let command = tokio::time::timeout(Duration::from_millis(100), active_rx.recv())
            .await
            .unwrap_or(None);
        let completion = match command {
            Some(WriterCommand::SendBytes { completion, .. }) => completion,
            None => panic!("shutdown did not select a live control stream"),
        };
        assert!(completion.send(Ok(())).is_ok());
        assert!(shutdown.observe_control_response(b"OK:disconnected"));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_ok()
        );
        assert!(stale_rx.try_recv().is_err());
        drop(active);
    }

    #[derive(Clone, Copy, Default)]
    struct ReplayCoverage {
        duplicate: usize,
        age_16383: usize,
        age_16384: usize,
        age_16385: usize,
        forward_small: usize,
        forward_large: usize,
    }

    impl ReplayCoverage {
        fn complete(self) -> bool {
            self.duplicate > 0
                && self.age_16383 > 0
                && self.age_16384 > 0
                && self.age_16385 > 0
                && self.forward_small > 0
                && self.forward_large > 0
        }
    }

    struct DropFlag(Arc<AtomicBool>);

    fn model_accept(
        highest: &mut Option<u64>,
        seen: &mut HashSet<u64>,
        counter: u64,
        model_window: u64,
    ) -> bool {
        match *highest {
            None => {
                *highest = Some(counter);
                seen.insert(counter);
                true
            }
            Some(current) if counter > current => {
                *highest = Some(counter);
                seen.retain(|value| counter - *value < model_window);
                seen.insert(counter);
                true
            }
            Some(current) if current - counter >= model_window => false,
            Some(_) => seen.insert(counter),
        }
    }

    fn replay_trace_matches(counters: &[u64], model_window: u64) -> bool {
        let mut window = ReplayWindow::default();
        let mut highest = None;
        let mut seen = HashSet::new();
        for &counter in counters {
            let expected = model_accept(&mut highest, &mut seen, counter, model_window);
            if window.accept(counter) != expected {
                return false;
            }
        }
        true
    }

    fn replay_trace_coverage(counters: &[u64]) -> ReplayCoverage {
        let mut highest = None;
        let mut seen = HashSet::new();
        let mut coverage = ReplayCoverage::default();
        for &counter in counters {
            if seen.contains(&counter) {
                coverage.duplicate += 1;
            }
            if let Some(current) = highest {
                if counter > current {
                    let delta = counter - current;
                    if delta < 16384 {
                        coverage.forward_small += 1;
                    } else {
                        coverage.forward_large += 1;
                    }
                } else {
                    match current - counter {
                        16383 => coverage.age_16383 += 1,
                        16384 => coverage.age_16384 += 1,
                        16385 => coverage.age_16385 += 1,
                        _ => {}
                    }
                }
            }
            model_accept(&mut highest, &mut seen, counter, 16384);
        }
        coverage
    }

    fn extend_rtp_reference(highest: u64, sequence: u16) -> u64 {
        let base = highest & !(u16::MAX as u64);
        let current = base | u64::from(sequence);
        let previous = current.checked_sub(1 << 16);
        let next = current.saturating_add(1 << 16);
        let mut selected = current;
        let mut distance = current.abs_diff(highest);
        if let Some(previous) = previous {
            let candidate_distance = previous.abs_diff(highest);
            if candidate_distance < distance {
                selected = previous;
                distance = candidate_distance;
            }
        }
        if next.abs_diff(highest) < distance {
            selected = next;
        }
        selected
    }

    fn rtp_trace_matches(sequences: &[u16]) -> bool {
        let mut window = ReplayWindow::default();
        let mut highest = None;
        let mut seen = HashSet::new();
        for &sequence in sequences {
            let extended = highest
                .map(|value| extend_rtp_reference(value, sequence))
                .unwrap_or(u64::from(sequence));
            let expected = model_accept(&mut highest, &mut seen, extended, 16384);
            if window.accept_rtp(sequence) != expected {
                return false;
            }
        }
        true
    }

    fn mix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn deterministic_replay_trace(seed: u64, length: usize) -> Vec<u64> {
        let mut state = seed;
        let mut counters = Vec::with_capacity(length);
        let prefix = [1_000, 1_000, 1_001, 17_385, 1_002, 1_001, 1_000, 25_000];
        counters.extend(prefix.into_iter().take(length));
        let mut highest = (seed & 0xffff).max(counters.iter().copied().max().unwrap_or(0));
        for _ in counters.len()..length {
            state = mix64(state);
            let counter = match state % 8 {
                0 => highest,
                1 => highest.saturating_sub(16383),
                2 => highest.saturating_sub(16384),
                3 => highest.saturating_sub(16385),
                4 => highest.saturating_sub(state % 512),
                5 => {
                    highest = highest.saturating_add(1 + (state >> 8) % 4);
                    highest
                }
                6 => {
                    highest = highest.saturating_add(16384 + (state >> 8) % 4_096);
                    highest
                }
                _ => state & 0x0000_ffff_ffff_ffff,
            };
            highest = highest.max(counter);
            counters.push(counter);
        }
        counters
    }

    #[test]
    fn writer_drains_latency_before_bulk() {
        let pool = PacketPool::new(512);
        let (latency_tx, latency) = packet_channel(256, true);
        let (priority_tx, priority) = packet_channel(256, true);
        let (bulk_tx, bulk) = packet_channel(256, true);
        for (sender, class) in [(&latency_tx, 0), (&priority_tx, 1), (&bulk_tx, 2)] {
            for _ in 0..160 {
                let mut packet = pool.acquire();
                packet.set_read_len(1).unwrap();
                packet.as_mut_slice()[0] = class;
                assert!(sender.try_send(packet).is_ok());
            }
        }
        for _ in 0..160 {
            let packet = next_writer_packet(&latency, &priority, &bulk).unwrap();
            assert_eq!(packet.packet.as_slice()[0], 0);
            assert_eq!(packet.class, PacketClass::Small);
        }
        let packet = next_writer_packet(&latency, &priority, &bulk).unwrap();
        assert_eq!(packet.packet.as_slice()[0], 1);
        assert_eq!(packet.class, PacketClass::Medium);
        for _ in 1..160 {
            assert_eq!(
                next_writer_packet(&latency, &priority, &bulk)
                    .unwrap()
                    .class,
                PacketClass::Medium
            );
        }
        let packet = next_writer_packet(&latency, &priority, &bulk).unwrap();
        assert_eq!(packet.packet.as_slice()[0], 2);
        assert_eq!(packet.class, PacketClass::Bulk);
    }

    #[test]
    fn worker_queues_hold_one_full_mmsg_batch_per_data_lane() {
        const TUN_MTU: u128 = 1_300;
        const BITS_PER_SECOND: u128 = 2_000_000;
        let buffered_us = WORKER_BULK_CAPACITY as u128 * TUN_MTU * 8 * 1_000_000 / BITS_PER_SECOND;
        assert!(buffered_us <= 700_000);
        assert_eq!(
            WORKER_LATENCY_CAPACITY,
            crate::striped_scheduler::SMALL_DATAGRAM_BATCH
        );
        assert_eq!(
            WORKER_PRIORITY_CAPACITY,
            crate::striped_scheduler::MEDIUM_DATAGRAM_BATCH
        );
        assert_eq!(
            WORKER_BULK_CAPACITY,
            crate::striped_scheduler::BULK_DATAGRAM_BATCH
        );
    }

    #[test]
    fn writer_uses_bulk_when_latency_is_empty() {
        let pool = PacketPool::new(4);
        let (latency_tx, latency) = packet_channel(800, true);
        let (priority_tx, priority) = packet_channel(800, true);
        let (bulk_tx, bulk) = packet_channel(800, true);
        drop(latency_tx);
        drop(priority_tx);
        let mut packet = pool.acquire();
        packet.set_read_len(1).unwrap();
        packet.as_mut_slice()[0] = 1;
        assert!(bulk_tx.try_send(packet).is_ok());
        let packet = next_writer_packet(&latency, &priority, &bulk).unwrap();
        assert_eq!(packet.packet.as_slice()[0], 1);
        assert_eq!(packet.class, PacketClass::Bulk);
    }

    #[test]
    fn writer_prefers_latency_when_both_queues_ready() {
        let pool = PacketPool::new(4);
        let (latency_tx, latency) = packet_channel(4, true);
        let (priority_tx, priority) = packet_channel(4, true);
        let (bulk_tx, bulk) = packet_channel(4, true);
        for (sender, class) in [(&latency_tx, 0), (&priority_tx, 1), (&bulk_tx, 2)] {
            let mut packet = pool.acquire();
            packet.set_read_len(1).unwrap();
            packet.as_mut_slice()[0] = class;
            assert!(sender.try_send(packet).is_ok());
        }
        let packet = next_writer_packet(&latency, &priority, &bulk).unwrap();
        assert_eq!(packet.packet.as_slice()[0], 0);
        assert_eq!(packet.class, PacketClass::Small);
    }

    #[test]
    fn writer_batches_respect_priority_lanes() {
        assert_eq!(
            WRITER_LATENCY_BATCH_LIMIT,
            crate::striped_scheduler::SMALL_DATAGRAM_BATCH
        );
        assert_eq!(
            WRITER_PRIORITY_BATCH_LIMIT,
            crate::striped_scheduler::MEDIUM_DATAGRAM_BATCH
        );
        assert_eq!(
            WRITER_BULK_BATCH_LIMIT,
            crate::striped_scheduler::BULK_DATAGRAM_BATCH
        );
        assert!(writer_batch_can_extend(PacketClass::Medium, false, true));
        assert!(!writer_batch_can_extend(PacketClass::Medium, true, false));
        assert!(writer_batch_can_extend(PacketClass::Bulk, false, false));
        assert!(!writer_batch_can_extend(PacketClass::Bulk, true, false));
        assert!(!writer_batch_can_extend(PacketClass::Bulk, false, true));
    }

    #[test]
    fn replay_window_accepts_reordering_once_and_rejects_duplicates() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(100));
        assert!(window.accept(102));
        assert!(window.accept(101));
        assert!(!window.accept(101));
        assert!(!window.accept(100));
        assert!(window.accept(230));
        assert!(!window.accept(102));
    }

    #[test]
    fn replay_window_handles_rtp_wrap_and_late_packets() {
        let mut window = ReplayWindow::default();
        for sequence in [65_534, 65_535, 0, 2, 1, 3] {
            assert!(window.accept_rtp(sequence));
        }
        assert!(!window.accept_rtp(0));
        assert!(!window.accept_rtp(65_535));
        assert_eq!(window.highest, Some(65_539));
    }

    #[test]
    fn replay_window_is_bounded_under_million_packet_attack() {
        let mut window = ReplayWindow::default();
        for counter in 0..1_000_000 {
            assert!(window.accept(counter));
            assert!(!window.accept(counter));
        }
        assert_eq!(std::mem::size_of_val(&window), 24);
    }

    proptest! {
        #[test]
        fn replay_window_matches_independent_set_model(
            counters in proptest::collection::vec(any::<u32>(), 1..=5_000)
        ) {
            let counters = counters.into_iter().map(u64::from).collect::<Vec<_>>();
            prop_assert!(replay_trace_matches(&counters, 16384));
        }

        #[test]
        fn rtp_replay_window_matches_independent_extended_sequence_model(
            sequences in proptest::collection::vec(any::<u16>(), 1..=2_000)
        ) {
            prop_assert!(rtp_trace_matches(&sequences));
        }
    }

    #[test]
    fn replay_oracle_detects_window_off_by_one_mutation() {
        let counters = [100, 16484, 101];
        assert!(replay_trace_matches(&counters, 16384));
        assert!(!replay_trace_matches(&counters, 16383));
    }

    #[test]
    fn deterministic_replay_fault_generator_is_reproducible_and_hits_boundaries() {
        let first = deterministic_replay_trace(0x1234_5678_9abc_def0, 4_096);
        let second = deterministic_replay_trace(0x1234_5678_9abc_def0, 4_096);
        let different = deterministic_replay_trace(0x1234_5678_9abc_def1, 4_096);
        assert_eq!(first, second);
        assert_ne!(first, different);
        assert!(first.windows(2).any(|pair| pair[0] == pair[1]));
        assert!(replay_trace_coverage(&first).complete());
    }

    #[test]
    fn replay_coverage_oracle_rejects_each_missing_boundary() {
        let complete = ReplayCoverage {
            duplicate: 1,
            age_16383: 1,
            age_16384: 1,
            age_16385: 1,
            forward_small: 1,
            forward_large: 1,
        };
        assert!(complete.complete());
        for index in 0..6 {
            let mut mutated = complete;
            match index {
                0 => mutated.duplicate = 0,
                1 => mutated.age_16383 = 0,
                2 => mutated.age_16384 = 0,
                3 => mutated.age_16385 = 0,
                4 => mutated.forward_small = 0,
                _ => mutated.forward_large = 0,
            }
            assert!(!mutated.complete());
        }
    }

    #[test]
    fn rtp_replay_reference_survives_multiple_wraps_duplicates_and_late_packets() {
        let mut sequence = 65_000u16;
        let mut trace = Vec::with_capacity(20_000);
        for index in 0..10_000 {
            sequence = sequence.wrapping_add(97);
            trace.push(sequence);
            if index % 7 == 0 {
                trace.push(sequence);
            }
            if index % 11 == 0 {
                trace.push(sequence.wrapping_sub(16383));
                trace.push(sequence.wrapping_sub(16384));
                trace.push(sequence.wrapping_sub(16385));
            }
        }
        assert!(rtp_trace_matches(&trace));
    }

    #[test]
    #[ignore = "explicit deterministic stability soak"]
    fn deterministic_replay_chaos_soak() {
        let seconds = std::env::var("CSQTT_SOAK_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120)
            .max(1);
        let first_seed = std::env::var("CSQTT_SOAK_SEED")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let counters_per_seed = std::env::var("CSQTT_REPLAY_SOAK_COUNTERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4_096)
            .max(8);
        let started = Instant::now();
        let mut offset = 0u64;
        loop {
            let seed = first_seed.wrapping_add(offset);
            let counters = deterministic_replay_trace(seed, counters_per_seed);
            assert!(
                replay_trace_matches(&counters, 16384)
                    && replay_trace_coverage(&counters).complete(),
                "replay window diverged at reproducible seed {seed}"
            );
            offset = offset.wrapping_add(1);
            if started.elapsed() >= Duration::from_secs(seconds) {
                break;
            }
        }
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn completed_writer_is_not_polled_twice() {
        let mut writer = tokio::spawn(async { Ok(()) });
        let reader = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });

        let result: Result<()> = (&mut writer).await.unwrap();
        result.unwrap();
        stop_session_tasks(1, writer, reader).await;
    }

    #[tokio::test]
    async fn completed_reader_is_not_polled_twice() {
        let writer = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });
        let mut reader = tokio::spawn(async { Ok(()) });

        let result: Result<()> = (&mut reader).await.unwrap();
        result.unwrap();
        stop_session_tasks(2, writer, reader).await;
    }

    #[tokio::test]
    async fn cancelled_session_aborts_every_child_task() {
        let writer = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });
        let reader = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });

        tokio::time::timeout(
            Duration::from_secs(1),
            stop_session_tasks(0, writer, reader),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn panicked_writer_handle_is_consumed_only_once() {
        let mut writer = tokio::spawn(async { panic!("injected writer failure") });
        let reader = tokio::spawn(async {
            pending::<()>().await;
            Ok(())
        });

        assert!((&mut writer).await.unwrap_err().is_panic());
        stop_session_tasks(1, writer, reader).await;
    }

    #[tokio::test]
    async fn cancellation_aborts_and_awaits_pending_session_startup() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let session = tokio::spawn(async move {
            let _flag = DropFlag(task_dropped);
            pending::<()>().await;
            Ok(false)
        });
        tokio::task::yield_now().await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(!await_session_task(&cancel, session).await.unwrap());
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn plaintext_corruption_and_replay_never_authenticate() {
        let pool = PacketPool::new(5);
        let cipher = ObfsCipher::new([0x52; 32]).unwrap();
        let config = ObfsConfig::new(ObfsMode::Video);
        let mut replay = ReplayProtection::default();
        let mut encoded = pool.acquire();
        encoded.read_area()[..7].copy_from_slice(b"payload");
        encoded.set_read_len(7).unwrap();
        cipher
            .wrap(&mut encoded, &config, &mut ObfsState::new())
            .unwrap();
        let wire = encoded.as_slice().to_vec();
        drop(encoded);

        let mut plaintext = pool.acquire();
        plaintext.read_area()[..6].copy_from_slice(b"DENIED");
        plaintext.set_read_len(6).unwrap();
        assert!(!authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut plaintext
        ));

        let mut corrupt_wire = wire.clone();
        let last = corrupt_wire.len() - 1;
        corrupt_wire[last] ^= 0x80;
        let mut corrupt = pool.acquire();
        corrupt.read_area()[..corrupt_wire.len()].copy_from_slice(&corrupt_wire);
        corrupt.set_read_len(corrupt_wire.len()).unwrap();
        assert!(!authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut corrupt
        ));

        let mut valid = pool.acquire();
        valid.read_area()[..wire.len()].copy_from_slice(&wire);
        valid.set_read_len(wire.len()).unwrap();
        assert!(authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut valid
        ));
        assert_eq!(valid.as_slice(), b"payload");

        let mut replayed = pool.acquire();
        replayed.read_area()[..wire.len()].copy_from_slice(&wire);
        replayed.set_read_len(wire.len()).unwrap();
        assert!(!authenticate_inbound(
            &cipher,
            &config,
            &mut replay,
            &mut replayed
        ));
    }

    #[tokio::test]
    async fn cancellation_waits_for_graceful_session_exit() {
        let cancel = CancellationToken::new();
        let exited = Arc::new(AtomicBool::new(false));
        let task_cancel = cancel.clone();
        let task_exited = exited.clone();
        let session = tokio::spawn(async move {
            task_cancel.cancelled().await;
            tokio::time::sleep(Duration::from_millis(25)).await;
            task_exited.store(true, Ordering::Release);
            Ok(false)
        });
        cancel.cancel();
        assert!(!await_session_task(&cancel, session).await.unwrap());
        assert!(exited.load(Ordering::Acquire));
    }

    #[test]
    fn transport_shutdown_token_is_independent() {
        let global = CancellationToken::new();
        let transport = CancellationToken::new();
        global.cancel();
        assert!(!transport.is_cancelled());
        transport.cancel();
        assert!(transport.is_cancelled());
    }

    #[test]
    fn endpoint_rotation_is_local_cyclic_and_overflow_safe() {
        for endpoint_count in 1..=8 {
            for id in 1..=126 {
                let selected = (0..endpoint_count)
                    .map(|cursor| turn_endpoint_index(id, cursor, endpoint_count))
                    .collect::<std::collections::HashSet<_>>();
                assert_eq!(selected.len(), endpoint_count);
                assert!(selected.iter().all(|endpoint| *endpoint < endpoint_count));
                assert_eq!(
                    turn_endpoint_index(id, usize::MAX, endpoint_count),
                    (id % endpoint_count + usize::MAX % endpoint_count) % endpoint_count
                );
            }
        }
    }

    #[test]
    fn turn_allocate_error_exposes_nested_io_source() {
        let error = anyhow::Error::new(TurnAllocateError(anyhow::Error::new(
            std::io::Error::from_raw_os_error(101),
        )));
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(101))
        }));
    }

    #[test]
    fn turn_allocate_error_exposes_structured_stun_code() {
        let error = TurnAllocateError(anyhow::Error::new(TurnRequestError::new(3, 0, 486)));
        assert_eq!(error.stun_code(), Some(486));
    }

    #[test]
    fn successful_config_delivery_is_sticky() {
        let sent = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicBool::new(true));
        ConfigDeliveryState {
            sent: sent.clone(),
            in_flight: in_flight.clone(),
        }
        .complete(true);
        assert!(sent.load(Ordering::Acquire));
        assert!(!in_flight.load(Ordering::Acquire));
    }

    #[test]
    fn failed_config_delivery_can_be_retried() {
        let sent = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicBool::new(true));
        ConfigDeliveryState {
            sent: sent.clone(),
            in_flight: in_flight.clone(),
        }
        .complete(false);
        assert!(!sent.load(Ordering::Acquire));
        assert!(!in_flight.load(Ordering::Acquire));
    }
}
