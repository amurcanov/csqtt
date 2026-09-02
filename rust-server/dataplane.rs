// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    net_setup::{TUN_ADDR, TUN_IFACE},
    packet::{PacketBuf, PacketBuffer, PacketPool, packet_pool_size},
    perf::{self, Profiler, Stage, thread_cpu_time_ns},
    striped_scheduler::PacketClass,
    tokio_io::{
        IoCounters, MAX_RX_PER_PASS, PacketOutput, RxOutcome, TICK_INTERVAL_MS, TUN_RX_DRAIN_BATCH,
        TokioIo,
    },
};
use anyhow::{Context, Result, anyhow};
use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::mpsc as async_mpsc;
use tokio_util::sync::CancellationToken;

const RESTART_BACKOFF_INITIAL_MS: u64 = 1_000;
const RESTART_BACKOFF_MAX_MS: u64 = 30_000;
const HEALTHY_UPTIME: Duration = Duration::from_secs(60);
const COMMAND_DRAIN_LIMIT: usize = 4096;
const SHUTDOWN_FLUSH_SYSCALLS: usize = 16;
const MAX_CONSECUTIVE_UDP_PASSES: u32 = 4;
const DATAPLANE_STACK_BYTES: usize = 8 * 1024 * 1024;
const SHARD_INPUT_CAPACITY: usize = 1024;
const SHARD_OUTPUT_CAPACITY: usize = 1024;
const SHARD_OUTPUT_DRAIN_LIMIT: usize = 256;
const MAX_DATAPLANE_SHARDS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointRoute {
    peer: SocketAddr,
    local_ip: Option<IpAddr>,
}

impl EndpointRoute {
    #[inline(always)]
    pub fn new(peer: SocketAddr, local_ip: Option<IpAddr>) -> Self {
        Self { peer, local_ip }
    }
}

pub enum RouterCommand<C> {
    Migrate {
        endpoint: EndpointRoute,
        shard: usize,
        command: C,
    },
    BindEndpoint {
        endpoint: EndpointRoute,
        shard: usize,
    },
    BindTunnel {
        ip: [u8; 4],
        shard: usize,
    },
}

pub enum WorkerOutput<C> {
    Udp {
        peer: SocketAddr,
        source_ip: Option<IpAddr>,
        class: PacketClass,
        buffer: PacketBuf,
    },
    Tun {
        class: PacketClass,
        buffer: PacketBuf,
    },
    FlushUdp,
    Router(RouterCommand<C>),
}

pub struct WorkerContext<C> {
    shard_index: usize,
    shard_count: usize,
    output: async_mpsc::Sender<WorkerOutput<C>>,
}

impl<C: Send + 'static> WorkerContext<C> {
    #[cfg(test)]
    pub(crate) fn new(
        shard_index: usize,
        shard_count: usize,
        output: async_mpsc::Sender<WorkerOutput<C>>,
    ) -> Self {
        Self {
            shard_index,
            shard_count,
            output,
        }
    }

    #[inline(always)]
    pub fn shard_index(&self) -> usize {
        self.shard_index
    }

    #[inline(always)]
    pub fn shard_count(&self) -> usize {
        self.shard_count
    }

    pub fn bind_endpoint(&self, endpoint: EndpointRoute) -> bool {
        self.output
            .try_send(WorkerOutput::Router(RouterCommand::BindEndpoint {
                endpoint,
                shard: self.shard_index,
            }))
            .is_ok()
    }

    pub fn bind_tunnel(&self, ip: [u8; 4]) -> bool {
        self.output
            .try_send(WorkerOutput::Router(RouterCommand::BindTunnel {
                ip,
                shard: self.shard_index,
            }))
            .is_ok()
    }

    pub fn migrate(&self, endpoint: EndpointRoute, shard: usize, command: C) -> Result<(), C> {
        match self
            .output
            .try_send(WorkerOutput::Router(RouterCommand::Migrate {
                endpoint,
                shard,
                command,
            })) {
            Ok(()) => Ok(()),
            Err(async_mpsc::error::TrySendError::Full(WorkerOutput::Router(
                RouterCommand::Migrate { command, .. },
            )))
            | Err(async_mpsc::error::TrySendError::Closed(WorkerOutput::Router(
                RouterCommand::Migrate { command, .. },
            ))) => Err(command),
            Err(_) => unreachable!(),
        }
    }
}

enum WorkerInput<C> {
    Udp {
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        packet: PacketBuffer,
    },
    Tun {
        packet: PacketBuffer,
    },
    IoCounters(IoCounters),
    Command(C),
    Shutdown,
}

struct RemotePacketSink<C> {
    output: async_mpsc::Sender<WorkerOutput<C>>,
    packet_pool: Arc<PacketPool>,
}

impl<C: Send + 'static> PacketOutput for RemotePacketSink<C> {
    #[inline(always)]
    fn has_udp_tx_slot(&self) -> bool {
        self.output.capacity() != 0
    }

    fn send_udp_with_duplicate_priority<F>(
        &mut self,
        peer: SocketAddr,
        source_ip: Option<IpAddr>,
        duplicate: bool,
        class: PacketClass,
        build: F,
    ) -> bool
    where
        F: FnOnce(&mut PacketBuf) -> bool,
    {
        let Some(mut buffer) = self.packet_pool.try_acquire() else {
            return false;
        };
        if !build(&mut buffer) {
            return false;
        }
        let duplicate_buffer = if duplicate {
            self.packet_pool
                .try_acquire()
                .and_then(|mut copy| copy.copy_from(buffer.as_slice()).then_some(copy))
        } else {
            None
        };
        if self
            .output
            .try_send(WorkerOutput::Udp {
                peer,
                source_ip,
                class,
                buffer,
            })
            .is_err()
        {
            return false;
        }
        if let Some(buffer) = duplicate_buffer {
            let _ = self.output.try_send(WorkerOutput::Udp {
                peer,
                source_ip,
                class,
                buffer,
            });
        }
        true
    }

    #[inline(always)]
    fn request_udp_flush(&mut self) {
        let _ = self.output.try_send(WorkerOutput::FlushUdp);
    }

    fn write_tun_priority(&mut self, payload: &[u8], class: PacketClass) -> bool {
        let Some(mut buffer) = self.packet_pool.try_acquire() else {
            return false;
        };
        if !buffer.copy_from(payload) {
            return false;
        }
        self.output
            .try_send(WorkerOutput::Tun { class, buffer })
            .is_ok()
    }
}

pub trait DataplaneLogic: Send + 'static {
    type Command: Send + 'static;

    fn fanout_command(command: Self::Command, _shard_count: usize) -> Vec<Self::Command>
    where
        Self: Sized,
    {
        vec![command]
    }

    fn on_udp<S: PacketOutput>(
        &mut self,
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        packet: &mut [u8],
        sink: &mut S,
    );
    fn on_tun<S: PacketOutput>(&mut self, packet: &mut [u8], sink: &mut S);
    fn on_tun_batch_end<S: PacketOutput>(&mut self, _sink: &mut S) {}
    fn begin_batch(&mut self, now: Instant);
    fn on_command<S: PacketOutput>(&mut self, command: Self::Command, sink: &mut S);
    fn on_tick<S: PacketOutput>(&mut self, sink: &mut S);
    fn on_io_counters(&mut self, counters: IoCounters);
}

pub struct DataplaneConfig {
    pub listen: SocketAddr,
    pub tun_iface: String,
    pub tun_addr: String,
    pub command_capacity: usize,
    pub shards: usize,
}

impl DataplaneConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            tun_iface: TUN_IFACE.to_owned(),
            tun_addr: TUN_ADDR.to_owned(),
            command_capacity: 4096,
            shards: configured_shard_count(),
        }
    }
}

fn configured_shard_count() -> usize {
    let configured = std::env::var("CSQTT_DATAPLANE_SHARDS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value != 0)
        .unwrap_or(1);
    configured.clamp(1, MAX_DATAPLANE_SHARDS)
}

enum RuntimeCommand<C> {
    Logic(C),
    Shutdown,
}

struct HandleInner<C> {
    sender: async_mpsc::Sender<RuntimeCommand<C>>,
    cancel_token: CancellationToken,
    shutdown_flag: Arc<AtomicBool>,
    queued_commands: Arc<AtomicUsize>,
    command_capacity: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DataplaneQueueSnapshot {
    pub queued: usize,
    pub capacity: usize,
}

pub struct DataplaneHandle<C> {
    inner: Arc<HandleInner<C>>,
}

impl<C> Clone for DataplaneHandle<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<C> DataplaneHandle<C> {
    pub fn try_send(&self, command: C) -> Result<()> {
        self.inner.queued_commands.fetch_add(1, Ordering::AcqRel);
        if let Err(_error) = self.inner.sender.try_send(RuntimeCommand::Logic(command)) {
            decrement_queue_len(&self.inner.queued_commands);
            return Err(anyhow!("dataplane command queue is full"));
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        self.inner.cancel_token.cancel();
        self.inner.shutdown_flag.store(true, Ordering::Release);
        self.inner.queued_commands.fetch_add(1, Ordering::AcqRel);
        match self.inner.sender.try_send(RuntimeCommand::Shutdown) {
            Ok(()) => Ok(()),
            Err(async_mpsc::error::TrySendError::Full(_)) => {
                decrement_queue_len(&self.inner.queued_commands);
                Ok(())
            }
            Err(async_mpsc::error::TrySendError::Closed(_)) => {
                decrement_queue_len(&self.inner.queued_commands);
                Ok(())
            }
        }
    }

    pub fn command_queue_snapshot(&self) -> DataplaneQueueSnapshot {
        DataplaneQueueSnapshot {
            queued: self.inner.queued_commands.load(Ordering::Acquire),
            capacity: self.inner.command_capacity,
        }
    }
}

fn decrement_queue_len(queued: &AtomicUsize) {
    let _ = queued.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        value.checked_sub(1)
    });
}

pub struct DataplaneRuntime<C> {
    handle: DataplaneHandle<C>,
    join: Option<JoinHandle<Result<()>>>,
    status: tokio::sync::watch::Receiver<Option<String>>,
}

impl<C: Send + 'static> DataplaneRuntime<C> {
    pub fn handle(&self) -> DataplaneHandle<C> {
        self.handle.clone()
    }

    pub fn status_receiver(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.status.clone()
    }

    pub fn shutdown(mut self) -> Result<()> {
        let signal_result = self.handle.shutdown();
        let join_result = if let Some(join) = self.join.take() {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !join.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if join.is_finished() {
                join.join()
                    .map_err(|_| anyhow!("dataplane thread panicked"))?
            } else {
                eprintln!("[DATAPLANE] shutdown timed out");
                Ok(())
            }
        } else {
            Ok(())
        };
        match (signal_result, join_result) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

pub fn spawn<L, F>(
    config: DataplaneConfig,
    logic_factory: F,
) -> Result<DataplaneRuntime<L::Command>>
where
    L: DataplaneLogic,
    F: Fn(WorkerContext<L::Command>) -> L + Send + Sync + 'static,
{
    if config.shards > 1 {
        return spawn_sharded(config, logic_factory);
    }
    let command_capacity = config.command_capacity.max(16);
    let queued_commands = Arc::new(AtomicUsize::new(0));
    let (command_tx, command_rx) = async_mpsc::channel(command_capacity);
    let cancel_token = CancellationToken::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = DataplaneHandle {
        inner: Arc::new(HandleInner {
            sender: command_tx,
            cancel_token: cancel_token.clone(),
            shutdown_flag: shutdown.clone(),
            queued_commands: queued_commands.clone(),
            command_capacity,
        }),
    };
    let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<()>>(1);
    let (status_tx, status_rx) = tokio::sync::watch::channel(None::<String>);
    let thread_shutdown = shutdown.clone();
    let thread_queued_commands = queued_commands;
    let thread_cancel_token = cancel_token.clone();
    let join = std::thread::Builder::new()
        .name("csqtt-dataplane".to_owned())
        .stack_size(DATAPLANE_STACK_BYTES)
        .spawn(move || {
            let mut command_rx = command_rx;
            let (output_tx, _output_rx) = async_mpsc::channel(SHARD_OUTPUT_CAPACITY);
            let worker_context = WorkerContext {
                shard_index: 0,
                shard_count: 1,
                output: output_tx,
            };
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = startup_tx.send(Err(
                        anyhow::Error::new(error).context("create tokio dataplane runtime")
                    ));
                    let _ = status_tx.send(Some("tokio dataplane failed".to_owned()));
                    return Err(anyhow!("create tokio dataplane runtime"));
                }
            };
            let mut first_attempt = true;
            let mut backoff_ms = RESTART_BACKOFF_INITIAL_MS;
            let result = loop {
                let attempt_started = Instant::now();
                let was_first_attempt = first_attempt;
                first_attempt = false;
                let attempt = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(run_dataplane(
                        &config,
                        (logic_factory)(WorkerContext {
                            shard_index: worker_context.shard_index,
                            shard_count: worker_context.shard_count,
                            output: worker_context.output.clone(),
                        }),
                        &mut command_rx,
                        &thread_queued_commands,
                        &thread_shutdown,
                        &thread_cancel_token,
                        was_first_attempt.then_some(&startup_tx),
                    ))
                }));
                let failure = match attempt {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(format!("{error:#}")),
                    Err(panic) => {
                        let message = panic_message(panic);
                        if was_first_attempt {
                            let _ = startup_tx.send(Err(anyhow!("dataplane panicked: {message}")));
                        }
                        Some(message)
                    }
                };
                let Some(failure) = failure else {
                    break Ok(());
                };
                if thread_shutdown.load(Ordering::Acquire) {
                    break Ok(());
                }
                if was_first_attempt {
                    break Err(anyhow!(failure));
                }
                if attempt_started.elapsed() >= HEALTHY_UPTIME {
                    backoff_ms = RESTART_BACKOFF_INITIAL_MS;
                }
                eprintln!("[DATAPLANE] dataplane failed, restarting in {backoff_ms}ms: {failure}");
                sleep_backoff(Duration::from_millis(backoff_ms), &thread_shutdown);
                if thread_shutdown.load(Ordering::Acquire) {
                    break Ok(());
                }
                backoff_ms = backoff_ms.saturating_mul(2).min(RESTART_BACKOFF_MAX_MS);
            };
            let status = match &result {
                Ok(()) => "tokio dataplane stopped".to_owned(),
                Err(error) => format!("tokio dataplane failed: {error:#}"),
            };
            let _ = status_tx.send(Some(status));
            result
        })
        .context("spawn tokio dataplane")?;
    match startup_rx.recv().context("wait dataplane startup")? {
        Ok(()) => Ok(DataplaneRuntime {
            handle,
            join: Some(join),
            status: status_rx,
        }),
        Err(error) => {
            let _ = join.join();
            Err(error)
        }
    }
}

fn spawn_sharded<L, F>(
    config: DataplaneConfig,
    logic_factory: F,
) -> Result<DataplaneRuntime<L::Command>>
where
    L: DataplaneLogic,
    F: Fn(WorkerContext<L::Command>) -> L + Send + Sync + 'static,
{
    let command_capacity = config.command_capacity.max(16);
    let queued_commands = Arc::new(AtomicUsize::new(0));
    let (command_tx, command_rx) = async_mpsc::channel(command_capacity);
    let cancel_token = CancellationToken::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = DataplaneHandle {
        inner: Arc::new(HandleInner {
            sender: command_tx,
            cancel_token: cancel_token.clone(),
            shutdown_flag: shutdown.clone(),
            queued_commands: queued_commands.clone(),
            command_capacity,
        }),
    };
    let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<()>>(1);
    let (status_tx, status_rx) = tokio::sync::watch::channel(None::<String>);
    let thread_shutdown = shutdown.clone();
    let thread_queued_commands = queued_commands;
    let thread_cancel_token = cancel_token.clone();
    let factory = Arc::new(logic_factory);
    let join = std::thread::Builder::new()
        .name("csqtt-io-router".to_owned())
        .stack_size(DATAPLANE_STACK_BYTES)
        .spawn(move || {
            let mut command_rx = command_rx;
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ =
                        startup_tx
                            .send(Err(anyhow::Error::new(error)
                                .context("create tokio I/O router runtime")));
                    let _ = status_tx.send(Some("tokio I/O router failed".to_owned()));
                    return Err(anyhow!("create tokio I/O router runtime"));
                }
            };
            let mut first_attempt = true;
            let mut backoff_ms = RESTART_BACKOFF_INITIAL_MS;
            let result = loop {
                let attempt_started = Instant::now();
                let was_first_attempt = first_attempt;
                first_attempt = false;
                let attempt = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(run_sharded_dataplane(
                        &config,
                        factory.clone(),
                        &mut command_rx,
                        &thread_queued_commands,
                        &thread_shutdown,
                        &thread_cancel_token,
                        was_first_attempt.then_some(&startup_tx),
                    ))
                }));
                let failure = match attempt {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(format!("{error:#}")),
                    Err(panic) => {
                        let message = panic_message(panic);
                        if was_first_attempt {
                            let _ = startup_tx.send(Err(anyhow!("I/O router panicked: {message}")));
                        }
                        Some(message)
                    }
                };
                let Some(failure) = failure else {
                    break Ok(());
                };
                if thread_shutdown.load(Ordering::Acquire) {
                    break Ok(());
                }
                if was_first_attempt {
                    break Err(anyhow!(failure));
                }
                if attempt_started.elapsed() >= HEALTHY_UPTIME {
                    backoff_ms = RESTART_BACKOFF_INITIAL_MS;
                }
                eprintln!("[DATAPLANE] I/O router failed, restarting in {backoff_ms}ms: {failure}");
                sleep_backoff(Duration::from_millis(backoff_ms), &thread_shutdown);
                if thread_shutdown.load(Ordering::Acquire) {
                    break Ok(());
                }
                backoff_ms = backoff_ms.saturating_mul(2).min(RESTART_BACKOFF_MAX_MS);
            };
            let status = match &result {
                Ok(()) => "tokio sharded dataplane stopped".to_owned(),
                Err(error) => format!("tokio sharded dataplane failed: {error:#}"),
            };
            let _ = status_tx.send(Some(status));
            result
        })
        .context("spawn sharded dataplane I/O router")?;
    match startup_rx
        .recv()
        .context("wait sharded dataplane startup")?
    {
        Ok(()) => Ok(DataplaneRuntime {
            handle,
            join: Some(join),
            status: status_rx,
        }),
        Err(error) => {
            let _ = join.join();
            Err(error)
        }
    }
}

async fn run_sharded_dataplane<L, F>(
    config: &DataplaneConfig,
    logic_factory: Arc<F>,
    command_rx: &mut async_mpsc::Receiver<RuntimeCommand<L::Command>>,
    queued_commands: &AtomicUsize,
    shutdown: &AtomicBool,
    cancel_token: &CancellationToken,
    startup_tx: Option<&mpsc::SyncSender<Result<()>>>,
) -> Result<()>
where
    L: DataplaneLogic,
    F: Fn(WorkerContext<L::Command>) -> L + Send + Sync + 'static,
{
    let mut io = match TokioIo::new(config.listen, &config.tun_iface, &config.tun_addr).await {
        Ok(io) => io,
        Err(error) => {
            if let Some(startup_tx) = startup_tx {
                let _ = startup_tx.send(Err(clone_anyhow(&error)));
            }
            return Err(error);
        }
    };
    let shard_count = config.shards.clamp(2, MAX_DATAPLANE_SHARDS);
    let mut input_txs = Vec::with_capacity(shard_count);
    let mut output_rxs = Vec::with_capacity(shard_count);
    let mut worker_joins = Vec::with_capacity(shard_count);
    for shard_index in 0..shard_count {
        let (input_tx, input_rx) = async_mpsc::channel(SHARD_INPUT_CAPACITY);
        let (output_tx, output_rx) = async_mpsc::channel(SHARD_OUTPUT_CAPACITY);
        let worker_cancel = cancel_token.clone();
        let worker_factory = logic_factory.clone();
        let context = WorkerContext {
            shard_index,
            shard_count,
            output: output_tx.clone(),
        };
        let join = std::thread::Builder::new()
            .name(format!("csqtt-data-{shard_index}"))
            .stack_size(DATAPLANE_STACK_BYTES)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("create tokio dataplane shard runtime")?;
                runtime.block_on(run_dataplane_worker(
                    worker_factory(context),
                    input_rx,
                    output_tx,
                    worker_cancel,
                ))
            })
            .context("spawn dataplane shard")?;
        input_txs.push(input_tx);
        output_rxs.push(output_rx);
        worker_joins.push(join);
    }
    eprintln!("[DATAPLANE] sharded I/O: 1 router + {shard_count} session workers");
    if let Some(startup_tx) = startup_tx {
        let _ = startup_tx.send(Ok(()));
    }
    let mut endpoint_shards = HashMap::<EndpointRoute, usize>::new();
    let mut tunnel_shards = [None; 256];
    let mut pending_router = VecDeque::<RouterCommand<L::Command>>::new();
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_INTERVAL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut consecutive_udp_passes = 0u32;
    let mut failure = None;

    'router: while !shutdown.load(Ordering::Acquire) && !cancel_token.is_cancelled() {
        drain_router_commands(
            &mut pending_router,
            &input_txs,
            &mut endpoint_shards,
            &mut tunnel_shards,
        );
        drain_worker_outputs(
            &mut io,
            &mut output_rxs,
            &mut pending_router,
            &input_txs,
            &mut endpoint_shards,
            &mut tunnel_shards,
        );
        let udp_pending = io.pending_udp_tx_len() != 0;
        let tun_pending = io.pending_tun_tx_len() != 0;
        let udp_throttled = consecutive_udp_passes >= MAX_CONSECUTIVE_UDP_PASSES;
        let udp_read = io.udp.readable();
        let tun_read = io.tun.readable();
        let udp_write = io.udp.writable();
        let tun_write = io.tun.writable();
        tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            _ = tick.tick() => {
                consecutive_udp_passes = 0;
                let counters = io.counters_snapshot();
                if let Some(input) = input_txs.first() {
                    let _ = input.try_send(WorkerInput::IoCounters(counters));
                }
            }
            command = command_rx.recv() => {
                consecutive_udp_passes = 0;
                match command {
                    Some(RuntimeCommand::Logic(command)) => {
                        decrement_queue_len(queued_commands);
                        for (index, command) in L::fanout_command(command, shard_count).into_iter().enumerate() {
                            if let Some(input) = input_txs.get(index % shard_count) {
                                let _ = input.try_send(WorkerInput::Command(command));
                            }
                        }
                    }
                    Some(RuntimeCommand::Shutdown) | None => break,
                }
            }
            _ = udp_read, if !udp_throttled => {
                consecutive_udp_passes = consecutive_udp_passes.saturating_add(1);
                io.note_readiness_wakeup();
                let mut processed = 0usize;
                while processed < MAX_RX_PER_PASS {
                    match io.dispatch_udp_rx(MAX_RX_PER_PASS - processed, &mut |peer, local_ip, packet, _| {
                        let mut forwarded = PacketBuffer::new();
                        if !forwarded.copy_from(packet) {
                            return;
                        }
                        let endpoint = EndpointRoute::new(peer, local_ip);
                        let shard = endpoint_shards.get(&endpoint).copied().unwrap_or(0);
                        let _ = input_txs[shard].try_send(WorkerInput::Udp { peer, local_ip, packet: forwarded });
                    }) {
                        RxOutcome::Batch(batch) => processed += batch,
                        RxOutcome::Drained => break,
                    }
                }
            }
            _ = tun_read => {
                consecutive_udp_passes = 0;
                io.note_readiness_wakeup();
                let mut processed = 0usize;
                while processed < TUN_RX_DRAIN_BATCH {
                    match io.read_tun_rx(&mut |packet, _| {
                        let mut forwarded = PacketBuffer::new();
                        if !forwarded.copy_from(packet) {
                            return;
                        }
                        let shard = crate::packet::extract_dst_ipv4(packet)
                            .and_then(|ip| (ip[..3] == [10, 66, 67]).then_some(ip[3] as usize))
                            .and_then(|index| tunnel_shards[index])
                            .unwrap_or(0);
                        let _ = input_txs[shard].try_send(WorkerInput::Tun { packet: forwarded });
                    }) {
                        Ok(count) if count > 0 => processed += count,
                        Ok(_) => break,
                        Err(error) => {
                            failure = Some(anyhow!("TUN RX failed: {error:#}"));
                            break 'router;
                        }
                    }
                }
            }
            _ = udp_write, if udp_pending => io.flush_udp_tx(usize::MAX),
            _ = tun_write, if tun_pending => io.flush_tun_tx(),
        }
        if io.take_tun_fatal() {
            failure = Some(anyhow!("TUN write failed"));
            break;
        }
        if io.pending_udp_tx_len() != 0 {
            io.flush_udp_tx(usize::MAX);
        }
        if io.pending_tun_tx_len() != 0 {
            io.flush_tun_tx();
        }
        if io.take_tun_fatal() {
            failure = Some(anyhow!("TUN write failed"));
            break;
        }
    }
    for input in &input_txs {
        let _ = input.try_send(WorkerInput::Shutdown);
    }
    if io.pending_udp_tx_len() != 0 {
        io.flush_udp_tx(SHUTDOWN_FLUSH_SYSCALLS);
    }
    if io.pending_tun_tx_len() != 0 {
        io.flush_tun_tx();
    }
    for join in worker_joins {
        let _ = join.join();
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn run_dataplane_worker<L>(
    mut logic: L,
    mut input_rx: async_mpsc::Receiver<WorkerInput<L::Command>>,
    output: async_mpsc::Sender<WorkerOutput<L::Command>>,
    cancel_token: CancellationToken,
) -> Result<()>
where
    L: DataplaneLogic,
{
    perf::publish_dataplane_tid();
    let mut sink = RemotePacketSink {
        output,
        packet_pool: PacketPool::new(packet_pool_size()),
    };
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_INTERVAL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            _ = tick.tick() => {
                logic.begin_batch(Instant::now());
                logic.on_tick(&mut sink);
            }
            event = input_rx.recv() => match event {
                Some(WorkerInput::Udp { peer, local_ip, mut packet }) => {
                    logic.begin_batch(Instant::now());
                    logic.on_udp(peer, local_ip, packet.as_mut_slice(), &mut sink);
                }
                Some(WorkerInput::Tun { mut packet }) => {
                    logic.begin_batch(Instant::now());
                    logic.on_tun(packet.as_mut_slice(), &mut sink);
                    logic.on_tun_batch_end(&mut sink);
                }
                Some(WorkerInput::IoCounters(counters)) => logic.on_io_counters(counters),
                Some(WorkerInput::Command(command)) => {
                    logic.begin_batch(Instant::now());
                    logic.on_command(command, &mut sink);
                }
                Some(WorkerInput::Shutdown) | None => break,
            }
        }
    }
    Ok(())
}

fn drain_router_commands<C: Send + 'static>(
    pending: &mut VecDeque<RouterCommand<C>>,
    inputs: &[async_mpsc::Sender<WorkerInput<C>>],
    endpoints: &mut HashMap<EndpointRoute, usize>,
    tunnels: &mut [Option<usize>; 256],
) {
    let mut remaining = pending.len();
    while remaining != 0 {
        remaining -= 1;
        let Some(command) = pending.pop_front() else {
            break;
        };
        match command {
            RouterCommand::BindEndpoint { endpoint, shard } => {
                endpoints.insert(endpoint, shard);
            }
            RouterCommand::BindTunnel { ip, shard } => {
                if ip[..3] == [10, 66, 67] {
                    tunnels[ip[3] as usize] = Some(shard);
                }
            }
            RouterCommand::Migrate {
                endpoint,
                shard,
                command,
            } => {
                if let Some(input) = inputs.get(shard) {
                    match input.try_send(WorkerInput::Command(command)) {
                        Ok(()) => {
                            endpoints.insert(endpoint, shard);
                        }
                        Err(async_mpsc::error::TrySendError::Full(WorkerInput::Command(
                            command,
                        )))
                        | Err(async_mpsc::error::TrySendError::Closed(WorkerInput::Command(
                            command,
                        ))) => {
                            pending.push_back(RouterCommand::Migrate {
                                endpoint,
                                shard,
                                command,
                            });
                        }
                        Err(_) => unreachable!(),
                    }
                }
            }
        }
    }
}

fn drain_worker_outputs<C: Send + 'static>(
    io: &mut TokioIo,
    outputs: &mut [async_mpsc::Receiver<WorkerOutput<C>>],
    pending_router: &mut VecDeque<RouterCommand<C>>,
    inputs: &[async_mpsc::Sender<WorkerInput<C>>],
    endpoints: &mut HashMap<EndpointRoute, usize>,
    tunnels: &mut [Option<usize>; 256],
) {
    for output in outputs {
        for _ in 0..SHARD_OUTPUT_DRAIN_LIMIT {
            let value = match output.try_recv() {
                Ok(value) => value,
                Err(_) => break,
            };
            match value {
                WorkerOutput::Udp {
                    peer,
                    source_ip,
                    class,
                    buffer,
                } => {
                    io.with_sink(|sink| {
                        let _ = sink.send_prebuilt_udp(peer, source_ip, buffer, class);
                    });
                }
                WorkerOutput::Tun { class, buffer } => {
                    io.with_sink(|sink| {
                        let _ = sink.write_prebuilt_tun(buffer, class);
                    });
                }
                WorkerOutput::FlushUdp => io.flush_udp_tx(1),
                WorkerOutput::Router(command) => pending_router.push_back(command),
            }
        }
    }
    drain_router_commands(pending_router, inputs, endpoints, tunnels);
}

async fn run_dataplane<L>(
    config: &DataplaneConfig,
    mut logic: L,
    command_rx: &mut async_mpsc::Receiver<RuntimeCommand<L::Command>>,
    queued_commands: &AtomicUsize,
    shutdown: &AtomicBool,
    cancel_token: &CancellationToken,
    startup_tx: Option<&mpsc::SyncSender<Result<()>>>,
) -> Result<()>
where
    L: DataplaneLogic,
{
    let mut io = match TokioIo::new(config.listen, &config.tun_iface, &config.tun_addr).await {
        Ok(io) => io,
        Err(error) => {
            if let Some(startup_tx) = startup_tx {
                let _ = startup_tx.send(Err(clone_anyhow(&error)));
            }
            return Err(error);
        }
    };
    perf::publish_dataplane_tid();
    if let Some(startup_tx) = startup_tx {
        let _ = startup_tx.send(Ok(()));
    }
    let mut profiler = Profiler::default();
    let mut last_counters = io.counters_snapshot();
    let mut last_report_packets = 0u64;
    let mut publish_perf = false;
    let mut consecutive_udp_passes = 0u32;
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_INTERVAL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !shutdown.load(Ordering::Acquire) && !cancel_token.is_cancelled() {
        let udp_pending = io.pending_udp_tx_len() != 0;
        let tun_pending = io.pending_tun_tx_len() != 0;
        let udp_throttled = consecutive_udp_passes >= MAX_CONSECUTIVE_UDP_PASSES;
        let udp_read = io.udp.readable();
        let tun_read = io.tun.readable();
        let udp_write = io.udp.writable();
        let tun_write = io.tun.writable();
        tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            _ = tick.tick() => {
                consecutive_udp_passes = 0;
                profiler.refresh_enabled();
                if profiler.enabled() {
                    perf::publish_dataplane_cpu(thread_cpu_time_ns());
                }
                let dispatch_started = profiler.begin(Stage::Dispatch, 0);
                logic.begin_batch(Instant::now());
                io.with_sink(|sink| logic.on_tick(sink));
                logic.on_io_counters(io.counters_snapshot());
                publish_perf = true;
                profiler.finish(Stage::Dispatch, dispatch_started);
            }
            command = command_rx.recv() => {
                consecutive_udp_passes = 0;
                let mut keep_running = true;
                match command {
                    Some(RuntimeCommand::Logic(command)) => {
                        decrement_queue_len(queued_commands);
                        let dispatch_started = profiler.begin(Stage::Dispatch, 0);
                        logic.begin_batch(Instant::now());
                        io.with_sink(|sink| logic.on_command(command, sink));
                        profiler.finish(Stage::Dispatch, dispatch_started);
                    }
                    Some(RuntimeCommand::Shutdown) => keep_running = false,
                    None => keep_running = false,
                }
                if keep_running {
                    for _ in 0..COMMAND_DRAIN_LIMIT {
                        match command_rx.try_recv() {
                            Ok(RuntimeCommand::Logic(command)) => {
                                decrement_queue_len(queued_commands);
                                let dispatch_started = profiler.begin(Stage::Dispatch, 0);
                                logic.begin_batch(Instant::now());
                                io.with_sink(|sink| logic.on_command(command, sink));
                                profiler.finish(Stage::Dispatch, dispatch_started);
                            }
                            Ok(RuntimeCommand::Shutdown) => {
                                keep_running = false;
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }
                if !keep_running {
                    break;
                }
            }
            _ = udp_read, if !udp_throttled => {
                consecutive_udp_passes = consecutive_udp_passes.saturating_add(1);
                io.note_readiness_wakeup();
                logic.begin_batch(Instant::now());
                let started = profiler.begin(Stage::UdpRx, 0);
                let mut processed = 0usize;
                while processed < MAX_RX_PER_PASS {
                    match io.dispatch_udp_rx(MAX_RX_PER_PASS - processed, &mut |peer, local_ip, packet, sink| {
                        logic.on_udp(peer, local_ip, packet, sink)
                    }) {
                        RxOutcome::Batch(batch) => processed += batch,
                        RxOutcome::Drained => break,
                    }
                }
                profiler.expand_batch(Stage::UdpRx, processed as u64, 0, started.is_some());
                profiler.finish(Stage::UdpRx, started);
            }
            _ = tun_read => {
                consecutive_udp_passes = 0;
                io.note_readiness_wakeup();
                logic.begin_batch(Instant::now());
                let started = profiler.begin(Stage::TunRx, 0);
                let mut processed = 0usize;
                while processed < TUN_RX_DRAIN_BATCH {
                    match io.read_tun_rx(&mut |packet, sink| logic.on_tun(packet, sink)) {
                        Ok(count) if count > 0 => processed += count,
                        Ok(_) => break,
                        Err(error) => {
                            return Err(anyhow!("TUN RX failed: {error:#}"));
                        }
                    }
                }
                io.with_sink(|sink| logic.on_tun_batch_end(sink));
                profiler.expand_batch(Stage::TunRx, processed as u64, 0, started.is_some());
                profiler.finish(Stage::TunRx, started);
            }
            _ = udp_write, if udp_pending => {
                io.flush_udp_tx(usize::MAX);
            }
            _ = tun_write, if tun_pending => {
                io.flush_tun_tx();
            }
        }
        if io.take_tun_fatal() {
            return Err(anyhow!("TUN write failed"));
        }
        let pending_udp_tx = io.pending_udp_tx_len();
        if pending_udp_tx != 0 {
            let flush_started = profiler.begin(Stage::Flush, pending_udp_tx);
            io.flush_udp_tx(usize::MAX);
            profiler.finish(Stage::Flush, flush_started);
        }
        let pending_tun_tx = io.pending_tun_tx_len();
        if pending_tun_tx != 0 {
            io.flush_tun_tx();
        }
        if io.take_tun_fatal() {
            return Err(anyhow!("TUN write failed"));
        }
        let bookkeeping_started = profiler.begin(Stage::Bookkeeping, 0);
        let counters = io.counters_snapshot();
        let total_rx = counters
            .udp_rx_packets
            .saturating_add(counters.tun_rx_packets);
        let report_due = total_rx.saturating_sub(last_report_packets) >= 1024
            || counters.udp_tx_errors != last_counters.udp_tx_errors
            || counters.tun_tx_errors != last_counters.tun_tx_errors
            || counters.udp_rx_errors != last_counters.udp_rx_errors
            || counters.tun_rx_errors != last_counters.tun_rx_errors;
        if report_due {
            logic.on_io_counters(counters);
            last_counters = counters;
            last_report_packets = total_rx;
        }
        profiler.finish(Stage::Bookkeeping, bookkeeping_started);
        if publish_perf {
            publish_perf = false;
            profiler.publish_dataplane();
        }
    }
    if io.pending_udp_tx_len() != 0 {
        io.flush_udp_tx(SHUTDOWN_FLUSH_SYSCALLS);
    }
    if io.pending_tun_tx_len() != 0 {
        io.flush_tun_tx();
    }
    Ok(())
}

fn sleep_backoff(total: Duration, shutdown: &AtomicBool) {
    let deadline = Instant::now() + total;
    while !shutdown.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn panic_message(panic: Box<dyn Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_owned()
    }
}

fn clone_anyhow(error: &anyhow::Error) -> anyhow::Error {
    anyhow!(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_migrates_before_routing_an_endpoint_to_its_owner() {
        let (input, mut received) = async_mpsc::channel(1);
        let endpoint = EndpointRoute::new("127.0.0.1:46000".parse().unwrap(), None);
        let mut pending = VecDeque::from([RouterCommand::Migrate {
            endpoint,
            shard: 0,
            command: 77u64,
        }]);
        let mut endpoints = HashMap::new();
        let mut tunnels = [None; 256];
        drain_router_commands(&mut pending, &[input], &mut endpoints, &mut tunnels);
        assert!(pending.is_empty());
        assert_eq!(endpoints.get(&endpoint), Some(&0));
        match received.try_recv() {
            Ok(WorkerInput::Command(command)) => assert_eq!(command, 77),
            _ => panic!("migration command was not delivered"),
        }
    }

    #[test]
    fn router_keeps_tunnel_ownership_in_the_csqtt_subnet_only() {
        let mut pending = VecDeque::from([
            RouterCommand::<u64>::BindTunnel {
                ip: [10, 66, 67, 91],
                shard: 3,
            },
            RouterCommand::BindTunnel {
                ip: [192, 0, 2, 91],
                shard: 2,
            },
        ]);
        let mut endpoints = HashMap::new();
        let mut tunnels = [None; 256];
        drain_router_commands(&mut pending, &[], &mut endpoints, &mut tunnels);
        assert_eq!(tunnels[91], Some(3));
        assert!(pending.is_empty());
    }

    #[test]
    fn remote_sink_transfers_the_prebuilt_packet_without_a_second_copy() {
        let (output, mut received) = async_mpsc::channel(2);
        let mut sink = RemotePacketSink::<u8> {
            output,
            packet_pool: PacketPool::new(2),
        };
        assert!(sink.send_udp_with_duplicate_priority(
            "127.0.0.1:46000".parse().unwrap(),
            None,
            false,
            PacketClass::Bulk,
            |buffer| buffer.copy_from(b"dataplane"),
        ));
        match received.try_recv() {
            Ok(WorkerOutput::Udp { buffer, .. }) => assert_eq!(buffer.as_slice(), b"dataplane"),
            _ => panic!("prebuilt UDP packet was not delivered"),
        }
    }

    #[test]
    fn distinct_devices_route_to_multiple_session_workers() {
        const SHARDS: usize = 11;
        const DEVICES: usize = 96;

        let mut inputs = Vec::with_capacity(SHARDS);
        let mut receivers = Vec::with_capacity(SHARDS);
        for _ in 0..SHARDS {
            let (input, receiver) = async_mpsc::channel(DEVICES);
            inputs.push(input);
            receivers.push(receiver);
        }
        let mut pending = VecDeque::new();
        let mut expected = HashMap::new();
        for index in 0..DEVICES {
            let endpoint = EndpointRoute::new(
                SocketAddr::from(([127, 0, 0, 1], 40_000 + index as u16)),
                None,
            );
            let device = format!("independent-device-{index}");
            let shard = crate::protocol::shard_for_device(&device, SHARDS);
            expected.insert(endpoint, shard);
            pending.push_back(RouterCommand::Migrate {
                endpoint,
                shard,
                command: index,
            });
        }
        let mut endpoints = HashMap::new();
        let mut tunnels = [None; 256];
        drain_router_commands(&mut pending, &inputs, &mut endpoints, &mut tunnels);

        assert!(pending.is_empty());
        assert_eq!(endpoints, expected);
        let active_workers = receivers
            .iter_mut()
            .map(|receiver| receiver.try_recv().is_ok())
            .filter(|active| *active)
            .count();
        assert!(active_workers > 1);
    }
}
