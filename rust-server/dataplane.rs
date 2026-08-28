// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    net_setup::{TUN_ADDR, TUN_IFACE},
    perf::{self, Profiler, Stage, thread_cpu_time_ns},
    tokio_io::{
        IoCounters, MAX_RX_PER_PASS, PacketSink, RxOutcome, TICK_INTERVAL_MS, TUN_RX_DRAIN_BATCH,
        TokioIo,
    },
};
use anyhow::{Context, Result, anyhow};
use std::{
    any::Any,
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

pub trait DataplaneLogic: Send + 'static {
    type Command: Send + 'static;

    fn on_udp(
        &mut self,
        peer: SocketAddr,
        local_ip: Option<IpAddr>,
        packet: &mut [u8],
        sink: &mut PacketSink<'_>,
    );
    fn on_tun(&mut self, packet: &mut [u8], sink: &mut PacketSink<'_>);
    fn on_tun_batch_end(&mut self, _sink: &mut PacketSink<'_>) {}
    fn begin_batch(&mut self, now: Instant);
    fn on_command(&mut self, command: Self::Command, sink: &mut PacketSink<'_>);
    fn on_tick(&mut self, sink: &mut PacketSink<'_>);
    fn on_io_counters(&mut self, counters: IoCounters);
}

pub struct DataplaneConfig {
    pub listen: SocketAddr,
    pub tun_iface: String,
    pub tun_addr: String,
    pub command_capacity: usize,
}

impl DataplaneConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            tun_iface: TUN_IFACE.to_owned(),
            tun_addr: TUN_ADDR.to_owned(),
            command_capacity: 4096,
        }
    }
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
    F: Fn() -> L + Send + 'static,
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
    let join = std::thread::Builder::new()
        .name("csqtt-dataplane".to_owned())
        .spawn(move || {
            let mut command_rx = command_rx;
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
                        (logic_factory)(),
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
