// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    client_perf::{self, Stage as PerfStage},
    flow_frame::{self, FlowSequencer},
    packet::{PacketBuf, PacketPool},
    stats::Stats,
    striped_scheduler::{DispatchTicket, PacketClass, packet_class},
    tun, udp_batch,
};
use anyhow::Result;
use arc_swap::{ArcSwap, ArcSwapOption};
use crossbeam_queue::ArrayQueue;
use socket2::SockRef;
use std::{
    collections::VecDeque,
    fs::File,
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use tokio::time::Instant;

const RETURN_CAPACITY: usize = 1024;
const RETURN_LATENCY_CAPACITY: usize = 128;
const RETURN_PRIORITY_CAPACITY: usize = 384;
const RETURN_BULK_CAPACITY: usize =
    RETURN_CAPACITY - RETURN_LATENCY_CAPACITY - RETURN_PRIORITY_CAPACITY;
pub(crate) const CLIENT_WORKER_PACKET_CHUNK: usize =
    crate::striped_scheduler::BULK_STREAM_STRIPE_PACKET_CHUNK;

const QUEUE_ACTIVE: u64 = 1;

#[cfg(unix)]
enum TunWriteState {
    Complete,
    Continue,
    Wait,
    Backoff,
    Yield,
    Closed,
    Failed,
}

struct ReturnReorder {
    reassembler: flow_frame::FlowReassembler<PacketBuf>,
    ready: VecDeque<PacketBuf>,
}

impl ReturnReorder {
    fn new() -> Self {
        Self {
            reassembler: flow_frame::FlowReassembler::new(),
            ready: VecDeque::with_capacity(64),
        }
    }

    fn push(&mut self, mut packet: PacketBuf) {
        if let Some((header, _)) = flow_frame::FrameHeader::decode(packet.as_slice()) {
            if packet.trim_front(flow_frame::FRAME_LEN).is_ok() {
                self.reassembler.push(header, packet, &mut self.ready);
            }
        } else {
            self.ready.push_back(packet);
        }
    }

    fn pop(&mut self) -> Option<PacketBuf> {
        self.ready.pop_front()
    }
}

fn frame_outbound_packet(sequences: &mut FlowSequencer, packet: &mut PacketBuf) -> bool {
    let Some(header) = sequences.next(packet.as_slice()) else {
        return true;
    };
    let Ok(prefix) = packet.prepend(flow_frame::FRAME_LEN) else {
        return false;
    };
    header.encode(prefix)
}

#[derive(Clone, Copy, Default)]
struct RoundRobinCursor {
    current_worker: usize,
    remaining: usize,
}

#[derive(Default)]
struct FastPathScheduler {
    workers: Arc<Vec<WorkerChannels>>,
    worker_count: usize,
    cursors: [RoundRobinCursor; 3],
}

impl FastPathScheduler {
    fn new() -> Self {
        Self {
            workers: Arc::new(Vec::new()),
            worker_count: 0,
            cursors: [RoundRobinCursor::default(); 3],
        }
    }

    #[inline(always)]
    fn begin(
        &mut self,
        source: &ArcSwap<Vec<WorkerChannels>>,
        packet: &[u8],
    ) -> Option<DispatchTicket> {
        let class = packet_class(packet);
        if self.cursors[class.index()].remaining == 0 {
            self.workers = source.load_full();
            self.sync_worker_count(self.workers.len());
        }
        self.begin_for_class(self.worker_count, class)
    }

    #[inline(always)]
    fn begin_with_count(&mut self, worker_count: usize, packet: &[u8]) -> Option<DispatchTicket> {
        self.begin_for_class(worker_count, packet_class(packet))
    }

    #[inline(always)]
    fn begin_for_class(
        &mut self,
        worker_count: usize,
        class: PacketClass,
    ) -> Option<DispatchTicket> {
        if worker_count == 0 {
            return None;
        }
        if self.worker_count != worker_count {
            self.sync_worker_count(worker_count);
        }
        let cursor = &mut self.cursors[class.index()];
        if cursor.remaining == 0 {
            cursor.remaining = class.stream_chunk();
        }
        let start_slot = cursor.current_worker;
        cursor.remaining -= 1;
        if cursor.remaining == 0 {
            cursor.current_worker += 1;
            if cursor.current_worker == worker_count {
                cursor.current_worker = 0;
            }
        }
        Some(DispatchTicket { start_slot, class })
    }

    #[inline(always)]
    fn workers(&self) -> &[WorkerChannels] {
        &self.workers
    }

    #[inline(always)]
    fn sync_worker_count(&mut self, worker_count: usize) {
        if self.worker_count != worker_count {
            self.worker_count = worker_count;
            self.cursors = [RoundRobinCursor::default(); 3];
        }
    }
}

struct QueuedPacket {
    packet: PacketBuf,
    epoch: u64,
}

struct PacketQueue {
    queue: ArrayQueue<QueuedPacket>,
    notify: Notify,
    state: AtomicU64,
    senders: AtomicUsize,
    receiver_open: AtomicBool,
}

pub struct PacketSender {
    shared: Arc<PacketQueue>,
}

pub struct PacketReceiver {
    shared: Arc<PacketQueue>,
}

impl Clone for PacketSender {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for PacketSender {
    fn drop(&mut self) {
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.notify.notify_waiters();
        }
    }
}

impl PacketSender {
    pub fn try_send(&self, packet: PacketBuf) -> std::result::Result<(), PacketBuf> {
        self.send(packet, false)
    }

    pub fn force_send(&self, packet: PacketBuf) -> std::result::Result<(), PacketBuf> {
        self.send(packet, true)
    }

    fn send(&self, packet: PacketBuf, force: bool) -> std::result::Result<(), PacketBuf> {
        client_perf::measure_sampled(PerfStage::PacketQueue, 128, || {
            self.send_inner(packet, force)
        })
    }

    fn send_inner(&self, packet: PacketBuf, force: bool) -> std::result::Result<(), PacketBuf> {
        if !self.shared.receiver_open.load(Ordering::Acquire) {
            return Err(packet);
        }
        let state = self.shared.state.load(Ordering::Acquire);
        if state & QUEUE_ACTIVE == 0 {
            return Err(packet);
        }
        let queued = QueuedPacket {
            packet,
            epoch: state >> 1,
        };
        if force {
            drop(self.shared.queue.force_push(queued));
        } else if let Err(queued) = self.shared.queue.push(queued) {
            return Err(queued.packet);
        }
        self.shared.notify.notify_one();
        Ok(())
    }
}

impl PacketReceiver {
    pub fn try_recv(&self) -> Option<PacketBuf> {
        client_perf::measure_sampled(PerfStage::PacketQueue, 128, || self.try_recv_inner())
    }

    fn try_recv_inner(&self) -> Option<PacketBuf> {
        loop {
            let queued = self.shared.queue.pop()?;
            let state = self.shared.state.load(Ordering::Acquire);
            if state & QUEUE_ACTIVE != 0 && queued.epoch == state >> 1 {
                return Some(queued.packet);
            }
        }
    }

    pub async fn recv(&self, cancel: &CancellationToken) -> Option<PacketBuf> {
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            if let Some(packet) = self.try_recv() {
                return Some(packet);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return None;
            }
            let notified = self.shared.notify.notified();
            if let Some(packet) = self.try_recv() {
                return Some(packet);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return None;
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return None,
                _ = notified => {}
            }
        }
    }

    fn resume(&self) {
        let previous = self.shared.state.load(Ordering::Acquire) >> 1;
        let epoch = previous.saturating_add(1);
        self.shared.state.store(epoch << 1, Ordering::Release);
        self.purge();
        self.shared
            .state
            .store((epoch << 1) | QUEUE_ACTIVE, Ordering::Release);
        self.shared.notify.notify_waiters();
    }

    fn suspend(&self) {
        let state = self.shared.state.load(Ordering::Acquire);
        self.shared
            .state
            .store(state & !QUEUE_ACTIVE, Ordering::Release);
        self.purge();
        self.shared.notify.notify_waiters();
    }

    fn purge(&self) {
        while self.shared.queue.pop().is_some() {}
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.shared.senders.load(Ordering::Acquire) == 0 && self.shared.queue.is_empty()
    }

    pub(crate) fn has_queued_packet(&self) -> bool {
        !self.shared.queue.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shared.queue.len()
    }
}

impl Drop for PacketReceiver {
    fn drop(&mut self) {
        self.shared.receiver_open.store(false, Ordering::Release);
        self.purge();
        self.shared.notify.notify_waiters();
    }
}

pub fn packet_channel(capacity: usize, active: bool) -> (PacketSender, PacketReceiver) {
    let state = u64::from(active) * QUEUE_ACTIVE;
    let shared = Arc::new(PacketQueue {
        queue: ArrayQueue::new(capacity.max(1)),
        notify: Notify::new(),
        state: AtomicU64::new(state),
        senders: AtomicUsize::new(1),
        receiver_open: AtomicBool::new(true),
    });
    (
        PacketSender {
            shared: shared.clone(),
        },
        PacketReceiver { shared },
    )
}

#[derive(Clone)]
pub struct WorkerChannels {
    pub id: usize,
    pub incarnation_id: u64,
    pub turn_path: Arc<str>,
    pub latency: PacketSender,
    pub priority: PacketSender,
    pub bulk: PacketSender,
}

fn interleave_turn_paths(workers: &mut Vec<WorkerChannels>) {
    workers.sort_unstable_by(|left, right| {
        left.turn_path
            .cmp(&right.turn_path)
            .then_with(|| left.id.cmp(&right.id))
    });
    let sorted = std::mem::take(workers);
    let mut groups = Vec::<Vec<WorkerChannels>>::new();
    for worker in sorted {
        if let Some(group) = groups.last_mut()
            && group
                .first()
                .is_some_and(|first| first.turn_path == worker.turn_path)
        {
            group.push(worker);
        } else {
            groups.push(vec![worker]);
        }
    }
    for offset in 0usize.. {
        let mut added = false;
        for group in &groups {
            if let Some(worker) = group.get(offset) {
                workers.push(worker.clone());
                added = true;
            }
        }
        if !added {
            return;
        }
    }
}

pub struct Dispatcher {
    workers: ArcSwap<Vec<WorkerChannels>>,
    return_latency_tx: PacketSender,
    return_priority_tx: PacketSender,
    return_tx: PacketSender,
    cancel: CancellationToken,
    tasks: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
}

impl Dispatcher {
    #[cfg(all(test, unix))]
    pub async fn start_test_tun(
        file: File,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let (return_latency_tx, mut return_latency_rx) =
            packet_channel(RETURN_LATENCY_CAPACITY, true);
        let (return_priority_tx, mut return_priority_rx) =
            packet_channel(RETURN_PRIORITY_CAPACITY, true);
        let (return_tx, mut return_rx) = packet_channel(RETURN_BULK_CAPACITY, true);
        let dispatcher = Arc::new(Self {
            workers: ArcSwap::from_pointee(Vec::new()),
            return_latency_tx,
            return_priority_tx,
            return_tx,
            cancel: cancel.clone(),
            tasks: tokio::sync::Mutex::new(Vec::new()),
        });
        let io_dispatcher = dispatcher.clone();
        let task = spawn_critical("test TUN dispatcher", cancel, async move {
            let (fd_tx, mut fd_rx) = mpsc::channel(1);
            io_dispatcher
                .run_tun(
                    file,
                    &mut return_latency_rx,
                    &mut return_priority_rx,
                    &mut return_rx,
                    pool,
                    stats,
                    &mut fd_rx,
                )
                .await;
            drop(fd_tx);
        });
        dispatcher.tasks.lock().await.push(task);
        dispatcher
    }

    pub async fn start(
        listen: &str,
        tun_uds: Option<String>,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
        cancel: CancellationToken,
    ) -> Result<(Arc<Self>, String)> {
        let tun_mode = tun_uds.is_some();
        let (return_latency_tx, return_latency_rx) =
            packet_channel(RETURN_LATENCY_CAPACITY, !tun_mode);
        let (return_priority_tx, return_priority_rx) =
            packet_channel(RETURN_PRIORITY_CAPACITY, !tun_mode);
        let (return_tx, return_rx) = packet_channel(RETURN_BULK_CAPACITY, !tun_mode);
        let dispatcher = Arc::new(Self {
            workers: ArcSwap::from_pointee(Vec::new()),
            return_latency_tx,
            return_priority_tx,
            return_tx,
            cancel: cancel.clone(),
            tasks: tokio::sync::Mutex::new(Vec::new()),
        });
        if let Some(name) = tun_uds {
            crate::log_error!("[КЛИЕНТ] Запуск UDS-слушателя: {name} для получения TUN FD...");
            let receiver = tun::FdReceiver::bind(&name)?;
            let (fd_tx, mut fd_rx) = mpsc::channel(4);
            let receive_cancel = dispatcher.cancel.clone();
            let receive_task =
                spawn_critical("TUN FD receiver", receive_cancel.clone(), async move {
                    loop {
                        let file = match receiver.receive(&receive_cancel).await {
                            Ok(file) => file,
                            Err(_) if receive_cancel.is_cancelled() => return,
                            Err(error) => {
                                crate::log_error!(
                                    "[ОШИБКА] Не удалось получить TUN FD из UDS: {error}"
                                );
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        };
                        if fd_tx.send(file).await.is_err() {
                            return;
                        }
                    }
                });
            let io_dispatcher = dispatcher.clone();
            let task_cancel = dispatcher.cancel.clone();
            let io_task = spawn_critical("TUN dispatcher", task_cancel.clone(), async move {
                let mut return_latency_rx = return_latency_rx;
                let mut return_priority_rx = return_priority_rx;
                let mut return_rx = return_rx;
                while let Some(file) = tokio::select! {
                    _ = task_cancel.cancelled() => None,
                    file = fd_rx.recv() => file,
                } {
                    crate::log_error!("[КЛИЕНТ] TUN FD успешно получен!");
                    return_latency_rx.resume();
                    return_priority_rx.resume();
                    return_rx.resume();
                    io_dispatcher
                        .run_tun(
                            file,
                            &mut return_latency_rx,
                            &mut return_priority_rx,
                            &mut return_rx,
                            pool.clone(),
                            stats.clone(),
                            &mut fd_rx,
                        )
                        .await;
                }
            });
            dispatcher.tasks.lock().await.push(io_task);
            dispatcher.tasks.lock().await.push(receive_task);
            Ok((dispatcher, "0".to_owned()))
        } else {
            let socket = bind_udp(listen).await?;
            let local_port = socket.local_addr()?.port().to_string();
            let socket = Arc::new(socket);
            let client = Arc::new(ArcSwapOption::<SocketAddr>::from_pointee(None));
            let read_dispatcher = dispatcher.clone();
            let read_socket = socket.clone();
            let read_client = client.clone();
            let read_pool = pool.clone();
            let read_stats = stats.clone();
            let read_cancel = dispatcher.cancel.clone();
            let read_task = spawn_critical("UDP reader", read_cancel, async move {
                read_dispatcher
                    .read_udp(read_socket, read_client, read_pool, read_stats)
                    .await;
            });
            let write_dispatcher = dispatcher.clone();
            let write_cancel = dispatcher.cancel.clone();
            let write_task = spawn_critical("UDP writer", write_cancel, async move {
                write_dispatcher
                    .write_udp(
                        socket,
                        client,
                        return_latency_rx,
                        return_priority_rx,
                        return_rx,
                        stats,
                    )
                    .await;
            });
            dispatcher
                .tasks
                .lock()
                .await
                .extend([read_task, write_task]);
            Ok((dispatcher, local_port))
        }
    }

    pub fn register(&self, channels: WorkerChannels) {
        let id = channels.id;
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id);
            updated.push(channels.clone());
            interleave_turn_paths(&mut updated);
            Arc::new(updated)
        });
    }

    pub fn unregister(&self, id: usize, incarnation_id: u64) {
        self.workers.rcu(|workers| {
            let mut updated = (**workers).clone();
            updated.retain(|worker| worker.id != id || worker.incarnation_id != incarnation_id);
            interleave_turn_paths(&mut updated);
            Arc::new(updated)
        });
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.workers.load().len()
    }

    #[cfg(test)]
    pub fn worker(&self, id: usize) -> Option<WorkerChannels> {
        self.workers
            .load()
            .iter()
            .find(|worker| worker.id == id)
            .cloned()
    }

    pub fn return_packet(&self, packet: PacketBuf) {
        client_perf::measure_sampled(PerfStage::ReaderReturn, 64, || {
            let sender = match packet_class(packet.as_slice()) {
                PacketClass::Small => &self.return_latency_tx,
                PacketClass::Medium => &self.return_priority_tx,
                PacketClass::Bulk => &self.return_tx,
            };
            let _ = sender.force_send(packet);
        });
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        for task in self.tasks.lock().await.drain(..) {
            let _ = task.await;
        }
    }

    #[cfg(unix)]
    async fn run_tun(
        self: &Arc<Self>,
        initial_file: File,
        latency_receiver: &mut PacketReceiver,
        priority_receiver: &mut PacketReceiver,
        bulk_receiver: &mut PacketReceiver,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
        replacements: &mut mpsc::Receiver<File>,
    ) {
        use tokio::io::unix::AsyncFd;

        let mut file = initial_file;
        loop {
            let device = match AsyncFd::new(file) {
                Ok(device) => Arc::new(device),
                Err(error) => {
                    crate::log_error!("[ОШИБКА] Не удалось зарегистрировать TUN FD: {error}");
                    return;
                }
            };
            let received = tokio::select! {
                _ = self.cancel.cancelled() => return,
                replacement = replacements.recv() => replacement,
                _ = self.clone().read_tun(device.clone(), pool.clone(), stats.clone()) => None,
                _ = self.write_tun(device, latency_receiver, priority_receiver, bulk_receiver, stats.clone()) => None,
            };
            let next = match received {
                Some(file) => file,
                None => match tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    replacement = replacements.recv() => replacement,
                } {
                    Some(file) => file,
                    None => return,
                },
            };
            crate::log_error!("[КЛИЕНТ] TUN FD заменён без перезапуска потоков");
            file = next;
        }
    }

    #[cfg(not(unix))]
    async fn run_tun(
        self: &Arc<Self>,
        _file: File,
        _latency_receiver: &mut PacketReceiver,
        _priority_receiver: &mut PacketReceiver,
        _bulk_receiver: &mut PacketReceiver,
        _pool: Arc<PacketPool>,
        _stats: Arc<Stats>,
        _replacements: &mut mpsc::Receiver<File>,
    ) {
        crate::log_error!("[ОШИБКА] TUN FD поддерживается только на Android и Unix");
    }

    #[cfg(unix)]
    async fn read_tun(
        self: Arc<Self>,
        device: Arc<tokio::io::unix::AsyncFd<File>>,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
    ) {
        use std::os::fd::AsRawFd;

        let mut scheduler = FastPathScheduler::new();
        let mut flow_sequences = FlowSequencer::new();
        loop {
            let readiness = tokio::select! {
                _ = self.cancel.cancelled() => return,
                result = device.readable() => result,
            };
            let mut guard = match readiness {
                Ok(guard) => guard,
                Err(error) => {
                    crate::log_error!("[ОШИБКА] Ожидание чтения TUN завершено: {error}");
                    return;
                }
            };

            let mut burst = 0usize;
            while burst < 32 {
                let Some(mut packet) = pool.try_acquire() else {
                    break;
                };
                let result = client_perf::measure_sampled(PerfStage::TunRx, 64, || {
                    guard.try_io(|inner| {
                        let area = packet.read_area();
                        let length = unsafe {
                            libc::read(
                                inner.get_ref().as_raw_fd(),
                                area.as_mut_ptr().cast(),
                                area.len(),
                            )
                        };
                        if length < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(length as usize)
                        }
                    })
                });
                match result {
                    Ok(Ok(0)) => return,
                    Ok(Ok(length)) => {
                        burst += 1;
                        if packet.set_read_len(length).is_err() {
                            return;
                        }
                        if !frame_outbound_packet(&mut flow_sequences, &mut packet) {
                            continue;
                        }
                        stats
                            .total_bytes_up
                            .fetch_add(length as i64, Ordering::Relaxed);
                        self.dispatch(&mut scheduler, packet);
                    }
                    Ok(Err(error)) if is_retryable_tun_error(&error) => {
                        break;
                    }
                    Ok(Err(error)) if is_closed_tun_error(&error) => {
                        crate::log_error!("[TUN] Интерфейс закрыт, ожидаем новый FD");
                        return;
                    }
                    Ok(Err(error)) => {
                        crate::log_error!("[ОШИБКА] Чтение TUN завершено: {error}");
                        return;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    async fn read_udp(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        client: Arc<ArcSwapOption<SocketAddr>>,
        pool: Arc<PacketPool>,
        stats: Arc<Stats>,
    ) {
        let mut receive_batch = Vec::with_capacity(udp_batch::MAX_DATAGRAMS);
        let mut sources = [SocketAddr::from(([0, 0, 0, 0], 0)); udp_batch::MAX_DATAGRAMS];
        let mut scheduler = FastPathScheduler::new();
        let mut flow_sequences = FlowSequencer::new();
        loop {
            let readiness = tokio::select! {
                _ = self.cancel.cancelled() => return,
                result = socket.readable() => result,
            };
            if readiness.is_err() {
                tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
                continue;
            }

            receive_batch.clear();
            while receive_batch.len() < udp_batch::MAX_DATAGRAMS {
                let Some(packet) = pool.try_acquire() else {
                    break;
                };
                receive_batch.push(packet);
            }
            if receive_batch.is_empty() {
                tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
                continue;
            }

            let batch_len = receive_batch.len();
            let result = client_perf::measure_sampled(PerfStage::UdpRx, 64, || {
                udp_batch::try_recv_from(
                    &socket,
                    receive_batch.as_mut_slice(),
                    &mut sources[..batch_len],
                )
            });
            match result {
                Ok(received) => {
                    for (index, packet) in receive_batch.drain(..received).enumerate() {
                        let address = sources[index];
                        let previous = client.load();
                        if previous.as_deref() != Some(&address) {
                            client.store(Some(Arc::new(address)));
                        }
                        client_perf::observe(PerfStage::UdpRx);
                        let mut packet = packet;
                        if !frame_outbound_packet(&mut flow_sequences, &mut packet) {
                            continue;
                        }
                        stats
                            .total_bytes_up
                            .fetch_add(packet.len() as i64, Ordering::Relaxed);
                        self.dispatch(&mut scheduler, packet);
                    }
                    receive_batch.clear();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    receive_batch.clear();
                }
                Err(_) => {
                    receive_batch.clear();
                    tokio::select! {
                        _ = self.cancel.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                    }
                }
            }
        }
    }

    fn dispatch(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
        self.dispatch_now(scheduler, packet);
    }

    fn dispatch_now(&self, scheduler: &mut FastPathScheduler, packet: PacketBuf) {
        let Some(ticket) = client_perf::measure_sampled(PerfStage::Scheduler, 64, || {
            scheduler.begin(&self.workers, packet.as_slice())
        }) else {
            return;
        };
        let workers = scheduler.workers();
        if let Err(packet) = enqueue_selected_worker(workers, ticket, packet) {
            let _ = replace_oldest_in_selected_queue(workers, ticket, packet);
        }
    }

    #[cfg(unix)]
    async fn write_tun(
        &self,
        device: Arc<tokio::io::unix::AsyncFd<File>>,
        latency_receiver: &mut PacketReceiver,
        priority_receiver: &mut PacketReceiver,
        bulk_receiver: &mut PacketReceiver,
        stats: Arc<Stats>,
    ) {
        let mut reorder = ReturnReorder::new();
        let mut pending: Option<(PacketBuf, usize)> = None;
        loop {
            if pending.is_none() {
                let Some(packet) = recv_ordered_return_packet(
                    &mut reorder,
                    latency_receiver,
                    priority_receiver,
                    bulk_receiver,
                    &self.cancel,
                )
                .await
                else {
                    return;
                };
                pending = Some((packet, 0));
            }

            let readiness = tokio::select! {
                _ = self.cancel.cancelled() => return,
                result = device.writable() => result,
            };
            let mut guard = match readiness {
                Ok(guard) => guard,
                Err(error) => {
                    crate::log_error!("[ОШИБКА] Ожидание записи TUN завершено: {error}");
                    return;
                }
            };
            let mut burst = 0usize;
            let state = loop {
                let state = {
                    let (packet, written) = pending.as_mut().expect("TUN packet is pending");
                    self.try_write_tun_packet(&mut guard, &stats, packet, written)
                };
                match state {
                    TunWriteState::Complete => {
                        burst += 1;
                        if burst == 64 {
                            pending = None;
                            break TunWriteState::Complete;
                        }
                        pending = next_ordered_return_packet(
                            &mut reorder,
                            latency_receiver,
                            priority_receiver,
                            bulk_receiver,
                        )
                        .map(|packet| (packet, 0));
                        if pending.is_none() {
                            break TunWriteState::Complete;
                        }
                    }
                    TunWriteState::Continue => {}
                    state => break state,
                }
            };
            drop(guard);
            match state {
                TunWriteState::Complete | TunWriteState::Wait => {}
                TunWriteState::Backoff => {
                    tokio::select! {
                        _ = self.cancel.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                    }
                }
                TunWriteState::Yield => tokio::task::yield_now().await,
                TunWriteState::Closed | TunWriteState::Failed => return,
                TunWriteState::Continue => unreachable!(),
            }
        }
    }

    #[cfg(unix)]
    fn try_write_tun_packet(
        &self,
        guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, File>,
        stats: &Stats,
        packet: &PacketBuf,
        written: &mut usize,
    ) -> TunWriteState {
        use std::os::fd::AsRawFd;

        let result = client_perf::measure_sampled(PerfStage::TunTx, 64, || {
            guard.try_io(|inner| {
                let remaining = &packet.as_slice()[*written..];
                let length = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        remaining.as_ptr().cast(),
                        remaining.len(),
                    )
                };
                if length < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(length as usize)
                }
            })
        });
        match result {
            Ok(Ok(0)) => {
                crate::log_error!("[ОШИБКА] Запись TUN вернула 0 байт");
                TunWriteState::Failed
            }
            Ok(Ok(length)) => {
                *written += length;
                if *written == packet.len() {
                    stats
                        .total_bytes_down
                        .fetch_add(packet.len() as i64, Ordering::Relaxed);
                    TunWriteState::Complete
                } else {
                    TunWriteState::Continue
                }
            }
            Ok(Err(error)) if is_retryable_tun_error(&error) => {
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOBUFS) | Some(libc::ENOMEM)
                ) {
                    TunWriteState::Backoff
                } else {
                    TunWriteState::Yield
                }
            }
            Ok(Err(error)) if is_closed_tun_error(&error) => {
                crate::log_error!("[TUN] Интерфейс закрыт, ожидаем новый FD");
                TunWriteState::Closed
            }
            Ok(Err(error)) => {
                crate::log_error!("[ОШИБКА] Запись TUN завершена: {error}");
                TunWriteState::Failed
            }
            Err(_) => TunWriteState::Wait,
        }
    }

    async fn write_udp(
        &self,
        socket: Arc<UdpSocket>,
        client: Arc<ArcSwapOption<SocketAddr>>,
        latency_receiver: PacketReceiver,
        priority_receiver: PacketReceiver,
        bulk_receiver: PacketReceiver,
        stats: Arc<Stats>,
    ) {
        let mut send_batch = Vec::with_capacity(udp_batch::MAX_DATAGRAMS);
        let mut reorder = ReturnReorder::new();
        loop {
            let Some(packet) = recv_ordered_return_packet(
                &mut reorder,
                &latency_receiver,
                &priority_receiver,
                &bulk_receiver,
                &self.cancel,
            )
            .await
            else {
                return;
            };
            send_batch.clear();
            let first_class = packet_class(packet.as_slice());
            send_batch.push(packet);
            while send_batch.len() < first_class.datagram_batch() {
                let higher_priority_waiting = match first_class {
                    PacketClass::Small => false,
                    PacketClass::Medium => latency_receiver.has_queued_packet(),
                    PacketClass::Bulk => {
                        latency_receiver.has_queued_packet()
                            || priority_receiver.has_queued_packet()
                    }
                };
                if higher_priority_waiting {
                    break;
                }
                let Some(next) = next_ordered_return_packet(
                    &mut reorder,
                    &latency_receiver,
                    &priority_receiver,
                    &bulk_receiver,
                ) else {
                    break;
                };
                if packet_class(next.as_slice()) != first_class {
                    reorder.ready.push_front(next);
                    break;
                }
                send_batch.push(next);
            }

            let address = client.load().as_deref().copied();
            self.write_udp_batch(&socket, address, &stats, &send_batch)
                .await;
        }
    }

    async fn write_udp_batch(
        &self,
        socket: &UdpSocket,
        address: Option<SocketAddr>,
        stats: &Stats,
        packets: &[PacketBuf],
    ) {
        if let Some(address) = address {
            let mut datagrams: [&[u8]; udp_batch::MAX_DATAGRAMS] = [&[]; udp_batch::MAX_DATAGRAMS];
            for (index, packet) in packets.iter().enumerate() {
                datagrams[index] = packet.as_slice();
            }
            let mut sent = 0usize;
            while sent < packets.len() {
                let readiness = tokio::select! {
                    biased;
                    _ = self.cancel.cancelled() => return,
                    result = socket.writable() => result,
                };
                if readiness.is_err() {
                    return;
                }

                match client_perf::measure_sampled(PerfStage::UdpTx, 64, || {
                    udp_batch::try_send_to(socket, address, &datagrams[sent..packets.len()])
                }) {
                    Ok(0) => tokio::task::yield_now().await,
                    Ok(count) => {
                        for packet in &packets[sent..sent + count] {
                            stats
                                .total_bytes_down
                                .fetch_add(packet.len() as i64, Ordering::Relaxed);
                        }
                        sent += count;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return,
                }
            }
        }
    }
}

fn next_return_packet(
    latency: &PacketReceiver,
    priority: &PacketReceiver,
    bulk: &PacketReceiver,
) -> Option<PacketBuf> {
    latency
        .try_recv()
        .or_else(|| priority.try_recv())
        .or_else(|| bulk.try_recv())
}

async fn recv_return_packet(
    latency: &PacketReceiver,
    priority: &PacketReceiver,
    bulk: &PacketReceiver,
    cancel: &CancellationToken,
) -> Option<PacketBuf> {
    loop {
        if let Some(packet) = next_return_packet(latency, priority, bulk) {
            return Some(packet);
        }
        if latency.is_closed() && priority.is_closed() && bulk.is_closed() {
            return None;
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return None,
            packet = latency.recv(cancel), if !latency.is_closed() => {
                if let Some(packet) = packet {
                    return Some(packet);
                }
            }
            packet = priority.recv(cancel), if !priority.is_closed() => {
                if let Some(packet) = packet {
                    return Some(packet);
                }
            }
            packet = bulk.recv(cancel), if !bulk.is_closed() => {
                if let Some(packet) = packet {
                    return Some(packet);
                }
            }
        }
    }
}

fn next_ordered_return_packet(
    reorder: &mut ReturnReorder,
    latency: &PacketReceiver,
    priority: &PacketReceiver,
    bulk: &PacketReceiver,
) -> Option<PacketBuf> {
    loop {
        if let Some(packet) = reorder.pop() {
            return Some(packet);
        }
        let packet = next_return_packet(latency, priority, bulk)?;
        reorder.push(packet);
    }
}

async fn recv_ordered_return_packet(
    reorder: &mut ReturnReorder,
    latency: &PacketReceiver,
    priority: &PacketReceiver,
    bulk: &PacketReceiver,
    cancel: &CancellationToken,
) -> Option<PacketBuf> {
    loop {
        if let Some(packet) = reorder.pop() {
            return Some(packet);
        }
        let packet = recv_return_packet(latency, priority, bulk, cancel).await?;
        reorder.push(packet);
    }
}

fn spawn_critical<F>(name: &'static str, cancel: CancellationToken, future: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = tokio::spawn(future).await {
            crate::log_error!("[СУПЕРВИЗОР] {name} завершился аварийно: {error}");
            cancel.cancel();
        }
    })
}

#[cfg(unix)]
fn is_closed_tun_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EIO || code == libc::EBADF || code == libc::ENODEV
    )
}

#[cfg(unix)]
fn is_retryable_tun_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Interrupted
        || error.kind() == std::io::ErrorKind::WouldBlock
        || matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ENOBUFS || code == libc::ENOMEM
        )
}

fn enqueue_selected_worker(
    workers: &[WorkerChannels],
    ticket: DispatchTicket,
    packet: PacketBuf,
) -> Result<(), PacketBuf> {
    let Some(worker) = workers.get(ticket.start_slot) else {
        return Err(packet);
    };
    match ticket.class {
        PacketClass::Small => worker.latency.try_send(packet),
        PacketClass::Medium => worker.priority.try_send(packet),
        PacketClass::Bulk => worker.bulk.try_send(packet),
    }
}

fn replace_oldest_in_selected_queue(
    workers: &[WorkerChannels],
    ticket: DispatchTicket,
    packet: PacketBuf,
) -> Result<(), PacketBuf> {
    let Some(worker) = workers.get(ticket.start_slot) else {
        return Err(packet);
    };
    match ticket.class {
        PacketClass::Small => worker.latency.force_send(packet),
        PacketClass::Medium => worker.priority.force_send(packet),
        PacketClass::Bulk => worker.bulk.force_send(packet),
    }
}

async fn bind_udp(address: &str) -> Result<UdpSocket> {
    for attempt in 1..=5 {
        match UdpSocket::bind(address).await {
            Ok(socket) => {
                SockRef::from(&socket).set_recv_buffer_size(625 * 1024)?;
                SockRef::from(&socket).set_send_buffer_size(625 * 1024)?;
                return Ok(socket);
            }
            Err(error) if attempt < 5 => {
                crate::log_error!("[ОЖИДАНИЕ] Порт {address} занят. Жду... ({attempt}/5): {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => crate::log_error!("[АВТО-ПОРТ] Порт {address} всё ещё занят: {error}"),
        }
    }
    UdpSocket::bind("127.0.0.1:0").await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::{
        fs::File,
        io::{IoSlice, Write},
        os::{
            fd::{AsRawFd, FromRawFd, IntoRawFd},
            unix::net::UnixStream,
        },
    };

    #[cfg(unix)]
    fn send_uds_fd(name: &str, file: &File) {
        use nix::sys::socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr, connect,
            sendmsg, socket,
        };

        let socket = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        connect(
            socket.as_raw_fd(),
            &UnixAddr::new_abstract(name.as_bytes()).unwrap(),
        )
        .unwrap();
        let payload = [1u8];
        let slices = [IoSlice::new(&payload)];
        let controls = [ControlMessage::ScmRights(&[file.as_raw_fd()])];
        sendmsg::<UnixAddr>(
            socket.as_raw_fd(),
            &slices,
            &controls,
            MsgFlags::empty(),
            None,
        )
        .unwrap();
    }

    #[derive(Clone, Copy, Default)]
    struct QueueCoverage {
        full_rejection: usize,
        forced_replacement: usize,
        inactive_rejection: usize,
        suspended: usize,
        resumed: usize,
        purged: usize,
    }

    impl QueueCoverage {
        fn complete(self) -> bool {
            self.full_rejection > 0
                && self.forced_replacement > 0
                && self.inactive_rejection > 0
                && self.suspended > 0
                && self.resumed > 0
                && self.purged > 0
        }
    }

    fn test_dispatcher() -> (
        Arc<Dispatcher>,
        PacketReceiver,
        PacketReceiver,
        PacketReceiver,
    ) {
        let (return_latency_tx, return_latency_rx) = packet_channel(8, true);
        let (return_priority_tx, return_priority_rx) = packet_channel(16, true);
        let (return_tx, return_rx) = packet_channel(64, true);
        (
            Arc::new(Dispatcher {
                workers: ArcSwap::from_pointee(Vec::new()),
                return_latency_tx,
                return_priority_tx,
                return_tx,
                cancel: CancellationToken::new(),
                tasks: tokio::sync::Mutex::new(Vec::new()),
            }),
            return_latency_rx,
            return_priority_rx,
            return_rx,
        )
    }

    fn channels(
        id: usize,
        capacity: usize,
    ) -> (
        WorkerChannels,
        PacketReceiver,
        PacketReceiver,
        PacketReceiver,
    ) {
        let (latency, latency_rx) = packet_channel(capacity, true);
        let (priority, priority_rx) = packet_channel(capacity, true);
        let (bulk, bulk_rx) = packet_channel(capacity, true);
        (
            WorkerChannels {
                id,
                incarnation_id: id as u64 + 1,
                turn_path: Arc::from("test"),
                latency,
                priority,
                bulk,
            },
            latency_rx,
            priority_rx,
            bulk_rx,
        )
    }

    #[test]
    fn registered_workers_interleave_turn_paths() {
        let (dispatcher, _latency, _priority, _bulk) = test_dispatcher();
        for (id, turn_path) in [
            (1, "turn-a"),
            (2, "turn-a"),
            (3, "turn-b"),
            (4, "turn-b"),
            (5, "turn-c"),
            (6, "turn-c"),
        ] {
            let (mut worker, _latency, _priority, _bulk) = channels(id, 1);
            worker.turn_path = Arc::from(turn_path);
            dispatcher.register(worker);
        }
        let workers = dispatcher.workers.load();
        let order: Vec<_> = workers
            .iter()
            .map(|worker| worker.turn_path.as_ref())
            .collect();
        assert_eq!(
            order,
            ["turn-a", "turn-b", "turn-c", "turn-a", "turn-b", "turn-c"]
        );
    }

    fn queue_trace_outcome(actions: &[(u8, u8)], replace_oldest: bool) -> (bool, QueueCoverage) {
        let capacity = 7;
        let pool = PacketPool::new(32);
        let (sender, receiver) = packet_channel(capacity, true);
        let mut model = VecDeque::new();
        let mut active = true;
        let mut coverage = QueueCoverage::default();
        for &(operation, value) in actions {
            match operation % 6 {
                0 => {
                    let mut packet = pool.acquire();
                    packet.set_read_len(1).unwrap();
                    packet.as_mut_slice()[0] = value;
                    let accepted = sender.try_send(packet).is_ok();
                    let expected = active && model.len() < capacity;
                    if accepted != expected {
                        return (false, coverage);
                    }
                    if expected {
                        model.push_back(value);
                    } else if active {
                        coverage.full_rejection += 1;
                    } else {
                        coverage.inactive_rejection += 1;
                    }
                }
                1 => {
                    let mut packet = pool.acquire();
                    packet.set_read_len(1).unwrap();
                    packet.as_mut_slice()[0] = value;
                    let accepted = sender.force_send(packet).is_ok();
                    if accepted != active {
                        return (false, coverage);
                    }
                    if active {
                        if model.len() == capacity {
                            coverage.forced_replacement += 1;
                            if replace_oldest {
                                model.pop_front();
                            } else {
                                model.pop_back();
                            }
                        }
                        model.push_back(value);
                    } else {
                        coverage.inactive_rejection += 1;
                    }
                }
                2 => {
                    let actual = receiver.try_recv().map(|packet| packet.as_slice()[0]);
                    if actual != model.pop_front() {
                        return (false, coverage);
                    }
                }
                3 => {
                    receiver.suspend();
                    active = false;
                    model.clear();
                    coverage.suspended += 1;
                }
                4 => {
                    receiver.resume();
                    active = true;
                    model.clear();
                    coverage.resumed += 1;
                }
                _ => {
                    receiver.purge();
                    model.clear();
                    coverage.purged += 1;
                }
            }
        }
        while let Some(expected) = model.pop_front() {
            if receiver.try_recv().map(|packet| packet.as_slice()[0]) != Some(expected) {
                return (false, coverage);
            }
        }
        (
            receiver.try_recv().is_none() && pool.available() == pool.capacity(),
            coverage,
        )
    }

    fn queue_trace_matches(actions: &[(u8, u8)], replace_oldest: bool) -> bool {
        queue_trace_outcome(actions, replace_oldest).0
    }

    fn mix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn deterministic_queue_actions(seed: u64, length: usize) -> Vec<(u8, u8)> {
        let mut state = seed;
        let mut actions = Vec::with_capacity(length);
        let prefix = [
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (0, 5),
            (0, 6),
            (0, 7),
            (0, 8),
            (1, 9),
            (3, 0),
            (0, 10),
            (4, 0),
            (1, 11),
            (5, 0),
        ];
        actions.extend(prefix.into_iter().take(length));
        for _ in actions.len()..length {
            state = mix64(state);
            actions.push(((state % 6) as u8, (state >> 24) as u8));
        }
        actions
    }

    fn tcp_packet(pool: &Arc<PacketPool>, source_port: u16, sequence: u32) -> PacketBuf {
        tcp_packet_len(pool, source_port, sequence, 1_200)
    }

    fn bulk_packet_bytes() -> [u8; 1_200] {
        let mut packet = [0u8; 1_200];
        packet[0] = 0x45;
        packet[9] = 17;
        packet
    }

    fn tcp_packet_len(
        pool: &Arc<PacketPool>,
        source_port: u16,
        sequence: u32,
        len: usize,
    ) -> PacketBuf {
        assert!(len >= 40);
        let mut packet = pool.acquire();
        packet.set_read_len(len).unwrap();
        let bytes = packet.as_mut_slice();
        bytes.fill(0);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[10, 66, 67, 2]);
        bytes[16..20].copy_from_slice(&[1, 1, 1, 1]);
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
        bytes[32] = 5 << 4;
        bytes[33] = 0x18;
        packet
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn uds_tun_replacement_delivers_data_without_restarting_dispatcher() {
        let name = format!(
            "csqtt-dispatcher-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        );
        let cancel = CancellationToken::new();
        let pool = PacketPool::new(8);
        let stats = Arc::new(Stats::default());
        let (dispatcher, _) = Dispatcher::start(
            "127.0.0.1:0",
            Some(name.clone()),
            pool,
            stats,
            cancel.clone(),
        )
        .await
        .unwrap();
        let (worker, latency, _priority, _bulk) = channels(1, 8);
        dispatcher.register(worker);
        let (first_reader, first_writer) = UnixStream::pair().unwrap();
        let first_tun = unsafe { File::from_raw_fd(first_reader.into_raw_fd()) };
        let (second_reader, mut second_writer) = UnixStream::pair().unwrap();
        let second_tun = unsafe { File::from_raw_fd(second_reader.into_raw_fd()) };

        send_uds_fd(&name, &first_tun);
        send_uds_fd(&name, &second_tun);
        let mut packet = [0u8; 28];
        let packet_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        second_writer.write_all(&packet).unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), latency.recv(&cancel))
            .await
            .expect("replacement TUN did not deliver a packet")
            .expect("dispatcher input closed after TUN replacement");
        assert_eq!(received.as_slice(), packet);
        drop(first_writer);
        dispatcher.shutdown().await;
    }

    #[test]
    fn outbound_tcp_frame_preserves_the_inner_packet_and_sequence() {
        let pool = PacketPool::new(1);
        let mut packet = tcp_packet(&pool, 50_000, 77);
        let mut sequences = FlowSequencer::with_sender_id(9);
        assert!(frame_outbound_packet(&mut sequences, &mut packet));
        let (header, payload) = flow_frame::FrameHeader::decode(packet.as_slice()).unwrap();
        assert_eq!(header.sender_id, 9);
        assert_eq!(header.sequence, 0);
        assert_eq!(u32::from_be_bytes(payload[24..28].try_into().unwrap()), 77);
        drop(packet);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn return_reorder_restores_out_of_order_tcp_frames_without_copying_payload() {
        let pool = PacketPool::new(2);
        let mut first = tcp_packet(&pool, 50_000, 1);
        let mut second = tcp_packet(&pool, 50_000, 2);
        let first_header = flow_frame::FrameHeader {
            sender_id: 9,
            flow_id: 11,
            sequence: 0,
        };
        let second_header = flow_frame::FrameHeader {
            sequence: 1,
            ..first_header
        };
        first_header.encode(first.prepend(flow_frame::FRAME_LEN).unwrap());
        second_header.encode(second.prepend(flow_frame::FRAME_LEN).unwrap());
        let mut reorder = ReturnReorder::new();
        reorder.push(second);
        reorder.push(first);
        assert_eq!(packet_sequence(&reorder.pop().unwrap()), 1);
        assert_eq!(packet_sequence(&reorder.pop().unwrap()), 2);
        assert!(reorder.pop().is_none());
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn fast_path_scheduler_assigns_exact_bulk_round_robin_chunks() {
        let mut scheduler = FastPathScheduler::new();
        let workers = 4;
        let packet = bulk_packet_bytes();
        for chunk in 0..9 {
            for _ in 0..CLIENT_WORKER_PACKET_CHUNK {
                let ticket = scheduler.begin_with_count(workers, &packet).unwrap();
                assert_eq!(ticket.start_slot, chunk % workers);
                assert_eq!(ticket.class, PacketClass::Bulk);
            }
        }
        assert!(scheduler.begin_with_count(0, &packet).is_none());
        assert_eq!(
            scheduler
                .begin_with_count(workers, &packet)
                .unwrap()
                .start_slot,
            1
        );
    }

    #[test]
    fn fast_path_scheduler_balances_every_supported_stream_count() {
        for workers in [9, 27, 54, 81, 108, 126] {
            let mut scheduler = FastPathScheduler::new();
            let mut assigned = vec![0usize; workers];
            let packet = bulk_packet_bytes();
            for _ in 0..(workers * CLIENT_WORKER_PACKET_CHUNK * 3) {
                let ticket = scheduler.begin_with_count(workers, &packet).unwrap();
                assigned[ticket.start_slot] += 1;
            }
            assert!(
                assigned
                    .iter()
                    .all(|count| *count == CLIENT_WORKER_PACKET_CHUNK * 3)
            );
        }
    }

    #[test]
    fn fast_path_scheduler_keeps_round_robin_cursors_per_packet_class() {
        let mut scheduler = FastPathScheduler::new();
        let mut latency = [0u8; 64];
        latency[0] = 0x45;
        latency[9] = 6;
        let mut priority = [0u8; 301];
        priority[0] = 0x45;
        priority[9] = 17;
        let mut bulk = [0u8; 1_200];
        bulk[0] = 0x45;
        bulk[9] = 6;
        let packets = [&latency[..], &priority[..], &bulk[..]];

        for (packet, class, chunk) in [
            (packets[0], PacketClass::Small, 4),
            (packets[1], PacketClass::Medium, 16),
            (packets[2], PacketClass::Bulk, 32),
        ] {
            for _ in 0..chunk {
                let ticket = scheduler.begin_with_count(2, packet).unwrap();
                assert_eq!(ticket.start_slot, 0);
                assert_eq!(ticket.class, class);
            }
            assert_eq!(scheduler.begin_with_count(2, packet).unwrap().start_slot, 1);
        }
    }

    #[test]
    fn fast_path_scheduler_applies_worker_changes_only_at_a_chunk_boundary() {
        let mut scheduler = FastPathScheduler::new();
        let workers = ArcSwap::from_pointee(vec![channels(0, 1).0, channels(1, 1).0]);
        let packet = bulk_packet_bytes();

        for _ in 0..5 {
            assert_eq!(scheduler.begin(&workers, &packet).unwrap().start_slot, 0);
            assert_eq!(scheduler.workers().len(), 2);
        }

        workers.store(Arc::new(vec![
            channels(0, 1).0,
            channels(1, 1).0,
            channels(2, 1).0,
        ]));

        for _ in 0..(CLIENT_WORKER_PACKET_CHUNK - 5) {
            assert_eq!(scheduler.begin(&workers, &packet).unwrap().start_slot, 0);
            assert_eq!(scheduler.workers().len(), 2);
        }

        assert_eq!(scheduler.begin(&workers, &packet).unwrap().start_slot, 0);
        assert_eq!(scheduler.workers().len(), 3);
    }

    #[test]
    fn client_dispatcher_routes_one_full_chunk_to_each_worker_before_advancing() {
        let (dispatcher, _return_latency, _return_priority, _return_bulk) = test_dispatcher();
        let pool = PacketPool::new(CLIENT_WORKER_PACKET_CHUNK * 3);
        let mut workers = Vec::new();
        let mut receivers = Vec::new();
        for id in 0..3 {
            let (worker, latency, priority, bulk) = channels(id, CLIENT_WORKER_PACKET_CHUNK);
            workers.push(worker);
            receivers.push((latency, priority, bulk));
        }
        dispatcher.workers.store(Arc::new(workers));
        let mut scheduler = FastPathScheduler::new();
        for sequence in 0..(CLIENT_WORKER_PACKET_CHUNK * 3) {
            dispatcher.dispatch(&mut scheduler, tcp_packet(&pool, 50_000, sequence as u32));
        }
        for (worker, (latency, priority, bulk)) in receivers.iter().enumerate() {
            assert_eq!(latency.len(), 0);
            assert_eq!(priority.len(), 0);
            assert_eq!(bulk.len(), CLIENT_WORKER_PACKET_CHUNK);
            for offset in 0..CLIENT_WORKER_PACKET_CHUNK {
                assert_eq!(
                    packet_sequence(&bulk.try_recv().unwrap()),
                    (worker * CLIENT_WORKER_PACKET_CHUNK + offset) as u32
                );
            }
        }
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn saturated_selected_queue_never_redirects_a_chunk_to_another_worker() {
        let (dispatcher, _return_latency, _return_priority, _return_bulk) = test_dispatcher();
        let pool = PacketPool::new(2);
        let (first, _first_latency, _first_priority, first_bulk) = channels(0, 1);
        let (second, second_latency, second_priority, second_bulk) = channels(1, 1);
        dispatcher.workers.store(Arc::new(vec![first, second]));
        let mut scheduler = FastPathScheduler::new();

        dispatcher.dispatch(&mut scheduler, tcp_packet(&pool, 50_000, 1));
        dispatcher.dispatch(&mut scheduler, tcp_packet(&pool, 50_000, 2));

        assert_eq!(packet_sequence(&first_bulk.try_recv().unwrap()), 2);
        assert!(second_latency.try_recv().is_none());
        assert!(second_priority.try_recv().is_none());
        assert!(second_bulk.try_recv().is_none());
        assert_eq!(pool.available(), pool.capacity());
    }

    fn packet_sequence(packet: &PacketBuf) -> u32 {
        u32::from_be_bytes(packet.as_slice()[24..28].try_into().unwrap_or_default())
    }

    #[tokio::test(start_paused = true)]
    async fn direct_downlink_preserves_late_tcp_retransmit() {
        let (dispatcher, _return_latency_rx, _return_priority_rx, return_rx) = test_dispatcher();
        let pool = PacketPool::new(4);
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 0));
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 2_320));
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 0);
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 2_320);
        tokio::time::advance(Duration::from_millis(81)).await;
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 1_160));
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 1_160);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[tokio::test(start_paused = true)]
    async fn direct_downlink_splits_latency_and_bulk_returns() {
        let (dispatcher, return_latency_rx, _return_priority_rx, return_rx) = test_dispatcher();
        let pool = PacketPool::new(4);
        dispatcher.return_packet(tcp_packet_len(&pool, 50_000, 7, 96));
        dispatcher.return_packet(tcp_packet(&pool, 50_000, 8));
        assert_eq!(packet_sequence(&return_latency_rx.try_recv().unwrap()), 7);
        assert_eq!(packet_sequence(&return_rx.try_recv().unwrap()), 8);
    }

    #[test]
    fn unregister_and_recover_one_worker_never_changes_its_siblings() {
        let (dispatcher, _return_latency_rx, _return_priority_rx, _return_rx) = test_dispatcher();
        for id in 0..9 {
            dispatcher.register(channels(id, 1).0);
        }
        for cycle in 0..10_000 {
            let id = cycle % 9;
            dispatcher.unregister(id, id as u64 + 1);
            assert_eq!(dispatcher.active_count(), 8);
            for sibling in 0..9 {
                assert_eq!(dispatcher.worker(sibling).is_some(), sibling != id);
            }
            dispatcher.register(channels(id, 1).0);
            assert_eq!(dispatcher.active_count(), 9);
        }
    }

    #[test]
    fn stale_registration_drop_cannot_unregister_replacement() {
        let (dispatcher, _return_latency_rx, _return_priority_rx, _return_rx) = test_dispatcher();
        let mut old = channels(4, 1).0;
        old.incarnation_id = 40;
        dispatcher.register(old);
        let mut replacement = channels(4, 1).0;
        replacement.incarnation_id = 41;
        dispatcher.register(replacement);

        dispatcher.unregister(4, 40);

        assert_eq!(dispatcher.active_count(), 1);
        assert_eq!(dispatcher.worker(4).unwrap().incarnation_id, 41);
    }

    #[test]
    fn overload_keeps_queues_and_packet_memory_strictly_bounded() {
        let (dispatcher, _return_latency_rx, _return_priority_rx, _return_rx) = test_dispatcher();
        let pool = PacketPool::new(64);
        let mut workers = Vec::new();
        let mut receivers = Vec::new();
        for id in 0..9 {
            let (worker, latency, priority, bulk) = channels(id, 1);
            workers.push(worker);
            receivers.push((latency, priority, bulk));
        }
        dispatcher.workers.store(Arc::new(workers));
        let mut scheduler = FastPathScheduler::new();
        for sequence in 0..100_000 {
            let mut packet = pool.try_acquire().unwrap();
            packet
                .set_read_len(if sequence % 2 == 0 { 100 } else { 1_000 })
                .unwrap();
            dispatcher.dispatch(&mut scheduler, packet);
        }
        let mut queued = 0;
        for (latency, priority, bulk) in &receivers {
            queued += latency.len() + priority.len() + bulk.len();
        }
        assert!(queued <= 18);
        assert!(queued > 0);
        assert_eq!(pool.available() + queued, pool.capacity());
        for (latency, priority, bulk) in &receivers {
            while latency.try_recv().is_some() {}
            while priority.try_recv().is_some() {}
            while bulk.try_recv().is_some() {}
        }
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn saturated_queue_replaces_oldest_with_newest() {
        let pool = PacketPool::new(4);
        let (sender, receiver) = packet_channel(2, true);
        for value in 1..=3 {
            let mut packet = pool.acquire();
            packet.set_read_len(1).unwrap();
            packet.as_mut_slice()[0] = value;
            assert!(sender.force_send(packet).is_ok());
        }
        assert_eq!(receiver.try_recv().unwrap().as_slice(), [2]);
        assert_eq!(receiver.try_recv().unwrap().as_slice(), [3]);
        assert!(receiver.try_recv().is_none());
    }

    #[test]
    fn queued_packets_remain_available_until_the_queue_is_purged() {
        let pool = PacketPool::new(2);
        let (sender, receiver) = packet_channel(2, true);
        assert!(sender.force_send(pool.acquire()).is_ok());
        assert!(receiver.try_recv().is_some());
        assert_eq!(pool.available(), pool.capacity());
    }

    #[test]
    fn suspend_and_resume_purge_previous_network_epoch() {
        let pool = PacketPool::new(3);
        let (sender, receiver) = packet_channel(3, true);
        assert!(sender.force_send(pool.acquire()).is_ok());
        receiver.suspend();
        assert_eq!(pool.available(), pool.capacity());
        assert!(sender.force_send(pool.acquire()).is_err());
        receiver.resume();
        assert!(sender.force_send(pool.acquire()).is_ok());
        assert!(receiver.try_recv().is_some());
        assert!(receiver.try_recv().is_none());
    }

    proptest! {
        #[test]
        fn packet_queue_matches_bounded_reference_model(
            actions in proptest::collection::vec((any::<u8>(), any::<u8>()), 1..=2_000)
        ) {
            prop_assert!(queue_trace_matches(&actions, true));
        }
    }

    #[test]
    fn queue_oracle_detects_keep_oldest_mutation() {
        let actions = [
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 4),
            (1, 5),
            (1, 6),
            (1, 7),
            (1, 8),
            (2, 0),
        ];
        assert!(queue_trace_matches(&actions, true));
        assert!(!queue_trace_matches(&actions, false));
    }

    #[test]
    fn deterministic_queue_fault_generator_is_reproducible_and_complete() {
        let first = deterministic_queue_actions(0x1234_5678_9abc_def0, 4_096);
        let second = deterministic_queue_actions(0x1234_5678_9abc_def0, 4_096);
        let different = deterministic_queue_actions(0x1234_5678_9abc_def1, 4_096);
        assert_eq!(first, second);
        assert_ne!(first, different);
        let mut covered = [false; 6];
        for &(operation, _) in &first {
            covered[usize::from(operation % 6)] = true;
        }
        assert!(covered.into_iter().all(|value| value));
        let (matches, coverage) = queue_trace_outcome(&first, true);
        assert!(matches);
        assert!(coverage.complete());
    }

    #[test]
    fn queue_coverage_oracle_rejects_each_missing_state_transition() {
        let complete = QueueCoverage {
            full_rejection: 1,
            forced_replacement: 1,
            inactive_rejection: 1,
            suspended: 1,
            resumed: 1,
            purged: 1,
        };
        assert!(complete.complete());
        for index in 0..6 {
            let mut mutated = complete;
            match index {
                0 => mutated.full_rejection = 0,
                1 => mutated.forced_replacement = 0,
                2 => mutated.inactive_rejection = 0,
                3 => mutated.suspended = 0,
                4 => mutated.resumed = 0,
                _ => mutated.purged = 0,
            }
            assert!(!mutated.complete());
        }
    }

    #[test]
    #[ignore = "explicit deterministic stability soak"]
    fn deterministic_queue_chaos_soak() {
        let seconds = std::env::var("CSQTT_SOAK_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120)
            .max(1);
        let first_seed = std::env::var("CSQTT_SOAK_SEED")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let actions_per_seed = std::env::var("CSQTT_QUEUE_SOAK_ACTIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4_096)
            .max(14);
        let started = Instant::now();
        let mut offset = 0u64;
        loop {
            let seed = first_seed.wrapping_add(offset);
            let actions = deterministic_queue_actions(seed, actions_per_seed);
            let (matches, coverage) = queue_trace_outcome(&actions, true);
            assert!(
                matches && coverage.complete(),
                "packet queue diverged at reproducible seed {seed}"
            );
            offset = offset.wrapping_add(1);
            if started.elapsed() >= Duration::from_secs(seconds) {
                break;
            }
        }
    }

    #[test]
    fn concurrent_send_suspend_resume_storm_never_replays_previous_epoch() {
        let pool = PacketPool::new(4_096);
        let (sender, receiver) = packet_channel(64, true);
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut threads = Vec::new();
        for thread in 0..8u8 {
            let sender = sender.clone();
            let pool = pool.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for sequence in 0..25_000u32 {
                    let mut packet = pool.acquire();
                    packet.set_read_len(2).unwrap();
                    packet.as_mut_slice()[0] = thread;
                    packet.as_mut_slice()[1] = sequence as u8;
                    drop(sender.force_send(packet));
                }
            }));
        }
        barrier.wait();
        for cycle in 0..10_000 {
            if cycle % 3 == 0 {
                receiver.suspend();
            } else if cycle % 3 == 1 {
                receiver.resume();
            } else {
                while receiver.try_recv().is_some() {}
            }
        }
        for thread in threads {
            thread.join().unwrap();
        }
        receiver.suspend();
        receiver.resume();
        let mut marker = pool.acquire();
        marker.set_read_len(1).unwrap();
        marker.as_mut_slice()[0] = 0xa5;
        assert!(sender.force_send(marker).is_ok());
        assert_eq!(receiver.try_recv().unwrap().as_slice(), [0xa5]);
        assert!(receiver.try_recv().is_none());
        drop(sender);
        drop(receiver);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn receiver_notification_race_has_no_lost_wakeup() {
        let pool = PacketPool::new(1);
        for sequence in 0..2_000 {
            let (sender, receiver) = packet_channel(1, true);
            let cancel = CancellationToken::new();
            let waiter_cancel = cancel.clone();
            let waiter = tokio::spawn(async move { receiver.recv(&waiter_cancel).await });
            if sequence % 2 == 0 {
                tokio::task::yield_now().await;
            }
            assert!(sender.force_send(pool.acquire()).is_ok());
            let packet = tokio::time::timeout(Duration::from_millis(1000), waiter)
                .await
                .unwrap()
                .unwrap();
            assert!(packet.is_some());
            drop(packet);
            drop(sender);
            assert_eq!(pool.available(), pool.capacity());
        }
    }

    #[test]
    fn receiver_drop_race_releases_every_buffer() {
        for _ in 0..100 {
            let pool = PacketPool::new(32);
            let (sender, receiver) = packet_channel(8, true);
            let barrier = Arc::new(std::sync::Barrier::new(9));
            let mut threads = Vec::new();
            for _ in 0..8 {
                let sender = sender.clone();
                let pool = pool.clone();
                let barrier = barrier.clone();
                threads.push(std::thread::spawn(move || {
                    barrier.wait();
                    drop(sender.force_send(pool.acquire()));
                }));
            }
            barrier.wait();
            drop(receiver);
            for thread in threads {
                thread.join().unwrap();
            }
            drop(sender);
            assert_eq!(pool.available(), pool.capacity());
        }
    }

    #[tokio::test]
    async fn critical_task_panic_is_contained_and_cancels_runtime() {
        let cancel = CancellationToken::new();
        let task = spawn_critical("injected", cancel.clone(), async {
            panic!("injected dispatcher panic");
        });
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn successful_critical_task_does_not_cancel_runtime() {
        let cancel = CancellationToken::new();
        spawn_critical("completed", cancel.clone(), async {})
            .await
            .unwrap();
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn dispatcher_shutdown_completes_during_total_packet_deficit() {
        let pool = PacketPool::new(1);
        let held = pool.acquire();
        let cancel = CancellationToken::new();
        let (dispatcher, _) = Dispatcher::start(
            "127.0.0.1:0",
            None,
            pool.clone(),
            Arc::new(Stats::default()),
            cancel,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_millis(100), dispatcher.shutdown())
            .await
            .unwrap();
        drop(held);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[tokio::test]
    async fn direct_udp_batches_preserve_idle_pool_and_fifo_order() {
        let pool = PacketPool::new(128);
        let stats = Arc::new(Stats::default());
        let cancel = CancellationToken::new();
        let (dispatcher, port) =
            Dispatcher::start("127.0.0.1:0", None, pool.clone(), stats, cancel)
                .await
                .unwrap();
        let (worker, latency_rx, _priority_rx, _bulk_rx) = channels(0, 128);
        dispatcher.register(worker);

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(pool.available(), pool.capacity());

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let payloads: Vec<[u8; 1]> = (0..udp_batch::MAX_DATAGRAMS)
            .map(|index| [index as u8])
            .collect();
        let datagrams: Vec<&[u8]> = payloads.iter().map(|payload| payload.as_slice()).collect();
        udp_batch::send_to(&peer, destination, &datagrams)
            .await
            .unwrap();

        let receive_cancel = CancellationToken::new();
        for expected in 0..udp_batch::MAX_DATAGRAMS {
            let packet =
                tokio::time::timeout(Duration::from_secs(1), latency_rx.recv(&receive_cancel))
                    .await
                    .expect("direct UDP packet did not reach its worker")
                    .expect("worker input closed unexpectedly");
            assert_eq!(packet.as_slice(), [expected as u8]);
        }

        for expected in 0..udp_batch::MAX_DATAGRAMS {
            let mut packet = pool.acquire();
            packet.set_read_len(1).unwrap();
            packet.as_mut_slice()[0] = expected as u8 + 0x80;
            dispatcher.return_packet(packet);
        }
        let mut buffer = [0u8; 8];
        for expected in 0..udp_batch::MAX_DATAGRAMS {
            let (length, source) =
                tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
                    .await
                    .expect("direct UDP return packet timed out")
                    .unwrap();
            assert_eq!(source, destination);
            assert_eq!(&buffer[..length], &[expected as u8 + 0x80]);
        }

        dispatcher.shutdown().await;
    }
}

#[cfg(test)]
mod throughput_soak_tests;
