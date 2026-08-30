// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    packet::{
        PACKET_CAPACITY, PacketBuf, PacketBuffer, PacketPool, TUN_MTU, TUN_TX_SLOTS, UDP_TX_SLOTS,
        packet_pool_size, socket_addr_to_storage, storage_to_socket_addr,
    },
    striped_scheduler::PacketClass,
};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::net::UdpSocket;

pub const TICK_INTERVAL_MS: u64 = 100;
pub const MAX_DATAGRAMS: usize = 100;
const MIN_DATAGRAMS: usize = 16;
const PRIORITY_DATAGRAMS: usize = MIN_DATAGRAMS;
pub const MAX_RX_PER_PASS: usize = 100;
pub const TUN_RX_DRAIN_BATCH: usize = 128;
const FEC_TX_SLOT_RESERVE: usize = 32;
const UDP_CONTROL_BYTES: usize = 128;
const URGENCY_FLUSH_SYSCALLS: usize = 1;
pub const UDP_RECV_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const UDP_SEND_BUFFER_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct IoCounters {
    pub udp_rx_packets: u64,
    pub udp_rx_bytes: u64,
    pub udp_rx_errors: u64,
    pub udp_rx_eagain: u64,
    pub udp_rx_enobufs: u64,
    pub udp_recv_syscalls: u64,
    pub udp_recv_batch_max: u64,
    pub udp_tx_packets: u64,
    pub udp_tx_bytes: u64,
    pub udp_tx_errors: u64,
    pub udp_tx_drops: u64,
    pub udp_tx_eagain: u64,
    pub udp_tx_enobufs: u64,
    pub udp_send_syscalls: u64,
    pub partial_sendmmsg: u64,
    pub tun_rx_packets: u64,
    pub tun_rx_bytes: u64,
    pub tun_rx_errors: u64,
    pub tun_tx_packets: u64,
    pub tun_tx_bytes: u64,
    pub tun_tx_errors: u64,
    pub tun_tx_drops: u64,
    pub readiness_wakeups: u64,
    pub free_udp_tx_slots: u64,
    pub free_tun_tx_slots: u64,
    pub packet_pool_capacity: u64,
    pub packet_pool_allocated: u64,
    pub packet_pool_retained: u64,
}

#[repr(align(8))]
struct ControlBuffer([u8; UDP_CONTROL_BYTES]);

impl ControlBuffer {
    const fn new() -> Self {
        Self([0; UDP_CONTROL_BYTES])
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct UdpTxSlot {
    buffer: Option<PacketBuf>,
    peer: libc::sockaddr_storage,
    peer_len: libc::socklen_t,
    control: ControlBuffer,
    control_len: usize,
}

impl UdpTxSlot {
    fn new() -> Self {
        Self {
            buffer: None,
            peer: unsafe { std::mem::zeroed() },
            peer_len: 0,
            control: ControlBuffer::new(),
            control_len: 0,
        }
    }

    fn prepare_current(&mut self, peer: SocketAddr, source_ip: Option<IpAddr>) {
        self.peer_len = socket_addr_to_storage(peer, &mut self.peer);
        self.control_len = match (peer, source_ip) {
            (SocketAddr::V4(_), Some(IpAddr::V4(ip))) => {
                write_ipv4_pktinfo_control(ip, &mut self.control)
            }
            _ => 0,
        };
    }
}

struct TunTxSlot {
    buffer: Option<PacketBuf>,
}

impl TunTxSlot {
    fn new() -> Self {
        Self { buffer: None }
    }
}

pub struct TunDevice(tun::Device);

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub struct TokioIo {
    pub(crate) udp: UdpSocket,
    pub(crate) tun: AsyncFd<TunDevice>,
    udp_tx: Vec<UdpTxSlot>,
    packet_pool: std::sync::Arc<PacketPool>,
    free_udp_tx: VecDeque<usize>,
    pending_udp_latency_tx: VecDeque<usize>,
    pending_udp_priority_tx: VecDeque<usize>,
    pending_udp_bulk_tx: VecDeque<usize>,
    tun_rx: PacketBuffer,
    tun_tx: Vec<TunTxSlot>,
    free_tun_tx: VecDeque<usize>,
    pending_tun_latency_tx: VecDeque<usize>,
    pending_tun_priority_tx: VecDeque<usize>,
    pending_tun_bulk_tx: VecDeque<usize>,
    rx_batch: [PacketBuffer; MAX_DATAGRAMS],
    rx_peers: [libc::sockaddr_storage; MAX_DATAGRAMS],
    rx_controls: [ControlBuffer; MAX_DATAGRAMS],
    rx_iovecs: [libc::iovec; MAX_DATAGRAMS],
    rx_msgs: [libc::mmsghdr; MAX_DATAGRAMS],
    tx_iovecs: [libc::iovec; MAX_DATAGRAMS],
    tx_msgs: [libc::mmsghdr; MAX_DATAGRAMS],
    udp_rx_batch_limit: usize,
    counters: IoCounters,
    tun_fatal: bool,
}

pub struct PacketSink<'a> {
    tun_fd: RawFd,
    packet_pool: &'a std::sync::Arc<PacketPool>,
    udp_tx: &'a mut [UdpTxSlot],
    tun_tx: &'a mut [TunTxSlot],
    free_udp_tx: &'a mut VecDeque<usize>,
    pending_udp_latency_tx: &'a mut VecDeque<usize>,
    pending_udp_priority_tx: &'a mut VecDeque<usize>,
    pending_udp_bulk_tx: &'a mut VecDeque<usize>,
    free_tun_tx: &'a mut VecDeque<usize>,
    pending_tun_latency_tx: &'a mut VecDeque<usize>,
    pending_tun_priority_tx: &'a mut VecDeque<usize>,
    pending_tun_bulk_tx: &'a mut VecDeque<usize>,
    counters: &'a mut IoCounters,
    tun_fatal: &'a mut bool,
    urgent_udp_flush: &'a mut bool,
}

impl PacketSink<'_> {
    #[inline(always)]
    pub fn has_udp_tx_slot(&self) -> bool {
        !self.free_udp_tx.is_empty()
    }

    #[inline]
    pub fn send_udp_with_duplicate_priority<F>(
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
        let Some(slot_id) = self.free_udp_tx.pop_front() else {
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        };
        let Some(mut buffer) = self.packet_pool.try_acquire() else {
            self.free_udp_tx.push_front(slot_id);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        };
        if !build(&mut buffer) {
            self.free_udp_tx.push_front(slot_id);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        }
        let slot = &mut self.udp_tx[slot_id];
        slot.buffer = Some(buffer);
        slot.prepare_current(peer, source_ip);
        let duplicate_id = if duplicate && self.free_udp_tx.len() > FEC_TX_SLOT_RESERVE {
            self.free_udp_tx.pop_front().and_then(|duplicate_id| {
                let Some(mut duplicate_buffer) = self.packet_pool.try_acquire() else {
                    self.free_udp_tx.push_front(duplicate_id);
                    return None;
                };
                let copied = self.udp_tx[slot_id]
                    .buffer
                    .as_ref()
                    .is_some_and(|source| duplicate_buffer.copy_from(source.as_slice()));
                if !copied {
                    self.free_udp_tx.push_front(duplicate_id);
                    return None;
                }
                let duplicate = &mut self.udp_tx[duplicate_id];
                duplicate.buffer = Some(duplicate_buffer);
                duplicate.prepare_current(peer, source_ip);
                Some(duplicate_id)
            })
        } else {
            None
        };
        self.enqueue_udp(slot_id, class);
        if let Some(duplicate_id) = duplicate_id {
            self.enqueue_udp(duplicate_id, class);
        }
        true
    }

    #[inline(always)]
    pub fn request_udp_flush(&mut self) {
        *self.urgent_udp_flush = true;
    }

    #[inline]
    pub fn send_udp(
        &mut self,
        peer: SocketAddr,
        source_ip: Option<IpAddr>,
        payload: &[u8],
    ) -> bool {
        let Some(slot_id) = self.free_udp_tx.pop_front() else {
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        };
        let Some(mut buffer) = self.packet_pool.try_acquire() else {
            self.free_udp_tx.push_front(slot_id);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        };
        if !buffer.copy_from(payload) {
            self.free_udp_tx.push_front(slot_id);
            self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
            return false;
        }
        let slot = &mut self.udp_tx[slot_id];
        slot.buffer = Some(buffer);
        slot.prepare_current(peer, source_ip);
        self.pending_udp_bulk_tx.push_back(slot_id);
        true
    }

    #[inline(always)]
    fn enqueue_udp(&mut self, slot_id: usize, class: PacketClass) {
        match class {
            PacketClass::Latency => self.pending_udp_latency_tx.push_back(slot_id),
            PacketClass::Priority => self.pending_udp_priority_tx.push_back(slot_id),
            PacketClass::Bulk => self.pending_udp_bulk_tx.push_back(slot_id),
        }
    }

    #[inline]
    pub fn write_tun_priority(&mut self, payload: &[u8], class: PacketClass) -> bool {
        if self.pending_tun_latency_tx.is_empty()
            && self.pending_tun_priority_tx.is_empty()
            && self.pending_tun_bulk_tx.is_empty()
        {
            match write_tun_packet(self.tun_fd, payload) {
                Ok(true) => {
                    self.counters.tun_tx_packets = self.counters.tun_tx_packets.saturating_add(1);
                    self.counters.tun_tx_bytes = self
                        .counters
                        .tun_tx_bytes
                        .saturating_add(payload.len() as u64);
                    return true;
                }
                Ok(false) => {}
                Err(_) => {
                    self.counters.tun_tx_errors = self.counters.tun_tx_errors.saturating_add(1);
                    self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
                    *self.tun_fatal = true;
                    return false;
                }
            }
        }
        let Some(slot_id) = self.free_tun_tx.pop_front() else {
            self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
            return false;
        };
        let Some(mut buffer) = self.packet_pool.try_acquire() else {
            self.free_tun_tx.push_front(slot_id);
            self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
            return false;
        };
        if !buffer.copy_from(payload) {
            self.free_tun_tx.push_front(slot_id);
            self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
            return false;
        }
        self.tun_tx[slot_id].buffer = Some(buffer);
        match class {
            PacketClass::Latency => self.pending_tun_latency_tx.push_back(slot_id),
            PacketClass::Priority => self.pending_tun_priority_tx.push_back(slot_id),
            PacketClass::Bulk => self.pending_tun_bulk_tx.push_back(slot_id),
        }
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RxOutcome {
    Batch(usize),
    Drained,
}

impl TokioIo {
    pub async fn new(listen: SocketAddr, tun_iface: &str, tun_addr: &str) -> Result<Self> {
        let domain = if listen.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let raw_socket =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create UDP socket")?;
        raw_socket.set_reuse_address(true)?;
        raw_socket.set_recv_buffer_size(UDP_RECV_BUFFER_BYTES)?;
        raw_socket.set_send_buffer_size(UDP_SEND_BUFFER_BYTES)?;
        let ipv4_pktinfo_enabled = listen.is_ipv4()
            && set_socket_int(
                raw_socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                1,
            )
            .is_ok();
        if listen.is_ipv4() && !ipv4_pktinfo_enabled {
            eprintln!("[DATAPLANE] IP_PKTINFO unavailable; UDP source address symmetry disabled");
        }
        raw_socket
            .bind(&listen.into())
            .with_context(|| format!("bind {listen}"))?;
        raw_socket
            .set_nonblocking(true)
            .context("set UDP nonblocking mode")?;
        let std_socket = std::net::UdpSocket::from(raw_socket);
        let udp = UdpSocket::from_std(std_socket).context("register UDP socket in tokio")?;

        let address = tun_addr
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid TUN address {tun_addr}"))?;
        let mut config = tun::Configuration::default();
        config
            .tun_name(tun_iface)
            .address(address)
            .netmask((255, 255, 255, 0))
            .mtu(TUN_MTU)
            .up();
        let device = create_tun_device(&config, tun_iface)?;
        device.set_nonblock().context("set TUN nonblocking mode")?;
        let tun = AsyncFd::new(TunDevice(device)).context("register TUN in tokio")?;

        Ok(Self {
            udp,
            tun,
            udp_tx: (0..UDP_TX_SLOTS).map(|_| UdpTxSlot::new()).collect(),
            packet_pool: PacketPool::new(packet_pool_size()),
            free_udp_tx: (0..UDP_TX_SLOTS).collect(),
            pending_udp_latency_tx: VecDeque::with_capacity(UDP_TX_SLOTS),
            pending_udp_priority_tx: VecDeque::with_capacity(UDP_TX_SLOTS),
            pending_udp_bulk_tx: VecDeque::with_capacity(UDP_TX_SLOTS),
            tun_rx: PacketBuffer::new(),
            tun_tx: (0..TUN_TX_SLOTS).map(|_| TunTxSlot::new()).collect(),
            free_tun_tx: (0..TUN_TX_SLOTS).collect(),
            pending_tun_latency_tx: VecDeque::with_capacity(TUN_TX_SLOTS),
            pending_tun_priority_tx: VecDeque::with_capacity(TUN_TX_SLOTS),
            pending_tun_bulk_tx: VecDeque::with_capacity(TUN_TX_SLOTS),
            rx_batch: std::array::from_fn(|_| PacketBuffer::new()),
            rx_peers: [unsafe { std::mem::zeroed() }; MAX_DATAGRAMS],
            rx_controls: std::array::from_fn(|_| ControlBuffer::new()),
            rx_iovecs: [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_DATAGRAMS],
            rx_msgs: std::array::from_fn(|_| unsafe { std::mem::zeroed() }),
            tx_iovecs: [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_DATAGRAMS],
            tx_msgs: std::array::from_fn(|_| unsafe { std::mem::zeroed() }),
            udp_rx_batch_limit: MIN_DATAGRAMS,
            counters: IoCounters::default(),
            tun_fatal: false,
        })
    }

    pub fn with_sink<R>(&mut self, process: impl FnOnce(&mut PacketSink<'_>) -> R) -> R {
        let mut urgent_udp_flush = false;
        let output = {
            let tun_fd = self.tun.as_raw_fd();
            let Self {
                udp_tx,
                packet_pool,
                tun_tx,
                free_udp_tx,
                pending_udp_latency_tx,
                pending_udp_priority_tx,
                pending_udp_bulk_tx,
                free_tun_tx,
                pending_tun_latency_tx,
                pending_tun_priority_tx,
                pending_tun_bulk_tx,
                counters,
                tun_fatal,
                ..
            } = self;
            let mut sink = PacketSink {
                tun_fd,
                packet_pool,
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_latency_tx,
                pending_udp_priority_tx,
                pending_udp_bulk_tx,
                free_tun_tx,
                pending_tun_latency_tx,
                pending_tun_priority_tx,
                pending_tun_bulk_tx,
                counters,
                tun_fatal,
                urgent_udp_flush: &mut urgent_udp_flush,
            };
            process(&mut sink)
        };
        if urgent_udp_flush {
            self.flush_udp_tx(URGENCY_FLUSH_SYSCALLS);
        }
        output
    }

    pub fn dispatch_udp_rx<L>(&mut self, budget: usize, logic: &mut L) -> RxOutcome
    where
        L: FnMut(SocketAddr, Option<IpAddr>, &mut [u8], &mut PacketSink<'_>),
    {
        let receive_limit = self.udp_rx_batch_limit.min(budget.max(1));
        let udp_fd = self.udp.as_raw_fd();
        let tun_fd = self.tun.as_raw_fd();
        for index in 0..receive_limit {
            self.rx_iovecs[index] = libc::iovec {
                iov_base: self.rx_batch[index].as_mut_ptr().cast(),
                iov_len: PACKET_CAPACITY,
            };
            self.rx_msgs[index] = unsafe { std::mem::zeroed() };
            let msg = &mut self.rx_msgs[index];
            msg.msg_hdr.msg_name =
                (&mut self.rx_peers[index] as *mut libc::sockaddr_storage).cast();
            msg.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_hdr.msg_iov = &mut self.rx_iovecs[index];
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_control = self.rx_controls[index].as_mut_ptr().cast();
            msg.msg_hdr.msg_controllen = UDP_CONTROL_BYTES as _;
        }
        let received = self.udp.try_io(Interest::READABLE, || {
            loop {
                let result = unsafe {
                    libc::recvmmsg(
                        udp_fd,
                        self.rx_msgs.as_mut_ptr(),
                        receive_limit as libc::c_uint,
                        (libc::MSG_DONTWAIT | libc::MSG_WAITFORONE) as _,
                        std::ptr::null_mut(),
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                return Ok(result as usize);
            }
        });
        let batch = match received {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.counters.udp_rx_eagain = self.counters.udp_rx_eagain.saturating_add(1);
                if receive_limit == self.udp_rx_batch_limit {
                    self.adapt_udp_rx_batch(0);
                }
                return RxOutcome::Drained;
            }
            Err(error) => {
                self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
                if error.raw_os_error() == Some(libc::ENOBUFS) {
                    self.counters.udp_rx_enobufs = self.counters.udp_rx_enobufs.saturating_add(1);
                }
                return RxOutcome::Drained;
            }
            Ok(0) => return RxOutcome::Drained,
            Ok(batch) => batch,
        };
        self.counters.udp_recv_syscalls = self.counters.udp_recv_syscalls.saturating_add(1);
        if receive_limit == self.udp_rx_batch_limit {
            self.adapt_udp_rx_batch(batch);
        }
        if batch as u64 > self.counters.udp_recv_batch_max {
            self.counters.udp_recv_batch_max = batch as u64;
        }
        for index in 0..batch {
            let msg = &self.rx_msgs[index];
            let header_flags = msg.msg_hdr.msg_flags;
            let len = msg.msg_len as usize;
            if header_flags & libc::MSG_TRUNC != 0 || len > PACKET_CAPACITY {
                self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
                continue;
            }
            if !self.rx_batch[index].set_len(len) {
                self.counters.udp_rx_errors = self.counters.udp_rx_errors.saturating_add(1);
                continue;
            }
            let Some(peer) = storage_to_socket_addr(&self.rx_peers[index], msg.msg_hdr.msg_namelen)
            else {
                continue;
            };
            #[allow(clippy::unnecessary_cast)] // cmsghdr field differs across libc targets.
            let control_len =
                (msg.msg_hdr.msg_controllen as usize).min(self.rx_controls[index].len());
            let local_ip = parse_ipv4_pktinfo_destination(unsafe {
                std::slice::from_raw_parts(
                    self.rx_controls[index].0.as_ptr().cast::<u8>(),
                    control_len,
                )
            })
            .map(IpAddr::V4);
            self.counters.udp_rx_packets = self.counters.udp_rx_packets.saturating_add(1);
            self.counters.udp_rx_bytes = self.counters.udp_rx_bytes.saturating_add(len as u64);
            let mut urgent_udp_flush = false;
            {
                let Self {
                    udp_tx,
                    packet_pool,
                    tun_tx,
                    free_udp_tx,
                    pending_udp_latency_tx,
                    pending_udp_priority_tx,
                    pending_udp_bulk_tx,
                    free_tun_tx,
                    pending_tun_latency_tx,
                    pending_tun_priority_tx,
                    pending_tun_bulk_tx,
                    counters,
                    tun_fatal,
                    ..
                } = self;
                let packet = self.rx_batch[index].as_mut_slice();
                let mut sink = PacketSink {
                    tun_fd,
                    packet_pool,
                    udp_tx,
                    tun_tx,
                    free_udp_tx,
                    pending_udp_latency_tx,
                    pending_udp_priority_tx,
                    pending_udp_bulk_tx,
                    free_tun_tx,
                    pending_tun_latency_tx,
                    pending_tun_priority_tx,
                    pending_tun_bulk_tx,
                    counters,
                    tun_fatal,
                    urgent_udp_flush: &mut urgent_udp_flush,
                };
                logic(peer, local_ip, packet, &mut sink);
            }
            if urgent_udp_flush {
                self.flush_udp_tx(URGENCY_FLUSH_SYSCALLS);
            }
        }
        RxOutcome::Batch(batch)
    }

    pub fn read_tun_rx<L>(&mut self, logic: &mut L) -> io::Result<usize>
    where
        L: FnMut(&mut [u8], &mut PacketSink<'_>),
    {
        let tun_fd = self.tun.as_raw_fd();
        let read = {
            let buffer = &mut self.tun_rx;
            self.tun.try_io(Interest::READABLE, |_| {
                loop {
                    let result = unsafe {
                        libc::read(tun_fd, buffer.as_mut_ptr().cast(), buffer.capacity())
                    };
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(error);
                    }
                    return Ok(result as usize);
                }
            })
        };
        let len = match read {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(0),
            Err(error) => {
                self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
                return Err(error);
            }
            Ok(0) => {
                self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN packet reader returned EOF",
                ));
            }
            Ok(len) => len,
        };
        if !self.tun_rx.set_len(len) {
            self.counters.tun_rx_errors = self.counters.tun_rx_errors.saturating_add(1);
            return Ok(0);
        }
        self.counters.tun_rx_packets = self.counters.tun_rx_packets.saturating_add(1);
        self.counters.tun_rx_bytes = self.counters.tun_rx_bytes.saturating_add(len as u64);
        let mut urgent_udp_flush = false;
        {
            let tun_fd = self.tun.as_raw_fd();
            let Self {
                udp_tx,
                packet_pool,
                tun_tx,
                free_udp_tx,
                pending_udp_latency_tx,
                pending_udp_priority_tx,
                pending_udp_bulk_tx,
                free_tun_tx,
                pending_tun_latency_tx,
                pending_tun_priority_tx,
                pending_tun_bulk_tx,
                counters,
                tun_fatal,
                ..
            } = self;
            let packet = self.tun_rx.as_mut_slice();
            let mut sink = PacketSink {
                tun_fd,
                packet_pool,
                udp_tx,
                tun_tx,
                free_udp_tx,
                pending_udp_latency_tx,
                pending_udp_priority_tx,
                pending_udp_bulk_tx,
                free_tun_tx,
                pending_tun_latency_tx,
                pending_tun_priority_tx,
                pending_tun_bulk_tx,
                counters,
                tun_fatal,
                urgent_udp_flush: &mut urgent_udp_flush,
            };
            logic(packet, &mut sink);
        }
        if urgent_udp_flush {
            self.flush_udp_tx(URGENCY_FLUSH_SYSCALLS);
        }
        Ok(1)
    }

    pub fn flush_udp_tx(&mut self, max_syscalls: usize) {
        let udp_fd = self.udp.as_raw_fd();
        let mut syscalls = 0usize;
        while self.pending_udp_tx_len() != 0 && syscalls < max_syscalls {
            let batch_limit = if !self.pending_udp_latency_tx.is_empty() {
                1
            } else if !self.pending_udp_priority_tx.is_empty() {
                PRIORITY_DATAGRAMS
            } else {
                MAX_DATAGRAMS
            };
            let batch_len = self.pending_udp_tx_batch_len(batch_limit);
            if batch_len == 0 {
                if let Some(slot_id) = self.pop_pending_udp_tx() {
                    self.counters.udp_tx_errors = self.counters.udp_tx_errors.saturating_add(1);
                    self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
                    self.free_udp_tx.push_back(slot_id);
                }
                continue;
            }
            for index in 0..batch_len {
                let Some(slot_id) = self.pending_udp_tx_slot(index) else {
                    continue;
                };
                let slot = &mut self.udp_tx[slot_id];
                let Some(buffer) = slot.buffer.as_mut() else {
                    continue;
                };
                self.tx_iovecs[index] = libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: buffer.len(),
                };
                self.tx_msgs[index] = unsafe { std::mem::zeroed() };
                self.tx_msgs[index].msg_hdr.msg_name =
                    (&mut slot.peer as *mut libc::sockaddr_storage).cast();
                self.tx_msgs[index].msg_hdr.msg_namelen = slot.peer_len;
                self.tx_msgs[index].msg_hdr.msg_iov = &mut self.tx_iovecs[index];
                self.tx_msgs[index].msg_hdr.msg_iovlen = 1;
                self.tx_msgs[index].msg_hdr.msg_control = if slot.control_len > 0 {
                    slot.control.as_mut_ptr().cast()
                } else {
                    std::ptr::null_mut()
                };
                self.tx_msgs[index].msg_hdr.msg_controllen = slot.control_len as _;
            }
            syscalls += 1;
            let mut tx_enobufs = false;
            let sent = self.udp.try_io(Interest::WRITABLE, || {
                loop {
                    let result = unsafe {
                        libc::sendmmsg(
                            udp_fd,
                            self.tx_msgs.as_mut_ptr(),
                            batch_len as libc::c_uint,
                            libc::MSG_DONTWAIT as _,
                        )
                    };
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        if error.raw_os_error() == Some(libc::ENOBUFS) {
                            tx_enobufs = true;
                            return Err(io::Error::from(io::ErrorKind::WouldBlock));
                        }
                        return Err(error);
                    }
                    return Ok(result as usize);
                }
            });
            match sent {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if tx_enobufs {
                        self.counters.udp_tx_enobufs =
                            self.counters.udp_tx_enobufs.saturating_add(1);
                    } else {
                        self.counters.udp_tx_eagain = self.counters.udp_tx_eagain.saturating_add(1);
                    }
                    return;
                }
                Err(_) => {
                    self.counters.udp_tx_errors = self.counters.udp_tx_errors.saturating_add(1);
                    self.counters.udp_tx_drops = self.counters.udp_tx_drops.saturating_add(1);
                    if let Some(slot_id) = self.pop_pending_udp_tx() {
                        self.udp_tx[slot_id].buffer.take();
                        self.free_udp_tx.push_back(slot_id);
                    }
                }
                Ok(0) => {
                    self.counters.udp_tx_eagain = self.counters.udp_tx_eagain.saturating_add(1);
                    return;
                }
                Ok(sent) => {
                    if sent < batch_len {
                        self.counters.partial_sendmmsg =
                            self.counters.partial_sendmmsg.saturating_add(1);
                    }
                    for index in 0..sent {
                        let length = self.tx_msgs[index].msg_len as usize;
                        let Some(slot_id) = self.pop_pending_udp_tx() else {
                            break;
                        };
                        self.counters.udp_tx_packets =
                            self.counters.udp_tx_packets.saturating_add(1);
                        self.counters.udp_tx_bytes =
                            self.counters.udp_tx_bytes.saturating_add(length as u64);
                        self.udp_tx[slot_id].buffer.take();
                        self.free_udp_tx.push_back(slot_id);
                    }
                }
            }
        }
    }

    pub fn flush_tun_tx(&mut self) {
        let tun_fd = self.tun.as_raw_fd();
        while let Some(slot_id) = self.front_pending_tun_tx() {
            if self.tun_tx[slot_id].buffer.is_none() {
                self.pop_pending_tun_tx();
                self.counters.tun_tx_errors = self.counters.tun_tx_errors.saturating_add(1);
                self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
                self.free_tun_tx.push_back(slot_id);
                continue;
            }
            let written = {
                let payload = self.tun_tx[slot_id]
                    .buffer
                    .as_ref()
                    .map(PacketBuf::as_slice)
                    .unwrap_or_default();
                self.tun
                    .try_io(Interest::WRITABLE, |_| write_tun_packet(tun_fd, payload))
            };
            match written {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.counters.tun_tx_errors = self.counters.tun_tx_errors.saturating_add(1);
                    self.counters.tun_tx_drops = self.counters.tun_tx_drops.saturating_add(1);
                    self.tun_fatal = true;
                    if let Some(slot_id) = self.pop_pending_tun_tx() {
                        self.tun_tx[slot_id].buffer.take();
                        self.free_tun_tx.push_back(slot_id);
                    }
                    return;
                }
                Ok(false) => return,
                Ok(true) => {
                    let payload_len = self.tun_tx[slot_id]
                        .buffer
                        .as_ref()
                        .map(PacketBuf::len)
                        .unwrap_or(0);
                    self.counters.tun_tx_packets = self.counters.tun_tx_packets.saturating_add(1);
                    self.counters.tun_tx_bytes = self
                        .counters
                        .tun_tx_bytes
                        .saturating_add(payload_len as u64);
                    self.pop_pending_tun_tx();
                    self.tun_tx[slot_id].buffer.take();
                    self.free_tun_tx.push_back(slot_id);
                }
            }
        }
    }

    #[inline(always)]
    pub fn pending_udp_tx_len(&self) -> usize {
        self.pending_udp_latency_tx
            .len()
            .saturating_add(self.pending_udp_priority_tx.len())
            .saturating_add(self.pending_udp_bulk_tx.len())
    }

    #[inline(always)]
    pub fn pending_tun_tx_len(&self) -> usize {
        self.pending_tun_latency_tx
            .len()
            .saturating_add(self.pending_tun_priority_tx.len())
            .saturating_add(self.pending_tun_bulk_tx.len())
    }

    #[inline(always)]
    fn pending_udp_tx_batch_len(&self, limit: usize) -> usize {
        if !self.pending_udp_latency_tx.is_empty() {
            self.pending_udp_latency_tx
                .iter()
                .take(limit)
                .take_while(|slot_id| self.udp_tx[**slot_id].buffer.is_some())
                .count()
        } else if !self.pending_udp_priority_tx.is_empty() {
            self.pending_udp_priority_tx
                .iter()
                .take(limit)
                .take_while(|slot_id| self.udp_tx[**slot_id].buffer.is_some())
                .count()
        } else {
            self.pending_udp_bulk_tx
                .iter()
                .take(limit)
                .take_while(|slot_id| self.udp_tx[**slot_id].buffer.is_some())
                .count()
        }
    }

    #[inline(always)]
    fn pending_udp_tx_slot(&self, index: usize) -> Option<usize> {
        if !self.pending_udp_latency_tx.is_empty() {
            self.pending_udp_latency_tx.get(index).copied()
        } else if !self.pending_udp_priority_tx.is_empty() {
            self.pending_udp_priority_tx.get(index).copied()
        } else {
            self.pending_udp_bulk_tx.get(index).copied()
        }
    }

    #[inline(always)]
    fn front_pending_tun_tx(&self) -> Option<usize> {
        self.pending_tun_latency_tx
            .front()
            .copied()
            .or_else(|| self.pending_tun_priority_tx.front().copied())
            .or_else(|| self.pending_tun_bulk_tx.front().copied())
    }

    #[inline(always)]
    fn pop_pending_udp_tx(&mut self) -> Option<usize> {
        self.pending_udp_latency_tx
            .pop_front()
            .or_else(|| self.pending_udp_priority_tx.pop_front())
            .or_else(|| self.pending_udp_bulk_tx.pop_front())
    }

    #[inline(always)]
    fn pop_pending_tun_tx(&mut self) -> Option<usize> {
        self.pending_tun_latency_tx
            .pop_front()
            .or_else(|| self.pending_tun_priority_tx.pop_front())
            .or_else(|| self.pending_tun_bulk_tx.pop_front())
    }

    pub fn take_tun_fatal(&mut self) -> bool {
        std::mem::take(&mut self.tun_fatal)
    }

    #[inline]
    pub fn note_readiness_wakeup(&mut self) {
        self.counters.readiness_wakeups = self.counters.readiness_wakeups.saturating_add(1);
    }

    pub fn counters_snapshot(&self) -> IoCounters {
        let mut snapshot = self.counters;
        snapshot.free_udp_tx_slots = self.free_udp_tx.len() as u64;
        snapshot.free_tun_tx_slots = self.free_tun_tx.len() as u64;
        let pool = self.packet_pool.snapshot();
        snapshot.packet_pool_capacity = pool.capacity as u64;
        snapshot.packet_pool_allocated = pool.allocated as u64;
        snapshot.packet_pool_retained = pool.retained as u64;
        snapshot
    }

    fn adapt_udp_rx_batch(&mut self, batch: usize) {
        if batch >= self.udp_rx_batch_limit && self.udp_rx_batch_limit < MAX_DATAGRAMS {
            self.udp_rx_batch_limit = match self.udp_rx_batch_limit {
                ..=MIN_DATAGRAMS => 32,
                17..=32 => 64,
                _ => MAX_DATAGRAMS,
            };
        } else if batch == 0 || batch.saturating_mul(4) <= self.udp_rx_batch_limit {
            self.udp_rx_batch_limit = match self.udp_rx_batch_limit {
                65.. => 64,
                33..=64 => 32,
                _ => MIN_DATAGRAMS,
            };
        }
    }
}

fn create_tun_device(config: &tun::Configuration, tun_iface: &str) -> Result<tun::Device> {
    let mut last_error = None;
    for attempt in 0..8 {
        match tun::create(config) {
            Ok(device) => return Ok(device),
            Err(error) if is_tun_create_retryable(&error) => {
                eprintln!(
                    "[TUN] create {tun_iface} attempt {} failed ({error}), retrying",
                    attempt + 1
                );
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(40 + attempt * 40));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create TUN device {tun_iface}"));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| tun::Error::String("TUN create retry exhausted".to_owned())))
        .with_context(|| format!("create TUN device {tun_iface}"))
}

fn is_tun_create_retryable(error: &tun::Error) -> bool {
    match error {
        tun::Error::Io(error) => matches!(
            error.raw_os_error(),
            Some(
                libc::EEXIST
                    | libc::EBUSY
                    | libc::EADDRINUSE
                    | libc::ENOENT
                    | libc::ENODEV
                    | libc::EAGAIN
                    | libc::EINTR
            )
        ),
        _ => false,
    }
}

fn set_socket_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn cmsg_align(length: usize) -> usize {
    let align = std::mem::size_of::<usize>();
    (length + align - 1) & !(align - 1)
}

fn parse_ipv4_pktinfo_destination(mut control: &[u8]) -> Option<Ipv4Addr> {
    while control.len() >= std::mem::size_of::<libc::cmsghdr>() {
        let header = unsafe { &*(control.as_ptr().cast::<libc::cmsghdr>()) };
        #[allow(clippy::unnecessary_cast)] // cmsghdr field differs across libc targets.
        let length = header.cmsg_len as usize;
        if length < std::mem::size_of::<libc::cmsghdr>() || length > control.len() {
            break;
        }
        if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_PKTINFO {
            let data_offset = cmsg_align(std::mem::size_of::<libc::cmsghdr>());
            if length >= data_offset + std::mem::size_of::<libc::in_pktinfo>() {
                let pktinfo = unsafe {
                    std::ptr::read_unaligned(
                        control[data_offset..].as_ptr().cast::<libc::in_pktinfo>(),
                    )
                };
                let spec = Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_ne_bytes());
                if !spec.is_unspecified() {
                    return Some(spec);
                }
                let destination = Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes());
                if !destination.is_unspecified() {
                    return Some(destination);
                }
            }
        }
        let advance = cmsg_align(length);
        if advance == 0 {
            break;
        }
        control = &control[advance.min(control.len())..];
    }
    None
}

fn write_ipv4_pktinfo_control(source: Ipv4Addr, control: &mut ControlBuffer) -> usize {
    if source.is_unspecified() {
        return 0;
    }
    let data_len = std::mem::size_of::<libc::in_pktinfo>();
    let space = unsafe { libc::CMSG_SPACE(data_len as libc::c_uint) as usize };
    let length = unsafe { libc::CMSG_LEN(data_len as libc::c_uint) as usize };
    if space > control.len() {
        return 0;
    }
    unsafe {
        std::ptr::write_bytes(control.as_mut_ptr(), 0, control.len());
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        (*header).cmsg_len = length as _;
        (*header).cmsg_level = libc::IPPROTO_IP;
        (*header).cmsg_type = libc::IP_PKTINFO;
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes(source.octets()),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        std::ptr::copy_nonoverlapping(
            (&pktinfo as *const libc::in_pktinfo).cast::<u8>(),
            libc::CMSG_DATA(header),
            data_len,
        );
    }
    space
}

fn write_tun_packet(fd: RawFd, payload: &[u8]) -> io::Result<bool> {
    loop {
        let result = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
        if result == payload.len() as isize {
            return Ok(true);
        }
        if result >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short TUN packet write",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(error);
    }
}

const _: () = {
    assert!(PACKET_CAPACITY >= TUN_MTU as usize);
    assert!(UDP_TX_SLOTS <= 4096);
    assert!(TUN_TX_SLOTS <= 4096);
};
