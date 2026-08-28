// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Bounded batched I/O for Tokio UDP sockets.
//!
//! The public `try_*` functions never wait.  On Android and Linux they use
//! `recvmmsg` / `sendmmsg`; other targets preserve the same prefix semantics
//! with ordinary Tokio UDP calls.  Both connected and unconnected sockets are
//! supported. The async wrappers wait for Tokio readiness and retry only work
//! that the kernel did not accept.
//!
//! Callers own the `PacketBuf`s supplied to [`try_recv_connected`] and must
//! acquire them only when they are prepared to receive.  A successful receive
//! has already set the `PacketBuf` lengths for the returned prefix.

use crate::packet::PacketBuf;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::packet::{PACKET_CAPACITY, PACKET_HEADROOM};
use std::io::{self, ErrorKind};
use tokio::net::UdpSocket;

/// Upper bound for a single kernel batch.  It bounds stack metadata and keeps
/// fairness predictable for a Tokio task.
pub const MIN_DATAGRAMS: usize = 16;
pub const MAX_DATAGRAMS: usize = 100;

pub const fn adapt_batch_limit(current: usize, received: usize) -> usize {
    if received >= current && current < MAX_DATAGRAMS {
        match current {
            ..=MIN_DATAGRAMS => 32,
            17..=32 => 64,
            _ => MAX_DATAGRAMS,
        }
    } else if received == 0 || received.saturating_mul(4) <= current {
        match current {
            65.. => 64,
            33..=64 => 32,
            _ => MIN_DATAGRAMS,
        }
    } else {
        current
    }
}

/// Receive up to `packets.len()` datagrams from a connected UDP socket without
/// waiting.
///
/// On success, returns the number of leading `PacketBuf`s whose read lengths
/// were set.  If no datagram is currently available, returns
/// [`ErrorKind::WouldBlock`].  `packets` must contain no more than
/// [`MAX_DATAGRAMS`] elements.
pub fn try_recv_connected(socket: &UdpSocket, packets: &mut [PacketBuf]) -> io::Result<usize> {
    validate_batch_len(packets.len())?;
    platform::try_recv_connected(socket, packets)
}

/// Await one or more datagrams from a connected UDP socket.
///
/// The returned prefix has the same meaning as [`try_recv_connected`].  The
/// helper never allocates packet storage; callers keep control over the packet
/// pool and its backpressure policy.
#[allow(dead_code)] // TURN's hot path owns readiness so it can preserve pool backpressure.
pub async fn recv_connected(socket: &UdpSocket, packets: &mut [PacketBuf]) -> io::Result<usize> {
    validate_batch_len(packets.len())?;
    if packets.is_empty() {
        return Ok(0);
    }

    loop {
        socket.readable().await?;
        match try_recv_connected(socket, packets) {
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

/// Send the leading datagrams accepted by a connected UDP socket without
/// waiting.
///
/// The result is a prefix count: `Ok(n)` means exactly `datagrams[..n]` was
/// emitted.  It intentionally never retries the unsent suffix, so it is safe
/// for best-effort traffic such as an optional FEC duplicate.  For a complete
/// delivery attempt use [`send_connected`].
pub fn try_send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<usize> {
    validate_batch_len(datagrams.len())?;
    platform::try_send_connected(socket, datagrams)
}

/// Send every datagram to a connected UDP socket, waiting for writability as
/// necessary.
///
/// `sendmmsg` may accept only a prefix of a batch.  This function advances past
/// that prefix and retries *only* the remaining suffix, never retransmitting a
/// datagram that was already accepted by the kernel.
pub async fn send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<()> {
    validate_batch_len(datagrams.len())?;

    let mut sent = 0usize;
    while sent < datagrams.len() {
        socket.writable().await?;
        match try_send_connected(socket, &datagrams[sent..]) {
            Ok(0) => {
                // A nonempty UDP batch cannot make forward progress with a
                // successful zero-message send.  Treat it as stale readiness
                // and wait again instead of spinning.
                continue;
            }
            Ok(count) => sent += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Receive up to `packets.len()` datagrams and their source addresses from an
/// unconnected UDP socket without waiting.
///
/// `sources` must have exactly one slot for each supplied packet. On success,
/// the first returned-count entries in both slices form matching datagrams and
/// source addresses in wire order. If no datagram is currently available, the
/// function returns [`ErrorKind::WouldBlock`].
pub fn try_recv_from(
    socket: &UdpSocket,
    packets: &mut [PacketBuf],
    sources: &mut [std::net::SocketAddr],
) -> io::Result<usize> {
    validate_receive_batch(packets.len(), sources.len())?;
    platform::try_recv_from(socket, packets, sources)
}

/// Await one or more datagrams and their source addresses from an unconnected
/// UDP socket.
///
/// The returned prefixes of `packets` and `sources` correspond one-to-one and
/// are ordered as delivered by the kernel.
#[allow(dead_code)] // Dispatcher owns readiness to avoid reserving pool buffers while idle.
pub async fn recv_from(
    socket: &UdpSocket,
    packets: &mut [PacketBuf],
    sources: &mut [std::net::SocketAddr],
) -> io::Result<usize> {
    validate_receive_batch(packets.len(), sources.len())?;
    if packets.is_empty() {
        return Ok(0);
    }

    loop {
        socket.readable().await?;
        match try_recv_from(socket, packets, sources) {
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

/// Send the leading datagrams accepted by an unconnected UDP socket to one
/// destination without waiting.
///
/// The result has the same prefix semantics as [`try_send_connected`]. The
/// destination is copied into every native `mmsghdr`, so a caller can safely
/// reuse or replace its `SocketAddr` as soon as this function returns.
pub fn try_send_to(
    socket: &UdpSocket,
    destination: std::net::SocketAddr,
    datagrams: &[&[u8]],
) -> io::Result<usize> {
    validate_batch_len(datagrams.len())?;
    platform::try_send_to(socket, destination, datagrams)
}

/// Send every datagram to one destination, waiting for writability as needed.
///
/// A partial native `sendmmsg` advances the cursor before waiting or retrying,
/// so a datagram accepted by the kernel is never emitted a second time.
#[allow(dead_code)] // Dispatcher uses its own loop to retain cancellation semantics.
pub async fn send_to(
    socket: &UdpSocket,
    destination: std::net::SocketAddr,
    datagrams: &[&[u8]],
) -> io::Result<()> {
    validate_batch_len(datagrams.len())?;

    let mut sent = 0usize;
    while sent < datagrams.len() {
        socket.writable().await?;
        match try_send_to(socket, destination, &datagrams[sent..]) {
            Ok(0) => continue,
            Ok(count) => sent += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_batch_len(length: usize) -> io::Result<()> {
    if length <= MAX_DATAGRAMS {
        return Ok(());
    }
    Err(io::Error::new(
        ErrorKind::InvalidInput,
        format!("UDP batch contains {length} datagrams; limit is {MAX_DATAGRAMS}"),
    ))
}

fn validate_receive_batch(packet_count: usize, source_count: usize) -> io::Result<()> {
    validate_batch_len(packet_count)?;
    if packet_count == source_count {
        return Ok(());
    }
    Err(io::Error::new(
        ErrorKind::InvalidInput,
        format!(
            "UDP receive batch has {packet_count} packet buffers but {source_count} source slots"
        ),
    ))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn would_block() -> io::Error {
    io::Error::from(ErrorKind::WouldBlock)
}

fn short_datagram_send() -> io::Error {
    io::Error::new(ErrorKind::WriteZero, "UDP datagram was not sent atomically")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod platform {
    use super::{
        MAX_DATAGRAMS, PACKET_CAPACITY, PACKET_HEADROOM, PacketBuf, portable, would_block,
    };
    use socket2::{SockAddr, SockAddrStorage};
    use std::{
        io::{self, ErrorKind},
        net::SocketAddr,
        os::fd::AsRawFd,
        ptr,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::{io::Interest, net::UdpSocket};

    // Some Android kernels or seccomp profiles can expose the libc symbols but
    // reject the mmsg syscalls.  Capability is process-wide and direction
    // specific: one receive failure must not disable batch sends, or vice
    // versa.
    static RECV_MMSG_ENABLED: AtomicBool = AtomicBool::new(true);
    static SEND_MMSG_ENABLED: AtomicBool = AtomicBool::new(true);
    static RECV_FROM_MMSG_ENABLED: AtomicBool = AtomicBool::new(true);
    static SEND_TO_MMSG_ENABLED: AtomicBool = AtomicBool::new(true);

    pub(super) fn try_recv_connected(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
    ) -> io::Result<usize> {
        if !RECV_MMSG_ENABLED.load(Ordering::Acquire) {
            return portable::try_recv_connected(socket, packets);
        }
        match try_recv_mmsg(socket, packets) {
            Err(error) if mmsg_unavailable(&error) => {
                RECV_MMSG_ENABLED.store(false, Ordering::Release);
                portable::try_recv_connected(socket, packets)
            }
            result => result,
        }
    }

    fn try_recv_mmsg(socket: &UdpSocket, packets: &mut [PacketBuf]) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        let mut iovecs = empty_iovecs();
        let mut messages = empty_messages();
        for (index, packet) in packets.iter_mut().enumerate() {
            let area = packet.read_area();
            iovecs[index] = libc::iovec {
                iov_base: area.as_mut_ptr().cast(),
                iov_len: area.len(),
            };
            messages[index].msg_hdr.msg_iov = &mut iovecs[index];
            messages[index].msg_hdr.msg_iovlen = 1;
        }

        let received = socket.try_io(Interest::READABLE, || {
            loop {
                let result = unsafe {
                    libc::recvmmsg(
                        socket.as_raw_fd(),
                        messages.as_mut_ptr(),
                        packets.len() as libc::c_uint,
                        libc::MSG_DONTWAIT | libc::MSG_WAITFORONE,
                        ptr::null_mut(),
                    )
                };
                if result >= 0 {
                    break if result == 0 {
                        Err(would_block())
                    } else {
                        Ok(result as usize)
                    };
                }
                let error = io::Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        })?;

        if received > packets.len() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "recvmmsg returned more datagrams than requested",
            ));
        }

        // Do not hand truncated data to the protocol parser.  Check every
        // header before changing PacketBuf ranges so an error leaves no packet
        // marked as valid.
        for message in &messages[..received] {
            if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "received UDP datagram exceeds PacketBuf capacity",
                ));
            }
            let length = message.msg_len as usize;
            if length > PACKET_CAPACITY - PACKET_HEADROOM {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "recvmmsg reported an invalid UDP datagram length",
                ));
            }
        }

        for (packet, message) in packets.iter_mut().zip(&messages[..received]) {
            packet
                .set_read_len(message.msg_len as usize)
                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
        }
        Ok(received)
    }

    pub(super) fn try_recv_from(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
        sources: &mut [SocketAddr],
    ) -> io::Result<usize> {
        if !RECV_FROM_MMSG_ENABLED.load(Ordering::Acquire) {
            return portable::try_recv_from(socket, packets, sources);
        }
        match try_recvfrom_mmsg(socket, packets, sources) {
            Err(error) if mmsg_unavailable(&error) => {
                RECV_FROM_MMSG_ENABLED.store(false, Ordering::Release);
                portable::try_recv_from(socket, packets, sources)
            }
            result => result,
        }
    }

    fn try_recvfrom_mmsg(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
        sources: &mut [SocketAddr],
    ) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        let mut iovecs = empty_iovecs();
        let mut messages = empty_messages();
        let mut source_storage: [SockAddrStorage; MAX_DATAGRAMS] =
            std::array::from_fn(|_| SockAddrStorage::zeroed());
        for (index, packet) in packets.iter_mut().enumerate() {
            let area = packet.read_area();
            iovecs[index] = libc::iovec {
                iov_base: area.as_mut_ptr().cast(),
                iov_len: area.len(),
            };
            messages[index].msg_hdr.msg_name =
                (&mut source_storage[index] as *mut SockAddrStorage).cast();
            messages[index].msg_hdr.msg_namelen = source_storage[index].size_of();
            messages[index].msg_hdr.msg_iov = &mut iovecs[index];
            messages[index].msg_hdr.msg_iovlen = 1;
        }

        let received = socket.try_io(Interest::READABLE, || {
            loop {
                let result = unsafe {
                    libc::recvmmsg(
                        socket.as_raw_fd(),
                        messages.as_mut_ptr(),
                        packets.len() as libc::c_uint,
                        libc::MSG_DONTWAIT | libc::MSG_WAITFORONE,
                        ptr::null_mut(),
                    )
                };
                if result >= 0 {
                    break if result == 0 {
                        Err(would_block())
                    } else {
                        Ok(result as usize)
                    };
                }
                let error = io::Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        })?;

        if received > packets.len() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "recvmmsg returned more datagrams than requested",
            ));
        }

        let mut received_sources = [None; MAX_DATAGRAMS];
        for index in 0..received {
            let message = &messages[index];
            if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "received UDP datagram exceeds PacketBuf capacity",
                ));
            }
            let length = message.msg_len as usize;
            if length > PACKET_CAPACITY - PACKET_HEADROOM {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "recvmmsg reported an invalid UDP datagram length",
                ));
            }
            received_sources[index] = Some(socket_addr_from_storage(
                std::mem::replace(&mut source_storage[index], SockAddrStorage::zeroed()),
                message.msg_hdr.msg_namelen,
            )?);
        }

        for index in 0..received {
            let source = received_sources[index].ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "recvmmsg completed without a source address",
                )
            })?;
            packets[index]
                .set_read_len(messages[index].msg_len as usize)
                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
            // The address was validated into this exact matching slot above.
            sources[index] = source;
        }
        Ok(received)
    }

    pub(super) fn try_send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<usize> {
        if !SEND_MMSG_ENABLED.load(Ordering::Acquire) {
            return portable::try_send_connected(socket, datagrams);
        }
        match try_send_mmsg(socket, datagrams) {
            Err(error) if mmsg_unavailable(&error) => {
                SEND_MMSG_ENABLED.store(false, Ordering::Release);
                portable::try_send_connected(socket, datagrams)
            }
            result => result,
        }
    }

    fn try_send_mmsg(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<usize> {
        if datagrams.is_empty() {
            return Ok(0);
        }

        let mut iovecs = empty_iovecs();
        let mut messages = empty_messages();
        for (index, datagram) in datagrams.iter().enumerate() {
            iovecs[index] = libc::iovec {
                iov_base: datagram.as_ptr().cast_mut().cast(),
                iov_len: datagram.len(),
            };
            messages[index].msg_hdr.msg_iov = &mut iovecs[index];
            messages[index].msg_hdr.msg_iovlen = 1;
        }

        let sent = socket.try_io(Interest::WRITABLE, || {
            loop {
                let result = unsafe {
                    libc::sendmmsg(
                        socket.as_raw_fd(),
                        messages.as_mut_ptr(),
                        datagrams.len() as libc::c_uint,
                        libc::MSG_DONTWAIT,
                    )
                };
                if result >= 0 {
                    break if result == 0 {
                        Err(would_block())
                    } else {
                        Ok(result as usize)
                    };
                }
                let error = io::Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        })?;

        if sent > datagrams.len() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "sendmmsg accepted more datagrams than requested",
            ));
        }
        Ok(sent)
    }

    pub(super) fn try_send_to(
        socket: &UdpSocket,
        destination: SocketAddr,
        datagrams: &[&[u8]],
    ) -> io::Result<usize> {
        if !SEND_TO_MMSG_ENABLED.load(Ordering::Acquire) {
            return portable::try_send_to(socket, destination, datagrams);
        }
        match try_sendto_mmsg(socket, destination, datagrams) {
            Err(error) if mmsg_unavailable(&error) => {
                SEND_TO_MMSG_ENABLED.store(false, Ordering::Release);
                portable::try_send_to(socket, destination, datagrams)
            }
            result => result,
        }
    }

    fn try_sendto_mmsg(
        socket: &UdpSocket,
        destination: SocketAddr,
        datagrams: &[&[u8]],
    ) -> io::Result<usize> {
        if datagrams.is_empty() {
            return Ok(0);
        }

        // `sendmmsg` consumes every header synchronously. A single immutable
        // `SockAddr` is therefore sufficient for all messages and keeps IPv4,
        // IPv6, scope-id, and network-byte-order conversion in socket2.
        let destination = SockAddr::from(destination);
        let mut iovecs = empty_iovecs();
        let mut messages = empty_messages();
        for (index, datagram) in datagrams.iter().enumerate() {
            iovecs[index] = libc::iovec {
                iov_base: datagram.as_ptr().cast_mut().cast(),
                iov_len: datagram.len(),
            };
            messages[index].msg_hdr.msg_name = destination.as_ptr().cast_mut().cast();
            messages[index].msg_hdr.msg_namelen = destination.len();
            messages[index].msg_hdr.msg_iov = &mut iovecs[index];
            messages[index].msg_hdr.msg_iovlen = 1;
        }

        let sent = socket.try_io(Interest::WRITABLE, || {
            loop {
                let result = unsafe {
                    libc::sendmmsg(
                        socket.as_raw_fd(),
                        messages.as_mut_ptr(),
                        datagrams.len() as libc::c_uint,
                        libc::MSG_DONTWAIT,
                    )
                };
                if result >= 0 {
                    break if result == 0 {
                        Err(would_block())
                    } else {
                        Ok(result as usize)
                    };
                }
                let error = io::Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        })?;

        if sent > datagrams.len() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "sendmmsg accepted more datagrams than requested",
            ));
        }
        Ok(sent)
    }

    fn mmsg_unavailable(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(code)
                if code == libc::ENOSYS || code == libc::EPERM || code == libc::EOPNOTSUPP
        )
    }

    fn socket_addr_from_storage(
        mut storage: SockAddrStorage,
        length: libc::socklen_t,
    ) -> io::Result<SocketAddr> {
        let max_length = storage.size_of();
        if length < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t
            || length > max_length
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "recvmmsg returned an invalid source address length",
            ));
        }

        // `SockAddr::new` requires a family-compatible initialized storage.
        // Read only the initialized family field first, validate the complete
        // structure size for that family, and construct SockAddr only then.
        let family = unsafe { storage.view_as::<libc::sockaddr>() }.sa_family as libc::c_int;
        let minimum_length = match family {
            libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "recvmmsg returned a non-IP source address",
                ));
            }
        };
        if length < minimum_length {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "recvmmsg returned a truncated IP source address",
            ));
        }

        let address = unsafe { SockAddr::new(storage, length) };
        address.as_socket().ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                "recvmmsg returned an undecodable IP source address",
            )
        })
    }

    fn empty_iovecs() -> [libc::iovec; MAX_DATAGRAMS] {
        std::array::from_fn(|_| libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        })
    }

    fn empty_messages() -> [libc::mmsghdr; MAX_DATAGRAMS] {
        std::array::from_fn(|_| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: ptr::null_mut(),
                msg_iovlen: 0,
                msg_control: ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        })
    }
}

mod portable {
    use super::{PacketBuf, short_datagram_send};
    use std::{
        io::{self, ErrorKind},
        net::SocketAddr,
    };
    use tokio::net::UdpSocket;

    pub(crate) fn try_recv_connected(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
    ) -> io::Result<usize> {
        let mut received = 0usize;
        for packet in packets {
            match socket.try_recv(packet.read_area()) {
                Ok(length) => {
                    packet.set_read_len(length).map_err(|error| {
                        io::Error::new(ErrorKind::InvalidData, error.to_string())
                    })?;
                    received += 1;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock && received > 0 => {
                    return Ok(received);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(received)
    }

    pub(crate) fn try_send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<usize> {
        let mut sent = 0usize;
        for datagram in datagrams {
            match socket.try_send(datagram) {
                Ok(length) if length == datagram.len() => sent += 1,
                Ok(_) => return Err(short_datagram_send()),
                Err(error) if error.kind() == ErrorKind::WouldBlock && sent > 0 => {
                    return Ok(sent);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }

    pub(crate) fn try_recv_from(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
        sources: &mut [SocketAddr],
    ) -> io::Result<usize> {
        let mut received = 0usize;
        for (packet, source) in packets.iter_mut().zip(sources.iter_mut()) {
            match socket.try_recv_from(packet.read_area()) {
                Ok((length, address)) => {
                    packet.set_read_len(length).map_err(|error| {
                        io::Error::new(ErrorKind::InvalidData, error.to_string())
                    })?;
                    *source = address;
                    received += 1;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock && received > 0 => {
                    return Ok(received);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(received)
    }

    pub(crate) fn try_send_to(
        socket: &UdpSocket,
        destination: SocketAddr,
        datagrams: &[&[u8]],
    ) -> io::Result<usize> {
        let mut sent = 0usize;
        for datagram in datagrams {
            match socket.try_send_to(datagram, destination) {
                Ok(length) if length == datagram.len() => sent += 1,
                Ok(_) => return Err(short_datagram_send()),
                Err(error) if error.kind() == ErrorKind::WouldBlock && sent > 0 => {
                    return Ok(sent);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod platform {
    use super::{PacketBuf, portable};
    use std::{io, net::SocketAddr};
    use tokio::net::UdpSocket;

    pub(super) fn try_recv_connected(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
    ) -> io::Result<usize> {
        portable::try_recv_connected(socket, packets)
    }

    pub(super) fn try_send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<usize> {
        portable::try_send_connected(socket, datagrams)
    }

    pub(super) fn try_recv_from(
        socket: &UdpSocket,
        packets: &mut [PacketBuf],
        sources: &mut [SocketAddr],
    ) -> io::Result<usize> {
        portable::try_recv_from(socket, packets, sources)
    }

    pub(super) fn try_send_to(
        socket: &UdpSocket,
        destination: SocketAddr,
        datagrams: &[&[u8]],
    ) -> io::Result<usize> {
        portable::try_send_to(socket, destination, datagrams)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketPool;

    async fn connected_pair() -> io::Result<(UdpSocket, UdpSocket)> {
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        receiver.connect(sender.local_addr()?).await?;
        sender.connect(receiver.local_addr()?).await?;
        Ok((sender, receiver))
    }

    async fn unconnected_pair() -> io::Result<(UdpSocket, UdpSocket)> {
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        Ok((sender, receiver))
    }

    #[tokio::test]
    async fn sends_and_receives_a_connected_prefix() {
        let (sender, receiver) = connected_pair().await.unwrap();
        let datagrams: [&[u8]; 3] = [b"first", b"second", b"third"];

        send_connected(&sender, &datagrams).await.unwrap();

        let pool = PacketPool::new(MAX_DATAGRAMS);
        let mut packets: Vec<_> = (0..datagrams.len()).map(|_| pool.acquire()).collect();
        let received = recv_connected(&receiver, &mut packets).await.unwrap();

        assert_eq!(received, datagrams.len());
        for (packet, datagram) in packets.iter().zip(datagrams) {
            assert_eq!(packet.as_slice(), datagram);
        }
    }

    #[tokio::test]
    async fn try_send_reports_the_full_nonblocking_prefix_when_writable() {
        let (sender, receiver) = connected_pair().await.unwrap();
        let datagrams: [&[u8]; 2] = [b"one", b"two"];

        sender.writable().await.unwrap();
        assert_eq!(
            try_send_connected(&sender, &datagrams).unwrap(),
            datagrams.len()
        );

        let pool = PacketPool::new(MAX_DATAGRAMS);
        let mut packets = vec![pool.acquire(), pool.acquire()];
        assert_eq!(recv_connected(&receiver, &mut packets).await.unwrap(), 2);
        assert_eq!(packets[0].as_slice(), b"one");
        assert_eq!(packets[1].as_slice(), b"two");
    }

    #[tokio::test]
    async fn sends_and_receives_an_unconnected_batch_with_source_addresses() {
        let (sender, receiver) = unconnected_pair().await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let source = sender.local_addr().unwrap();
        let datagrams: [&[u8]; 3] = [b"alpha", b"beta", b"gamma"];

        send_to(&sender, destination, &datagrams).await.unwrap();

        let pool = PacketPool::new(MAX_DATAGRAMS);
        let mut packets: Vec<_> = (0..datagrams.len()).map(|_| pool.acquire()).collect();
        let mut sources = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); 3];
        let received = recv_from(&receiver, &mut packets, &mut sources)
            .await
            .unwrap();

        assert_eq!(received, datagrams.len());
        for ((packet, received_source), datagram) in packets.iter().zip(sources).zip(datagrams) {
            assert_eq!(packet.as_slice(), datagram);
            assert_eq!(received_source, source);
        }
    }

    #[test]
    fn rejects_batches_larger_than_the_fixed_limit() {
        let oversized = vec![b"packet".as_slice(); MAX_DATAGRAMS + 1];
        let error = validate_batch_len(oversized.len()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn adaptive_batch_limits_follow_the_discrete_ladder() {
        assert_eq!(adapt_batch_limit(MIN_DATAGRAMS, MIN_DATAGRAMS), 32);
        assert_eq!(adapt_batch_limit(32, 32), 64);
        assert_eq!(adapt_batch_limit(64, 64), MAX_DATAGRAMS);
        assert_eq!(adapt_batch_limit(MAX_DATAGRAMS, 25), 64);
        assert_eq!(adapt_batch_limit(64, 16), 32);
        assert_eq!(adapt_batch_limit(32, 8), MIN_DATAGRAMS);
    }

    #[test]
    fn rejects_receive_batches_without_matching_source_slots() {
        let error = validate_receive_batch(2, 1).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}
