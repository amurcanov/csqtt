// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::packet::PacketBuf;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::packet::{PACKET_CAPACITY, PACKET_HEADROOM};
use std::io::{self, ErrorKind};
use tokio::net::UdpSocket;

pub const MIN_DATAGRAMS: usize = 16;
pub const MAX_DATAGRAMS: usize = 128;

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

pub fn try_recv_connected(socket: &UdpSocket, packets: &mut [PacketBuf]) -> io::Result<usize> {
    validate_batch_len(packets.len())?;
    platform::try_recv_connected(socket, packets)
}

#[allow(dead_code)]
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

pub fn try_send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<usize> {
    validate_batch_len(datagrams.len())?;
    platform::try_send_connected(socket, datagrams)
}

pub async fn send_connected(socket: &UdpSocket, datagrams: &[&[u8]]) -> io::Result<()> {
    validate_batch_len(datagrams.len())?;

    let mut sent = 0usize;
    while sent < datagrams.len() {
        socket.writable().await?;
        match try_send_connected(socket, &datagrams[sent..]) {
            Ok(0) => {
                continue;
            }
            Ok(count) => sent += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn try_recv_from(
    socket: &UdpSocket,
    packets: &mut [PacketBuf],
    sources: &mut [std::net::SocketAddr],
) -> io::Result<usize> {
    validate_receive_batch(packets.len(), sources.len())?;
    platform::try_recv_from(socket, packets, sources)
}

#[allow(dead_code)]
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

pub fn try_send_to(
    socket: &UdpSocket,
    destination: std::net::SocketAddr,
    datagrams: &[&[u8]],
) -> io::Result<usize> {
    validate_batch_len(datagrams.len())?;
    platform::try_send_to(socket, destination, datagrams)
}

#[allow(dead_code)]
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
        mem::MaybeUninit,
        net::SocketAddr,
        os::fd::AsRawFd,
        ptr,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::{io::Interest, net::UdpSocket};

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

        let mut iovecs = uninit_iovecs();
        let mut messages = uninit_messages();
        for (index, packet) in packets.iter_mut().enumerate() {
            let area = packet.read_area();
            iovecs[index].write(libc::iovec {
                iov_base: area.as_mut_ptr().cast(),
                iov_len: area.len(),
            });
            messages[index].write(mmsg_header(iovecs[index].as_mut_ptr()));
        }
        let messages = initialized_messages(&mut messages, packets.len());

        let received = socket.try_io(Interest::READABLE, || {
            loop {
                let result = unsafe {
                    recv_mmsg(
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

        let mut iovecs = uninit_iovecs();
        let mut messages = uninit_messages();
        let mut source_storage = uninit_sources();
        for (index, packet) in packets.iter_mut().enumerate() {
            let area = packet.read_area();
            iovecs[index].write(libc::iovec {
                iov_base: area.as_mut_ptr().cast(),
                iov_len: area.len(),
            });
            let mut header = mmsg_header(iovecs[index].as_mut_ptr());
            header.msg_hdr.msg_name = source_storage[index].as_mut_ptr().cast();
            header.msg_hdr.msg_namelen = std::mem::size_of::<SockAddrStorage>() as libc::socklen_t;
            messages[index].write(header);
        }
        let messages = initialized_messages(&mut messages, packets.len());

        let received = socket.try_io(Interest::READABLE, || {
            loop {
                let result = unsafe {
                    recv_mmsg(
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
                unsafe { source_storage[index].assume_init_read() },
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

        let mut iovecs = uninit_iovecs();
        let mut messages = uninit_messages();
        for (index, datagram) in datagrams.iter().enumerate() {
            iovecs[index].write(libc::iovec {
                iov_base: datagram.as_ptr().cast_mut().cast(),
                iov_len: datagram.len(),
            });
            messages[index].write(mmsg_header(iovecs[index].as_mut_ptr()));
        }
        let messages = initialized_messages(&mut messages, datagrams.len());

        let sent = socket.try_io(Interest::WRITABLE, || {
            loop {
                let result = unsafe {
                    send_mmsg(
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

        let destination = SockAddr::from(destination);
        let mut iovecs = uninit_iovecs();
        let mut messages = uninit_messages();
        for (index, datagram) in datagrams.iter().enumerate() {
            iovecs[index].write(libc::iovec {
                iov_base: datagram.as_ptr().cast_mut().cast(),
                iov_len: datagram.len(),
            });
            let mut header = mmsg_header(iovecs[index].as_mut_ptr());
            header.msg_hdr.msg_name = destination.as_ptr().cast_mut().cast();
            header.msg_hdr.msg_namelen = destination.len();
            messages[index].write(header);
        }
        let messages = initialized_messages(&mut messages, datagrams.len());

        let sent = socket.try_io(Interest::WRITABLE, || {
            loop {
                let result = unsafe {
                    send_mmsg(
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

    unsafe fn recv_mmsg(
        fd: libc::c_int,
        messages: *mut libc::mmsghdr,
        count: libc::c_uint,
        flags: libc::c_int,
        timeout: *mut libc::timespec,
    ) -> libc::c_int {
        #[cfg(target_os = "android")]
        {
            unsafe {
                libc::syscall(
                    libc::SYS_recvmmsg as libc::c_long,
                    fd,
                    messages,
                    count,
                    flags,
                    timeout,
                ) as libc::c_int
            }
        }
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::recvmmsg(fd, messages, count, flags, timeout) }
        }
    }

    unsafe fn send_mmsg(
        fd: libc::c_int,
        messages: *mut libc::mmsghdr,
        count: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::c_int {
        #[cfg(target_os = "android")]
        {
            unsafe {
                libc::syscall(
                    libc::SYS_sendmmsg as libc::c_long,
                    fd,
                    messages,
                    count,
                    flags,
                ) as libc::c_int
            }
        }
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::sendmmsg(fd, messages, count, flags) }
        }
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

    fn uninit_iovecs() -> [MaybeUninit<libc::iovec>; MAX_DATAGRAMS] {
        [const { MaybeUninit::uninit() }; MAX_DATAGRAMS]
    }

    fn uninit_messages() -> [MaybeUninit<libc::mmsghdr>; MAX_DATAGRAMS] {
        [const { MaybeUninit::uninit() }; MAX_DATAGRAMS]
    }

    fn uninit_sources() -> [MaybeUninit<SockAddrStorage>; MAX_DATAGRAMS] {
        [const { MaybeUninit::zeroed() }; MAX_DATAGRAMS]
    }

    fn initialized_messages(
        messages: &mut [MaybeUninit<libc::mmsghdr>; MAX_DATAGRAMS],
        count: usize,
    ) -> &mut [libc::mmsghdr] {
        unsafe { std::slice::from_raw_parts_mut(messages.as_mut_ptr().cast(), count) }
    }

    fn mmsg_header(iovec: *mut libc::iovec) -> libc::mmsghdr {
        libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iovec,
                msg_iovlen: 1,
                msg_control: ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        }
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

    #[tokio::test]
    async fn maximum_unconnected_mmsg_batch_preserves_every_datagram_and_source() {
        let (sender, receiver) = unconnected_pair().await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let source = sender.local_addr().unwrap();
        let payloads: Vec<Vec<u8>> = (0..MAX_DATAGRAMS)
            .map(|index| vec![index as u8; 192])
            .collect();
        let datagrams: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();

        send_to(&sender, destination, &datagrams).await.unwrap();

        let pool = PacketPool::new(MAX_DATAGRAMS);
        let mut packets: Vec<_> = (0..MAX_DATAGRAMS).map(|_| pool.acquire()).collect();
        let mut sources = vec![std::net::SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAMS];
        let mut total_received = 0usize;
        while total_received < MAX_DATAGRAMS {
            let received = recv_from(
                &receiver,
                &mut packets[total_received..],
                &mut sources[total_received..],
            )
            .await
            .unwrap();
            assert!(received > 0);
            total_received += received;
        }

        assert_eq!(total_received, MAX_DATAGRAMS);
        for index in 0..MAX_DATAGRAMS {
            assert_eq!(packets[index].as_slice(), datagrams[index]);
            assert_eq!(sources[index], source);
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

    macro_rules! adaptive_limit_case {
        ($name:ident, $current:expr, $received:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(adapt_batch_limit($current, $received), $expected);
            }
        };
    }

    adaptive_limit_case!(adaptive_limit_promotes_minimum_batch, 16, 16, 32);
    adaptive_limit_case!(adaptive_limit_promotes_32_to_64, 32, 32, 64);
    adaptive_limit_case!(adaptive_limit_promotes_64_to_maximum, 64, 64, MAX_DATAGRAMS);
    adaptive_limit_case!(
        adaptive_limit_keeps_full_maximum_batch,
        MAX_DATAGRAMS,
        MAX_DATAGRAMS,
        MAX_DATAGRAMS
    );
    adaptive_limit_case!(
        adaptive_limit_reduces_maximum_on_quarter_fill,
        MAX_DATAGRAMS,
        MAX_DATAGRAMS / 4,
        64
    );
    adaptive_limit_case!(adaptive_limit_reduces_64_on_quarter_fill, 64, 16, 32);
    adaptive_limit_case!(adaptive_limit_reduces_32_on_quarter_fill, 32, 8, 16);
    adaptive_limit_case!(adaptive_limit_keeps_minimum_when_socket_is_empty, 16, 0, 16);

    macro_rules! accepted_batch_length_case {
        ($name:ident, $length:expr) => {
            #[test]
            fn $name() {
                assert!(validate_batch_len($length).is_ok());
            }
        };
    }

    accepted_batch_length_case!(batch_length_accepts_empty_control_batch, 0);
    accepted_batch_length_case!(batch_length_accepts_single_datagram, 1);
    accepted_batch_length_case!(batch_length_accepts_minimum_batch, MIN_DATAGRAMS);
    accepted_batch_length_case!(batch_length_accepts_maximum_batch, MAX_DATAGRAMS);

    macro_rules! matching_receive_slots_case {
        ($name:ident, $length:expr) => {
            #[test]
            fn $name() {
                assert!(validate_receive_batch($length, $length).is_ok());
            }
        };
    }

    matching_receive_slots_case!(receive_slots_accept_empty_batch, 0);
    matching_receive_slots_case!(receive_slots_accept_single_datagram, 1);
    matching_receive_slots_case!(receive_slots_accept_minimum_batch, MIN_DATAGRAMS);
    matching_receive_slots_case!(receive_slots_accept_maximum_batch, MAX_DATAGRAMS);
}
