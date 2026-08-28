// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use std::{
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub const PACKET_CAPACITY: usize = 1600;
pub const UDP_TX_SLOTS: usize = 4096;
pub const TUN_TX_SLOTS: usize = 1024;
pub const TUN_MTU: u16 = 1300;
pub const PACKET_POOL_RETAINED_MAX: usize = 256;

pub const fn packet_pool_size() -> usize {
    UDP_TX_SLOTS + TUN_TX_SLOTS
}

pub struct PacketPool {
    queue: ArrayQueue<BytesMut>,
    allocated: AtomicUsize,
    retained: AtomicUsize,
    retained_limit: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PacketPoolSnapshot {
    pub capacity: usize,
    pub allocated: usize,
    pub retained: usize,
}

impl PacketPool {
    pub fn new(buffers: usize) -> Arc<Self> {
        let capacity = buffers.max(1);
        Arc::new(Self {
            queue: ArrayQueue::new(capacity),
            allocated: AtomicUsize::new(0),
            retained: AtomicUsize::new(0),
            retained_limit: capacity.min(PACKET_POOL_RETAINED_MAX),
        })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<PacketBuf> {
        let storage = if let Some(storage) = self.queue.pop() {
            self.retained.fetch_sub(1, Ordering::AcqRel);
            storage
        } else {
            self.allocated
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |allocated| {
                    (allocated < self.queue.capacity()).then_some(allocated + 1)
                })
                .ok()?;
            BytesMut::zeroed(PACKET_CAPACITY)
        };
        Some(PacketBuf {
            storage,
            len: 0,
            pool: self.clone(),
        })
    }

    pub fn snapshot(&self) -> PacketPoolSnapshot {
        PacketPoolSnapshot {
            capacity: self.queue.capacity(),
            allocated: self.allocated.load(Ordering::Acquire),
            retained: self.retained.load(Ordering::Acquire),
        }
    }

    fn release(&self, storage: BytesMut) {
        if storage.len() != PACKET_CAPACITY {
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
        if self.queue.push(storage).is_err() {
            self.retained.fetch_sub(1, Ordering::AcqRel);
            self.allocated.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

pub struct PacketBuf {
    storage: BytesMut,
    len: usize,
    pool: Arc<PacketPool>,
}

impl PacketBuf {
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    #[inline(always)]
    pub fn storage_mut(&mut self) -> &mut [u8] {
        &mut self.storage[..]
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) -> bool {
        if len > PACKET_CAPACITY {
            return false;
        }
        self.len = len;
        true
    }

    #[inline(always)]
    pub fn copy_from(&mut self, data: &[u8]) -> bool {
        if data.len() > PACKET_CAPACITY {
            return false;
        }
        self.storage[..data.len()].copy_from_slice(data);
        self.len = data.len();
        true
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_ptr()
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        self.pool.release(mem::take(&mut self.storage));
    }
}

pub struct PacketBuffer {
    bytes: [u8; PACKET_CAPACITY],
    len: usize,
}

impl PacketBuffer {
    pub fn new() -> Self {
        Self {
            bytes: [0; PACKET_CAPACITY],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        PACKET_CAPACITY
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) -> bool {
        if len > PACKET_CAPACITY {
            return false;
        }
        self.len = len;
        true
    }

    #[inline(always)]
    pub fn copy_from(&mut self, data: &[u8]) -> bool {
        if data.len() > PACKET_CAPACITY {
            return false;
        }
        self.bytes[..data.len()].copy_from_slice(data);
        self.len = data.len();
        true
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
pub fn extract_dst_ipv4(packet: &[u8]) -> Option<[u8; 4]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some([packet[16], packet[17], packet[18], packet[19]])
}

pub fn socket_addr_to_storage(
    address: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    unsafe {
        std::ptr::write_bytes(
            storage as *mut libc::sockaddr_storage as *mut u8,
            0,
            std::mem::size_of::<libc::sockaddr_storage>(),
        );
    }
    match address {
        SocketAddr::V4(address) => {
            let raw = storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
            unsafe {
                (*raw).sin_family = libc::AF_INET as libc::sa_family_t;
                (*raw).sin_port = address.port().to_be();
                (*raw).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                };
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(address) => {
            let raw = storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
            unsafe {
                (*raw).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*raw).sin6_port = address.port().to_be();
                (*raw).sin6_flowinfo = address.flowinfo();
                (*raw).sin6_addr = libc::in6_addr {
                    s6_addr: address.ip().octets(),
                };
                (*raw).sin6_scope_id = address.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

pub fn storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let raw =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(raw.sin_port)))
        }
        libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let raw = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            let ip = Ipv6Addr::from(raw.sin6_addr.s6_addr);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(raw.sin6_port),
                raw.sin6_flowinfo,
                raw.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_pool_is_bounded_and_recovers_buffers() {
        let pool = PacketPool::new(2);
        let first = pool.try_acquire().expect("first packet");
        let second = pool.try_acquire().expect("second packet");
        assert!(pool.try_acquire().is_none());
        assert_eq!(pool.snapshot().allocated, 2);
        drop(first);
        drop(second);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.capacity, 2);
        assert_eq!(snapshot.allocated, 2);
        assert_eq!(snapshot.retained, 2);
    }

    #[test]
    fn packet_pool_discards_excess_idle_storage() {
        let capacity = PACKET_POOL_RETAINED_MAX + 8;
        let pool = PacketPool::new(capacity);
        let packets = (0..capacity)
            .map(|_| pool.try_acquire().expect("packet pool capacity"))
            .collect::<Vec<_>>();
        drop(packets);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.retained, PACKET_POOL_RETAINED_MAX);
        assert_eq!(snapshot.allocated, PACKET_POOL_RETAINED_MAX);
    }
}
