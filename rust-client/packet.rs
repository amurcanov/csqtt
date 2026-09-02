// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::client_perf::{self, Stage as PerfStage};
use anyhow::{Result, bail};
use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use std::{
    mem,
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub const PACKET_HEADROOM: usize = 64;
pub const PACKET_CAPACITY: usize = 2304;
pub const PACKET_POOL_PER_WORKER: usize = 256;
pub const PACKET_POOL_SHARED: usize = 512;
const PACKET_POOL_RETAINED_MAX: usize = 2048;

pub const fn packet_pool_size(workers: usize) -> usize {
    workers
        .saturating_mul(PACKET_POOL_PER_WORKER)
        .saturating_add(PACKET_POOL_SHARED)
}

pub struct PacketPool {
    queue: ArrayQueue<BytesMut>,
    allocated: AtomicUsize,
    allocation_limit: usize,
}

impl PacketPool {
    pub fn new(buffers: usize) -> Arc<Self> {
        let capacity = buffers.max(1);
        let retained_limit = capacity.min(PACKET_POOL_RETAINED_MAX);
        Arc::new(Self {
            queue: ArrayQueue::new(retained_limit),
            allocated: AtomicUsize::new(0),
            allocation_limit: capacity,
        })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<PacketBuf> {
        client_perf::measure_sampled(PerfStage::PacketPool, 128, || self.try_acquire_inner())
    }

    fn try_acquire_inner(self: &Arc<Self>) -> Option<PacketBuf> {
        let storage = if let Some(storage) = self.queue.pop() {
            storage
        } else {
            self.allocated
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |allocated| {
                    (allocated < self.allocation_limit).then_some(allocated + 1)
                })
                .ok()?;
            BytesMut::zeroed(PACKET_CAPACITY)
        };
        Some(PacketBuf {
            storage,
            range: PACKET_HEADROOM..PACKET_HEADROOM,
            pool: self.clone(),
        })
    }

    #[cfg(test)]
    pub fn acquire(self: &Arc<Self>) -> PacketBuf {
        self.try_acquire().expect("test packet pool exhausted")
    }

    #[cfg(test)]
    pub fn capacity(&self) -> usize {
        self.allocation_limit
    }

    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.allocation_limit
            .saturating_sub(self.allocated.load(Ordering::Acquire))
            .saturating_add(self.queue.len())
    }

    #[cfg(test)]
    pub fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn retained(&self) -> usize {
        self.queue.len()
    }

    fn release(&self, storage: BytesMut) {
        client_perf::measure_sampled(PerfStage::PacketPool, 128, || self.release_inner(storage));
    }

    fn release_inner(&self, storage: BytesMut) {
        if storage.len() != PACKET_CAPACITY {
            self.allocated.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        if self.queue.push(storage).is_err() {
            self.allocated.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

pub struct PacketBuf {
    storage: BytesMut,
    range: Range<usize>,
    pool: Arc<PacketPool>,
}

impl PacketBuf {
    pub fn len(&self) -> usize {
        self.range.len()
    }

    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.range.clone()]
    }

    #[allow(dead_code)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.range.clone()]
    }

    pub fn read_area(&mut self) -> &mut [u8] {
        let start = PACKET_HEADROOM;
        &mut self.storage[start..PACKET_CAPACITY]
    }

    pub fn set_read_len(&mut self, len: usize) -> Result<()> {
        if len > PACKET_CAPACITY - PACKET_HEADROOM {
            bail!("packet read length exceeds capacity");
        }
        self.range = PACKET_HEADROOM..PACKET_HEADROOM + len;
        Ok(())
    }

    pub fn prepend(&mut self, len: usize) -> Result<&mut [u8]> {
        if len > self.range.start {
            bail!("packet prepend exceeds headroom");
        }
        self.range.start -= len;
        Ok(&mut self.storage[self.range.start..self.range.start + len])
    }

    pub fn extend_tail(&mut self, len: usize) -> Result<&mut [u8]> {
        let Some(end) = self.range.end.checked_add(len) else {
            bail!("packet tail length overflow");
        };
        if end > PACKET_CAPACITY {
            bail!("packet tail exceeds capacity");
        }
        let start = self.range.end;
        self.range.end = end;
        Ok(&mut self.storage[start..end])
    }

    pub fn trim_front(&mut self, len: usize) -> Result<()> {
        if len > self.range.len() {
            bail!("packet trim exceeds length");
        }
        self.range.start += len;
        Ok(())
    }

    pub fn truncate(&mut self, len: usize) -> Result<()> {
        if len > self.range.len() {
            bail!("packet truncate exceeds length");
        }
        self.range.end = self.range.start + len;
        Ok(())
    }

    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub fn storage_mut(&mut self) -> &mut BytesMut {
        &mut self.storage
    }

    pub fn set_range(&mut self, range: Range<usize>) -> Result<()> {
        if range.start > range.end || range.end > PACKET_CAPACITY {
            bail!("packet range is invalid");
        }
        self.range = range;
        Ok(())
    }
}

impl AsRef<[u8]> for PacketBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        self.pool.release(mem::take(&mut self.storage));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headroom_and_pool_reuse() {
        let pool = PacketPool::new(1);
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.allocated(), 0);
        assert_eq!(pool.retained(), 0);
        {
            let mut packet = pool.acquire();
            packet.read_area()[..4].copy_from_slice(b"data");
            packet.set_read_len(4).unwrap();
            packet.prepend(2).unwrap().copy_from_slice(b"hd");
            assert_eq!(packet.as_slice(), b"hddata");
            packet.trim_front(2).unwrap();
            assert_eq!(packet.as_slice(), b"data");
        }
        assert_eq!(pool.acquire().len(), 0);
    }

    #[test]
    fn invalid_ranges_return_errors() {
        let pool = PacketPool::new(0);
        let mut packet = pool.acquire();
        assert!(packet.set_read_len(PACKET_CAPACITY).is_err());
        assert!(packet.prepend(PACKET_HEADROOM + 1).is_err());
        assert!(packet.extend_tail(PACKET_CAPACITY).is_err());
        assert!(packet.trim_front(1).is_err());
        assert!(packet.truncate(1).is_err());
        let invalid_start = 9;
        let invalid_end = 8;
        assert!(packet.set_range(invalid_start..invalid_end).is_err());
        assert!(packet.set_range(0..PACKET_CAPACITY + 1).is_err());
    }

    #[test]
    fn maximum_read_area_is_accepted() {
        let pool = PacketPool::new(1);
        let mut packet = pool.acquire();
        let maximum = PACKET_CAPACITY - PACKET_HEADROOM;
        packet.set_read_len(maximum).unwrap();
        assert_eq!(packet.len(), maximum);
    }

    #[test]
    fn exact_headroom_and_tail_capacity_are_accepted() {
        let pool = PacketPool::new(1);
        let mut packet = pool.acquire();
        packet
            .set_read_len(PACKET_CAPACITY - PACKET_HEADROOM)
            .unwrap();
        packet.prepend(PACKET_HEADROOM).unwrap();
        packet.extend_tail(0).unwrap();
        assert_eq!(packet.len(), PACKET_CAPACITY);
    }

    #[test]
    fn packet_budget_is_strict_and_recovers_after_release() {
        let pool = PacketPool::new(2);
        let first = pool.try_acquire().unwrap();
        let second = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());
        assert_eq!(pool.available(), 0);
        drop(first);
        assert!(pool.try_acquire().is_some());
        drop(second);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn concurrent_deficit_never_exceeds_packet_budget_or_leaks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let pool = PacketPool::new(8);
        let in_use = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let pool = pool.clone();
                let in_use = in_use.clone();
                let maximum = maximum.clone();
                scope.spawn(move || {
                    for _ in 0..10_000 {
                        let Some(packet) = pool.try_acquire() else {
                            std::thread::yield_now();
                            continue;
                        };
                        let current = in_use.fetch_add(1, Ordering::AcqRel) + 1;
                        maximum.fetch_max(current, Ordering::AcqRel);
                        in_use.fetch_sub(1, Ordering::AcqRel);
                        drop(packet);
                    }
                });
            }
        });
        assert!(maximum.load(Ordering::Acquire) <= pool.capacity());
        assert_eq!(in_use.load(Ordering::Acquire), 0);
        assert_eq!(pool.available(), pool.capacity());
        assert!(pool.allocated() <= pool.capacity());
    }

    #[test]
    fn large_pool_retains_only_bounded_idle_storage() {
        let pool = PacketPool::new(PACKET_POOL_RETAINED_MAX * 2);
        let packets = (0..pool.capacity())
            .map(|_| pool.try_acquire().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pool.allocated(), pool.capacity());
        drop(packets);
        assert_eq!(pool.available(), pool.capacity());
        assert_eq!(pool.retained(), PACKET_POOL_RETAINED_MAX);
        assert_eq!(pool.allocated(), PACKET_POOL_RETAINED_MAX);
    }

    #[test]
    fn production_pool_covers_all_bounded_worker_queues() {
        for (workers, expected) in [(9, 2_816), (27, 7_424), (108, 28_160), (126, 32_768)] {
            assert_eq!(packet_pool_size(workers), expected);
        }
    }
}
