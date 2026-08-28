use crate::{packet::PacketBuffer, striped_scheduler::PacketClass};
use std::collections::VecDeque;

const LATENCY_SLOTS: usize = 16;
const PRIORITY_MIN_SLOTS: usize = 32;
const PRIORITY_MAX_SLOTS: usize = 252;
const PRIORITY_SLOTS_PER_PATH: usize = 2;
const BULK_MIN_SLOTS: usize = 72;
const BULK_MAX_SLOTS: usize = 1_008;
const BULK_SLOTS_PER_PATH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientQueueProfile {
    pub latency_slots: usize,
    pub priority_slots: usize,
    pub bulk_slots: usize,
}

pub fn profile_for_active_paths(active_paths: usize) -> ClientQueueProfile {
    let active_paths = active_paths.min(PRIORITY_MAX_SLOTS / PRIORITY_SLOTS_PER_PATH);
    if active_paths == 0 {
        return ClientQueueProfile {
            latency_slots: 0,
            priority_slots: 0,
            bulk_slots: 0,
        };
    }
    ClientQueueProfile {
        latency_slots: LATENCY_SLOTS,
        priority_slots: active_paths
            .saturating_mul(PRIORITY_SLOTS_PER_PATH)
            .clamp(PRIORITY_MIN_SLOTS, PRIORITY_MAX_SLOTS),
        bulk_slots: active_paths
            .saturating_mul(BULK_SLOTS_PER_PATH)
            .clamp(BULK_MIN_SLOTS, BULK_MAX_SLOTS),
    }
}

#[derive(Default)]
struct PacketSlots {
    free: Vec<PacketBuffer>,
    pending: VecDeque<PacketBuffer>,
}

impl PacketSlots {
    fn resize(&mut self, capacity: usize) {
        while self.free.len().saturating_add(self.pending.len()) < capacity {
            self.free.push(PacketBuffer::new());
        }
        while self.free.len().saturating_add(self.pending.len()) > capacity {
            if self.free.pop().is_none() {
                self.pending.pop_back();
            }
        }
        if capacity == 0 {
            self.free.clear();
            self.pending.clear();
            self.free.shrink_to_fit();
            self.pending.shrink_to_fit();
        }
    }

    fn enqueue(&mut self, packet: &[u8]) -> bool {
        let Some(mut slot) = self.free.pop() else {
            return false;
        };
        if !slot.copy_from(packet) {
            self.free.push(slot);
            return false;
        }
        self.pending.push_back(slot);
        true
    }

    fn dequeue(&mut self) -> Option<PacketBuffer> {
        self.pending.pop_front()
    }

    fn requeue_front(&mut self, packet: PacketBuffer) {
        self.pending.push_front(packet);
    }

    fn recycle(&mut self, packet: PacketBuffer) {
        self.free.push(packet);
    }

    fn clear_pending(&mut self) {
        while let Some(packet) = self.pending.pop_front() {
            self.free.push(packet);
        }
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[derive(Default)]
struct ClientEgressLane {
    active_paths: usize,
    latency: PacketSlots,
    priority: PacketSlots,
    bulk: PacketSlots,
}

impl ClientEgressLane {
    fn configure(&mut self, active_paths: usize) {
        self.active_paths = active_paths.min(PRIORITY_MAX_SLOTS / PRIORITY_SLOTS_PER_PATH);
        let profile = profile_for_active_paths(self.active_paths);
        self.latency.resize(profile.latency_slots);
        self.priority.resize(profile.priority_slots);
        self.bulk.resize(profile.bulk_slots);
    }

    fn queue_mut(&mut self, class: PacketClass) -> &mut PacketSlots {
        match class {
            PacketClass::Latency => &mut self.latency,
            PacketClass::Priority => &mut self.priority,
            PacketClass::Bulk => &mut self.bulk,
        }
    }

    fn clear_pending(&mut self) {
        self.latency.clear_pending();
        self.priority.clear_pending();
        self.bulk.clear_pending();
    }

    #[cfg(test)]
    fn queue(&self, class: PacketClass) -> &PacketSlots {
        match class {
            PacketClass::Latency => &self.latency,
            PacketClass::Priority => &self.priority,
            PacketClass::Bulk => &self.bulk,
        }
    }
}

pub struct DownlinkQueue {
    lanes: Box<[ClientEgressLane; 256]>,
    latency_ring: Vec<usize>,
    priority_ring: Vec<usize>,
    bulk_ring: Vec<usize>,
    latency_cursor: usize,
    priority_cursor: usize,
    bulk_cursor: usize,
}

impl Default for DownlinkQueue {
    fn default() -> Self {
        Self {
            lanes: Box::new(std::array::from_fn(|_| ClientEgressLane::default())),
            latency_ring: Vec::new(),
            priority_ring: Vec::new(),
            bulk_ring: Vec::new(),
            latency_cursor: 0,
            priority_cursor: 0,
            bulk_cursor: 0,
        }
    }
}

impl DownlinkQueue {
    pub fn configure(&mut self, key: usize, active_paths: usize) {
        let Some(lane) = self.lanes.get_mut(key) else {
            return;
        };
        if lane.active_paths == active_paths.min(PRIORITY_MAX_SLOTS / PRIORITY_SLOTS_PER_PATH) {
            return;
        }
        lane.configure(active_paths);
        self.rebuild_rings();
    }

    pub fn enqueue(&mut self, key: usize, class: PacketClass, packet: &[u8]) -> bool {
        self.lanes
            .get_mut(key)
            .is_some_and(|lane| lane.active_paths != 0 && lane.queue_mut(class).enqueue(packet))
    }

    pub fn dequeue(&mut self, class: PacketClass) -> Option<(usize, PacketBuffer)> {
        let attempts = self.ring_len(class);
        for _ in 0..attempts {
            let key = self.next_key(class)?;
            let lane = &mut self.lanes[key];
            if let Some(packet) = lane.queue_mut(class).dequeue() {
                return Some((key, packet));
            }
        }
        None
    }

    pub fn requeue_front(&mut self, key: usize, class: PacketClass, packet: PacketBuffer) {
        if let Some(lane) = self.lanes.get_mut(key) {
            lane.queue_mut(class).requeue_front(packet);
        }
    }

    pub fn recycle(&mut self, key: usize, class: PacketClass, packet: PacketBuffer) {
        if let Some(lane) = self.lanes.get_mut(key) {
            lane.queue_mut(class).recycle(packet);
        }
    }

    pub fn clear(&mut self, key: usize) {
        if let Some(lane) = self.lanes.get_mut(key) {
            lane.clear_pending();
        }
    }

    fn rebuild_rings(&mut self) {
        self.latency_ring.clear();
        self.priority_ring.clear();
        self.bulk_ring.clear();
        for (key, lane) in self.lanes.iter().enumerate() {
            if lane.active_paths == 0 {
                continue;
            }
            self.latency_ring.push(key);
            self.priority_ring.push(key);
            self.bulk_ring
                .extend(std::iter::repeat_n(key, lane.active_paths));
        }
        self.latency_cursor %= self.latency_ring.len().max(1);
        self.priority_cursor %= self.priority_ring.len().max(1);
        self.bulk_cursor %= self.bulk_ring.len().max(1);
    }

    fn ring_len(&self, class: PacketClass) -> usize {
        match class {
            PacketClass::Latency => self.latency_ring.len(),
            PacketClass::Priority => self.priority_ring.len(),
            PacketClass::Bulk => self.bulk_ring.len(),
        }
    }

    fn next_key(&mut self, class: PacketClass) -> Option<usize> {
        let (ring, cursor) = match class {
            PacketClass::Latency => (&self.latency_ring, &mut self.latency_cursor),
            PacketClass::Priority => (&self.priority_ring, &mut self.priority_cursor),
            PacketClass::Bulk => (&self.bulk_ring, &mut self.bulk_cursor),
        };
        let key = *ring.get(*cursor)?;
        *cursor += 1;
        if *cursor == ring.len() {
            *cursor = 0;
        }
        Some(key)
    }

    #[cfg(test)]
    fn pending_len(&self, key: usize, class: PacketClass) -> usize {
        self.lanes
            .get(key)
            .map_or(0, |lane| lane.queue(class).pending_len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(value: u8) -> [u8; 24] {
        [value; 24]
    }

    #[test]
    fn profiles_cover_each_supported_worker_total() {
        for active_paths in [9, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99, 108, 117, 126] {
            let profile = profile_for_active_paths(active_paths);
            assert_eq!(profile.latency_slots, 16);
            assert_eq!(profile.priority_slots, (active_paths * 2).max(32));
            assert_eq!(profile.bulk_slots, active_paths * 8);
        }
    }

    #[test]
    fn bulk_ring_is_weighted_by_active_paths() {
        let mut queue = DownlinkQueue::default();
        queue.configure(2, 9);
        queue.configure(3, 18);
        for value in 0..27u8 {
            assert!(queue.enqueue(2, PacketClass::Bulk, &packet(value)));
            assert!(queue.enqueue(3, PacketClass::Bulk, &packet(value)));
        }
        let mut first = 0usize;
        let mut second = 0usize;
        for _ in 0..27 {
            let (key, packet) = queue.dequeue(PacketClass::Bulk).unwrap();
            queue.recycle(key, PacketClass::Bulk, packet);
            match key {
                2 => first += 1,
                3 => second += 1,
                _ => unreachable!(),
            }
        }
        assert_eq!(first, 9);
        assert_eq!(second, 18);
    }

    #[test]
    fn lanes_have_independent_bulk_capacity() {
        let mut queue = DownlinkQueue::default();
        queue.configure(2, 9);
        queue.configure(3, 9);
        for value in 0..72u8 {
            assert!(queue.enqueue(2, PacketClass::Bulk, &packet(value)));
        }
        assert!(!queue.enqueue(2, PacketClass::Bulk, &packet(99)));
        assert!(queue.enqueue(3, PacketClass::Bulk, &packet(100)));
        assert_eq!(queue.pending_len(2, PacketClass::Bulk), 72);
        assert_eq!(queue.pending_len(3, PacketClass::Bulk), 1);
    }

    #[test]
    fn shrinking_active_paths_discards_only_excess_packets_from_the_lane() {
        let mut queue = DownlinkQueue::default();
        queue.configure(5, 18);
        for value in 0..144u8 {
            assert!(queue.enqueue(5, PacketClass::Bulk, &packet(value)));
        }
        queue.configure(5, 9);
        assert_eq!(queue.pending_len(5, PacketClass::Bulk), 72);
    }

    #[test]
    fn clearing_a_lane_keeps_its_reserved_slots_isolated() {
        let mut queue = DownlinkQueue::default();
        queue.configure(5, 18);
        queue.configure(6, 18);
        assert!(queue.enqueue(5, PacketClass::Bulk, &packet(1)));
        assert!(queue.enqueue(6, PacketClass::Bulk, &packet(2)));
        queue.clear(5);
        assert_eq!(queue.pending_len(5, PacketClass::Bulk), 0);
        assert_eq!(queue.pending_len(6, PacketClass::Bulk), 1);
        for value in 0..144u8 {
            assert!(queue.enqueue(5, PacketClass::Bulk, &packet(value)));
        }
    }

    #[test]
    fn inactive_lane_rejects_packets_until_it_is_reactivated() {
        let mut queue = DownlinkQueue::default();
        assert!(!queue.enqueue(5, PacketClass::Bulk, &packet(1)));
        queue.configure(5, 18);
        assert!(queue.enqueue(5, PacketClass::Bulk, &packet(2)));
        queue.configure(5, 0);
        assert!(!queue.enqueue(5, PacketClass::Bulk, &packet(3)));
        queue.configure(5, 18);
        assert!(queue.enqueue(5, PacketClass::Bulk, &packet(4)));
    }
}
