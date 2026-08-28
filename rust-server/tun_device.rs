// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    packet::extract_dst_ipv4,
    striped_scheduler::{
        BULK_STRIPE_PACKET_CHUNK, LATENCY_STRIPE_PACKET_CHUNK, PRIORITY_STRIPE_PACKET_CHUNK,
        PacketClass,
    },
};
use std::net::Ipv4Addr;

pub const TUN_IFACE: &str = "csqtt1";
pub const TUN_SUBNET: &str = "10.66.67.0/24";
const SUBNET_PREFIX: [u8; 3] = [10, 66, 67];

pub type SessionId = u64;
pub type RegistrationId = u64;
pub type WorkerId = u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteEndpoint {
    pub session_id: SessionId,
    pub registration_id: RegistrationId,
    pub worker_id: WorkerId,
    pub slot: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSelection {
    start: usize,
    len: usize,
}

impl RouteSelection {
    #[inline(always)]
    pub fn len(self) -> usize {
        self.len
    }
}

#[derive(Default)]
struct LocalStripeCursor {
    next: usize,
    remaining: usize,
}

#[derive(Default)]
struct LocalStripedScheduler {
    latency: LocalStripeCursor,
    priority: LocalStripeCursor,
    bulk: LocalStripeCursor,
}

impl LocalStripedScheduler {
    #[inline(always)]
    fn select(&mut self, count: usize, class: PacketClass) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let (cursor, chunk) = match class {
            PacketClass::Latency => (&mut self.latency, LATENCY_STRIPE_PACKET_CHUNK),
            PacketClass::Priority => (&mut self.priority, PRIORITY_STRIPE_PACKET_CHUNK),
            PacketClass::Bulk => (&mut self.bulk, BULK_STRIPE_PACKET_CHUNK),
        };
        if cursor.next >= count {
            cursor.next = 0;
            cursor.remaining = 0;
        }
        if cursor.remaining == 0 {
            cursor.remaining = chunk;
        }
        let selected = cursor.next;
        cursor.remaining -= 1;
        if cursor.remaining == 0 {
            cursor.next += 1;
            if cursor.next == count {
                cursor.next = 0;
            }
        }
        Some(selected)
    }
}

#[derive(Default)]
struct RouteGroup {
    endpoints: Vec<RouteEndpoint>,
    scheduler: LocalStripedScheduler,
}

impl RouteGroup {
    fn register(&mut self, endpoint: RouteEndpoint) {
        self.endpoints.retain(|current| {
            current.registration_id != endpoint.registration_id
                && current.worker_id != endpoint.worker_id
        });
        self.endpoints.push(endpoint);
        self.endpoints
            .sort_unstable_by_key(|current| current.worker_id);
    }

    fn unregister(&mut self, registration_id: RegistrationId) -> bool {
        let previous_len = self.endpoints.len();
        self.endpoints
            .retain(|endpoint| endpoint.registration_id != registration_id);
        self.endpoints.len() != previous_len
    }

    #[cfg(test)]
    #[inline(always)]
    fn select(&mut self, class: PacketClass) -> Option<RouteEndpoint> {
        let selection = self.select_window(class)?;
        self.endpoint_at(selection, 0)
    }

    #[inline(always)]
    fn select_window(&mut self, class: PacketClass) -> Option<RouteSelection> {
        let len = self.endpoints.len();
        let start = self.scheduler.select(len, class)?;
        Some(RouteSelection { start, len })
    }

    #[inline(always)]
    fn endpoint_at(&self, selection: RouteSelection, offset: usize) -> Option<RouteEndpoint> {
        if offset >= selection.len || selection.len == 0 {
            return None;
        }
        let index = selection.start + offset;
        let index = if index >= selection.len {
            index - selection.len
        } else {
            index
        };
        self.endpoints.get(index).copied()
    }

    fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

pub struct RouteTable {
    groups: Box<[Option<RouteGroup>; 256]>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            groups: Box::new(std::array::from_fn(|_| None)),
        }
    }

    pub fn register(
        &mut self,
        ip: [u8; 4],
        session_id: SessionId,
        registration_id: RegistrationId,
        worker_id: WorkerId,
        slot: usize,
    ) -> bool {
        let Some(index) = route_index(ip) else {
            return false;
        };
        self.groups[index]
            .get_or_insert_with(RouteGroup::default)
            .register(RouteEndpoint {
                session_id,
                registration_id,
                worker_id,
                slot,
            });
        true
    }

    pub fn update_slot(
        &mut self,
        ip: [u8; 4],
        session_id: SessionId,
        registration_id: RegistrationId,
        slot: usize,
    ) {
        let Some(index) = route_index(ip) else {
            return;
        };
        let Some(group) = self.groups[index].as_mut() else {
            return;
        };
        if let Some(endpoint) = group.endpoints.iter_mut().find(|endpoint| {
            endpoint.session_id == session_id && endpoint.registration_id == registration_id
        }) {
            endpoint.slot = slot;
        }
    }

    pub fn unregister(&mut self, ip: [u8; 4], registration_id: RegistrationId) -> bool {
        let Some(index) = route_index(ip) else {
            return false;
        };
        let Some(group) = self.groups[index].as_mut() else {
            return false;
        };
        let removed = group.unregister(registration_id);
        if group.is_empty() {
            self.groups[index] = None;
        }
        removed
    }

    #[inline(always)]
    pub fn packet_key(packet: &[u8]) -> Option<usize> {
        route_index(extract_dst_ipv4(packet)?)
    }

    #[inline(always)]
    pub fn tunnel_key(ip: [u8; 4]) -> Option<usize> {
        route_index(ip)
    }

    #[inline(always)]
    pub fn active_path_count(&self, key: usize) -> usize {
        self.groups
            .get(key)
            .and_then(|group| group.as_ref())
            .map_or(0, |group| group.endpoints.len())
    }

    #[inline(always)]
    pub fn select_key_window(&mut self, key: usize, class: PacketClass) -> Option<RouteSelection> {
        self.groups.get_mut(key)?.as_mut()?.select_window(class)
    }

    #[inline(always)]
    pub fn endpoint_at(
        &self,
        key: usize,
        selection: RouteSelection,
        offset: usize,
    ) -> Option<RouteEndpoint> {
        self.groups
            .get(key)?
            .as_ref()?
            .endpoint_at(selection, offset)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn select(&mut self, ip: [u8; 4], class: PacketClass) -> Option<RouteEndpoint> {
        let index = route_index(ip)?;
        self.groups[index].as_mut()?.select(class)
    }

    #[cfg(test)]
    pub fn stream_count(&self, ip: [u8; 4]) -> usize {
        route_index(ip).map_or(0, |key| self.active_path_count(key))
    }
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn route_index(ip: [u8; 4]) -> Option<usize> {
    (ip[..3] == SUBNET_PREFIX).then_some(ip[3] as usize)
}

pub fn parse_ipv4(value: &str) -> Option<[u8; 4]> {
    Some(value.parse::<Ipv4Addr>().ok()?.octets())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> [u8; 4] {
        [10, 66, 67, last]
    }

    #[test]
    fn route_table_supports_all_stream_scales() {
        for count in [9, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99, 108, 117, 126] {
            let mut table = RouteTable::new();
            for id in 1..=count as u64 {
                assert!(table.register(ip(2), id, id, id as u16, id as usize));
            }
            assert_eq!(table.stream_count(ip(2)), count);
            for _ in 0..100_000 {
                let selected = table.select(ip(2), PacketClass::Bulk).unwrap();
                assert!((1..=count as u64).contains(&selected.session_id));
            }
        }
    }

    #[test]
    fn unregister_is_registration_exact() {
        let mut table = RouteTable::new();
        assert!(table.register(ip(7), 100, 10, 1, 1));
        assert!(table.register(ip(7), 200, 20, 2, 2));
        assert!(table.unregister(ip(7), 10));
        assert_eq!(table.stream_count(ip(7)), 1);
        assert_eq!(
            table.select(ip(7), PacketClass::Bulk).unwrap().session_id,
            200
        );
    }

    #[test]
    fn compacted_session_slot_is_updated() {
        let mut table = RouteTable::new();
        assert!(table.register(ip(7), 100, 10, 1, 3));
        table.update_slot(ip(7), 100, 10, 9);
        assert_eq!(table.select(ip(7), PacketClass::Bulk).unwrap().slot, 9);
    }

    #[test]
    fn foreign_subnet_is_rejected() {
        let mut table = RouteTable::new();
        assert!(!table.register([10, 66, 68, 2], 1, 1, 1, 1));
        assert!(table.select([10, 66, 68, 2], PacketClass::Bulk).is_none());
    }

    #[test]
    fn replacement_transport_atomically_keeps_one_logical_worker() {
        let mut table = RouteTable::new();
        assert!(table.register(ip(7), 100, 10, 4, 1));
        assert!(table.register(ip(7), 200, 20, 4, 2));

        assert_eq!(table.stream_count(ip(7)), 1);
        assert_eq!(
            table.select(ip(7), PacketClass::Bulk).unwrap().session_id,
            200
        );
        assert!(!table.unregister(ip(7), 10));
        assert_eq!(
            table.select(ip(7), PacketClass::Bulk).unwrap().session_id,
            200
        );
    }

    #[test]
    fn bulk_selection_respects_scheduler_chunks() {
        let mut table = RouteTable::new();
        for id in 1..=2 {
            assert!(table.register(ip(2), id, id, id as u16, id as usize));
        }

        for _ in 0..crate::striped_scheduler::BULK_STRIPE_PACKET_CHUNK {
            assert_eq!(table.select(ip(2), PacketClass::Bulk).unwrap().worker_id, 1);
        }
        assert_eq!(table.select(ip(2), PacketClass::Bulk).unwrap().worker_id, 2);
    }

    #[test]
    fn local_scheduler_restarts_safely_after_path_count_shrinks() {
        let mut scheduler = LocalStripedScheduler::default();
        assert_eq!(scheduler.select(3, PacketClass::Bulk), Some(0));
        assert_eq!(scheduler.select(3, PacketClass::Bulk), Some(0));
        assert_eq!(scheduler.select(3, PacketClass::Bulk), Some(1));
        assert_eq!(scheduler.select(2, PacketClass::Bulk), Some(0));
        assert_eq!(scheduler.select(2, PacketClass::Bulk), Some(0));
        assert_eq!(scheduler.select(2, PacketClass::Bulk), Some(1));
    }

    #[test]
    fn route_selection_exposes_all_candidates_from_start() {
        let mut table = RouteTable::new();
        for id in 1..=3 {
            assert!(table.register(ip(2), id, id, id as u16, id as usize));
        }
        let key = route_index(ip(2)).unwrap();
        let selection = table.select_key_window(key, PacketClass::Bulk).unwrap();
        assert_eq!(selection.len(), 3);
        assert_eq!(table.endpoint_at(key, selection, 0).unwrap().worker_id, 1);
        assert_eq!(table.endpoint_at(key, selection, 1).unwrap().worker_id, 2);
        assert_eq!(table.endpoint_at(key, selection, 2).unwrap().worker_id, 3);
        assert!(table.endpoint_at(key, selection, 3).is_none());
    }

    #[test]
    fn latency_packets_round_robin_independently_from_bulk() {
        let mut table = RouteTable::new();
        assert!(table.register(ip(2), 1, 1, 1, 1));
        assert!(table.register(ip(2), 2, 2, 2, 2));

        for _ in 0..8 {
            assert!(table.select(ip(2), PacketClass::Bulk).is_some());
        }

        assert_eq!(
            table.select(ip(2), PacketClass::Latency).unwrap().worker_id,
            1
        );
        assert_eq!(
            table.select(ip(2), PacketClass::Latency).unwrap().worker_id,
            2
        );
    }
}
