// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::atomic::{AtomicUsize, Ordering};

pub const TCP_LATENCY_PACKET_LIMIT: usize = 192;
pub const UDP_LATENCY_PACKET_LIMIT: usize = 300;
pub const LATENCY_STRIPE_PACKET_CHUNK: usize = 1;
pub const PRIORITY_STRIPE_PACKET_CHUNK: usize = 2;
pub const BULK_STRIPE_PACKET_CHUNK: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketClass {
    Latency,
    Priority,
    Bulk,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchTicket {
    pub start_slot: usize,
    pub worker_count: usize,
    pub cohort_len: usize,
    pub class: PacketClass,
}

impl DispatchTicket {
    #[allow(dead_code)]
    #[inline(always)]
    pub fn worker_index(self, offset: usize) -> usize {
        (self.start_slot + offset) % self.worker_count
    }
}

pub struct StripedScheduler {
    latency_packet: AtomicUsize,
    priority_packet: AtomicUsize,
    bulk_packet: AtomicUsize,
}

impl StripedScheduler {
    pub const fn new() -> Self {
        Self {
            latency_packet: AtomicUsize::new(0),
            priority_packet: AtomicUsize::new(0),
            bulk_packet: AtomicUsize::new(0),
        }
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn begin(&self, count: usize, packet: &[u8]) -> Option<DispatchTicket> {
        self.begin_class(count, packet_class(packet))
    }

    #[inline(always)]
    pub fn begin_class(&self, count: usize, class: PacketClass) -> Option<DispatchTicket> {
        if count == 0 {
            return None;
        }

        let worker_idx = match class {
            PacketClass::Latency => {
                (self.latency_packet.fetch_add(1, Ordering::Relaxed) / LATENCY_STRIPE_PACKET_CHUNK)
                    % count
            }
            PacketClass::Priority => {
                (self.priority_packet.fetch_add(1, Ordering::Relaxed)
                    / PRIORITY_STRIPE_PACKET_CHUNK)
                    % count
            }
            PacketClass::Bulk => {
                (self.bulk_packet.fetch_add(1, Ordering::Relaxed) / BULK_STRIPE_PACKET_CHUNK)
                    % count
            }
        };

        let safe_idx = worker_idx.min(count.saturating_sub(1));

        Some(DispatchTicket {
            start_slot: safe_idx,
            worker_count: count,
            cohort_len: count,
            class,
        })
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn select(&self, count: usize, packet: &[u8]) -> Option<usize> {
        self.begin(count, packet).map(|ticket| ticket.start_slot)
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn select_class(&self, count: usize, class: PacketClass) -> Option<usize> {
        self.begin_class(count, class)
            .map(|ticket| ticket.start_slot)
    }
}

impl Default for StripedScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
pub fn packet_class(packet: &[u8]) -> PacketClass {
    match internet_transport(packet) {
        Some(1 | 58) => PacketClass::Latency,
        Some(6) if packet.len() < TCP_LATENCY_PACKET_LIMIT => PacketClass::Latency,
        Some(17) if packet.len() <= UDP_LATENCY_PACKET_LIMIT => PacketClass::Latency,
        Some(17) => PacketClass::Priority,
        _ => PacketClass::Bulk,
    }
}

#[inline(always)]
fn internet_transport(packet: &[u8]) -> Option<u8> {
    match packet.first().map(|first| first >> 4) {
        Some(4) => {
            let header_len = usize::from(packet.first()? & 0x0f).checked_mul(4)?;
            if header_len >= 20 && packet.len() >= header_len {
                Some(packet[9])
            } else {
                None
            }
        }
        Some(6) if packet.len() >= 40 => ipv6_transport(packet),
        _ => None,
    }
}

#[inline(always)]
fn ipv6_transport(packet: &[u8]) -> Option<u8> {
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..8 {
        match protocol {
            0 | 43 | 60 => {
                let header = packet.get(offset..offset.checked_add(2)?)?;
                protocol = header[0];
                offset = offset.checked_add((usize::from(header[1]) + 1).checked_mul(8)?)?;
            }
            44 => {
                let header = packet.get(offset..offset.checked_add(8)?)?;
                if u16::from_be_bytes([header[2], header[3]]) & 0xfff8 != 0 {
                    return None;
                }
                protocol = header[0];
                offset = offset.checked_add(8)?;
            }
            51 => {
                let header = packet.get(offset..offset.checked_add(2)?)?;
                protocol = header[0];
                offset = offset.checked_add((usize::from(header[1]) + 2).checked_mul(4)?)?;
            }
            _ => return Some(protocol),
        }
        if offset > packet.len() {
            return None;
        }
    }
    Some(protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, length: usize) -> Vec<u8> {
        let mut packet = vec![0; length.max(20)];
        packet[0] = 0x45;
        packet[9] = protocol;
        packet
    }

    fn ipv6(protocol: u8, length: usize) -> Vec<u8> {
        let mut packet = vec![0; length.max(40)];
        packet[0] = 0x60;
        packet[6] = protocol;
        packet
    }

    #[test]
    fn classifies_only_requested_internet_packets_as_latency() {
        assert_eq!(packet_class(&ipv4(1, 1_400)), PacketClass::Latency);
        assert_eq!(packet_class(&ipv6(58, 1_400)), PacketClass::Latency);
        assert_eq!(packet_class(&ipv4(6, 191)), PacketClass::Latency);
        assert_eq!(packet_class(&ipv4(6, 192)), PacketClass::Bulk);
        assert_eq!(packet_class(&ipv4(17, 199)), PacketClass::Latency);
        assert_eq!(packet_class(&ipv4(17, 300)), PacketClass::Latency);
        assert_eq!(packet_class(&ipv4(17, 301)), PacketClass::Priority);
        assert_eq!(packet_class(&ipv4(17, 1_400)), PacketClass::Priority);
        assert_eq!(packet_class(&ipv4(50, 60)), PacketClass::Bulk);
        assert_eq!(packet_class(b"GETCONF:device"), PacketClass::Bulk);
    }

    #[test]
    fn bulk_stripes_in_fixed_packet_chunks() {
        let scheduler = StripedScheduler::new();
        for _ in 0..BULK_STRIPE_PACKET_CHUNK {
            assert_eq!(
                scheduler
                    .begin_class(2, PacketClass::Bulk)
                    .unwrap()
                    .start_slot,
                0
            );
        }
        assert_eq!(
            scheduler
                .begin_class(2, PacketClass::Bulk)
                .unwrap()
                .start_slot,
            1
        );
    }

    #[test]
    fn bulk_chunk_is_fixed_for_every_stream_count() {
        assert_eq!(BULK_STRIPE_PACKET_CHUNK, 2);
    }

    #[test]
    fn latency_stripes_in_configured_packet_chunks() {
        let scheduler = StripedScheduler::new();
        for _ in 0..LATENCY_STRIPE_PACKET_CHUNK {
            assert_eq!(
                scheduler
                    .begin_class(2, PacketClass::Latency)
                    .unwrap()
                    .start_slot,
                0
            );
        }
        assert_eq!(
            scheduler
                .begin_class(2, PacketClass::Latency)
                .unwrap()
                .start_slot,
            1
        );
    }

    #[test]
    fn priority_stripes_in_configured_packet_chunks() {
        let scheduler = StripedScheduler::new();
        for _ in 0..PRIORITY_STRIPE_PACKET_CHUNK {
            assert_eq!(
                scheduler
                    .begin_class(2, PacketClass::Priority)
                    .unwrap()
                    .start_slot,
                0
            );
        }
        assert_eq!(
            scheduler
                .begin_class(2, PacketClass::Priority)
                .unwrap()
                .start_slot,
            1
        );
    }
}
