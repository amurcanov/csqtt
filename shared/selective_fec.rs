// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::time::{Duration, Instant};

const MAX_SMALL_UDP_PAYLOAD: usize = 256;
const DUPLICATES_PER_SECOND: u32 = 50;
const DUPLICATE_BURST: u32 = 10;
const REFILL_INTERVAL: Duration = Duration::from_millis(1_000 / DUPLICATES_PER_SECOND as u64);

pub struct Budget {
    tokens: u32,
    updated: Instant,
}

impl Budget {
    pub fn new() -> Self {
        Self {
            tokens: DUPLICATE_BURST,
            updated: Instant::now(),
        }
    }

    #[inline(always)]
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated);
        let refill = elapsed.as_nanos() / REFILL_INTERVAL.as_nanos();
        if refill != 0 {
            let refill = refill.min(u128::from(u32::MAX)) as u32;
            self.tokens = self.tokens.saturating_add(refill).min(DUPLICATE_BURST);
            self.updated += REFILL_INTERVAL.saturating_mul(refill);
        }
        if self.tokens == 0 {
            false
        } else {
            self.tokens -= 1;
            true
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
pub fn should_duplicate(packet: &[u8]) -> bool {
    let packet = crate::flow_frame::payload(packet);
    if is_control(packet) {
        return true;
    }
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => ipv4_transport(packet).is_some_and(classify_transport),
        Some(6) => ipv6_transport(packet).is_some_and(classify_transport),
        _ => false,
    }
}

#[inline(always)]
fn is_control(packet: &[u8]) -> bool {
    packet.starts_with(b"GETCONF:")
        || packet.starts_with(b"TUNCONF:")
        || packet == b"READY"
        || packet == b"READY_OK"
        || packet.starts_with(b"DENIED:")
        || packet.starts_with(b"DISCONNECT:")
}

#[derive(Clone, Copy)]
struct Transport<'a> {
    protocol: u8,
    bytes: &'a [u8],
}

#[inline(always)]
fn classify_transport(transport: Transport<'_>) -> bool {
    match transport.protocol {
        6 if transport.bytes.len() >= 14 => {
            let source = u16::from_be_bytes([transport.bytes[0], transport.bytes[1]]);
            let destination = u16::from_be_bytes([transport.bytes[2], transport.bytes[3]]);
            source == 53 || destination == 53 || transport.bytes[13] & 0x02 != 0
        }
        17 if transport.bytes.len() >= 8 => {
            let source = u16::from_be_bytes([transport.bytes[0], transport.bytes[1]]);
            let destination = u16::from_be_bytes([transport.bytes[2], transport.bytes[3]]);
            source == 53
                || destination == 53
                || transport.bytes.len().saturating_sub(8) <= MAX_SMALL_UDP_PAYLOAD
        }
        _ => false,
    }
}

#[inline(always)]
fn ipv4_transport(packet: &[u8]) -> Option<Transport<'_>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f).checked_mul(4)?;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return None;
    }
    Some(Transport {
        protocol: packet[9],
        bytes: &packet[header_len..],
    })
}

#[inline(always)]
fn ipv6_transport(packet: &[u8]) -> Option<Transport<'_>> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
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
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff8 != 0 {
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
            _ => break,
        }
        if offset > packet.len() {
            return None;
        }
    }
    Some(Transport {
        protocol,
        bytes: packet.get(offset..)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = protocol;
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = protocol;
        packet.extend_from_slice(payload);
        packet
    }

    fn udp(source: u16, destination: u16, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 8 + payload_len];
        packet[0..2].copy_from_slice(&source.to_be_bytes());
        packet[2..4].copy_from_slice(&destination.to_be_bytes());
        packet
    }

    fn tcp(source: u16, destination: u16, flags: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0..2].copy_from_slice(&source.to_be_bytes());
        packet[2..4].copy_from_slice(&destination.to_be_bytes());
        packet[12] = 0x50;
        packet[13] = flags;
        packet
    }

    #[test]
    fn duplicates_control() {
        assert!(should_duplicate(b"READY"));
        assert!(should_duplicate(b"GETCONF:value"));
    }

    #[test]
    fn duplicates_dns_syn_and_small_udp() {
        assert!(should_duplicate(&ipv4(17, &udp(40000, 53, 900))));
        assert!(should_duplicate(&ipv4(6, &tcp(40000, 443, 0x02))));
        assert!(should_duplicate(&ipv4(17, &udp(40000, 443, 256))));
        assert!(!should_duplicate(&ipv4(17, &udp(40000, 443, 257))));
        assert!(!should_duplicate(&ipv4(6, &tcp(40000, 443, 0x10))));
    }

    #[test]
    fn supports_ipv6_and_rejects_non_initial_fragments() {
        assert!(should_duplicate(&ipv6(17, &udp(53, 40000, 900))));
        let mut fragmented = ipv4(17, &udp(40000, 53, 20));
        fragmented[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(!should_duplicate(&fragmented));
    }

    #[test]
    fn budget_limits_burst() {
        let mut budget = Budget::new();
        for _ in 0..DUPLICATE_BURST {
            assert!(budget.allow());
        }
        assert!(!budget.allow());
    }
}
