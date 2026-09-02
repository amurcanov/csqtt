// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

pub const SMALL_PACKET_MAX: usize = 164;
pub const MEDIUM_PACKET_MAX: usize = 999;
pub const SMALL_STREAM_STRIPE_PACKET_CHUNK: usize = 4;
pub const MEDIUM_STREAM_STRIPE_PACKET_CHUNK: usize = 16;
pub const BULK_STREAM_STRIPE_PACKET_CHUNK: usize = 32;
pub const SMALL_DATAGRAM_BATCH: usize = 16;
pub const MEDIUM_DATAGRAM_BATCH: usize = 64;
pub const BULK_DATAGRAM_BATCH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketClass {
    Small,
    Medium,
    Bulk,
}

impl PacketClass {
    #[inline(always)]
    pub const fn index(self) -> usize {
        match self {
            Self::Small => 0,
            Self::Medium => 1,
            Self::Bulk => 2,
        }
    }

    #[inline(always)]
    pub const fn stream_chunk(self) -> usize {
        match self {
            Self::Small => SMALL_STREAM_STRIPE_PACKET_CHUNK,
            Self::Medium => MEDIUM_STREAM_STRIPE_PACKET_CHUNK,
            Self::Bulk => BULK_STREAM_STRIPE_PACKET_CHUNK,
        }
    }

    #[inline(always)]
    pub const fn datagram_batch(self) -> usize {
        match self {
            Self::Small => SMALL_DATAGRAM_BATCH,
            Self::Medium => MEDIUM_DATAGRAM_BATCH,
            Self::Bulk => BULK_DATAGRAM_BATCH,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchTicket {
    pub start_slot: usize,
    pub class: PacketClass,
}

#[inline(always)]
pub fn packet_class(packet: &[u8]) -> PacketClass {
    let packet = crate::flow_frame::payload(packet);
    let Some((transport, offset)) = internet_transport(packet) else {
        return size_class(packet.len());
    };
    if matches!(transport, 1 | 58) || is_dns(packet, transport, offset) {
        return PacketClass::Small;
    }
    if transport == 6 && is_tcp_control(packet, offset) {
        return PacketClass::Small;
    }
    size_class(packet.len())
}

#[inline(always)]
const fn size_class(length: usize) -> PacketClass {
    if length <= SMALL_PACKET_MAX {
        PacketClass::Small
    } else if length <= MEDIUM_PACKET_MAX {
        PacketClass::Medium
    } else {
        PacketClass::Bulk
    }
}

#[inline(always)]
fn is_dns(packet: &[u8], transport: u8, offset: usize) -> bool {
    if !matches!(transport, 6 | 17) {
        return false;
    }
    let Some(ports) = packet.get(offset..offset.saturating_add(4)) else {
        return false;
    };
    let source = u16::from_be_bytes([ports[0], ports[1]]);
    let destination = u16::from_be_bytes([ports[2], ports[3]]);
    source == 53 || destination == 53
}

#[inline(always)]
fn is_tcp_control(packet: &[u8], offset: usize) -> bool {
    let Some(header) = packet.get(offset..offset.saturating_add(14)) else {
        return false;
    };
    let flags = header[13];
    if flags & (0x02 | 0x01 | 0x04) != 0 {
        return true;
    }
    if flags & 0x10 == 0 {
        return false;
    }
    let header_len = usize::from(header[12] >> 4).saturating_mul(4);
    header_len >= 20 && packet.len() <= offset.saturating_add(header_len)
}

#[inline(always)]
fn internet_transport(packet: &[u8]) -> Option<(u8, usize)> {
    match packet.first().map(|first| first >> 4) {
        Some(4) => {
            let header_len = usize::from(packet.first()? & 0x0f).checked_mul(4)?;
            if header_len >= 20 && packet.len() >= header_len {
                Some((packet[9], header_len))
            } else {
                None
            }
        }
        Some(6) if packet.len() >= 40 => ipv6_transport(packet),
        _ => None,
    }
}

#[inline(always)]
fn ipv6_transport(packet: &[u8]) -> Option<(u8, usize)> {
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
            _ => return Some((protocol, offset)),
        }
        if offset > packet.len() {
            return None;
        }
    }
    Some((protocol, offset))
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

    fn tcp(flags: u8, payload_len: usize) -> Vec<u8> {
        let mut packet = ipv4(6, 40 + payload_len);
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }

    fn dns(protocol: u8, length: usize) -> Vec<u8> {
        let mut packet = ipv4(protocol, length.max(28));
        packet[20..22].copy_from_slice(&53u16.to_be_bytes());
        packet[22..24].copy_from_slice(&44444u16.to_be_bytes());
        packet
    }

    #[test]
    fn classifies_size_boundaries() {
        assert_eq!(packet_class(&ipv4(17, 164)), PacketClass::Small);
        assert_eq!(packet_class(&ipv4(17, 165)), PacketClass::Medium);
        assert_eq!(packet_class(&ipv4(17, 999)), PacketClass::Medium);
        assert_eq!(packet_class(&ipv4(17, 1_000)), PacketClass::Bulk);
    }

    #[test]
    fn classifies_icmp_and_dns_as_small() {
        assert_eq!(packet_class(&ipv4(1, 1_400)), PacketClass::Small);
        assert_eq!(packet_class(&ipv6(58, 1_400)), PacketClass::Small);
        assert_eq!(packet_class(&dns(17, 1_400)), PacketClass::Small);
        assert_eq!(packet_class(&dns(6, 1_400)), PacketClass::Small);
    }

    #[test]
    fn classifies_tcp_control_without_demoting_tcp_payload() {
        assert_eq!(packet_class(&tcp(0x02, 1_200)), PacketClass::Small);
        assert_eq!(packet_class(&tcp(0x01, 1_200)), PacketClass::Small);
        assert_eq!(packet_class(&tcp(0x10, 0)), PacketClass::Small);
        assert_eq!(packet_class(&tcp(0x18, 1_200)), PacketClass::Bulk);
    }

    #[test]
    fn classes_expose_requested_chunks_and_batches() {
        assert_eq!(PacketClass::Small.stream_chunk(), 4);
        assert_eq!(PacketClass::Medium.stream_chunk(), 16);
        assert_eq!(PacketClass::Bulk.stream_chunk(), 32);
        assert_eq!(PacketClass::Small.datagram_batch(), 16);
        assert_eq!(PacketClass::Medium.datagram_batch(), 64);
        assert_eq!(PacketClass::Bulk.datagram_batch(), 128);
    }

    fn ipv6(protocol: u8, length: usize) -> Vec<u8> {
        let mut packet = vec![0; length.max(40)];
        packet[0] = 0x60;
        packet[6] = protocol;
        packet
    }
}
