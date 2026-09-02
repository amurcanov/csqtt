use std::{
    collections::{HashMap, VecDeque},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub const FRAME_LEN: usize = 24;
const FRAME_MAGIC: [u8; 4] = *b"CQF1";
const MAX_TRACKED_FLOWS: usize = 4096;
const MAX_PENDING_PER_FLOW: usize = 96;
const MAX_PENDING_TOTAL: usize = 4096;
const GAP_RELEASE_AFTER_MS: u64 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FrameHeader {
    pub sender_id: u64,
    pub flow_id: u64,
    pub sequence: u32,
}

impl FrameHeader {
    #[inline(always)]
    pub fn encode(self, output: &mut [u8]) -> bool {
        if output.len() < FRAME_LEN {
            return false;
        }
        output[..4].copy_from_slice(&FRAME_MAGIC);
        output[4..12].copy_from_slice(&self.sender_id.to_be_bytes());
        output[12..20].copy_from_slice(&self.flow_id.to_be_bytes());
        output[20..24].copy_from_slice(&self.sequence.to_be_bytes());
        true
    }

    #[inline(always)]
    pub fn decode(packet: &[u8]) -> Option<(Self, &[u8])> {
        if packet.len() < FRAME_LEN || packet[..4] != FRAME_MAGIC {
            return None;
        }
        Some((
            Self {
                sender_id: u64::from_be_bytes(packet[4..12].try_into().ok()?),
                flow_id: u64::from_be_bytes(packet[12..20].try_into().ok()?),
                sequence: u32::from_be_bytes(packet[20..24].try_into().ok()?),
            },
            &packet[FRAME_LEN..],
        ))
    }
}

#[inline(always)]
pub fn payload(packet: &[u8]) -> &[u8] {
    FrameHeader::decode(packet).map_or(packet, |(_, payload)| payload)
}

pub struct FlowSequencer {
    sender_id: u64,
    sequences: HashMap<u64, u32>,
}

impl Default for FlowSequencer {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowSequencer {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let address = (&now as *const u64 as usize) as u64;
        Self::with_sender_id(mix64(now ^ address))
    }

    pub fn with_sender_id(sender_id: u64) -> Self {
        Self {
            sender_id: sender_id.max(1),
            sequences: HashMap::with_capacity(MAX_TRACKED_FLOWS),
        }
    }

    #[inline(always)]
    pub fn next(&mut self, packet: &[u8]) -> Option<FrameHeader> {
        let flow_id = tcp_flow_id(packet)?;
        if self.sequences.len() == MAX_TRACKED_FLOWS && !self.sequences.contains_key(&flow_id) {
            self.sequences.clear();
            self.sender_id = mix64(self.sender_id.wrapping_add(0x9e37_79b9_7f4a_7c15)).max(1);
        }
        let sequence = self.sequences.entry(flow_id).or_insert(0);
        let header = FrameHeader {
            sender_id: self.sender_id,
            flow_id,
            sequence: *sequence,
        };
        *sequence = sequence.wrapping_add(1);
        Some(header)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct ReassemblyKey {
    sender_id: u64,
    flow_id: u64,
}

struct Pending<T> {
    sequence: u32,
    value: T,
}

struct FlowState<T> {
    expected: u32,
    gap_started_ms: Option<u64>,
    pending: Vec<Pending<T>>,
}

pub struct FlowReassembler<T> {
    flows: HashMap<ReassemblyKey, FlowState<T>>,
    pending_total: usize,
    started: Instant,
}

impl<T> Default for FlowReassembler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FlowReassembler<T> {
    pub fn new() -> Self {
        Self {
            flows: HashMap::with_capacity(MAX_TRACKED_FLOWS),
            pending_total: 0,
            started: Instant::now(),
        }
    }

    #[inline(always)]
    pub fn push(&mut self, header: FrameHeader, value: T, output: &mut VecDeque<T>) {
        let now_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.push_at(header, value, now_ms, output);
    }

    pub fn push_at(
        &mut self,
        header: FrameHeader,
        value: T,
        now_ms: u64,
        output: &mut VecDeque<T>,
    ) {
        let key = ReassemblyKey {
            sender_id: header.sender_id,
            flow_id: header.flow_id,
        };
        if self.flows.len() == MAX_TRACKED_FLOWS && !self.flows.contains_key(&key) {
            self.flows.clear();
            self.pending_total = 0;
        }
        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            expected: 0,
            gap_started_ms: None,
            pending: Vec::new(),
        });
        let pending_before = state.pending.len();
        release_expired(state, now_ms, output);
        self.pending_total = self
            .pending_total
            .saturating_sub(pending_before.saturating_sub(state.pending.len()));
        if header.sequence == state.expected {
            output.push_back(value);
            state.expected = state.expected.wrapping_add(1);
            state.gap_started_ms = None;
            let pending_before = state.pending.len();
            drain_contiguous(state, output);
            self.pending_total = self
                .pending_total
                .saturating_sub(pending_before.saturating_sub(state.pending.len()));
            return;
        }
        if !is_forward(header.sequence, state.expected)
            || state
                .pending
                .iter()
                .any(|pending| pending.sequence == header.sequence)
        {
            return;
        }
        if state.pending.len() == MAX_PENDING_PER_FLOW {
            let pending_before = state.pending.len();
            release_lowest(state, now_ms, output);
            self.pending_total = self
                .pending_total
                .saturating_sub(pending_before.saturating_sub(state.pending.len()));
        }
        if self.pending_total == MAX_PENDING_TOTAL {
            if state.pending.is_empty() {
                output.push_back(value);
                state.expected = header.sequence.wrapping_add(1);
                state.gap_started_ms = None;
                return;
            }
            let pending_before = state.pending.len();
            release_lowest(state, now_ms, output);
            self.pending_total = self
                .pending_total
                .saturating_sub(pending_before.saturating_sub(state.pending.len()));
        }
        state.pending.push(Pending {
            sequence: header.sequence,
            value,
        });
        self.pending_total += 1;
        if self.pending_total > MAX_PENDING_TOTAL {
            let pending_before = state.pending.len();
            release_lowest(state, now_ms, output);
            self.pending_total = self
                .pending_total
                .saturating_sub(pending_before.saturating_sub(state.pending.len()));
        }
        if state.gap_started_ms.is_none() {
            state.gap_started_ms = Some(now_ms);
        }
        let pending_before = state.pending.len();
        release_expired(state, now_ms, output);
        self.pending_total = self
            .pending_total
            .saturating_sub(pending_before.saturating_sub(state.pending.len()));
    }

    #[cfg(test)]
    fn tracked_flows(&self) -> usize {
        self.flows.len()
    }

    #[cfg(test)]
    fn pending_total(&self) -> usize {
        self.pending_total
    }
}

fn release_expired<T>(state: &mut FlowState<T>, now_ms: u64, output: &mut VecDeque<T>) {
    if state
        .gap_started_ms
        .is_some_and(|started| now_ms.saturating_sub(started) >= GAP_RELEASE_AFTER_MS)
    {
        release_lowest(state, now_ms, output);
    }
}

fn release_lowest<T>(state: &mut FlowState<T>, now_ms: u64, output: &mut VecDeque<T>) {
    let Some((index, _)) = state
        .pending
        .iter()
        .enumerate()
        .filter_map(|(index, pending)| {
            is_forward(pending.sequence, state.expected)
                .then_some((index, pending.sequence.wrapping_sub(state.expected)))
        })
        .min_by_key(|(_, distance)| *distance)
    else {
        state.gap_started_ms = None;
        return;
    };
    let pending = state.pending.swap_remove(index);
    state.expected = pending.sequence.wrapping_add(1);
    output.push_back(pending.value);
    state.gap_started_ms = None;
    drain_contiguous(state, output);
    if !state.pending.is_empty() {
        state.gap_started_ms = Some(now_ms);
    }
}

fn drain_contiguous<T>(state: &mut FlowState<T>, output: &mut VecDeque<T>) {
    while let Some(index) = state
        .pending
        .iter()
        .position(|pending| pending.sequence == state.expected)
    {
        let pending = state.pending.swap_remove(index);
        state.expected = state.expected.wrapping_add(1);
        output.push_back(pending.value);
    }
}

#[inline(always)]
fn is_forward(sequence: u32, expected: u32) -> bool {
    sequence != expected && sequence.wrapping_sub(expected) < (1 << 31)
}

#[inline(always)]
pub fn tcp_flow_id(packet: &[u8]) -> Option<u64> {
    let (header_len, protocol, source, destination) = match packet.first().copied()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len + 20 {
                return None;
            }
            (header_len, packet[9], &packet[12..16], &packet[16..20])
        }
        6 => {
            if packet.len() < 60 {
                return None;
            }
            (40, packet[6], &packet[8..24], &packet[24..40])
        }
        _ => return None,
    };
    if protocol != 6 {
        return None;
    }
    let tcp = &packet[header_len..];
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    let flags = tcp[13];
    if tcp.len() == data_offset && flags & 0x03 == 0 {
        return None;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    hash_bytes(&mut hash, &[protocol]);
    hash_bytes(&mut hash, source);
    hash_bytes(&mut hash, destination);
    hash_bytes(&mut hash, &tcp[..4]);
    Some(mix64(hash))
}

#[inline(always)]
fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
}

#[inline(always)]
fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(payload_len: usize, flags: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload_len];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }

    fn header(sequence: u32) -> FrameHeader {
        FrameHeader {
            sender_id: 17,
            flow_id: 23,
            sequence,
        }
    }

    #[test]
    fn frame_roundtrip_preserves_header_and_payload() {
        let header = header(9);
        let mut bytes = vec![0u8; FRAME_LEN];
        assert!(header.encode(&mut bytes));
        bytes.extend_from_slice(b"payload");
        assert_eq!(
            FrameHeader::decode(&bytes),
            Some((header, b"payload".as_slice()))
        );
        assert_eq!(payload(&bytes), b"payload");
    }

    #[test]
    fn malformed_or_unframed_data_is_not_decoded() {
        assert!(FrameHeader::decode(b"CQF1").is_none());
        assert!(FrameHeader::decode(b"not-a-frame").is_none());
        assert_eq!(payload(b"not-a-frame"), b"not-a-frame");
    }

    #[test]
    fn tcp_flow_id_is_stable_for_a_direction() {
        let first = ipv4_tcp(10, 0x18, 1000, 443);
        let second = ipv4_tcp(20, 0x18, 1000, 443);
        let reverse = ipv4_tcp(10, 0x18, 443, 1000);
        assert_eq!(tcp_flow_id(&first), tcp_flow_id(&second));
        assert_ne!(tcp_flow_id(&first), tcp_flow_id(&reverse));
    }

    #[test]
    fn ack_only_tcp_is_not_framed() {
        assert!(tcp_flow_id(&ipv4_tcp(0, 0x10, 1000, 443)).is_none());
        assert!(tcp_flow_id(&ipv4_tcp(0, 0x02, 1000, 443)).is_some());
    }

    #[test]
    fn udp_and_non_ip_packets_are_not_framed() {
        let mut udp = ipv4_tcp(10, 0x18, 1000, 443);
        udp[9] = 17;
        assert!(tcp_flow_id(&udp).is_none());
        assert!(tcp_flow_id(b"control").is_none());
    }

    #[test]
    fn sequencer_starts_each_flow_at_zero() {
        let packet = ipv4_tcp(1, 0x18, 1000, 443);
        let other = ipv4_tcp(1, 0x18, 1001, 443);
        let mut sequencer = FlowSequencer::with_sender_id(7);
        assert_eq!(sequencer.next(&packet).unwrap().sequence, 0);
        assert_eq!(sequencer.next(&packet).unwrap().sequence, 1);
        assert_eq!(sequencer.next(&other).unwrap().sequence, 0);
    }

    #[test]
    fn reassembler_releases_reverse_arrival_in_sequence() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        reassembler.push_at(header(1), 1, 0, &mut output);
        reassembler.push_at(header(0), 0, 1, &mut output);
        assert_eq!(output.into_iter().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn duplicate_frame_is_dropped() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        reassembler.push_at(header(0), 10, 0, &mut output);
        reassembler.push_at(header(0), 11, 1, &mut output);
        assert_eq!(output.into_iter().collect::<Vec<_>>(), vec![10]);
    }

    #[test]
    fn missing_frame_releases_the_lowest_pending_after_deadline() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        reassembler.push_at(header(1), 1, 0, &mut output);
        reassembler.push_at(header(2), 2, GAP_RELEASE_AFTER_MS, &mut output);
        assert_eq!(output.into_iter().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn late_original_after_gap_release_is_dropped() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        reassembler.push_at(header(1), 1, 0, &mut output);
        reassembler.push_at(header(2), 2, GAP_RELEASE_AFTER_MS, &mut output);
        reassembler.push_at(header(0), 0, GAP_RELEASE_AFTER_MS + 1, &mut output);
        assert_eq!(output.into_iter().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn independent_flows_do_not_block_each_other() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        let other = FrameHeader {
            flow_id: 24,
            ..header(0)
        };
        reassembler.push_at(header(1), 11, 0, &mut output);
        reassembler.push_at(other, 20, 1, &mut output);
        reassembler.push_at(header(0), 10, 2, &mut output);
        assert_eq!(output.into_iter().collect::<Vec<_>>(), vec![20, 10, 11]);
    }

    #[test]
    fn sequence_wrap_is_contiguous() {
        let first = FrameHeader {
            sequence: u32::MAX,
            ..header(0)
        };
        let second = FrameHeader {
            sequence: 0,
            ..header(0)
        };
        let mut state = FlowReassembler::new();
        let mut output = VecDeque::new();
        state.flows.insert(
            ReassemblyKey {
                sender_id: 17,
                flow_id: 23,
            },
            FlowState {
                expected: u32::MAX,
                gap_started_ms: None,
                pending: Vec::new(),
            },
        );
        state.push_at(first, 1, 0, &mut output);
        state.push_at(second, 2, 1, &mut output);
        assert_eq!(output.into_iter().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn flow_table_stays_bounded() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        for flow_id in 0..=MAX_TRACKED_FLOWS as u64 {
            reassembler.push_at(
                FrameHeader {
                    sender_id: 1,
                    flow_id,
                    sequence: 0,
                },
                flow_id,
                0,
                &mut output,
            );
        }
        assert!(reassembler.tracked_flows() <= MAX_TRACKED_FLOWS);
    }

    #[test]
    fn pending_reorder_memory_is_globally_bounded() {
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        for index in 0..MAX_PENDING_TOTAL.saturating_add(128) {
            reassembler.push_at(
                FrameHeader {
                    sender_id: 1,
                    flow_id: (index % 64) as u64,
                    sequence: (index / 64 + 1) as u32,
                },
                index,
                0,
                &mut output,
            );
        }
        assert!(reassembler.pending_total() <= MAX_PENDING_TOTAL);
    }

    #[test]
    fn seventy_two_paths_with_configured_bulk_stripes_restore_a_single_tcp_flow() {
        const PATHS: usize = 72;
        const STRIPE: usize = crate::striped_scheduler::BULK_STREAM_STRIPE_PACKET_CHUNK;
        const PATHS_PER_REORDER_WINDOW: usize = MAX_PENDING_PER_FLOW / STRIPE;
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();

        for window in 0..(PATHS / PATHS_PER_REORDER_WINDOW) {
            let base = window * PATHS_PER_REORDER_WINDOW * STRIPE;
            for path in (0..PATHS_PER_REORDER_WINDOW).rev() {
                for offset in 0..STRIPE {
                    let sequence = base + path * STRIPE + offset;
                    reassembler.push_at(header(sequence as u32), sequence, 0, &mut output);
                    if offset == 0 {
                        reassembler.push_at(header(sequence as u32), sequence, 0, &mut output);
                    }
                }
            }
        }

        assert_eq!(
            output.into_iter().collect::<Vec<_>>(),
            (0..PATHS * STRIPE).collect::<Vec<_>>()
        );
        assert_eq!(reassembler.pending_total(), 0);
    }

    #[test]
    fn seventy_two_paths_with_a_late_bulk_stripe_keep_output_order_and_memory_bounded() {
        const PATHS: usize = 72;
        const STRIPE: usize = crate::striped_scheduler::BULK_STREAM_STRIPE_PACKET_CHUNK;
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();

        for path in 1..PATHS {
            for offset in 0..STRIPE {
                let sequence = path * STRIPE + offset;
                reassembler.push_at(header(sequence as u32), sequence, 0, &mut output);
                assert!(reassembler.pending_total() <= MAX_PENDING_PER_FLOW);
            }
        }
        for offset in 0..STRIPE {
            reassembler.push_at(
                header(offset as u32),
                offset,
                GAP_RELEASE_AFTER_MS + 1,
                &mut output,
            );
        }

        let output = output.into_iter().collect::<Vec<_>>();
        assert!(output.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(output.iter().all(|sequence| *sequence >= STRIPE));
        assert!(reassembler.pending_total() <= MAX_PENDING_PER_FLOW);
    }

    #[test]
    fn one_hundred_twenty_six_parallel_tcp_flows_keep_each_flow_ordered() {
        const FLOWS: usize = 126;
        const PACKETS_PER_FLOW: usize = 128;
        let mut reassembler = FlowReassembler::new();
        let mut output = VecDeque::new();
        let mut received = (0..FLOWS)
            .map(|_| Vec::with_capacity(PACKETS_PER_FLOW))
            .collect::<Vec<_>>();

        for base in (0..PACKETS_PER_FLOW).step_by(2) {
            for flow in 0..FLOWS {
                for sequence in [base + 1, base] {
                    reassembler.push_at(
                        FrameHeader {
                            sender_id: 17,
                            flow_id: flow as u64,
                            sequence: sequence as u32,
                        },
                        (flow, sequence),
                        0,
                        &mut output,
                    );
                }
            }
            while let Some((flow, sequence)) = output.pop_front() {
                received[flow].push(sequence);
            }
        }

        for packets in received {
            assert_eq!(packets, (0..PACKETS_PER_FLOW).collect::<Vec<_>>());
        }
        assert_eq!(reassembler.pending_total(), 0);
    }
}
