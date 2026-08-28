// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![cfg(any())]
use super::{
    PacketClass, PacketReceiver, WorkerChannels, force_worker, packet_channel, try_workers,
};
use crate::{
    packet::{PacketBuf, PacketPool},
    striped_scheduler::StripedScheduler,
};
use std::{cmp::Reverse, env, sync::Arc, time::Duration};

const TOTALS: [usize; 14] = [9, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99, 108, 117, 126];
const LATENCY_CAPACITY: usize = 3;
const BULK_CAPACITY: usize = 4;
const FLOW_COUNT: usize = 12;
const MAGIC: [u8; 4] = *b"TCHS";
const META_OFFSET: usize = 40;
const TCP_HEADER_END: usize = 68;
const FLAG_CONTROL: u8 = 1;
const FLAG_NO_FAULT: u8 = 1 << 1;
const FLAG_FORCE_DELAY: u8 = 1 << 2;
const FLAG_FORCE_DROP: u8 = 1 << 3;
const FLAG_FORCE_DUPLICATE: u8 = 1 << 4;
const FLAG_FAIRNESS: u8 = 1 << 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mutation {
    AcceptStaleEpoch,
    AcceptReplay,
    DropControl,
    PinFirstWorker,
    DisableForceFallback,
    SkipGroupedInterruption,
    NeverReturnPrimary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Dominant,
    OneNinth,
    ReturnBurst,
    Reconnect,
    SlowNeighbor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
enum Feature {
    DominantTraffic,
    OneNinthTraffic,
    ReturnBurst,
    VariableDelay,
    Jitter,
    Reorder,
    Drop,
    Duplicate,
    Reconnect,
    EpochChurn,
    QueueBound,
    PoolBound,
    StaleQueuePurge,
    StaleWireFilter,
    ReplayReject,
    ForcedFallback,
    SlowSaturation,
    HealthyProgress,
    ControlUnderBulk,
    BulkProgress,
    FairRecovery,
}

const FEATURE_COUNT: usize = Feature::FairRecovery as usize + 1;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Coverage {
    totals: u32,
    hits: [u64; FEATURE_COUNT],
}

impl Default for Coverage {
    fn default() -> Self {
        Self {
            totals: 0,
            hits: [0; FEATURE_COUNT],
        }
    }
}

impl Coverage {
    fn hit(&mut self, feature: Feature) {
        self.hits[feature as usize] = self.hits[feature as usize].saturating_add(1);
    }

    fn add(&mut self, feature: Feature, value: u64) {
        self.hits[feature as usize] = self.hits[feature as usize].saturating_add(value.max(1));
    }

    fn merge(&mut self, other: &Self) {
        self.totals |= other.totals;
        for (target, source) in self.hits.iter_mut().zip(other.hits) {
            *target = target.saturating_add(source);
        }
    }

    fn complete(&self) -> bool {
        self.totals == (1_u32 << TOTALS.len()) - 1 && self.hits.iter().all(|value| *value > 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Report {
    coverage: Coverage,
    digest: u64,
    violations: u64,
    delivered_control: u64,
    delivered_bulk: u64,
    maximum_pool_use: usize,
}

impl Report {
    fn valid(&self) -> bool {
        self.violations == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketMeta {
    id: u64,
    flow: u32,
    sequence: u32,
    epoch: u32,
    flags: u8,
}

struct HarnessReceiver {
    latency: PacketReceiver,
    priority: PacketReceiver,
    bulk: PacketReceiver,
}

struct WireEvent {
    due: u64,
    tie: u64,
    worker: usize,
    phase: Phase,
    packet: PacketBuf,
}

struct Scenario {
    count: usize,
    active_count: usize,
    seed: u64,
    mutation: Option<Mutation>,
    pool: Arc<PacketPool>,
    scheduler: StripedScheduler,
    channels: Vec<WorkerChannels>,
    receivers: Vec<HarnessReceiver>,
    wire: Vec<WireEvent>,
    coverage: Coverage,
    tick: u64,
    epoch: u32,
    next_id: u64,
    next_tie: u64,
    sequences: [u32; FLOW_COUNT],
    flow_ports: [u16; FLOW_COUNT],
    last_delivered: [u32; FLOW_COUNT],
    delivered: [bool; FLOW_COUNT],
    last_due: [u64; FLOW_COUNT],
    due_seen: [bool; FLOW_COUNT],
    fair_seen: Vec<bool>,
    dominant_groups: Vec<u64>,
    return_groups: Vec<u64>,
    slow_saturated: bool,
    healthy_after_saturation: u64,
    slow_group: usize,
    healthy_group: usize,
    dominant_primary: u64,
    dominant_secondary: u64,
    one_ninth_primary: u64,
    one_ninth_secondary: u64,
    single_interruptions: u64,
    grouped_interruptions: u64,
    return_primary: u64,
    return_secondary: u64,
    interrupted_secondary_delivered: u64,
    returned_primary_delivered: u64,
    return_started_at: Option<u64>,
    first_return_delivered_at: Option<u64>,
    delivered_control: u64,
    delivered_bulk: u64,
    violations: u64,
    digest: u64,
    maximum_pool_use: usize,
}

impl Scenario {
    fn new(count: usize, seed: u64, mutation: Option<Mutation>) -> Self {
        let pool = PacketPool::new(count * 14 + 512);
        let scheduler = StripedScheduler::new();
        let mut flow_ports = [0; FLOW_COUNT];
        for (flow, port) in flow_ports.iter_mut().enumerate() {
            *port = find_flow_port(&scheduler, count, flow % (count / 9));
        }
        let mut channels = Vec::with_capacity(count);
        let mut receivers = Vec::with_capacity(count);
        for id in 0..count {
            let (latency, latency_rx) = packet_channel(LATENCY_CAPACITY, true);
            let (priority, priority_rx) = packet_channel(LATENCY_CAPACITY, true);
            let (bulk, bulk_rx) = packet_channel(BULK_CAPACITY, true);
            channels.push(WorkerChannels {
                id,
                incarnation_id: id as u64 + 1,
                turn_path: Arc::from("test"),
                latency,
                priority,
                bulk,
            });
            receivers.push(HarnessReceiver {
                latency: latency_rx,
                priority: priority_rx,
                bulk: bulk_rx,
            });
        }
        Self {
            count,
            active_count: count,
            seed,
            mutation,
            pool,
            scheduler,
            channels,
            receivers,
            wire: Vec::new(),
            coverage: Coverage::default(),
            tick: 0,
            epoch: 0,
            next_id: 1,
            next_tie: 0,
            sequences: [0; FLOW_COUNT],
            flow_ports,
            last_delivered: [0; FLOW_COUNT],
            delivered: [false; FLOW_COUNT],
            last_due: [0; FLOW_COUNT],
            due_seen: [false; FLOW_COUNT],
            fair_seen: vec![false; count],
            dominant_groups: vec![0; count / 9],
            return_groups: vec![0; count / 9],
            slow_saturated: false,
            healthy_after_saturation: 0,
            slow_group: 4 % (count / 9),
            healthy_group: 5 % (count / 9),
            dominant_primary: 0,
            dominant_secondary: 0,
            one_ninth_primary: 0,
            one_ninth_secondary: 0,
            single_interruptions: 0,
            grouped_interruptions: 0,
            return_primary: 0,
            return_secondary: 0,
            interrupted_secondary_delivered: 0,
            returned_primary_delivered: 0,
            return_started_at: None,
            first_return_delivered_at: None,
            delivered_control: 0,
            delivered_bulk: 0,
            violations: 0,
            digest: seed,
            maximum_pool_use: 0,
        }
    }

    fn exercise_pool_bound(&mut self) {
        let mut held = Vec::with_capacity(self.pool.capacity());
        while let Some(packet) = self.pool.try_acquire() {
            held.push(packet);
        }
        if held.len() != self.pool.capacity() || self.pool.try_acquire().is_some() {
            self.violations = self.violations.saturating_add(1);
        }
        self.maximum_pool_use = self.maximum_pool_use.max(held.len());
        self.coverage.hit(Feature::PoolBound);
        drop(held);
        if self.pool.available() != self.pool.capacity() {
            self.violations = self.violations.saturating_add(1);
        }
    }

    fn issue(&mut self, flow: usize, flags: u8) {
        self.issue_with_tcp_sequence(flow, flags, None);
    }

    fn issue_with_tcp_sequence(&mut self, flow: usize, flags: u8, tcp_sequence: Option<u32>) {
        let flow = flow % FLOW_COUNT;
        self.sequences[flow] = self.sequences[flow].saturating_add(1);
        let meta = PacketMeta {
            id: self.next_id,
            flow: flow as u32,
            sequence: self.sequences[flow],
            epoch: self.epoch,
            flags,
        };
        self.next_id = self.next_id.saturating_add(1);
        let wire_sequence =
            tcp_sequence.unwrap_or_else(|| self.sequences[flow].wrapping_mul(1_200));
        let Some(packet) = make_packet(&self.pool, meta, self.flow_ports[flow], wire_sequence)
        else {
            self.coverage.hit(Feature::PoolBound);
            return;
        };
        self.observe_pool();
        let Some(ticket) = self.scheduler.begin(self.active_count, packet.as_slice()) else {
            self.violations = self.violations.saturating_add(1);
            return;
        };
        let workers = &self.channels[..self.active_count];
        if self.mutation == Some(Mutation::PinFirstWorker) {
            let channel = match ticket.class {
                PacketClass::Latency => &workers[0].latency,
                PacketClass::Priority => &workers[0].priority,
                PacketClass::Bulk => &workers[0].bulk,
            };
            if let Err(packet) = channel.try_send(packet) {
                let _ = channel.force_send(packet);
            }
            self.observe_bounds(None);
            return;
        }
        match try_workers(workers, ticket, packet) {
            Ok(()) => {}
            Err(packet) if self.mutation == Some(Mutation::DisableForceFallback) => {
                drop(packet);
            }
            Err(packet) => {
                self.coverage.hit(Feature::ForcedFallback);
                let _ = force_worker(workers, ticket, packet);
            }
        }
        self.observe_bounds(None);
    }

    fn observe_pool(&mut self) {
        let in_use = self.pool.capacity().saturating_sub(self.pool.available());
        self.maximum_pool_use = self.maximum_pool_use.max(in_use);
        if self.pool.available() > self.pool.capacity() {
            self.violations = self.violations.saturating_add(1);
        }
    }

    fn observe_bounds(&mut self, phase: Option<Phase>) {
        for (index, receiver) in self.receivers.iter().enumerate() {
            let latency = receiver.latency.len();
            let priority = receiver.priority.len();
            let bulk = receiver.bulk.len();
            if latency > LATENCY_CAPACITY || priority > LATENCY_CAPACITY || bulk > BULK_CAPACITY {
                self.violations = self.violations.saturating_add(1);
            }
            if latency == LATENCY_CAPACITY || priority == LATENCY_CAPACITY || bulk == BULK_CAPACITY
            {
                self.coverage.hit(Feature::QueueBound);
            }
            if phase == Some(Phase::SlowNeighbor)
                && index / 9 == self.slow_group
                && (latency == LATENCY_CAPACITY
                    || priority == LATENCY_CAPACITY
                    || bulk == BULK_CAPACITY)
            {
                self.slow_saturated = true;
                self.coverage.hit(Feature::SlowSaturation);
            }
        }
        self.observe_pool();
    }

    fn drain_worker(&mut self, worker: usize, latency: usize, bulk: usize, phase: Phase) {
        let mut packets = Vec::with_capacity(latency + bulk);
        for _ in 0..latency {
            let Some(packet) = self.receivers[worker].latency.try_recv() else {
                break;
            };
            packets.push(packet);
        }
        for _ in 0..bulk {
            let Some(packet) = self.receivers[worker].bulk.try_recv() else {
                break;
            };
            packets.push(packet);
        }
        for packet in packets {
            self.schedule(worker, packet, phase);
        }
    }

    fn drain_phase(&mut self, phase: Phase) {
        for worker in 0..self.active_count {
            let group = worker / 9;
            let budgets = match phase {
                Phase::Dominant if group == 0 => (4, 8),
                Phase::Dominant if self.tick.is_multiple_of(9) => (1, 1),
                Phase::Dominant => (0, 0),
                Phase::OneNinth if group == 0 => (4, 8),
                Phase::OneNinth if group == 1 && self.tick.is_multiple_of(9) => (1, 1),
                Phase::OneNinth => (1, 2),
                Phase::ReturnBurst => (8, 16),
                Phase::Reconnect => (4, 8),
                Phase::SlowNeighbor if group == self.slow_group && self.tick.is_multiple_of(23) => {
                    (1, 1)
                }
                Phase::SlowNeighbor if group == self.slow_group => (0, 0),
                Phase::SlowNeighbor if group == self.healthy_group => (8, 16),
                Phase::SlowNeighbor => (2, 4),
            };
            self.drain_worker(worker, budgets.0, budgets.1, phase);
        }
        self.observe_bounds(Some(phase));
    }

    fn drain_all(&mut self, phase: Phase) {
        for worker in 0..self.count {
            self.drain_worker(worker, 32, 32, phase);
        }
        self.observe_bounds(Some(phase));
    }

    fn schedule(&mut self, worker: usize, packet: PacketBuf, phase: Phase) {
        let Some(meta) = decode_packet(&packet) else {
            self.violations = self.violations.saturating_add(1);
            return;
        };
        if meta.epoch != self.epoch {
            self.violations = self.violations.saturating_add(1);
            return;
        }
        let group = worker / 9;
        if meta.flags & FLAG_FAIRNESS != 0 {
            self.fair_seen[worker] = true;
        }
        if phase == Phase::Dominant {
            self.dominant_groups[group] = self.dominant_groups[group].saturating_add(1);
        }
        if phase == Phase::ReturnBurst {
            self.return_groups[group] = self.return_groups[group].saturating_add(1);
        }
        if phase == Phase::SlowNeighbor && group == self.healthy_group && self.slow_saturated {
            self.healthy_after_saturation = self.healthy_after_saturation.saturating_add(1);
            self.coverage.hit(Feature::HealthyProgress);
        }
        let fault = mix64(
            self.seed
                ^ meta.id.rotate_left(17)
                ^ (worker as u64).rotate_left(31)
                ^ u64::from(meta.epoch),
        );
        if meta.flags & FLAG_FORCE_DROP != 0
            || (meta.flags & FLAG_NO_FAULT == 0 && fault.is_multiple_of(43))
        {
            self.coverage.hit(Feature::Drop);
            return;
        }
        let base = if meta.flags & FLAG_FORCE_DELAY != 0 {
            96
        } else if meta.flags & FLAG_NO_FAULT != 0 {
            0
        } else if phase == Phase::SlowNeighbor && group == 0 {
            40
        } else {
            1 + fault % 7
        };
        let jitter = if meta.flags & (FLAG_NO_FAULT | FLAG_FORCE_DELAY) != 0 {
            0
        } else {
            (fault >> 8) % 13
        };
        if base > 1 {
            self.coverage.hit(Feature::VariableDelay);
        }
        if jitter > 0 {
            self.coverage.hit(Feature::Jitter);
        }
        let due = self.tick.saturating_add(base).saturating_add(jitter);
        let flow = meta.flow as usize;
        if self.due_seen[flow] && due < self.last_due[flow] {
            self.coverage.hit(Feature::Reorder);
        }
        self.last_due[flow] = due;
        self.due_seen[flow] = true;
        let duplicate = meta.flags & FLAG_FORCE_DUPLICATE != 0
            || (meta.flags & FLAG_NO_FAULT == 0 && (fault >> 16).is_multiple_of(47));
        let duplicate_packet = duplicate
            .then(|| clone_packet(&self.pool, &packet))
            .flatten();
        self.next_tie = self.next_tie.saturating_add(1);
        self.wire.push(WireEvent {
            due,
            tie: self.next_tie,
            worker,
            phase,
            packet,
        });
        if let Some(packet) = duplicate_packet {
            self.coverage.hit(Feature::Duplicate);
            self.next_tie = self.next_tie.saturating_add(1);
            self.wire.push(WireEvent {
                due,
                tie: self.next_tie,
                worker,
                phase,
                packet,
            });
        }
        self.observe_pool();
    }

    fn deliver_ready(&mut self) {
        let mut ready = Vec::new();
        let mut index = 0;
        while index < self.wire.len() {
            if self.wire[index].due <= self.tick {
                ready.push(self.wire.swap_remove(index));
            } else {
                index += 1;
            }
        }
        ready.sort_unstable_by_key(|event| (event.due, Reverse(event.tie)));
        for event in ready {
            self.deliver(event);
        }
        self.observe_pool();
    }

    fn deliver(&mut self, event: WireEvent) {
        let Some(meta) = decode_packet(&event.packet) else {
            self.violations = self.violations.saturating_add(1);
            return;
        };
        if meta.epoch != self.epoch {
            if self.mutation != Some(Mutation::AcceptStaleEpoch) {
                self.coverage.hit(Feature::StaleWireFilter);
                return;
            }

            self.violations = self.violations.saturating_add(1);
        }
        if meta.flags & FLAG_CONTROL != 0 && self.mutation == Some(Mutation::DropControl) {
            return;
        }
        let flow = meta.flow as usize;
        if self.delivered[flow] && meta.sequence <= self.last_delivered[flow] {
            if self.mutation != Some(Mutation::AcceptReplay) {
                self.coverage.hit(Feature::ReplayReject);
                return;
            }

            self.violations = self.violations.saturating_add(1);
        }
        if self.delivered[flow] && meta.sequence <= self.last_delivered[flow] {
            self.violations = self.violations.saturating_add(1);
        }
        self.delivered[flow] = true;
        self.last_delivered[flow] = self.last_delivered[flow].max(meta.sequence);
        if event.phase == Phase::OneNinth && flow == 1 {
            self.interrupted_secondary_delivered =
                self.interrupted_secondary_delivered.saturating_add(1);
        }
        if event.phase == Phase::ReturnBurst && flow == 0 {
            self.returned_primary_delivered = self.returned_primary_delivered.saturating_add(1);
            self.first_return_delivered_at.get_or_insert(self.tick);
        }
        if meta.flags & FLAG_CONTROL != 0 {
            self.delivered_control = self.delivered_control.saturating_add(1);
        } else {
            self.delivered_bulk = self.delivered_bulk.saturating_add(1);
            self.coverage.hit(Feature::BulkProgress);
        }
        self.digest = mix64(
            self.digest
                ^ meta.id
                ^ (meta.sequence as u64).rotate_left(9)
                ^ (event.worker as u64).rotate_left(37)
                ^ self.tick.rotate_left(21),
        );
    }

    fn advance(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.deliver_ready();
            self.tick = self.tick.saturating_add(1);
        }
    }

    fn churn_epoch(&mut self) {
        let queued_before: usize = self
            .receivers
            .iter()
            .map(|receiver| receiver.latency.len() + receiver.priority.len() + receiver.bulk.len())
            .sum();
        for receiver in &self.receivers {
            receiver.latency.suspend();
            receiver.priority.suspend();
            receiver.bulk.suspend();
        }
        self.epoch = self.epoch.saturating_add(1);
        for receiver in &self.receivers {
            receiver.latency.resume();
            receiver.priority.resume();
            receiver.bulk.resume();
        }
        let queued_after: usize = self
            .receivers
            .iter()
            .map(|receiver| receiver.latency.len() + receiver.priority.len() + receiver.bulk.len())
            .sum();
        if queued_before > 0 {
            self.coverage
                .add(Feature::StaleQueuePurge, queued_before as u64);
        }
        if queued_after != 0 {
            self.violations = self
                .violations
                .saturating_add(queued_after.try_into().unwrap_or(u64::MAX));
        }
        self.coverage.hit(Feature::EpochChurn);
        self.coverage.hit(Feature::Reconnect);
    }

    fn fairness_probe(&mut self) {
        if self.count > 9 {
            self.active_count = self.count - 9;
            self.issue(7, FLAG_NO_FAULT | FLAG_FAIRNESS);
            self.drain_all(Phase::Reconnect);
            self.deliver_ready();
            self.churn_epoch();
            self.active_count = self.count;
        }
        self.fair_seen.fill(false);
        for block in 0..self.count as u32 {
            self.issue_with_tcp_sequence(0, FLAG_NO_FAULT | FLAG_FAIRNESS, Some(block * 8192));
            self.drain_all(Phase::Reconnect);
            self.deliver_ready();
        }
        if self.fair_seen.iter().all(|seen| *seen) {
            self.coverage.hit(Feature::FairRecovery);
        } else {
            self.violations = self.violations.saturating_add(1);
        }
    }

    fn deterministic_fault_probe(&mut self) {
        self.issue(2, FLAG_FORCE_DELAY);
        self.drain_all(Phase::Reconnect);
        for _ in 0..self.count * LATENCY_CAPACITY {
            self.issue(3, FLAG_CONTROL | FLAG_NO_FAULT);
        }
        self.issue(3, FLAG_CONTROL | FLAG_NO_FAULT);
        self.observe_bounds(None);
        self.churn_epoch();
        self.issue(4, FLAG_FORCE_DELAY);
        self.drain_all(Phase::Reconnect);
        self.issue(4, FLAG_NO_FAULT);
        self.drain_all(Phase::Reconnect);
        self.deliver_ready();
        self.issue(5, FLAG_FORCE_DUPLICATE);
        self.drain_all(Phase::Reconnect);
        self.deliver_ready();
        self.issue(6, FLAG_FORCE_DROP);
        self.drain_all(Phase::Reconnect);
        self.issue(7, FLAG_CONTROL | FLAG_NO_FAULT);
        self.drain_all(Phase::Reconnect);
        self.deliver_ready();
        self.advance(128);
    }

    fn slow_neighbor_probe(&mut self) {
        if self.count == 9 {
            return;
        }
        self.active_count = self.count;
        for step in 0..self.count * BULK_CAPACITY * 2 {
            self.issue(4 + step % 2, 0);
            for worker in 0..self.count {
                if worker / 9 != self.slow_group {
                    self.drain_worker(worker, 2, 4, Phase::SlowNeighbor);
                }
            }
            self.observe_bounds(Some(Phase::SlowNeighbor));
            self.deliver_ready();
            self.tick = self.tick.saturating_add(1);
            if self.slow_saturated && self.healthy_after_saturation > 0 {
                break;
            }
        }
        if !self.slow_saturated || self.healthy_after_saturation == 0 {
            self.violations = self.violations.saturating_add(1);
        }
        self.churn_epoch();
    }

    fn run_traffic(&mut self, steps: usize) {
        let phase_span = steps.div_ceil(5).max(9);
        let total_steps = phase_span * 5;
        for step in 0..total_steps {
            let phase = match step / phase_span {
                0 => Phase::Dominant,
                1 => Phase::OneNinth,
                2 => Phase::ReturnBurst,
                3 => Phase::Reconnect,
                _ => Phase::SlowNeighbor,
            };
            match phase {
                Phase::Dominant => {
                    self.coverage.hit(Feature::DominantTraffic);
                    for lane in 0..4 {
                        let flags = if lane == 0 && step.is_multiple_of(9) {
                            FLAG_CONTROL | FLAG_NO_FAULT
                        } else {
                            0
                        };
                        self.issue(0, flags);
                        self.dominant_primary = self.dominant_primary.saturating_add(1);
                    }
                }
                Phase::OneNinth => {
                    self.coverage.hit(Feature::OneNinthTraffic);
                    for _ in 0..8 {
                        self.issue(0, 0);
                        self.one_ninth_primary = self.one_ninth_primary.saturating_add(1);
                    }
                    self.issue(1, FLAG_CONTROL | FLAG_NO_FAULT);
                    self.one_ninth_secondary = self.one_ninth_secondary.saturating_add(1);
                    self.single_interruptions = self.single_interruptions.saturating_add(1);
                    if step.is_multiple_of(27)
                        && self.mutation != Some(Mutation::SkipGroupedInterruption)
                    {
                        for lane in 0..8 {
                            let flags = if lane == 0 {
                                FLAG_CONTROL | FLAG_NO_FAULT
                            } else {
                                0
                            };
                            self.issue(1, flags);
                            self.one_ninth_secondary = self.one_ninth_secondary.saturating_add(1);
                        }
                        self.grouped_interruptions = self.grouped_interruptions.saturating_add(1);
                    }
                }
                Phase::ReturnBurst => {
                    self.coverage.hit(Feature::ReturnBurst);
                    self.return_started_at.get_or_insert(self.tick);
                    for lane in 0..9 {
                        let flags = if lane == 0 {
                            FLAG_CONTROL | FLAG_NO_FAULT
                        } else {
                            0
                        };
                        if self.mutation == Some(Mutation::NeverReturnPrimary) {
                            self.issue(1, flags);
                            self.return_secondary = self.return_secondary.saturating_add(1);
                        } else {
                            self.issue(0, flags);
                            self.return_primary = self.return_primary.saturating_add(1);
                        }
                    }
                }
                Phase::Reconnect => {
                    if step.is_multiple_of(17) {
                        self.issue(2, FLAG_FORCE_DELAY);
                        self.drain_phase(phase);
                        self.churn_epoch();
                        if self.count > 9 {
                            self.active_count = if self.active_count == self.count {
                                self.count - 9
                            } else {
                                self.count
                            };
                        }
                    }
                    self.issue(2, 0);
                    if step.is_multiple_of(9) {
                        self.issue(3, FLAG_CONTROL | FLAG_NO_FAULT);
                    }
                }
                Phase::SlowNeighbor => {
                    for lane in 0..6 {
                        let flags = if lane == 0 && step.is_multiple_of(9) {
                            FLAG_CONTROL | FLAG_NO_FAULT
                        } else {
                            0
                        };
                        self.issue(4 + lane % 2, flags);
                    }
                }
            }
            self.drain_phase(phase);
            if self
                .receivers
                .iter()
                .any(|receiver| receiver.bulk.len() > 0)
                && self
                    .wire
                    .iter()
                    .filter_map(|event| decode_packet(&event.packet))
                    .any(|meta| meta.flags & FLAG_CONTROL != 0)
            {
                self.coverage.hit(Feature::ControlUnderBulk);
            }
            self.deliver_ready();
            self.tick = self.tick.saturating_add(1);
        }
        if self.active_count != self.count {
            self.churn_epoch();
            self.active_count = self.count;
        }
    }

    fn finalize(mut self) -> Report {
        for _ in 0..16 {
            self.drain_all(Phase::ReturnBurst);
            self.advance(32);
        }
        self.wire.clear();
        self.observe_pool();
        if self.pool.available() != self.pool.capacity() {
            self.violations = self.violations.saturating_add(1);
        }
        if self.coverage.hits[Feature::ForcedFallback as usize] == 0 {
            self.violations = self.violations.saturating_add(1);
        }
        if self.coverage.hits[Feature::StaleQueuePurge as usize] == 0
            || self.coverage.hits[Feature::StaleWireFilter as usize] == 0
            || self.coverage.hits[Feature::ReplayReject as usize] == 0
        {
            self.violations = self.violations.saturating_add(1);
        }
        if self.delivered_control == 0 || self.delivered_bulk == 0 {
            self.violations = self.violations.saturating_add(1);
        }
        if self.single_interruptions.saturating_mul(8) != self.one_ninth_primary
            || self
                .single_interruptions
                .saturating_add(self.grouped_interruptions.saturating_mul(8))
                != self.one_ninth_secondary
            || self.single_interruptions == 0
            || self.grouped_interruptions == 0
        {
            self.violations = self.violations.saturating_add(1);
        }
        if self.dominant_primary == 0
            || self.dominant_secondary != 0
            || self.return_primary == 0
            || self.return_secondary != 0
            || self.interrupted_secondary_delivered == 0
            || self.returned_primary_delivered == 0
        {
            self.violations = self.violations.saturating_add(1);
        }
        match (self.return_started_at, self.first_return_delivered_at) {
            (Some(started), Some(delivered)) if delivered.saturating_sub(started) <= 64 => {}
            _ => {
                self.violations = self.violations.saturating_add(1);
            }
        }
        if self.count > 9 && (!self.slow_saturated || self.healthy_after_saturation == 0) {
            self.violations = self.violations.saturating_add(1);
        }
        Report {
            coverage: self.coverage,
            digest: self.digest,
            violations: self.violations,
            delivered_control: self.delivered_control,
            delivered_bulk: self.delivered_bulk,
            maximum_pool_use: self.maximum_pool_use,
        }
    }
}

fn make_packet(
    pool: &Arc<PacketPool>,
    meta: PacketMeta,
    source_port: u16,
    tcp_sequence: u32,
) -> Option<PacketBuf> {
    let mut packet = pool.try_acquire()?;
    let length = if meta.flags & FLAG_CONTROL != 0 {
        TCP_HEADER_END
    } else {
        1024
    };
    packet.set_read_len(length).ok()?;
    let bytes = packet.as_mut_slice();
    bytes.fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 66, 67, 2]);
    bytes[16..20].copy_from_slice(&[1, 1, 1, 1]);
    bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[24..28].copy_from_slice(&tcp_sequence.to_be_bytes());
    bytes[32] = 12 << 4;
    bytes[33] = 0x10;
    let meta_bytes = &mut bytes[META_OFFSET..TCP_HEADER_END];
    meta_bytes[0..4].copy_from_slice(&MAGIC);
    meta_bytes[4..12].copy_from_slice(&meta.id.to_le_bytes());
    meta_bytes[12..16].copy_from_slice(&meta.flow.to_le_bytes());
    meta_bytes[16..20].copy_from_slice(&meta.sequence.to_le_bytes());
    meta_bytes[20..24].copy_from_slice(&meta.epoch.to_le_bytes());
    meta_bytes[24] = meta.flags;
    meta_bytes[25] = meta_bytes[..25]
        .iter()
        .fold(0_u8, |checksum, byte| checksum ^ byte);
    Some(packet)
}

fn decode_packet(packet: &PacketBuf) -> Option<PacketMeta> {
    let bytes = packet.as_slice();
    if bytes.len() < TCP_HEADER_END || bytes[META_OFFSET..META_OFFSET + 4] != MAGIC {
        return None;
    }
    let meta = &bytes[META_OFFSET..TCP_HEADER_END];
    let checksum = meta[..25]
        .iter()
        .fold(0_u8, |checksum, byte| checksum ^ byte);
    if checksum != meta[25] {
        return None;
    }
    Some(PacketMeta {
        id: u64::from_le_bytes(meta[4..12].try_into().ok()?),
        flow: u32::from_le_bytes(meta[12..16].try_into().ok()?),
        sequence: u32::from_le_bytes(meta[16..20].try_into().ok()?),
        epoch: u32::from_le_bytes(meta[20..24].try_into().ok()?),
        flags: meta[24],
    })
}

fn find_flow_port(scheduler: &StripedScheduler, count: usize, target_group: usize) -> u16 {
    for port in 1024u16..=u16::MAX {
        let mut packet = [0u8; TCP_HEADER_END + 1];
        let length = packet.len();
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 66, 67, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = 12 << 4;
        if let Some(ticket) = scheduler.begin(count, &packet)
            && ticket.start_slot / 9 == target_group
        {
            return port;
        }
    }
    1024
}

fn clone_packet(pool: &Arc<PacketPool>, packet: &PacketBuf) -> Option<PacketBuf> {
    let mut cloned = pool.try_acquire()?;
    cloned.set_read_len(packet.len()).ok()?;
    cloned.as_mut_slice().copy_from_slice(packet.as_slice());
    Some(cloned)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn run_scenario(count: usize, seed: u64, steps: usize, mutation: Option<Mutation>) -> Report {
    let mut scenario = Scenario::new(count, seed, mutation);
    scenario.exercise_pool_bound();
    scenario.fairness_probe();
    scenario.deterministic_fault_probe();
    scenario.slow_neighbor_probe();
    scenario.run_traffic(steps.max(45));
    scenario.finalize()
}

fn run_suite(seed: u64, total_steps: usize) -> Report {
    let mut report = Report {
        coverage: Coverage::default(),
        digest: seed,
        violations: 0,
        delivered_control: 0,
        delivered_bulk: 0,
        maximum_pool_use: 0,
    };
    let steps = total_steps.div_ceil(TOTALS.len()).max(45);
    for (index, count) in TOTALS.into_iter().enumerate() {
        let scenario = run_scenario(count, mix64(seed ^ count as u64), steps.max(count), None);
        report.coverage.merge(&scenario.coverage);
        report.coverage.totals |= 1 << index;
        report.digest = mix64(report.digest ^ scenario.digest ^ count as u64);
        report.violations = report.violations.saturating_add(scenario.violations);
        report.delivered_control = report
            .delivered_control
            .saturating_add(scenario.delivered_control);
        report.delivered_bulk = report
            .delivered_bulk
            .saturating_add(scenario.delivered_bulk);
        report.maximum_pool_use = report.maximum_pool_use.max(scenario.maximum_pool_use);
    }
    report
}

fn assert_report(report: &Report) {
    assert_eq!(report.violations, 0, "{report:#?}");
    assert!(report.coverage.complete(), "{report:#?}");
    assert!(report.delivered_control > 0, "{report:#?}");
    assert!(report.delivered_bulk > 0, "{report:#?}");
    assert!(report.maximum_pool_use > 0, "{report:#?}");
}

#[test]
fn deterministic_transport_chaos_covers_9_through_126_and_replays_exactly() {
    let first = run_suite(0x4d59_5df4_d0f3_3173, TOTALS.len() * 180);
    assert_report(&first);
    let replay = run_suite(0x4d59_5df4_d0f3_3173, TOTALS.len() * 180);
    assert_eq!(replay, first);
}

#[test]
fn transport_chaos_coverage_meta_test_rejects_every_missing_counter() {
    let report = run_suite(0xa076_1d64_78bd_642f, TOTALS.len() * 90);
    assert_report(&report);
    for index in 0..FEATURE_COUNT {
        let mut incomplete = report.coverage.clone();
        incomplete.hits[index] = 0;
        assert!(!incomplete.complete(), "counter={index}");
    }
    let mut incomplete = report.coverage;
    incomplete.totals &= !(1_u32 << (TOTALS.len() - 1));
    assert!(!incomplete.complete());
}

#[test]
fn transport_chaos_mutation_oracle_detects_each_broken_invariant() {
    let baseline = run_scenario(18, 0xe703_7ed1_a0b4_28db, 135, None);
    assert!(baseline.valid(), "{baseline:#?}");
    for mutation in [
        Mutation::AcceptStaleEpoch,
        Mutation::AcceptReplay,
        Mutation::DropControl,
        Mutation::PinFirstWorker,
        Mutation::DisableForceFallback,
        Mutation::SkipGroupedInterruption,
        Mutation::NeverReturnPrimary,
    ] {
        let report = run_scenario(18, 0xe703_7ed1_a0b4_28db, 135, Some(mutation));
        assert!(
            !report.valid(),
            "mutation={mutation:?} escaped oracle: {report:#?}"
        );
    }
}

#[test]
#[ignore = "long deterministic transport chaos soak"]
fn deterministic_transport_chaos_soak() {
    let seed = env::var("CSQTT_SOAK_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0x8ebc_6af0_9c88_c6e3);
    let steps = env::var("CSQTT_TRANSPORT_CHAOS_STEPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(240_000)
        .max(TOTALS.len() * 126);
    let report = run_suite(seed, steps);
    assert_report(&report);
    eprintln!(
        "transport-chaos seed={seed} steps={steps} digest={} control={} bulk={} max_pool={}",
        report.digest, report.delivered_control, report.delivered_bulk, report.maximum_pool_use
    );
}
