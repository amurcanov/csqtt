// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{PacketReceiver, PacketSender, packet_channel};
use crate::packet::{
    PACKET_CAPACITY, PACKET_HEADROOM, PACKET_POOL_PER_WORKER, PACKET_POOL_SHARED, PacketBuf,
    PacketPool,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

const GIB: u64 = 1024 * 1024 * 1024;
const KIB: u64 = 1024;
const RATE_PER_WORKER: u64 = 500 * KIB;
const PROFILE_SECONDS: u64 = 49;
const DEADLINE_SECONDS: u64 = 51;
const QUEUE_CAPACITY: usize = 64;
const PACKET_BYTES: usize = PACKET_CAPACITY - PACKET_HEADROOM;
const ORACLE_HEADER_BYTES: usize = 24;
const ORACLE_MAGIC: u64 = 0x4353_5154_5453_4f41;

#[derive(Debug)]
struct SendReport {
    bytes: u64,
    packets: u64,
    elapsed: Duration,
}

#[derive(Debug)]
struct ReceiveReport {
    bytes: u64,
    packets: u64,
    maximum_progress_gap: Duration,
}

#[derive(Debug)]
struct WorkerReport {
    target: u64,
    sent: u64,
    delivered: u64,
    sent_packets: u64,
    delivered_packets: u64,
    send_elapsed: Duration,
    maximum_progress_gap: Duration,
}

#[derive(Debug)]
struct ProfileReport {
    workers: usize,
    target: u64,
    delivered: u64,
    rate_per_worker: Option<u64>,
    per_worker: Vec<WorkerReport>,
    elapsed: Duration,
    peak_in_flight: usize,
    in_flight_at_end: usize,
    pool_capacity: usize,
    pool_available: usize,
}

#[derive(Default)]
struct InFlight {
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl InFlight {
    fn acquired(&self) {
        let current = self.current.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(current, Ordering::AcqRel);
    }

    fn released(&self) {
        assert!(self.current.fetch_sub(1, Ordering::AcqRel) > 0);
    }
}

fn paced_duration(bytes: u64, rate: u64) -> Duration {
    assert!(rate > 0);
    let nanoseconds = (u128::from(bytes) * 1_000_000_000_u128).div_ceil(u128::from(rate));
    Duration::from_nanos(u64::try_from(nanoseconds).unwrap())
}

fn next_packet_length(remaining: u64) -> usize {
    assert!(remaining > 0);
    if remaining <= PACKET_BYTES as u64 {
        return remaining as usize;
    }
    let tail = remaining - PACKET_BYTES as u64;
    if tail < ORACLE_HEADER_BYTES as u64 {
        return usize::try_from(remaining - ORACLE_HEADER_BYTES as u64).unwrap();
    }
    PACKET_BYTES
}

fn stamp_packet(packet: &mut PacketBuf, worker: usize, sequence: u64) {
    assert!(packet.len() >= ORACLE_HEADER_BYTES);
    let bytes = packet.as_mut_slice();
    bytes[..8].copy_from_slice(&ORACLE_MAGIC.to_be_bytes());
    bytes[8..16].copy_from_slice(&(worker as u64).to_be_bytes());
    bytes[16..24].copy_from_slice(&sequence.to_be_bytes());
}

fn verify_packet(packet: &PacketBuf, worker: usize, sequence: u64, length: usize) {
    assert_eq!(packet.len(), length);
    let bytes = packet.as_slice();
    assert_eq!(
        u64::from_be_bytes(bytes[..8].try_into().unwrap()),
        ORACLE_MAGIC
    );
    assert_eq!(
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        worker as u64
    );
    assert_eq!(
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        sequence
    );
}

async fn send_exact(
    sender: PacketSender,
    pool: Arc<PacketPool>,
    in_flight: Arc<InFlight>,
    worker: usize,
    target: u64,
    rate: Option<u64>,
    started: Instant,
) -> SendReport {
    let mut sent = 0_u64;
    let mut sequence = 0_u64;
    while sent < target {
        let length = next_packet_length(target - sent);
        if let Some(rate) = rate {
            tokio::time::sleep_until(started + paced_duration(sent + length as u64, rate)).await;
        }
        let mut packet = loop {
            if let Some(packet) = pool.try_acquire() {
                in_flight.acquired();
                break packet;
            }
            tokio::task::yield_now().await;
        };
        packet.set_read_len(length).unwrap();
        stamp_packet(&mut packet, worker, sequence);
        loop {
            match sender.try_send(packet) {
                Ok(()) => break,
                Err(returned) => {
                    packet = returned;
                    tokio::task::yield_now().await;
                }
            }
        }
        sent += length as u64;
        sequence += 1;
    }
    SendReport {
        bytes: sent,
        packets: sequence,
        elapsed: started.elapsed(),
    }
}

async fn receive_exact(
    receiver: PacketReceiver,
    in_flight: Arc<InFlight>,
    worker: usize,
    target: u64,
    started: Instant,
) -> ReceiveReport {
    let cancel = CancellationToken::new();
    let mut received = 0_u64;
    let mut sequence = 0_u64;
    let mut previous_progress = Duration::ZERO;
    let mut maximum_progress_gap = Duration::ZERO;
    while received < target {
        let packet = receiver.recv(&cancel).await.unwrap();
        let expected_length = next_packet_length(target - received);
        verify_packet(&packet, worker, sequence, expected_length);
        received += packet.len() as u64;
        sequence += 1;
        let progress = started.elapsed();
        maximum_progress_gap = maximum_progress_gap.max(progress.saturating_sub(previous_progress));
        previous_progress = progress;
        in_flight.released();
        drop(packet);
    }
    ReceiveReport {
        bytes: received,
        packets: sequence,
        maximum_progress_gap,
    }
}

async fn run_profile(workers: usize, target: u64, rate: Option<u64>) -> ProfileReport {
    assert!(workers > 0);
    let pool = PacketPool::new(workers * PACKET_POOL_PER_WORKER + PACKET_POOL_SHARED);
    let pool_capacity = pool.capacity();
    let in_flight = Arc::new(InFlight::default());
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for worker in 0..workers {
        let share = target / workers as u64 + u64::from((worker as u64) < target % workers as u64);
        assert!(share >= ORACLE_HEADER_BYTES as u64);
        let (sender, receiver) = packet_channel(QUEUE_CAPACITY, true);
        let send_pool = pool.clone();
        let send_in_flight = in_flight.clone();
        let receive_in_flight = in_flight.clone();
        tasks.spawn(async move {
            let (sent, received) = tokio::join!(
                send_exact(
                    sender,
                    send_pool,
                    send_in_flight,
                    worker,
                    share,
                    rate,
                    started
                ),
                receive_exact(receiver, receive_in_flight, worker, share, started)
            );
            (
                worker,
                WorkerReport {
                    target: share,
                    sent: sent.bytes,
                    delivered: received.bytes,
                    sent_packets: sent.packets,
                    delivered_packets: received.packets,
                    send_elapsed: sent.elapsed,
                    maximum_progress_gap: received.maximum_progress_gap,
                },
            )
        });
    }
    let mut per_worker: Vec<Option<WorkerReport>> =
        std::iter::repeat_with(|| None).take(workers).collect();
    while let Some(result) = tasks.join_next().await {
        let (worker, report) = result.unwrap();
        assert!(per_worker[worker].replace(report).is_none());
    }
    let per_worker: Vec<WorkerReport> = per_worker.into_iter().map(Option::unwrap).collect();
    let delivered = per_worker.iter().map(|report| report.delivered).sum();
    ProfileReport {
        workers,
        target,
        delivered,
        rate_per_worker: rate,
        per_worker,
        elapsed: started.elapsed(),
        peak_in_flight: in_flight.peak.load(Ordering::Acquire),
        in_flight_at_end: in_flight.current.load(Ordering::Acquire),
        pool_capacity,
        pool_available: pool.available(),
    }
}

fn assert_complete(report: &ProfileReport) {
    assert_eq!(report.delivered, report.target, "{report:#?}");
    assert_eq!(report.per_worker.len(), report.workers, "{report:#?}");
    assert_eq!(
        report
            .per_worker
            .iter()
            .map(|worker| worker.delivered)
            .sum::<u64>(),
        report.target
    );
    for (worker, worker_report) in report.per_worker.iter().enumerate() {
        let expected = report.target / report.workers as u64
            + u64::from((worker as u64) < report.target % report.workers as u64);
        assert_eq!(worker_report.target, expected, "{report:#?}");
        assert_eq!(worker_report.sent, expected, "{report:#?}");
        assert_eq!(worker_report.delivered, expected, "{report:#?}");
        assert_eq!(
            worker_report.sent_packets, worker_report.delivered_packets,
            "{report:#?}"
        );
        assert!(
            worker_report.maximum_progress_gap < Duration::from_millis(500),
            "{report:#?}"
        );
        if let Some(rate) = report.rate_per_worker {
            assert!(
                worker_report.send_elapsed >= paced_duration(expected, rate),
                "{report:#?}"
            );
        }
    }
    assert_eq!(report.in_flight_at_end, 0, "{report:#?}");
    assert!(
        report.peak_in_flight <= report.workers * (QUEUE_CAPACITY + 2),
        "{report:#?}"
    );
    assert_eq!(report.pool_available, report.pool_capacity, "{report:#?}");
}

#[test]
fn five_hundred_kib_rate_math_is_exact_for_all_requested_worker_counts() {
    let deadline_bytes = RATE_PER_WORKER * DEADLINE_SECONDS;
    assert_eq!(deadline_bytes * 9, 235_008_000);
    assert_eq!(deadline_bytes * 27, 705_024_000);
    assert!(deadline_bytes * 9 < GIB);
    assert!(deadline_bytes * 27 < GIB);
    assert!(deadline_bytes * 108 > GIB);
    assert!(deadline_bytes * 126 > GIB);
    assert_eq!(GIB.div_ceil(RATE_PER_WORKER * 9), 234);
    assert_eq!(GIB.div_ceil(RATE_PER_WORKER * 27), 78);
    assert_eq!(GIB.div_ceil(RATE_PER_WORKER * 108), 20);
    assert_eq!(GIB.div_ceil(RATE_PER_WORKER * 126), 17);
    assert_eq!(GIB.div_ceil(deadline_bytes), 42);
    assert_eq!(GIB.div_ceil(deadline_bytes).div_ceil(9) * 9, 45);
}

#[tokio::test]
async fn bounded_pipeline_delivers_every_byte_and_returns_every_buffer() {
    for workers in [9, 27, 108, 126] {
        let report = tokio::time::timeout(
            Duration::from_secs(30),
            run_profile(workers, 16 * 1024 * 1024, None),
        )
        .await
        .unwrap();
        assert_complete(&report);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_channel_recreation_under_saturated_load_recovers_cleanly() {
    const RECREATIONS: usize = 128;
    const GENERATION_BYTES: u64 = PACKET_BYTES as u64 * 129 + ORACLE_HEADER_BYTES as u64;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let pool = PacketPool::new(QUEUE_CAPACITY + 2);
        let in_flight = Arc::new(InFlight::default());
        let mut delivered = 0_u64;
        for generation in 0..RECREATIONS {
            let started = Instant::now();
            let (sender, receiver) = packet_channel(QUEUE_CAPACITY, true);
            let stale_sender = sender.clone();
            let (sent, received) = tokio::join!(
                send_exact(
                    sender,
                    pool.clone(),
                    in_flight.clone(),
                    generation,
                    GENERATION_BYTES,
                    None,
                    started
                ),
                receive_exact(
                    receiver,
                    in_flight.clone(),
                    generation,
                    GENERATION_BYTES,
                    started
                )
            );
            assert_eq!(sent.bytes, GENERATION_BYTES);
            assert_eq!(received.bytes, GENERATION_BYTES);
            assert_eq!(sent.packets, received.packets);
            assert!(received.maximum_progress_gap < Duration::from_millis(500));
            delivered += received.bytes;

            let mut probe = loop {
                if let Some(packet) = pool.try_acquire() {
                    in_flight.acquired();
                    break packet;
                }
                tokio::task::yield_now().await;
            };
            probe.set_read_len(ORACLE_HEADER_BYTES).unwrap();
            stamp_packet(&mut probe, generation, u64::MAX);
            let returned = stale_sender.try_send(probe).unwrap_err();
            verify_packet(&returned, generation, u64::MAX, ORACLE_HEADER_BYTES);
            in_flight.released();
            drop(returned);
            assert_eq!(in_flight.current.load(Ordering::Acquire), 0);
            assert_eq!(pool.available(), pool.capacity());
        }
        assert_eq!(delivered, GENERATION_BYTES * RECREATIONS as u64);
        assert!(in_flight.peak.load(Ordering::Acquire) <= QUEUE_CAPACITY + 2);
        assert_eq!(in_flight.current.load(Ordering::Acquire), 0);
        assert_eq!(pool.available(), pool.capacity());
    })
    .await;
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real 51 second 1 GiB throughput profile"]
async fn one_gibibyte_with_9_27_108_126_workers_and_500_kib_per_worker_limit() {
    let target_9 = RATE_PER_WORKER * 9 * PROFILE_SECONDS;
    let target_27 = RATE_PER_WORKER * 27 * PROFILE_SECONDS;
    let profile_9 = run_profile(9, target_9, Some(RATE_PER_WORKER));
    let profile_27 = run_profile(27, target_27, Some(RATE_PER_WORKER));
    let profile_108 = run_profile(108, GIB, Some(RATE_PER_WORKER));
    let profile_126 = run_profile(126, GIB, Some(RATE_PER_WORKER));
    let (report_9, report_27, report_108, report_126) =
        tokio::time::timeout(Duration::from_secs(DEADLINE_SECONDS), async {
            tokio::join!(profile_9, profile_27, profile_108, profile_126)
        })
        .await
        .unwrap();
    for report in [&report_9, &report_27, &report_108, &report_126] {
        assert_complete(report);
        assert!(report.elapsed <= Duration::from_secs(DEADLINE_SECONDS));
    }
    assert_eq!(report_9.delivered, 225_792_000);
    assert_eq!(report_27.delivered, 677_376_000);
    assert_eq!(report_108.delivered, GIB);
    assert_eq!(report_126.delivered, GIB);
    assert_eq!(
        report_9.delivered + report_27.delivered + report_108.delivered + report_126.delivered,
        3_050_651_648
    );
}
