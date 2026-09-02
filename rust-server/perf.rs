// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use serde::{Deserialize, Serialize};
use std::sync::{
    LazyLock, RwLock,
    atomic::{AtomicU64, Ordering},
};

pub const SAMPLE_INTERVAL: u64 = 64;

pub static ALL_CLIENTS: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_DATAPLANE: LazyLock<RwLock<Snapshot>> =
    LazyLock::new(|| RwLock::new(Snapshot::default()));
pub static GLOBAL_PROTOCOL: LazyLock<RwLock<Snapshot>> =
    LazyLock::new(|| RwLock::new(Snapshot::default()));
pub static DATAPLANE_CPU_NS: AtomicU64 = AtomicU64::new(0);
pub static DATAPLANE_TID: AtomicU64 = AtomicU64::new(0);
pub static DATAPLANE_CPU_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub operations: u64,
    pub bytes: u64,
    pub samples: u64,
    pub sampled_ns: u64,
    #[serde(default)]
    pub sampled_wall_ns: u64,
}

impl Counters {
    pub fn delta(self, previous: Self) -> Self {
        Self {
            operations: self.operations.saturating_sub(previous.operations),
            bytes: self.bytes.saturating_sub(previous.bytes),
            samples: self.samples.saturating_sub(previous.samples),
            sampled_ns: self.sampled_ns.saturating_sub(previous.sampled_ns),
            sampled_wall_ns: self
                .sampled_wall_ns
                .saturating_sub(previous.sampled_wall_ns),
        }
    }

    fn add(self, other: Self) -> Self {
        Self {
            operations: self.operations.saturating_add(other.operations),
            bytes: self.bytes.saturating_add(other.bytes),
            samples: self.samples.saturating_add(other.samples),
            sampled_ns: self.sampled_ns.saturating_add(other.sampled_ns),
            sampled_wall_ns: self.sampled_wall_ns.saturating_add(other.sampled_wall_ns),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub dispatch: Counters,
    pub udp_rx: Counters,
    pub tun_rx: Counters,
    pub route_replay: Counters,
    pub tun_write: Counters,
    pub udp_queue: Counters,
    pub flush: Counters,
    pub bookkeeping: Counters,
}

impl Snapshot {
    pub fn delta(self, previous: Self) -> Self {
        Self {
            dispatch: self.dispatch.delta(previous.dispatch),
            udp_rx: self.udp_rx.delta(previous.udp_rx),
            tun_rx: self.tun_rx.delta(previous.tun_rx),
            route_replay: self.route_replay.delta(previous.route_replay),
            tun_write: self.tun_write.delta(previous.tun_write),
            udp_queue: self.udp_queue.delta(previous.udp_queue),
            flush: self.flush.delta(previous.flush),
            bookkeeping: self.bookkeeping.delta(previous.bookkeeping),
        }
    }

    pub fn merge(self, other: Self) -> Self {
        Self {
            dispatch: self.dispatch.add(other.dispatch),
            udp_rx: self.udp_rx.add(other.udp_rx),
            tun_rx: self.tun_rx.add(other.tun_rx),
            route_replay: self.route_replay.add(other.route_replay),
            tun_write: self.tun_write.add(other.tun_write),
            udp_queue: self.udp_queue.add(other.udp_queue),
            flush: self.flush.add(other.flush),
            bookkeeping: self.bookkeeping.add(other.bookkeeping),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Stage {
    Dispatch,
    UdpRx,
    TunRx,
    RouteReplay,
    TunWrite,
    UdpQueue,
    Flush,
    Bookkeeping,
}

impl Stage {
    #[cfg(feature = "diagnostics")]
    fn index(self) -> usize {
        match self {
            Self::Dispatch => 0,
            Self::UdpRx => 1,
            Self::TunRx => 2,
            Self::RouteReplay => 3,
            Self::TunWrite => 4,
            Self::UdpQueue => 5,
            Self::Flush => 6,
            Self::Bookkeeping => 7,
        }
    }
}

#[derive(Default)]
pub struct Profiler {
    #[cfg(feature = "diagnostics")]
    enabled: bool,
    #[cfg(feature = "diagnostics")]
    cursors: [u64; 8],
    #[cfg(feature = "diagnostics")]
    counters: [Counters; 8],
}

impl Profiler {
    pub fn refresh_enabled(&mut self) {
        #[cfg(feature = "diagnostics")]
        {
            self.enabled = ALL_CLIENTS.load(Ordering::Acquire) != 0;
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = self;
        }
    }

    pub fn enabled(&self) -> bool {
        #[cfg(feature = "diagnostics")]
        {
            self.enabled
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = self;
            false
        }
    }

    #[inline(always)]
    pub fn begin(&mut self, stage: Stage, bytes: usize) -> Option<u64> {
        #[cfg(feature = "diagnostics")]
        {
            if !self.enabled {
                return None;
            }
            let index = stage.index();
            let counter = &mut self.counters[index];
            counter.operations = counter.operations.saturating_add(1);
            counter.bytes = counter.bytes.saturating_add(bytes as u64);
            let cursor = self.cursors[index];
            self.cursors[index] = cursor.wrapping_add(1);
            if cursor.is_multiple_of(SAMPLE_INTERVAL) {
                counter.samples = counter.samples.saturating_add(1);
                Some(thread_cpu_time_ns())
            } else {
                None
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (stage, bytes);
            None
        }
    }

    #[inline(always)]
    pub fn finish(&mut self, stage: Stage, started: Option<u64>) {
        #[cfg(feature = "diagnostics")]
        {
            let Some(started) = started else {
                return;
            };
            self.finish_elapsed(stage, thread_cpu_time_ns().saturating_sub(started));
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (stage, started);
        }
    }

    #[cfg(feature = "diagnostics")]
    #[inline(always)]
    pub fn finish_elapsed(&mut self, stage: Stage, elapsed_ns: u64) {
        let counter = &mut self.counters[stage.index()];
        counter.sampled_ns = counter.sampled_ns.saturating_add(elapsed_ns);
    }

    #[inline(always)]
    pub fn expand_batch(&mut self, stage: Stage, operations: u64, bytes: u64, sampled: bool) {
        #[cfg(feature = "diagnostics")]
        {
            if !self.enabled {
                return;
            }
            let counter = &mut self.counters[stage.index()];
            let additional = operations.saturating_sub(1);
            counter.operations = counter.operations.saturating_add(additional);
            counter.bytes = counter.bytes.saturating_add(bytes);
            if sampled {
                counter.samples = counter.samples.saturating_add(additional);
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = (stage, operations, bytes, sampled);
        }
    }

    #[cfg(feature = "diagnostics")]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            dispatch: self.counters[Stage::Dispatch.index()],
            udp_rx: self.counters[Stage::UdpRx.index()],
            tun_rx: self.counters[Stage::TunRx.index()],
            route_replay: self.counters[Stage::RouteReplay.index()],
            tun_write: self.counters[Stage::TunWrite.index()],
            udp_queue: self.counters[Stage::UdpQueue.index()],
            flush: self.counters[Stage::Flush.index()],
            bookkeeping: self.counters[Stage::Bookkeeping.index()],
        }
    }

    pub fn publish_dataplane(&self) {
        #[cfg(feature = "diagnostics")]
        {
            if self.enabled
                && let Ok(mut global) = GLOBAL_DATAPLANE.write()
            {
                *global = self.snapshot();
            }
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            let _ = self;
        }
    }

    #[cfg(feature = "diagnostics")]
    pub fn publish_protocol(&self) {
        if self.enabled
            && let Ok(mut global) = GLOBAL_PROTOCOL.write()
        {
            *global = self.snapshot();
        }
    }
}

#[inline]
pub fn publish_dataplane_cpu(cpu_ns: u64) {
    DATAPLANE_CPU_NS.store(cpu_ns, Ordering::Release);
    DATAPLANE_CPU_SEQUENCE.fetch_add(1, Ordering::Release);
}

#[inline]
pub fn publish_dataplane_tid() {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if tid > 0 {
        DATAPLANE_TID.store(tid as u64, Ordering::Release);
    }
}

#[inline(always)]
pub fn thread_cpu_time_ns() -> u64 {
    clock_time_ns(libc::CLOCK_THREAD_CPUTIME_ID)
}

#[inline(always)]
pub fn process_cpu_time_ns() -> u64 {
    clock_time_ns(libc::CLOCK_PROCESS_CPUTIME_ID)
}

pub fn process_cpu_split_ns() -> (u64, u64) {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return (0, 0);
    };
    let Some((_, user_ticks, system_ticks)) = parse_proc_stat(&stat) else {
        return (0, 0);
    };
    ticks_to_ns(user_ticks, system_ticks).unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct ThreadCpuSnapshot {
    pub tid: u32,
    pub name: String,
    pub user_ns: u64,
    pub system_ns: u64,
}

pub fn process_thread_cpu_snapshot() -> Vec<ThreadCpuSnapshot> {
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut threads = Vec::new();
    for entry in entries.flatten() {
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((name, user_ticks, system_ticks)) = parse_proc_stat(&stat) else {
            continue;
        };
        let Some((user_ns, system_ns)) = ticks_to_ns(user_ticks, system_ticks) else {
            continue;
        };
        threads.push(ThreadCpuSnapshot {
            tid,
            name: name.to_owned(),
            user_ns,
            system_ns,
        });
    }
    threads
}

fn parse_proc_stat(stat: &str) -> Option<(&str, u64, u64)> {
    let comm_start = stat.find('(')?;
    let comm_end = stat.rfind(')')?;
    if comm_end <= comm_start {
        return None;
    }
    let mut fields = stat[comm_end + 1..].split_whitespace();
    let user_ticks = fields.nth(11)?.parse().ok()?;
    let system_ticks = fields.next()?.parse().ok()?;
    Some((&stat[comm_start + 1..comm_end], user_ticks, system_ticks))
}

fn ticks_to_ns(user_ticks: u64, system_ticks: u64) -> Option<(u64, u64)> {
    #[allow(clippy::useless_conversion)]
    static TICKS_PER_SECOND: LazyLock<i64> =
        LazyLock::new(|| unsafe { libc::sysconf(libc::_SC_CLK_TCK).into() });
    let ticks_per_second = *TICKS_PER_SECOND;
    if ticks_per_second <= 0 {
        return None;
    }
    let scale = |ticks: u64| {
        (u128::from(ticks) * 1_000_000_000u128 / ticks_per_second as u128).min(u128::from(u64::MAX))
            as u64
    };
    Some((scale(user_ticks), scale(system_ticks)))
}

#[inline(always)]
fn clock_time_ns(clock: libc::clockid_t) -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(clock, &mut value) };
    if result != 0 {
        return 0;
    }
    (value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! counter_delta_case {
        ($name:ident, $field:ident, $current:expr, $previous:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let current = Counters {
                    $field: $current,
                    ..Counters::default()
                };
                let previous = Counters {
                    $field: $previous,
                    ..Counters::default()
                };
                assert_eq!(current.delta(previous).$field, $expected);
            }
        };
    }

    counter_delta_case!(counter_delta_operations_increase, operations, 9, 4, 5);
    counter_delta_case!(
        counter_delta_operations_rolls_back_to_zero,
        operations,
        4,
        9,
        0
    );
    counter_delta_case!(counter_delta_bytes_increase, bytes, 4096, 1024, 3072);
    counter_delta_case!(counter_delta_bytes_rolls_back_to_zero, bytes, 7, 8, 0);
    counter_delta_case!(counter_delta_samples_increase, samples, 72, 64, 8);
    counter_delta_case!(counter_delta_samples_rolls_back_to_zero, samples, 63, 64, 0);
    counter_delta_case!(counter_delta_cpu_increase, sampled_ns, 901, 900, 1);
    counter_delta_case!(counter_delta_cpu_rolls_back_to_zero, sampled_ns, 0, 1, 0);
    counter_delta_case!(counter_delta_wall_increase, sampled_wall_ns, 128, 32, 96);
    counter_delta_case!(
        counter_delta_wall_rolls_back_to_zero,
        sampled_wall_ns,
        1,
        2,
        0
    );

    macro_rules! counter_merge_case {
        ($name:ident, $field:ident, $left:expr, $right:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let left = Counters {
                    $field: $left,
                    ..Counters::default()
                };
                let right = Counters {
                    $field: $right,
                    ..Counters::default()
                };
                assert_eq!(left.add(right).$field, $expected);
            }
        };
    }

    counter_merge_case!(counter_merge_operations_adds, operations, 19, 23, 42);
    counter_merge_case!(
        counter_merge_operations_saturates,
        operations,
        u64::MAX,
        1,
        u64::MAX
    );
    counter_merge_case!(counter_merge_bytes_adds, bytes, 12_000, 34_000, 46_000);
    counter_merge_case!(
        counter_merge_bytes_saturates,
        bytes,
        u64::MAX - 1,
        2,
        u64::MAX
    );
    counter_merge_case!(counter_merge_samples_adds, samples, 63, 1, 64);
    counter_merge_case!(
        counter_merge_samples_saturates,
        samples,
        u64::MAX,
        64,
        u64::MAX
    );
    counter_merge_case!(counter_merge_cpu_adds, sampled_ns, 55, 89, 144);
    counter_merge_case!(
        counter_merge_cpu_saturates,
        sampled_ns,
        u64::MAX - 7,
        8,
        u64::MAX
    );
    counter_merge_case!(counter_merge_wall_adds, sampled_wall_ns, 250, 750, 1000);
    counter_merge_case!(
        counter_merge_wall_saturates,
        sampled_wall_ns,
        u64::MAX,
        1,
        u64::MAX
    );

    macro_rules! snapshot_delta_case {
        ($name:ident, $field:ident) => {
            #[test]
            fn $name() {
                let current = Snapshot {
                    $field: Counters {
                        operations: 21,
                        bytes: 2100,
                        samples: 21,
                        sampled_ns: 210,
                        sampled_wall_ns: 420,
                    },
                    ..Snapshot::default()
                };
                let previous = Snapshot {
                    $field: Counters {
                        operations: 13,
                        bytes: 1300,
                        samples: 13,
                        sampled_ns: 130,
                        sampled_wall_ns: 260,
                    },
                    ..Snapshot::default()
                };
                let delta = current.delta(previous).$field;
                assert_eq!(delta.operations, 8);
                assert_eq!(delta.bytes, 800);
                assert_eq!(delta.samples, 8);
                assert_eq!(delta.sampled_ns, 80);
                assert_eq!(delta.sampled_wall_ns, 160);
            }
        };
    }

    snapshot_delta_case!(snapshot_delta_dispatch, dispatch);
    snapshot_delta_case!(snapshot_delta_udp_rx, udp_rx);
    snapshot_delta_case!(snapshot_delta_tun_rx, tun_rx);
    snapshot_delta_case!(snapshot_delta_route_replay, route_replay);
    snapshot_delta_case!(snapshot_delta_tun_write, tun_write);
    snapshot_delta_case!(snapshot_delta_udp_queue, udp_queue);
    snapshot_delta_case!(snapshot_delta_flush, flush);
    snapshot_delta_case!(snapshot_delta_bookkeeping, bookkeeping);

    macro_rules! snapshot_merge_case {
        ($name:ident, $field:ident) => {
            #[test]
            fn $name() {
                let left = Snapshot {
                    $field: Counters {
                        operations: 3,
                        bytes: 30,
                        samples: 3,
                        sampled_ns: 300,
                        sampled_wall_ns: 3000,
                    },
                    ..Snapshot::default()
                };
                let right = Snapshot {
                    $field: Counters {
                        operations: 4,
                        bytes: 40,
                        samples: 4,
                        sampled_ns: 400,
                        sampled_wall_ns: 4000,
                    },
                    ..Snapshot::default()
                };
                let merged = left.merge(right).$field;
                assert_eq!(merged.operations, 7);
                assert_eq!(merged.bytes, 70);
                assert_eq!(merged.samples, 7);
                assert_eq!(merged.sampled_ns, 700);
                assert_eq!(merged.sampled_wall_ns, 7000);
            }
        };
    }

    snapshot_merge_case!(snapshot_merge_dispatch, dispatch);
    snapshot_merge_case!(snapshot_merge_udp_rx, udp_rx);
    snapshot_merge_case!(snapshot_merge_tun_rx, tun_rx);
    snapshot_merge_case!(snapshot_merge_route_replay, route_replay);
    snapshot_merge_case!(snapshot_merge_tun_write, tun_write);
    snapshot_merge_case!(snapshot_merge_udp_queue, udp_queue);
    snapshot_merge_case!(snapshot_merge_flush, flush);
    snapshot_merge_case!(snapshot_merge_bookkeeping, bookkeeping);

    fn proc_stat(name: &str, user_ticks: u64, system_ticks: u64) -> String {
        let mut stat = format!("42 ({name}) S");
        for _ in 0..10 {
            stat.push_str(" 0");
        }
        format!("{stat} {user_ticks} {system_ticks} 0 0")
    }

    macro_rules! proc_stat_case {
        ($name:ident, $thread_name:expr, $user:expr, $system:expr) => {
            #[test]
            fn $name() {
                let stat = proc_stat($thread_name, $user, $system);
                assert_eq!(parse_proc_stat(&stat), Some(($thread_name, $user, $system)));
            }
        };
    }

    proc_stat_case!(proc_stat_parses_server_thread, "csqtt", 41, 9);
    proc_stat_case!(
        proc_stat_parses_dataplane_thread,
        "dataplane fast path",
        87,
        12
    );
    proc_stat_case!(
        proc_stat_parses_parenthesis_in_thread_name,
        "worker) 7",
        5,
        6
    );
    proc_stat_case!(
        proc_stat_parses_unicode_thread_name,
        "поток-обработчик",
        11,
        13
    );

    #[test]
    fn profiler_fast_path_has_an_explicit_mode_contract() {
        let mut profiler = Profiler::default();
        #[cfg(feature = "diagnostics")]
        {
            let previous = ALL_CLIENTS.swap(1, Ordering::AcqRel);
            profiler.refresh_enabled();
            assert!(profiler.enabled());
            let started = profiler.begin(Stage::Dispatch, 120);
            assert!(started.is_some());
            profiler.finish(Stage::Dispatch, started);
            let snapshot = profiler.snapshot();
            assert_eq!(snapshot.dispatch.operations, 1);
            assert_eq!(snapshot.dispatch.bytes, 120);
            assert_eq!(snapshot.dispatch.samples, 1);
            ALL_CLIENTS.store(previous, Ordering::Release);
        }
        #[cfg(not(feature = "diagnostics"))]
        {
            profiler.refresh_enabled();
            assert!(!profiler.enabled());
            let started = profiler.begin(Stage::Dispatch, 120);
            assert!(started.is_none());
            profiler.finish(Stage::Dispatch, started);
        }
    }

    #[test]
    fn tick_conversion_preserves_cpu_ordering() {
        let (small_user, small_system) = ticks_to_ns(12, 7).unwrap();
        let (large_user, large_system) = ticks_to_ns(13, 8).unwrap();
        assert!(large_user >= small_user);
        assert!(large_system >= small_system);
    }

    #[test]
    fn tick_conversion_saturates_at_u64_limit() {
        let (user, system) = ticks_to_ns(u64::MAX, u64::MAX).unwrap();
        assert_eq!(user, u64::MAX);
        assert_eq!(system, u64::MAX);
    }
}
