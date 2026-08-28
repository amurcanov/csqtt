// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::future::Future;

#[repr(usize)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Stage {
    TunRx,
    TunTx,
    UdpRx,
    UdpTx,
    Scheduler,
    PacketQueue,
    PacketPool,
    WriterBatch,
    ReaderReturn,
    TurnRx,
    TurnTx,
    TurnControl,
    CryptoObfs,
    StreamRecovery,
    ControlStdin,
    StatsEmit,
}

#[inline]
pub fn observe(_stage: Stage) {}

#[inline]
pub fn measure<T>(_stage: Stage, action: impl FnOnce() -> T) -> T {
    action()
}

#[inline]
pub fn measure_sampled<T>(_stage: Stage, _sample_rate: u64, action: impl FnOnce() -> T) -> T {
    action()
}

#[inline]
pub async fn measure_wall_sampled<T, F>(_stage: Stage, _sample_rate: u64, future: F) -> T
where
    F: Future<Output = T>,
{
    future.await
}
