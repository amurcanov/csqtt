// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    client_perf::{self, Stage as PerfStage},
    events::Events,
};
use std::sync::{
    Arc,
    atomic::{AtomicI32, AtomicI64, Ordering},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Stats {
    pub total_bytes_up: AtomicI64,
    pub total_bytes_down: AtomicI64,
    pub active_connections: AtomicI32,
}

impl Stats {
    pub async fn run(self: Arc<Self>, events: Events, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = interval.tick() => {
                    client_perf::measure(PerfStage::StatsEmit, || {
                        let active = self.active_connections.load(Ordering::Relaxed);
                        let up = self.total_bytes_up.load(Ordering::Relaxed);
                        let down = self.total_bytes_down.load(Ordering::Relaxed);
                        let total_mb = (up + down) as f64 / (1024.0 * 1024.0);
                        crate::log_error!("[СТАТИСТИКА] Активных: {active} | Трафик: {total_mb:.2} МБ");
                        events.stats(active, up, down);
                    });
                }
            }
        }
    }
}
