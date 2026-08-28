// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::protocol::StreamRepairCommand;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::Notify;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RepairApplyResult {
    pub restarts: usize,
    pub credential_resets: usize,
}

pub struct RepairState {
    slots: Vec<RepairSlot>,
}

struct RepairSlot {
    restart_generation: AtomicU64,
    credential_generation: AtomicU64,
    last_sequence: AtomicU64,
    ready_sequence: AtomicU64,
    notify: Notify,
}

impl RepairSlot {
    fn new() -> Self {
        Self {
            restart_generation: AtomicU64::new(0),
            credential_generation: AtomicU64::new(0),
            last_sequence: AtomicU64::new(0),
            ready_sequence: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }
}

impl RepairState {
    pub fn new(desired_count: usize) -> Arc<Self> {
        let mut slots = Vec::with_capacity(desired_count.saturating_add(1));
        for _ in 0..=desired_count {
            slots.push(RepairSlot::new());
        }
        Arc::new(Self { slots })
    }

    pub fn restart_generation(&self, worker_id: usize) -> u64 {
        self.slot(worker_id)
            .map(|slot| slot.restart_generation.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    pub fn credential_generation(&self, worker_id: usize) -> u64 {
        self.slot(worker_id)
            .map(|slot| slot.credential_generation.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    pub async fn changed(&self, worker_id: usize, observed_generation: u64) {
        let Some(slot) = self.slot(worker_id) else {
            std::future::pending::<()>().await;
            return;
        };
        loop {
            if slot.restart_generation.load(Ordering::Acquire) != observed_generation {
                return;
            }
            slot.notify.notified().await;
        }
    }

    pub fn mark_ready(&self, worker_id: usize) {
        let Some(slot) = self.slot(worker_id) else {
            return;
        };
        let sequence = slot.last_sequence.load(Ordering::Acquire);
        slot.ready_sequence.store(sequence, Ordering::Release);
    }

    pub fn apply_repair(&self, command: &StreamRepairCommand) -> RepairApplyResult {
        let mut result = RepairApplyResult::default();
        for worker_id in &command.worker_ids {
            let worker_id = usize::from(*worker_id);
            let Some(slot) = self.slot(worker_id) else {
                continue;
            };
            let mut current = slot.last_sequence.load(Ordering::Acquire);
            loop {
                if command.sequence <= current {
                    break;
                }
                match slot.last_sequence.compare_exchange(
                    current,
                    command.sequence,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(previous) => {
                        if previous != 0 && slot.ready_sequence.load(Ordering::Acquire) < previous {
                            slot.credential_generation.fetch_add(1, Ordering::AcqRel);
                            result.credential_resets += 1;
                        }
                        slot.restart_generation.fetch_add(1, Ordering::AcqRel);
                        slot.notify.notify_waiters();
                        result.restarts += 1;
                        break;
                    }
                    Err(next) => current = next,
                }
            }
        }
        result
    }

    pub fn apply_alive(&self, command: &StreamRepairCommand) -> usize {
        let mut applied = 0usize;
        for worker_id in &command.worker_ids {
            let worker_id = usize::from(*worker_id);
            let Some(slot) = self.slot(worker_id) else {
                continue;
            };
            slot.ready_sequence
                .fetch_max(command.sequence, Ordering::AcqRel);
            applied += 1;
        }
        applied
    }

    fn slot(&self, worker_id: usize) -> Option<&RepairSlot> {
        (worker_id != 0)
            .then(|| self.slots.get(worker_id))
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(sequence: u64, worker_ids: &[u16]) -> StreamRepairCommand {
        StreamRepairCommand {
            sequence,
            desired_count: 36,
            worker_ids: worker_ids.to_vec(),
        }
    }

    #[test]
    fn duplicate_repair_sequence_is_ignored() {
        let repair = RepairState::new(36);
        assert_eq!(
            repair.apply_repair(&command(1, &[14, 28])),
            RepairApplyResult {
                restarts: 2,
                credential_resets: 0,
            }
        );
        assert_eq!(
            repair.apply_repair(&command(1, &[14, 28])),
            RepairApplyResult::default()
        );
        assert_eq!(repair.restart_generation(14), 1);
        assert_eq!(repair.restart_generation(28), 1);
    }

    #[test]
    fn unresolved_second_sequence_requests_new_credentials() {
        let repair = RepairState::new(36);
        assert_eq!(repair.apply_repair(&command(1, &[14])).credential_resets, 0);
        assert_eq!(repair.apply_repair(&command(2, &[14])).credential_resets, 1);
        assert_eq!(repair.credential_generation(14), 1);
    }

    #[test]
    fn ready_or_alive_sequence_prevents_credential_escalation() {
        let repair = RepairState::new(36);
        repair.apply_repair(&command(1, &[14]));
        repair.mark_ready(14);
        assert_eq!(repair.apply_repair(&command(2, &[14])).credential_resets, 0);
        repair.apply_alive(&command(2, &[14]));
        assert_eq!(repair.apply_repair(&command(3, &[14])).credential_resets, 0);
    }

    #[test]
    fn invalid_worker_ids_are_ignored() {
        let repair = RepairState::new(9);
        assert_eq!(
            repair.apply_repair(&command(1, &[0, 10])),
            RepairApplyResult::default()
        );
    }
}
