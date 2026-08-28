// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use serde::Serialize;
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

pub const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";
const NETWORK_TIMEOUT_BURST_WINDOW: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct Events {
    enabled: bool,
    panel_restart_emitted: Arc<AtomicBool>,
    network_suspect_emitted: Arc<AtomicBool>,
    network_timeouts: Arc<AtomicUsize>,
    network_timeout_window_started: Arc<Mutex<Option<Instant>>>,
    unavailable_hashes: Arc<Mutex<HashSet<String>>>,
}

impl Events {
    pub fn from_env() -> Self {
        Self::new(std::env::var("CSQTT_EVENTS").as_deref() == Ok("1"))
    }

    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            panel_restart_emitted: Arc::new(AtomicBool::new(false)),
            network_suspect_emitted: Arc::new(AtomicBool::new(false)),
            network_timeouts: Arc::new(AtomicUsize::new(0)),
            network_timeout_window_started: Arc::new(Mutex::new(None)),
            unavailable_hashes: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn emit<T: Serialize>(&self, kind: &str, payload: &T) {
        if !self.enabled {
            return;
        }
        if let Some(line) = encode_event(kind, payload) {
            crate::log_output!("{line}");
        }
    }

    pub fn ready(&self, worker: usize) {
        self.emit("READY", &serde_json::json!({"worker": worker}));
    }

    pub fn stopped(&self) {
        self.emit("STOPPED", &serde_json::json!({}));
    }

    pub fn process(&self, pid: u32) {
        self.emit("PROCESS", &serde_json::json!({"pid": pid}));
    }

    pub fn config(&self, config: &str) {
        self.emit("CONFIG", &serde_json::json!({"config": config}));
    }

    pub fn stats(&self, active: i32, bytes_up: i64, bytes_down: i64) {
        self.emit(
            "STATS",
            &serde_json::json!({
                "active": active,
                "bytes_up": bytes_up,
                "bytes_down": bytes_down
            }),
        );
    }

    pub fn active_zero(&self) {
        self.emit("ACTIVE_ZERO", &serde_json::json!({}));
    }

    pub fn panel_restart(&self) {
        if !self.panel_restart_emitted.swap(true, Ordering::AcqRel) {
            self.emit("SERVER_RESTART", &serde_json::json!({"source": "panel"}));
        }
    }

    pub fn progress(&self, kind: &str) {
        self.emit("PROGRESS", &serde_json::json!({"kind": kind}));
    }

    pub fn network_timeout(&self) {
        let now = Instant::now();
        let mut window = self
            .network_timeout_window_started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if window.is_none_or(|started| {
            now.saturating_duration_since(started) > NETWORK_TIMEOUT_BURST_WINDOW
        }) {
            *window = Some(now);
            self.network_timeouts.store(0, Ordering::Release);
            self.network_suspect_emitted.store(false, Ordering::Release);
        }
        let should_emit = self.network_timeouts.fetch_add(1, Ordering::AcqRel) + 1 >= 6
            && !self.network_suspect_emitted.swap(true, Ordering::AcqRel);
        drop(window);
        if should_emit {
            self.emit("NETWORK_SUSPECT", &serde_json::json!({}));
        }
    }

    pub fn network_recovered(&self) {
        self.network_timeouts.store(0, Ordering::Release);
        self.network_suspect_emitted.store(false, Ordering::Release);
        let mut window = self
            .network_timeout_window_started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *window = None;
    }

    pub fn call_unavailable(&self, hash: &str, code: i64) {
        let should_emit = self
            .unavailable_hashes
            .lock()
            .map(|mut hashes| hashes.insert(hash.to_owned()))
            .unwrap_or(false);
        if should_emit {
            self.emit(
                "CALL_UNAVAILABLE",
                &serde_json::json!({"hash": hash, "code": code}),
            );
        }
    }
}

fn encode_event<T: Serialize>(kind: &str, payload: &T) -> Option<String> {
    let json = serde_json::to_string(payload).ok()?;
    Some(format!("{EVENT_PREFIX}{kind}|{json}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_payload_lifecycle_events_are_json_objects() {
        assert_eq!(
            encode_event("READY", &serde_json::json!({})).as_deref(),
            Some("__CSQTT_EVENT__|READY|{}")
        );
        assert_eq!(
            encode_event("STOPPED", &serde_json::json!({})).as_deref(),
            Some("__CSQTT_EVENT__|STOPPED|{}")
        );
        assert_eq!(
            encode_event("ACTIVE_ZERO", &serde_json::json!({})).as_deref(),
            Some("__CSQTT_EVENT__|ACTIVE_ZERO|{}")
        );
    }

    #[test]
    fn panel_restart_is_deduplicated_across_workers() {
        let first = Events::new(false);
        let second = first.clone();
        assert!(!first.panel_restart_emitted.load(Ordering::Acquire));
        first.panel_restart();
        assert!(second.panel_restart_emitted.load(Ordering::Acquire));
        second.panel_restart();
        assert!(first.panel_restart_emitted.load(Ordering::Acquire));
    }

    #[test]
    fn network_suspect_requires_a_timeout_burst_and_resets_after_recovery() {
        let events = Events::new(false);
        for _ in 0..5 {
            events.network_timeout();
        }
        assert!(!events.network_suspect_emitted.load(Ordering::Acquire));
        events.network_timeout();
        assert!(events.network_suspect_emitted.load(Ordering::Acquire));
        events.network_recovered();
        assert_eq!(events.network_timeouts.load(Ordering::Acquire), 0);
        assert!(!events.network_suspect_emitted.load(Ordering::Acquire));
    }

    #[test]
    fn sparse_turn_timeouts_do_not_become_a_network_outage() {
        let events = Events::new(false);
        events.network_timeout();
        {
            let mut window = events
                .network_timeout_window_started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *window =
                Some(Instant::now() - NETWORK_TIMEOUT_BURST_WINDOW - Duration::from_millis(1));
        }
        for _ in 0..5 {
            events.network_timeout();
        }
        assert_eq!(events.network_timeouts.load(Ordering::Acquire), 5);
        assert!(!events.network_suspect_emitted.load(Ordering::Acquire));
    }

    #[test]
    fn call_unavailable_is_deduplicated_per_hash() {
        let events = Events::new(false);
        events.call_unavailable("dead-call", 951);
        events.call_unavailable("dead-call", 951);
        events.call_unavailable("other-call", 951);
        let hashes = events.unavailable_hashes.lock().unwrap();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains("dead-call"));
        assert!(hashes.contains("other-call"));
    }
}
