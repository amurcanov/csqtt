// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::Result;
use std::{future::Future, time::Duration};
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPolicy {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub reset_after: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            reset_after: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UdpFailure {
    Returned,
    Error(String),
    Panic,
    Cancelled,
}

impl std::fmt::Display for UdpFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Returned => formatter.write_str("listener returned unexpectedly"),
            Self::Error(error) => write!(formatter, "listener error: {error}"),
            Self::Panic => formatter.write_str("listener task panicked"),
            Self::Cancelled => formatter.write_str("listener task was cancelled"),
        }
    }
}

fn classify_join(result: std::result::Result<Result<()>, JoinError>) -> UdpFailure {
    match result {
        Ok(Ok(())) => UdpFailure::Returned,
        Ok(Err(error)) => UdpFailure::Error(format!("{error:#}")),
        Err(error) if error.is_panic() => UdpFailure::Panic,
        Err(_) => UdpFailure::Cancelled,
    }
}

fn bounded_delay(policy: RestartPolicy, delay: Duration) -> Duration {
    let minimum = Duration::from_millis(1);
    delay.max(minimum).min(policy.max_delay.max(minimum))
}

fn next_delay(policy: RestartPolicy, delay: Duration) -> Duration {
    bounded_delay(policy, delay.saturating_mul(2))
}

pub async fn supervise<R, F, O>(
    shutdown: CancellationToken,
    policy: RestartPolicy,
    mut runner: R,
    mut on_failure: O,
) where
    R: FnMut() -> F,
    F: Future<Output = Result<()>> + Send + 'static,
    O: FnMut(UdpFailure, Duration),
{
    let initial_delay = bounded_delay(policy, policy.initial_delay);
    let mut delay = initial_delay;

    loop {
        if shutdown.is_cancelled() {
            return;
        }

        let started = tokio::time::Instant::now();
        let mut attempt = tokio::spawn(runner());
        let result = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                attempt.abort();
                let _ = attempt.await;
                return;
            }
            result = &mut attempt => result,
        };

        if shutdown.is_cancelled() {
            return;
        }

        if started.elapsed() >= policy.reset_after {
            delay = initial_delay;
        }

        let failure = classify_join(result);
        on_failure(failure, delay);

        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }

        delay = next_delay(policy, delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::sync::mpsc;

    fn test_policy() -> RestartPolicy {
        RestartPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(40),
            reset_after: Duration::from_millis(100),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn error_backoff_is_exponential_and_capped() {
        let shutdown = CancellationToken::new();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let supervisor = tokio::spawn(supervise(
            shutdown.clone(),
            test_policy(),
            || async { Err(anyhow!("injected recv failure")) },
            move |failure, delay| {
                sender.send((failure, delay)).unwrap();
            },
        ));

        let expected = [10, 20, 40, 40, 40];
        for milliseconds in expected {
            let (failure, delay) = receiver.recv().await.unwrap();
            assert_eq!(
                failure,
                UdpFailure::Error("injected recv failure".to_owned())
            );
            assert_eq!(delay, Duration::from_millis(milliseconds));
            tokio::time::advance(delay).await;
        }

        shutdown.cancel();
        supervisor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn panic_is_contained_and_next_attempt_runs() {
        let shutdown = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = attempts.clone();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let supervisor = tokio::spawn(supervise(
            shutdown.clone(),
            test_policy(),
            move || {
                let attempt = runner_attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        panic!("injected UDP panic");
                    }
                    pending::<Result<()>>().await
                }
            },
            move |failure, delay| {
                sender.send((failure, delay)).unwrap();
            },
        ));

        let (failure, delay) = receiver.recv().await.unwrap();
        assert_eq!(failure, UdpFailure::Panic);
        assert_eq!(delay, Duration::from_millis(10));
        tokio::time::advance(delay).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        shutdown.cancel();
        supervisor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stable_attempt_resets_accumulated_backoff() {
        let shutdown = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = attempts.clone();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let supervisor = tokio::spawn(supervise(
            shutdown.clone(),
            test_policy(),
            move || {
                let attempt = runner_attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    match attempt {
                        0 => Err(anyhow!("short failure")),
                        1 => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            Err(anyhow!("failure after stable interval"))
                        }
                        _ => pending::<Result<()>>().await,
                    }
                }
            },
            move |failure, delay| {
                sender.send((failure, delay)).unwrap();
            },
        ));

        let (_, first_delay) = receiver.recv().await.unwrap();
        assert_eq!(first_delay, Duration::from_millis(10));
        tokio::time::advance(first_delay).await;
        tokio::time::advance(Duration::from_millis(100)).await;
        let (failure, recovered_delay) = receiver.recv().await.unwrap();
        assert_eq!(
            failure,
            UdpFailure::Error("failure after stable interval".to_owned())
        );
        assert_eq!(recovered_delay, Duration::from_millis(10));
        tokio::time::advance(recovered_delay).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        shutdown.cancel();
        supervisor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_aborts_hung_runner() {
        struct DropProbe(Arc<AtomicBool>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let shutdown = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = attempts.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let runner_dropped = dropped.clone();
        let supervisor = tokio::spawn(supervise(
            shutdown.clone(),
            test_policy(),
            move || {
                runner_attempts.fetch_add(1, Ordering::SeqCst);
                let probe = DropProbe(runner_dropped.clone());
                async move {
                    let _probe = probe;
                    pending::<Result<()>>().await
                }
            },
            |_, _| {},
        ));

        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        shutdown.cancel();
        supervisor.await.unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_during_backoff_prevents_restart() {
        let shutdown = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = attempts.clone();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let supervisor = tokio::spawn(supervise(
            shutdown.clone(),
            test_policy(),
            move || {
                runner_attempts.fetch_add(1, Ordering::SeqCst);
                async { Err(anyhow!("injected failure")) }
            },
            move |failure, delay| {
                sender.send((failure, delay)).unwrap();
            },
        ));

        let _ = receiver.recv().await.unwrap();
        shutdown.cancel();
        supervisor.await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn successful_return_is_treated_as_restartable_failure() {
        let shutdown = CancellationToken::new();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let supervisor = tokio::spawn(supervise(
            shutdown.clone(),
            test_policy(),
            || async { Ok(()) },
            move |failure, delay| {
                sender.send((failure, delay)).unwrap();
            },
        ));

        let (failure, delay) = receiver.recv().await.unwrap();
        assert_eq!(failure, UdpFailure::Returned);
        assert_eq!(delay, Duration::from_millis(10));
        shutdown.cancel();
        supervisor.await.unwrap();
    }

    #[test]
    fn invalid_initial_delay_is_bounded_by_cap() {
        let policy = RestartPolicy {
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_millis(40),
            reset_after: Duration::from_secs(1),
        };
        assert_eq!(
            bounded_delay(policy, policy.initial_delay),
            Duration::from_millis(40)
        );
        assert_eq!(
            next_delay(policy, Duration::from_millis(40)),
            Duration::from_millis(40)
        );
    }

    #[test]
    fn zero_policy_cannot_create_a_hot_loop() {
        let policy = RestartPolicy {
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            reset_after: Duration::ZERO,
        };
        assert_eq!(
            bounded_delay(policy, policy.initial_delay),
            Duration::from_millis(1)
        );
        assert_eq!(next_delay(policy, Duration::ZERO), Duration::from_millis(1));
    }
}
