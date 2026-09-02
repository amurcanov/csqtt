// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![allow(linker_messages)]

mod auth;
mod captcha;
mod captcha_slider;
mod client_perf;
mod cpu_task;
mod dispatcher;
mod dns;
mod events;
#[path = "../shared/flow_frame.rs"]
mod flow_frame;
mod logging;
mod namegen;
mod obfs;
mod packet;
mod profiles;
mod protocol;
mod repair;
#[path = "../shared/selective_fec.rs"]
mod selective_fec;
mod session;
mod stats;
#[path = "../shared/striped_scheduler.rs"]
mod striped_scheduler;
mod stun_codec;
mod tun;
mod turn;
mod turn_core;
mod turn_endpoint;
mod turn_stream;
mod udp_batch;
mod vk_js_calls;
#[path = "../shared/wire_protocol.rs"]
mod wire_protocol;
mod worker;
mod wrap;

use anyhow::{Context, Result, bail};
use auth::{VkAuth, VkHashCheck};
use base64::{Engine, engine::general_purpose::STANDARD};
use captcha::CaptchaSolver;
use clap::Parser;
use dispatcher::Dispatcher;
use events::Events;
use obfs::ObfsMode;
use packet::{PacketPool, packet_pool_size};
use repair::RepairState;
use session::ShutdownCoordinator;
use stats::Stats;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;
use turn_endpoint::TurnTransportMode;
use worker::{
    GROUPS_PER_CREDENTIAL, GroupContext, PauseGate, RuntimeParams, WORKER_START_INTERVAL,
    WORKERS_PER_GROUP, WorkerStartPacer, parse_hashes, run_groups,
};

const GROUPS_PER_VK_HASH: usize = 3;
const MAX_VK_HASHES: usize = 6;
const MAX_WORKERS: usize = 126;
const STREAMS_PER_RUNTIME_WORKER: usize = 12;
const MAX_RUNTIME_WORKER_THREADS: usize = 4;
use wrap::derive_wrap_key;

#[derive(Parser)]
#[command(disable_help_flag = true)]
struct Arguments {
    #[arg(long, default_value = "")]
    turn: String,
    #[arg(long, default_value = "")]
    port: String,
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: String,
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    vk: String,
    #[arg(long, default_value = "manual")]
    vk_hash_mode: String,
    #[arg(long, default_value = "")]
    peer: String,
    #[arg(short = 'n', long, default_value_t = 18)]
    workers: usize,
    #[arg(long, default_value_t = false)]
    allow_hash_redistribution: bool,
    #[arg(long, default_value = "unknown")]
    device_id: String,
    #[arg(long, default_value = "")]
    password: String,
    #[arg(long, default_value = "vkcalls")]
    vk_auth_mode: String,
    #[arg(long, default_value = "auto")]
    captcha_mode: String,
    #[arg(long, default_value = "chrome")]
    fingerprint: String,
    #[arg(long, default_value = "")]
    client_ids: String,
    #[arg(long, default_value = "audio")]
    obfs: String,
    #[arg(long, default_value = "udp")]
    turn_transport: String,
    #[arg(long = "gen", default_value_t = 0)]
    generation: u64,
    #[arg(long, default_value = "")]
    salt: String,
    #[arg(long, default_value = "")]
    tun_uds: String,
    #[arg(long, default_value_t = false)]
    validate_vk_hashes: bool,
}

fn main() {
    std::panic::set_hook(Box::new(|_| {
        #[cfg(unix)]
        unsafe {
            const MESSAGE: &[u8] = b"[PANIC] Rust client task failed\n";
            let _ = libc::write(libc::STDERR_FILENO, MESSAGE.as_ptr().cast(), MESSAGE.len());
        }
    }));
    let arguments = Arguments::parse_from(normalized_arguments());
    let runtime = match build_runtime(runtime_worker_threads(arguments.workers)) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("[ФАТАЛ] {error:#}");
            std::process::exit(1);
        }
    };
    let failure = runtime.block_on(async {
        match tokio::spawn(run(arguments)).await {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(format!("{error:#}")),
            Err(error) => Some(format!("паника верхнего уровня изолирована: {error}")),
        }
    });
    if let Some(failure) = failure {
        crate::log_error!("[ФАТАЛ] {failure}");
        let _ = logging::shutdown(Duration::from_secs(1));
        std::process::exit(1);
    }
}

fn build_runtime(default_worker_threads: usize) -> Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(default_worker_threads);
    builder
        .enable_all()
        .build()
        .context("создание Tokio runtime")
}

fn runtime_worker_threads(requested_workers: usize) -> usize {
    normalize_worker_count(requested_workers)
        .div_ceil(STREAMS_PER_RUNTIME_WORKER)
        .clamp(1, MAX_RUNTIME_WORKER_THREADS)
}

async fn run(arguments: Arguments) -> Result<()> {
    if arguments.validate_vk_hashes {
        return run_vk_hash_validation(&arguments).await;
    }
    let js_hash_mode = arguments.vk_hash_mode == "auto_js";
    let js_auth_mode = arguments.vk_auth_mode == "auto_js";
    if js_auth_mode && !js_hash_mode {
        bail!("[КЛИЕНТ] Режим авторизации Auto JS требует режим хешей Auto JS");
    }
    if arguments.peer.is_empty() || (!js_hash_mode && arguments.vk.is_empty()) {
        bail!("[КЛИЕНТ] Нужны -peer и хеши VK");
    }
    if arguments.password.is_empty() {
        bail!("[КЛИЕНТ] Нужен -password: WRAP ключ выводится из пароля подключения");
    }
    let peer = resolve_peer(&arguments.peer).await?;
    let mode = ObfsMode::parse(&arguments.obfs)?;
    let turn_transport = TurnTransportMode::parse(&arguments.turn_transport)?;
    let wrap_key = derive_wrap_key(&arguments.password)?;
    let session_profile = profiles::random_profile(&arguments.fingerprint);
    let mut js_calls = None;
    let mut js_credential_broker = None;
    let hash_source = if js_hash_mode {
        let bootstrap = read_vk_js_bootstrap().await?;
        let started = vk_js_calls::start(
            bootstrap,
            &arguments.device_id,
            js_auth_mode,
            &session_profile,
        )
        .await?;
        let hashes = started.hashes.join(",");
        js_calls = Some(started.active);
        js_credential_broker = Some(started.credential_broker);
        hashes
    } else {
        arguments.vk.clone()
    };
    let hashes: Vec<_> = parse_hashes(&hash_source)
        .into_iter()
        .take(MAX_VK_HASHES)
        .collect();
    if hashes.is_empty() {
        bail!("[КЛИЕНТ] Нет хешей VK");
    }
    let workers = normalize_worker_count_for_hashes(
        arguments.workers,
        hashes.len(),
        arguments.allow_hash_redistribution || js_hash_mode,
    );
    let groups = workers / WORKERS_PER_GROUP;
    let cancel = CancellationToken::new();
    let captcha = CaptchaSolver::new(&arguments.captcha_mode, cancel.clone());
    let events = Events::from_env();
    let client_ids: Vec<_> = arguments
        .client_ids
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let auth = Arc::new(VkAuth::new(
        &arguments.vk_auth_mode,
        session_profile,
        &client_ids,
        captcha.clone(),
        js_credential_broker,
    ));
    let stats = Arc::new(Stats::default());
    let paused = Arc::new(PauseGate::new());
    let finish_js_calls = Arc::new(AtomicBool::new(false));
    let control_task = start_control_input(
        cancel.clone(),
        paused.clone(),
        captcha,
        events.clone(),
        finish_js_calls.clone(),
    );
    let parent_task = start_parent_monitor(cancel.clone());
    events.process(std::process::id());
    let pool = PacketPool::new(packet_pool_size(workers));
    let tun_uds = (!arguments.tun_uds.is_empty()).then_some(arguments.tun_uds.clone());
    let dispatcher_result = Dispatcher::start(
        &arguments.listen,
        tun_uds,
        pool.clone(),
        stats.clone(),
        cancel.clone(),
    )
    .await;
    let (dispatcher, local_port) = match dispatcher_result {
        Ok(value) => value,
        Err(error) => {
            if let Some(active) = js_calls.take() {
                active.leave_creator().await;
            }
            return Err(error);
        }
    };
    let local_port: Arc<str> = Arc::from(local_port);
    let params = Arc::new(RuntimeParams {
        peer,
        turn_host: (!arguments.turn.is_empty()).then(|| Arc::from(arguments.turn.as_str())),
        turn_port: (!arguments.port.is_empty()).then(|| Arc::from(arguments.port.as_str())),
        turn_transport,
        hashes: hashes.into(),
        wrap_key,
        mode,
        generation: arguments.generation,
        salt: Arc::from(arguments.salt.as_str()),
        local_port: local_port.clone(),
        device_id: Arc::from(arguments.device_id.as_str()),
        password: Arc::from(arguments.password.as_str()),
        workers,
    });
    print_configuration(
        &arguments,
        auth.client_ids(),
        workers,
        groups,
        params.hashes.len(),
        &local_port,
        params.turn_transport,
    );
    let repair = RepairState::new(workers);
    let stats_task = tokio::spawn(stats.clone().run(events.clone(), cancel.clone()));
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel::<String>(32);
    let config_events = events.clone();
    let config_task = tokio::spawn(async move {
        let mut last_config = None;
        while let Some(config) = config_rx.recv().await {
            if last_config.as_deref() == Some(config.as_str()) {
                continue;
            }
            if let Some(value) = config.strip_prefix("TUNCONF:") {
                dns::mark_tunnel_active();
                let mut fields = value.splitn(3, ':');
                let ip = fields.next().unwrap_or_default();
                let dns = fields.next().unwrap_or_default();
                crate::log_error!("[КЛИЕНТ] Tunnel IP: {ip}/32 | DNS: {dns}");
            }
            config_events.config(&config);
            last_config = Some(config);
        }
    });
    let (ready_credential_tx, ready_credential_rx) =
        if should_leave_js_creator(js_hash_mode, js_auth_mode) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
    let context = Arc::new(GroupContext {
        params,
        auth,
        dispatcher: dispatcher.clone(),
        pool,
        stats,
        events: events.clone(),
        paused,
        config_tx,
        start_pacer: Arc::new(WorkerStartPacer::new(WORKER_START_INTERVAL)),
        credential_pacer: Arc::new(tokio::sync::Mutex::new(())),
        ready_credential_tx,
        config_sent: Arc::new(AtomicBool::new(false)),
        config_in_flight: Arc::new(AtomicBool::new(false)),
        server_stream_repair: Arc::new(AtomicBool::new(false)),
        repair,
        shutdown: Arc::new(ShutdownCoordinator::new()),
        cancel: cancel.clone(),
    });
    let required_ready_bots = required_js_ready_bots(groups);
    if js_auth_mode {
        crate::log_error!("[VK JS] Создатель удерживает звонок");
    }
    let creator_leave_task = match (js_calls.as_ref(), ready_credential_rx) {
        (Some(active), Some(receiver)) => Some(tokio::spawn(leave_js_creator_after_ready_workers(
            active.clone(),
            receiver,
            required_ready_bots,
            cancel.clone(),
        ))),
        _ => None,
    };
    let shutdown_events = events.clone();
    let groups_future = run_groups(groups, context);
    tokio::pin!(groups_future);
    let groups_completed = tokio::select! {
        _ = &mut groups_future => true,
        _ = tokio::signal::ctrl_c() => {
            crate::log_error!("[КЛИЕНТ] Получен сигнал завершения");
            cancel.cancel();
            false
        }
        _ = cancel.cancelled() => false,
    };
    cancel.cancel();
    if !groups_completed {
        groups_future.await;
    }
    dispatcher.shutdown().await;
    stats_task.abort();
    config_task.abort();
    control_task.abort();
    parent_task.abort();
    let _ = stats_task.await;
    let _ = config_task.await;
    let _ = control_task.await;
    let _ = parent_task.await;
    if let Some(mut task) = creator_leave_task
        && tokio::time::timeout(Duration::from_secs(9), &mut task)
            .await
            .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    if let Some(active) = js_calls.take() {
        if finish_js_calls.load(Ordering::Acquire) {
            active.finish().await;
        } else {
            active.leave_creator().await;
        }
    }
    shutdown_events.stopped();
    crate::log_error!("[КЛИЕНТ] Все воркеры завершены");
    let _ = logging::shutdown(Duration::from_secs(1));
    Ok(())
}

async fn leave_js_creator_after_ready_workers(
    active: vk_js_calls::ActiveCalls,
    receiver: tokio::sync::mpsc::UnboundedReceiver<usize>,
    required_ready_bots: usize,
    cancel: CancellationToken,
) {
    let all_ready = wait_for_js_credential_readiness(receiver, required_ready_bots, cancel).await;
    if all_ready {
        crate::log_error!("[VK JS] TURN-боты готовы, создатель выходит из звонка");
    }
    let _ = tokio::time::timeout(Duration::from_secs(8), active.leave_creator()).await;
}

async fn wait_for_js_credential_readiness(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<usize>,
    expected_credentials: usize,
    cancel: CancellationToken,
) -> bool {
    let mut ready = HashSet::with_capacity(expected_credentials);
    while ready.len() < expected_credentials {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            credential = receiver.recv() => match credential {
                Some(credential) => {
                    ready.insert(credential);
                }
                None => break,
            },
        }
    }
    ready.len() == expected_credentials
}

fn required_js_ready_bots(groups: usize) -> usize {
    groups.div_ceil(GROUPS_PER_CREDENTIAL).clamp(1, 2)
}

fn normalize_worker_count(requested: usize) -> usize {
    requested.clamp(WORKERS_PER_GROUP, MAX_WORKERS) / WORKERS_PER_GROUP * WORKERS_PER_GROUP
}

fn normalize_worker_count_for_hashes(
    requested: usize,
    hash_count: usize,
    allow_hash_redistribution: bool,
) -> usize {
    if allow_hash_redistribution {
        return normalize_worker_count(requested);
    }
    let maximum = hash_count.clamp(1, MAX_VK_HASHES) * GROUPS_PER_VK_HASH * WORKERS_PER_GROUP;
    normalize_worker_count(requested).min(maximum)
}

fn should_leave_js_creator(_js_hash_mode: bool, _js_auth_mode: bool) -> bool {
    false
}

fn normalized_arguments() -> Vec<String> {
    std::env::args().map(normalize_cli_argument).collect()
}

fn normalize_cli_argument(argument: String) -> String {
    const FLAGS: &[&str] = &[
        "turn",
        "port",
        "listen",
        "vk",
        "vk-hash-mode",
        "peer",
        "device-id",
        "password",
        "vk-auth-mode",
        "captcha-mode",
        "fingerprint",
        "client-ids",
        "obfs",
        "turn-transport",
        "gen",
        "salt",
        "tun-uds",
        "allow-hash-redistribution",
        "validate-vk-hashes",
    ];
    if let Some(value) = argument.strip_prefix('-') {
        let name = value.split('=').next().unwrap_or(value);
        if !value.starts_with('-') && FLAGS.contains(&name) {
            return format!("-{argument}");
        }
    }
    argument
}

async fn read_vk_js_bootstrap() -> Result<vk_js_calls::Bootstrap> {
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(15),
        BufReader::new(tokio::io::stdin()).read_line(&mut line),
    )
    .await
    .context("тайм-аут передачи данных Auto JS")?
    .context("чтение данных Auto JS")?;
    let encoded = line
        .trim()
        .strip_prefix("VK_JS_BOOTSTRAP:")
        .context("неверный формат данных Auto JS")?;
    if encoded.len() > 32 * 1024 {
        bail!("слишком большие данные Auto JS");
    }
    let decoded = STANDARD
        .decode(encoded)
        .context("повреждены данные Auto JS")?;
    let bootstrap: vk_js_calls::Bootstrap =
        serde_json::from_slice(&decoded).context("некорректные данные Auto JS")?;
    Ok(bootstrap)
}

async fn run_vk_hash_validation(arguments: &Arguments) -> Result<()> {
    let hashes: Vec<_> = parse_hashes(&arguments.vk)
        .into_iter()
        .take(MAX_VK_HASHES)
        .collect();
    if hashes.is_empty() {
        bail!("[КЛИЕНТ] Нет хешей VK для проверки");
    }
    let client_ids: Vec<_> = arguments
        .client_ids
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    for (hash, result) in auth::check_vk_hashes(&arguments.fingerprint, &client_ids, &hashes).await
    {
        let payload = match result {
            VkHashCheck::Valid => serde_json::json!({
                "hash": hash,
                "status": "valid"
            }),
            VkHashCheck::Invalid { code, message } => serde_json::json!({
                "hash": hash,
                "status": "invalid",
                "code": code,
                "message": message
            }),
            VkHashCheck::Unavailable { message } => serde_json::json!({
                "hash": hash,
                "status": "unavailable",
                "message": message
            }),
        };
        println!("HASH_CHECK:{payload}");
    }
    Ok(())
}

async fn resolve_peer(peer: &str) -> Result<SocketAddr> {
    let mut last_error = None;
    for _ in 0..15 {
        match dns::resolve_socket(peer).await {
            Ok(address) => return Ok(address),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("пустой DNS-ответ для пира")))
        .context("ошибка разбора пира")
}

fn start_control_input(
    cancel: CancellationToken,
    paused: Arc<PauseGate>,
    captcha: Arc<CaptchaSolver>,
    events: Events,
    finish_js_calls: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let control_required = events.enabled();
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        loop {
            let line = tokio::select! {
                _ = cancel.cancelled() => return,
                result = lines.next_line() => match result {
                    Ok(Some(line)) => line,
                    Ok(None) => {
                        if control_required {
                            crate::log_error!("[КЛИЕНТ] Канал управления закрыт");
                            cancel.cancel();
                        }
                        return;
                    }
                    Err(error) => {
                        crate::log_error!("[КЛИЕНТ] Ошибка канала управления: {error}");
                        if control_required {
                            cancel.cancel();
                        }
                        return;
                    }
                },
            };
            let line = line.trim();
            client_perf::observe(client_perf::Stage::ControlStdin);
            if !line.contains("error:tunnel stopped") && line != "FINISH_VK_CALLS" {
                crate::log_error!("[STDIN] {line}");
            }
            match line {
                "PAUSE" => paused.set_paused(true),
                "RESUME" => paused.set_paused(false),
                "FINISH_VK_CALLS" => finish_js_calls.store(true, Ordering::Release),
                "STOP" => {
                    crate::log_error!("[КЛИЕНТ] Получена команда STOP");
                    cancel.cancel();
                    return;
                }
                _ => {
                    if let Some(result) = line.strip_prefix("CAPTCHA_RESULT|") {
                        if captcha.submit_result(result.to_owned()) {
                            crate::log_error!("[КАПЧА] Результат от Kotlin записан в канал");
                        } else {
                            crate::log_error!(
                                "[КАПЧА] Канал результата уже заполнен, устаревший ответ отклонён"
                            );
                        }
                    }
                }
            }
        }
    })
}

fn start_parent_monitor(cancel: CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let parent = unsafe { libc::getppid() };
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
                if unsafe { libc::getppid() } != parent {
                    cancel.cancel();
                    return;
                }
            }
        }
        #[cfg(not(unix))]
        cancel.cancelled().await;
    })
}

fn print_configuration(
    arguments: &Arguments,
    client_ids: String,
    workers: usize,
    groups: usize,
    hashes: usize,
    local_port: &str,
    turn_transport: TurnTransportMode,
) {
    let captcha = match arguments.captcha_mode.as_str() {
        "wv" => "WBV selected in Android",
        "rjs" => "RJS Rust v2 with WBV Auto fallback",
        _ => "AUTO: Rust v2 x2 -> WBV Auto x2 -> Rust v2 x1 -> Manual WBV",
    };
    crate::log_error!("[КЛИЕНТ] ═══════════════════════════════════════");
    crate::log_error!("[КЛИЕНТ] VK Creds: Client IDs: {client_ids}");
    crate::log_error!("[КЛИЕНТ] VK Auth: {}", arguments.vk_auth_mode);
    crate::log_error!("[КЛИЕНТ] TLS: {} fingerprint", arguments.fingerprint);
    crate::log_error!("[КЛИЕНТ] Воркеров: {workers} (групп: {groups}, по {WORKERS_PER_GROUP})");
    crate::log_error!("[КЛИЕНТ] Хешей: {hashes}");
    crate::log_error!(
        "[КЛИЕНТ] Слушаю: {} (порт {local_port}) | Пир: {}",
        arguments.listen,
        arguments.peer
    );
    crate::log_error!(
        "[КЛИЕНТ] TURN: {} | WRAP: ON | obfs={}",
        turn_transport.as_str(),
        arguments.obfs,
    );
    crate::log_error!("[WRAP] WRAP Ключ вычислен ✓");
    crate::log_error!("[КЛИЕНТ] Device ID: {}", arguments.device_id);
    crate::log_error!("[КЛИЕНТ] Captcha: {captcha}");
    crate::log_error!("[КЛИЕНТ] ═══════════════════════════════════════");
}

#[cfg(test)]
mod worker_count_tests {
    use super::*;

    #[test]
    fn every_supported_total_maps_to_complete_nine_allocation_groups() {
        for groups in 1..=MAX_WORKERS / WORKERS_PER_GROUP {
            let workers = groups * WORKERS_PER_GROUP;
            assert_eq!(normalize_worker_count(workers), workers);
            assert_eq!(workers / WORKERS_PER_GROUP, groups);
        }
        assert_eq!(normalize_worker_count(MAX_WORKERS), 126);
    }

    #[test]
    fn invalid_totals_never_create_partial_or_excess_group() {
        for requested in 0..=1_000 {
            let workers = normalize_worker_count(requested);
            assert!((WORKERS_PER_GROUP..=MAX_WORKERS).contains(&workers));
            assert_eq!(workers % WORKERS_PER_GROUP, 0);
        }
    }

    #[test]
    fn runtime_thread_budget_follows_stream_budget() {
        assert_eq!(runtime_worker_threads(9), 1);
        assert_eq!(runtime_worker_threads(18), 2);
        assert_eq!(runtime_worker_threads(27), 3);
        assert_eq!(runtime_worker_threads(36), 3);
        assert_eq!(runtime_worker_threads(45), 4);
        assert_eq!(runtime_worker_threads(54), 4);
        assert_eq!(runtime_worker_threads(126), 4);
    }

    #[test]
    fn hash_count_caps_native_worker_admission_to_twenty_seven_each() {
        assert_eq!(normalize_worker_count_for_hashes(usize::MAX, 1, false), 27);
        assert_eq!(normalize_worker_count_for_hashes(usize::MAX, 4, false), 108);
        assert_eq!(normalize_worker_count_for_hashes(usize::MAX, 5, false), 126);
        assert_eq!(normalize_worker_count_for_hashes(usize::MAX, 6, false), 126);
        assert_eq!(
            normalize_worker_count_for_hashes(usize::MAX, 100, false),
            126
        );
    }

    #[test]
    fn automatic_call_failure_may_redistribute_complete_groups() {
        assert_eq!(normalize_worker_count_for_hashes(162, 5, true), 126);
        assert_eq!(normalize_worker_count_for_hashes(54, 1, true), 54);
        assert_eq!(normalize_worker_count_for_hashes(50, 1, true), 45);
    }

    #[test]
    fn auto_js_account_auth_supports_nine_credentials_in_one_call() {
        assert_eq!(normalize_worker_count_for_hashes(162, 1, true), 126);
        assert!(
            MAX_WORKERS.div_ceil(worker::WORKERS_PER_CREDENTIAL)
                <= vk_js_calls::MAX_ACCOUNT_CREDENTIALS
        );
    }

    #[test]
    fn auto_js_always_keeps_creator_while_running() {
        assert!(!should_leave_js_creator(true, false));
        assert!(!should_leave_js_creator(true, true));
        assert!(!should_leave_js_creator(false, false));
        assert!(!should_leave_js_creator(false, true));
    }

    #[test]
    fn auto_js_waits_for_at_most_two_independent_turn_bots() {
        assert_eq!(required_js_ready_bots(1), 1);
        assert_eq!(required_js_ready_bots(2), 1);
        assert_eq!(required_js_ready_bots(3), 2);
        assert_eq!(required_js_ready_bots(13), 2);
    }

    #[test]
    fn vk_hash_may_start_with_a_hyphen() {
        let arguments = Arguments::try_parse_from([
            "csqtt-client",
            "--vk",
            "-Wabc",
            "--peer",
            "127.0.0.1:9000",
            "--password",
            "secret",
        ])
        .unwrap();
        assert_eq!(arguments.vk, "-Wabc");
    }

    #[test]
    fn android_single_dash_flags_do_not_rewrite_hyphenated_hash_values() {
        assert_eq!(normalize_cli_argument("-vk".to_owned()), "--vk");
        assert_eq!(normalize_cli_argument("-Wabc".to_owned()), "-Wabc");
        assert_eq!(
            normalize_cli_argument("-allow-hash-redistribution".to_owned()),
            "--allow-hash-redistribution"
        );
    }

    #[test]
    fn hyphenated_hash_and_redistribution_flag_parse_together() {
        let arguments = Arguments::try_parse_from([
            "csqtt-client",
            "--vk",
            "-Wabc,-Wdef",
            "--peer",
            "127.0.0.1:9000",
            "--password",
            "secret",
            "--allow-hash-redistribution",
        ])
        .unwrap();
        assert_eq!(arguments.vk, "-Wabc,-Wdef");
        assert!(arguments.allow_hash_redistribution);
    }

    #[tokio::test]
    async fn js_creator_waits_for_every_distinct_ready_credential() {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        sender.send(1).unwrap();
        sender.send(1).unwrap();
        sender.send(2).unwrap();
        assert!(wait_for_js_credential_readiness(receiver, 2, CancellationToken::new()).await);
    }

    #[tokio::test]
    async fn js_creator_wait_is_cancel_safe() {
        let (_sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(!wait_for_js_credential_readiness(receiver, 1, cancel).await);
    }
}
