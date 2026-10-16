// SPDX-License-Identifier: AGPL-3.0-only
//! Load generator for the node performance budgets (`just perf-node`, see perf/README.md).
//!
//! Starts a release `tavrn-node` with its own PostgreSQL database (or targets `--url`), registers
//! N users with TOTP, creates a room with a plaintext and an encrypted channel, connects N
//! WebSockets and runs the scenarios: idle node, idle connections, 20 msg/s plaintext and
//! encrypted (real MLS clients, a self-update commit every 100 messages) with message lists
//! alongside, login, and a ramp to 1000 connections. The node's CPU time and RSS are sampled from
//! `/proc`; the CPU under load is also given on the reference machine (`machine.rs`). Results go to a
//! JSON file that `perf/report.ts` classifies against `perf/budgets.json`.

mod api;
mod disk;
mod guard;
mod machine;
mod mls;
mod node;
mod procstat;
mod stats;
mod ws;

use std::{
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use futures::{StreamExt, stream};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::{
    api::{Api, User, client_ip},
    mls::{CommitLog, Member, SharedMember, commit_body, with_member},
    procstat::{Sampler, Usage},
    stats::{Samples, lock, round1},
    ws::{Observer, WsStats},
};

#[derive(Parser, Debug, Clone)]
#[command(name = "tavrn-loadgen", about = "tavrn node load generator")]
struct Args {
    /// Target an already running node instead of starting one (then pass --pid for CPU/RSS).
    #[arg(long)]
    url: Option<String>,
    /// Process id of the node given with --url.
    #[arg(long)]
    pid: Option<u32>,
    /// Node binary to start (release build).
    #[arg(long, default_value = "target/release/tavrn-node")]
    node_bin: PathBuf,
    /// PostgreSQL server for the throwaway database perf_<ulid> (only the host part is used).
    #[arg(long, env = "TAVRN_TEST_DATABASE_URL", default_value = "postgres://tavrn:tavrn@localhost:55432/tavrn_test")]
    database_url: String,
    /// Data directory of the started node (a fresh subdirectory per run, removed afterwards).
    #[arg(long, default_value = "data-dev/perf-node")]
    data_dir: PathBuf,
    /// Simulated users, each with one WebSocket and one MLS device.
    #[arg(long, default_value_t = 200)]
    clients: usize,
    /// Total WebSocket connections at the end of the ramp.
    #[arg(long, default_value_t = 1000)]
    ramp_to: usize,
    /// Messages per second over all users.
    #[arg(long, default_value_t = 20)]
    rate: u32,
    /// Message list requests per second during the load scenarios.
    #[arg(long, default_value_t = 5)]
    list_rate: u32,
    /// Seconds for the idle node baseline (before any user exists).
    #[arg(long, default_value_t = 10)]
    baseline_secs: u64,
    /// Seconds for the idle-connections scenario.
    #[arg(long, default_value_t = 30)]
    idle_secs: u64,
    /// Seconds for each load scenario.
    #[arg(long, default_value_t = 60)]
    load_secs: u64,
    /// A member commits a self-update every this many encrypted messages.
    #[arg(long, default_value_t = 100)]
    commit_every: u64,
    /// Seconds to hold the connections after the ramp.
    #[arg(long, default_value_t = 10)]
    ramp_hold_secs: u64,
    /// Result file.
    #[arg(long, default_value = "perf/results/raw/node.json")]
    out: PathBuf,
}

#[derive(Serialize)]
struct Metric {
    id: String,
    label: String,
    value: Option<f64>,
    unit: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    baseline: bool,
    details: Value,
}

#[derive(Default)]
struct Report {
    metrics: Vec<Metric>,
    info: serde_json::Map<String, Value>,
}

impl Report {
    fn add(&mut self, id: &str, label: &str, value: Option<f64>, unit: &'static str, details: Value) {
        eprintln!("  {id} = {} {unit}", value.map_or("n/a".into(), |v| v.to_string()));
        self.metrics.push(Metric { id: id.into(), label: label.into(), value, unit, baseline: false, details });
    }

    /// p50/p95/p99 of an operation: the p95 as a metric (the budgeted one), the summary as details.
    fn latency(&mut self, id: &str, label: &str, s: &Samples) {
        self.add(id, label, s.percentile(95.0).map(round1), "ms", s.summary());
    }

    /// Value of a metric reported so far.
    fn value(&self, id: &str) -> Option<f64> {
        self.metrics.iter().find(|m| m.id == id).and_then(|m| m.value)
    }

    fn append(&mut self, other: Report) {
        self.metrics.extend(other.metrics);
        self.info.extend(other.info);
    }

    fn usage(&mut self, prefix: &str, label: &str, u: Option<Usage>, rss: bool) {
        let details = u.map_or(Value::Null, |u| json!(u));
        self.add(&format!("{prefix}_cpu_pct"), &format!("{label}: CPU"), u.map(|u| u.cpu_pct), "%", details.clone());
        if rss {
            self.add(
                &format!("{prefix}_rss_mb"),
                &format!("{label}: RSS (max)"),
                u.map(|u| u.rss_max_mb),
                "MB",
                details,
            );
        }
    }
}

fn loadavg() -> Vec<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse().ok())
        .collect()
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("loadgen failed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<()> {
    guard::ensure_quiet_machine().await?;
    let started_at = now_iso();
    let loadavg_before = loadavg();
    let nofile = node::raise_open_files_limit()?;
    eprintln!("tavrn-loadgen: {} clients, ramp to {}, open files limit {nofile}", args.clients, args.ramp_to);

    let mut database = None;
    let mut spawned = None;
    let mut run_dir = None;
    let target = match &args.url {
        Some(url) => Ok((url.clone(), args.pid)),
        None => {
            async {
                let db = node::TempDatabase::create(&args.database_url).await?;
                eprintln!("database {} (fsync {})", db.name, db.fsync);
                let dir = args.data_dir.join(&db.name);
                database = Some(db);
                let n = node::SpawnedNode::start(
                    &args.node_bin,
                    database.as_ref().map(|d| d.url.as_str()).unwrap_or_default(),
                    &dir,
                )
                .await;
                run_dir = Some(dir);
                let n = n?;
                eprintln!("node {} (pid {}), log {}", n.url, n.pid, n.log.display());
                let target = (n.url.clone(), Some(n.pid));
                spawned = Some(n);
                Ok::<_, anyhow::Error>(target)
            }
            .await
        }
    };
    let result = match target {
        Ok((url, pid)) => bench(&args, &url, pid, database.as_ref().map(|d| d.url.as_str())).await,
        Err(e) => Err(e),
    };

    // Cleanup runs whatever happened above.
    if let Some(n) = spawned.as_mut() {
        n.stop().await;
    }
    if let Some(db) = &database
        && let Err(e) = db.drop_database().await
    {
        eprintln!("warning: could not drop database {}: {e:#}", db.name);
    }
    if let Some(dir) = &run_dir {
        let _ = std::fs::remove_dir_all(dir);
    }

    let (report, timeline) = result?;
    let out = json!({
        "kind": "node",
        "started_at": started_at,
        "finished_at": now_iso(),
        "machine": {
            "loadavg_before": loadavg_before,
            "cpu": machine::cpu_topology(&std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default()),
            "open_files_limit": nofile,
            "postgres_fsync": database.as_ref().map(|d| d.fsync.clone()),
        },
        "config": {
            "clients": args.clients, "ramp_to": args.ramp_to, "rate": args.rate, "list_rate": args.list_rate,
            "idle_secs": args.idle_secs, "load_secs": args.load_secs, "commit_every": args.commit_every,
            "target": if args.url.is_some() { "external" } else { "spawned (release, PostgreSQL, production mode)" },
        },
        "info": report.info,
        "metrics": report.metrics,
        "timeline": timeline,
    });
    if let Some(dir) = args.out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&args.out, serde_json::to_string_pretty(&out)?)?;
    eprintln!("results written to {}", args.out.display());
    Ok(())
}

/// Everything the scenarios share.
struct Ctx {
    api: Api,
    users: Vec<User>,
    members: Vec<SharedMember>,
    log: Arc<CommitLog>,
    plain_id: String,
    enc_id: String,
    ws: Arc<WsStats>,
    observer: Arc<Observer>,
    connections: usize,
    sampler: Option<Sampler>,
    /// Speed of this machine relative to the reference (`machine::speed_factor`).
    speed: Option<f64>,
    /// The node's database (a started node only): the disk probe's.
    database_url: Option<String>,
}

/// Starts the disk probe (`disk.rs`) when the node's database is known.
async fn start_probe(database_url: Option<&str>, every: Duration) -> Result<Option<disk::Probe>> {
    match database_url {
        Some(url) => Ok(Some(disk::Probe::start(url, every).await.context("disk probe")?)),
        None => Ok(None),
    }
}

async fn finish_probe(probe: Option<disk::Probe>) -> Result<Option<Samples>> {
    match probe {
        Some(p) => Ok(Some(p.finish().await?)),
        None => Ok(None),
    }
}

/// Runs `f` for every item with at most `n` in flight, failing on the first error.
async fn concurrently<T, F, Fut, R>(items: Vec<T>, n: usize, f: F) -> Result<Vec<R>>
where
    F: Fn(T) -> Fut,
    Fut: std::future::Future<Output = Result<R>>,
{
    stream::iter(items.into_iter().map(f)).buffered(n).collect::<Vec<_>>().await.into_iter().collect()
}

async fn bench(
    args: &Args,
    url: &str,
    pid: Option<u32>,
    database_url: Option<&str>,
) -> Result<(Report, Vec<procstat::Snapshot>)> {
    let mut report = Report::default();
    let api = Api::new(url)?;
    let sampler = pid.map(Sampler::start).transpose()?;
    if sampler.is_none() {
        eprintln!("no --pid: CPU and RSS are not measured");
    }

    // Idle node: the baseline before any user exists.
    eprintln!("[1/7] idle node baseline ({} s)", args.baseline_secs);
    let usage = measure(&sampler, Duration::from_secs(args.baseline_secs)).await?;
    report.usage("node.idle", "Idle node", usage, true);
    for m in report.metrics.iter_mut().filter(|m| m.id.starts_with("node.idle_")) {
        m.baseline = true;
    }

    eprintln!("[2/7] {} users with TOTP", args.clients);
    let run = ulid::Ulid::generate().to_string().to_lowercase();
    let prefix = format!("p{}", &run[run.len() - 6..]);
    let started = Instant::now();
    let users = concurrently((0..args.clients).collect(), 16, |i| {
        let api = api.clone();
        let prefix = prefix.clone();
        async move { api.register(&format!("{prefix}u{i}"), &client_ip(i)).await }
    })
    .await?;
    report.info.insert("register_secs".into(), json!(round1(started.elapsed().as_secs_f64())));
    login_bench(&api, &users, &mut report).await?;

    eprintln!("[3/7] room, channels, MLS group of {} devices", users.len());
    let (ctx_base, setup_info) = setup_room(&api, users).await?;
    report.info.extend(setup_info);
    let speed = machine::speed_factor(ctx_base.catch_up_cpu_secs, args.clients);
    report.add(
        "node.machine_catch_up_cpu_secs",
        "Machine: CPU time of the load generator's MLS catch-up (fixed work, lower is faster)",
        ctx_base.catch_up_cpu_secs.map(round1),
        "s",
        json!({
            "reference_secs": machine::REFERENCE_CATCH_UP_CPU_SECS,
            "speed": speed.map(machine::round3),
            "calibrated_with": machine::CALIBRATED_WITH.map(|(name, _)| name),
        }),
    );
    if let Some(m) = report.metrics.last_mut() {
        m.baseline = true;
    }
    let (stop_tx, stop_rx) = watch::channel(false);
    let ws = Arc::new(WsStats::default());
    let observer = Arc::new(Observer::default());
    let ws_url = ws::ws_url(url);
    let tasks = Mutex::new(Vec::new());
    let started = Instant::now();
    concurrently(ctx_base.users.iter().enumerate().collect(), 32, |(i, u)| {
        let (ws, stop, obs, url, tasks) = (ws.clone(), stop_rx.clone(), observer.clone(), &ws_url, &tasks);
        async move {
            let handle = ws::connect(url, &u.token, ws, (i == 0).then_some(obs), stop).await?;
            lock(tasks).push(handle);
            Ok(())
        }
    })
    .await?;
    report.info.insert("connect_secs".into(), json!(round1(started.elapsed().as_secs_f64())));
    let ctx = Ctx {
        api,
        users: ctx_base.users,
        members: ctx_base.members,
        log: ctx_base.log,
        plain_id: ctx_base.plain_id,
        enc_id: ctx_base.enc_id,
        ws: ws.clone(),
        observer,
        connections: args.clients,
        sampler,
        speed,
        database_url: database_url.map(String::from),
    };

    eprintln!("[4/7] {} idle connections ({} s)", ctx.connections, args.idle_secs);
    let dropped = WsStats::get(&ws.dropped);
    // The disk while the node idles: the machine's own write latency.
    let probe = start_probe(ctx.database_url.as_deref(), Duration::from_millis(100)).await?;
    let usage = measure(&ctx.sampler, Duration::from_secs(args.idle_secs)).await?;
    let probe = finish_probe(probe).await?;
    report.add(
        "node.machine_pg_commit_p95_ms",
        "Machine: PostgreSQL commit of one row with the node idle, p95",
        probe.as_ref().and_then(|p| p.percentile(95.0)).map(round1),
        "ms",
        probe.as_ref().map_or(Value::Null, Samples::summary),
    );
    if let Some(m) = report.metrics.last_mut() {
        m.baseline = true;
    }
    report.usage("node.ws_idle", &format!("{} idle WebSockets", ctx.connections), usage, true);
    report.add(
        "node.ws_idle_dropped",
        "Idle WebSockets dropped",
        Some((WsStats::get(&ws.dropped) - dropped) as f64),
        "count",
        Value::Null,
    );

    eprintln!("[5/7] plaintext: {} msg/s for {} s", args.rate, args.load_secs);
    load_confirmed(args, &ctx, false, &mut report).await?;
    eprintln!("[6/7] encrypted: {} msg/s for {} s, commit every {}", args.rate, args.load_secs, args.commit_every);
    load_confirmed(args, &ctx, true, &mut report).await?;
    report.info.insert("mls_final_epoch".into(), json!(ctx.log.epoch()));

    eprintln!("[7/7] ramp to {} connections", args.ramp_to);
    ramp(args, &ctx, url, &stop_rx, &tasks, &mut report).await?;

    let _ = stop_tx.send(true);
    let handles = std::mem::take(&mut *lock(&tasks));
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
    let timeline = ctx.sampler.as_ref().map(Sampler::timeline).unwrap_or_default();
    Ok((report, timeline))
}

/// CPU/RSS of the node over `secs` of doing nothing (None without a pid).
async fn measure(sampler: &Option<Sampler>, secs: Duration) -> Result<Option<Usage>> {
    let window = sampler.as_ref().map(Sampler::window).transpose()?;
    tokio::time::sleep(secs).await;
    match (sampler, window) {
        (Some(s), Some(w)) => Ok(Some(w.finish(s)?)),
        _ => Ok(None),
    }
}

/// Password step of the login (Argon2id) for ten users, and whether the per-IP limiter answers.
async fn login_bench(api: &Api, users: &[User], report: &mut Report) -> Result<()> {
    let mut login = Samples::default();
    for u in users.iter().take(10) {
        let body = json!({ "username": u.username, "password": u.password, "device_name": "loadgen" });
        let (status, json, ms) = api.call(Method::POST, "/auth/login", None, Some(&u.ip), Some(&body)).await?;
        if status == StatusCode::OK && json["status"] == "second_factor_required" {
            login.push(ms);
        } else {
            login.errors += 1;
        }
    }
    report.add(
        "node.login_p50_ms",
        "Login password step (Argon2id), p50",
        login.percentile(50.0).map(round1),
        "ms",
        login.summary(),
    );
    // One address hammering the login: production allows 10 per minute and IP.
    let body = json!({ "username": "ratelimitprobe", "password": "wrong-password", "device_name": "loadgen" });
    let mut limited = None;
    for attempt in 1..=15 {
        let (status, _, ms) = api.call(Method::POST, "/auth/login", None, Some("198.19.255.254"), Some(&body)).await?;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some((attempt, ms));
            break;
        }
    }
    report.add(
        "node.login_rate_limited",
        "Login rate limiter answers 429",
        Some(if limited.is_some() { 1.0 } else { 0.0 }),
        "bool",
        json!({ "attempt": limited.map(|l| l.0), "response_ms": limited.map(|l| round1(l.1)) }),
    );
    Ok(())
}

struct RoomSetup {
    users: Vec<User>,
    members: Vec<SharedMember>,
    log: Arc<CommitLog>,
    plain_id: String,
    enc_id: String,
    /// CPU seconds of the catch-up threads together (the machine's speed, `machine.rs`).
    catch_up_cpu_secs: Option<f64>,
}

/// A public room with a plaintext and an encrypted channel; all users join, attest a device and
/// join the encrypted channel's MLS group by external commit (one after the other, as the epoch
/// moves with every join); then every member catches up to the final epoch.
async fn setup_room(api: &Api, users: Vec<User>) -> Result<(RoomSetup, serde_json::Map<String, Value>)> {
    let mut info = serde_json::Map::new();
    let owner = users.first().ok_or_else(|| anyhow!("no users"))?.clone();
    let room =
        api.ok(Method::POST, "/rooms", Some(&owner), Some(json!({ "name": "perf", "join_mode": "public" }))).await?;
    let room_id = room["id"].as_str().ok_or_else(|| anyhow!("room id"))?.to_string();
    let plain_id = room["channels"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c["kind"] == "text"))
        .and_then(|c| c["id"].as_str())
        .ok_or_else(|| anyhow!("default text channel"))?
        .to_string();
    api.ok(
        Method::PATCH,
        &format!("/rooms/{room_id}/channels/{plain_id}"),
        Some(&owner),
        Some(json!({ "encrypted": false })),
    )
    .await?;
    let enc = api
        .ok(
            Method::POST,
            &format!("/rooms/{room_id}/channels"),
            Some(&owner),
            Some(json!({ "kind": "text", "name": "secret", "encrypted": true })),
        )
        .await?;
    let enc_id = enc["id"].as_str().ok_or_else(|| anyhow!("channel id"))?.to_string();
    concurrently(users.iter().skip(1).collect(), 16, |u| {
        let path = format!("/rooms/{room_id}/join");
        async move { api.ok(Method::POST, &path, Some(u), Some(json!({}))).await.map(|_| ()) }
    })
    .await?;

    let members: Vec<Member> = concurrently(users.iter().collect(), 16, |u| mls::attest(api, u, &enc_id))
        .await
        .context("device attestation")?;
    let members: Vec<SharedMember> = members.into_iter().map(|m| Arc::new(Mutex::new(m))).collect();
    let log = Arc::new(CommitLog::default());
    let creator = members.first().ok_or_else(|| anyhow!("no members"))?;
    let group_info = with_member(creator, |m| Ok(m.client.create_group(&m.conversation)?)).await?;
    api.ok(
        Method::POST,
        &format!("/conversations/{enc_id}/mls/group"),
        Some(&owner),
        Some(json!({ "group_info": mls::b64(&group_info) })),
    )
    .await?;

    let started = Instant::now();
    let mut joins = Samples::default();
    for (member, user) in members.iter().zip(&users).skip(1) {
        let gi = api.ok(Method::GET, &format!("/conversations/{enc_id}/mls/group-info"), Some(user), None).await?;
        let gi = tavrn_crypto::util::b64url_decode(gi["group_info"].as_str().ok_or_else(|| anyhow!("group_info"))?)?;
        let out = with_member(member, move |m| Ok(m.client.join_by_external_commit(&m.conversation, &gi)?)).await?;
        let path = format!("/conversations/{enc_id}/mls/commits");
        let (status, body, ms) =
            api.call(Method::POST, &path, Some(&user.token), Some(&user.ip), Some(&commit_body(&out))).await?;
        if status != StatusCode::CREATED {
            bail!("external join of {}: {status} {body}", user.username);
        }
        joins.push(ms);
        with_member(member, |m| Ok(m.client.merge_pending_commit(&m.conversation)?)).await?;
        log.push(out.epoch, out.commit)?;
    }
    info.insert("mls_join_secs".into(), json!(round1(started.elapsed().as_secs_f64())));
    info.insert("mls_join_commit_ms".into(), joins.summary());

    // Every member processes the joins after its own, spread over all cores. The threads' CPU time is the
    // calibration of the machine's speed (`machine.rs`).
    let started = Instant::now();
    let shared = members.clone();
    let shared_log = log.clone();
    let catch_up_cpu_secs = tokio::task::spawn_blocking(move || -> Result<Option<f64>> {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let chunk = shared.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            let handles: Vec<_> = shared
                .chunks(chunk)
                .map(|part| {
                    let log = &shared_log;
                    scope.spawn(move || -> Result<Option<f64>> {
                        let cpu = machine::thread_cpu_secs();
                        for m in part {
                            lock(m).catch_up(log)?;
                        }
                        Ok(cpu.zip(machine::thread_cpu_secs()).map(|(from, to)| to - from))
                    })
                })
                .collect();
            let mut total = Some(0.0);
            for h in handles {
                let cpu = h.join().map_err(|_| anyhow!("catch-up thread panicked"))??;
                total = total.zip(cpu).map(|(t, c)| t + c);
            }
            Ok(total)
        })
    })
    .await??;
    info.insert("mls_catch_up_secs".into(), json!(round1(started.elapsed().as_secs_f64())));
    info.insert("mls_catch_up_cpu_secs".into(), json!(catch_up_cpu_secs.map(round1)));
    info.insert("mls_group_size".into(), json!(members.len()));
    Ok((RoomSetup { users, members, log, plain_id, enc_id, catch_up_cpu_secs }, info))
}

/// A send slower than this (the send p95 budget) is recorded with the second it was scheduled in.
const SLOW_SEND_MS: f64 = 50.0;

/// A load scenario, repeated once when its send p95 exceeds [`SLOW_SEND_MS`]: on a shared runner a stretch of slow
/// disk flushes (PostgreSQL runs with fsync) can push the p95 of one minute far up while reads and CPU stay as
/// always (perf/README.md "Noisy runners"). A slowness of the node shows again in the repetition, which is reported;
/// the first attempt is kept in the info.
async fn load_confirmed(args: &Args, ctx: &Ctx, encrypted: bool, report: &mut Report) -> Result<()> {
    let name = if encrypted { "enc" } else { "plain" };
    let mut first = Report::default();
    load(args, ctx, encrypted, &mut first).await?;
    let p95 = first.value(&format!("node.{name}_send_p95_ms"));
    let Some(p95) = p95.filter(|v| *v > SLOW_SEND_MS) else {
        report.append(first);
        return Ok(());
    };
    eprintln!("  send p95 {p95} ms > {SLOW_SEND_MS} ms: repeating the scenario once");
    let summary: serde_json::Map<String, Value> =
        first.metrics.iter().map(|m| (m.id.clone(), json!(m.value))).collect();
    let mut second = Report::default();
    load(args, ctx, encrypted, &mut second).await?;
    report.append(second);
    report.info.insert(format!("{name}_first_attempt"), json!({ "metrics": summary, "info": first.info }));
    Ok(())
}

/// `rate` messages per second for `load_secs` (open loop, round-robin over the users), message
/// lists alongside; encrypted: real MLS ciphertext and a self-update commit every `commit_every`.
async fn load(args: &Args, ctx: &Ctx, encrypted: bool, report: &mut Report) -> Result<()> {
    let conv = if encrypted { ctx.enc_id.clone() } else { ctx.plain_id.clone() };
    let name = if encrypted { "enc" } else { "plain" };
    let label = if encrypted { "Encrypted" } else { "Plaintext" };
    let send = Arc::new(Mutex::new(Samples::default()));
    let list = Arc::new(Mutex::new(Samples::default()));
    let commit = Arc::new(Mutex::new(Samples::default()));
    let sent = Arc::new(Mutex::new(Vec::<(String, Instant)>::new()));
    // Second of the scenario in which each send slower than SLOW_SEND_MS was scheduled: tells a stall of a few
    // seconds (many in a row) from a spread-out slowness.
    let slow = Arc::new(Mutex::new(std::collections::BTreeMap::<u64, u32>::new()));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let commit_gate = Arc::new(tokio::sync::Mutex::new(()));
    let commit_seq = Arc::new(AtomicU64::new(0));
    let events_before = WsStats::get(&ctx.ws.message_events);
    let total = u64::from(args.rate) * args.load_secs;
    let interval = Duration::from_secs_f64(1.0 / f64::from(args.rate.max(1)));
    let list_every = u64::from((args.rate / args.list_rate.max(1)).max(1));
    // The disk beside the node's writes, a commit every 250 ms (a fifth of the node's message rate).
    let probe = start_probe(ctx.database_url.as_deref(), Duration::from_millis(250)).await?;
    let window = ctx.sampler.as_ref().map(Sampler::window).transpose()?;
    let start = tokio::time::Instant::now();
    let mut handles = Vec::new();

    for seq in 0..total {
        tokio::time::sleep_until(start + interval * seq as u32).await;
        let i = seq as usize % ctx.users.len();
        let user = ctx.users[i].clone();
        let (api, conv_id, send, sent, errs, slow) =
            (ctx.api.clone(), conv.clone(), send.clone(), sent.clone(), errors.clone(), slow.clone());
        let second = seq / u64::from(args.rate.max(1));
        let member = ctx.members[i].clone();
        let log = ctx.log.clone();
        handles.push(tokio::spawn(async move {
            let (conv, errors) = (conv_id, errs);
            let body = format!("perf message {seq}");
            let payload = if encrypted {
                match with_member(&member, move |m| {
                    m.catch_up(&log)?;
                    m.encrypt(&body)
                })
                .await
                {
                    Ok((content, epoch)) => json!({ "content": content, "epoch": epoch }),
                    Err(e) => {
                        lock(&send).errors += 1;
                        lock(&errors).push(format!("encrypt: {e:#}"));
                        return;
                    }
                }
            } else {
                json!({ "content": { "type": "text", "body": body } })
            };
            let started = Instant::now();
            let path = format!("/conversations/{conv}/messages");
            match api.call(Method::POST, &path, Some(&user.token), Some(&user.ip), Some(&payload)).await {
                Ok((StatusCode::CREATED, msg, ms)) => {
                    lock(&send).push(ms);
                    if ms > SLOW_SEND_MS {
                        *lock(&slow).entry(second).or_default() += 1;
                    }
                    if let Some(id) = msg["id"].as_str() {
                        lock(&sent).push((id.to_string(), started));
                    }
                }
                Ok((status, body, _)) => {
                    lock(&send).errors += 1;
                    lock(&errors).push(format!("send: {status} {body}"));
                }
                Err(e) => {
                    lock(&send).errors += 1;
                    lock(&errors).push(format!("send: {e:#}"));
                }
            }
        }));
        if seq % list_every == 0 {
            let reader = ctx.users[(i * 7 + 3) % ctx.users.len()].clone();
            let (api, list, errors) = (ctx.api.clone(), list.clone(), errors.clone());
            let path = format!("/conversations/{conv}/messages?limit=50");
            handles.push(tokio::spawn(async move {
                match api.call(Method::GET, &path, Some(&reader.token), Some(&reader.ip), None).await {
                    Ok((StatusCode::OK, Value::Array(_), ms)) => lock(&list).push(ms),
                    Ok((status, body, _)) => {
                        lock(&list).errors += 1;
                        lock(&errors)
                            .push(format!("list: {status} {}", body.to_string().chars().take(200).collect::<String>()));
                    }
                    Err(e) => {
                        lock(&list).errors += 1;
                        lock(&errors).push(format!("list: {e:#}"));
                    }
                }
            }));
        }
        if encrypted && seq > 0 && seq % args.commit_every == 0 {
            let n = commit_seq.fetch_add(1, Ordering::Relaxed) as usize;
            let k = (n * 13 + 1) % ctx.members.len();
            let (member, user) = (ctx.members[k].clone(), ctx.users[k].clone());
            let (api, log, commit, errors, gate) =
                (ctx.api.clone(), ctx.log.clone(), commit.clone(), errors.clone(), commit_gate.clone());
            let path = format!("/conversations/{conv}/mls/commits");
            handles.push(tokio::spawn(async move {
                let _gate = gate.lock().await;
                let result = async {
                    let log2 = log.clone();
                    let out = with_member(&member, move |m| {
                        m.catch_up(&log2)?;
                        Ok(m.client.self_update(&m.conversation)?)
                    })
                    .await?;
                    let (status, body, ms) = api
                        .call(Method::POST, &path, Some(&user.token), Some(&user.ip), Some(&commit_body(&out)))
                        .await?;
                    if status != StatusCode::CREATED {
                        with_member(&member, |m| Ok(m.client.discard_pending_commit(&m.conversation)?)).await?;
                        bail!("commit: {status} {body}");
                    }
                    lock(&commit).push(ms);
                    with_member(&member, |m| Ok(m.client.merge_pending_commit(&m.conversation)?)).await?;
                    log.push(out.epoch, out.commit)
                }
                .await;
                if let Err(e) = result {
                    lock(&commit).errors += 1;
                    lock(&errors).push(format!("{e:#}"));
                }
            }));
        }
    }
    for h in handles {
        h.await?;
    }
    let usage = match (&ctx.sampler, window) {
        (Some(s), Some(w)) => Some(w.finish(s)?),
        _ => None,
    };
    let probe = finish_probe(probe).await?;
    // Late WebSocket deliveries.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let send = lock(&send).clone();
    let list = lock(&list).clone();
    let commit = lock(&commit).clone();
    let delivered = WsStats::get(&ctx.ws.message_events) - events_before;
    let expected = send.count() as u64 * ctx.connections as u64;
    let mut delivery = Samples::default();
    {
        let received = lock(&ctx.observer.received);
        for (id, t0) in lock(&sent).iter() {
            match received.get(id) {
                Some(t) => delivery.push(t.saturating_duration_since(*t0).as_secs_f64() * 1000.0),
                None => delivery.errors += 1,
            }
        }
    }
    let error_list = lock(&errors).clone();
    let slow = lock(&slow).clone();
    report.info.insert(format!("{name}_slow_sends_by_second"), json!(slow));
    let users = ctx.users.len();
    report.latency(&format!("node.{name}_send_p95_ms"), &format!("{label}: send p95 ({users} clients)"), &send);
    report.latency(&format!("node.{name}_list_p95_ms"), &format!("{label}: list 50 p95 (under load)"), &list);
    report.latency(
        &format!("node.{name}_pg_commit_p95_ms"),
        &format!("{label}: PostgreSQL commit of one row beside the load, p95 (the disk)"),
        &probe.unwrap_or_default(),
    );
    if encrypted {
        report.latency("node.enc_commit_p95_ms", "Encrypted: MLS commit p95", &commit);
    }
    report.latency(&format!("node.{name}_delivery_p95_ms"), &format!("{label}: send → WebSocket p95"), &delivery);
    report.usage(&format!("node.{name}"), &format!("{label} load"), usage, false);
    report.add(
        &format!("node.{name}_cpu_ref_pct"),
        &format!("{label} load: CPU on the reference machine"),
        usage.zip(ctx.speed).map(|(u, speed)| machine::on_reference(u.cpu_pct, speed)),
        "%",
        json!({ "measured_pct": usage.map(|u| u.cpu_pct), "speed": ctx.speed.map(machine::round3) }),
    );
    let errors_total = send.errors + list.errors + commit.errors;
    report.add(
        &format!("node.{name}_errors"),
        &format!("{label}: errors"),
        Some(errors_total as f64),
        "count",
        json!({ "first": error_list.iter().take(5).collect::<Vec<_>>(), "sent": send.count() }),
    );
    report.add(
        &format!("node.{name}_ws_delivered_pct"),
        &format!("{label}: WebSocket deliveries"),
        Some(if expected == 0 { 0.0 } else { round1(delivered as f64 / expected as f64 * 100.0) }),
        "%",
        json!({ "delivered": delivered, "expected": expected, "resyncs": WsStats::get(&ctx.ws.resyncs) }),
    );
    Ok(())
}

/// Opens connections up to `ramp_to` (50 at a time), holds them and reports errors and RSS.
async fn ramp(
    args: &Args,
    ctx: &Ctx,
    url: &str,
    stop: &watch::Receiver<bool>,
    tasks: &Mutex<Vec<tokio::task::JoinHandle<()>>>,
    report: &mut Report,
) -> Result<()> {
    let failed_before = WsStats::get(&ctx.ws.failed);
    let dropped_before = WsStats::get(&ctx.ws.dropped);
    let window = ctx.sampler.as_ref().map(Sampler::window).transpose()?;
    let ws_url = ws::ws_url(url);
    let extra = args.ramp_to.saturating_sub(ctx.connections);
    let connect = Arc::new(Mutex::new(Samples::default()));
    let started = Instant::now();
    let results: Vec<()> = stream::iter((0..extra).map(|i| {
        let user = &ctx.users[i % ctx.users.len()];
        let (stats, stop, ws_url, connect) = (ctx.ws.clone(), stop.clone(), &ws_url, connect.clone());
        async move {
            let t0 = Instant::now();
            match ws::connect(ws_url, &user.token, stats, None, stop).await {
                Ok(h) => {
                    lock(&connect).push(t0.elapsed().as_secs_f64() * 1000.0);
                    lock(tasks).push(h);
                }
                Err(_) => lock(&connect).errors += 1,
            }
        }
    }))
    .buffer_unordered(50)
    .collect()
    .await;
    let ramp_secs = started.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_secs(args.ramp_hold_secs)).await;
    let usage = match (&ctx.sampler, window) {
        (Some(s), Some(w)) => Some(w.finish(s)?),
        _ => None,
    };
    let connect = lock(&connect).clone();
    let errors = (WsStats::get(&ctx.ws.failed) - failed_before) + (WsStats::get(&ctx.ws.dropped) - dropped_before);
    let open = ctx.connections + connect.count();
    report.add(
        "node.ramp_errors",
        &format!("Ramp to {} connections: errors", args.ramp_to),
        Some(errors as f64),
        "count",
        json!({ "open": open, "opened": results.len(), "ramp_secs": round1(ramp_secs), "connect_ms": connect.summary() }),
    );
    report.add(
        "node.ramp_rss_mb",
        &format!("Ramp to {} connections: RSS (max)", args.ramp_to),
        usage.map(|u| u.rss_max_mb),
        "MB",
        usage.map_or(Value::Null, |u| json!(u)),
    );
    report.add(
        "node.ramp_cpu_pct",
        &format!("Ramp to {} connections: CPU", args.ramp_to),
        usage.map(|u| u.cpu_pct),
        "%",
        Value::Null,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_timestamps() {
        let s = now_iso();
        assert_eq!(s.len(), 20);
        assert!(s.starts_with("20"));
        assert!(s.ends_with('Z'));
    }

    #[test]
    fn cli_defaults_match_the_plan() {
        let args = Args::parse_from(["tavrn-loadgen"]);
        assert_eq!((args.clients, args.ramp_to, args.rate, args.commit_every), (200, 1000, 20, 100));
    }
}
