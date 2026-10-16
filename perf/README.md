# Performance benchmarks

This tier measures the node's performance budgets with a load generator. It is separate from `just check`
because it takes minutes: CI runs it every night (`.github/workflows/perf.yml`, never on pull requests), and you
can start that workflow by hand ("Run workflow").

```bash
just perf-node     # release builds, the load generator against a release node with PostgreSQL, then the report
```

Prerequisites: everything `just check` needs, a PostgreSQL server for throwaway databases
(`TAVRN_TEST_DATABASE_URL`, default the test container of the README on port 55432) and Node.js 24 for the report
(`perf/report.ts` has no dependencies). The recipe builds the release binaries `tavrn-node` and `tavrn-loadgen`
first; the first release build takes a few minutes.

The web client benchmarks (start-up, rendering under load, voice CPU in the browser) use the same report and
budget file and live in [tavrn-web](https://github.com/just-tavrn/tavrn-web), where the browser and the
end-to-end helpers are.

## Running alone

The load generator must run **alone on the machine** and needs several GB of free memory: it starts a release
node, 200 MLS clients and up to 1000 WebSockets, and next to other heavy work (builds, test suites, another
benchmark) it both skews the numbers and can exhaust the memory of a small machine. A guard
(`perf/loadgen/src/guard.rs`) therefore refuses to start when less than 6 GB is available (`MemAvailable`) or
the 1-minute load average exceeds half the core count. It first waits up to two minutes for the machine to calm
down (for example right after a release build) and then fails with a message naming the reason. `PERF_GUARD=off`
skips the check (Linux only; elsewhere it is skipped).

On a shared or small machine, run at reduced scale, for example
`tavrn-loadgen --clients 50 --ramp-to 200`. Compare only runs made with the same parameters.

## What is measured

### Node (`perf/loadgen`, Rust)

`tavrn-loadgen` starts the release `tavrn-node` itself in **production mode**. It uses a fresh PostgreSQL
database `perf_<ulid>` on the server of `TAVRN_TEST_DATABASE_URL` (default: the test container on port
55432), a free port and a temporary data directory under `data-dev/perf-node/`. The database and the
directory are removed at the end. Production mode means production rate limits, so every simulated user
sends its own `X-Forwarded-For` address from 198.18.0.0/15 (the node trusts loopback proxies), as real
clients behind a reverse proxy would. The node's CPU time and RSS are read from `/proc/<pid>/stat` and
`/proc/<pid>/status` once per second. Linux only.

Scenarios, in this order:

1. **Idle node** (10 s, before any user exists). This is the node baseline: RSS and CPU.
2. **Users**: 200 registrations with TOTP enrollment done in code (`totp-rs`). **Login**: the Argon2id
   password step for ten users. It is reported but has no latency budget. One address then tries 15 logins:
   the rate limiter must answer `429`.
3. **Room**: a public room with a plaintext channel and an encrypted channel. All users join. Every user
   uploads an identity key and an attested device key. The owner creates the MLS group and the other 199
   devices join it by external commit, one after the other. Then every member catches up to the final
   epoch.
4. **200 idle WebSockets** (30 s): RSS and CPU. Alongside, the disk probe (see "Noisy runners").
5. **Plaintext load** (60 s): 20 messages per second in total, round-robin over the users, sent open-loop
   (on schedule, not waiting for earlier requests). Alongside, 5 message lists per second (`limit=50`).
   Results: send, list and send → WebSocket delivery latencies (p50/p95/p99), node CPU, errors, and the
   share of `message.create` events that reached all 200 connections. The node's CPU is budgeted on the
   reference machine (see "Machine speed" below).
6. **Encrypted load** (60 s): the same with real MLS ciphertext from `tavrn-crypto`. A member commits a
   self-update every 100 messages; the commit latency is budgeted. The load generator is the only
   committer, so members catch up from its local commit log instead of the node's handshake log.
7. **Ramp to 1000 connections** (connections only, 50 at a time, then held for 10 s): errors and RSS.

To measure an already running node instead, use
`target/release/tavrn-loadgen --url http://host:port --pid <pid>`. Without `--pid` there are no CPU or RSS
values. The node must allow open registration and local room creation. `--help` lists the knobs (number of
clients, rate, durations).

The load generator runs on the same machine as the node and uses CPU too (MLS clients, 1000 sockets).
Compare runs from the same machine.

### Machine speed

A CPU share depends on the machine as much as on the node. GitHub's 4-core `ubuntu-latest` runners are
not one machine: the nightlies of October 2026 ran on AMD EPYC 7763, 9V45 and 9V74 and on two Intel Xeon
models, and the same node measured 10.2 % to 13.9 % of one core under the plaintext load on them (12.5 % to
25.3 % before the read buffer fix below). A fixed CPU budget measures the runner, not the node.

The load generator calibrates every run with the MLS catch-up of its setup: every member processes the
commits after its own join, the same computation in every run of the default scale. The CPU time of its
threads together is `node.machine_catch_up_cpu_secs` (a baseline; lower is faster). The node's CPU under load
is reported twice:

- `node.plain_cpu_pct` / `node.enc_cpu_pct`: as measured on this machine (info);
- `node.plain_cpu_ref_pct` / `node.enc_cpu_ref_pct`: the same on the reference machine, the measured share
  times *reference catch-up / this catch-up* (budgeted).

The reference machine is the EPYC 7763 runner. That the catch-up follows the runners the way the node does is
measured, not assumed: for one version of the code, the node's share divided by the catch-up varies by about
10 % over the runners while the share itself varies by 40 % to 100 %:

| Run (2026-10) | Code | Runner | Catch-up | Measured plain / enc | On the reference |
|---|---|---|---|---|---|
| 38227947218 (10-12) | 3d7ab04 | EPYC 9V45 | 12.5 s wall | 12.5 / 12.4 % | 23.1 % (60 s ref.) |
| 38375860961 (10-13) | 706697b | EPYC 7763 | 22.7 s wall | 23.7 / 23.0 % | 24.1 % (60 s ref.) |
| 38529235052 (10-14) | 9506e17 | EPYC 7763 | 24.8 s wall | 25.3 / 24.3 % | 23.5 % (60 s ref.) |
| 38698402544 (10-15) | e4462d1 | Xeon 6973P-C | 15.4 s wall | 16.3 / 15.0 % | 24.4 % (60 s ref.) |
| 38865178559 (10-16) | 090d3b7 | EPYC 9V74 | 26.2 CPU s | 10.2 / 10.5 % | 12.5 / 12.9 % |
| 38961332219 (10-16) | 090d3b7 | EPYC 7763 | 32.3 CPU s | 13.9 / 13.7 % | 13.9 / 13.7 % |
| 38961335441 (10-16) | 090d3b7 | EPYC 7763 | 32.2 CPU s | 13.6 / 13.7 % | 13.7 / 13.7 % |
| 38961339671 (10-16) | 090d3b7 | Xeon Platinum 8573C | 31.8 CPU s | 12.4 / 12.6 % | 12.6 / 12.8 % |

The first four runs predate the CPU measurement of the catch-up; their reference values use its wall time
times four threads busy 65 % of it, against the reference of those load generators (60 CPU seconds).

The catch-up is fixed work only while the code doing it stays the same: OpenMLS through tavrn-crypto.
0.4.0-rc.10 took tavrn-crypto 0.1.0 from crates.io, whose MLS client caches the groups it loaded instead of
rebuilding them for every call; the catch-up became half as expensive (on the EPYC 7763 from about 60 to 32
CPU seconds; on one local machine from 30.7 to 15.7 with the two load generators against the same node). The
node became cheaper between the same two nightlies (0.4.0-rc.9, read buffer fix below). Scaled by a catch-up that had halved, the
node's 43 % gain on the EPYC 7763 (24.5 % → 13.8 % measured) vanished: every scaled value stayed at 23–25 %.
The reference is therefore tied to the crates it was measured with (`CALIBRATED_WITH` in
`perf/loadgen/src/machine.rs`, their `Cargo.lock` checksums), and a unit test of the load generator fails when
one of them changes. To measure the reference again, run the old and the new load generator against the same
node on one machine (pinned, for example `taskset -c 0-3`, `--node-bin` of one build) and scale
`REFERENCE_CATCH_UP_CPU_SECS` by the ratio of their `mls_catch_up_cpu_secs`; or run the Performance workflow
before and after the change and compare runs on the EPYC 7763. Then update the checksums.

The calibration holds for the default 200 clients only; at another scale the `_ref` values are missing (the
report fails them) and only the measured shares can be compared between runs of the same parameters. A local
machine scales differently from the runners (a virtualized Linux such as WSL pays more for the node's many
small system calls), so compare local `_ref` values with local runs, not with the nightly. The raw results
also record the CPU topology (`machine.cpu`: model, logical CPUs, threads per core) and the load generator's
own CPU in every measurement window (`loadgen_cpu_pct` in the details of a usage metric), for a later check
of other calibrations against the runners.

The budget is 17 % of one reference core at 20 messages per second. Before the read buffer fix the node
took 23–25 % on the reference: before every read, tungstenite zeroed the free part of a connection's
128 KiB read buffer, also for the reads that found nothing, and each event wakes every connection, which polls
its socket. With a 4 KiB buffer (`ws::READ_BUFFER`) the runners give 12.5–13.9 % (mean 13.2 %) on the
reference. The budget is about a quarter above that: 22 % above the highest runner value, 29 % above the
mean; the warning from 13.6 % (80 %) shows a creep before.

### Noisy runners

The latency budgets of writes (send p95 50 ms, MLS commit p95 150 ms) measure the node and the machine's
disk: every accepted message is a PostgreSQL commit, and the server commits with `fsync`. GitHub's runners
differ there. On the AMD EPYC 9V74 runners the plaintext send p95 was 115 ms and 107-134 ms (two runs) while
eight runs of the same and older code on other runners measured 10-18 ms; in those runs the reads (list p95
8-9 ms) and the node's CPU (steady second by second) were as always, the slow sends were spread over the whole
minute (where recorded), and even the 199 MLS join commits of the setup, one after the other with no load, took 98-110 ms at
p95 (20-30 ms on the other runners). The load average gate does not tell these runs apart: every run waits
for the load of the release build to fall below half the cores.

Two measures keep such a runner from failing the nightly without hiding a slow node:

- **Disk probe.** While the 200 connections idle (scenario 4), the load generator commits one row every
  100 ms on a table of its own in the run's database (`perf/loadgen/src/disk.rs`), without the node:
  `node.machine_pg_commit_p95_ms` (a baseline). The median is the same everywhere (0.6 ms); the tail is not:
  the p95 was 0.8 ms on an EPYC 7763 runner, 1.5 ms on a local SSD and 9.6 ms on an EPYC 9V74 runner
  (p99 2.5 against 41.6 ms, slowest commit 5.5 against 318 ms). When it exceeds `disk.slow_ms` of
  `budgets.json` (3 ms, about midway between those on a log scale), a write latency over its budget
  (`"disk_bound": true`) is reported **INCONCLUSIVE** instead of OVER and does not fail the run. Everything else, CPU, reads, errors, RSS,
  is judged as always, and the write latencies are judged on every other runner.
- **Repetition.** A load scenario whose send p95 is above 50 ms is repeated once, right away, and the
  repetition is reported (the first attempt stays in the info as `<scenario>_first_attempt`). A stretch of
  slow flushes on an otherwise normal disk passes the second time; a slow node is slow twice.

For every attempt the info also lists the seconds in which sends took longer than 50 ms
(`<scenario>_slow_sends_by_second`): a stall shows as many in a few seconds, a slow disk as a few in most.

## Reading the report

`perf/report.ts` merges the raw results (`perf/results/raw/node.json`, and `client-<project>.json` when the web
client benchmarks ran into the same directory) and
classifies each metric that has a budget in `budgets.json`:

| Status | Meaning |
|---|---|
| `OK` | below 80 % of the budget |
| `WARNING` | 80 % to 100 % of the budget |
| `OVER` | above the budget: the run fails (exit code 1) |
| `INCONCLUSIVE` | a write latency above its budget on a slow disk (see "Noisy runners"): reported, the run does not fail |
| `MISSING` | the benchmark ran but produced no value (a step failed): the run fails |
| `INFO` | no budget, for context (p50/p99, heap after a run, slow-machine values without a budget) |

The report prints a table of budgeted metrics, then the informational metrics and the baselines, then the
machine. It writes `perf/results/<timestamp>.json` (gitignored; the CI artifact `perf-results`). That file
holds every metric with its status, the baselines, the machine (CPU model, cores, load average before each
benchmark and after the run, Node, Chromium and rustc versions, and whether the PostgreSQL server runs with
`fsync`; with `fsync=off` the node's write latencies are optimistic) and the configuration and setup timings
of each benchmark. Absolute numbers depend on the machine. Compare a result with the baselines and the
load average recorded next to it before you call it a regression.

## Changing budgets

The numbers live in one place: `perf/budgets.json`. Each entry is `{ "max": n }` (the value must not
exceed it) or `{ "min": n }` (the value must reach it), keyed by metric id. Metric ids are `node.<name>`
and `client.<project>.<name>`. Budgets are product decisions: change them in a reviewed pull request
and say in the commit why. A unit test (`perf/report.test.ts`, `just test-perf-report`) pins the classification
and a few of the numbers. To budget a new metric, emit it from the load generator or the
spec, then add its id to `budgets.json`.
