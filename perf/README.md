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
4. **200 idle WebSockets** (30 s): RSS and CPU.
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
not one machine: the nightlies of October 2026 ran on an AMD EPYC 9V45 once and on an EPYC 7763 after
that, and the node's plaintext load went from 12.5 % to 23.7 % and 25.3 % of one core although nothing in
between touched its hot path (locally, on one machine, the commits of the first two nights measured the same
within 2 %). The
load generator's own work, which did not change at all, slowed down by the same factor: its MLS catch-up took
12.5 s, 22.7 s and 24.8 s. A fixed CPU budget therefore measured the runner, not the node.

The load generator calibrates every run with that catch-up: every member processes the commits after its
own join (OpenMLS from the pinned tavrn-crypto), the same computation in every run of the default scale. The
CPU time of its threads together is `node.machine_catch_up_cpu_secs` (a baseline; lower is faster). The
node's CPU under load is reported twice:

- `node.plain_cpu_pct` / `node.enc_cpu_pct`: as measured on this machine (info);
- `node.plain_cpu_ref_pct` / `node.enc_cpu_ref_pct`: the same on the reference machine, the measured share
  times *reference catch-up / this catch-up* (budgeted).

The reference machine is one whose catch-up takes 60 CPU seconds
(`perf/loadgen/src/machine.rs`), about the EPYC 7763 runner (22.7 s and 24.8 s of wall time on four
threads, which are busy 65 % of it together). Scaled this way, the October runs give 23.1 % (EPYC 9V45),
24.1 % and 23.5 % (EPYC 7763): the spread between the runners shrinks from a factor of 2 to 4 %. The
calibration holds for the default 200 clients only; at another scale the `_ref` values are missing (the
report fails them) and only the measured shares can be compared between runs of the same parameters. A local
machine scales differently from the runners (a virtualized Linux such as WSL pays more for the node's many
small system calls), so compare local `_ref` values with local runs, not with the nightly.

The budget is 20 % of one reference core at 20 messages per second. The node itself got cheaper at the same
time: before every read, tungstenite zeroed the free part of a connection's 128 KiB read buffer, also for
the reads that found nothing, and each event wakes every connection, which polls its socket. That zeroing
was 39 % of the node's user CPU under this load; with a 4 KiB buffer (`ws::READ_BUFFER`) the plaintext load
fell from 15.0 % to 10.1 % and the encrypted load from 13.2 % to 8.3 % (pinned to four CPUs; 19.6 % to
11.4 % and 17.0 % to 9.4 % unpinned). On the reference machine that is about 16 % (from about 24 %). The
budget leaves room for noise and catches a regression of about a quarter; the warning from 16 % shows a
creep before.

## Reading the report

`perf/report.ts` merges the raw results (`perf/results/raw/node.json`, and `client-<project>.json` when the web
client benchmarks ran into the same directory) and
classifies each metric that has a budget in `budgets.json`:

| Status | Meaning |
|---|---|
| `OK` | below 80 % of the budget |
| `WARNING` | 80 % to 100 % of the budget |
| `OVER` | above the budget: the run fails (exit code 1) |
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
