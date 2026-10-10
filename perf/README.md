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
   share of `message.create` events that reached all 200 connections.
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
