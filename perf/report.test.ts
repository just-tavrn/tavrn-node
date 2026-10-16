// SPDX-License-Identifier: AGPL-3.0-only
// Unit tests of the budget classification (run by `pnpm -r test` / `just test-js`).
import assert from "node:assert/strict";
import { test } from "node:test";
import { classify, evaluate, failed, table, type Budgets, type RawFile } from "./report.ts";

test("max budgets: ok below 80 %, warning from 80 % to 100 %, over above", () => {
  const b = { max: 100 };
  assert.deepEqual(classify(79.9, b, 0.8), { status: "ok", ratio: 0.799 });
  assert.equal(classify(80, b, 0.8).status, "warning");
  assert.equal(classify(100, b, 0.8).status, "warning");
  assert.equal(classify(100.1, b, 0.8).status, "over");
});

test("zero, min and missing budgets", () => {
  assert.equal(classify(0, { max: 0 }, 0.8).status, "ok");
  assert.equal(classify(1, { max: 0 }, 0.8).status, "over");
  assert.equal(classify(1, { min: 1 }, 0.8).status, "ok");
  assert.equal(classify(0, { min: 1 }, 0.8).status, "over");
  assert.equal(classify(null, { max: 5 }, 0.8).status, "missing");
  assert.equal(classify(Number.NaN, { max: 5 }, 0.8).status, "missing");
  assert.equal(classify(42, undefined, 0.8).status, "info");
});

test("evaluate: budgets of benchmarks that ran must have a value, others are ignored", () => {
  const budgets: Budgets = {
    warning_at: 0.8,
    budgets: { "node.a": { max: 10 }, "node.b": { max: 10 }, "client.desktop.c": { max: 10 }, "client.slow.d": { max: 1 } },
  };
  const node: RawFile = {
    kind: "node",
    started_at: "",
    finished_at: "",
    machine: {},
    metrics: [
      { id: "node.a", label: "a", value: 9, unit: "ms" },
      { id: "node.x", label: "x", value: 1, unit: "ms" },
    ],
  };
  const desktop: RawFile = { kind: "client", project: "desktop", started_at: "", finished_at: "", machine: {}, metrics: [{ id: "client.desktop.c", label: "c", value: 2, unit: "ms" }] };
  const result = evaluate([node, desktop], budgets);
  const status = Object.fromEntries(result.map((m) => [m.id, m.status]));
  assert.deepEqual(status, { "node.a": "warning", "node.x": "info", "client.desktop.c": "ok", "node.b": "missing" });
  assert.equal(failed(result), true);
  assert.equal(failed(result.filter((m) => m.id !== "node.b")), false);
  assert.match(table(result), /WARNING\s+node\.a\s+9 ms\s+<= 10 ms\s+90 %/);
});

test("the budget file carries the decided budgets", async () => {
  const { readFileSync } = await import("node:fs");
  const budgets = JSON.parse(readFileSync(new URL("./budgets.json", import.meta.url), "utf8")) as Budgets;
  assert.equal(budgets.warning_at, 0.8);
  const max = (id: string) => budgets.budgets[id]?.max;
  assert.equal(max("client.desktop.start_to_shell_ms"), 2000);
  assert.equal(max("client.slow.start_to_shell_ms"), 5000);
  assert.equal(max("client.desktop.ingest_enc_render_p95_ms"), 150);
  assert.equal(max("node.enc_commit_p95_ms"), 150);
  assert.equal(max("node.ramp_rss_mb"), 400);
  // The node's CPU under load on the reference machine (perf/README.md "Machine speed"); the measured share is info.
  assert.equal(max("node.plain_cpu_ref_pct"), 17);
  assert.equal(max("node.enc_cpu_ref_pct"), 17);
  assert.equal(max("node.plain_cpu_pct"), undefined);
  // Phase 4 voice: connected idle <= 5 %, talking <= 15 % of one core.
  assert.equal(max("client.desktop.voice_idle_cpu_pct"), 5);
  assert.equal(max("client.desktop.voice_talk_cpu_pct"), 15);
  for (const [id, b] of Object.entries(budgets.budgets)) assert.ok(b.max !== undefined || b.min !== undefined, id);
});
