// SPDX-License-Identifier: AGPL-3.0-only
// Merges the raw benchmark results (perf/results/raw/*.json from the load generator and the
// Playwright client benchmarks), classifies every metric against perf/budgets.json, prints a table
// and writes perf/results/<timestamp>.json. Exit code 1 if a metric is over budget or missing.
//
// Usage: node perf/report.ts [raw result files…]   (default: every file in perf/results/raw)
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { cpus, loadavg } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export interface Budget {
  max?: number;
  min?: number;
  note?: string;
}

export interface Budgets {
  warning_at: number;
  budgets: Record<string, Budget>;
}

export interface RawMetric {
  id: string;
  label: string;
  value: number | null;
  unit: string;
  baseline?: boolean;
  details?: unknown;
}

export interface RawFile {
  kind: "node" | "client";
  project?: string;
  started_at: string;
  finished_at: string;
  machine: Record<string, unknown>;
  metrics: RawMetric[];
  info?: Record<string, unknown>;
  config?: Record<string, unknown>;
}

export type Status = "ok" | "warning" | "over" | "missing" | "info";

export interface Classified extends RawMetric {
  status: Status;
  budget?: Budget;
  /** Share of the budget used (value / max), for `max` budgets above zero. */
  ratio?: number;
}

/** ok below `warningAt` of a `max` budget, warning up to 100 %, over above; `min` budgets are met or over. */
export function classify(value: number | null, budget: Budget | undefined, warningAt: number): { status: Status; ratio?: number } {
  if (!budget) return { status: "info" };
  if (value === null || !Number.isFinite(value)) return { status: "missing" };
  if (budget.min !== undefined && value < budget.min) return { status: "over" };
  if (budget.max === undefined) return { status: "ok" };
  if (budget.max === 0) return { status: value <= 0 ? "ok" : "over" };
  const ratio = value / budget.max;
  return { status: ratio > 1 ? "over" : ratio >= warningAt ? "warning" : "ok", ratio };
}

/** Prefix of the metric ids a raw file produces (`node.` or `client.<project>.`). */
const prefixOf = (f: RawFile) => (f.kind === "node" ? "node." : `client.${f.project}.`);

export function evaluate(files: RawFile[], budgets: Budgets): Classified[] {
  const out: Classified[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    for (const m of f.metrics) {
      const budget = budgets.budgets[m.id];
      seen.add(m.id);
      out.push({ ...m, ...classify(m.value, budget, budgets.warning_at), budget });
    }
  }
  // A budget of a benchmark that ran but did not produce the metric (a step failed) is missing.
  const prefixes = files.map(prefixOf);
  for (const [id, budget] of Object.entries(budgets.budgets)) {
    if (!seen.has(id) && prefixes.some((p) => id.startsWith(p))) {
      out.push({ id, label: budget.note ?? id, value: null, unit: "", status: "missing", budget });
    }
  }
  return out;
}

export const failed = (metrics: Classified[]) => metrics.some((m) => m.status === "over" || m.status === "missing");

function fmt(v: number | null | undefined, unit = ""): string {
  if (v === null || v === undefined) return "n/a";
  const n = Number.isInteger(v) ? String(v) : Math.abs(v) >= 100 ? v.toFixed(0) : Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(2);
  return unit && unit !== "count" && unit !== "bool" ? `${n} ${unit}` : n;
}

function budgetText(b: Budget | undefined, unit: string): string {
  if (!b) return "";
  if (b.min !== undefined) return `>= ${fmt(b.min)}`;
  return b.max === undefined ? "" : `<= ${fmt(b.max, unit)}`;
}

export function table(metrics: Classified[]): string {
  const rows = metrics.map((m) => [
    m.status.toUpperCase(),
    m.id,
    fmt(m.value, m.unit),
    budgetText(m.budget, m.unit),
    m.ratio === undefined ? "" : `${Math.round(m.ratio * 100)} %`,
    m.label,
  ]);
  const head = ["status", "metric", "value", "budget", "used", "description"];
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]!.length)));
  const line = (r: string[]) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]!))).join("  ");
  return [line(head), widths.map((w) => "-".repeat(w)).join("  "), ...rows.map(line)].join("\n");
}

function version(cmd: string, args: string[]): string {
  try {
    return execFileSync(cmd, args, { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

function main() {
  const here = dirname(fileURLToPath(import.meta.url));
  const rawDir = join(here, "results/raw");
  const args = process.argv.slice(2);
  const paths = args.length ? args.map((p) => resolve(p)) : readdirSync(rawDir).filter((f) => f.endsWith(".json")).map((f) => join(rawDir, f));
  if (!paths.length) {
    console.error("no raw results: run `just perf` (or perf-node / perf-client) first");
    process.exit(1);
  }
  const files = paths.map((p) => JSON.parse(readFileSync(p, "utf8")) as RawFile);
  const budgets = JSON.parse(readFileSync(join(here, "budgets.json"), "utf8")) as Budgets;
  const metrics = evaluate(files, budgets);
  const budgeted = metrics.filter((m) => m.status !== "info");
  const infos = metrics.filter((m) => m.status === "info" && !m.baseline);
  const baselines = metrics.filter((m) => m.baseline);

  const chromium = files.map((f) => f.machine.chromium).find(Boolean) ?? "not run";
  const machine = {
    cpu: cpus()[0]?.model ?? "unknown",
    cores: cpus().length,
    loadavg_before: Object.fromEntries(files.map((f) => [f.kind === "node" ? "node" : `client-${f.project}`, f.machine.loadavg_before])),
    loadavg_after: loadavg().map((v) => Math.round(v * 100) / 100),
    node: process.version,
    chromium,
    rustc: version("rustc", ["--version"]),
    // fsync=off on the test database makes the node's write latencies optimistic.
    postgres_fsync: files.find((f) => f.kind === "node")?.machine.postgres_fsync ?? null,
  };
  const counts = Object.fromEntries((["ok", "warning", "over", "missing"] as Status[]).map((s) => [s, budgeted.filter((m) => m.status === s).length]));

  console.log(`\ntavrn performance report (budgets: perf/budgets.json)\n`);
  console.log(table(budgeted));
  if (infos.length) console.log(`\nInformational (no budget)\n\n${table(infos)}`);
  if (baselines.length) console.log(`\nBaselines\n\n${table(baselines)}`);
  console.log(`\nMachine: ${machine.cpu}, ${machine.cores} cores, load average before ${JSON.stringify(machine.loadavg_before)}`);
  console.log(`         Node ${machine.node}, Chromium ${machine.chromium}, ${machine.rustc}, PostgreSQL fsync ${machine.postgres_fsync ?? "n/a"}`);
  console.log(`Result:  ${counts.ok} ok, ${counts.warning} warning, ${counts.over} over, ${counts.missing} missing`);

  const generatedAt = new Date().toISOString();
  const outFile = join(here, "results", `${generatedAt.replace(/[:.]/g, "-")}.json`);
  mkdirSync(dirname(outFile), { recursive: true });
  const sources = files.map((f, i) => ({ file: paths[i], kind: f.kind, project: f.project, started_at: f.started_at, finished_at: f.finished_at, config: f.config, info: f.info }));
  writeFileSync(outFile, JSON.stringify({ generated_at: generatedAt, machine, counts, metrics: [...budgeted, ...infos], baselines, sources }, null, 2));
  console.log(`Written: ${outFile}\n`);
  process.exit(failed(metrics) ? 1 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
