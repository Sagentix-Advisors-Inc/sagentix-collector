// Health telemetry (apps/sos-app/docs/COLLECTOR_CHANNEL.md, sections 3 and 10): what the collector says about itself and
// each connector, so sos-app can show a connector failing, and notice a collector that stopped, without anyone asking
// the client for a log. Modelled on an enterprise agent's status check-in (per-integration health, an expected
// schedule, the agent's own state).
//
// After every run that is not a dry run, the health of each source is kept beside the run report in
// sagentix-collector.health.json (mode 0600), so a check-in between runs (the resident agent's, every 6 hours) carries
// the last run's state. Nothing here holds a provider's text: counts, statuses, our own codes and hints.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writePrivate, type CheckinOutcome, type Mode, type Runner } from "./channel.ts";
import { classify, dedupe, hintFor, primary, type Diagnostic } from "./diagnostics.ts";
import type { ConnectorStatus, RunRecorder, SourceReport } from "./report.ts";
import type { VaultSummary } from "./deliveries.ts";
import type { Result } from "./types.ts";

export const HEALTH_FILE = "sagentix-collector.health.json";
export const HEALTH_FORMAT = "sagentix-collector-health/1";
export const CHECKIN_FORMAT = "sagentix-checkin/2";
/** The schedule a collector says it keeps, in minutes (SAGENTIX_SCHEDULE_MINUTES overrides): the generated schedules
 *  run once a day; the resident agent checks in every 6 hours (src/agent.ts CHECKIN_MS). */
export const SCHEDULE_ENV = "SAGENTIX_SCHEDULE_MINUTES";
export const DEFAULT_INTERVAL = { agent: 360, cron: 1440, ci: 1440 } as const;
export const MAX_CONNECTORS = 100;

export type VaultState = "ok" | "locked" | "missing";
export type UpdateState = "unknown" | "current" | "pending-restart" | "refused" | "approval-needed" | "notify";
export type ScheduleKind = "agent" | "cron" | "ci";

export interface ConnectorHealth {
  source: string;
  status: ConnectorStatus;
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  results: { pass: number; fail: number; skipped: number };
  calls: number;
  retries: number;
  httpErrors: Record<string, number>;
  error?: Diagnostic;
}

export interface HealthState {
  format: typeof HEALTH_FORMAT;
  updatedAt: string;
  /** Local clock minus sos-app's (its Date header), in ms, from the last answer received. */
  clockSkewMs: number | null;
  lastCheckin: { action: CheckinOutcome["action"]; wrote: boolean; at: string } | null;
  connectors: ConnectorHealth[];
}

export interface AgentHealth {
  uptime: number;
  vault: VaultState;
  clockSkewMs: number | null;
  updateState: UpdateState;
  schedule: { kind: ScheduleKind; intervalMinutes?: number; nextExpectedAt?: string };
}

const empty = (now: Date): HealthState => ({ format: HEALTH_FORMAT, updatedAt: now.toISOString(), clockSkewMs: null, lastCheckin: null, connectors: [] });

/** The health file beside the config, or an empty state when it is missing or not ours. */
export function readHealth(dir: string, now: Date = new Date()): HealthState {
  const file = join(dir, HEALTH_FILE);
  if (!existsSync(file)) return empty(now);
  try {
    const j = JSON.parse(readFileSync(file, "utf8")) as Partial<HealthState>;
    if (j.format !== HEALTH_FORMAT || !Array.isArray(j.connectors)) return empty(now);
    return { ...empty(now), ...j, connectors: j.connectors.slice(0, MAX_CONNECTORS) } as HealthState;
  } catch { return empty(now); }
}

/** Writes the state (0600). Never throws: health is a convenience, a full disk must not end a run. */
export function writeHealth(dir: string, s: HealthState, log?: (s: string) => void): void {
  try { writePrivate(join(dir, HEALTH_FILE), JSON.stringify(s, null, 2) + "\n"); }
  catch (e) { log?.(`warning: cannot write ${join(dir, HEALTH_FILE)}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); }
}

// ── The clock, from sos-app's answers ─────────────────────────────────────────────────────────────

let lastSkew: number | null = null;
/** The skew seen on the last answer of this process, or null. */
export const clockSkew = () => lastSkew;
/** For the tests. */
export const _resetSkew = () => { lastSkew = null; };

/** A fetch that notes the skew between this machine's clock and the Date header of each answer it gets. */
export function observeDate(f: typeof fetch, now: () => Date = () => new Date()): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const res = await f(input, init);
    const d = res.headers?.get?.("date");
    const server = d ? Date.parse(d) : NaN;
    if (Number.isFinite(server)) lastSkew = Math.round(now().getTime() - server);
    return res;
  }) as typeof fetch;
}

// ── Each source's health, after a run ─────────────────────────────────────────────────────────────

/** The diagnostics of one source: what it threw, each refused call behind a skipped result, each deprecated call. */
export function diagnosticsOf(rec: RunRecorder, report: SourceReport, results: readonly Result[]): Diagnostic[] {
  const source = report.name;
  const fails = rec.failures.get(source) ?? [];
  const out: Diagnostic[] = [];
  if (report.error) {
    const thrown = rec.thrown.get(source) ?? new Error(report.error.message);
    const d = classify(thrown, { source });
    // A network fault or a timeout names the call that got no answer.
    const call = d.code === "NETWORK" || d.code === "TIMEOUT" ? fails.find((f) => f.status === 0) : undefined;
    out.push(call ? classify(thrown, { source, method: call.method, url: call.url, status: 0, timedOut: call.timedOut }) : d);
  }
  for (const r of results) {
    if (!r.apiError || !r.check.startsWith(`${source}.`)) continue;
    const st = r.apiError.status;
    const call = fails.find((f) => f.status === st);
    out.push(classify(undefined, { source, check: r.check, status: st, message: r.apiError.message, ...(call ? { method: call.method, url: call.url, timedOut: call.timedOut } : {}) }));
  }
  for (const f of fails) {
    if (f.deprecated || f.status === 410) out.push(classify(undefined, { source, method: f.method, url: f.url, status: f.status, ...(f.deprecated ? { headers: { deprecation: "1" } } : {}) }));
  }
  // Nothing read and nothing refused: the connector has no credential or input to read from.
  if (!out.length && report.pass + report.fail === 0 && report.skipped > 0) {
    out.push({ code: "CONFIG_INVALID", owner: "customer", source, hint: hintFor("CONFIG_INVALID", source), frames: [] });
  }
  return dedupe(out);
}

/** healthy: read and nothing went wrong; degraded: read, with faults; failing: threw, or faults and nothing read;
 *  unconfigured: nothing could be read and nothing was refused (no credential, no input); skipped: nothing at all. */
export function statusOf(report: SourceReport, diagnostics: readonly Diagnostic[]): ConnectorStatus {
  const judged = report.pass + report.fail;
  if (report.error) return "failing";
  if (diagnostics.some((d) => d.code !== "CONFIG_INVALID")) return judged > 0 ? "degraded" : "failing";
  if (judged > 0) return "healthy";
  return report.skipped > 0 ? "unconfigured" : "skipped";
}

/**
 * Sets each named source's v2 fields on its report entry (status, calls, retries, HTTP errors, diagnostics) and
 * returns its connector health, `lastSuccessAt` carried from `previous` when this run did not read it.
 */
export function sourceHealth(rec: RunRecorder, names: readonly string[], results: readonly Result[], now: Date, previous: readonly ConnectorHealth[] = []): ConnectorHealth[] {
  const at = now.toISOString();
  const out: ConnectorHealth[] = [];
  for (const name of names) {
    const report = rec.sources.find((s) => s.name === name);
    if (!report) continue;
    const st = rec.stats.get(name) ?? { calls: 0, retries: 0, httpErrors: 0 };
    const diagnostics = diagnosticsOf(rec, report, results);
    const status = statusOf(report, diagnostics);
    Object.assign(report, { status, calls: st.calls, retries: st.retries, httpErrors: { ...(st.byStatus ?? {}) }, diagnostics });
    const before = previous.find((p) => p.source === name);
    const error = primary(diagnostics);
    out.push({
      source: name, status, lastRunAt: at,
      lastSuccessAt: status === "healthy" || status === "degraded" ? at : before?.lastSuccessAt ?? null,
      results: { pass: report.pass, fail: report.fail, skipped: report.skipped },
      calls: st.calls, retries: st.retries, httpErrors: { ...(st.byStatus ?? {}) }, ...(error ? { error } : {}),
    });
  }
  return out;
}

/** This run's connectors over the earlier state: a source not run this time keeps its last entry. */
export function mergeConnectors(previous: readonly ConnectorHealth[], fresh: readonly ConnectorHealth[]): ConnectorHealth[] {
  const m = new Map(previous.map((c) => [c.source, c]));
  for (const c of fresh) m.set(c.source, c);
  return [...m.values()].slice(0, MAX_CONNECTORS);
}

// ── The check-in's own fields ─────────────────────────────────────────────────────────────────────

/** ok: the vault opened; locked: it is there but could not be read; missing: no vault (none configured, or never set). */
export function vaultState(bridged: boolean, summary: VaultSummary | undefined): VaultState {
  if (!bridged) return "missing";
  if (!summary || summary.error) return "locked";
  return summary.sealKey || summary.entries.length ? "ok" : "missing";
}

/** What the last check-in left: the update this collector is on its way to, or not. */
export function updateStateOf(last: HealthState["lastCheckin"]): UpdateState {
  if (!last) return "unknown";
  switch (last.action) {
    case "none": return "current";
    case "update": return last.wrote ? "pending-restart" : "refused";
    case "approval-needed": return "approval-needed";
    case "notify": return "notify";
    default: return "unknown";
  }
}

export function scheduleOf(mode: Mode, runner: Runner, env: NodeJS.ProcessEnv, now: Date): AgentHealth["schedule"] {
  const kind: ScheduleKind = mode === "agent" ? "agent" : runner === "github" ? "ci" : "cron";
  const given = Number(env[SCHEDULE_ENV]);
  const minutes = Number.isInteger(given) && given >= 5 && given <= 10_080 ? given : DEFAULT_INTERVAL[kind];
  return { kind, intervalMinutes: minutes, nextExpectedAt: new Date(now.getTime() + minutes * 60_000).toISOString() };
}

/** The fields check-in/2 adds to check-in/1: the agent's own health, and each configured connector's last state. */
export function checkinHealth(o: { dir: string; env: NodeJS.ProcessEnv; mode: Mode; runner: Runner; now: Date; vault: VaultState; sources?: readonly string[];
                                   uptime?: number }): { agent: AgentHealth; connectors: ConnectorHealth[] } {
  const state = readHealth(o.dir, o.now);
  const skew = clockSkew() ?? state.clockSkewMs;
  const known = new Map(state.connectors.map((c) => [c.source, c]));
  const names = [...new Set([...(o.sources ?? []), ...known.keys()])];
  const connectors = names.slice(0, MAX_CONNECTORS).map((s): ConnectorHealth => known.get(s)
    ?? { source: s, status: "skipped", lastRunAt: null, lastSuccessAt: null, results: { pass: 0, fail: 0, skipped: 0 }, calls: 0, retries: 0, httpErrors: {} });
  return {
    agent: { uptime: Math.max(0, Math.round(o.uptime ?? process.uptime())), vault: o.vault, clockSkewMs: skew, updateState: updateStateOf(state.lastCheckin),
             schedule: scheduleOf(o.mode, o.runner, o.env, o.now) },
    connectors,
  };
}

/** Keeps what a check-in answered, and the clock skew, for the next check-in's updateState and clockSkewMs. */
export function noteCheckin(dir: string, outcome: CheckinOutcome, now: Date, write = true): void {
  if (!write) return;
  const s = readHealth(dir, now);
  writeHealth(dir, { ...s, updatedAt: now.toISOString(), clockSkewMs: clockSkew() ?? s.clockSkewMs,
                     lastCheckin: { action: outcome.action, wrote: !!outcome.wrote, at: now.toISOString() } });
}

/** After a run: each source's health merged into the file. */
export function noteRun(dir: string, fresh: readonly ConnectorHealth[], now: Date, log?: (s: string) => void): void {
  const s = readHealth(dir, now);
  writeHealth(dir, { ...s, updatedAt: now.toISOString(), clockSkewMs: clockSkew() ?? s.clockSkewMs, connectors: mergeConnectors(s.connectors, fresh) }, log);
}
