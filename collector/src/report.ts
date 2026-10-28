// The run report (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 2): what every run did, source by source, so a bug,
// a refused call or a mis-read shows up in sos-app without anyone asking the client for a log. It carries counts,
// timings, the shape of each outbound call (method, host, templated path, status) and the stderr lines, scrubbed;
// never a response body, a request header, a query string or a credential.
//
// Written beside the config as sagentix-run-report.json before it is sent, so the client can read exactly what
// leaves. A send that fails leaves sagentix-pending-report.json, sent first ("late": true) by the next run.

import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { REPORT_PATH, collectorInfo, osInfo, signedPost, writePrivate, type Channel, type Mode, type Runner } from "./channel.ts";

export const REPORT_FORMAT = "sagentix-run-report/1";
export const REPORT_FILE = "sagentix-run-report.json";
export const PENDING_FILE = "sagentix-pending-report.json";
export const MAX_REPORT_BYTES = 512 * 1024;
export const MAX_LOG_LINES = 1000;
export const MAX_LINE = 500;
export const MAX_WARNINGS = 50;

export interface SourceReport {
  name: string; ms: number; pass: number; fail: number; skipped: number;
  error: { message: string; stack: string } | null;
  warnings: string[];
}
/** `deprecation` and `sunset` are the provider's own warning that an endpoint is going (RFC 9745 Deprecation, RFC 8594
 *  Sunset, 2026-10-28): the live API often says so before its documentation does, so the report carries them. */
export interface CallReport { source: string; method: string; host: string; path: string; status: number; count: number; ms: number;
  deprecation?: string; sunset?: string }
export type PushReport = { status: number; runId?: string; error?: string };

export interface RunReport {
  format: typeof REPORT_FORMAT;
  issuedAt: string;
  late: boolean;
  collector: { version: string; commit: string };
  runner: Runner;
  mode: Mode;
  os: { platform: string; release: string; arch: string };
  node: string;
  startedAt: string; endedAt: string; exitCode: number;
  sources: SourceReport[];
  calls: CallReport[];
  pushes: PushReport[];
  log: string[];
}

// ── Scrubbing ─────────────────────────────────────────────────────────────────────────────────────

const SECRET_ENV = /(_TOKEN|_SECRET|_KEY|_PASSWORD|_KEY_JSON)$/;
const PEM = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(-----END [A-Z0-9 ]+-----|$)/g;
const JWT = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
const AUTH = /\b(Bearer|Basic|SSWS)\s+[A-Za-z0-9._~+/=-]{6,}/gi;
const AWS_KEY_ID = /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;

/** The values of the environment's secrets (section 2): names ending _TOKEN, _SECRET, _KEY, _PASSWORD, _KEY_JSON, or SAGENTIX_COLLECTOR_KEY. */
export function envSecrets(env: NodeJS.ProcessEnv): string[] {
  return Object.entries(env)
    .filter(([k, v]) => typeof v === "string" && v.length >= 6 && (SECRET_ENV.test(k) || k === "SAGENTIX_COLLECTOR_KEY"))
    .map(([, v]) => v as string)
    .sort((a, b) => b.length - a.length);   // the longest first, so a secret containing another is cut whole
}

/** Text with every secret value, token shape and email address replaced. */
export function scrubText(text: string, secrets: readonly string[]): string {
  let t = text;
  for (const s of secrets) t = t.split(s).join("<secret>");
  return t.replace(PEM, "<secret>").replace(JWT, "<secret>").replace(AUTH, (_m, scheme: string) => `${scheme} <secret>`)
    .replace(AWS_KEY_ID, "<secret>").replace(EMAIL, "<email>");
}

/** Every string in a value scrubbed (keys are the report's own field names and stay). */
function scrubDeep<T>(v: T, secrets: readonly string[]): T {
  if (typeof v === "string") return scrubText(v, secrets) as T;
  if (Array.isArray(v)) return v.map((x) => scrubDeep(x, secrets)) as T;
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubDeep(x, secrets)])) as T;
  return v;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX20 = /^[0-9a-f]{20,}$/i;
// Base64 or base64url of 20 or more characters with a digit and a letter in it: an id, not a word like
// "deviceManagementConfigurations".
const B64_20 = /^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9+/=_-]{20,}$/;

/** A URL path with its ids replaced by `:id` (numbers, UUIDs, 12-digit account ids, long hex or base64, emails). */
export function templatePath(path: string): string {
  return path.split("?")[0].split("#")[0].split("/").map((seg) => {
    if (!seg) return seg;
    let d = seg;
    try { d = decodeURIComponent(seg); } catch { /* keep it */ }
    return /^\d+$/.test(d) || UUID.test(d) || HEX20.test(d) || B64_20.test(d) || /@/.test(d) ? ":id" : seg;
  }).join("/");
}

// ── Recording ─────────────────────────────────────────────────────────────────────────────────────

/** Everything one run does that goes into its report. */
export class RunRecorder {
  readonly startedAt: Date;
  readonly sources: SourceReport[] = [];
  readonly pushes: PushReport[] = [];
  readonly log: string[] = [];
  private readonly calls = new Map<string, CallReport>();
  private current: SourceReport | undefined;
  private readonly clock: () => number;

  constructor(now: () => Date, clock: () => number = () => performance.now()) {
    this.startedAt = now();
    this.clock = clock;
  }

  /** An err() that also records each line (and, while a source runs, counts it as that source's warning). */
  tee(err: (s: string) => void): (s: string) => void {
    return (s: string) => {
      for (const line of String(s).split("\n")) {
        this.log.push(line);
        if (this.current && this.current.warnings.length < MAX_WARNINGS) this.current.warnings.push(line);
      }
      err(s);
    };
  }

  /** Runs one source's work with its outbound HTTP counted, and its time and warnings recorded. */
  async source<T>(name: string, work: () => Promise<T>): Promise<{ value?: T; error?: unknown; report: SourceReport }> {
    const report: SourceReport = { name, ms: 0, pass: 0, fail: 0, skipped: 0, error: null, warnings: [] };
    this.sources.push(report);
    this.current = report;
    const t0 = this.clock();
    const restore = this.instrumentFetch(name);
    try {
      return { value: await work(), report };
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      report.error = { message: err.message, stack: err.stack ?? "" };
      return { error: e, report };
    } finally {
      restore();
      report.ms = Math.round(this.clock() - t0);
      this.current = undefined;
    }
  }

  /** Warnings that belong to no source (the check-in's), as their own entry. */
  note(name: string, warnings: string[]): void {
    if (warnings.length) this.sources.push({ name, ms: 0, pass: 0, fail: 0, skipped: 0, error: null, warnings: warnings.slice(0, MAX_WARNINGS) });
  }

  /** One outbound call, by its shape only. */
  call(source: string, method: string, url: string, status: number, ms: number, headers?: Headers): void {
    let host = "", path = "";
    try { const u = new URL(url); host = u.host; path = templatePath(u.pathname); } catch { host = "(not a URL)"; }
    const key = `${source}\n${method}\n${host}\n${path}\n${status}`;
    const c = this.calls.get(key) ?? { source, method, host, path, status, count: 0, ms: 0 };
    c.count++; c.ms += Math.round(ms);
    // Dates or "true", never more: a header value is the provider's, but it is cut short all the same.
    const dep = headers?.get("deprecation"), sun = headers?.get("sunset");
    if (dep) c.deprecation = dep.slice(0, 64);
    if (sun) c.sunset = sun.slice(0, 64);
    this.calls.set(key, c);
  }

  callList(): CallReport[] { return [...this.calls.values()]; }

  /** A warning in the source's own list, once per endpoint: the provider retires (410) or plans to retire it. */
  deprecated(source: string, method: string, url: string, status: number, sunset: string | null): void {
    let where = url;
    try { const u = new URL(url); where = `${u.host}${templatePath(u.pathname)}`; } catch { /* the raw string, scrubbed later */ }
    const text = status === 410 ? `provider endpoint gone (HTTP 410): ${method} ${where}`
      : `provider marks this endpoint deprecated${sunset ? `, sunset ${sunset.slice(0, 64)}` : ""}: ${method} ${where}`;
    const s = this.sources.find((x) => x.name === source);
    // The source's entry exists from the moment it starts (source() pushes it first).
    if (s && !s.warnings.includes(text) && s.warnings.length < MAX_WARNINGS) s.warnings.push(text);
  }

  /**
   * Every source reaches the network through the global fetch (the default `fetchFn` of each client, read when the
   * client is built), so wrapping it while one source runs counts that source's calls, and only them.
   */
  private instrumentFetch(source: string): () => void {
    const original = globalThis.fetch;
    if (typeof original !== "function") return () => {};
    const rec = this;
    const wrapped = async function (input: string | URL | Request, init?: RequestInit): Promise<Response> {
      const url = input instanceof Request ? input.url : String(input);
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
      const t0 = rec.clock();
      try {
        const res = await original(input, init);
        rec.call(source, method, url, res.status, rec.clock() - t0, res.headers);
        if (res.headers?.get("deprecation") || res.headers?.get("sunset") || res.status === 410) {
          rec.deprecated(source, method, url, res.status, res.headers?.get("sunset") ?? null);
        }
        return res;
      } catch (e) {
        rec.call(source, method, url, 0, rec.clock() - t0);
        throw e;
      }
    };
    globalThis.fetch = wrapped as typeof fetch;
    return () => { if (globalThis.fetch === wrapped) globalThis.fetch = original; };
  }
}

// ── Building, trimming, sending ───────────────────────────────────────────────────────────────────

export function buildReport(rec: RunRecorder, o: { now: Date; exitCode: number; runner: Runner; mode: Mode; env: NodeJS.ProcessEnv }): RunReport {
  const report: RunReport = {
    format: REPORT_FORMAT,
    issuedAt: o.now.toISOString(),
    late: false,
    collector: collectorInfo(o.env),
    runner: o.runner,
    mode: o.mode,
    os: osInfo(),
    node: process.version,
    startedAt: rec.startedAt.toISOString(), endedAt: o.now.toISOString(), exitCode: o.exitCode,
    sources: rec.sources.map((s) => ({ ...s, warnings: s.warnings.slice(0, MAX_WARNINGS).map((w) => w.slice(0, MAX_LINE)) })),
    calls: rec.callList(),
    pushes: rec.pushes,
    log: rec.log.slice(0, MAX_LOG_LINES).map((l) => l.slice(0, MAX_LINE)),
  };
  if (rec.log.length > MAX_LOG_LINES) report.log[MAX_LOG_LINES - 1] = `(log cut: ${rec.log.length} lines, the first ${MAX_LOG_LINES - 1} kept)`;
  return trimReport(scrubDeep(report, envSecrets(o.env)));
}

const bytes = (r: RunReport) => Buffer.byteLength(JSON.stringify(r, null, 2));

/** At most MAX_REPORT_BYTES: drops log lines first, then calls, then stacks, and says so in a last log line. */
export function trimReport(r: RunReport, max: number = MAX_REPORT_BYTES): RunReport {
  if (bytes(r) <= max) return r;
  const out: RunReport = { ...r, log: [...r.log], calls: [...r.calls], sources: r.sources.map((s) => ({ ...s, error: s.error && { ...s.error } })) };
  const cut: string[] = [];
  const note = () => `(report trimmed to ${max} bytes: ${cut.join(", ")})`;
  const fits = () => bytes({ ...out, log: [...out.log, note()] }) <= max;
  const logs = out.log.length;
  while (out.log.length && !fits()) out.log.splice(Math.floor(out.log.length / 2));
  if (out.log.length < logs) cut.push(`log ${logs} to ${out.log.length} lines`);
  if (!fits()) {
    const calls = out.calls.length;
    out.calls.sort((a, b) => b.count - a.count);
    while (out.calls.length && !fits()) out.calls.splice(Math.floor(out.calls.length / 2));
    cut.push(`calls ${calls} to ${out.calls.length}`);
  }
  if (!fits()) {
    for (const s of out.sources) if (s.error) s.error.stack = "";
    cut.push("stacks removed");
  }
  if (out.log.length >= MAX_LOG_LINES) out.log.pop();
  out.log.push(note());
  return out;
}

/** The report's bytes, as written and as sent. */
export const reportBytes = (r: RunReport) => new TextEncoder().encode(JSON.stringify(r, null, 2) + "\n");

/** HTTP answers that will never accept this body; a pending copy of it would be refused on every later run. */
const PERMANENT = new Set([400, 413]);

/**
 * Writes the report beside the config, then (not on a dry run) sends any pending report first and this one after.
 * Never throws; what happened goes to `log`.
 */
export async function deliverReport(r: RunReport, o: { dry: boolean; channel?: Channel; dir: string; log: (s: string) => void }): Promise<void> {
  const file = join(o.dir, REPORT_FILE), pending = join(o.dir, PENDING_FILE);
  try { writePrivate(file, new TextDecoder().decode(reportBytes(r))); } catch (e) { o.log(`warning: cannot write ${file}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); }
  if (o.dry || !o.channel) return;
  const send = async (body: Uint8Array<ArrayBuffer>): Promise<{ ok: boolean; keep: boolean; why: string }> => {
    try {
      const res = await signedPost(o.channel!, REPORT_PATH, body);
      if (res.status >= 200 && res.status < 300) return { ok: true, keep: false, why: "" };
      return { ok: false, keep: !PERMANENT.has(res.status), why: `HTTP ${res.status}` };
    } catch (e) { return { ok: false, keep: true, why: String((e as Error)?.message ?? e) }; }
  };
  if (existsSync(pending)) {
    let body: Uint8Array<ArrayBuffer> | undefined;
    try { body = new Uint8Array(readFileSync(pending)); } catch { /* unreadable: leave it */ }
    if (body) {
      const s = await send(body);
      if (s.ok || !s.keep) { rmSync(pending, { force: true }); if (!s.ok) o.log(`warning: the report left from an earlier run was refused (${s.why}) and removed`); }
      else o.log(`warning: the report left from an earlier run is still not sent (${s.why}); kept as ${pending}`);
    }
  }
  const s = await send(reportBytes(r));
  if (s.ok) return;
  if (!s.keep) { o.log(`warning: sos-app refused the run report (${s.why}); a copy stays in ${file}`); return; }
  try { writePrivate(pending, new TextDecoder().decode(reportBytes({ ...r, late: true }))); } catch { /* the report file is still there */ }
  o.log(`warning: the run report was not sent (${s.why}); kept as ${pending}, sent first next run`);
}
