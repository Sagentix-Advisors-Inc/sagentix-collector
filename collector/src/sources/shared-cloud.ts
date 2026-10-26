// Helpers shared by the AWS, Azure, GCP, Jira and LMS sources: option lists, retry with backoff on
// throttling, a result builder, and a scrubber that keeps secret values out of every detail.

import type { OptionValue, Outcome, Result } from "../types.ts";
import { redact } from "./readonly_http.ts";

export type Obj = Record<string, unknown>;
export const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
export const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
export const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
export const j = (v: unknown): string => JSON.stringify(v);

/** A repeatable or comma-separated option as a list of non-empty strings. */
export const list = (v: OptionValue): string[] =>
  (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);

export const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface HttpReply { status: number; headers: Record<string, string>; body: string }

export interface RetryOptions {
  /** Attempts in all, the first included (default 5). */
  attempts?: number;
  /** First backoff in ms, doubled each time (default 500). */
  baseMs?: number;
  /** Longest single wait in ms (default 20000). */
  maxMs?: number;
  sleep?: (ms: number) => Promise<void>;
  /** True when this reply means "slow down" (default: 429 or 503). */
  throttled?: (r: HttpReply) => boolean;
}

/** Retry-After as seconds or an HTTP date, in ms; undefined when absent or unreadable. */
export function retryAfterMs(headers: Record<string, string>, now = Date.now()): number | undefined {
  const v = headers["retry-after"] ?? headers["Retry-After"];
  if (!v) return undefined;
  if (/^\d+(\.\d+)?$/.test(v.trim())) return Number(v) * 1000;
  const t = Date.parse(v);
  return Number.isFinite(t) ? Math.max(0, t - now) : undefined;
}

/**
 * Calls `send` until it gives a reply that is not throttled, or the attempts run out (then the last
 * throttled reply is returned, and the caller turns it into "skipped"). A thrown error is a reply
 * with status 0.
 */
export async function withRetry(send: () => Promise<HttpReply>, o: RetryOptions = {}): Promise<HttpReply> {
  const attempts = o.attempts ?? 5, base = o.baseMs ?? 500, max = o.maxMs ?? 20_000;
  const sleep = o.sleep ?? realSleep;
  const throttled = o.throttled ?? ((r: HttpReply) => r.status === 429 || r.status === 503);
  let last: HttpReply = { status: 0, headers: {}, body: "" };
  for (let i = 0; i < attempts; i++) {
    try { last = await send(); } catch (e) { last = { status: 0, headers: {}, body: `request failed: ${String(e)}` }; }
    if (!throttled(last)) return last;
    if (i < attempts - 1) await sleep(Math.min(max, retryAfterMs(last.headers) ?? base * 2 ** i));
  }
  return last;
}

/** Collects results for one source; checks are named without the source prefix. */
export class Results<C extends string> {
  readonly results: Result[] = [];
  readonly prefix: string;
  constructor(prefix: string) { this.prefix = prefix; }
  add(check: C, resource: string, result: Outcome, detail: string): void {
    this.results.push({ check: `${this.prefix}.${check}`, resource: resource.slice(0, 300), result, detail: detail.slice(0, 1000) });
  }
  skip(check: C, resource: string, detail: string): void { this.add(check, resource, "skipped", detail); }
  skipAll(checks: readonly C[], resource: string, detail: string): void { for (const c of checks) this.skip(c, resource, detail); }
}

/** Every check skipped for one resource and reason (no credentials, scope unknown). */
export const allSkipped = (prefix: string, checks: readonly string[], resource: string, reason: string): Result[] =>
  checks.map((c) => ({ check: `${prefix}.${c}`, resource, result: "skipped" as const, detail: reason }));

/**
 * Replaces every occurrence of a secret (credential values read from the environment) in resources
 * and details with "[redacted]". Values shorter than 8 characters are ignored, so a short common
 * string never blanks out ordinary words.
 */
export function scrub(results: Result[], secrets: (string | undefined)[]): Result[] {
  return redact(results, secrets);   // one implementation: it also cleans format 3's apiError, expected and observed
}

/** Days between an ISO timestamp and now; undefined when it does not parse. */
export function ageDays(iso: string | undefined, now: Date): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? (now.getTime() - t) / 86_400_000 : undefined;
}

/** Short reason for a refused or failed call, for a "skipped" detail. Never echoes request headers. */
export function httpWhy(r: HttpReply, message?: string): string {
  const hint = r.status === 401 || r.status === 403 ? " (the identity may lack the read permission for this call)" : "";
  const m = (message ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
  return `HTTP ${r.status}${m ? `: ${m}` : ""}${hint}`;
}

/** Whether a port range (inclusive) contains any of the given ports. */
export const rangeHits = (from: number, to: number, ports: readonly number[]) => ports.filter((p) => p >= from && p <= to);
export const ADMIN_PORTS = [22, 3389] as const;
