// Shared plumbing for the identity and code-hosting sources (Entra ID, Okta, Google Workspace,
// GitHub): a GET-only JSON client, retry on rate limits, pagination, "skipped" details and token
// redaction. The only non-GET request any of these sources makes is the OAuth token request in
// oauth.ts, to the identity provider's token endpoint.

import type { Outcome, Read, Result } from "../types.ts";

export interface HttpResponse {
  status: number;
  /** Lower-cased header names. */
  headers: Record<string, string>;
  body: unknown;
}

/** One GET. `url` is a path under the client's base, or an absolute URL on the same origin (a next-page link). */
export interface RestApi {
  get(url: string): Promise<HttpResponse>;
}

export type Obj = Record<string, unknown>;
export const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
export const str = (v: unknown) => (typeof v === "string" ? v : undefined);
export const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
export const ok = (r: HttpResponse) => r.status >= 200 && r.status < 300;
export const enc = encodeURIComponent;

export type Sleep = (ms: number) => Promise<void>;
export const realSleep: Sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * A GET-only client over fetch. Requests to another origin are refused without sending the
 * credentials, so a next-page link cannot carry the token elsewhere.
 */
export function fetchRest(o: { base: string; headers: () => Promise<Record<string, string>>; fetchFn?: typeof fetch }): RestApi {
  const origin = new URL(o.base).origin;
  const f = o.fetchFn ?? fetch;
  return {
    async get(url: string) {
      const full = /^https?:\/\//i.test(url) ? url : `${o.base}${url}`;
      const target = new URL(full);
      if (target.origin !== origin) return { status: 0, headers: {}, body: { message: `refused a request to ${target.origin}; this client reads ${origin} only` } };
      let auth: Record<string, string>;
      try { auth = await o.headers(); } catch (e) { return { status: 401, headers: {}, body: { message: String((e as Error).message ?? e) } }; }
      const res = await f(full, { method: "GET", headers: { accept: "application/json", ...auth } });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      // Should a response ever echo the credential, it is cut out before anything reads it.
      const secrets = Object.values(auth).flatMap((v) => [v, v.replace(/^(Bearer|SSWS)\s+/i, "")]).filter((s) => s.length >= 8);
      const text = secrets.reduce((t, s) => t.split(s).join("[redacted]"), await res.text());
      let body: unknown = text;
      try { body = text ? JSON.parse(text) : null; } catch { /* keep text */ }
      return { status: res.status, headers, body };
    },
  };
}

const RATE_REASONS = /rateLimitExceeded|userRateLimitExceeded|quotaExceeded|secondary rate limit|API rate limit exceeded/i;

/** True when the answer is a rate limit rather than a refusal. */
export function isRateLimited(r: HttpResponse): boolean {
  if (r.status === 429) return true;
  if (r.status !== 403) return false;
  if (r.headers["x-ratelimit-remaining"] === "0" || r.headers["retry-after"] !== undefined) return true;
  return RATE_REASONS.test(JSON.stringify(r.body ?? "").slice(0, 2000));
}

/** How long to wait before retrying: Retry-After, then Okta's X-Rate-Limit-Reset or GitHub's x-ratelimit-reset (epoch seconds), else exponential. Capped at 60 s. */
export function retryDelayMs(h: Record<string, string>, attempt: number, nowMs: number): number {
  const cap = 60_000;
  const ra = h["retry-after"];
  if (ra !== undefined) {
    const s = Number(ra);
    if (Number.isFinite(s)) return Math.min(cap, Math.max(0, s * 1000));
    const d = Date.parse(ra);
    if (Number.isFinite(d)) return Math.min(cap, Math.max(0, d - nowMs));
  }
  const reset = Number(h["x-rate-limit-reset"] ?? h["x-ratelimit-reset"]);
  if (Number.isFinite(reset) && reset > 0) return Math.min(cap, Math.max(1000, reset * 1000 - nowMs + 1000));
  return Math.min(cap, 1000 * 2 ** attempt);
}

/** Retries a rate-limited GET up to `max` times; a thrown network error becomes status 0. */
export function withRetry(api: RestApi, sleep: Sleep = realSleep, max = 4, now: () => number = Date.now): RestApi {
  return {
    async get(url: string) {
      for (let attempt = 0; ; attempt++) {
        let r: HttpResponse;
        try { r = await api.get(url); } catch (e) { r = { status: 0, headers: {}, body: { message: `request failed: ${String(e)}` } }; }
        if (!isRateLimited(r) || attempt >= max) return r;
        await sleep(retryDelayMs(r.headers, attempt, now()));
      }
    },
  };
}

/** The URL of rel="next" in a Link header (GitHub, Okta). */
export function linkNext(h: Record<string, string>): string | undefined {
  const link = h["link"];
  if (!link) return undefined;
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="?next"?/);
    if (m) return m[1];
  }
  return undefined;
}

/** Why a call gave no usable answer, for a "skipped" detail. */
export function why(r: HttpResponse): string {
  const b = r.body;
  let msg = "";
  if (isObj(b)) {
    const e = b.error;
    if (isObj(e)) msg = String(e.message ?? e.code ?? "");
    else if (typeof e === "string") msg = `${e}${typeof b.error_description === "string" ? `: ${b.error_description}` : ""}`;
    else msg = String(b.errorSummary ?? b.message ?? "");
  } else if (typeof b === "string") msg = b;
  msg = msg.replace(/\s+/g, " ").trim().slice(0, 300);
  const hint = r.status === 401 || r.status === 403
    ? " (the credential may lack the read permission for this call, or the feature is not licensed)"
    : r.status === 429 ? " (rate limited; retries exhausted)" : "";
  return `HTTP ${r.status}${msg ? `: ${msg}` : ""}${hint}`;
}

/**
 * Every item of a paged list. `items` picks the array out of a page; `next` gives the next page's
 * URL or undefined. Returns the first failing response instead when a page cannot be read.
 */
export async function getAll(
  api: RestApi, first: string,
  items: (body: unknown) => unknown[] | undefined,
  next: (r: HttpResponse) => string | undefined,
  maxPages = 100,
): Promise<{ items: unknown[]; truncated: boolean; pages: number } | { error: HttpResponse }> {
  const out: unknown[] = [];
  let url: string | undefined = first;
  for (let page = 0; url; page++) {
    if (page >= maxPages) return { items: out, truncated: true, pages: page };
    const r = await api.get(url);
    const got = ok(r) ? items(r.body) : undefined;
    if (!got) return { error: r };
    out.push(...got);
    url = next(r);
    if (!url) return { items: out, truncated: false, pages: page + 1 };
  }
  return { items: out, truncated: false, pages: 0 };
}

/** What a paged read saw, for the results built from it (format 3): a truncated list makes them incomplete. */
export const listRead = (l: { items?: unknown[]; hosts?: unknown[]; truncated: boolean; pages?: number }): Read =>
  ({ method: "config-read", itemsRead: (l.items ?? l.hosts ?? []).length, ...(l.pages !== undefined ? { pagesRead: l.pages } : {}), complete: !l.truncated });

/** Stamps every result from index `from` on that has no read of its own: one line after the results a list produced. */
export function stampRead(results: Result[], from: number, read: Read): void {
  for (let i = from; i < results.length; i++) if (results[i].method === undefined && results[i].complete === undefined) Object.assign(results[i], read);
}

/** Collects results for one source, one resource at a time. */
export class Emitter<C extends string> {
  results: Result[] = [];
  readonly prefix: string;
  readonly resource: string;
  constructor(prefix: string, resource: string) { this.prefix = prefix; this.resource = resource; }
  add(check: C, result: Outcome, detail: string, resource = this.resource, read?: Read) {
    this.results.push({ ...read, check: `${this.prefix}.${check}`, resource: resource.slice(0, 300), result, detail: detail.slice(0, 1000) });
  }
  skip(check: C, r: HttpResponse, what: string, resource = this.resource) {
    this.add(check, "skipped", `${what} not readable: ${why(r)}`, resource, { method: "config-read", apiError: { status: r.status, message: why(r) } });
  }
  skipAll(checks: readonly C[], detail: string, resource = this.resource) {
    for (const c of checks) this.add(c, "skipped", detail, resource);
  }
}

/** Replaces every secret (8 characters or longer) found in a result with "[redacted]". */
export function redact(results: Result[], secrets: (string | undefined)[]): Result[] {
  const s = secrets.filter((x): x is string => typeof x === "string" && x.length >= 8);
  if (!s.length) return results;
  const clean = (t: string) => s.reduce((acc, x) => acc.split(x).join("[redacted]"), t);
  // Every text a result carries: an API's error message (apiError, format 3) can echo a credential as easily as a detail.
  return results.map((r) => ({ ...r, resource: clean(r.resource), detail: clean(r.detail),
    ...(r.expected !== undefined ? { expected: clean(r.expected) } : {}), ...(r.observed !== undefined ? { observed: clean(r.observed) } : {}),
    ...(r.apiError ? { apiError: { status: r.apiError.status, message: clean(r.apiError.message) } } : {}) }));
}

/** Up to `n` identifiers, for a failing detail. */
export const firstIds = (ids: string[], n = 10) => (ids.length ? ` (${ids.length > n ? `first ${n}: ` : ""}${ids.slice(0, n).join(", ")})` : "");

export const DAY_MS = 86_400_000;
export const intOpt = (v: unknown, dflt: number) => {
  const n = typeof v === "string" ? Number(v) : NaN;
  return Number.isInteger(n) && n >= 0 ? n : dflt;
};
