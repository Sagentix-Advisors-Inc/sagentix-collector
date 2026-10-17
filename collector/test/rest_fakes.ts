// Fakes and a shared contract suite for the REST-based sources (Entra ID, Okta, Google Workspace,
// GitHub). Nothing here touches the network.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { HttpResponse, RestApi } from "../src/sources/readonly_http.ts";
import type { OptionValue, Result, Source } from "../src/types.ts";
import { NOW } from "./helpers.ts";

export const res = (status: number, body: unknown, headers: Record<string, string> = {}): HttpResponse => ({ status, headers, body });
export type Route = HttpResponse | ((url: string, n: number) => HttpResponse);
export type Routes = Record<string, Route>;

/**
 * A fake read-only API. A route is keyed by the exact relative URL (with query) or by its path; a
 * function route gets the URL and how many times its key was asked. Absolute URLs under `base` are
 * made relative. Every URL asked is recorded in `calls`.
 */
export function fakeRest(base: string, routes: Routes, calls: string[] = []): RestApi {
  const counts = new Map<string, number>();
  return {
    async get(url: string) {
      const rel = url.startsWith(base) ? url.slice(base.length) : url;
      calls.push(rel);
      const key = rel in routes ? rel : rel.split("?")[0];
      const r = routes[key];
      const n = (counts.get(key) ?? 0) + 1;
      counts.set(key, n);
      if (r === undefined) return res(404, { message: `no fake for ${rel}` });
      return typeof r === "function" ? r(rel, n) : r;
    },
  };
}

export const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

export interface Contract {
  source: Source;
  clientKey: string;
  base: string;
  prefix: string;
  strong: () => Routes;
  /** One override per check that turns its pass into a fail. */
  fails: Record<string, Routes>;
  opts?: Record<string, OptionValue>;
  env?: Record<string, string>;
  /** A route to answer 429 once, and the check whose result must still pass. */
  rateLimited: { path: string; check: string };
}

export async function runWith(c: Contract, api: RestApi | null, extra: { opts?: Record<string, OptionValue>; env?: Record<string, string>; waits?: number[] } = {}): Promise<Result[]> {
  const waits = extra.waits ?? [];
  return c.source.run({
    opts: { ...(c.opts ?? {}), ...(extra.opts ?? {}) }, env: { ...(c.env ?? {}), ...(extra.env ?? {}) },
    clients: { [c.clientKey]: api, sleep: async (ms: number) => { waits.push(ms); } },
    now: NOW, warn: () => {},
  });
}

export const of = (rs: Result[], id: string) => rs.filter((r) => r.check === id);

/** The tests every REST source must pass. */
export function contractSuite(c: Contract): void {
  const api = (over: Routes = {}, calls: string[] = []) => fakeRest(c.base, { ...c.strong(), ...over }, calls);
  const name = c.source.name;

  test(`${name}: every check the source declares has a fail case`, () => {
    assert.deepEqual(Object.keys(c.fails).map((k) => `${c.prefix}.${k}`).sort(), [...c.source.emits].sort());
  });

  test(`${name}: a well-configured system passes every check`, async () => {
    const rs = await runWith(c, api());
    for (const id of c.source.emits) {
      const mine = of(rs, id);
      assert.ok(mine.length >= 1, `${id}: no result`);
      for (const r of mine) assert.equal(r.result, "pass", `${id} [${r.resource}]: ${r.detail}`);
    }
    for (const r of rs) assert.ok(c.source.emits.includes(r.check), `undeclared ${r.check}`);
    const keys = rs.map((r) => `${r.check}|${r.resource}`);
    assert.equal(new Set(keys).size, keys.length, "(check, resource) is unique");
  });

  for (const [check, over] of Object.entries(c.fails)) {
    test(`${name}.${check}: fail with the observed value when weakened`, async () => {
      const fail = of(await runWith(c, api(over)), `${c.prefix}.${check}`);
      assert.ok(fail.some((r) => r.result === "fail"), JSON.stringify(fail));
      for (const r of fail) assert.ok(r.detail.length > 0 && r.detail.length <= 1000 && r.resource.length <= 300);
    });
  }

  test(`${name}: a 403 on every call gives skipped, never pass`, async () => {
    const rs = await runWith(c, { get: async () => res(403, { message: "Forbidden" }) });
    assert.ok(rs.length >= c.source.emits.length);
    for (const id of c.source.emits) assert.ok(of(rs, id).length >= 1, `${id}: no result`);
    for (const r of rs) {
      assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
      assert.match(r.detail, /HTTP 403|not shown|not given/);
    }
  });

  test(`${name}: no client gives skipped for every check`, async () => {
    const rs = await runWith(c, null);
    for (const id of c.source.emits) assert.ok(of(rs, id).length >= 1, id);
    for (const r of rs) assert.equal(r.result, "skipped");
  });

  test(`${name}: a 429 is retried after the advertised wait`, async () => {
    const strong = c.strong();
    const orig = strong[c.rateLimited.path];
    assert.ok(orig, `no strong route ${c.rateLimited.path}`);
    const waits: number[] = [];
    const rs = await runWith(c, fakeRest(c.base, {
      ...strong,
      [c.rateLimited.path]: (url, n) => (n === 1 ? res(429, { message: "Too Many Requests" }, { "retry-after": "2" }) : typeof orig === "function" ? orig(url, n - 1) : orig),
    }), { waits });
    assert.ok(waits.includes(2000), `waits ${JSON.stringify(waits)}`);
    for (const r of of(rs, `${c.prefix}.${c.rateLimited.check}`)) assert.equal(r.result, "pass", r.detail);
  });

  test(`${name}: a 429 that never clears ends as skipped after bounded retries`, async () => {
    const waits: number[] = [];
    const rs = await runWith(c, { get: async () => res(429, {}, { "retry-after": "1" }) }, { waits });
    for (const r of rs) assert.equal(r.result, "skipped");
    assert.ok(waits.length > 0 && waits.every((w) => w <= 60_000));
  });

  test(`${name}: a secret echoed by the API never reaches a result`, async () => {
    const secret = "SECRET-0123456789-abcdef";
    const echo: RestApi = { get: async (u) => res(403, { message: `bad credential ${secret} for ${u}`, error: { message: `token ${secret}` } }) };
    const env = Object.fromEntries(Object.keys(c.env ?? {}).map((k) => [k, k.match(/SECRET|TOKEN/) ? secret : (c.env ?? {})[k]]));
    const rs = await runWith(c, echo, { env });
    const secretVars = Object.keys(env).filter((k) => env[k] === secret);
    if (secretVars.length) assert.ok(!JSON.stringify(rs).includes(secret), "the secret leaked into a result");
  });
}
