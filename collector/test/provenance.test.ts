// How a result was read (format sagentix-collect/3; sos-app migration 0040): pages read, whether the list was whole,
// and the call that failed. sos-app does not count a pass from an incomplete read, so the collector must say so.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Emitter, getAll, listRead, redact, stampRead, type HttpResponse, type RestApi } from "../src/sources/readonly_http.ts";
import { getAll as cfGetAll, type CloudflareApi } from "../src/sources/cloudflare/api.ts";
import { vet } from "../src/payload.ts";
import type { Result } from "../src/types.ts";

const page = (n: number, next?: string): HttpResponse => ({ status: 200, headers: {}, body: { items: Array.from({ length: n }, (_, i) => i), next } });

test("getAll counts the pages it read and says when it stopped before the end", async () => {
  const api: RestApi = { get: async (u) => (u === "p1" ? page(2, "p2") : u === "p2" ? page(2, "p3") : page(1)) };
  const whole = await getAll(api, "p1", (b) => (b as { items: unknown[] }).items, (r) => (r.body as { next?: string }).next);
  assert.deepEqual(whole, { items: [0, 1, 0, 1, 0], truncated: false, pages: 3 });
  const cut = await getAll(api, "p1", (b) => (b as { items: unknown[] }).items, (r) => (r.body as { next?: string }).next, 2);
  assert.deepEqual(cut, { items: [0, 1, 0, 1], truncated: true, pages: 2 });
  assert.deepEqual(listRead(cut as { items: unknown[]; truncated: boolean; pages: number }), { method: "config-read", itemsRead: 4, pagesRead: 2, complete: false });
});

test("Cloudflare's paged list says it was cut at 40 pages instead of stopping silently", async () => {
  const full = (p: number): { status: number; body: unknown } => ({ status: 200, body: { success: true, result: Array(50).fill({}), result_info: { total_pages: 99, page: p } } });
  const api: CloudflareApi = { get: async (path) => full(Number(/page=(\d+)/.exec(path)![1])) } as CloudflareApi;
  const r = await cfGetAll(api, "/zones", 50, 40);
  assert.ok(!("error" in r));
  assert.equal(r.truncated, true);
  assert.equal(r.pages, 40);
  const short: CloudflareApi = { get: async () => ({ status: 200, body: { success: true, result: [{}], result_info: { total_pages: 1 } } }) } as CloudflareApi;
  assert.deepEqual(await cfGetAll(short, "/zones"), { items: [{}], truncated: false, pages: 1 });
});

test("a skipped result carries the failed call, and stampRead marks only the results a list produced", () => {
  const out = new Emitter<"a" | "b">("x", "org 1");
  out.add("a", "pass", "before the list");
  const from = out.results.length;
  out.skip("b", { status: 403, headers: {}, body: { message: "forbidden" } }, "users");
  out.add("a", "pass", "from the list", "user 2");
  stampRead(out.results, from, { method: "config-read", itemsRead: 7, complete: false });
  assert.equal(out.results[0].complete, undefined);
  assert.deepEqual(out.results[1].apiError, { status: 403, message: "HTTP 403: forbidden (the credential may lack the read permission for this call, or the feature is not licensed)" });
  assert.equal(out.results[1].complete, undefined, "a result with its own read keeps it");
  assert.equal(out.results[2].complete, false);
});

test("the provenance fields reach the payload, and a secret in an API error is redacted", () => {
  const secret = "SECRET-0123456789-abcdef";
  const rs: Result[] = [{ check: "cloudflare.dnssec", resource: "zone a", result: "skipped", detail: "no", apiError: { status: 401, message: `bad token ${secret}` },
                          expected: "active", observed: `x ${secret}` }];
  const clean = redact(rs, [secret]);
  assert.ok(!JSON.stringify(clean).includes(secret));
  const vetted = vet(clean, new Map([["cloudflare.dnssec", {} as never]])).results[0];
  assert.deepEqual(vetted.apiError, { status: 401, message: "bad token [redacted]" });
  assert.equal(vetted.expected, "active");
});
