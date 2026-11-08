// The Resend source against a fake API shaped like Resend's API reference and OpenAPI (resend.yaml 1.5.1, read 2026-11-02).
import { test } from "node:test";
import assert from "node:assert/strict";
import { RESEND_BASE, resend, resendFromEnv, resendTime } from "../src/sources/resend.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { RE_KEY, ok, list, ago, rec, domain, strong, C } from "./fixtures/rest/resend.ts";

contractSuite(C);

test("resend: timestamps in Resend's format parse; a domain without a DKIM record fails; record values and key names never leave", async () => {
  assert.equal(resendTime("2026-04-08 00:11:13.110779+00"), Date.parse("2026-04-08T00:11:13.110Z"));
  assert.equal(resendTime(null), undefined);
  const rs = await runWith(C, fakeRest(RESEND_BASE, { ...strong(), "/domains/d1": ok(domain("d1", "sagentix.example", "verified", [rec("SPF", "TXT")])) }));
  const d = of(rs, "resend.sending_domains_authenticated");
  assert.equal(d.length, 1);
  assert.equal(d[0].result, "fail");
  assert.match(d[0].detail, /no DKIM record/);
  assert.equal(d[0].resource, "resend domain sagentix.example");
  const all = JSON.stringify(await runWith(C, fakeRest(RESEND_BASE, strong())));
  assert.ok(!all.includes("amazonses") && !all.includes("Alice"));
});

test("resend: follows after= pages; options change the windows", async () => {
  const calls: string[] = [];
  const routes: Routes = { ...strong(),
    "/api-keys": (url) => new URL(`https://x${url}`).searchParams.get("after") === "k1"
      ? list([{ id: "k2", created_at: ago(50), last_used_at: ago(40) }])
      : list([{ id: "k1", created_at: ago(100), last_used_at: ago(1) }], true) };
  let rs = await runWith(C, fakeRest(RESEND_BASE, routes, calls));
  assert.ok(calls.includes("/api-keys?limit=100&after=k1"));
  assert.match(of(rs, "resend.api_keys_in_use")[0].detail, /^2 API key/);
  assert.equal(of(rs, "resend.api_keys_in_use")[0].result, "pass");
  rs = await runWith(C, fakeRest(RESEND_BASE, routes), { opts: { "resend-inactive-days": "30", "resend-key-max-age-days": "60" } });
  assert.equal(of(rs, "resend.api_keys_in_use")[0].result, "fail");
  assert.equal(of(rs, "resend.api_keys_rotated")[0].result, "fail");
});

test("resend: the real client sends GET with a Bearer key and a User-Agent, to api.resend.com only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const api = resendFromEnv({ RESEND_API_KEY: RE_KEY }, (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch);
  assert.ok(typeof api !== "string");
  await api.get("/domains?limit=100");
  assert.equal(seen[0].url, "https://api.resend.com/domains?limit=100");
  assert.equal(seen[0].init.method, "GET");
  const h = seen[0].init.headers as Record<string, string>;
  assert.equal(h.authorization, `Bearer ${RE_KEY}`);
  assert.match(h["user-agent"], /^sagentix-evidence-collector\//);
  assert.equal(typeof resendFromEnv({ RESEND_API_KEY: "sk_wrong" }), "string");
  assert.equal(typeof resendFromEnv({}), "string");
});
