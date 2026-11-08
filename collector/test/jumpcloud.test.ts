// The JumpCloud source against a fake JumpCloud API shaped like the v1 and v2 OpenAPI references
// (docs.jumpcloud.com, read 2026-10-20). Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGE, SYSTEM_FIELDS, USER_FIELDS, jumpcloud, jumpcloudFromEnv, systemsPath, usersPath } from "../src/sources/jumpcloud.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { BASE, ORG, ok, v1, settings, user, policy, system, strong, withUser, withSystem, withPw, C, type U, type S } from "./fixtures/rest/jumpcloud.ts";

contractSuite(C);

test("jumpcloud: asks only for the listed user and system fields, sorted by _id; no name, email or hostname reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  const u = new URL(`https://x${calls.find((c) => c.startsWith("/systemusers"))}`).searchParams;
  assert.equal(u.get("fields"), USER_FIELDS);
  assert.equal(u.get("sort"), "_id");
  assert.equal(new URL(`https://x${calls.find((c) => c.startsWith("/systems?"))}`).searchParams.get("fields"), SYSTEM_FIELDS);
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "achao", "anna.chao", "annas-macbook", "Acme", "it@acme"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "jumpcloud.device_encrypted").map((r) => r.resource), ["jumpcloud system s1 serial C02TEST0001", "jumpcloud system s2 serial PF3TEST2"]);
  assert.equal(of(rs, "jumpcloud.users_mfa_enrolled")[0].resource, `jumpcloud org ${ORG}`);
  // The suspended user is reported, not judged; a disabled policy is not judged.
  assert.match(of(rs, "jumpcloud.users_mfa_enrolled")[0].detail, /2 of 2 active user\(s\) enrolled .*1 staged or suspended user\(s\) not judged/);
  assert.match(of(rs, "jumpcloud.policies_require_mfa")[0].detail, /^2 enabled allow/);
  for (const c of calls) assert.ok(!/[\s]/.test(c), c);
});

test("jumpcloud: v1 lists page by skip until totalCount; v2 lists until a short page", async () => {
  const calls: string[] = [];
  const first = Array.from({ length: PAGE }, (_, i) => user(`u${i}`));
  const routes: Routes = {
    ...strong(),
    "/systemusers": (url) => (new URL(`https://x${url}`).searchParams.get("skip") === "0" ? v1(first, PAGE + 1) : v1([user("u999", { required: false })], PAGE + 1)),
    "/v2/authn/policies": (url) => (new URL(`https://x${url}`).searchParams.get("skip") === "0" ? ok(Array.from({ length: PAGE }, (_, i) => policy(`p${i}`))) : ok([policy("pz", { mfa: false })])),
  };
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.deepEqual(calls.filter((c) => c.startsWith("/systemusers")), [usersPath(0), usersPath(PAGE)]);
  assert.equal(calls.filter((c) => c.startsWith("/v2/authn/policies")).length, 2);
  assert.match(of(rs, "jumpcloud.users_mfa_required")[0].detail, /100 of 101 active user\(s\).*u999/);
  assert.equal(of(rs, "jumpcloud.policies_require_mfa")[0].result, "fail");
});

test("jumpcloud: --jumpcloud-max-devices caps the systems read", async () => {
  const calls: string[] = [];
  const many = Array.from({ length: PAGE }, (_, i) => system(`s${i}`, `SN${i}`));
  const rs = await runWith(C, fakeRest(BASE, { ...strong(), "/systems": v1(many, 5000) }, calls), { opts: { "jumpcloud-max-devices": "100" } });
  assert.deepEqual(calls.filter((c) => c.startsWith("/systems?")), [systemsPath(0)]);
  assert.equal(of(rs, "jumpcloud.device_encrypted").length, PAGE);
  assert.match(of(rs, "jumpcloud.device_encrypted")[0].detail, /only the first 100 devices read/);
});

test("jumpcloud: a 401 (bad or expired API key) is skipped with the status, never failed", async () => {
  const rs = await runWith(C, { get: async () => res(401, { message: "Unauthorized" }) });
  assert.ok(rs.length >= 10);
  for (const r of rs) { assert.equal(r.result, "skipped", r.check); assert.match(r.detail, /HTTP 401/); }
});

test("jumpcloud: missing evidence is skipped, never passed; no --jumpcloud-min-os skips device_os_minimum once", async () => {
  const s = system("s1", "C02TEST0001", { contact: null });
  delete (s as Record<string, unknown>).fde;
  const u = { _id: "u1", state: "ACTIVATED" };
  const rs = await runWith(C, fakeRest(BASE, {
    ...strong(), "/systems": v1([s]), "/systemusers": v1([u]), "/v2/authn/policies": ok([]),
    [`/organizations/${ORG}`]: ok({ _id: ORG, settings: {} }), [`/v2/organizations/${ORG}/administratorlinks`]: res(403, { message: "Forbidden" }),
  }), { opts: { "jumpcloud-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "jumpcloud.device_os_minimum").length, 1);
  assert.match(of(rs, "jumpcloud.device_os_minimum")[0].detail, /--jumpcloud-min-os/);
});

test("jumpcloud: a per-user gap covered by an enabled User Portal policy is skipped, not failed or passed", async () => {
  const rs = await runWith(C, fakeRest(BASE, { ...strong(), ...withUser({ required: false }) }));
  const r = of(rs, "jumpcloud.users_mfa_required")[0];
  assert.equal(r.result, "skipped");
  assert.match(r.detail, /1 enabled User Portal polic\(ies\) require MFA/);
  assert.ok(!r.detail.includes("anna.chao@"), "a policy name's email address is cut out");
});

test("jumpcloud: an API key that sees several organizations needs --jumpcloud-org-id; with it, x-org-id names the org", async () => {
  const two = { ...strong(), "/organizations": v1([{ _id: ORG }, { _id: "6230a0d26a4e4bc86c6b36f2" }]) };
  const rs = await runWith(C, fakeRest(BASE, two));
  for (const c of ["admin_mfa_required", "password_policy", "account_lockout", "admins_limited"]) {
    assert.equal(of(rs, `jumpcloud.${c}`)[0].result, "skipped");
    assert.match(of(rs, `jumpcloud.${c}`)[0].detail, /--jumpcloud-org-id/);
  }
  const calls: string[] = [];
  const named = await runWith(C, fakeRest(BASE, two, calls), { opts: { "jumpcloud-org-id": ORG } });
  assert.ok(!calls.includes("/organizations?limit=10"));
  assert.equal(of(named, "jumpcloud.password_policy")[0].result, "pass");
  const bad = await runWith(C, fakeRest(BASE, two), { opts: { "jumpcloud-org-id": "not-an-id" } });
  for (const r of bad) { assert.equal(r.result, "skipped"); assert.match(r.detail, /24 hexadecimal/); }
});

test("jumpcloud: the real client sends GET with x-api-key (and x-org-id) to the region's API, and the key never reaches a result", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const key = "jca_0123456789abcdefSECRET";
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ message: `key ${key} has no access` }), { status: 403 });
  }) as unknown as typeof fetch;
  const api = jumpcloudFromEnv({ JUMPCLOUD_API_KEY: key }, { region: "eu", orgId: ORG }, f);
  assert.ok(typeof api !== "string");
  const r = await api.get("/systems?limit=1");
  assert.equal(seen[0].url, "https://console.eu.jumpcloud.com/api/systems?limit=1");
  assert.equal(seen[0].init.method, "GET");
  const h = seen[0].init.headers as Record<string, string>;
  assert.equal(h["x-api-key"], key);
  assert.equal(h["x-org-id"], ORG);
  assert.ok(!JSON.stringify(r.body).includes(key));
  assert.equal(typeof jumpcloudFromEnv({}, {}), "string");
  assert.equal(typeof jumpcloudFromEnv({ JUMPCLOUD_API_KEY: key }, { region: "mars" }), "string");
  const rs = await runWith(C, { get: async () => res(403, { message: `bad key ${key}` }) }, { env: { JUMPCLOUD_API_KEY: key } });
  assert.ok(!JSON.stringify(rs).includes(key));
});
