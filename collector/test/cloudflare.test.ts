// The Cloudflare source against a fake API: one pass and one fail case per check, "skipped" when the
// API refuses, and the OPA sub-source.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cloudflare } from "../src/sources/cloudflare.ts";
import type { CfResponse, CloudflareApi } from "../src/sources/cloudflare/api.ts";
import { DEFAULT_POLICY_DIR, OPA_CHECKS, opaChecks, spawnOpa, type OpaRunner } from "../src/sources/cloudflare/opa.ts";
import type { OptionValue, Result } from "../src/types.ts";
import { ACCOUNT, NOW, ZONE, cannedOpa, errBody, fakeCloudflare, inDays, missingOpa, okBody } from "./helpers.ts";

const Z = `/zones/${ZONE}`, A = `/accounts/${ACCOUNT}`;
const setting = (id: string, value: unknown) => okBody({ id, value });

async function runCf(api: CloudflareApi | null, opts: Record<string, OptionValue> = {}, opa: OpaRunner = missingOpa): Promise<Result[]> {
  return cloudflare.run({ opts, env: {}, clients: { cloudflare: api, opa }, now: NOW, warn: () => {} });
}
const of = (rs: Result[], check: string) => rs.filter((r) => r.check === `cloudflare.${check}`);

// One override per check that turns its pass into a fail.
const FAILS: Record<string, Record<string, CfResponse>> = {
  min_tls_version: { [`${Z}/settings/min_tls_version`]: setting("min_tls_version", "1.0") },
  tls_1_3: { [`${Z}/settings/tls_1_3`]: setting("tls_1_3", "off") },
  always_use_https: { [`${Z}/settings/always_use_https`]: setting("always_use_https", "off") },
  automatic_https_rewrites: { [`${Z}/settings/automatic_https_rewrites`]: setting("automatic_https_rewrites", "off") },
  ssl_mode: { [`${Z}/settings/ssl`]: setting("ssl", "flexible") },
  hsts: { [`${Z}/settings/security_header`]: setting("security_header", { strict_transport_security: { enabled: true, max_age: 86400, include_subdomains: true } }) },
  security_level: { [`${Z}/settings/security_level`]: setting("security_level", "essentially_off") },
  browser_integrity_check: { [`${Z}/settings/browser_check`]: setting("browser_check", "off") },
  dnssec: { [`${Z}/dnssec`]: okBody({ status: "disabled" }) },
  waf_managed_ruleset: { [`${Z}/rulesets/phases/http_request_firewall_managed/entrypoint`]: errBody(404, "not found") },
  waf_custom_rules: { [`${Z}/rulesets/phases/http_request_firewall_custom/entrypoint`]: okBody({ rules: [{ action: "log", enabled: true }, { action: "block", enabled: false }] }) },
  rate_limiting_rules: { [`${Z}/rulesets/phases/http_ratelimit/entrypoint`]: errBody(404, "not found") },
  bot_protection: { [`${Z}/bot_management`]: okBody({ fight_mode: false, sbfm_definitely_automated: "allow" }) },
  leaked_credential_checks: { [`${Z}/leaked-credential-checks`]: okBody({ enabled: false }) },
  edge_certificates_valid: { [`${Z}/ssl/certificate_packs`]: okBody([{ id: "p9", type: "sni_custom", status: "active", certificates: [{ expires_on: inDays(20) }] }]) },
  custom_hostname_min_tls: { [`${Z}/custom_hostnames`]: okBody([{ id: "h1", hostname: "old.customer.test", ssl: { settings: { min_tls_version: "1.0" } } }]) },
  page_shield: { [`${Z}/page_shield`]: okBody({ enabled: false }) },
  security_txt: { [`${Z}/security-center/securitytxt`]: okBody({ enabled: false, contact: [] }) },
  account_enforces_2fa: { [A]: okBody({ id: ACCOUNT, settings: { enforce_twofactor: false } }) },
  members_have_2fa: { [`${A}/members`]: okBody([{ id: "m1", status: "accepted", roles: [], user: { two_factor_authentication_enabled: false } }]) },
  super_admins_limited: { [`${A}/members`]: okBody(["a", "b", "c", "d"].map((id) => ({ id, status: "accepted", roles: [{ name: "Super Administrator - All Privileges" }], user: { two_factor_authentication_enabled: true } }))) },
  audit_log_available: { [`${A}/audit_logs`]: okBody([]) },
  account_tokens_expire: { [`${A}/tokens`]: okBody([{ id: "t2", name: "forever", status: "active" }]) },
  security_notifications: { [`${A}/alerting/v3/policies`]: okBody([{ id: "n2", alert_type: "billing_usage_alert", enabled: true }, { id: "n3", alert_type: "dos_attack_l7", enabled: false }]) },
  access_apps_have_policies: { [`${A}/access/apps/app1/policies`]: okBody([{ id: "p2", decision: "bypass", include: [{ everyone: {} }], require: [] }]) },
  access_mfa_required: { [`${A}/access/apps/app1/policies`]: okBody([{ id: "p3", decision: "allow", include: [{ email_domain: { domain: "example.com" } }], require: [] }]) },
  access_session_duration: { [`${A}/access/apps`]: okBody([{ id: "app1", name: "Admin", type: "self_hosted", domain: "admin.example.com", session_duration: "720h" }]) },
  gateway_dns_filtering: { [`${A}/gateway/rules`]: okBody([{ id: "g2", enabled: true, action: "allow", filters: ["dns"] }]) },
  device_posture_rules: { [`${A}/devices/posture`]: okBody([]) },
  r2_public_access_off: { [`${A}/r2/buckets/logs/domains/managed`]: okBody({ domain: "pub-1.r2.dev", enabled: true }) },
};

test("every API check the source declares has a pass and a fail case here", () => {
  const api = cloudflare.emits.map((c) => c.replace(/^cloudflare\./, ""));
  assert.deepEqual(Object.keys(FAILS).sort(), [...api].sort());
  assert.ok(Object.keys(FAILS).length >= 15);
});

test("a well-configured account passes every API check", async () => {
  const rs = await runCf(fakeCloudflare());
  for (const check of Object.keys(FAILS)) {
    const mine = of(rs, check);
    assert.ok(mine.length >= 1, `${check}: no result`);
    for (const r of mine) assert.equal(r.result, "pass", `${check} [${r.resource}]: ${r.detail}`);
  }
});

for (const [check, over] of Object.entries(FAILS)) {
  test(`${check}: pass on the strong fixture, fail with the observed value when weakened`, async () => {
    const pass = of(await runCf(fakeCloudflare()), check);
    assert.ok(pass.length && pass.every((r) => r.result === "pass"), JSON.stringify(pass));
    const fail = of(await runCf(fakeCloudflare(over)), check);
    assert.ok(fail.some((r) => r.result === "fail"), `${check}: ${JSON.stringify(fail)}`);
    for (const r of fail) assert.ok(r.detail.length > 0 && r.detail.length <= 1000);
  });
}

test("a 403 from the API gives skipped, never pass, for every check", async () => {
  // Zones listable and readable, everything else refused.
  const api: CloudflareApi = {
    async get(path) {
      const p = path.split("?")[0];
      if (p === "/zones" || p === Z) return fakeCloudflare().get(path);
      return errBody(403, "Authentication error");
    },
  };
  const rs = await runCf(api);
  assert.ok(rs.length >= cloudflare.emits.length);
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.ok(rs.every((r) => /HTTP 403/.test(r.detail)), "the detail names the refusal");
});

test("a feature missing from the plan is skipped (Page Shield on Free answers 403)", async () => {
  const rs = await runCf(fakeCloudflare({ [`${Z}/page_shield`]: errBody(403, "This zone is not entitled to use Page Shield") }));
  const ps = of(rs, "page_shield");
  assert.equal(ps.length, 1);
  assert.equal(ps[0].result, "skipped");
  assert.match(ps[0].detail, /not entitled/);
});

test("no security.txt configured (Cloudflare answers success with result \"\") is a fail, not skipped", async () => {
  const rs = await runCf(fakeCloudflare({ [`${Z}/security-center/securitytxt`]: okBody("") }));
  const st = of(rs, "security_txt");
  assert.equal(st.length, 1);
  assert.equal(st[0].result, "fail");
  assert.match(st[0].detail, /no security\.txt is configured/);
});

test("Access independent MFA counts at policy, application or organisation level, and a lower level can turn it off", async () => {
  const noRule = okBody([{ id: "p3", decision: "allow", include: [{ email_domain: { domain: "example.com" } }], require: [] }]);
  const app = (extra: Record<string, unknown>) => okBody([{ id: "app1", name: "Admin", type: "self_hosted", domain: "admin.example.com", session_duration: "8h", ...extra }]);
  const on = { allowed_authenticators: ["security_key", "biometrics"], session_duration: "24h" };
  const org = okBody({ auth_domain: "x.cloudflareaccess.com", mfa_required_for_all_apps: true, mfa_config: on });
  const verdict = async (over: Record<string, CfResponse>) => of(await runCf(fakeCloudflare({ [`${A}/access/apps/app1/policies`]: noRule, ...over })), "access_mfa_required")[0];
  const cases: [string, Record<string, CfResponse>, string][] = [
    ["none set", {}, "fail"],
    ["organisation", { [`${A}/access/organizations`]: org }, "pass"],
    ["application", { [`${A}/access/apps`]: app({ mfa_config: { mfa_disabled: false, ...on } }) }, "pass"],
    ["policy", { [`${A}/access/apps/app1/policies`]: okBody([{ id: "p3", decision: "allow", include: [{ email_domain: { domain: "example.com" } }], require: [], mfa_config: on }]) }, "pass"],
    ["organisation on, application disabled", { [`${A}/access/organizations`]: org, [`${A}/access/apps`]: app({ mfa_config: { mfa_disabled: true } }) }, "fail"],
    ["organisation set but not required for all apps", { [`${A}/access/organizations`]: okBody({ mfa_required_for_all_apps: false, mfa_config: on }) }, "fail"],
  ];
  for (const [name, over, want] of cases) {
    const r = await verdict(over);
    assert.equal(r.result, want, name);
    assert.match(r.detail, /independent MFA/);
  }
});

test("a Gateway DNS block rule passes only while a DNS location or an enrolled device sends queries to Gateway", async () => {
  const none = { [`${A}/gateway/locations`]: okBody([]), [`${A}/devices/physical-devices`]: okBody([]) };
  const verdict = async (over: Record<string, CfResponse>) => of(await runCf(fakeCloudflare(over)), "gateway_dns_filtering")[0];
  const idle = await verdict(none);
  assert.equal(idle.result, "fail");
  assert.match(idle.detail, /filter nothing/);
  assert.equal((await verdict({ ...none, [`${A}/devices/physical-devices`]: okBody([{ id: "dev1" }]) })).result, "pass");
  assert.equal((await verdict({ ...none, [`${A}/gateway/locations`]: okBody([{ id: "l1" }]) })).result, "pass");
  assert.equal((await verdict({ ...none, [`${A}/gateway/locations`]: errBody(403, "forbidden") })).result, "skipped");
});

test("no token: every API check is skipped", async () => {
  const rs = await runCf(null, { zone: [ZONE], account: [ACCOUNT] });
  assert.ok(rs.length >= cloudflare.emits.length);
  for (const r of rs) assert.equal(r.result, "skipped");
});

test("resources name the zone, pack, hostname, app, token and bucket; (check, resource) is unique", async () => {
  const rs = await runCf(fakeCloudflare());
  const res = new Set(rs.map((r) => r.resource));
  for (const want of ["zone example.com", `account ${ACCOUNT}`, "zone example.com certificate pack universal pack1", "custom hostname app.customer.test",
    "access app Admin (admin.example.com)", "api token sagentix-collector-readonly (t1)", "r2 bucket logs"]) assert.ok(res.has(want), want);
  const keys = rs.map((r) => `${r.check}|${r.resource}`);
  assert.equal(new Set(keys).size, keys.length);
});

test("--zone limits the run to that zone and skips the zone list", async () => {
  const calls: string[] = [];
  await runCf(fakeCloudflare({}, calls), { zone: [ZONE] });
  assert.ok(!calls.some((c) => c.split("?")[0] === "/zones"));
  assert.ok(calls.includes(Z));
});

test("the client is only asked to GET paths under the zone, the account or the zone list", async () => {
  const calls: string[] = [];
  await runCf(fakeCloudflare({}, calls));
  assert.ok(calls.length > 30);
  for (const p of calls) assert.match(p, new RegExp(`^/(zones(\\?|$)|zones/${ZONE}|accounts/${ACCOUNT})`));
});

test("the fetch client sends GET with the bearer token and nothing else", async () => {
  const { fetchCloudflareApi } = await import("../src/sources/cloudflare/api.ts");
  const seen: { url: string; init: RequestInit }[] = [];
  const api = fetchCloudflareApi("tok", (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
  }) as unknown as typeof fetch);
  await api.get("/zones");
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, "Bearer tok");
  assert.equal(seen[0].init.body, undefined);
});

test("Enterprise bot management is skipped, not judged", async () => {
  const rs = await runCf(fakeCloudflare({
    [Z]: okBody({ id: ZONE, name: "example.com", account: { id: ACCOUNT }, plan: { legacy_id: "enterprise" } }),
    [`${Z}/bot_management`]: okBody({ fight_mode: false, auto_update_model: true }),
  }));
  assert.equal(of(rs, "bot_protection")[0].result, "skipped");
});

test("a Cloudflare-managed certificate with 20 days left passes; an uploaded one fails", async () => {
  const pack = (type: string) => ({ [`${Z}/ssl/certificate_packs`]: okBody([{ id: "p", type, status: "active", certificates: [{ expires_on: inDays(20) }] }]) });
  assert.equal(of(await runCf(fakeCloudflare(pack("universal"))), "edge_certificates_valid")[0].result, "pass");
  assert.equal(of(await runCf(fakeCloudflare(pack("sni_custom"))), "edge_certificates_valid")[0].result, "fail");
});

test("an account with no Access app, R2 bucket or custom hostname gets skipped for those checks", async () => {
  const rs = await runCf(fakeCloudflare({
    [`${A}/access/apps`]: okBody([]), [`${A}/r2/buckets`]: okBody({ buckets: [] }), [`${Z}/custom_hostnames`]: okBody([]),
  }));
  for (const c of ["access_apps_have_policies", "access_mfa_required", "access_session_duration", "r2_public_access_off", "custom_hostname_min_tls"]) {
    assert.deepEqual(of(rs, c).map((r) => r.result), ["skipped"], c);
  }
});

// ── OPA sub-source ────────────────────────────────────────────────────────────────────────────────

const dir = mkdtempSync(join(tmpdir(), "collector-opa-"));
const zs = (id: string, value: unknown) => ({ address: `module.baseline.cloudflare_zone_setting.${id}`, mode: "managed", type: "cloudflare_zone_setting", name: id,
  values: { zone_id: "z1", setting_id: id, value } });
const hardened = [
  zs("min_tls_version", "1.2"), zs("tls_1_3", "on"), zs("always_use_https", "on"), zs("automatic_https_rewrites", "on"), zs("ssl", "strict"),
  zs("security_header", { strict_transport_security: { enabled: true, max_age: 31536000, include_subdomains: true, nosniff: true, preload: false } }),
  { address: "module.baseline.cloudflare_zone_dnssec.this", mode: "managed", type: "cloudflare_zone_dnssec", name: "this", values: { zone_id: "z1", status: "active" } },
  { address: "module.baseline.cloudflare_ruleset.waf_managed", mode: "managed", type: "cloudflare_ruleset", name: "waf_managed",
    values: { zone_id: "z1", kind: "zone", phase: "http_request_firewall_managed", rules: [{ action: "execute", action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee" }, expression: "true", enabled: true }] } },
];
const statePath = join(dir, "state.json");
writeFileSync(statePath, JSON.stringify({ format_version: "1.0", values: { root_module: { resources: [], child_modules: [{ address: "module.baseline", resources: hardened }] } } }));

test("OPA results carry the API check ids and resource \"tofu <address>\"", async () => {
  const seen: string[][] = [];
  const rs = await opaChecks(cannedOpa([
    { ksi: "KSI-SVC-SIN", rule: "min_tls_version", zone_id: "z1", pass: false, msg: "1.0" },
    { ksi: "KSI-SVC-VRI", rule: "dnssec", zone_id: "z1", pass: true, msg: "active" },
    { ksi: "KSI-SVC-VRI", rule: "dnssec", zone_id: "z2", pass: false, msg: "absent" },
  ], seen), dir, statePath);
  assert.deepEqual(rs.map((r) => [r.check, r.resource, r.result]), [
    ["cloudflare.min_tls_version", "tofu module.baseline.cloudflare_zone_setting.min_tls_version", "fail"],
    ["cloudflare.dnssec", "tofu module.baseline.cloudflare_zone_dnssec.this", "pass"],
    ["cloudflare.dnssec", "tofu zone z2: no cloudflare_zone_dnssec", "fail"],
  ]);
  assert.deepEqual(seen[0], ["eval", "--format", "json", "--data", dir, "--input", statePath, "data.sagentix.cloudflare.checks"]);
});

test("a missing opa binary or state file makes OPA checks skipped, never passed", async () => {
  for (const rs of [
    await opaChecks(missingOpa, DEFAULT_POLICY_DIR, statePath),
    await opaChecks(spawnOpa({ PATH: "/nonexistent" }), DEFAULT_POLICY_DIR, statePath),
    await opaChecks(cannedOpa([]), DEFAULT_POLICY_DIR, join(dir, "absent.json")),
  ]) {
    assert.equal(rs.length, OPA_CHECKS.length);
    for (const r of rs) assert.equal(r.result, "skipped");
  }
  assert.deepEqual(await opaChecks(missingOpa, DEFAULT_POLICY_DIR, undefined), [], "no --tofu-state: OPA is not asked");
});

test("the real opa over the repo's policies passes a hardened state (skipped when opa is absent)", async (t) => {
  const rs = await opaChecks(spawnOpa(), DEFAULT_POLICY_DIR, statePath);
  if (rs.every((r) => r.result === "skipped" && /not on PATH|no OPA policies/.test(r.detail))) return t.skip("opa or the policies are absent");
  assert.equal(rs.length, 8);
  for (const r of rs) {
    assert.equal(r.result, "pass", `${r.check}: ${r.detail}`);
    assert.match(r.resource, /^tofu module\.baseline\.cloudflare_/);
    assert.ok(OPA_CHECKS.includes(r.check));
  }
});

test("the Cloudflare source runs OPA only with --tofu-state and merges its results", async () => {
  const rs = await runCf(fakeCloudflare(), { "tofu-state": statePath, policy: dir }, cannedOpa([{ rule: "hsts", zone_id: "z1", pass: true, msg: "ok" }]));
  assert.ok(rs.some((r) => r.check === "cloudflare.hsts" && r.resource === "tofu module.baseline.cloudflare_zone_setting.security_header"));
  assert.ok(rs.some((r) => r.check === "cloudflare.hsts" && r.resource === "zone example.com"));
});
