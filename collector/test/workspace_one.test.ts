// The Omnissa Workspace ONE UEM source against a fake API shaped like the MDM API V3 device search and the MDM API V1
// encryption-status references (release 2607 OpenAPI documents). Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGE, encryptionPath, searchPath, workspaceOne, ws1FromEnv } from "../src/sources/workspace_one.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const BASE = "https://as1234.awmdm.com/api";
const SEARCH = "/mdm/devices/search";
const ok = (b: unknown) => res(200, b);
const q = (url: string) => new URL(`https://x${url}`).searchParams;

interface Over { type?: string; os?: string; seen?: string; enroll?: string; compliance?: string; compromised?: boolean; encrypted?: boolean }

function device(n: number, o: Over = {}): Record<string, unknown> {
  return {
    udid: `UDID${n}`, serial_number: `C02WS1000${n}`, mac_address: "aa:bb:cc:dd:ee:ff", imei: "",
    device_friendly_name: "Anna's MacBook Pro", device_reported_name: "Anna-MBP",
    enrollment_user_name: "achao", enrollment_user_email_address: "anna@acme.example",
    ownership: "CORPORATE", platform_name: "Apple macOS", device_type: o.type ?? "APPLE_OS_X", model: "MacBook Pro",
    operating_system: o.os ?? "15.1.0", last_seen: o.seen ?? daysAgo(1), enrollment_status: o.enroll ?? "ENROLLED",
    compliance_status: o.compliance ?? "COMPLIANT", compromised_status: o.compromised ?? false, wifi_ssid: "AcmeCorp",
    Id: { Value: n }, Uuid: `0000000${n}-0000-0000-0000-00000000000${n}`,
  };
}
const uuid = (n: number) => `0000000${n}-0000-0000-0000-00000000000${n}`;
const search = (devs: Record<string, unknown>[], total = devs.length) => ok({ devices: devs, page: 0, page_size: PAGE, total });

function fleet(devs: { n: number; o?: Over }[]): Routes {
  const r: Routes = { [SEARCH]: search(devs.map((d) => device(d.n, d.o))) };
  for (const d of devs) r[encryptionPath(uuid(d.n))] = ok({ encryption_status: d.o?.encrypted ?? true });
  return r;
}
const strong = () => fleet([{ n: 1 }, { n: 2, o: { type: "WINDOWS_PC", os: "10.0.26100.1000" } }]);
const weak = (o: Over) => fleet([{ n: 1 }, { n: 2, o }]);

const C: Contract = {
  source: workspaceOne, clientKey: "workspace_one", base: BASE, prefix: "workspace_one", strong,
  opts: { "workspace-one-min-os": ["macos=14.0", "windows=10.0.22631"] },
  env: { WS1_API_URL: "https://as1234.awmdm.com", WS1_TOKEN_URL: "https://na.uemauth.workspaceone.com/connect/token", WS1_CLIENT_ID: "client-1", WS1_CLIENT_SECRET: "x" },
  rateLimited: { path: SEARCH, check: "enrolled" },
  fails: {
    disk_encryption: weak({ encrypted: false }),
    os_minimum: weak({ os: "13.6.9" }),
    last_seen: weak({ seen: daysAgo(30) }),
    enrolled: weak({ enroll: "PENDING_AGENT" }),
    compliant: weak({ compliance: "NOT_COMPLIANT" }),
    compromised: weak({ compromised: true }),
  },
};

contractSuite(C);

test("workspace_one: GET only the search and encryption-status endpoints; no device name, user, email or SSID reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.equal(calls[0], searchPath(0));
  assert.deepEqual([...new Set(calls.map((c) => c.split("?")[0].replace(/[0-9a-f-]{36}/, "{uuid}")))].sort(), [SEARCH, "/mdm/devices/{uuid}/security/encryption-status"].sort());
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "anna@", "achao", "MacBook", "AcmeCorp", "aa:bb"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "workspace_one.enrolled").map((r) => r.resource), [`workspace one device ${uuid(1)} serial C02WS10001`, `workspace one device ${uuid(2)} serial C02WS10002`]);
});

test("workspace_one: the search pages by 0-based page until total is reached", async () => {
  const calls: string[] = [];
  const devs = Array.from({ length: PAGE + 1 }, (_, i) => device(i + 1));
  const routes: Routes = { [SEARCH]: (url) => (q(url).get("page") === "0" ? search(devs.slice(0, PAGE), PAGE + 1) : search(devs.slice(PAGE), PAGE + 1)) };
  for (const d of devs) routes[encryptionPath(String(d.Uuid))] = ok({ encryption_status: true });
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.deepEqual(calls.filter((c) => c.startsWith(SEARCH)).map((c) => q(c).get("page")), ["0", "1"]);
  assert.ok(calls.filter((c) => c.startsWith(SEARCH)).every((c) => q(c).get("page_size") === String(PAGE)));
  assert.equal(of(rs, "workspace_one.enrolled").length, PAGE + 1);
});

test("workspace_one: --workspace-one-max-devices caps devices and encryption calls, and marks the read incomplete", async () => {
  const calls: string[] = [];
  const routes = fleet([1, 2, 3, 4].map((n) => ({ n })));
  const rs = await runWith(C, fakeRest(BASE, routes, calls), { opts: { "workspace-one-max-devices": "2" } });
  assert.equal(of(rs, "workspace_one.enrolled").length, 2);
  assert.equal(calls.filter((c) => c.endsWith("/encryption-status")).length, 2);
  assert.ok(rs.filter((r) => r.resource.startsWith("workspace one device")).every((r) => r.complete === false));
});

test("workspace_one: missing evidence is skipped, never passed; no --workspace-one-min-os skips os_minimum once", async () => {
  const d = device(1, { compliance: "PENDING_COMPLIANCE_CHECK", enroll: "UNKNOWN" });
  delete d.last_seen; delete d.compromised_status;
  const rs = await runWith(C, fakeRest(BASE, { [SEARCH]: search([d]), [encryptionPath(uuid(1))]: ok({}) }), { opts: { "workspace-one-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "workspace_one.os_minimum").length, 1);
  assert.match(of(rs, "workspace_one.os_minimum")[0].detail, /--workspace-one-min-os/);
});

test("workspace_one: a retired device is skipped, not judged; a 403 on encryption status skips once and stops calling", async () => {
  const calls: string[] = [];
  const routes = fleet([{ n: 1 }, { n: 2 }, { n: 3, o: { enroll: "RETIRED", compliance: "NOT_COMPLIANT" } }]);
  routes[encryptionPath(uuid(1))] = res(403, { errorCode: 406, message: "Passed Device Id is not valid or it's not accessible to the user." });
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.ok(rs.filter((r) => r.resource.includes(uuid(3))).every((r) => r.result === "skipped" && /RETIRED/.test(r.detail)));
  assert.ok(of(rs, "workspace_one.disk_encryption").every((r) => r.result === "skipped"));
  assert.equal(calls.filter((c) => c.endsWith("/encryption-status")).length, 1);
});

test("workspace_one: a rejected token is reported as an error (skipped, HTTP 401), never as a failing device", async () => {
  const rs = await runWith(C, fakeRest(BASE, { [SEARCH]: res(401, { message: "Unauthorized" }) }));
  assert.equal(rs.length, 6);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("workspace_one: the real client posts client credentials to the regional token URL, then sends GET with Bearer and the version header", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    if (url.endsWith("/connect/token")) return new Response(JSON.stringify({ access_token: "ws1-0123456789", token_type: "Bearer", expires_in: 3600 }), { status: 200 });
    return new Response("{\"devices\":[],\"total\":0}", { status: 200 });
  }) as unknown as typeof fetch;
  const api = ws1FromEnv({ WS1_API_URL: "https://as1234.awmdm.com", WS1_TOKEN_URL: "https://emea.uemauth.workspaceone.com/connect/token", WS1_CLIENT_ID: "client-1", WS1_CLIENT_SECRET: "secret-0123456789" }, f);
  assert.ok(typeof api !== "string");
  await api.v3.get(searchPath(0));
  await api.v1.get(encryptionPath(uuid(1)));
  assert.equal(seen[0].url, "https://emea.uemauth.workspaceone.com/connect/token");
  assert.equal(seen[0].init.method, "POST");
  assert.match(String(seen[0].init.body), /grant_type=client_credentials/);
  assert.equal(seen[1].url, `${BASE}${searchPath(0)}`);
  assert.equal(seen[1].init.method, "GET");
  const h1 = seen[1].init.headers as Record<string, string>, h2 = seen[2].init.headers as Record<string, string>;
  assert.equal(h1.authorization, "Bearer ws1-0123456789");
  assert.equal(h1.accept, "application/json;version=3");
  assert.equal(h2.accept, "application/json;version=1");
  assert.equal(seen.length, 3, "one token request serves both clients");
  // The secret only goes to a documented token host, over https.
  for (const bad of ["https://evil.example/connect/token", "http://na.uemauth.workspaceone.com/connect/token"])
    assert.equal(typeof ws1FromEnv({ WS1_API_URL: "https://as1234.awmdm.com", WS1_TOKEN_URL: bad, WS1_CLIENT_ID: "a", WS1_CLIENT_SECRET: "b" }), "string", bad);
  assert.equal(typeof ws1FromEnv({ WS1_API_URL: "http://as1234.awmdm.com", WS1_TOKEN_URL: "https://na.uemauth.workspaceone.com/connect/token", WS1_CLIENT_ID: "a", WS1_CLIENT_SECRET: "b" }), "string");
});
