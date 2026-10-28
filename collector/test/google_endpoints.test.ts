// The Google endpoint management source against a fake Cloud Identity Devices API shaped like the devices.list
// reference and the cloudidentity v1 discovery document. Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEVICES_BASE, DEVICES_SCOPE, PAGE, devicesPath, googleDevicesFromEnv, googleEndpoints } from "../src/sources/google_endpoints.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const LIST = "/v1/devices";
const ok = (b: unknown) => res(200, b);
const q = (url: string) => new URL(`https://x${url}`).searchParams;

interface Over { type?: string; os?: string; enc?: string; fw?: boolean | null; sync?: string; comp?: string }

function device(n: number, o: Over = {}): Record<string, unknown> {
  const d: Record<string, unknown> = {
    name: `devices/dev${n}`, deviceId: `dev${n}`, serialNumber: `SNGOOG${n}`, deviceType: o.type ?? "MAC_OS", osVersion: o.os ?? "MacOS 15.1.0",
    lastSyncTime: o.sync ?? daysAgo(1), encryptionState: o.enc ?? "ENCRYPTED", compromisedState: o.comp ?? "UNCOMPROMISED",
    hostname: "annas-macbook.acme.example", otherAccounts: ["anna@gmail.com"], wifiMacAddresses: ["aa:bb:cc:dd:ee:ff"], model: "MacBookPro18,1", ownerType: "COMPANY",
  };
  if (o.fw !== null) d.endpointVerificationSpecificAttributes = { additionalSignals: { is_os_native_firewall_enabled: o.fw ?? true, windows_domain_name: "ACME" },
    browserAttributes: [{ chromeProfileId: "anna-profile", chromeBrowserInfo: { browserVersion: "130.0" } }] };
  return d;
}
const page = (devs: Record<string, unknown>[], next?: string) => ok({ devices: devs, ...(next ? { nextPageToken: next } : {}) });
const strong = (): Routes => ({ [LIST]: page([device(1), device(2, { type: "WINDOWS", os: "Windows 10.0.26100" })]) });
const weak = (o: Over): Routes => ({ [LIST]: page([device(1), device(2, o)]) });

const C: Contract = {
  source: googleEndpoints, clientKey: "google_endpoints", base: DEVICES_BASE, prefix: "google_endpoints", strong,
  opts: { "google-endpoints-min-os": ["mac_os=14.0", "windows=10.0.22631"] },
  env: { GOOGLE_SA_KEY_FILE: "/nonexistent/sa.json", GOOGLE_ADMIN_EMAIL: "reader@acme.example" },
  rateLimited: { path: LIST, check: "disk_encryption" },
  fails: {
    disk_encryption: weak({ enc: "NOT_ENCRYPTED" }),
    firewall: weak({ fw: false }),
    os_minimum: weak({ os: "MacOS 13.6.9" }),
    last_sync: weak({ sync: daysAgo(40) }),
    compromised: weak({ comp: "COMPROMISED" }),
  },
};

contractSuite(C);

test("google_endpoints: one documented list call for my_customer with the USER_ASSIGNED_DEVICES view; no hostname, account or MAC reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(DEVICES_BASE, strong(), calls));
  assert.deepEqual(calls, [devicesPath("my_customer")]);
  assert.equal(q(calls[0]).get("customer"), "customers/my_customer");
  assert.equal(q(calls[0]).get("view"), "USER_ASSIGNED_DEVICES");
  assert.equal(q(calls[0]).get("pageSize"), String(PAGE));
  const all = JSON.stringify(rs);
  for (const s of ["anna", "aa:bb", "ACME", "MacBookPro"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "google_endpoints.firewall").map((r) => r.resource), ["google device dev1 serial SNGOOG1", "google device dev2 serial SNGOOG2"]);
});

test("google_endpoints: pages follow nextPageToken; GOOGLE_CUSTOMER_ID names the customer", async () => {
  const calls: string[] = [];
  const routes: Routes = { [LIST]: (url) => (q(url).get("pageToken") === "p2" ? page([device(3)]) : page([device(1), device(2)], "p2")) };
  const rs = await runWith(C, fakeRest(DEVICES_BASE, routes, calls), { env: { GOOGLE_CUSTOMER_ID: "C01abc234" } });
  assert.deepEqual(calls.map((c) => q(c).get("pageToken")), [null, "p2"]);
  assert.ok(calls.every((c) => q(c).get("customer") === "customers/C01abc234"));
  assert.equal(of(rs, "google_endpoints.disk_encryption").length, 3);
});

test("google_endpoints: --google-endpoints-max-devices caps the pages read and marks the read incomplete", async () => {
  const calls: string[] = [];
  const many = Array.from({ length: PAGE }, (_, i) => device(i + 1));
  const routes: Routes = { [LIST]: (url) => page(many, `t${Number(q(url).get("pageToken")?.slice(1) ?? 0) + 1}`) };
  const rs = await runWith(C, fakeRest(DEVICES_BASE, routes, calls), { opts: { "google-endpoints-max-devices": "150" } });
  assert.equal(calls.length, 2);
  assert.equal(of(rs, "google_endpoints.disk_encryption").length, 150);
  assert.ok(of(rs, "google_endpoints.disk_encryption").every((r) => r.complete === false));
});

test("google_endpoints: missing evidence is skipped, never passed; no --google-endpoints-min-os skips os_minimum once", async () => {
  const d = device(1, { enc: "UNSUPPORTED_BY_DEVICE", fw: null, comp: "COMPROMISED_STATE_UNSPECIFIED", type: "IOS", os: "iOS 18.1" });
  delete d.lastSyncTime;
  const rs = await runWith(C, fakeRest(DEVICES_BASE, { [LIST]: page([d]) }), { opts: { "google-endpoints-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "google_endpoints.os_minimum").length, 1);
  assert.match(of(rs, "google_endpoints.firewall")[0].detail, /not an Endpoint Verification device/);
  // A floor for another platform does not judge this one.
  const rs2 = await runWith(C, fakeRest(DEVICES_BASE, { [LIST]: page([d]) }));
  assert.match(of(rs2, "google_endpoints.os_minimum")[0].detail, /no --google-endpoints-min-os floor for IOS/);
});

test("google_endpoints: a delegation without the devices scope is reported as an error (skipped, HTTP 403) naming the scope", async () => {
  const rs = await runWith(C, fakeRest(DEVICES_BASE, { [LIST]: res(403, { error: { code: 403, message: "Request had insufficient authentication scopes.", status: "PERMISSION_DENIED" } }) }));
  assert.equal(rs.length, 5);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 403/); assert.ok(r.detail.includes(DEVICES_SCOPE)); }
});

test("google_endpoints: the real client signs a delegation assertion for the devices scope only and sends GET with Bearer", async () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dir = mkdtempSync(join(tmpdir(), "collector-gendpoints-"));
  const keyFile = join(dir, "sa.json");
  writeFileSync(keyFile, JSON.stringify({ type: "service_account", client_email: "c@p.iam.gserviceaccount.com", private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString() }));
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    if (url === "https://oauth2.googleapis.com/token") return new Response(JSON.stringify({ access_token: "ya29.0123456789", expires_in: 3600 }), { status: 200 });
    return new Response("{\"devices\":[]}", { status: 200 });
  }) as unknown as typeof fetch;
  const api = googleDevicesFromEnv({ GOOGLE_SA_KEY_FILE: keyFile, GOOGLE_ADMIN_EMAIL: "reader@acme.example" }, f);
  assert.ok(typeof api !== "string");
  await api.get(devicesPath("my_customer"));
  assert.equal(seen[0].init.method, "POST");
  const assertion = new URLSearchParams(String(seen[0].init.body)).get("assertion")!;
  const claims = JSON.parse(Buffer.from(assertion.split(".")[1], "base64url").toString());
  assert.equal(claims.scope, DEVICES_SCOPE);
  assert.equal(claims.sub, "reader@acme.example");
  assert.equal(seen[1].url, `${DEVICES_BASE}${devicesPath("my_customer")}`);
  assert.equal(seen[1].init.method, "GET");
  assert.equal((seen[1].init.headers as Record<string, string>).authorization, "Bearer ya29.0123456789");
  // A key file pointing its token_uri elsewhere is refused; the browser sign-in path says why it cannot be used.
  const bad = join(dir, "bad.json");
  writeFileSync(bad, JSON.stringify({ client_email: "c@p", private_key: "x", token_uri: "https://evil.example/token" }));
  assert.match(String(googleDevicesFromEnv({ GOOGLE_SA_KEY_FILE: bad, GOOGLE_ADMIN_EMAIL: "a@b" })), /token_uri/);
  assert.match(String(googleDevicesFromEnv({ GOOGLE_OAUTH_CLIENT_FILE: "c.json" })), /service-account path/);
});
