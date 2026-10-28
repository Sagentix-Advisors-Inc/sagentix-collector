// The Ivanti Neurons for MDM source against a fake Customer Integration API shaped like the guide's Get Device Details
// and device search examples ({ errors, result }) and the OpenAPI file's field types. Fixtures are written by hand.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGE, detailPath, ivanti_mdm, ivantiMdmFromEnv } from "../src/sources/ivanti_mdm.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "./rest_fakes.ts";

const BASE = "https://mdm.example.com/api/v1";
const DEV = "/device";
const META = "/metadata/tenant";
const SPACE = 23071;
const ok = (result: unknown) => res(200, { errors: null, result });
const q = (url: string) => new URL(`https://x${url}`).searchParams;
const ms = (iso: string) => Date.parse(iso);

interface Over { compliant?: boolean; version?: string; checkin?: string; passcode?: boolean; fde?: boolean; firewall?: boolean; sip?: boolean;
  state?: string; bitlocker?: string | null }
interface Dev { id: number; serial: string; plat: string; o?: Over }

function row(d: Dev): Record<string, unknown> {
  const o = d.o ?? {};
  return {
    id: d.id, guid: `guid-${d.id}`, deviceName: "Anna's MacBook Pro", displayName: "Anna Chao", firstName: "Anna", lastName: "Chao",
    emailAddress: "anna@acme.example", uid: "achao", phoneNumber: "+15555550100", imei: "490154203237518",
    platformType: d.plat, platformVersion: o.version ?? (d.plat === "IOS" ? "18.1" : "15.1"),
    lastCheckin: ms(o.checkin ?? daysAgo(1)), registrationState: o.state ?? "ACTIVE", serialNumber: d.serial,
    complianceState: o.compliant ?? true,
    passcodeCompliant: d.plat === "IOS" ? (o.passcode ?? true) : null,
    passcodeCompliantWithProfiles: d.plat === "IOS" || d.plat === "ANDROID" ? (o.passcode ?? true) : null,
    bitLockerEncryptionStatus: o.bitlocker ?? null, dmPartitionId: SPACE, dmPartitionName: "Default Space",
  };
}
function detail(d: Dev): Record<string, unknown> {
  const o = d.o ?? {};
  return { ...row(d), lastCheckin: daysAgo(1), osxFdeEnabled: o.fde ?? true, osxSystemIntegrityProtectionEnabled: o.sip ?? true,
    osxFirewallSettings: { allowSigned: true, allowSignedApp: true, applicationsList: [], blockAllIncoming: false, enableLogging: true, firewallEnabled: o.firewall ?? true, stealthMode: true } };
}

/** Routes for a device space: tenant metadata, the id-sorted search paged with searchAfterValues, and each Mac's details. */
function space(devs: Dev[], pageSize = PAGE): Routes {
  const sorted = [...devs].sort((a, b) => a.id - b.id);
  const search: Route = (url) => {
    const after = q(url).get("searchAfterValues[0]");
    const rest = after === null ? sorted : sorted.filter((d) => d.id > Number(after));
    return ok({ totalCount: sorted.length, searchResults: rest.slice(0, pageSize).map(row) });
  };
  const r: Routes = { [META]: ok({ defaultDmPartitionId: SPACE, defaultCmPartitionId: 1 }), [DEV]: search };
  for (const d of devs) r[detailPath(String(d.id))] = ok(detail(d));
  return r;
}
const MAC = { id: 101, serial: "C02TEST0001", plat: "OSX" }, IPHONE = { id: 102, serial: "F2LTEST0002", plat: "IOS" };
const strong = () => space([MAC, IPHONE]);
const weakMac = (o: Over) => space([{ ...MAC, o }, IPHONE]);
const weakPhone = (o: Over) => space([MAC, { ...IPHONE, o }]);

const C: Contract = {
  source: ivanti_mdm, clientKey: "ivanti_mdm", base: BASE, prefix: "ivanti_mdm", strong,
  opts: { "ivanti-mdm-min-os": ["osx=14.0", "ios=17.0"] },
  env: { IVANTI_MDM_URL: "https://mdm.example.com", IVANTI_MDM_USERNAME: "collector@acme.example", IVANTI_MDM_PASSWORD: "x" },
  rateLimited: { path: DEV, check: "device_compliant" },
  fails: {
    device_compliant: weakPhone({ compliant: false }),
    disk_encryption: weakMac({ fde: false }),
    os_minimum: weakPhone({ version: "16.7.10" }),
    last_checkin: weakMac({ checkin: daysAgo(30) }),
    passcode_compliant: weakPhone({ passcode: false }),
    firewall: weakMac({ firewall: false }),
    system_integrity: weakMac({ sip: false }),
  },
};

contractSuite(C);

test("ivanti_mdm: GET only, the default space from tenant metadata, id-sorted search; no name, email, phone or IMEI reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.equal(calls[0], META);
  const search = calls.filter((c) => c.startsWith(`${DEV}?`));
  assert.ok(search.every((c) => q(c).get("dmPartitionId") === String(SPACE) && q(c).get("rows") === String(PAGE) && q(c).get("sortFields[0].name") === "id" && q(c).get("sortFields[0].order") === "ASC"));
  // Only the Mac costs a details call.
  assert.deepEqual(calls.filter((c) => /^\/device\/\d+$/.test(c)), ["/device/101"]);
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "anna@", "achao", "Chao", "MacBook", "5555550100", "490154203237518"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "ivanti_mdm.device_compliant").map((r) => r.resource), ["ivanti device 101 serial C02TEST0001", "ivanti device 102 serial F2LTEST0002"]);
  // macOS-only checks report on the Mac only; passcode on the iPhone only.
  assert.deepEqual(of(rs, "ivanti_mdm.firewall").map((r) => r.resource), ["ivanti device 101 serial C02TEST0001"]);
  assert.deepEqual(of(rs, "ivanti_mdm.passcode_compliant").map((r) => r.resource), ["ivanti device 102 serial F2LTEST0002"]);
});

test("ivanti_mdm: search pages with searchAfterValues set to the last id until totalCount is reached", async () => {
  const calls: string[] = [];
  const devs = Array.from({ length: 5 }, (_, i) => ({ id: 200 + i, serial: `SN${i}`, plat: "IOS" }));
  const routes = space(devs, 2);   // a server that answers fewer rows than asked
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.deepEqual(calls.filter((c) => c.startsWith(`${DEV}?`)).map((c) => q(c).get("searchAfterValues[0]")), [null, "201", "203"]);
  assert.equal(of(rs, "ivanti_mdm.device_compliant").length, 5);
  assert.ok(of(rs, "ivanti_mdm.device_compliant").every((r) => r.result === "pass" && r.complete === true));
});

test("ivanti_mdm: --ivanti-mdm-space-id skips tenant metadata; --ivanti-mdm-max-devices caps the read and marks it incomplete", async () => {
  const calls: string[] = [];
  const devs = Array.from({ length: 4 }, (_, i) => ({ id: 300 + i, serial: `SN${i}`, plat: "OSX" }));
  const rs = await runWith(C, fakeRest(BASE, space(devs), calls), { opts: { "ivanti-mdm-space-id": "999", "ivanti-mdm-max-devices": "2" } });
  assert.ok(!calls.includes(META));
  assert.equal(q(calls[0]).get("dmPartitionId"), "999");
  assert.equal(of(rs, "ivanti_mdm.device_compliant").length, 2);
  assert.equal(calls.filter((c) => /^\/device\/\d+$/.test(c)).length, 2);
  assert.ok(of(rs, "ivanti_mdm.device_compliant").every((r) => r.complete === false));
});

test("ivanti_mdm: missing evidence is skipped, never passed; retired devices are not judged; no --ivanti-mdm-min-os skips os_minimum once", async () => {
  const mac = { ...MAC };
  const routes = space([mac, { id: 103, serial: "SN-RETIRED", plat: "IOS", o: { state: "RETIRED", compliant: false } }]);
  routes[DEV] = ok({ totalCount: 2, searchResults: [
    { id: 101, serialNumber: "C02TEST0001", platformType: "OSX", registrationState: "ACTIVE" },
    { ...row({ id: 103, serial: "SN-RETIRED", plat: "IOS", o: { state: "RETIRED", compliant: false } }) },
  ] });
  routes[detailPath("101")] = ok({ id: 101, platformType: "OSX", osxFirewallSettings: {} });
  const rs = await runWith(C, fakeRest(BASE, routes), { opts: { "ivanti-mdm-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.ok(!JSON.stringify(rs).includes("SN-RETIRED"));
  assert.equal(of(rs, "ivanti_mdm.os_minimum").length, 1);
  assert.match(of(rs, "ivanti_mdm.os_minimum")[0].detail, /--ivanti-mdm-min-os/);
  assert.match(of(rs, "ivanti_mdm.passcode_compliant")[0].detail, /no active iOS or Android device/);
  assert.match(of(rs, "ivanti_mdm.device_compliant")[0].detail, /1 retired, wiped or pending/);
});

test("ivanti_mdm: BitLocker status is judged wherever a non-Mac device reports it; UNKNOWN is skipped", async () => {
  const pc = (id: number, bitlocker: string) => ({ id, serial: `PC${id}`, plat: "UNKNOWN", o: { bitlocker } });
  const rs = await runWith(C, fakeRest(BASE, space([pc(1, "FULLY_ENCRYPTED"), pc(2, "PARTIALLY_ENCRYPTED"), pc(3, "NOT_ENCRYPTED"), pc(4, "UNKNOWN")])));
  assert.deepEqual(of(rs, "ivanti_mdm.disk_encryption").map((r) => r.result), ["pass", "fail", "fail", "skipped"]);
  // No Mac and no phone: the platform-bound checks report once for the space.
  assert.deepEqual(of(rs, "ivanti_mdm.firewall").map((r) => [r.result, r.resource]), [["skipped", `ivanti_mdm mdm.example.com space ${SPACE}`]]);
});

test("ivanti_mdm: a 403 on device details skips the Mac checks once, then stops calling; the search checks still judge", async () => {
  const calls: string[] = [];
  const macs = [MAC, { id: 105, serial: "C02TEST0005", plat: "OSX" }];
  const routes = space(macs);
  routes[detailPath("101")] = res(403, { errors: { globalErrors: [{ code: "403", message: "Forbidden" }] }, result: null });
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.equal(calls.filter((c) => /^\/device\/\d+$/.test(c)).length, 1);
  assert.ok(of(rs, "ivanti_mdm.firewall").every((r) => r.result === "skipped" && /HTTP 403/.test(r.detail)));
  assert.ok(of(rs, "ivanti_mdm.device_compliant").every((r) => r.result === "pass"));
});

test("ivanti_mdm: rejected credentials are reported as an error (skipped, HTTP 401), never as failing devices", async () => {
  const rs = await runWith(C, fakeRest(BASE, { [META]: res(401, { errors: { globalErrors: [{ code: "401", message: "Unauthorized" }] } }) }));
  assert.equal(rs.length, 7);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("ivanti_mdm: the password, and its Basic encoding, never reach a result even when the API echoes them", async () => {
  const pw = "Pa55-word-0123456789", user = "collector@acme.example";
  const basic = Buffer.from(`${user}:${pw}`).toString("base64");
  const echo = { get: async () => res(403, { errors: { globalErrors: [{ code: "403", message: `bad ${pw} / Basic ${basic}` }] } }) };
  const rs = await runWith(C, echo, { env: { IVANTI_MDM_PASSWORD: pw } });
  const all = JSON.stringify(rs);
  assert.ok(!all.includes(pw) && !all.includes(basic));
  assert.ok(rs.every((r) => r.result === "skipped"));
});

test("ivanti_mdm: the real client sends GET with Basic credentials to <origin>/api/v1, over https only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("{\"errors\":null,\"result\":{}}", { status: 200 }); }) as unknown as typeof fetch;
  const api = ivantiMdmFromEnv({ IVANTI_MDM_URL: "https://mdm.example.com/", IVANTI_MDM_USERNAME: "u@acme.example", IVANTI_MDM_PASSWORD: "secret-0123456789" }, f);
  assert.ok(typeof api !== "string");
  await api.get(META);
  assert.equal(seen[0].url, `${BASE}${META}`);
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, `Basic ${Buffer.from("u@acme.example:secret-0123456789").toString("base64")}`);
  assert.equal(typeof ivantiMdmFromEnv({ IVANTI_MDM_URL: "http://mdm.example.com", IVANTI_MDM_USERNAME: "a", IVANTI_MDM_PASSWORD: "b" }), "string");
  assert.equal(typeof ivantiMdmFromEnv({ IVANTI_MDM_URL: "https://mdm.example.com", IVANTI_MDM_USERNAME: "a" }), "string");
});
