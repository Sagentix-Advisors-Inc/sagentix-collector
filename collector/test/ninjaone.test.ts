// The NinjaOne source against a fake Public API v2 shaped like NinjaRMM-API-v2.yaml (List devices and the
// computer-systems, volumes, operating-systems and device-health query reports). Fixtures are written by hand from the
// documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGE, contactDate, ninjaone, ninjaoneFromEnv } from "../src/sources/ninjaone.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "./rest_fakes.ts";
import { NOW } from "./helpers.ts";

const BASE = "https://ca.ninjarmm.com";
const DEV = "/v2/devices";
const Q = "/v2/queries";
const ok = (b: unknown) => res(200, b);
const q = (url: string) => new URL(`https://x${url}`).searchParams;
const secsAgo = (days: number) => Math.floor((NOW.getTime() - days * 86_400_000) / 1000);

interface Over { nodeClass?: string; approval?: string; contact?: number; conv?: string; prot?: string; build?: string; osName?: string;
  failed?: number; pending?: number }
interface Dev { id: number; serial: string; o?: Over }

function node(d: Dev): Record<string, unknown> {
  return {
    id: d.id, uid: `uid-${d.id}`, organizationId: 1, locationId: 1, nodeClass: d.o?.nodeClass ?? "WINDOWS_WORKSTATION",
    approvalStatus: d.o?.approval ?? "APPROVED", offline: false, displayName: "Anna's ThinkPad", systemName: "ANNA-T14",
    dnsName: "anna-t14.acme.example", netbiosName: "ANNA-T14", lastContact: d.o?.contact ?? secsAgo(1), lastUpdate: secsAgo(1),
    userData: { owner: "anna@acme.example" }, tags: ["Anna Chao"],
  };
}

/** Routes for a set of devices; each query report is answered in one page plus an empty one behind a cursor. */
function fleet(devs: Dev[]): Routes {
  const list: Route = (url) => {
    const after = q(url).get("after");
    const rows = devs.filter((d) => after === null || d.id > Number(after)).slice(0, Number(q(url).get("pageSize")));
    return ok(rows.map(node));
  };
  const reportOf = (rows: () => unknown[]): Route => (url) =>
    q(url).get("cursor") ? ok({ cursor: { name: "c-1", offset: 1, count: 0, expires: 0 }, results: [] })
      : ok({ cursor: { name: "c-1", offset: 0, count: devs.length, expires: 0 }, results: rows() });
  return {
    [DEV]: list,
    [`${Q}/computer-systems`]: reportOf(() => devs.map((d) => ({ deviceId: d.id, name: "ANNA-T14", serialNumber: d.serial, manufacturer: "LENOVO", domain: "acme" }))),
    [`${Q}/volumes`]: reportOf(() => devs.flatMap((d) => [
      { deviceId: d.id, name: "C:\\", driveLetter: "C:", label: "Windows", bitLockerStatus: { conversionStatus: d.o?.conv ?? "FULLY_ENCRYPTED", protectionStatus: d.o?.prot ?? "PROTECTED", encryptionMethod: "XTS_AES_128", lockStatus: "UNLOCKED" } },
      { deviceId: d.id, name: "D:\\", driveLetter: "D:", label: "USB", bitLockerStatus: { conversionStatus: "FULLY_DECRYPTED", protectionStatus: "UNPROTECTED" } },
    ])),
    [`${Q}/operating-systems`]: reportOf(() => devs.map((d) => ({ deviceId: d.id, name: d.o?.osName ?? "Windows 11 Professional Edition", buildNumber: d.o?.build ?? "26100", releaseId: "24H2", needsReboot: false }))),
    [`${Q}/device-health`]: reportOf(() => devs.map((d) => ({ deviceId: d.id, failedOSPatchesCount: d.o?.failed ?? 0, pendingOSPatchesCount: d.o?.pending ?? 0, healthStatus: "HEALTHY" }))),
  };
}
const strong = () => fleet([{ id: 11, serial: "PF3TEST01" }, { id: 12, serial: "PF3TEST02" }]);
const weak = (o: Over) => fleet([{ id: 11, serial: "PF3TEST01" }, { id: 12, serial: "PF3TEST02", o }]);

const C: Contract = {
  source: ninjaone, clientKey: "ninjaone", base: BASE, prefix: "ninjaone", strong,
  opts: { "ninjaone-min-os": ["windows=10.0.22631"] },
  env: { NINJAONE_URL: BASE, NINJAONE_CLIENT_ID: "client-1", NINJAONE_CLIENT_SECRET: "x" },
  rateLimited: { path: DEV, check: "approved" },
  fails: {
    disk_encryption: weak({ conv: "ENCRYPTION_PAUSED" }),
    os_minimum: weak({ build: "19045" }),
    os_patches: weak({ failed: 2 }),
    last_contact: weak({ contact: secsAgo(30) }),
    approved: weak({ approval: "PENDING" }),
  },
};

contractSuite(C);

test("ninjaone: GET only the five documented endpoints; no display name, owner, user or tag reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.deepEqual([...new Set(calls.map((c) => c.split("?")[0]))].sort(),
    [DEV, `${Q}/computer-systems`, `${Q}/device-health`, `${Q}/operating-systems`, `${Q}/volumes`].sort());
  assert.ok(calls.filter((c) => c.startsWith(`${Q}/volumes`)).every((c) => q(c).get("include") === "bl"));
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "anna", "ANNA", "ThinkPad", "acme.example"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "ninjaone.approved").map((r) => r.resource), ["ninjaone device 11 serial PF3TEST01", "ninjaone device 12 serial PF3TEST02"]);
  assert.ok(rs.every((r) => r.method === "config-read"));
});

test("ninjaone: devices page by the last node id; query reports follow cursor.name until an empty page", async () => {
  const calls: string[] = [];
  const devs = Array.from({ length: PAGE + 3 }, (_, i) => ({ id: i + 1, serial: `SN${i + 1}` }));
  const routes = fleet(devs);
  routes[`${Q}/device-health`] = (url) => {
    const cur = q(url).get("cursor");
    const half = cur === null ? devs.slice(0, PAGE) : cur === "page-2" ? devs.slice(PAGE) : [];
    return ok({ cursor: { name: cur === null ? "page-2" : "page-3" }, results: half.map((d) => ({ deviceId: d.id, failedOSPatchesCount: 0, pendingOSPatchesCount: 0 })) });
  };
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.deepEqual(calls.filter((c) => c.startsWith(`${DEV}?`)).map((c) => q(c).get("after")), [null, String(PAGE), String(PAGE + 3)]);
  assert.deepEqual(calls.filter((c) => c.startsWith(`${Q}/device-health`)).map((c) => q(c).get("cursor")), [null, "page-2", "page-3"]);
  assert.equal(of(rs, "ninjaone.os_patches").length, PAGE + 3);
  assert.ok(of(rs, "ninjaone.os_patches").every((r) => r.result === "pass"));
});

test("ninjaone: servers and network devices are left out unless --ninjaone-include-servers; Macs are skipped for BitLocker", async () => {
  const routes = fleet([{ id: 1, serial: "A1" }, { id: 2, serial: "A2", o: { nodeClass: "WINDOWS_SERVER" } }, { id: 3, serial: "A3", o: { nodeClass: "NMS_SWITCH" } },
    { id: 4, serial: "A4", o: { nodeClass: "MAC", osName: "macOS 15.1" } }]);
  const rs = await runWith(C, fakeRest(BASE, routes), { opts: { "ninjaone-min-os": ["windows=10.0.22631", "macos=15.0"] } });
  assert.deepEqual(of(rs, "ninjaone.approved").map((r) => r.resource.split(" serial")[0]), ["ninjaone device 1", "ninjaone device 4"]);
  const mac = of(rs, "ninjaone.disk_encryption").find((r) => r.resource.includes("device 4"))!;
  assert.equal(mac.result, "skipped");
  assert.match(mac.detail, /BitLocker only/);
  assert.equal(of(rs, "ninjaone.os_minimum").find((r) => r.resource.includes("device 4"))!.result, "pass");
  const withServers = await runWith(C, fakeRest(BASE, routes), { opts: { "ninjaone-include-servers": true } });
  assert.equal(of(withServers, "ninjaone.approved").length, 3);
});

test("ninjaone: missing evidence is skipped, never passed; no --ninjaone-min-os skips os_minimum once", async () => {
  const routes = fleet([{ id: 1, serial: "A1", o: { conv: "UNKNOWN", approval: "DECOMMISSIONED" } }]);
  routes[DEV] = (url) => {
    if (q(url).get("after")) return ok([]);
    const n = node({ id: 1, serial: "A1", o: { approval: "DECOMMISSIONED" } });
    delete n.lastContact;
    return ok([n]);
  };
  routes[`${Q}/device-health`] = ok({ cursor: null, results: [{ deviceId: 1, healthStatus: "UNKNOWN" }] });
  const rs = await runWith(C, fakeRest(BASE, routes), { opts: { "ninjaone-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "ninjaone.os_minimum").length, 1);
  assert.match(of(rs, "ninjaone.os_minimum")[0].detail, /--ninjaone-min-os/);
});

test("ninjaone: a report the client cannot read skips only its check; pending patches above the allowance fail", async () => {
  const routes = weak({ pending: 3 });
  routes[`${Q}/volumes`] = res(403, { error: "forbidden", error_description: "Insufficient scope" });
  const rs = await runWith(C, fakeRest(BASE, routes));
  assert.deepEqual(of(rs, "ninjaone.disk_encryption").map((r) => r.result), ["skipped"]);
  assert.match(of(rs, "ninjaone.disk_encryption")[0].detail, /HTTP 403/);
  assert.ok(of(rs, "ninjaone.approved").every((r) => r.result === "pass"));
  assert.deepEqual(of(rs, "ninjaone.os_patches").map((r) => r.result), ["pass", "fail"]);
  const allowed = await runWith(C, fakeRest(BASE, weak({ pending: 3 })), { opts: { "ninjaone-max-pending-patches": "5" } });
  assert.ok(of(allowed, "ninjaone.os_patches").every((r) => r.result === "pass"));
});

test("ninjaone: a rejected token is reported as an error (skipped, HTTP 401), never as a failing device", async () => {
  const rs = await runWith(C, fakeRest(BASE, { [DEV]: res(401, { error: "invalid_token" }) }));
  assert.equal(rs.length, 5);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("ninjaone: lastContact is read as epoch seconds or milliseconds", () => {
  assert.equal(contactDate(1793190350)?.toISOString(), new Date(1793190350_000).toISOString());
  assert.equal(contactDate(1793190350123)?.toISOString(), new Date(1793190350123).toISOString());
  assert.equal(contactDate(undefined), undefined);
  assert.equal(contactDate(0), undefined);
});

test("ninjaone: the real client asks /ws/oauth/token for the monitoring scope only, then sends GET with Bearer to known instances only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    if (url.endsWith("/ws/oauth/token")) return new Response(JSON.stringify({ access_token: "nj-0123456789", expires_in: 3600, scope: "monitoring", token_type: "Bearer" }), { status: 200 });
    return new Response("[]", { status: 200 });
  }) as unknown as typeof fetch;
  const secret = "secret-0123456789";
  const api = ninjaoneFromEnv({ NINJAONE_URL: "https://eu.ninjarmm.com", NINJAONE_CLIENT_ID: "client-1", NINJAONE_CLIENT_SECRET: secret }, f);
  assert.ok(typeof api !== "string");
  await api.get(DEV);
  assert.equal(seen[0].url, "https://eu.ninjarmm.com/ws/oauth/token");
  assert.equal(seen[0].init.method, "POST");
  const form = new URLSearchParams(String(seen[0].init.body));
  assert.equal(form.get("grant_type"), "client_credentials");
  assert.equal(form.get("scope"), "monitoring");
  assert.equal(seen[1].url, `https://eu.ninjarmm.com${DEV}`);
  assert.equal(seen[1].init.method, "GET");
  assert.equal((seen[1].init.headers as Record<string, string>).authorization, "Bearer nj-0123456789");
  assert.equal(typeof ninjaoneFromEnv({ NINJAONE_URL: "http://eu.ninjarmm.com", NINJAONE_CLIENT_ID: "a", NINJAONE_CLIENT_SECRET: "b" }), "string");
  assert.equal(typeof ninjaoneFromEnv({ NINJAONE_URL: "https://ninja.evil.example", NINJAONE_CLIENT_ID: "a", NINJAONE_CLIENT_SECRET: "b" }), "string");
  // A failed token request names the host and status, never the secret.
  const bad = ninjaoneFromEnv({ NINJAONE_URL: "https://app.ninjarmm.com", NINJAONE_CLIENT_ID: "a", NINJAONE_CLIENT_SECRET: secret },
    (async () => new Response(JSON.stringify({ error: "invalid_client" }), { status: 401 })) as unknown as typeof fetch);
  assert.ok(typeof bad !== "string");
  const r = await bad.get(DEV);
  assert.equal(r.status, 401);
  assert.ok(!JSON.stringify(r).includes(secret));
});
