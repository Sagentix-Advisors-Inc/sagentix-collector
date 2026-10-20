// The Defender for Endpoint source against a fake api.security.microsoft.com, shaped like the machine,
// deviceavinfo, machinesVulnerabilities and recommendation reference pages (read 2026-10-20). Fixtures are
// written by hand from the documented field names and example responses.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFENDER_BASE, DEFENDER_SCOPE, defenderChecks, defenderFromEnv, defender_endpoint } from "../src/sources/defender_endpoint.ts";
import { withRetry } from "../src/sources/readonly_http.ts";
import { NOW } from "./helpers.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const ok = (b: unknown) => res(200, b);
const page = (value: unknown[], next?: string) => ok({ value, ...(next ? { "@odata.nextLink": next } : {}) });
const M = "/api/machines";
const AV = "/api/deviceavinfo";
const V = "/api/vulnerabilities/machinesVulnerabilities";
const R = "/api/recommendations";
const TAMPER_ID = "sca-_-tamper-example";

/** computerDnsName and the IP addresses come back (no $select); they are here to prove they never reach a result. */
function machines(): Record<string, unknown>[] {
  return [
    { id: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", computerDnsName: "annas-laptop.acme.example", osPlatform: "Windows11", onboardingStatus: "Onboarded",
      healthStatus: "Active", lastSeen: daysAgo(1), exposureLevel: "Low", lastIpAddress: "172.17.230.209", lastExternalIpAddress: "167.220.196.71", machineTags: ["Bob Smith"] },
    { id: "30a8fa2826abf24d24379b23f8a44d471f00feab", computerDnsName: "bob-macbook.acme.example", osPlatform: "macOS", onboardingStatus: "Onboarded",
      healthStatus: "Active", lastSeen: daysAgo(2), exposureLevel: "Medium", lastIpAddress: "10.0.0.8" },
  ];
}
function avRows(): Record<string, unknown>[] {
  return [
    { id: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", machineId: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", computerDnsName: "annas-laptop", osKind: "windows",
      avMode: "0", avIsSignatureUpToDate: "True", avIsEngineUpToDate: "True", avIsPlatformUpToDate: "True", lastSeenTime: daysAgo(1), rbacGroupName: "Laptops" },
    { id: "30a8fa2826abf24d24379b23f8a44d471f00feab", machineId: "30a8fa2826abf24d24379b23f8a44d471f00feab", computerDnsName: "bob-macbook", osKind: "mac",
      avMode: "0", avIsSignatureUpToDate: "True", avIsEngineUpToDate: "True", avIsPlatformUpToDate: "True", lastSeenTime: daysAgo(2) },
  ];
}
const tamperRec = (exposed: number, status = "Active") => ({ id: TAMPER_ID, recommendationName: "Turn on Tamper Protection", recommendationCategory: "SecurityControls",
  status, exposedMachinesCount: exposed, totalMachineCount: 2 });
const otherRec = { id: "sca-_-scid-91", recommendationName: "Turn on Microsoft Defender Antivirus", recommendationCategory: "SecurityControls", status: "Active", exposedMachinesCount: 0 };

function strong(): Routes {
  return {
    [M]: page(machines()),
    [AV]: page(avRows()),
    [V]: page([]),
    [R]: page([otherRec, tamperRec(0)]),
  };
}
const withMachine = (i: number, change: (m: Record<string, unknown>) => void): Routes => {
  const ms = machines(); change(ms[i]); return { [M]: page(ms) };
};
const withAv = (i: number, change: (m: Record<string, unknown>) => void): Routes => {
  const rs = avRows(); change(rs[i]); return { [AV]: page(rs) };
};

const C: Contract = {
  source: defender_endpoint, clientKey: "defender_endpoint", base: DEFENDER_BASE, prefix: "defender_endpoint", strong,
  env: { DEFENDER_TENANT_ID: "tenant-1", DEFENDER_CLIENT_ID: "app-1", DEFENDER_CLIENT_SECRET: "x" },
  rateLimited: { path: AV, check: "av_signatures_current" },
  fails: {
    device_onboarded: withMachine(1, (m) => { m.onboardingStatus = "CanBeOnboarded"; }),
    sensor_healthy: withMachine(0, (m) => { m.healthStatus = "Inactive"; }),
    av_active_mode: withAv(1, (r) => { r.avMode = "1"; }),
    av_signatures_current: withAv(0, (r) => { r.avIsSignatureUpToDate = "False"; }),
    high_exposure_devices: withMachine(1, (m) => { m.exposureLevel = "High"; }),
    critical_vulnerability_devices: { [V]: page([{ id: "x", cveId: "CVE-2016-3348", machineId: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", fixingKbId: "3185911", severity: "Critical" }]) },
    tamper_protection: { [R]: page([tamperRec(1)]), [`${R}/${TAMPER_ID}/machineReferences`]: page([{ id: "30a8fa2826abf24d24379b23f8a44d471f00feab", computerDnsName: "bob-macbook" }]) },
  },
};

contractSuite(C);

test("defender_endpoint: no device name, IP address or tag reaches a result; devices are named by machine id", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(DEFENDER_BASE, { ...strong(), ...C.fails.tamper_protection }, calls));
  const all = JSON.stringify(rs);
  for (const s of ["annas", "bob-macbook", "acme.example", "172.17", "167.220", "10.0.0.8", "Bob Smith", "Laptops"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "defender_endpoint.sensor_healthy").map((r) => r.resource),
    ["defender device 1e5bc9d7e413ddd7902c2932e418702b84d0cc07", "defender device 30a8fa2826abf24d24379b23f8a44d471f00feab"]);
  const tp = of(rs, "defender_endpoint.tamper_protection")[0];
  assert.equal(tp.result, "fail"); assert.match(tp.detail, /30a8fa2826abf24d24379b23f8a44d471f00feab/);
  // Every request is a GET under /api, with the documented filters.
  assert.ok(calls.every((c) => c.startsWith("/api/")));
  assert.ok(calls.includes(`${V}?$filter=severity%20eq%20'Critical'&$top=10000&$skip=0`), calls.join("\n"));
  assert.ok(calls.includes(`${R}?$filter=recommendationCategory%20eq%20'SecurityControls'&$top=10000&$skip=0`));
});

test("defender_endpoint: antivirus pages follow @odata.nextLink", async () => {
  const calls: string[] = [];
  const [a, b] = avRows();
  const routes = { ...strong(), [AV]: (_u: string, n: number) => (n === 1 ? page([a], `${DEFENDER_BASE}${AV}?$skiptoken=abc`) : page([b])) };
  const rs = await runWith(C, fakeRest(DEFENDER_BASE, routes, calls));
  assert.ok(calls.includes(`${AV}?$skiptoken=abc`));
  assert.equal(of(rs, "defender_endpoint.av_signatures_current").length, 2);
});

test("defender_endpoint: machine pages use $top and $skip while a page comes back full, and --defender-max-devices caps the list", async () => {
  const ms = [...machines(), { ...machines()[0], id: "c3", lastSeen: daysAgo(3) }];
  const calls: string[] = [];
  const routes: Routes = { ...strong(), [M]: (u: string) => {
    const q = new URL(`https://x${u}`).searchParams, top = Number(q.get("$top")), skip = Number(q.get("$skip"));
    return page(ms.slice(skip, skip + top));
  } };
  const api = withRetry(fakeRest(DEFENDER_BASE, routes, calls), async () => {});
  const o = { seenDays: 14, maxExposure: 0, maxDevices: 10_000, allowPassive: false, pageSize: 2 };
  let rs = await defenderChecks(api, "tenant-1", o, NOW);
  assert.deepEqual(calls.filter((c) => c.startsWith(M)), [`${M}?$top=2&$skip=0`, `${M}?$top=2&$skip=2`]);
  assert.equal(of(rs, "defender_endpoint.device_onboarded").length, 3);
  rs = await defenderChecks(api, "tenant-1", { ...o, maxDevices: 2 }, NOW);
  const onb = of(rs, "defender_endpoint.device_onboarded");
  assert.equal(onb.length, 2); assert.match(onb[0].detail, /capped at 2/);
  // A capped list cannot show the High-exposure count is within the limit.
  assert.equal(of(rs, "defender_endpoint.high_exposure_devices")[0].result, "skipped");
});

test("defender_endpoint: passive mode fails unless --defender-allow-passive; Disabled always fails; Other is skipped", async () => {
  const rows = avRows();
  rows[0].avMode = "5"; rows[1].avMode = "2";
  const extra = { ...avRows()[0], machineId: "m3", id: "m3", avMode: "3" };
  const routes = { ...strong(), [AV]: page([...rows, extra]) };
  const on = (rs: Awaited<ReturnType<typeof runWith>>, id: string) => of(rs, "defender_endpoint.av_active_mode").find((r) => r.resource.endsWith(id))!;
  let rs = await runWith(C, fakeRest(DEFENDER_BASE, routes));
  assert.equal(on(rs, "1e5bc9d7e413ddd7902c2932e418702b84d0cc07").result, "fail");
  assert.match(on(rs, "1e5bc9d7e413ddd7902c2932e418702b84d0cc07").detail, /PassiveAudit/);
  rs = await runWith(C, fakeRest(DEFENDER_BASE, routes), { opts: { "defender-allow-passive": true } });
  assert.equal(on(rs, "1e5bc9d7e413ddd7902c2932e418702b84d0cc07").result, "pass");
  assert.equal(on(rs, "30a8fa2826abf24d24379b23f8a44d471f00feab").result, "fail");
  assert.equal(on(rs, "m3").result, "skipped");
});

test("defender_endpoint: missing evidence is skipped, never passed", async () => {
  const ms = machines();
  ms[0].onboardingStatus = "InsufficientInfo";
  ms[1].healthStatus = "Unknown";
  const av = avRows();
  av[0].avIsEngineUpToDate = "Unknown";
  const rs = await runWith(C, fakeRest(DEFENDER_BASE, { ...strong(), [M]: page(ms), [AV]: page(av), [R]: page([otherRec]) }));
  const one = (c: string) => of(rs, `defender_endpoint.${c}`);
  assert.equal(one("device_onboarded").find((r) => r.resource.endsWith("0cc07"))!.result, "skipped");
  assert.equal(one("sensor_healthy").length, 1);   // only the onboarded machine
  assert.equal(one("sensor_healthy")[0].result, "skipped");
  assert.equal(one("av_signatures_current").find((r) => r.resource.endsWith("0cc07"))!.result, "skipped");
  assert.equal(one("tamper_protection")[0].result, "skipped");
  // A stale last report fails even when healthStatus says Active.
  const rs2 = await runWith(C, fakeRest(DEFENDER_BASE, withMachine(0, (m) => { m.lastSeen = daysAgo(30); })));
  const stale = of(rs2, "defender_endpoint.sensor_healthy").find((r) => r.resource.endsWith("0cc07"))!;
  assert.equal(stale.result, "fail"); assert.match(stale.detail, /30 day\(s\) ago, at most 14/);
});

test("defender_endpoint: --defender-max-exposure sets how many devices may be exposed", async () => {
  const vulns = page([
    { id: "a", machineId: "m1", severity: "Critical", fixingKbId: null },
    { id: "b", machineId: "m1", severity: "Critical", fixingKbId: "5034441" },
    { id: "c", machineId: "m2", severity: "Critical", fixingKbId: null },
  ]);
  let rs = await runWith(C, fakeRest(DEFENDER_BASE, { ...strong(), [V]: vulns }), { opts: { "defender-max-exposure": "2" } });
  const v = of(rs, "defender_endpoint.critical_vulnerability_devices")[0];
  assert.equal(v.result, "pass"); assert.match(v.detail, /^2 device\(s\).*\(1 of them fixed by a Microsoft update/);
  rs = await runWith(C, fakeRest(DEFENDER_BASE, { ...strong(), [V]: vulns }), { opts: { "defender-max-exposure": "1" } });
  assert.equal(of(rs, "defender_endpoint.critical_vulnerability_devices")[0].result, "fail");
});

test("defender_endpoint: a 404 from the machine list means no recent machine, not a failure", async () => {
  const rs = await runWith(C, fakeRest(DEFENDER_BASE, { ...strong(), [M]: res(404, { error: { code: "NotFound", message: "no machines" } }) }));
  for (const c of ["device_onboarded", "sensor_healthy", "high_exposure_devices"]) {
    const r = of(rs, `defender_endpoint.${c}`);
    assert.equal(r.length, 1); assert.equal(r[0].result, "skipped"); assert.match(r[0].detail, /lists no machine/);
  }
});

test("defender_endpoint: a token or licence refusal is reported as skipped, never as a failing device", async () => {
  const rs = await runWith(C, fakeRest(DEFENDER_BASE, {
    [M]: res(401, { error: { code: "Unauthorized", message: "Access token has expired." } }),
    [AV]: res(403, { error: { code: "Forbidden", message: "Missing application roles." } }),
    [V]: res(403, { error: { code: "Forbidden", message: "Missing application roles." } }),
    [R]: res(403, { error: { code: "Forbidden", message: "Missing application roles." } }),
  }));
  assert.equal(rs.length, 7);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 40[13]/); }
});

test("defender_endpoint: credentials come from DEFENDER_* or fall back to ENTRA_*; the token asks for the Defender audience", async () => {
  assert.equal(typeof defenderFromEnv({}), "string");
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return url.includes("login.microsoftonline.com") ? new Response(JSON.stringify({ access_token: "at-0123456789", expires_in: 3600 }), { status: 200 }) : new Response("{\"value\":[]}", { status: 200 });
  }) as unknown as typeof fetch;
  const api = defenderFromEnv({ ENTRA_TENANT_ID: "t1", ENTRA_CLIENT_ID: "c1", ENTRA_CLIENT_SECRET: "s-0123456789" }, f);
  assert.ok(typeof api !== "string");
  await api.get(M);
  assert.match(seen[0].url, /login\.microsoftonline\.com\/t1\/oauth2\/v2\.0\/token/);
  assert.equal(seen[0].init.method, "POST");
  assert.equal(new URLSearchParams(String(seen[0].init.body)).get("scope"), DEFENDER_SCOPE);
  assert.equal(seen[1].url, `${DEFENDER_BASE}${M}`);
  assert.equal(seen[1].init.method, "GET");
  assert.equal((seen[1].init.headers as Record<string, string>).authorization, "Bearer at-0123456789");
  // DEFENDER_* wins over ENTRA_*.
  const api2 = defenderFromEnv({ DEFENDER_TENANT_ID: "t2", ENTRA_TENANT_ID: "t1", ENTRA_CLIENT_ID: "c1", ENTRA_CLIENT_SECRET: "s-0123456789" }, f);
  assert.ok(typeof api2 !== "string");
  await api2.get(M);
  assert.match(seen[2].url, /\/t2\/oauth2/);
});
