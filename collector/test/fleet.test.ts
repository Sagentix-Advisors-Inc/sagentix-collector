// The Fleet source against a fake REST API shaped like Fleet's docs (docs/REST API/rest-api.md,
// "List hosts"). Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fleet, fleetFromEnv, PAGE } from "../src/sources/fleet.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { BASE, ok, pol, hosts, hostRoute, withHost, setPolicy, C } from "./fixtures/rest/fleet.ts";

contractSuite(C);

test("fleet: no hostname, computer name, display name, end user or email reaches a result; hosts are named by id and serial", async () => {
  const rs = await runWith(C, fakeRest(BASE, C.strong()));
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "anna", "Bob", "DESKTOP-BOB", "MacBook-Pro", "acme.example"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual([...new Set(of(rs, "fleet.disk_encryption").map((r) => r.resource))], ["fleet host 1 serial C02TEST0001", "fleet host 2 serial PF3TEST0002"]);
  // A policy unrelated to every check (Gatekeeper, failing) changes nothing.
  assert.ok(rs.every((r) => r.result === "pass"));
});

test("fleet: an email inside a policy name is cut out of the detail", async () => {
  const rs = await runWith(C, fakeRest(BASE, withHost(0, (h) => { (h.policies as { name: string }[])[0].name = "Screen lock (owner anna.chao@acme.example)"; })));
  const r = of(rs, "fleet.screen_lock").find((x) => x.resource.includes("host 1"))!;
  assert.match(r.detail, /\[email\]/);
  assert.ok(!r.detail.includes("acme.example"));
});

test("fleet: hosts are read page by page with policies populated until a short page", async () => {
  const calls: string[] = [];
  const many = Array.from({ length: PAGE }, (_, i) => ({ ...hosts()[0], id: 100 + i, hardware_serial: `SN${100 + i}` }));
  const routes: Routes = { "/hosts": (url) => (new URL(`https://x${url}`).searchParams.get("page") === "0" ? hostRoute(many) : hostRoute([hosts()[1]])) };
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.equal(calls.length, 2);
  const q = new URL(`https://x${calls[1]}`).searchParams;
  assert.equal(q.get("page"), "1"); assert.equal(q.get("per_page"), String(PAGE)); assert.equal(q.get("populate_policies"), "true");
  assert.equal(of(rs, "fleet.last_seen").length, PAGE + 1);
});

test("fleet: --fleet-max-hosts stops reading and says so", async () => {
  const many = Array.from({ length: PAGE }, (_, i) => ({ ...hosts()[0], id: 100 + i }));
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, { "/hosts": hostRoute(many) }, calls), { opts: { "fleet-max-hosts": "50" } });
  assert.equal(calls.length, 1);
  assert.equal(of(rs, "fleet.disk_encryption").length, 50);
  assert.match(of(rs, "fleet.disk_encryption")[0].detail, /only the first 50 hosts/);
});

test("fleet: missing evidence is skipped, never passed", async () => {
  const linux = { id: 3, hardware_serial: "LNX3", platform: "ubuntu", os_version: "Ubuntu 22.04.4 LTS", mdm: { enrollment_status: null }, policies: [] };
  const list = [...hosts(), linux];
  delete (list[1] as Record<string, unknown>).disk_encryption_enabled;
  delete (list[1] as Record<string, unknown>).seen_time;
  (list[0].policies as { id: number; response: string }[])[0].response = "";
  const rs = await runWith(C, fakeRest(BASE, { "/hosts": hostRoute(list) }));
  const on = (check: string, host: number) => of(rs, `fleet.${check}`).find((r) => r.resource.startsWith(`fleet host ${host} `))!;
  assert.equal(on("disk_encryption", 2).result, "skipped");
  assert.equal(on("last_seen", 2).result, "skipped");
  assert.equal(on("mdm_enrolled", 3).result, "skipped");
  assert.equal(on("screen_lock", 3).result, "skipped");   // no policy applies to the Linux host
  assert.equal(on("screen_lock", 1).result, "skipped");   // the policy has not answered yet
});

test("fleet: with no matching policy anywhere, a policy check is one fleet-level skipped result", async () => {
  const list = hosts().map((h) => ({ ...h, policies: [] }));
  const rs = await runWith(C, fakeRest(BASE, { "/hosts": hostRoute(list) }));
  for (const c of ["screen_lock", "firewall", "edr_present", "os_up_to_date"]) {
    const mine = of(rs, `fleet.${c}`);
    assert.equal(mine.length, 1, c);
    assert.equal(mine[0].result, "skipped");
    assert.equal(mine[0].resource, "fleet fleet.example.com");
    assert.match(mine[0].detail, /--fleet-policy/);
  }
});

test("fleet: --fleet-policy picks policies by id; --fleet-min-os sets a version floor per platform", async () => {
  const list = hosts();
  (list[0].policies as unknown[]).push(pol(99, "Corp lock", "fail", "darwin"));
  let rs = await runWith(C, fakeRest(BASE, { "/hosts": hostRoute(list) }), { opts: { "fleet-policy": ["screen_lock=99,20"] } });
  assert.equal(of(rs, "fleet.screen_lock").find((r) => r.resource.includes("host 1"))!.result, "fail");
  assert.equal(of(rs, "fleet.screen_lock").find((r) => r.resource.includes("host 2"))!.result, "pass");

  const bare = hosts().map((h) => ({ ...h, policies: [] }));
  rs = await runWith(C, fakeRest(BASE, { "/hosts": hostRoute(bare) }), { opts: { "fleet-min-os": ["darwin=15.3", "windows=10.0.22631"] } });
  const mac = of(rs, "fleet.os_up_to_date").find((r) => r.resource.includes("host 1"))!;
  const win = of(rs, "fleet.os_up_to_date").find((r) => r.resource.includes("host 2"))!;
  assert.equal(mac.result, "fail"); assert.match(mac.detail, /15\.2 is below the --fleet-min-os floor 15\.3/);
  assert.equal(win.result, "pass"); assert.match(win.detail, /10\.0\.22631\.4602 meets/);
});

test("fleet: an expired or wrong token is reported as an error (skipped, HTTP 401), not as a failing device", async () => {
  const rs = await runWith(C, fakeRest(BASE, { "/hosts": res(401, { message: "Authentication required", errors: [{ name: "base", reason: "Authentication required" }] }) }));
  assert.equal(rs.length, 7);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("fleet: the real client sends GET with a Bearer token to FLEET_URL's /api/v1/fleet over https only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const api = fleetFromEnv({ FLEET_URL: "https://fleet.example.com/", FLEET_API_TOKEN: "tok-abcdefgh1234" }, (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch);
  assert.ok(typeof api !== "string");
  await api.get("/hosts?page=0");
  assert.equal(seen[0].url, "https://fleet.example.com/api/v1/fleet/hosts?page=0");
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, "Bearer tok-abcdefgh1234");
  assert.equal(typeof fleetFromEnv({ FLEET_URL: "http://fleet.example.com", FLEET_API_TOKEN: "x" }), "string");
  assert.equal(typeof fleetFromEnv({ FLEET_URL: "https://fleet.example.com" }), "string");
});

const setQuery = (id: number, query: string) => (h: Record<string, unknown>) => {
  for (const p of h.policies as { id: number; query: string }[]) if (p.id === id) p.query = query;
};

test("fleet: Fleet's library Windows screen-lock policy (<= 1800 s) passing does not show the 900 s limit; its fail still fails", async () => {
  const lib = "SELECT 1 FROM registry WHERE path = 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs' AND CAST(data as INTEGER) <= 1800;";
  const win = (rs: Awaited<ReturnType<typeof runWith>>) => of(rs, "fleet.screen_lock").find((r) => r.resource.includes("PF3TEST0002"))!;
  const loose = win(await runWith(C, fakeRest(BASE, withHost(1, setQuery(20, lib)))));
  assert.equal(loose.result, "skipped", loose.detail);
  assert.match(loose.detail, /up to 1800 s, above the 900 s/);
  const tight = win(await runWith(C, fakeRest(BASE, withHost(1, setQuery(20, lib.replace("1800", "900"))))));
  assert.equal(tight.result, "pass", tight.detail);
  const failing = win(await runWith(C, fakeRest(BASE, withHost(1, (h) => { setQuery(20, lib)(h); setPolicy(20, "fail")(h); }))));
  assert.equal(failing.result, "fail");
});

test("fleet: Fleet's library macOS OS policy (version >= '14.1.1') proves no currency; a floor below --fleet-min-os does not count", async () => {
  const lib = "SELECT 1 FROM os_version WHERE version >= '14.1.1';";
  const mac = (rs: Awaited<ReturnType<typeof runWith>>) => of(rs, "fleet.os_up_to_date").find((r) => r.resource.includes("C02TEST0001"))!;
  const stale = mac(await runWith(C, fakeRest(BASE, withHost(0, setQuery(13, lib)))));
  assert.equal(stale.result, "skipped", stale.detail);
  assert.match(stale.detail, /never raised/);
  const raised = mac(await runWith(C, fakeRest(BASE, withHost(0, setQuery(13, lib.replace("14.1.1", "15.2"))))));
  assert.equal(raised.result, "pass", raised.detail);
  // With a floor of 16.0 the policy's 15.2 bar does not count, and the host (15.2) fails the floor itself.
  const below = mac(await runWith(C, fakeRest(BASE, withHost(0, setQuery(13, lib.replace("14.1.1", "15.2")))), { opts: { "fleet-min-os": ["darwin=16.0"] } }));
  assert.equal(below.result, "fail", below.detail);
  assert.match(below.detail, /below the --fleet-min-os floor 16\.0/);
});
