// The Configuration Manager source against a fake administration service shaped like the SMS_CombinedDeviceResources,
// SMS_SoftwareUpdate, SMS_UpdateComplianceStatus and SMS_G_System_CI_ComplianceState class references. Fixtures are
// written by hand from the documented property names; the PowerShell transport is tested with a fake exec.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PATHS, cmDate, configmgr, configmgrFromEnv, getScript } from "../src/sources/configmgr.ts";
import type { Run } from "../src/sources/windows.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const BASE = "https://cm01.corp.example.com/AdminService/wmi";
const ok = (value: unknown[], next?: string) => res(200, { "@odata.context": `${BASE}/$metadata#X`, value, ...(next ? { "@odata.nextLink": next } : {}) });

interface Over { client?: boolean; active?: string | null; ep?: boolean | null; av?: boolean; sig?: string; late?: boolean; unknown?: boolean; baseline?: number }

function device(id: number, o: Over = {}): Record<string, unknown> {
  return {
    ResourceID: id, SerialNumber: `PF3CM00${id}`, Name: "ANNA-LAPTOP", UserName: "achao", UserDomainName: "CORP", DeviceOS: "Microsoft Windows NT Workstation 10.0",
    IsClient: o.client ?? true, IsObsolete: false, Unknown: false, ClientActiveStatus: 1,
    LastActiveTime: o.active === null ? null : (o.active ?? daysAgo(1)), LastPolicyRequest: daysAgo(2),
    EPEnabled: o.ep === null ? null : (o.ep ?? true), EPAntivirusEnabled: o.av ?? true, EPAntivirusSignatureLastUpdateDateTime: o.sig ?? daysAgo(1),
  };
}
const UPDATES = [
  { CI_ID: 101, ArticleID: "5044284", IsDeployed: true, IsExpired: false, DatePosted: daysAgo(60), SeverityName: "Critical", LocalizedDisplayName: "2026-08 Cumulative Update" },
  { CI_ID: 102, ArticleID: "5046617", IsDeployed: true, IsExpired: false, DatePosted: daysAgo(5), SeverityName: "Important", LocalizedDisplayName: "2026-10 Cumulative Update" },
];

function site(devs: { id: number; o?: Over }[]): Routes {
  const status: unknown[] = [];
  const ci: unknown[] = [];
  for (const d of devs) {
    status.push({ MachineID: d.id, CI_ID: 102, Status: 2, ArticleID: "5046617" });   // recent: within the grace period
    if (d.o?.late) status.push({ MachineID: d.id, CI_ID: 101, Status: 2, ArticleID: "5044284" });
    if (d.o?.unknown) status.push({ MachineID: d.id, CI_ID: 101, Status: 0, ArticleID: "5044284" });
    ci.push({ ResourceID: d.id, CI_ID: 900, LocalizedDisplayName: "CIS Windows 11 baseline", ComplianceState: d.o?.baseline ?? 1, UserName: "achao" });
  }
  return {
    [PATHS.devices]: ok(devs.map((d) => device(d.id, d.o))),
    [PATHS.updates]: ok(UPDATES),
    [PATHS.updateStatus]: ok(status),
    [PATHS.baselines]: ok(ci),
  };
}
const strong = () => site([{ id: 16777219 }, { id: 16777220 }]);
const weak = (o: Over) => site([{ id: 16777219 }, { id: 16777220, o }]);

const C: Contract = {
  source: configmgr, clientKey: "configmgr", base: BASE, prefix: "configmgr", strong,
  env: { CONFIGMGR_PROVIDER: "cm01.corp.example.com" },
  rateLimited: { path: PATHS.devices, check: "client_installed" },
  fails: {
    client_installed: weak({ client: false }),
    last_seen: weak({ active: daysAgo(40) }),
    antimalware_enabled: weak({ av: false }),
    antimalware_signatures_current: weak({ sig: daysAgo(20) }),
    updates_installed: weak({ late: true }),
    baselines_compliant: weak({ baseline: 2 }),
  },
};

contractSuite(C);

test("configmgr: GET only the four documented classes; no computer name or user reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.deepEqual(calls, [PATHS.devices, PATHS.updates, PATHS.updateStatus, PATHS.baselines]);
  const all = JSON.stringify(rs);
  for (const s of ["ANNA", "achao", "CORP\\"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "configmgr.last_seen").map((r) => r.resource), ["configmgr device 16777219 serial PF3CM0016777219", "configmgr device 16777220 serial PF3CM0016777220"]);
});

test("configmgr: a failing update names the KB and severity; a recent required update does not fail; unknown detection is skipped", async () => {
  const rs = await runWith(C, fakeRest(BASE, site([{ id: 1, o: { late: true } }, { id: 2 }, { id: 3, o: { unknown: true } }])));
  const u = of(rs, "configmgr.updates_installed");
  assert.match(u[0].detail, /"KB5044284" "Critical"/);
  assert.equal(u[0].result, "fail");
  assert.equal(u[1].result, "pass");
  assert.equal(u[2].result, "skipped");
});

test("configmgr: a device without a client fails client_installed and skips the rest; unknown and obsolete records are not counted", async () => {
  const routes = site([{ id: 1, o: { client: false } }]);
  routes[PATHS.devices] = ok([device(1, { client: false }), { ...device(2), Unknown: true }, { ...device(3), IsObsolete: true }]);
  const rs = await runWith(C, fakeRest(BASE, routes));
  assert.deepEqual(of(rs, "configmgr.client_installed").map((r) => r.result), ["fail"]);
  assert.ok(rs.filter((r) => r.check !== "configmgr.client_installed").every((r) => r.result === "skipped"));
  assert.ok(!rs.some((r) => /device [23] /.test(r.resource)));
});

test("configmgr: missing evidence is skipped, never passed (no Endpoint Protection, no activity, no baseline)", async () => {
  const routes = site([{ id: 1, o: { ep: null, active: null, unknown: true } }]);
  routes[PATHS.devices] = ok([{ ...device(1, { ep: null, active: null }), LastPolicyRequest: null }]);
  routes[PATHS.baselines] = ok([]);
  const rs = await runWith(C, fakeRest(BASE, routes));
  for (const r of rs.filter((x) => x.check !== "configmgr.client_installed")) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.match(of(rs, "configmgr.antimalware_enabled")[0].detail, /EPEnabled empty/);
});

test("configmgr: lists follow @odata.nextLink; --configmgr-max-devices caps and marks the read incomplete", async () => {
  const calls: string[] = [];
  const routes = site([{ id: 1 }, { id: 2 }, { id: 3 }]);
  routes[PATHS.devices] = (url) => (url.includes("skiptoken") ? ok([device(3)]) : ok([device(1), device(2)], `${BASE}${PATHS.devices}?$skiptoken=2`));
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.equal(calls.filter((c) => c.startsWith(PATHS.devices)).length, 2);
  assert.equal(of(rs, "configmgr.client_installed").length, 3);
  const capped = await runWith(C, fakeRest(BASE, site([{ id: 1 }, { id: 2 }, { id: 3 }])), { opts: { "configmgr-max-devices": "2" } });
  assert.equal(of(capped, "configmgr.client_installed").length, 2);
  assert.ok(capped.filter((r) => r.resource.startsWith("configmgr device")).every((r) => r.complete === false));
});

test("configmgr: an account that is not an administrative user is reported as an error (skipped, HTTP 401), never as failing devices", async () => {
  const rs = await runWith(C, fakeRest(BASE, { [PATHS.devices]: res(401, "") }));
  assert.equal(rs.length, 6);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("configmgr: WMI DMTF and ISO dates both parse", () => {
  assert.equal(cmDate("20261014120000.000000+000"), Date.parse("2026-10-14T12:00:00Z"));
  assert.equal(cmDate("20261014120000.000000-300"), Date.parse("2026-10-14T17:00:00Z"));
  assert.equal(cmDate("2026-10-14T12:00:00Z"), Date.parse("2026-10-14T12:00:00Z"));
  assert.equal(cmDate("not a date"), undefined);
});

test("configmgr: the real client runs one GET through PowerShell with the account's own credentials, only under /AdminService/ on the provider", async () => {
  const seen: string[][] = [];
  const exec = async (_cmd: string, args: readonly string[]): Promise<Run> => {
    seen.push([...args]);
    return { code: 0, stdout: JSON.stringify({ status: 200, body: JSON.stringify({ value: [{ ResourceID: 1 }] }) }) + "\r\n", stderr: "" };
  };
  const api = configmgrFromEnv({ CONFIGMGR_PROVIDER: "cm01.corp.example.com" }, exec, "win32");
  assert.ok(typeof api !== "string");
  const r = await api.get(PATHS.devices);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { value: [{ ResourceID: 1 }] });
  const script = Buffer.from(seen[0].at(-1)!, "base64").toString("utf16le");
  assert.match(script, /Invoke-WebRequest -Uri \$u -Method Get -UseDefaultCredentials -UseBasicParsing -MaximumRedirection 0/);
  assert.ok(!/-Method (Post|Put|Patch|Delete)/i.test(script));
  assert.ok(script.includes(Buffer.from(new URL(`${BASE}${PATHS.devices}`).href).toString("base64")));
  assert.equal(script, getScript(new URL(`${BASE}${PATHS.devices}`).href));
  const u2 = await api.get(PATHS.updates); assert.equal(u2.status, 200);
  assert.ok(Buffer.from(seen[1].at(-1)!, "base64").toString("utf16le").includes(Buffer.from(`${BASE}/SMS_SoftwareUpdate?$filter=IsDeployed%20eq%20true`).toString("base64")));
  // Another origin or a path outside the administration service is never asked.
  assert.equal((await api.get("https://evil.example/AdminService/wmi/SMS_Site")).status, 0);
  assert.equal((await api.get("https://cm01.corp.example.com/ReportServer")).status, 0);
  assert.equal(seen.length, 2);
  // An HTTP error comes back with its status.
  const deny = configmgrFromEnv({ CONFIGMGR_PROVIDER: "cm01.corp.example.com" }, async () => ({ code: 0, stdout: "{\"status\":403,\"body\":\"\"}", stderr: "" }), "win32");
  assert.equal(typeof deny !== "string" && (await deny.get(PATHS.devices)).status, 403);
  assert.match(String(configmgrFromEnv({ CONFIGMGR_PROVIDER: "cm01.corp.example.com" }, exec, "linux")), /Windows/);
  assert.equal(typeof configmgrFromEnv({ CONFIGMGR_PROVIDER: "cm01.corp.example.com/../x y" }, exec, "win32"), "string");
  assert.equal(typeof configmgrFromEnv({}, exec, "win32"), "string");
});
