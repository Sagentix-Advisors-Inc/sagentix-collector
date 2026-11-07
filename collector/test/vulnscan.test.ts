// Vulnerability scanner results (Nessus .nessus, Tenable Vulnerability Management export, Qualys host list detection)
// reconciled with an asset inventory. Fixtures follow the element and field names of each vendor's documentation
// (cited in src/sources/vulnscan.ts). No network; nothing is executed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { elements, parseSla, readInventory, vulnscan } from "../src/sources/vulnscan.ts";
import type { OptionValue, Result } from "../src/types.ts";

const NOW = new Date("2026-11-07T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000);
const dir = mkdtempSync(join(tmpdir(), "vulnscan-test-"));
let n = 0;
const file = (body: string, ext: string) => { const p = join(dir, `f${n++}.${ext}`); writeFileSync(p, body); return p; };
const run = (opts: Record<string, OptionValue>): Promise<Result[]> => vulnscan.run({ opts, env: {}, clients: {}, now: NOW, warn: () => {} });
const of = (rs: Result[], c: string) => { const m = rs.filter((r) => r.check === `vulnscan.${c}`); assert.equal(m.length, 1, JSON.stringify(rs)); return m[0]; };

const nessusHost = (ip: string, fqdn: string, ago: number, cred: "yes" | "no" | null, items = "") => `
  <ReportHost name="${ip}"><HostProperties>
    <tag name="HOST_END_TIMESTAMP">${Math.floor(daysAgo(ago).getTime() / 1000)}</tag><tag name="host-ip">${ip}</tag><tag name="host-fqdn">${fqdn}</tag>
  </HostProperties>
  ${cred ? `<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"><plugin_output>Information about this scan :
Nessus version : 10.9.0
Credentialed checks : ${cred}
</plugin_output></ReportItem>` : ""}${items}
  </ReportHost>`;
const nessus = (...hosts: string[]) => `<?xml version="1.0" ?><NessusClientData_v2><Policy><policyName>Monthly</policyName></Policy><Report name="Monthly" xmlns:cm="http://www.nessus.org/cm">${hosts.join("")}</Report></NessusClientData_v2>`;

const tenable = (recs: { host: string; ip: string; plugin: number; sev?: string; state?: string; first?: number; last?: number; output?: string }[]) => JSON.stringify(recs.map((r) => ({
  asset: { uuid: `u-${r.host}`, hostname: r.host, fqdn: `${r.host}.corp.example`, ipv4: r.ip },
  plugin: { id: r.plugin, name: r.plugin === 19506 ? "Nessus Scan Information" : "x" }, severity: r.sev ?? "info", state: r.state ?? "OPEN",
  first_found: daysAgo(r.first ?? 1).toISOString(), last_found: daysAgo(r.last ?? 1).toISOString(), output: r.output ?? "",
})));

const qualys = (hosts: { ip: string; dns: string; vm: number; auth?: number; dets?: { qid: number; sev: number; status: string; first: number; type?: string }[] }[]) =>
  `<?xml version="1.0" encoding="UTF-8" ?><!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/host_list_vm_detection_output.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>${NOW.toISOString()}</DATETIME><HOST_LIST>${hosts.map((h) => `<HOST><ID>1</ID><IP>${h.ip}</IP><DNS><![CDATA[${h.dns}]]></DNS>
<LAST_VM_SCANNED_DATE>${daysAgo(h.vm).toISOString()}</LAST_VM_SCANNED_DATE>${h.auth !== undefined ? `<LAST_VM_AUTH_SCANNED_DATE>${daysAgo(h.auth).toISOString()}</LAST_VM_AUTH_SCANNED_DATE>` : ""}
<DETECTION_LIST>${(h.dets ?? []).map((d) => `<DETECTION><QID>${d.qid}</QID><TYPE>${d.type ?? "Confirmed"}</TYPE><SEVERITY>${d.sev}</SEVERITY><STATUS>${d.status}</STATUS><FIRST_FOUND_DATETIME>${daysAgo(d.first).toISOString()}</FIRST_FOUND_DATETIME></DETECTION>`).join("")}</DETECTION_LIST></HOST>`).join("")}
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>`;

test("nessus: every inventory asset scanned with credentials this month passes; findings_within_sla is skipped (one scan has no first-found date)", async () => {
  const report = file(nessus(nessusHost("10.0.0.5", "web1.corp.example", 3, "yes"), nessusHost("10.0.0.6", "db1.corp.example", 3, "yes")), "nessus");
  const inv = file("hostname,owner\nweb1.corp.example,ops\n10.0.0.6,ops\n", "csv");
  const rs = await run({ "vulnscan-report": [report], "vulnscan-inventory": inv });
  for (const r of rs) assert.ok(vulnscan.emits.includes(r.check));
  assert.equal(of(rs, "authenticated_coverage").result, "pass", of(rs, "authenticated_coverage").detail);
  assert.match(of(rs, "authenticated_coverage").detail, /2 of 2 inventory asset\(s\) \(100%\) scanned with working credentials/);
  assert.equal(of(rs, "scan_recent").result, "pass");
  assert.equal(of(rs, "findings_within_sla").result, "skipped");
  assert.equal(of(rs, "authenticated_coverage").resource, `vulnscan inventory ${inv.split("/").pop()}`);
});

test("nessus: an asset missing from the scans, one scanned without credentials and one scanned long ago all fail, named from the inventory", async () => {
  const report = file(nessus(nessusHost("10.0.0.5", "web1.corp.example", 3, "no"), nessusHost("10.0.0.6", "db1.corp.example", 45, "yes"), nessusHost("10.0.0.7", "x.corp.example", 1, null)), "nessus");
  const inv = file("web1\ndb1.corp.example\nmissing.corp.example\n10.0.0.7\n", "txt");
  const rs = await run({ "vulnscan-report": report, "vulnscan-inventory": inv });
  const cov = of(rs, "authenticated_coverage");
  assert.equal(cov.result, "fail");
  assert.match(cov.detail, /1 of 4 inventory asset\(s\) \(25%\).*1 not in any scan, 1 scanned without credentials, 1 with no credential record/);
  assert.match(cov.detail, /missing\.corp\.example/);
  const age = of(rs, "scan_recent");
  assert.equal(age.result, "fail");
  assert.match(age.detail, /2 not scanned in the last 30 day\(s\) \(db1\.corp\.example, missing\.corp\.example\)/);
  assert.doesNotMatch(JSON.stringify(rs), /Nessus version/);
});

test("tenable export: plugin 19506 says whether credentials worked; open findings past their window fail with plugin ids only", async () => {
  const recs = tenable([
    { host: "web1", ip: "10.0.0.5", plugin: 19506, output: "Credentialed checks : yes", last: 2 },
    { host: "web1", ip: "10.0.0.5", plugin: 156032, sev: "critical", first: 40 },
    { host: "web1", ip: "10.0.0.5", plugin: 150000, sev: "medium", first: 40 },
    { host: "web1", ip: "10.0.0.5", plugin: 140000, sev: "high", first: 90, state: "FIXED" },
  ]);
  const rs = await run({ "vulnscan-report": file(recs, "json"), "vulnscan-inventory": file(JSON.stringify(["web1.corp.example"]), "json") });
  assert.equal(of(rs, "authenticated_coverage").result, "pass");
  const sla = of(rs, "findings_within_sla");
  assert.equal(sla.result, "fail");
  assert.match(sla.detail, /2 open finding\(s\) by severity: critical 1, medium 1; past the window \(critical 30 d, high 30 d, medium 90 d, low 180 d\): critical 1 \(plugin 156032\)/);
  const ok = await run({ "vulnscan-report": file(recs, "json"), "vulnscan-sla": "critical=60" });
  assert.equal(of(ok, "findings_within_sla").result, "pass");
  assert.equal(of(ok, "authenticated_coverage").result, "skipped");   // no inventory: coverage is never judged against what the scanner reached
  assert.match(of(ok, "scan_recent").detail, /no inventory given/);
});

test("qualys detection: authenticated when the last authenticated VM scan is the last VM scan; only confirmed, unfixed detections count", async () => {
  const x = qualys([
    { ip: "10.0.0.5", dns: "web1.corp.example", vm: 5, auth: 5, dets: [{ qid: 38173, sev: 4, status: "Active", first: 20 }, { qid: 11, sev: 5, status: "Fixed", first: 300 }, { qid: 12, sev: 5, status: "Active", first: 300, type: "Potential" }] },
    { ip: "10.0.0.6", dns: "db1.corp.example", vm: 5, auth: 60 },
  ]);
  const rs = await run({ "vulnscan-report": file(x, "xml"), "vulnscan-inventory": file("ip\n10.0.0.5\n10.0.0.6\n", "csv") });
  const cov = of(rs, "authenticated_coverage");
  assert.equal(cov.result, "fail");
  assert.match(cov.detail, /1 scanned without credentials.* \(10\.0\.0\.6\); 100% required/);
  const sla = of(rs, "findings_within_sla");
  assert.equal(sla.result, "pass", sla.detail);
  assert.match(sla.detail, /1 open finding\(s\) by severity: high 1/);
});

test("a file that is no scan, an unreadable inventory, a bad --vulnscan-sla and no file at all are skipped or refused, never passed", async () => {
  const rs = await run({ "vulnscan-report": file("<html>nothing</html>", "xml") });
  assert.ok(rs.every((r) => r.result === "skipped"));
  assert.match(rs[0].detail, /neither a \.nessus file/);
  const none = await run({});
  assert.ok(none.every((r) => r.result === "skipped") && none.length === 3);
  const inv = await run({ "vulnscan-report": file(nessus(nessusHost("10.0.0.5", "a", 1, "yes")), "nessus"), "vulnscan-inventory": join(dir, "nope.csv") });
  assert.ok(inv.every((r) => r.result === "skipped"));
  assert.match(vulnscan.validate!({ "vulnscan-sla": "urgent=3" })!, /severity=days/);
  assert.deepEqual(parseSla("high=15"), { critical: 30, high: 15, medium: 90, low: 180 });
});

test("the XML reader is linear and exact: it ignores look-alike tags and reads self-closed ones", () => {
  assert.deepEqual(elements(`<HOSTX>1</HOSTX><HOST a="1">2</HOST><HOST/>`, "HOST").map((e) => e.inner), ["2", ""]);
  const big = "<HOST>" + "<".repeat(200_000);
  const t = Date.now();
  elements(big, "HOST");
  assert.ok(Date.now() - t < 500);
  assert.deepEqual(readInventory(file('[{"fqdn":"A.example"},{"ip":"10.0.0.1"},"b"]', "json")), ["a.example", "10.0.0.1", "b"]);
});

test("tenable asset export: last_authenticated_scan_date against last_scan_time gives the credential record, merged with a vulnerability export of the same host", async () => {
  const assets = JSON.stringify([
    { id: "u-web1", hostnames: ["web1"], fqdns: ["web1.corp.example"], ipv4s: ["10.0.0.5"], last_scan_time: daysAgo(2).toISOString(), last_authenticated_scan_date: daysAgo(2).toISOString() },
    { id: "u-db1", hostnames: ["db1"], ipv4s: ["10.0.0.6"], last_scan_time: daysAgo(2).toISOString(), last_authenticated_scan_date: daysAgo(90).toISOString() },
  ]);
  const vulns = tenable([{ host: "web1", ip: "10.0.0.5", plugin: 156032, sev: "high", first: 3 }]);
  const rs = await run({ "vulnscan-report": [file(assets, "json"), file(vulns, "json")], "vulnscan-inventory": file("web1.corp.example\ndb1\n", "txt") });
  const cov = of(rs, "authenticated_coverage");
  assert.equal(cov.result, "fail");
  assert.match(cov.detail, /1 of 2 .*1 scanned without credentials.*\(db1\)/);
  assert.equal(of(rs, "scan_recent").result, "pass");
  assert.equal(of(rs, "findings_within_sla").result, "pass");
});
