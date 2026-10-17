// ScubaGoggles and ScubaGear over trimmed copies of each tool's own sample report (CC0; MetaData and
// Results shape kept, Raw dropped, Details replaced by a planted email that must never leave). No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadCatalog } from "../src/catalog.ts";
import { checkIdFor, scubagear, scubagoggles } from "../src/sources/scuba.ts";
import type { OptionValue, Result, Source } from "../src/types.ts";
import { NO_MAPPINGS } from "./helpers.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const fixture = (name: string) => new URL(`./fixtures/${name}`, import.meta.url).pathname;
const GOGGLES = fixture("scubagoggles_ScubaResults.json");
const GEAR = fixture("scubagear_ScubaResults.json");
const dir = mkdtempSync(join(tmpdir(), "scuba-test-"));
const catalog = loadCatalog();

const run = (s: Source, opts: Record<string, OptionValue>, warns: string[] = []): Promise<Result[]> =>
  s.run({ opts, env: {}, clients: {}, now: NOW, warn: (w) => warns.push(w) });
const results = (s: Source, file: string) => run(s, { [`${s.name}-results`]: file, [`${s.name}-max-age-days`]: "400" });

for (const [s, file, tool, tenant, prefix] of [
  [scubagoggles, GOGGLES, "ScubaGoggles", "gws tenant ABCDEFG", "GWS."],
  [scubagear, GEAR, "ScubaGear", "m365 tenant ca08493a-c9c8-4db0-a9e8-d3b4bafac269", "MS."],
] as const) {
  test(`${s.name}: the emitted ids are exactly the catalogue's, and every one names its policy`, () => {
    assert.ok(s.emits.length > 100, `${s.emits.length}`);
    const mine = [...catalog.values()].filter((c) => c.source === s.name).map((c) => c.id).sort();
    assert.deepEqual([...s.emits].sort(), mine);
    for (const id of s.emits) assert.match(catalog.get(id)!.title, new RegExp(`^${prefix.replace(".", "\\.")}`, "i"));
  });

  test(`${s.name}: the sample report maps Pass, Fail, Warning and N/A to pass, fail, fail and skipped`, async () => {
    const doc = JSON.parse(readFileSync(file, "utf8"));
    const rows = Object.values(doc.Results as Record<string, { Controls: { "Control ID": string; Result: string }[] }[]>).flat().flatMap((g) => g.Controls);
    const rs = await results(s, file);
    assert.ok(rs.every((r) => r.resource === tenant), rs[0].resource);
    const keys = rs.map((r) => r.check);
    assert.equal(new Set(keys).size, keys.length, "one result per policy");
    let compared = 0;
    for (const row of rows) {
      const r = rs.find((x) => x.check === checkIdFor(s.name, row["Control ID"]));
      if (!r) continue;   // a policy the pinned mapping does not hold
      compared++;
      const want = row.Result === "Pass" ? "pass" : row.Result === "Fail" || row.Result === "Warning" ? "fail" : "skipped";
      assert.equal(r.result, want, `${row["Control ID"]} ${row.Result}: ${r.detail}`);
      assert.match(r.detail, new RegExp(`^${tool} \\d`));
    }
    assert.ok(compared > 80, `${compared} policies compared`);
    for (const r of rs) assert.ok(s.emits.includes(r.check));
  });

  test(`${s.name}: the tool's Details (names, emails, OUs) never reach a result`, async () => {
    const all = JSON.stringify(await results(s, file));
    for (const bad of ["alice@example.org", "Finance", "example.org", "Example Org"]) assert.ok(!all.includes(bad), bad);
  });

  test(`${s.name}: a report older than the allowed age, or with no file, is skipped, never passed`, async () => {
    let rs = await run(s, { [`${s.name}-results`]: file });   // default 30 days; the sample is older
    assert.ok(rs.length && rs.every((r) => r.result === "skipped" && /days old/.test(r.detail)), rs[0].detail);
    rs = await run(s, {});
    assert.ok(rs.length === s.emits.length && rs.every((r) => r.result === "skipped"));
    rs = await run(s, { [`${s.name}-results`]: join(dir, "missing.json") });
    assert.ok(rs.every((r) => r.result === "skipped" && /not readable/.test(r.detail)));
  });
}

test("scubagoggles: a folder is searched for the newest ScubaResults file; a BOM and one-item lists are read", async () => {
  const doc = JSON.parse(readFileSync(GOGGLES, "utf8"));
  doc.MetaData.TimestampZulu = "2026-10-14T00:00:00Z";
  // PowerShell's ConvertTo-Json turns a one-item list into an object: Results.<product> and Controls.
  doc.Results = { gmail: { GroupName: "g", GroupNumber: "1", Controls: { "Control ID": "GWS.GMAIL.1.1v1", Result: "Pass", Criticality: "Shall", Details: "-" } } };
  const out = join(dir, "run", "GWSBaselineConformance_2026_10_14");
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "ScubaResults_old.json"), JSON.stringify({ MetaData: { Tool: "ScubaGoggles", TimestampZulu: "2026-10-01T00:00:00Z" }, Results: {} }));
  utimesSync(join(out, "ScubaResults_old.json"), new Date("2026-10-01"), new Date("2026-10-01"));
  writeFileSync(join(out, "ScubaResults_new.json"), "﻿" + JSON.stringify(doc));
  const rs = await run(scubagoggles, { "scubagoggles-results": join(dir, "run") });
  const r = rs.find((x) => x.check === "scubagoggles.gws.gmail.1.1v1")!;
  assert.equal(r.result, "pass", r.detail);
  assert.ok(rs.filter((x) => x.check !== r.check).every((x) => x.result === "skipped" && /did not report/.test(x.detail)));
});

test("scubagear: several rows for one policy give the worst; Omitted and Error give skipped; another tool's file is refused", async () => {
  const mk = (rows: [string, string][], tool = "ScubaGear") => {
    const p = join(dir, `gear-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(p, JSON.stringify({ MetaData: { Tool: tool, ToolVersion: "1.8.0", TenantId: "t1", TimestampZulu: "2026-10-14T00:00:00Z" },
      Results: { AAD: [{ GroupName: "x", GroupNumber: "1", Controls: rows.map(([id, res]) => ({ "Control ID": id, Result: res, Criticality: "Shall", Details: "" })) }] } }));
    return p;
  };
  const warns: string[] = [];
  let rs = await run(scubagear, { "scubagear-results": mk([["MS.AAD.1.1v1", "Pass"], ["MS.AAD.1.1v1", "Fail"], ["MS.AAD.2.1v1", "Omitted"], ["MS.AAD.2.2v1", "Error"], ["MS.AAD.99.9v9", "Fail"]]) }, warns);
  const of = (id: string) => rs.find((r) => r.check === `scubagear.${id}`)!;
  assert.equal(of("ms.aad.1.1v1").result, "fail");
  assert.equal(of("ms.aad.2.1v1").result, "skipped");
  assert.equal(of("ms.aad.2.2v1").result, "skipped");
  assert.ok(!rs.some((r) => r.check.includes("99.9")));
  assert.match(warns.join("\n"), /MS\.AAD\.99\.9v9/);
  rs = await run(scubagear, { "scubagear-results": mk([["MS.AAD.1.1v1", "Pass"]], "ScubaGoggles") });
  assert.ok(rs.every((r) => r.result === "skipped" && /written by ScubaGoggles/.test(r.detail)));
});

test("the catalogues are generated: hub ids and KSIs follow CISA's CSV and FedRAMP's KSI control lists", { skip: NO_MAPPINGS }, () => {
  const rules = JSON.parse(readFileSync(new URL("../../apps/sos-app/src/data/fedramp_rules.json", import.meta.url), "utf8")) as { ksis: { id: string; controls: string[] }[] };
  for (const name of ["scubagoggles", "scubagear"]) {
    const doc = JSON.parse(readFileSync(new URL(`../../apps/sos-app/src/data/checks/${name}.json`, import.meta.url), "utf8"));
    assert.match(doc.notes, /build_scuba_catalog\.py/);
    assert.match(doc.engine.commit, /^[0-9a-f]{40}$/);
    assert.equal(doc.engine.licence, "CC0-1.0");
    for (const c of doc.checks) {
      const want = rules.ksis.filter((k) => k.controls.some((x) => c.hub.includes(x))).map((k) => k.id);
      assert.deepEqual(c.ksis, want, c.id);
    }
  }
  // CISA's CSV row: MS.AAD.1.1v1,CM-7 (legacy authentication blocked).
  assert.ok(catalog.get("scubagear.ms.aad.1.1v1")!.hub!.includes("cm-7"));
});
