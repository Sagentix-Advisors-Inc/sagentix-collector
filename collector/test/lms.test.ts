// The LMS source over CSV files in a temp directory: pass and fail per check, missing input, CSV
// quoting, and that only ids and counts reach a result.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LMS_CHECKS, lms, parseCsv } from "../src/sources/lms.ts";
import type { OptionValue, Result } from "../src/types.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const dir = mkdtempSync(join(tmpdir(), "lms-test-"));
let n = 0;
const file = (text: string) => { const p = join(dir, `f${n++}.csv`); writeFileSync(p, text); return p; };

const ROSTER = "person_id,role,email\nE1,engineer,ann@example.com\nE2,admin,bob@example.com\n";
const TRAINING = [
  "person_id,course,completed_on,manager",
  'E1,"Security Awareness 2026, annual",2026-03-01,Carol Secret',
  "E2,Security awareness basics,2026-02-01,Carol Secret",
  "E2,Role-based admin training,2026-04-01,Carol Secret",
  "X9,Harassment prevention,2026-01-01,Carol Secret",
].join("\r\n");

const run = (roster: string, training: string, extra: Record<string, OptionValue> = {}): Promise<Result[]> =>
  lms.run({ opts: { "roster-csv": file(roster), "training-csv": file(training), ...extra }, env: {}, clients: {}, now: NOW, warn: () => {} });
const one = (rs: Result[], c: string) => { const m = rs.filter((r) => r.check === `lms.${c}`); assert.equal(m.length, 1, c); return m[0]; };

test("every check passes when the roster is trained", async () => {
  const rs = await run(ROSTER, TRAINING);
  for (const c of LMS_CHECKS) assert.equal(one(rs, c).result, "pass", `${c}: ${one(rs, c).detail}`);
  assert.match(one(rs, "training_records_complete").detail, /1 training row\(s\) name people not on the roster/);
});

test("security_awareness_current fails for a completion older than 12 months", async () => {
  const t = TRAINING.replace("2026-03-01", "2025-09-01");
  const r = one(await run(ROSTER, t), "security_awareness_current");
  assert.equal(r.result, "fail"); assert.match(r.detail, /person ids E1\)/);
});

test("role_based_training_current fails when an admin lacks it, and is skipped when nobody is privileged", async () => {
  const t = TRAINING.split("\r\n").filter((l) => !l.includes("Role-based")).join("\n");
  const r = one(await run(ROSTER, t), "role_based_training_current");
  assert.equal(r.result, "fail"); assert.match(r.detail, /E2/);
  const s = one(await run(ROSTER.replace("admin", "engineer"), TRAINING), "role_based_training_current");
  assert.equal(s.result, "skipped");
});

test("training_records_complete fails for a roster person with no record", async () => {
  const r = one(await run(ROSTER + "E3,engineer,eve@example.com\n", TRAINING), "training_records_complete");
  assert.equal(r.result, "fail"); assert.match(r.detail, /E3/);
});

test("unparseable dates are counted, not passed", async () => {
  const r = one(await run(ROSTER, TRAINING.replace("2026-03-01", "March 1st")), "security_awareness_current");
  assert.equal(r.result, "fail"); assert.match(r.detail, /1 training row\(s\) with an unreadable completed_on/);
});

test("a missing file or column gives skipped for every check", async () => {
  let rs = await lms.run({ opts: { "roster-csv": join(dir, "nope.csv"), "training-csv": file(TRAINING) }, env: {}, clients: {}, now: NOW, warn: () => {} });
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /not readable/); }
  rs = await run(ROSTER, "person_id,course\nE1,x\n");
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /no column completed_on/); }
  rs = await lms.run({ opts: {}, env: {}, clients: {}, now: NOW, warn: () => {} });
  for (const r of rs) assert.equal(r.result, "skipped");
});

test("the CSV parser handles quotes, commas, escaped quotes, CRLF and a BOM", () => {
  assert.deepEqual(parseCsv('﻿a,b\r\n"x, y","say ""hi"""\r\n'), [["a", "b"], ["x, y", 'say "hi"']]);
  assert.deepEqual(parseCsv("a\n\nb"), [["a"], ["b"]]);
});

test("results carry ids and counts only: no email, other column or unconfigured course name", async () => {
  const all = JSON.stringify(await run(ROSTER + "E3,engineer,eve@example.com\n", TRAINING));
  for (const bad of ["@example.com", "Carol", "Harassment", "annual", "admin training"]) assert.ok(!all.includes(bad), bad);
});
