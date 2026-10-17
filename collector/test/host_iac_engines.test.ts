// The stig (Cinc Auditor + MITRE STIG profiles), kubescape and checkov sources. Every fixture is built here by
// hand in each tool's documented shape (field names from InSpec's json reporter, Kubescape's jsonprinter.go and
// Checkov's report.py); no tool output is copied. No network; the cinc-auditor subprocess is a fake.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadCatalog } from "../src/catalog.ts";
import { STIG_PROFILES, cincArgs, controlOutcome, parseInspec, parseTarget, stig, type CincSpawner } from "../src/sources/stig.ts";
import { kubescape, parseKubescape } from "../src/sources/kubescape.ts";
import { PLAN_CHECK, checkov, parseCheckov, resourceType } from "../src/sources/checkov.ts";
import type { OptionValue, Result, Source } from "../src/types.ts";
import { NO_MAPPINGS } from "./helpers.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const dir = mkdtempSync(join(tmpdir(), "host-iac-test-"));
let n = 0;
const file = (body: unknown, ageDays = 0) => {
  const p = join(dir, `r${n++}.json`);
  writeFileSync(p, JSON.stringify(body));
  const t = new Date(NOW.getTime() - ageDays * 86_400_000);
  utimesSync(p, t, t);
  return p;
};
const catalog = loadCatalog();
const ids = (source: string) => new Set([...catalog.values()].filter((c) => c.source === source).map((c) => c.id));
const run = (s: Source, opts: Record<string, OptionValue>, clients: Record<string, unknown> = {}, env: NodeJS.ProcessEnv = {}) => {
  const warns: string[] = [];
  return s.run({ opts, env, clients, now: NOW, warn: (w) => warns.push(w) }).then((rs) => ({ rs, warns }));
};
const one = (rs: Result[], id: string) => { const m = rs.filter((r) => r.check === id); assert.equal(m.length, 1, `${id}: ${JSON.stringify(rs)}`); return m[0]; };
const PERSON = /alice|bob@|carol|\/home\//i;
function clean(s: Source, rs: Result[]) {
  for (const r of rs) {
    assert.ok(s.emits.includes(r.check), r.check);
    assert.ok(r.detail.length > 0 && r.detail.length <= 1000 && r.resource.length <= 300, JSON.stringify(r));
    assert.ok(!PERSON.test(r.resource) && !PERSON.test(r.detail), `a person's name or path leaked: ${JSON.stringify(r)}`);
  }
}

// ── STIG ────────────────────────────────────────────────────────────────────────────────────────────

const STIG = ids("stig");
const rhel9 = [...STIG].filter((i) => i.startsWith("stig.rhel9.")).sort();
const vid = (check: string) => check.split(".")[2].toUpperCase();
const ctl = (check: string, statuses: string[], extra: Record<string, unknown> = {}) => ({
  id: `S${vid(check)}`, title: "t", impact: 0.5, tags: { gid: vid(check), severity: "medium", nist: ["CM-6 b"] },
  waiver_data: {}, results: statuses.map((s) => ({ status: s, code_desc: "User alice in /home/alice has mode 0644", start_time: daysAgo(1), skip_message: "carol" })),
  ...extra,
});
const inspec = (controls: unknown[], profile = STIG_PROFILES.rhel9) => ({
  platform: { name: "redhat", release: "9.6", target_id: "0f3c2a9e-7b1d-4c55-9a0e-1d2c3b4a5f60" },
  profiles: [
    { name: profile.name, version: profile.version, controls },
    { name: "inspec-profile-resources", version: "0.1.0", controls: [], parent_profile: profile.name },
  ],
  statistics: { duration: 1.2 }, version: "7.2.1",
});

test("stig: the catalogue holds five pinned profiles, every check with a hub control", { skip: NO_MAPPINGS }, () => {
  assert.ok(STIG.size > 1000, String(STIG.size));
  for (const k of Object.keys(STIG_PROFILES)) assert.ok([...STIG].some((i) => i.startsWith(`stig.${k}.v-`)), k);
  for (const i of STIG) assert.ok(catalog.get(i)!.hub!.length > 0, i);
  assert.deepEqual(new Set(stig.emits), STIG);
});

test("stig: control outcomes; never InSpec's own messages", () => {
  const [a, b, c, d, e, f, g] = rhel9;
  const doc = inspec([
    ctl(a, ["passed", "passed"]), ctl(b, ["passed", "failed"]), ctl(c, ["skipped"]), ctl(d, ["error", "passed"]),
    ctl(e, ["passed"], { waiver_data: { run: false, justification: "bob@example.com said so" } }),
    ctl(f, []), ctl(g, ["passed"], { status: "not_applicable" }),
    ctl("stig.rhel9.v-999999999", ["failed"]),
  ]);
  const { results, summary } = parseInspec(doc, "stig rhel9 host h1", STIG);
  assert.equal(summary.kept, 7); assert.equal(summary.dropped, 1);
  const by = Object.fromEntries(results.map((r) => [r.check, r]));
  assert.equal(by[a].result, "pass"); assert.match(by[a].detail, /2 test\(s\): 2 passed/);
  assert.equal(by[b].result, "fail");
  assert.equal(by[c].result, "skipped");
  assert.equal(by[d].result, "skipped"); assert.match(by[d].detail, /could not run/);
  assert.equal(by[e].result, "skipped"); assert.match(by[e].detail, /waived/);
  assert.equal(by[f].result, "skipped");
  assert.equal(by[g].result, "skipped"); assert.match(by[g].detail, /not applicable/);
  clean(stig, results);
  assert.equal(controlOutcome({ results: [] }).result, "skipped");
});

test("stig: an unknown profile is dropped unless --stig-profile maps it, and SV- ids fall back to V-", () => {
  const custom = { name: "acme-rhel9-overlay", version: "1.0.0" };
  const c = { ...ctl(rhel9[0], ["passed"]), tags: { severity: "low" } };   // no gid: id SV-… is used
  let r = parseInspec(inspec([c], custom), "x", STIG);
  assert.equal(r.results.length, 0); assert.deepEqual(r.summary.droppedProfiles, ["acme-rhel9-overlay"]);
  r = parseInspec(inspec([c], custom), "x", STIG, "rhel9");
  assert.equal(one(r.results, rhel9[0]).result, "pass");
  assert.throws(() => parseInspec({ nope: 1 }, "x", STIG), /not an InSpec JSON report/);
});

test("stig: a report file is read, labelled without the user, and skipped when stale", async () => {
  let { rs, warns } = await run(stig, { "cinc-report": file(inspec([ctl(rhel9[0], ["passed"]), ctl(rhel9[1], ["failed"])])) });
  assert.equal(one(rs, rhel9[0]).result, "pass");
  assert.match(one(rs, rhel9[0]).resource, /^stig rhel9 host redhat 9\.6 target 0f3c2a9e/);
  assert.match(warns.join("\n"), /2 controls; 2 results/);
  clean(stig, rs);
  const old = inspec([ctl(rhel9[0], ["passed"])]);
  (old.profiles[0].controls[0] as { results: { start_time: string }[] }).results[0].start_time = daysAgo(45);
  ({ rs } = await run(stig, { "cinc-report": file(old) }));
  assert.equal(one(rs, rhel9[0]).result, "skipped"); assert.match(one(rs, rhel9[0]).detail, /45 days old/);
});

test("stig: targets are ssh, winrm or local, never with a password, and need a profile", async () => {
  assert.deepEqual(parseTarget("ssh://ec2-user@10.0.1.5:22"), { uri: "ssh://ec2-user@10.0.1.5:22", label: "10.0.1.5" });
  assert.equal(parseTarget("winrm://svc@win01.corp.example").label, "win01.corp.example");
  assert.equal(parseTarget("local://").label, "local");
  for (const bad of ["docker://abc", "ssh://u:pw@h", "http://h", "ssh://u@h;rm -rf /", "aws://"]) assert.throws(() => parseTarget(bad), bad);
  await assert.rejects(run(stig, {}), /--stig-target/);
  await assert.rejects(run(stig, { "stig-target": "ssh://u@h" }), /--stig-profile/);
  await assert.rejects(run(stig, { "stig-target": "ssh://u@h", "stig-profile": "win2022" }), /must be one of/);
});

test("stig: a scan runs only the bundled profile with a fixed reporter, and a failed run stops", async () => {
  const profiles = mkdtempSync(join(tmpdir(), "stig-profiles-"));
  writeFileSync(join(profiles, "rhel9.tar.gz"), "archive");
  const calls: string[][] = [];
  const fake = (code: number, write = true): CincSpawner => async (_bin, args) => {
    calls.push(args);
    const rep = args[args.indexOf("--reporter") + 1].replace(/^json:/, "");
    if (write) writeFileSync(rep, JSON.stringify(inspec([ctl(rhel9[0], ["failed"])])));
    return { code, stderr: "password=sup3rs3cretvalue" };
  };
  const opts = { "stig-target": ["ssh://alice@10.0.0.9"], "stig-profile": "rhel9", "stig-profiles-dir": profiles, "stig-key-file": "/k/id", "stig-sudo": true };
  const { rs } = await run(stig, opts, { cinc: fake(101) }, { STIG_TARGET_PASSWORD: "sup3rs3cretvalue" });
  assert.equal(one(rs, rhel9[0]).result, "fail");
  assert.equal(one(rs, rhel9[0]).resource, "stig rhel9 host 10.0.0.9");
  const a = calls[0];
  assert.deepEqual(a.slice(0, 4), ["exec", join(profiles, "rhel9.tar.gz"), "-t", "ssh://alice@10.0.0.9"]);
  assert.ok(a.includes("--sudo") && a.includes("-i") && a.includes("--no-color"));
  for (const bad of ["--command", "-c", "--sudo-command", "--shell-command", "--shell"]) assert.ok(!a.includes(bad), bad);
  clean(stig, rs);
  await assert.rejects(run(stig, opts, { cinc: fake(1) }, { STIG_TARGET_PASSWORD: "sup3rs3cretvalue" }), (e: Error) => /exited 1/.test(e.message) && !e.message.includes("sup3rs3cretvalue"));
  await assert.rejects(run(stig, opts, { cinc: fake(0, false) }), /wrote no report/);
  await assert.rejects(run(stig, { ...opts, "stig-profile": "rhel8" }, { cinc: fake(0) }), /not there/);
  assert.deepEqual(cincArgs({ archive: "a", target: "local://", sudo: false, inputFiles: ["i.yml"] }, "/r.json"),
    ["exec", "a", "-t", "local://", "--reporter", "json:/r.json", "--no-color", "--input-file", "i.yml"]);
});

// ── Kubescape ──────────────────────────────────────────────────────────────────────────────────────

const KS = ids("kubescape");
const ksDoc = (controls: Record<string, [string, string | undefined, number, number, number]>, extra: Record<string, unknown> = {}) => ({
  generationTime: daysAgo(1), clusterAPIServerInfo: null, clusterCloudProvider: "", customerGUID: "", clusterName: "", reportGUID: "g",
  summaryDetails: {
    controls: Object.fromEntries(Object.entries(controls).map(([id, [status, sub, p, f, s]]) => [id, {
      controlID: id, name: "n", status, statusInfo: { status, ...(sub ? { subStatus: sub } : {}) },
      ResourceCounters: { passedResources: p, failedResources: f, skippedResources: s, excludedResources: 0 },
      subStatusCounters: { ignoredResources: 0, acknowledgedResources: 0 }, score: 0, scoreFactor: 0,
    }])),
    frameworks: [{ name: "NSA", version: "" }, { name: "MITRE", version: "" }], status: "failed",
  },
  metadata: { scanMetadata: { targetType: "Framework", kubescapeVersion: "v4.0.15", formatVersion: "v2", scanningTarget: 4, targetNames: ["nsa", "mitre"] },
              targetMetadata: { directoryContextMetadata: { basePath: "/home/alice/k8s", hostName: "alice-laptop" } } },
  results: [{ resourceID: "path=1/api=apps/v1/carol/Deployment/web" }],
  ...extra,
});

test("kubescape: catalogue has no CIS or SOC 2 control and every check maps to a hub control", { skip: NO_MAPPINGS }, () => {
  assert.ok(KS.size >= 30, String(KS.size));
  for (const i of KS) {
    const c = catalog.get(i)!;
    assert.ok(c.hub!.length > 0, i);
    assert.ok(!/\bCIS\b|\bSOC ?2\b|\bAICPA\b|\bISO\b/.test(c.title), c.title);
  }
});

test("kubescape: failed, passed, irrelevant, skipped and unknown controls", async () => {
  const { rs, warns } = await run(kubescape, { "kubescape-report": file(ksDoc({
    "C-0057": ["failed", undefined, 1, 1, 0], "C-0038": ["passed", undefined, 2, 0, 0], "C-0015": ["passed", "irrelevant", 0, 0, 0],
    "C-0066": ["skipped", "configuration", 0, 0, 0], "C-0030": ["passed", "w/exceptions", 3, 0, 0], "C-0070": ["passed", "incompleteCoverage", 2, 0, 0],
    "C-0092": ["failed", undefined, 0, 1, 0],
  })) });
  assert.equal(one(rs, "kubescape.c-0057").result, "fail"); assert.match(one(rs, "kubescape.c-0057").detail, /1 resource\(s\) failed, 1 passed/);
  assert.equal(one(rs, "kubescape.c-0038").result, "pass");
  assert.equal(one(rs, "kubescape.c-0015").result, "skipped");
  assert.equal(one(rs, "kubescape.c-0066").result, "skipped");
  assert.equal(one(rs, "kubescape.c-0030").result, "pass"); assert.match(one(rs, "kubescape.c-0030").detail, /excepted/);
  assert.equal(one(rs, "kubescape.c-0070").result, "skipped");
  assert.ok(!rs.some((r) => r.check === "kubescape.c-0092"));
  assert.match(warns.join(""), /1 not in the catalogue and dropped \(C-0092\)/);
  assert.match(rs[0].resource, /^kubescape directory r\d+\.json$/);
  clean(kubescape, rs);
});

test("kubescape: a cluster scan names the cluster, never the user part of the context", () => {
  const r = parseKubescape(ksDoc({ "C-0057": ["passed", undefined, 4, 0, 0] }, { clusterName: "alice@prod-east", metadata: { scanMetadata: { scanningTarget: 0 } } }), "/x/r.json", KS);
  assert.equal(r.results[0].resource, "kubescape cluster prod-east");
});

test("kubescape: a stale, foreign or missing report is skipped or refused, never passed", async () => {
  const { rs } = await run(kubescape, { "kubescape-report": file(ksDoc({ "C-0038": ["passed", undefined, 2, 0, 0] }, { generationTime: daysAgo(40) })) });
  assert.equal(one(rs, "kubescape.c-0038").result, "skipped"); assert.match(one(rs, "kubescape.c-0038").detail, /40 days old/);
  await assert.rejects(run(kubescape, { "kubescape-report": file({ matches: [] }) }), /not a Kubescape JSON report/);
  await assert.rejects(run(kubescape, { "kubescape-report": join(dir, "missing.json") }), /not readable/);
  await assert.rejects(run(kubescape, {}), /--kubescape-report/);
});

// ── Checkov ────────────────────────────────────────────────────────────────────────────────────────

const CK = ids("checkov");
const rec = (id: string, result: string, resource: string) => ({
  check_id: id, bc_check_id: null, check_name: "n", check_result: { result }, code_block: [[1, "secret = \"x\""]],
  file_path: "/main.tf", file_abs_path: "/home/alice/infra/main.tf", repo_file_path: "/home/alice/infra/main.tf",
  file_line_range: [1, 3], resource, severity: null, benchmarks: {}, guideline: null,
});
const ckReport = (type: string, recs: ReturnType<typeof rec>[], quiet = false) => {
  const by = (r: string) => recs.filter((x) => x.check_result.result === r);
  return {
    check_type: type,
    results: quiet ? { failed_checks: by("FAILED") } : { passed_checks: by("PASSED"), failed_checks: by("FAILED"), skipped_checks: by("SKIPPED"), parsing_errors: [] },
    summary: { passed: by("PASSED").length, failed: by("FAILED").length, skipped: by("SKIPPED").length, parsing_errors: 0, resource_count: 3, checkov_version: "3.3.21" },
    url: "Add an api key '--bc-api-key <api-key>' to see more detailed insights via https://bridgecrew.cloud",
  };
};

test("checkov: catalogue checks all carry CM-6, and the plan check carries KSI-CMT-VTD", { skip: NO_MAPPINGS }, () => {
  assert.ok(CK.size >= 40, String(CK.size));
  for (const i of CK) assert.ok(catalog.get(i)!.hub!.includes("cm-6"), i);
  assert.ok(catalog.get(PLAN_CHECK)!.ksis!.includes("KSI-CMT-VTD"));
  assert.equal(resourceType("aws_iam_user.alice"), "aws_iam_user");
  assert.equal(resourceType("module.net.aws_security_group.admin"), "aws_security_group");
  assert.equal(resourceType("Deployment.carol.web"), "Deployment");
});

test("checkov: per-check outcomes over several frameworks, with types and never names or paths", async () => {
  const doc = [
    ckReport("terraform", [rec("CKV_AWS_24", "FAILED", "aws_security_group.alice_admin"), rec("CKV_AWS_24", "PASSED", "aws_security_group.web"),
      rec("CKV_AWS_3", "PASSED", "aws_ebs_volume.data"), rec("CKV_AWS_7", "SKIPPED", "aws_kms_key.k"), rec("CKV_AWS_999", "FAILED", "x.y")]),
    ckReport("kubernetes", [rec("CKV_K8S_16", "FAILED", "Deployment.carol.web")]),
  ];
  const { rs, warns } = await run(checkov, { "checkov-report": file(doc) });
  const tf = rs.filter((r) => r.resource.startsWith("checkov terraform "));
  assert.equal(one(tf, "checkov.ckv_aws_24").result, "fail"); assert.match(one(tf, "checkov.ckv_aws_24").detail, /aws_security_group ×1/);
  assert.equal(one(tf, "checkov.ckv_aws_3").result, "pass");
  assert.equal(one(tf, "checkov.ckv_aws_7").result, "skipped");
  assert.equal(one(rs, "checkov.ckv_k8s_16").result, "fail");
  assert.ok(!rs.some((r) => r.check === PLAN_CHECK), "the plan check comes from a terraform_plan report only");
  assert.match(warns.join(""), /terraform, kubernetes; \d+ results; 1 check\(s\) not in the catalogue dropped/);
  clean(checkov, rs);
});

test("checkov: a Terraform plan report gives the plan check; quiet and empty reports never pass", async () => {
  let { rs } = await run(checkov, { "checkov-report": file(ckReport("terraform_plan", [rec("CKV_AWS_3", "PASSED", "aws_ebs_volume.data"), rec("CKV_AWS_145", "PASSED", "aws_s3_bucket.b")])) });
  assert.equal(one(rs, PLAN_CHECK).result, "pass");
  ({ rs } = await run(checkov, { "checkov-report": file(ckReport("terraform_plan", [rec("CKV_AWS_999", "FAILED", "x.y")])) }));
  assert.equal(one(rs, PLAN_CHECK).result, "fail"); assert.match(one(rs, PLAN_CHECK).detail, /CKV_AWS_999/);
  ({ rs } = await run(checkov, { "checkov-report": file(ckReport("terraform_plan", [rec("CKV_AWS_3", "PASSED", "aws_ebs_volume.d")], true)) }));
  assert.equal(one(rs, PLAN_CHECK).result, "skipped");
  ({ rs } = await run(checkov, { "checkov-report": file(ckReport("terraform", [rec("CKV_AWS_3", "PASSED", "aws_ebs_volume.d"), rec("CKV_AWS_24", "FAILED", "aws_security_group.a")], true)) }));
  assert.ok(!rs.some((r) => r.check === "checkov.ckv_aws_3"), "quiet reports list no passes");
  assert.equal(one(rs, "checkov.ckv_aws_24").result, "fail");
  assert.deepEqual(parseCheckov({ passed: 0, failed: 0, skipped: 0, parsing_errors: 0, resource_count: 0, checkov_version: "3.3.21" }, "/e.json", CK).results, []);
});

test("checkov: a stale or foreign report is skipped or refused", async () => {
  const { rs } = await run(checkov, { "checkov-report": file(ckReport("terraform", [rec("CKV_AWS_3", "PASSED", "aws_ebs_volume.d")]), 45) });
  assert.equal(one(rs, "checkov.ckv_aws_3").result, "skipped"); assert.match(one(rs, "checkov.ckv_aws_3").detail, /45 days old/);
  await assert.rejects(run(checkov, { "checkov-report": file({ SchemaVersion: 2 }) }), /not a Checkov JSON report/);
  await assert.rejects(run(checkov, {}), /--checkov-report/);
});
