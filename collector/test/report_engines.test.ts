// Trivy, Grype, Syft (SBOMs), Gitleaks and OpenSSF Scorecard over report files written to a temp
// directory. Each fixture follows the field names of the tool's own golden output (cited per source
// file). No network; nothing is executed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { trivy } from "../src/sources/trivy.ts";
import { grype } from "../src/sources/grype.ts";
import { syft } from "../src/sources/syft.ts";
import { gitleaks } from "../src/sources/gitleaks.ts";
import { scorecard, SCORECARD_MAP } from "../src/sources/scorecard.ts";
import type { OptionValue, Result, Source } from "../src/types.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const dir = mkdtempSync(join(tmpdir(), "engines-test-"));
let n = 0;
const file = (body: unknown, raw = false) => { const p = join(dir, `r${n++}.json`); writeFileSync(p, raw ? String(body) : JSON.stringify(body)); return p; };
const run = (s: Source, opts: Record<string, OptionValue>): Promise<Result[]> => s.run({ opts, env: {}, clients: {}, now: NOW, warn: () => {} });
const one = (rs: Result[], id: string) => { const m = rs.filter((r) => r.check === id); assert.equal(m.length, 1, `${id}: ${JSON.stringify(rs)}`); return m[0]; };

function everyResultDeclared(s: Source, rs: Result[]) {
  for (const r of rs) {
    assert.ok(s.emits.includes(r.check), r.check);
    assert.ok(r.detail.length > 0 && r.detail.length <= 1000 && r.resource.length <= 300);
  }
}

// ── Trivy (integration/testdata/dockerfile.json.golden, alpine-310.json.golden) ─────────────────────

const trivyImage = (vulns: { id: string; sev: string; fixed?: string }[]) => ({
  SchemaVersion: 2, CreatedAt: daysAgo(1), ArtifactName: "registry.example/app:1.4.2", ArtifactType: "container_image",
  Metadata: { ImageID: "sha256:abc" },
  Results: [{ Target: "registry.example/app:1.4.2 (alpine 3.20)", Class: "os-pkgs", Type: "alpine",
    Vulnerabilities: vulns.map((v) => ({ VulnerabilityID: v.id, PkgName: "openssl", InstalledVersion: "3.0.1", FixedVersion: v.fixed, Status: v.fixed ? "fixed" : "affected", Severity: v.sev })) }],
});
const trivyRepo = (fails: { id: string; sev: string }[]) => ({
  SchemaVersion: 2, CreatedAt: daysAgo(1), ArtifactName: ".", ArtifactType: "repository",
  Results: [
    { Target: "Dockerfile", Class: "config", Type: "dockerfile", MisconfSummary: { Successes: 26, Failures: fails.length },
      Misconfigurations: fails.map((f) => ({ Type: "Dockerfile Security Check", ID: f.id, AVDID: `AVD-${f.id}`, Title: "t", Severity: f.sev, Status: "FAIL", Message: "secret text in a message" })) },
    { Target: "package-lock.json", Class: "lang-pkgs", Type: "npm", Vulnerabilities: [{ VulnerabilityID: "CVE-2024-1", PkgName: "x", Severity: "HIGH", FixedVersion: "2.0.0" }] },
  ],
});

test("trivy: a clean image and repository pass; critical vulnerabilities and high misconfigurations fail with ids", async () => {
  let rs = await run(trivy, { "trivy-report": [file(trivyImage([{ id: "CVE-2025-9", sev: "HIGH", fixed: "3.0.2" }])), file(trivyRepo([{ id: "DS-0026", sev: "LOW" }]))] });
  everyResultDeclared(trivy, rs);
  const img = rs.filter((r) => r.resource.startsWith("trivy container_image"));
  const repo = rs.filter((r) => r.resource.startsWith("trivy repository"));
  assert.equal(one(img, "trivy.image_no_critical_vulns").result, "pass");
  assert.equal(one(img, "trivy.dependencies_no_critical_vulns").result, "skipped");
  assert.equal(one(img, "trivy.iac_no_high_misconfig").result, "skipped");
  assert.equal(one(repo, "trivy.iac_no_high_misconfig").result, "pass");
  assert.equal(one(repo, "trivy.dependencies_no_critical_vulns").result, "pass");   // HIGH only; CRITICAL fails by default

  rs = await run(trivy, { "trivy-report": [file(trivyImage([{ id: "CVE-2025-1", sev: "CRITICAL", fixed: "3.0.2" }])), file(trivyRepo([{ id: "DS-0002", sev: "HIGH" }]))], "trivy-vuln-severities": "CRITICAL,HIGH" });
  const v = rs.find((r) => r.check === "trivy.image_no_critical_vulns" && r.resource.includes("container_image"))!;
  assert.equal(v.result, "fail"); assert.match(v.detail, /CVE-2025-1/); assert.match(v.detail, /1 finding\(s\) with a fixed version/);
  const m = rs.find((r) => r.check === "trivy.iac_no_high_misconfig" && r.resource.includes("repository"))!;
  assert.equal(m.result, "fail"); assert.match(m.detail, /AVD-DS-0002/); assert.ok(!m.detail.includes("secret text"));
  assert.equal(rs.find((r) => r.check === "trivy.dependencies_no_critical_vulns" && r.resource.includes("repository"))!.result, "fail");
});

test("trivy: a stale, foreign or unreadable report is skipped, never passed", async () => {
  const old = { ...trivyImage([]), CreatedAt: daysAgo(45) };
  for (const f of [file(old), file({ matches: [] }), file("{nope", true), join(dir, "missing.json"), file({ ...trivyImage([]), SchemaVersion: 1 })]) {
    const rs = await run(trivy, { "trivy-report": f });
    assert.ok(rs.length === 3 && rs.every((r) => r.result === "skipped"), JSON.stringify(rs));
  }
  assert.ok((await run(trivy, {})).every((r) => r.result === "skipped"));
  assert.equal(one(await run(trivy, { "trivy-report": file(old), "trivy-max-age-days": "60" }), "trivy.image_no_critical_vulns").result, "pass");
});

// ── Grype (grype/presenter/json/testdata/snapshot/*.golden; models/vulnerability.go) ────────────────

const grypeDoc = (matches: { id: string; sev: string; state: string; date?: string }[]) => ({
  matches: matches.map((m) => ({
    vulnerability: { id: m.id, dataSource: "", severity: m.sev, urls: [], fix: { versions: m.state === "fixed" ? ["1.2.1"] : [], state: m.state, ...(m.date ? { available: [{ version: "1.2.1", date: m.date }] } : {}) }, advisories: [], risk: 1 },
    relatedVulnerabilities: [], matchDetails: [], artifact: { name: "pkg", version: "1.0", type: "deb" },
  })),
  source: { type: "image", target: { userInput: "registry.example/app:1.4.2", imageID: "sha256:abc" } },
  distro: { name: "debian", version: "12" },
  descriptor: { name: "grype", version: "0.92.0", timestamp: "2026-10-15T05:21:52.123456789-07:00" },
});

test("grype: a fix available for longer than the allowed days fails; recent fixes and unfixable ones do not", async () => {
  const day = (d: number) => daysAgo(d).slice(0, 10);
  let r = one(await run(grype, { "grype-report": file(grypeDoc([{ id: "CVE-1", sev: "Critical", state: "fixed", date: day(5) }, { id: "CVE-2", sev: "High", state: "not-fixed" }, { id: "CVE-3", sev: "Medium", state: "fixed", date: day(400) }])) }), "grype.no_aged_fixable_critical_high");
  assert.equal(r.result, "pass", r.detail); assert.equal(r.resource, "grype image registry.example/app:1.4.2");
  assert.match(r.detail, /1 critical\/high without a fix/);
  r = one(await run(grype, { "grype-report": file(grypeDoc([{ id: "CVE-4", sev: "High", state: "fixed", date: day(45) }, { id: "CVE-5", sev: "Critical", state: "fixed" }])) }), "grype.no_aged_fixable_critical_high");
  assert.equal(r.result, "fail"); assert.match(r.detail, /CVE-4, CVE-5/); assert.match(r.detail, /1 with no fix date/);
  r = one(await run(grype, { "grype-report": file(grypeDoc([{ id: "CVE-4", sev: "High", state: "fixed", date: day(45) }])), "grype-fix-days": "60" }), "grype.no_aged_fixable_critical_high");
  assert.equal(r.result, "pass");
});

test("grype: not a Grype report, or too old, gives skipped", async () => {
  assert.equal(one(await run(grype, { "grype-report": file({ SchemaVersion: 2 }) }), "grype.no_aged_fixable_critical_high").result, "skipped");
  const old = { ...grypeDoc([]), descriptor: { name: "grype", version: "0.92.0", timestamp: daysAgo(40) } };
  const r = one(await run(grype, { "grype-report": file(old) }), "grype.no_aged_fixable_critical_high");
  assert.equal(r.result, "skipped"); assert.match(r.detail, /40 days old/);
});

// ── SBOMs (syft/format/{cyclonedxjson,spdxjson,syftjson}/testdata/snapshot/*.golden) ─────────────────

const cdx = (comps: { purl?: string }[]) => ({ bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: "urn:uuid:x", version: 1,
  metadata: { timestamp: daysAgo(2), tools: { components: [{ type: "application", author: "anchore", name: "syft", version: "1.20.0" }] } },
  components: comps.map((c, i) => ({ "bom-ref": `r${i}`, type: "library", name: `package-${i}`, version: "1.0.1", ...(c.purl ? { purl: c.purl } : {}) })) });
const spdx = { spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: "img", documentNamespace: "x", documentDescribes: ["SPDXRef-root"],
  creationInfo: { creators: ["Tool: syft-1.20.0"], created: daysAgo(3) },
  packages: [{ name: "img", SPDXID: "SPDXRef-root", versionInfo: "sha256:x" },
    { name: "package-1", SPDXID: "SPDXRef-Package-1", versionInfo: "1.0.1", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:npm/package-1@1.0.1" }] }] };
const syftJson = { artifacts: [{ name: "a", version: "1", purl: "pkg:deb/debian/a@1" }], artifactRelationships: [], source: {}, distro: {}, descriptor: { name: "syft", version: "1.20.0" }, schema: { version: "16.0.0" } };

test("syft: CycloneDX, SPDX and Syft JSON SBOMs with components pass; package URL coverage is measured", async () => {
  const rs = await run(syft, { "sbom-file": [file(cdx([{ purl: "pkg:npm/a@1" }, { purl: "pkg:npm/b@1" }])), file(spdx), file(syftJson)] });
  everyResultDeclared(syft, rs);
  for (const r of rs) assert.equal(r.result, "pass", `${r.check} ${r.resource}: ${r.detail}`);
  assert.match(rs.find((r) => r.check === "syft.sbom_present" && r.detail.startsWith("SPDX"))!.detail, /1 component/);   // the described root is not a component
  const low = await run(syft, { "sbom-file": file(cdx([{ purl: "pkg:npm/a@1" }, {}, {}])) });
  assert.equal(one(low, "syft.sbom_components_identified").result, "fail");
  assert.match(one(low, "syft.sbom_components_identified").detail, /1 of 3 component\(s\) \(33\.3%\)/);
});

test("syft: a named SBOM that is missing, not an SBOM, empty or too old fails; none named is skipped", async () => {
  for (const f of [join(dir, "release-9.cdx.json"), file({ hello: 1 }), file(cdx([]))]) assert.equal(one(await run(syft, { "sbom-file": f }), "syft.sbom_present").result, "fail");
  const old = { ...cdx([{ purl: "pkg:npm/a@1" }]), metadata: { timestamp: daysAgo(200) } };
  assert.equal(one(await run(syft, { "sbom-file": file(old) }), "syft.sbom_present").result, "pass");
  assert.equal(one(await run(syft, { "sbom-file": file(old), "sbom-max-age-days": "90" }), "syft.sbom_present").result, "fail");
  assert.ok((await run(syft, {})).every((r) => r.result === "skipped"));
});

// ── Gitleaks (testdata/expected/report/json_simple.json, empty.json) ─────────────────────────────────

test("gitleaks: [] passes; findings fail with counts and rule ids only, never the secret, author or email", async () => {
  assert.equal(one(await run(gitleaks, { "gitleaks-report": file([]) }), "gitleaks.no_findings").result, "pass");
  const finding = { RuleID: "aws-access-token", Description: "", StartLine: 1, EndLine: 2, StartColumn: 1, EndColumn: 2, Match: "AKIAEXAMPLESECRET1234", Secret: "AKIAEXAMPLESECRET1234",
    File: "deploy/secret-config.py", SymlinkFile: "", Commit: "0000000000000000", Entropy: 3.5, Author: "John Doe", Email: "dev@example.com", Date: "10-19-2003", Message: "opps", Tags: [], Fingerprint: "0000:deploy/secret-config.py:aws-access-token:1" };
  const r = one(await run(gitleaks, { "gitleaks-report": file([finding, { ...finding, RuleID: "generic-api-key", Commit: "1111" }]) }), "gitleaks.no_findings");
  assert.equal(r.result, "fail");
  assert.match(r.detail, /2 finding\(s\) in 1 file\(s\) across 2 commit/);
  assert.match(r.detail, /aws-access-token 1/);
  for (const bad of ["AKIA", "John", "dev@example", "secret-config", "opps"]) assert.ok(!JSON.stringify(r).includes(bad), bad);
});

test("gitleaks: an old file, or JSON that is not a findings array, gives skipped", async () => {
  const p = file([]);
  utimesSync(p, new Date(daysAgo(60)), new Date(daysAgo(60)));
  assert.equal(one(await run(gitleaks, { "gitleaks-report": p }), "gitleaks.no_findings").result, "skipped");
  assert.equal(one(await run(gitleaks, { "gitleaks-report": file({ findings: [] }) }), "gitleaks.no_findings").result, "skipped");
  assert.equal(one(await run(gitleaks, { "gitleaks-report": file([{ foo: 1 }]) }), "gitleaks.no_findings").result, "skipped");
});

// ── OpenSSF Scorecard (pkg/scorecard/testdata/check1.json; JSONScorecardResultV2) ───────────────────

const scoreDoc = (scores: Record<string, number>, date = daysAgo(1)) => ({
  date, repo: { name: "github.com/acme/api", commit: "68bc59901773ab4c051dfcea0cc4201a1567ab32" }, scorecard: { version: "v5.2.1", commit: "ccbc5990" }, score: 7.1,
  checks: Object.entries(scores).map(([name, score]) => ({ details: ["Warn: by user someone@example.com in src/x"], score, reason: "reason with a username", name, documentation: { url: "u", short: "s" } })),
  metadata: [],
});

test("scorecard: each mapped check passes at the threshold, fails below it and is skipped when inconclusive or absent", async () => {
  const all = Object.fromEntries(Object.values(SCORECARD_MAP).map((n) => [n, 10]));
  let rs = await run(scorecard, { "scorecard-result": file(scoreDoc(all)) });
  everyResultDeclared(scorecard, rs);
  assert.equal(rs.length, Object.keys(SCORECARD_MAP).length);
  for (const r of rs) { assert.equal(r.result, "pass", r.detail); assert.equal(r.resource, "repo github.com/acme/api"); }
  rs = await run(scorecard, { "scorecard-result": file(scoreDoc({ ...all, "Branch-Protection": 6, "Signed-Releases": -1, SAST: 7 })) });
  assert.equal(one(rs, "scorecard.branch_protection").result, "fail");
  assert.match(one(rs, "scorecard.branch_protection").detail, /6\/10.*at least 7/);
  assert.equal(one(rs, "scorecard.signed_releases").result, "skipped");
  assert.equal(one(rs, "scorecard.sast").result, "pass");
  const { SBOM: _drop, ...noSbom } = all;
  assert.equal(one(await run(scorecard, { "scorecard-result": file(scoreDoc(noSbom)) }), "scorecard.sbom").result, "skipped");
  assert.equal(one(await run(scorecard, { "scorecard-result": file(scoreDoc({ ...all, "Code-Review": 8 })), "scorecard-min-score": "9" }), "scorecard.code_review").result, "fail");
  assert.ok(!JSON.stringify(rs).includes("someone@example.com") && !JSON.stringify(rs).includes("username"));
});

test("scorecard: a stale or foreign file gives skipped for every check", async () => {
  for (const f of [file(scoreDoc({ SAST: 10 }, daysAgo(90))), file([])]) {
    const rs = await run(scorecard, { "scorecard-result": f });
    assert.ok(rs.length === Object.keys(SCORECARD_MAP).length && rs.every((r) => r.result === "skipped"));
  }
});
