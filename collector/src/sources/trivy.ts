// Trivy (Aqua Security, Apache-2.0): the JSON report (`trivy image|fs|repo|config --format json`) the
// customer's pipeline already writes. The collector reads the file; it never runs Trivy and never
// calls the network.
//
// Shape (pkg/types/report.go, SchemaVersion 2; checked against integration/testdata/*.json.golden):
//   { SchemaVersion, CreatedAt, ArtifactName, ArtifactType: container_image|filesystem|repository|vm|...,
//     Results: [ { Target, Class: os-pkgs|lang-pkgs|config|secret|license, Type,
//                  Vulnerabilities: [ { VulnerabilityID, Severity, FixedVersion, Status } ],
//                  MisconfSummary: { Successes, Failures },
//                  Misconfigurations: [ { ID, AVDID, Severity, Status: PASS|FAIL|EXCEPTION } ] } ] }
//
// Results carry counts, severities and the public advisory or check ids (CVE-…, AVD-…/DS-…), never
// file contents, package paths or the scanned image's configuration.

import { basename } from "node:path";
import type { Result, Source, SourceContext } from "../types.ts";
import { arr, isObj, str, Results, type Obj } from "./shared-cloud.ts";
import { bySeverity, idList, paths, posNum, readJsonFile, staleness } from "./report_files.ts";

export const TRIVY_CHECKS = ["iac_no_high_misconfig", "image_no_critical_vulns", "dependencies_no_critical_vulns"] as const;
type C = (typeof TRIVY_CHECKS)[number];
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
const DEFAULTS = { maxAgeDays: 30, misconfig: ["CRITICAL", "HIGH"], vuln: ["CRITICAL"] };

const sevList = (v: unknown, d: string[]) => {
  const xs = (typeof v === "string" ? v.split(",") : []).map((s) => s.trim().toUpperCase()).filter((s) => (SEVERITIES as readonly string[]).includes(s));
  return xs.length ? xs : d;
};

function vulnCheck(out: Results<C>, check: C, resource: string, results: Obj[], classes: string[], want: string[]) {
  const pkgResults = results.filter((r) => classes.includes(String(r.Class)));
  if (!pkgResults.length) return out.skip(check, resource, `the report has no ${classes.join(" or ")} result; the vulnerability scanner did not run or found no packages`);
  const counts = new Map<string, number>();
  const hits = new Set<string>();
  let fixable = 0;
  for (const r of pkgResults) for (const v of arr(r.Vulnerabilities).filter(isObj)) {
    const sev = String(v.Severity ?? "UNKNOWN").toUpperCase();
    counts.set(sev, (counts.get(sev) ?? 0) + 1);
    if (want.includes(sev)) {
      hits.add(String(v.VulnerabilityID ?? "?"));
      if (str(v.FixedVersion)) fixable++;
    }
  }
  out.add(check, resource, hits.size ? "fail" : "pass",
    `${pkgResults.length} package target(s) scanned; vulnerabilities by severity: ${bySeverity(counts, SEVERITIES)}; ${hits.size} distinct ${want.join("/")} advisory id(s)${idList([...hits].sort())}, ${fixable} finding(s) with a fixed version; none at ${want.join("/")} required`);
}

export const trivy: Source = {
  name: "trivy",
  options: {
    "trivy-report": { type: "string", multiple: true, help: "Trivy JSON report (`trivy … --format json --output <file>`); repeatable" },
    "trivy-max-age-days": { type: "string", help: `days a report stays current (default ${DEFAULTS.maxAgeDays})` },
    "trivy-misconfig-severities": { type: "string", help: `misconfiguration severities that fail (default ${DEFAULTS.misconfig.join(",")})` },
    "trivy-vuln-severities": { type: "string", help: `vulnerability severities that fail (default ${DEFAULTS.vuln.join(",")})` },
  },
  emits: TRIVY_CHECKS.map((c) => `trivy.${c}`),
  describe(opts) {
    const ps = paths(opts["trivy-report"]);
    return `trivy reports ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Results<C>("trivy");
    const files = paths(ctx.opts["trivy-report"]);
    if (!files.length) { out.skipAll(TRIVY_CHECKS, "trivy", "give --trivy-report <file>; run `trivy image|fs|config --format json --output <file>` in the pipeline first"); return out.results; }
    const maxAge = posNum(ctx.opts["trivy-max-age-days"], DEFAULTS.maxAgeDays);
    const misSev = sevList(ctx.opts["trivy-misconfig-severities"], DEFAULTS.misconfig);
    const vulnSev = sevList(ctx.opts["trivy-vuln-severities"], DEFAULTS.vuln);
    for (const f of files) {
      const r = readJsonFile(f);
      if ("error" in r) { out.skipAll(TRIVY_CHECKS, `trivy ${basename(f)}`, r.error); continue; }
      const d = r.data;
      if (!isObj(d) || !("SchemaVersion" in d) || !("ArtifactName" in d || "Results" in d)) { out.skipAll(TRIVY_CHECKS, `trivy ${basename(f)}`, `${basename(f)} is not a Trivy JSON report (no SchemaVersion/ArtifactName)`); continue; }
      const type = str(d.ArtifactType) ?? "unknown";
      const resource = `trivy ${type} ${str(d.ArtifactName) ?? basename(f)}`;
      if (d.SchemaVersion !== 2) { out.skipAll(TRIVY_CHECKS, resource, `report SchemaVersion ${String(d.SchemaVersion)}; this reader knows version 2`); continue; }
      const created = str(d.CreatedAt);
      const stale = staleness(created ?? r.mtime.toISOString(), ctx.now, maxAge, created ? "report" : "report file (no CreatedAt; file time used)");
      if (stale) { out.skipAll(TRIVY_CHECKS, resource, stale); continue; }
      const results = arr(d.Results).filter(isObj);

      // Misconfigurations: config results exist (with MisconfSummary) whenever IaC files were scanned.
      const cfg = results.filter((x) => x.Class === "config");
      if (!cfg.length) out.skip("iac_no_high_misconfig", resource, "the report has no config result; the misconfiguration scanner did not run or found no IaC files");
      else {
        const counts = new Map<string, number>();
        const ids = new Set<string>();
        let passed = 0;
        for (const x of cfg) {
          passed += Number(isObj(x.MisconfSummary) ? x.MisconfSummary.Successes ?? 0 : 0) || 0;
          for (const m of arr(x.Misconfigurations).filter(isObj)) {
            if (String(m.Status).toUpperCase() !== "FAIL") continue;
            const sev = String(m.Severity ?? "UNKNOWN").toUpperCase();
            counts.set(sev, (counts.get(sev) ?? 0) + 1);
            if (misSev.includes(sev)) ids.add(String(m.AVDID ?? m.ID ?? "?"));
          }
        }
        const bad = misSev.reduce((n, s) => n + (counts.get(s) ?? 0), 0);
        out.add("iac_no_high_misconfig", resource, bad ? "fail" : "pass",
          `${cfg.length} IaC file(s) scanned, ${passed} check(s) passed; failed by severity: ${bySeverity(counts, SEVERITIES)}; ${bad} at ${misSev.join("/")}${idList([...ids].sort(), "check ids ")}; none at ${misSev.join("/")} required`);
      }

      if (type === "container_image") vulnCheck(out, "image_no_critical_vulns", resource, results, ["os-pkgs", "lang-pkgs"], vulnSev);
      else out.skip("image_no_critical_vulns", resource, `the report is of a ${type}, not a container image`);
      if (type === "filesystem" || type === "repository") vulnCheck(out, "dependencies_no_critical_vulns", resource, results, ["lang-pkgs", "os-pkgs"], vulnSev);
      else out.skip("dependencies_no_critical_vulns", resource, `the report is of a ${type}, not a filesystem or repository`);
    }
    return out.results;
  },
};
