// Grype (Anchore, Apache-2.0): the JSON report (`grype <image|dir|sbom> -o json`) the customer's
// pipeline writes. Read locally; no network.
//
// Shape (grype/presenter/models: document.go, match.go, vulnerability.go; checked against
// grype/presenter/json/testdata/snapshot/*.golden):
//   { matches: [ { vulnerability: { id, severity: Critical|High|Medium|Low|Negligible|Unknown,
//                                   fix: { versions: [], state: fixed|not-fixed|wont-fix|unknown,
//                                          available?: [ { version, date: "YYYY-MM-DD" } ] } },
//                  artifact: { name, version, type } } ],
//     source: { type: image|directory|file|…, target }, descriptor: { name: "grype", version, timestamp } }
//
// The check: no critical or high match whose fix has been available for longer than the allowed
// number of days. A fixable match with no fix date (older Grype, or a feed without dates) counts as
// aged: its age cannot be shown. Matches without a fix are counted in the detail, not failed.

import { basename } from "node:path";
import type { Result, Source, SourceContext } from "../types.ts";
import { arr, isObj, str, Results, type Obj } from "./shared-cloud.ts";
import { bySeverity, idList, localTarget, paths, posNum, readJsonFile, staleness } from "./report_files.ts";

export const GRYPE_CHECKS = ["no_aged_fixable_critical_high"] as const;
type C = (typeof GRYPE_CHECKS)[number];
const ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"] as const;
const DEFAULTS = { fixDays: 30, maxAgeDays: 30 };

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();

function targetName(src: Obj): string {
  const t = src.target;
  if (typeof t === "string") return t;
  if (isObj(t)) return str(t.userInput) ?? str(t.name) ?? str(t.path) ?? "?";
  return "?";
}

export const grype: Source = {
  name: "grype",
  options: {
    "grype-report": { type: "string", multiple: true, help: "Grype JSON report (`grype <target> -o json --file <file>`); repeatable" },
    "grype-fix-days": { type: "string", help: `days a critical or high fix may stay unapplied (default ${DEFAULTS.fixDays})` },
    "grype-max-age-days": { type: "string", help: `days a report stays current (default ${DEFAULTS.maxAgeDays})` },
  },
  emits: GRYPE_CHECKS.map((c) => `grype.${c}`),
  describe(opts) {
    const ps = paths(opts["grype-report"]);
    return `grype reports ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Results<C>("grype");
    const files = paths(ctx.opts["grype-report"]);
    if (!files.length) { out.skipAll(GRYPE_CHECKS, "grype", "give --grype-report <file>; run `grype <target> -o json --file <file>` in the pipeline first"); return out.results; }
    const fixDays = posNum(ctx.opts["grype-fix-days"], DEFAULTS.fixDays);
    const maxAge = posNum(ctx.opts["grype-max-age-days"], DEFAULTS.maxAgeDays);
    for (const f of files) {
      const r = readJsonFile(f);
      if ("error" in r) { out.skipAll(GRYPE_CHECKS, `grype ${basename(f)}`, r.error); continue; }
      const d = r.data;
      if (!isObj(d) || !Array.isArray(d.matches) || !isObj(d.descriptor) || str(d.descriptor.name) !== "grype") {
        out.skipAll(GRYPE_CHECKS, `grype ${basename(f)}`, `${basename(f)} is not a Grype JSON report (matches[] and descriptor.name "grype")`);
        continue;
      }
      const src = isObj(d.source) ? d.source : {};
      const resource = `grype ${str(src.type) ?? "source"} ${localTarget(targetName(src))}`;
      const ts = str(d.descriptor.timestamp);
      const stale = staleness(ts || r.mtime.toISOString(), ctx.now, maxAge, ts ? "report" : "report file (no descriptor.timestamp; file time used)");
      if (stale) { out.skipAll(GRYPE_CHECKS, resource, stale); continue; }

      const counts = new Map<string, number>();
      const aged: string[] = [], undated: string[] = [], recent: string[] = [];
      let noFix = 0;
      for (const m of d.matches.filter(isObj)) {
        const v = isObj(m.vulnerability) ? m.vulnerability : {};
        const sev = cap(String(v.severity ?? "Unknown"));
        counts.set(sev, (counts.get(sev) ?? 0) + 1);
        if (sev !== "Critical" && sev !== "High") continue;
        const fix = isObj(v.fix) ? v.fix : {};
        const id = String(v.id ?? "?");
        if (String(fix.state) !== "fixed") { noFix++; continue; }
        const dates = arr(fix.available).filter(isObj).map((a) => Date.parse(String(a.date ?? ""))).filter(Number.isFinite);
        if (!dates.length) { undated.push(id); continue; }
        const days = (ctx.now.getTime() - Math.min(...dates)) / 86_400_000;
        (days > fixDays ? aged : recent).push(id);
      }
      const bad = [...new Set([...aged, ...undated])].sort();
      out.add("no_aged_fixable_critical_high", resource, bad.length ? "fail" : "pass",
        `${d.matches.length} match(es) by severity: ${bySeverity(counts, ORDER)}; critical/high with a fix: ${aged.length} fixed upstream more than ${fixDays} days ago, ${undated.length} with no fix date (age unknown), ${recent.length} within ${fixDays} days${idList(bad)}; ${noFix} critical/high without a fix (counted, not judged); none aged or undated required`);
    }
    return out.results;
  },
};
