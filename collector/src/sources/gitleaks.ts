// Gitleaks (MIT): the JSON report (`gitleaks git|dir --report-format json --report-path <file>`) the
// customer's pipeline writes. Read locally; no network.
//
// Shape (report/json.go encodes []Finding; report/finding.go; testdata/expected/report/json_simple.json
// and empty.json): a JSON array, `[]` when nothing leaked, else
//   [ { RuleID, Description, File, StartLine, Commit, Secret, Match, Author, Email, Date, Fingerprint, ... } ]
//
// A finding holds the secret itself and the committer's name and email. None of that is read into a
// result: only the number of findings, the rule ids (e.g. "aws-access-token") and how many files and
// commits they touch. The report has no timestamp, so its freshness is the file's modification time.

import { basename } from "node:path";
import type { Result, Source, SourceContext } from "../types.ts";
import { isObj, Results } from "./shared-cloud.ts";
import { paths, posNum, readJsonFile, staleness } from "./report_files.ts";

export const GITLEAKS_CHECKS = ["no_findings"] as const;
type C = (typeof GITLEAKS_CHECKS)[number];
const DEFAULT_MAX_AGE_DAYS = 30;

export const gitleaks: Source = {
  name: "gitleaks",
  options: {
    "gitleaks-report": { type: "string", multiple: true, help: "Gitleaks JSON report (`--report-format json --report-path <file>`); repeatable, one per repository" },
    "gitleaks-max-age-days": { type: "string", help: `days a report file stays current, by its modification time (default ${DEFAULT_MAX_AGE_DAYS})` },
  },
  emits: GITLEAKS_CHECKS.map((c) => `gitleaks.${c}`),
  describe(opts) {
    const ps = paths(opts["gitleaks-report"]);
    return `gitleaks reports ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Results<C>("gitleaks");
    const files = paths(ctx.opts["gitleaks-report"]);
    if (!files.length) { out.skip("no_findings", "gitleaks", "give --gitleaks-report <file>; run `gitleaks git --report-format json --report-path <file>` in the pipeline first"); return out.results; }
    const maxAge = posNum(ctx.opts["gitleaks-max-age-days"], DEFAULT_MAX_AGE_DAYS);
    for (const f of files) {
      const resource = `gitleaks ${basename(f)}`;
      const r = readJsonFile(f);
      if ("error" in r) { out.skip("no_findings", resource, r.error); continue; }
      if (!Array.isArray(r.data)) { out.skip("no_findings", resource, `${basename(f)} is not a Gitleaks JSON report (a JSON array of findings)`); continue; }
      const stale = staleness(r.mtime.toISOString(), ctx.now, maxAge, "report file");
      if (stale) { out.skip("no_findings", resource, stale); continue; }
      const findings = r.data.filter(isObj);
      if (findings.length !== r.data.length || findings.some((x) => !("RuleID" in x))) { out.skip("no_findings", resource, `${basename(f)} holds entries that are not Gitleaks findings (no RuleID)`); continue; }
      const rules = new Map<string, number>();
      const files_ = new Set<string>(), commits = new Set<string>();
      for (const x of findings) {
        const id = String(x.RuleID).replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 60) || "?";
        rules.set(id, (rules.get(id) ?? 0) + 1);
        files_.add(String(x.File ?? "")); if (x.Commit) commits.add(String(x.Commit));
      }
      const byRule = [...rules].sort((a, b) => b[1] - a[1]).slice(0, 30).map(([k, n]) => `${k} ${n}`).join(", ");
      out.add("no_findings", resource, findings.length ? "fail" : "pass",
        findings.length
          ? `${findings.length} finding(s) in ${files_.size} file(s)${commits.size ? ` across ${commits.size} commit(s)` : ""}; by rule: ${byRule}; zero findings required (the secrets, authors and paths stay in the report)`
          : "0 findings; zero findings required");
    }
    return out.results;
  },
};
