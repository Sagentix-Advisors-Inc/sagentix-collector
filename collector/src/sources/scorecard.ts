// OpenSSF Scorecard (Apache-2.0): the JSON result (`scorecard --repo=<repo> --format=json`, or the
// scorecard-action's results file with `results_format: json`). Read locally; no network.
//
// Shape (pkg/scorecard/json.go, JSONScorecardResultV2; pkg/scorecard/testdata/check1.json):
//   { date, repo: { name, commit }, scorecard: { version, commit }, score,
//     checks: [ { name: "Branch-Protection", score: 0..10 or -1, reason, details, documentation } ] }
// A score of -1 is Scorecard's InconclusiveResultScore (checker/check_result.go) and gives "skipped".
// Check names are the constants in checks/*.go. Only the score is sent; reason and details stay local.

import { basename } from "node:path";
import type { Result, Source, SourceContext } from "../types.ts";
import { arr, isObj, str, Results } from "./shared-cloud.ts";
import { nonNegNum, paths, posNum, readJsonFile, staleness } from "./report_files.ts";

/** Collector check name -> Scorecard check name. */
export const SCORECARD_MAP = {
  branch_protection: "Branch-Protection",
  code_review: "Code-Review",
  signed_releases: "Signed-Releases",
  pinned_dependencies: "Pinned-Dependencies",
  dangerous_workflow: "Dangerous-Workflow",
  token_permissions: "Token-Permissions",
  sast: "SAST",
  vulnerabilities: "Vulnerabilities",
  ci_tests: "CI-Tests",
  dependency_update_tool: "Dependency-Update-Tool",
  security_policy: "Security-Policy",
  sbom: "SBOM",
} as const;
type C = keyof typeof SCORECARD_MAP;
export const SCORECARD_CHECKS = Object.keys(SCORECARD_MAP) as C[];
const DEFAULTS = { minScore: 7, maxAgeDays: 30 };

export const scorecard: Source = {
  name: "scorecard",
  options: {
    "scorecard-result": { type: "string", multiple: true, help: "OpenSSF Scorecard JSON (`scorecard --repo=<repo> --format=json`); repeatable, one per repository" },
    "scorecard-min-score": { type: "string", help: `lowest passing score out of 10 (default ${DEFAULTS.minScore})` },
    "scorecard-max-age-days": { type: "string", help: `days a result stays current (default ${DEFAULTS.maxAgeDays})` },
  },
  emits: SCORECARD_CHECKS.map((c) => `scorecard.${c}`),
  describe(opts) {
    const ps = paths(opts["scorecard-result"]);
    return `scorecard results ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Results<C>("scorecard");
    const files = paths(ctx.opts["scorecard-result"]);
    if (!files.length) { out.skipAll(SCORECARD_CHECKS, "scorecard", "give --scorecard-result <file>; run `scorecard --repo=<repo> --format=json` or the scorecard action first"); return out.results; }
    const min = Math.min(10, nonNegNum(ctx.opts["scorecard-min-score"], DEFAULTS.minScore));
    const maxAge = posNum(ctx.opts["scorecard-max-age-days"], DEFAULTS.maxAgeDays);
    for (const f of files) {
      const r = readJsonFile(f);
      if ("error" in r) { out.skipAll(SCORECARD_CHECKS, `scorecard ${basename(f)}`, r.error); continue; }
      const d = r.data;
      if (!isObj(d) || !Array.isArray(d.checks) || !isObj(d.repo)) { out.skipAll(SCORECARD_CHECKS, `scorecard ${basename(f)}`, `${basename(f)} is not a Scorecard JSON result (repo, checks[])`); continue; }
      const resource = `repo ${str(d.repo.name) ?? basename(f)}`;
      const stale = staleness(str(d.date), ctx.now, maxAge, "Scorecard result");
      if (stale) { out.skipAll(SCORECARD_CHECKS, resource, stale); continue; }
      const version = isObj(d.scorecard) ? str(d.scorecard.version) ?? "?" : "?";
      const commit = (str(d.repo.commit) ?? "").slice(0, 12);
      const byName = new Map(arr(d.checks).filter(isObj).map((c) => [String(c.name), c]));
      for (const c of SCORECARD_CHECKS) {
        const name = SCORECARD_MAP[c];
        const got = byName.get(name);
        if (!got) { out.skip(c, resource, `Scorecard ${version} did not run ${name} (left out with --checks, or not in this version)`); continue; }
        const score = Number(got.score);
        if (!Number.isFinite(score) || score < 0) { out.skip(c, resource, `Scorecard ${version} ${name}: inconclusive (score ${String(got.score)})`); continue; }
        out.add(c, resource, score >= min ? "pass" : "fail",
          `Scorecard ${version} ${name} ${score}/10 at commit ${commit || "?"} on ${String(d.date).slice(0, 10)}; at least ${min} required`);
      }
    }
    return out.results;
  },
};
