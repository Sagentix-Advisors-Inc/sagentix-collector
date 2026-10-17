// Checkov (Prisma Cloud / Palo Alto Networks, Apache-2.0): the JSON report `checkov -d <dir> -o json` or
// `checkov -f plan.json -o json` writes in the customer's pipeline over Terraform, CloudFormation, Kubernetes,
// Helm, Dockerfiles and the like. The collector reads the file; it never runs Checkov and never calls the network.
//
// Shape (checkov/common/output/report.py get_dict and runners/runner_registry.py at tag 3.3.21; checked against a
// Checkov 3.3.21 run on 2026-10-15): one framework gives an object, several give an array of them, nothing
// scanned gives the bare summary.
//   { check_type: terraform|terraform_plan|cloudformation|kubernetes|helm|dockerfile|…,
//     results: { passed_checks: [Record], failed_checks: [Record], skipped_checks: [Record], parsing_errors: [path] },
//     summary: { passed, failed, skipped, parsing_errors, resource_count, checkov_version } }
//   Record: { check_id, check_name, check_result: { result: PASSED|FAILED|SKIPPED }, file_path, resource, … }
// With --quiet, results holds failed_checks only, so a pass cannot be shown and those checks are skipped.
// Results carry counts and resource types ("aws_s3_bucket"), never resource names, file paths or code.

import { basename } from "node:path";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../catalog.ts";
import type { Outcome, Result, Source } from "../types.ts";
import { arr, isObj, str, type Obj } from "./shared-cloud.ts";
import { idList, paths, posNum, readJsonFile, staleness } from "./report_files.ts";

const DEFAULT_MAX_AGE_DAYS = 30;
export const PLAN_CHECK = "checkov.plan_no_failed_checks";

function catalogIds(dir: string = DEFAULT_CATALOG_DIR): string[] {
  try {
    return [...loadCatalog(dir).values()].filter((c) => c.source === "checkov").map((c) => c.id).sort();
  } catch {
    return [];
  }
}

/** "aws_s3_bucket.logs" -> "aws_s3_bucket"; a Kubernetes "Deployment.shop.web" -> "Deployment". The name never leaves. */
export const resourceType = (r: unknown): string => {
  const s = typeof r === "string" ? r : "";
  const t = s.replace(/^module\.[^.]+\./, "").split(".")[0];
  return /^[A-Za-z][\w:-]{0,60}$/.test(t) ? t : "resource";
};

interface Tally { passed: number; failed: number; skipped: number; failedTypes: Map<string, number> }

/** Records grouped by check id, with failed resource types counted. */
export function tally(results: Obj): Map<string, Tally> {
  const out = new Map<string, Tally>();
  const add = (key: "passed" | "failed" | "skipped", recs: unknown) => {
    for (const r of arr(recs).filter(isObj)) {
      const id = str(r.check_id);
      if (!id) continue;
      const t = out.get(id) ?? { passed: 0, failed: 0, skipped: 0, failedTypes: new Map() };
      t[key]++;
      if (key === "failed") { const ty = resourceType(r.resource); t.failedTypes.set(ty, (t.failedTypes.get(ty) ?? 0) + 1); }
      out.set(id, t);
    }
  };
  add("passed", results.passed_checks);
  add("failed", results.failed_checks);
  add("skipped", results.skipped_checks);
  return out;
}

const types = (m: Map<string, number>) => [...m].sort().map(([t, n]) => `${t} ×${n}`);

export function outcomeOf(t: Tally, quiet: boolean): { result: Outcome; detail: string } {
  const counts = `${t.failed} resource(s) failed, ${t.passed} passed, ${t.skipped} suppressed`;
  if (t.failed) return { result: "fail", detail: `${counts}${idList(types(t.failedTypes), "failing types ")}` };
  if (quiet) return { result: "skipped", detail: "the report was written with --quiet (failures only), so a pass cannot be shown" };
  if (t.passed) return { result: "pass", detail: counts };
  return { result: "skipped", detail: `every result was suppressed in the code (skipped_checks); ${counts}` };
}

/** The framework reports in a Checkov JSON file (an object, an array, or a bare summary when nothing was scanned). */
export function frameworkReports(doc: unknown): Obj[] | "empty" | undefined {
  if (Array.isArray(doc)) return doc.filter((x): x is Obj => isObj(x) && typeof x.check_type === "string");
  if (!isObj(doc)) return undefined;
  if (typeof doc.check_type === "string") return [doc];
  if ("checkov_version" in doc && "resource_count" in doc) return "empty";
  return undefined;
}

export function parseCheckov(doc: unknown, file: string, known: ReadonlySet<string>): { results: Result[]; dropped: number; frameworks: string[] } {
  const reports = frameworkReports(doc);
  if (reports === undefined) throw new Error(`${basename(file)} is not a Checkov JSON report (no check_type)`);
  const out: Result[] = [];
  if (reports === "empty") return { results: out, dropped: 0, frameworks: [] };
  let dropped = 0;
  for (const rep of reports) {
    const type = String(rep.check_type);
    const resource = `checkov ${type} ${basename(file)}`.slice(0, 300);
    const res = isObj(rep.results) ? rep.results : {};
    const quiet = !("passed_checks" in res);
    const summary = isObj(rep.summary) ? rep.summary : {};
    const parsingErrors = arr(res.parsing_errors).length || Number(summary.parsing_errors ?? 0) || 0;
    const parseNote = parsingErrors ? `; ${parsingErrors} file(s) Checkov could not parse were not checked` : "";
    const t = tally(res);
    for (const [id, x] of t) {
      const check = `checkov.${id.toLowerCase()}`;
      if (!known.has(check)) { dropped++; continue; }
      const { result, detail } = outcomeOf(x, quiet);
      out.push({ check, resource, result, detail: `${id}: ${detail}${parseNote}`.slice(0, 1000) });
    }
    if (type === "terraform_plan" && known.has(PLAN_CHECK)) {
      const failed = [...t.values()].reduce((n, x) => n + x.failed, 0);
      const passed = [...t.values()].reduce((n, x) => n + x.passed, 0);
      const failingIds = [...t].filter(([, x]) => x.failed).map(([id]) => id).sort();
      let r: { result: Outcome; detail: string };
      if (failed) r = { result: "fail", detail: `${failed} failed result(s) across ${failingIds.length} check(s)${idList(failingIds, "check ids ")}` };
      else if (parsingErrors) r = { result: "skipped", detail: `the plan could not be parsed in full${parseNote}` };
      else if (quiet) r = { result: "skipped", detail: "the report was written with --quiet; it lists failures only, and none, which does not show what ran" };
      else if (!passed) r = { result: "skipped", detail: "no Checkov check evaluated a resource in the plan" };
      else r = { result: "pass", detail: `${passed} passed result(s), none failed, across ${t.size} check(s)` };
      out.push({ check: PLAN_CHECK, resource, result: r.result, detail: r.detail.slice(0, 1000) });
    }
  }
  return { results: out, dropped, frameworks: reports.map((r) => String(r.check_type)) };
}

export const checkov: Source = {
  name: "checkov",
  options: {
    "checkov-report": { type: "string", multiple: true, help: "Checkov JSON report (`checkov -d <dir> -o json`, or `-f plan.json` for a Terraform plan); repeatable" },
    "checkov-max-age-days": { type: "string", help: `days a report file stays current, by its modification time (default ${DEFAULT_MAX_AGE_DAYS})` },
  },
  emits: catalogIds(),
  describe(opts) {
    const ps = paths(opts["checkov-report"]);
    return `checkov reports ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx) {
    const files = paths(ctx.opts["checkov-report"]);
    if (!files.length) throw new Error("give --checkov-report <file>; run `checkov -d <dir> -o json > <file>` in the pipeline first.");
    const known = new Set(catalogIds(typeof ctx.opts.catalog === "string" ? ctx.opts.catalog : DEFAULT_CATALOG_DIR));
    const maxAge = posNum(ctx.opts["checkov-max-age-days"], DEFAULT_MAX_AGE_DAYS);
    const out: Result[] = [];
    for (const f of files) {
      const r = readJsonFile(f);
      if ("error" in r) throw new Error(`--checkov-report: ${r.error}`);
      const { results, dropped, frameworks } = parseCheckov(r.data, f, known);
      ctx.warn(`checkov ${basename(f)}: ${frameworks.length ? frameworks.join(", ") : "nothing scanned"}; ${results.length} results; ${dropped} check(s) not in the catalogue dropped`);
      const stale = staleness(r.mtime.toISOString(), ctx.now, maxAge, "report file (Checkov writes no timestamp; file time used)");
      if (stale) { out.push(...results.map((x) => ({ ...x, result: "skipped" as const, detail: stale }))); continue; }
      out.push(...results);
    }
    return out;
  },
};
