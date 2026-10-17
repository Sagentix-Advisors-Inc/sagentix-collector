// Kubescape (CNCF, Apache-2.0): the JSON report `kubescape scan framework nsa,mitre --format json --output <file>`
// writes in the customer's pipeline, against a cluster or over manifests and Helm charts. The collector reads the
// file; it never runs Kubescape and never calls the network.
//
// Shape (core/pkg/resultshandling/printer/v2/jsonprinter.go at v4.0.15 and opa-utils v0.0.312
// reporthandling/results/v1/reportsummary; checked against a Kubescape 4.0.15 run on 2026-10-15):
//   { generationTime, clusterName, metadata: { scanMetadata: { kubescapeVersion, scanningTarget, targetNames } },
//     summaryDetails: { controls: { "C-0057": { controlID, name, status, statusInfo: { status, subStatus, info },
//                                               ResourceCounters: { passedResources, failedResources, skippedResources } } } },
//     results: [...], resources: [...] }
// Only summaryDetails is read, and results carry counts only: never resource, namespace or label names.

import { basename } from "node:path";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../catalog.ts";
import type { Outcome, Result, Source } from "../types.ts";
import { isObj, str, type Obj } from "./shared-cloud.ts";
import { paths, posNum, readJsonFile, staleness } from "./report_files.ts";

const DEFAULT_MAX_AGE_DAYS = 30;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
/** scanMetadata.scanningTarget: 0 cluster, 1 file, 2 repo, 3 local git, 4 directory. */
const TARGETS = ["cluster", "files", "repository", "repository", "directory"];

function catalogIds(dir: string = DEFAULT_CATALOG_DIR): string[] {
  try {
    return [...loadCatalog(dir).values()].filter((c) => c.source === "kubescape").map((c) => c.id).sort();
  } catch {
    return [];
  }
}

const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);

/** One control summary's outcome and a counts-only detail. */
export function controlOutcome(s: Obj): { result: Outcome; detail: string } {
  const info = isObj(s.statusInfo) ? s.statusInfo : {};
  const status = str(info.status) ?? str(s.status) ?? "";
  const sub = str(info.subStatus) ?? "";
  const rc = isObj(s.ResourceCounters) ? s.ResourceCounters : {};
  const [p, f, k] = [num(rc.passedResources), num(rc.failedResources), num(rc.skippedResources)];
  const tally = `${f} resource(s) failed, ${p} passed, ${k} skipped`;
  if (status === "failed" || f > 0) return { result: "fail", detail: tally };
  if (status === "skipped") return { result: "skipped", detail: `Kubescape skipped the control${sub ? ` (${sub})` : ""}; ${tally}` };
  if (status === "passed") {
    if (sub === "irrelevant" || p === 0) return { result: "skipped", detail: `no resource the control applies to was scanned; ${tally}` };
    if (sub === "incompleteCoverage" || sub === "notEvaluated") return { result: "skipped", detail: `Kubescape could not collect every resource the control needs (${sub}); ${tally}` };
    return { result: "pass", detail: tally + (sub === "w/exceptions" ? "; some resources were excepted by the customer's exceptions file" : "") };
  }
  return { result: "skipped", detail: `status ${JSON.stringify(status)} is not one this reader knows; ${tally}` };
}

export function parseKubescape(doc: unknown, file: string, known: ReadonlySet<string>): { resource: string; generated?: string; results: Result[]; dropped: string[] } {
  if (!isObj(doc) || !isObj(doc.summaryDetails) || !isObj(doc.summaryDetails.controls)) {
    throw new Error(`${basename(file)} is not a Kubescape JSON report (no summaryDetails.controls)`);
  }
  const meta = isObj(doc.metadata) && isObj(doc.metadata.scanMetadata) ? doc.metadata.scanMetadata : {};
  const target = TARGETS[num(meta.scanningTarget)] ?? "scan";
  // A kube context can be "user@cluster"; keep the part after the last "@", and never an e-mail address.
  const cluster = (str(doc.clusterName) ?? "").replace(EMAIL, "[email]").replace(/^.*@/, "").trim();
  const resource = (target === "cluster" && cluster ? `kubescape cluster ${cluster}` : `kubescape ${target} ${basename(file)}`).slice(0, 300);
  const results: Result[] = [];
  const dropped: string[] = [];
  for (const [id, s] of Object.entries(doc.summaryDetails.controls)) {
    const check = `kubescape.${id.toLowerCase()}`;
    if (!isObj(s) || !known.has(check)) { dropped.push(id); continue; }
    const { result, detail } = controlOutcome(s);
    results.push({ check, resource, result, detail: `${id}: ${detail}`.slice(0, 1000) });
  }
  return { resource, generated: str(doc.generationTime), results, dropped: dropped.sort() };
}

export const kubescape: Source = {
  name: "kubescape",
  options: {
    "kubescape-report": { type: "string", multiple: true, help: "Kubescape JSON report (`kubescape scan framework nsa,mitre --format json --output <file>`); repeatable" },
    "kubescape-max-age-days": { type: "string", help: `days a report stays current (default ${DEFAULT_MAX_AGE_DAYS})` },
  },
  emits: catalogIds(),
  describe(opts) {
    const ps = paths(opts["kubescape-report"]);
    return `kubescape reports ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx) {
    const files = paths(ctx.opts["kubescape-report"]);
    if (!files.length) throw new Error("give --kubescape-report <file>; run `kubescape scan framework nsa,mitre --format json --output <file>` in the pipeline first.");
    const known = new Set(catalogIds(typeof ctx.opts.catalog === "string" ? ctx.opts.catalog : DEFAULT_CATALOG_DIR));
    const maxAge = posNum(ctx.opts["kubescape-max-age-days"], DEFAULT_MAX_AGE_DAYS);
    const out: Result[] = [];
    for (const f of files) {
      const r = readJsonFile(f);
      if ("error" in r) throw new Error(`--kubescape-report: ${r.error}`);
      const { resource, generated, results, dropped } = parseKubescape(r.data, f, known);
      ctx.warn(`kubescape ${basename(f)}: ${results.length} controls read; ${dropped.length} not in the catalogue and dropped${dropped.length ? ` (${dropped.slice(0, 20).join(", ")}${dropped.length > 20 ? ", …" : ""})` : ""}`);
      const stale = staleness(generated ?? r.mtime.toISOString(), ctx.now, maxAge, generated ? "report" : "report file (no generationTime; file time used)");
      if (stale) { out.push(...results.map((x) => ({ ...x, result: "skipped" as const, detail: `${resource}: ${stale}`.slice(0, 1000) }))); continue; }
      out.push(...results);
    }
    return out;
  },
};
