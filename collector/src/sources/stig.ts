// DISA STIGs on customer hosts, through Cinc Auditor (Apache-2.0, the community build of Chef InSpec; never
// Chef's EULA binary) and MITRE SAF's STIG profiles (Apache-2.0 with MITRE's notice). The collector runs
// `cinc-auditor exec <bundled profile> -t ssh://… --reporter json:<file>` as a subprocess, or reads an InSpec
// JSON report the customer produced (--cinc-report). Each profile control becomes one result,
// `stig.<profile>.<v-id>` (apps/sos-app/src/data/checks/stig_<profile>.json, built by
// scripts/build_stig_catalog.py); a control the catalogue does not list is dropped and counted.
//
// Read-only: only the profiles bundled in the runner image run (their controls only read the host), only
// ssh://, winrm:// and local:// targets are accepted, and no option that runs an arbitrary command or changes
// the shell (`--command`, `--sudo-command`, `--shell-command`, a custom profile) is offered. Credentials
// never go in a target URI: an SSH key file (--stig-key-file) or STIG_TARGET_PASSWORD in the environment.
//
// Report shape (InSpec's json reporter, checked against Cinc Auditor 7.2.1 output on 2026-10-15):
//   { platform: { name, release, target_id }, version,
//     profiles: [ { name, version, controls: [ { id: "SV-257777", impact, tags: { gid: "V-257777", severity, nist },
//                   waiver_data, status?, results: [ { status: passed|failed|skipped|error, start_time, code_desc } ] } ] } ] }
// Results carry counts only: never InSpec's code_desc, messages or skip messages, which can name users, paths
// and file contents.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../catalog.ts";
import type { OptionValue, Outcome, Result, Source } from "../types.ts";
import { arr, isObj, scrub, str, type Obj } from "./shared-cloud.ts";
import { paths, posNum, readJsonFile, staleness } from "./report_files.ts";

/** Profile key -> MITRE profile name, at the versions apps/sos-app/scripts/build_stig_catalog.py pins. */
export const STIG_PROFILES: Record<string, { name: string; version: string }> = {
  rhel9: { name: "redhat-enterprise-linux-9-stig-baseline", version: "2.7.2" },
  rhel8: { name: "redhat-enterprise-linux-8-stig-baseline", version: "2.7.1" },
  ubuntu2204: { name: "canonical-ubuntu-22.04-lts-stig-baseline", version: "2.7.2" },
  ubuntu2404: { name: "canonical-ubuntu-24.04-lts-stig-baseline", version: "1.4.2" },
  al2023: { name: "amazon-linux-2023-stig-baseline", version: "1.3.2" },
};
/** The Cinc Auditor release the runner image bundles. */
export const CINC_VERSION = "7.2.1";
/** Where the runner image keeps one archived (dependencies vendored) profile per key: <dir>/<key>.tar.gz. */
export const DEFAULT_PROFILE_DIR = "/opt/sagentix/stig";
export const TARGET_SCHEMES = ["ssh", "winrm", "local"] as const;
const DEFAULT_MAX_AGE_DAYS = 30;
/** cinc-auditor exit codes that mean "the scan ran": 0 all passed, 100 a test skipped, 101 a test failed. */
const SCAN_RAN = new Set([0, 100, 101]);
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

const one = (v: OptionValue): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

function catalogIds(dir: string = DEFAULT_CATALOG_DIR): string[] {
  try {
    return [...loadCatalog(dir).values()].filter((c) => c.source === "stig").map((c) => c.id).sort();
  } catch {
    return [];
  }
}

/** The profile key for an InSpec profile name, or undefined. */
export const keyForProfile = (name: string): string | undefined =>
  Object.entries(STIG_PROFILES).find(([, p]) => p.name === name)?.[0];

/** A target URI checked for scheme and stripped to a label (no user, no password). Throws on anything else. */
export function parseTarget(t: string): { uri: string; label: string } {
  const m = /^([a-z]+):\/\/(.*)$/.exec(t.trim());
  if (!m || !(TARGET_SCHEMES as readonly string[]).includes(m[1])) {
    throw new Error(`--stig-target ${JSON.stringify(t.slice(0, 80))}: use ssh://user@host[:port], winrm://user@host[:port] or local://`);
  }
  if (m[1] === "local") return { uri: "local://", label: "local" };
  const at = m[2].lastIndexOf("@");
  const userinfo = at >= 0 ? m[2].slice(0, at) : "";
  if (userinfo.includes(":")) throw new Error("--stig-target must not carry a password; put it in STIG_TARGET_PASSWORD or use --stig-key-file");
  const host = (at >= 0 ? m[2].slice(at + 1) : m[2]).replace(/\/.*$/, "");
  if (!host || /[\s'"`;|&$<>]/.test(host)) throw new Error(`--stig-target: ${JSON.stringify(host)} is not a host name or address`);
  return { uri: t.trim(), label: host.replace(/:\d+$/, "") };
}

// ── Report → results ─────────────────────────────────────────────────────────────────────────────────

export interface StigSummary { controls: number; kept: number; dropped: number; droppedProfiles: string[]; versionNotes: string[] }

/** One control's outcome and a counts-only detail. */
export function controlOutcome(c: Obj): { result: Outcome; detail: string } {
  const tags = isObj(c.tags) ? c.tags : {};
  const sev = str(tags.severity) ?? "unknown";
  const counts = { passed: 0, failed: 0, skipped: 0, error: 0 };
  for (const r of arr(c.results).filter(isObj)) {
    const s = String(r.status ?? "");
    if (s in counts) counts[s as keyof typeof counts]++;
  }
  const n = counts.passed + counts.failed + counts.skipped + counts.error;
  const tally = `${n} test(s): ${counts.passed} passed, ${counts.failed} failed, ${counts.skipped} skipped, ${counts.error} errored; severity ${sev}`;
  const waiver = isObj(c.waiver_data) ? c.waiver_data : {};
  if (waiver.run === false || waiver.skipped_due_to_waiver === true) return { result: "skipped", detail: `waived in the customer's waiver file; ${tally}` };
  const status = str(c.status);
  if (status === "not_applicable" || status === "not_reviewed") return { result: "skipped", detail: `InSpec marked it ${status.replace("_", " ")}; ${tally}` };
  if (counts.failed) return { result: "fail", detail: tally };
  if (counts.error) return { result: "skipped", detail: `a test could not run on the host, so the control is not shown either way; ${tally}` };
  if (counts.passed) return { result: "pass", detail: tally };
  return { result: "skipped", detail: `InSpec skipped every test (not applicable on this host, or a condition was not met); ${tally}` };
}

/** Newest start_time in the report, or undefined. */
export function reportTime(doc: Obj): string | undefined {
  let best: number | undefined;
  for (const p of arr(doc.profiles).filter(isObj)) for (const c of arr(p.controls).filter(isObj)) for (const r of arr(c.results).filter(isObj)) {
    const t = Date.parse(String(r.start_time ?? ""));
    if (Number.isFinite(t) && (best === undefined || t > best)) best = t;
  }
  return best === undefined ? undefined : new Date(best).toISOString();
}

/**
 * Maps one InSpec JSON report to results for `resource`. Profiles that are not a pinned STIG profile (and no
 * --stig-profile override) are dropped; so are controls the catalogue does not list.
 */
export function parseInspec(doc: unknown, resource: string, known: ReadonlySet<string>, forceKey?: string): { results: Result[]; summary: StigSummary } {
  if (!isObj(doc) || !Array.isArray(doc.profiles)) throw new Error("not an InSpec JSON report (no profiles[])");
  const summary: StigSummary = { controls: 0, kept: 0, dropped: 0, droppedProfiles: [], versionNotes: [] };
  const results: Result[] = [];
  const seen = new Set<string>();
  for (const p of doc.profiles.filter(isObj)) {
    const controls = arr(p.controls).filter(isObj);
    if (!controls.length) continue;   // a dependency such as inspec-profile-resources has none
    const name = str(p.name) ?? "?";
    const key = forceKey ?? keyForProfile(name);
    if (!key) { summary.droppedProfiles.push(name); summary.dropped += controls.length; summary.controls += controls.length; continue; }
    const pinned = STIG_PROFILES[key]?.version;
    if (pinned && str(p.version) && str(p.version) !== pinned) summary.versionNotes.push(`${name} ${str(p.version)} (catalogue built from ${pinned})`);
    for (const c of controls) {
      summary.controls++;
      const tags = isObj(c.tags) ? c.tags : {};
      const gid = /^V-\d+$/.test(String(tags.gid ?? "")) ? String(tags.gid) : String(c.id ?? "").replace(/^SV-(\d+).*$/, "V-$1");
      const check = `stig.${key}.${gid.toLowerCase()}`;
      if (!/^V-\d+$/.test(gid) || !known.has(check) || seen.has(check)) { summary.dropped++; continue; }
      seen.add(check);
      const { result, detail } = controlOutcome(c);
      results.push({ check, resource: resource.slice(0, 300), result, detail: detail.slice(0, 1000) });
    }
  }
  summary.kept = results.length;
  return { results, summary };
}

/** "stig rhel9 host 10.0.1.5": the profile key and a label with no user name or e-mail address in it. */
export const resourceFor = (key: string | undefined, label: string) =>
  `stig ${key ?? "profile"} host ${label}`.replace(EMAIL, "[email]").slice(0, 300);

// ── Subprocess ───────────────────────────────────────────────────────────────────────────────────────

export interface CincRun { code: number | null; stderr: string }
export type CincSpawner = (bin: string, args: string[], env: NodeJS.ProcessEnv) => Promise<CincRun>;

export const spawnCinc: CincSpawner = (bin, args, env) => new Promise((resolve, reject) => {
  const p = spawn(bin, args, { env, stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  p.stderr.on("data", (d: Buffer) => { err = (err + d.toString()).slice(-4000); });
  p.on("error", reject);
  p.on("close", (code) => resolve({ code, stderr: err }));
});

export interface CincOptions { bin: string; archive: string; target: string; keyFile?: string; sudo: boolean; inputFiles: string[]; env: NodeJS.ProcessEnv; spawner: CincSpawner }

/** The cinc-auditor arguments for one scan: fixed reporter, no colour, never a command or shell override. */
export function cincArgs(o: Omit<CincOptions, "bin" | "env" | "spawner">, reportPath: string, password?: string): string[] {
  const args = ["exec", o.archive, "-t", o.target, "--reporter", `json:${reportPath}`, "--no-color"];
  if (o.keyFile) args.push("-i", o.keyFile);
  if (o.sudo) args.push("--sudo");
  if (password) args.push("--password", password);
  for (const f of o.inputFiles) args.push("--input-file", f);
  return args;
}

/** Runs one scan into a fresh directory and returns the parsed report. A failed run is an error, never an empty scan. */
export async function runCinc(o: CincOptions): Promise<unknown> {
  try { statSync(o.archive); } catch {
    throw new Error(`the STIG profile ${o.archive} is not there; run inside the collector runner image or pass --stig-profiles-dir`);
  }
  const dir = mkdtempSync(join(tmpdir(), "sagentix-stig-"));
  const report = join(dir, "report.json");
  const password = o.env.STIG_TARGET_PASSWORD || undefined;
  try {
    let run: CincRun;
    try { run = await o.spawner(o.bin, cincArgs(o, report, password), o.env); } catch (e) {
      throw new Error(`cannot run ${o.bin} (${(e as NodeJS.ErrnoException).code ?? String(e)}); install Cinc Auditor ${CINC_VERSION} or pass --cinc-bin.`);
    }
    const tail = (password ? run.stderr.split(password).join("[redacted]") : run.stderr).trim().split("\n").slice(-5).join(" / ");
    if (run.code === null || !SCAN_RAN.has(run.code)) throw new Error(`${o.bin} exited ${run.code} on ${parseTarget(o.target).label}: ${tail}`);
    let text: string;
    try { text = readFileSync(report, "utf8"); } catch { throw new Error(`${o.bin} wrote no report for ${parseTarget(o.target).label}: ${tail}`); }
    return JSON.parse(text);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── Source ───────────────────────────────────────────────────────────────────────────────────────────

export const stig: Source = {
  name: "stig",
  options: {
    "stig-profile": { type: "string", help: `STIG profile to run: ${Object.keys(STIG_PROFILES).join(", ")} (with --cinc-report, forces the mapping)` },
    "stig-target": { type: "string", multiple: true, help: "host to scan: ssh://user@host[:port], winrm://user@host[:port] or local://; repeatable" },
    "stig-key-file": { type: "string", help: "SSH private key for the targets (a WinRM password goes in STIG_TARGET_PASSWORD)" },
    "stig-sudo": { type: "boolean", help: "read root-only files through sudo on the target (the account needs sudo for reads)" },
    "stig-input-file": { type: "string", multiple: true, help: "InSpec input file the profile reads (e.g. the site's banner or allowed services); repeatable" },
    "stig-profiles-dir": { type: "string", help: `where the archived profiles are (default ${DEFAULT_PROFILE_DIR})` },
    "cinc-bin": { type: "string", help: "the cinc-auditor executable (default cinc-auditor on PATH)" },
    "cinc-report": { type: "string", multiple: true, help: "read this InSpec JSON report instead of scanning; repeatable" },
    "stig-max-age-days": { type: "string", help: `days a report stays current (default ${DEFAULT_MAX_AGE_DAYS})` },
  },
  emits: catalogIds(),
  describe(opts) {
    const reports = paths(opts["cinc-report"]);
    if (reports.length) return `STIG results from InSpec reports ${reports.map((p) => basename(p)).join(", ")}`;
    const ts = paths(opts["stig-target"]).map((t) => { try { return parseTarget(t).label; } catch { return "?"; } });
    return `Cinc Auditor ${CINC_VERSION} STIG ${one(opts["stig-profile"]) ?? "(no profile)"} scan of ${ts.join(", ") || "(no target)"}`;
  },
  async run(ctx) {
    const known = new Set(catalogIds(one(ctx.opts.catalog) ?? DEFAULT_CATALOG_DIR));
    const forced = one(ctx.opts["stig-profile"]);
    if (forced && !STIG_PROFILES[forced]) throw new Error(`--stig-profile must be one of ${Object.keys(STIG_PROFILES).join(", ")}.`);
    const reports = paths(ctx.opts["cinc-report"]);
    const targets = paths(ctx.opts["stig-target"]);
    if (!reports.length && !targets.length) throw new Error("give --stig-target ssh://user@host (with --stig-profile) or --cinc-report <InSpec JSON file>.");
    const maxAge = posNum(ctx.opts["stig-max-age-days"], DEFAULT_MAX_AGE_DAYS);
    const out: Result[] = [];
    const note = (label: string, s: StigSummary) => {
      ctx.warn(`stig ${label}: ${s.controls} controls; ${s.kept} results; ${s.dropped} dropped (not in the catalogue)` +
        (s.droppedProfiles.length ? `; profiles that are not a pinned STIG profile: ${s.droppedProfiles.join(", ")} (pass --stig-profile to map one)` : "") +
        (s.versionNotes.length ? `; version differs: ${s.versionNotes.join(", ")}` : ""));
    };
    for (const f of reports) {
      const r = readJsonFile(f);
      if ("error" in r) throw new Error(`--cinc-report: ${r.error}`);
      const doc = r.data;
      if (!isObj(doc)) throw new Error(`--cinc-report ${basename(f)} is not an InSpec JSON report`);
      const platform = isObj(doc.platform) ? doc.platform : {};
      const when = reportTime(doc);
      const label = `${str(platform.name) ?? "unknown"} ${str(platform.release) ?? ""} target ${(str(platform.target_id) ?? basename(f)).slice(0, 16)}`.replace(/\s+/g, " ");
      const firstKey = forced ?? arr(doc.profiles).filter(isObj).map((p) => keyForProfile(str(p.name) ?? "")).find(Boolean);
      const resource = resourceFor(firstKey, label);
      const stale = staleness(when ?? r.mtime.toISOString(), ctx.now, maxAge, when ? "report" : "report file (no test start time; file time used)");
      const { results, summary } = parseInspec(doc, resource, known, forced);
      note(basename(f), summary);
      if (stale) { for (const x of results) out.push({ ...x, result: "skipped", detail: stale }); continue; }
      out.push(...results);
    }
    if (targets.length) {
      if (!forced) throw new Error(`--stig-target needs --stig-profile (${Object.keys(STIG_PROFILES).join(", ")}).`);
      const dir = one(ctx.opts["stig-profiles-dir"]) ?? DEFAULT_PROFILE_DIR;
      const spawner = (ctx.clients.cinc as CincSpawner | undefined) ?? spawnCinc;
      for (const t of targets) {
        const { label } = parseTarget(t);
        const doc = await runCinc({
          bin: one(ctx.opts["cinc-bin"]) ?? "cinc-auditor", archive: join(dir, `${forced}.tar.gz`), target: t,
          keyFile: one(ctx.opts["stig-key-file"]), sudo: ctx.opts["stig-sudo"] === true, inputFiles: paths(ctx.opts["stig-input-file"]),
          env: ctx.env, spawner,
        });
        const { results, summary } = parseInspec(doc, resourceFor(forced, label), known, forced);
        note(label, summary);
        out.push(...results);
      }
    }
    return scrub(out, [ctx.env.STIG_TARGET_PASSWORD]);
  },
};
