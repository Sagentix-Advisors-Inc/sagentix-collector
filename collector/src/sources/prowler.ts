// Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler) as an evidence engine. The collector runs
// `prowler <provider> --output-formats json-ocsf` as a subprocess with the read-only credentials already in
// the CI environment, or reads an OCSF file the customer produced (--prowler-output). Each OCSF Detection
// Finding becomes one result, `prowler.<provider>.<CheckID>`; a check sos-app's catalogue
// (apps/sos-app/src/data/checks/prowler_<provider>.json) does not list is dropped and counted.
//
// Fields read, checked against Prowler 5.45.0, the pinned release (tag 5.45.0, commit bffc884; read 2026-10-20):
// https://github.com/prowler-cloud/prowler/blob/5.45.0/prowler/lib/outputs/ocsf/ocsf.py writes metadata.event_code
// (the CheckID), finding_info.analytic.uid, status_code (PASS, FAIL, MANUAL), status "Suppressed" when muted,
// status_detail, message, resources[].uid/name/region (namespace for Kubernetes), cloud.account.uid, cloud.region
// and unmapped.provider; prowler/lib/cli/parser.py still has --output-filename, --output-directory, --no-banner and
// --ignore-exit-code-3, and the file ends .ocsf.json. https://docs.prowler.com/user-guide/cli/tutorials/reporting
// (read 2026-10-20) lists json-ocsf among the output formats.
//
// The collector never passes a Prowler option that writes, fixes or sends anywhere (Security Hub, S3,
// Slack, Shodan, Prowler Cloud, secret validation), and refuses one given in --prowler-args.

import { spawn } from "node:child_process";
import { accessSync, constants, createReadStream, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../catalog.ts";
import type { Outcome, OptionValue, Result, Source } from "../types.ts";
import { scrub } from "./shared-cloud.ts";
import { pool } from "../pool.ts";

export const PROWLER_PROVIDERS = ["aws", "azure", "gcp", "kubernetes", "m365", "github", "googleworkspace", "okta", "cloudflare"] as const;
export type ProwlerProvider = (typeof PROWLER_PROVIDERS)[number];

/** The version the catalogues were built from (apps/sos-app/scripts/build_prowler_catalog.py). */
export const PROWLER_VERSION = "5.47.0";

/** Options that make Prowler write, fix or send, or that change the output the collector reads. */
export const REFUSED_ARGS = [
  "--push-to-cloud", "--security-hub", "--send-sh-only-fails", "--fixer", "--fixer-config", "--output-bucket",
  "--output-bucket-no-assume", "--slack", "--shodan", "--scan-secrets-validate",
  "--output-formats", "--output-modes", "-M", "--output-directory", "-o", "--output-filename", "-F", "--status",
];

/** Environment variables whose values never leave the machine, even if Prowler echoes them in a detail. */
const SECRET_ENVS = [
  "GITHUB_TOKEN", "CLOUDFLARE_API_TOKEN_READONLY", "ENTRA_CLIENT_SECRET", "M365_CERTIFICATE_CONTENT",
  "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_OAUTH_APP_TOKEN",
  "GITHUB_APP_KEY", "OKTA_PRIVATE_KEY", "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "GOOGLEWORKSPACE_CREDENTIALS_CONTENT",
];

/** Every Prowler check id sos-app's catalogue lists (read once, from the default catalogue). */
function catalogIds(dir: string = DEFAULT_CATALOG_DIR): string[] {
  try {
    return [...loadCatalog(dir).values()].filter((c) => c.source === "prowler").map((c) => c.id).sort();
  } catch {
    return [];
  }
}

const one = (v: OptionValue): string | undefined => {
  const x = Array.isArray(v) ? v[0] : v;
  return typeof x === "string" && x.trim() ? x.trim() : undefined;
};
/** --prowler-provider aws,azure or repeated, in order, without repeats. */
const providersOf = (v: OptionValue): string[] =>
  [...new Set((Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((x) => String(x).split(",")).map((x) => x.trim()).filter(Boolean))];

/** Splits --prowler-args like a shell would for plain words and '…' or "…" quoting (no expansion). */
export function splitArgs(s: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/** The provider's authentication flag, chosen from what the environment holds. Everything else Prowler reads from env itself. */
export function authArgs(provider: ProwlerProvider, env: NodeJS.ProcessEnv): string[] {
  // The generated workflow names what the collector's own source reads, so Prowler reads the same scope
  // (Prowler 5.47.0: aws --region, azure --subscription-ids, gcp --project-ids).
  const scope = (name: string, flag: string) => { const v = (env[name] ?? "").split(/\s+/).filter(Boolean); return v.length ? [flag, ...v] : []; };
  switch (provider) {
    case "aws": return scope("SAGENTIX_PROWLER_AWS_REGIONS", "--region");
    case "gcp": return scope("SAGENTIX_PROWLER_GCP_PROJECTS", "--project-ids");
    case "m365":
      // A certificate signs in every Microsoft 365 service, Exchange and Teams included; a secret covers Graph only.
      // --init-modules installs the PowerShell modules those services need (an ephemeral runner has none).
      if (env.M365_CERTIFICATE_CONTENT) return ["--certificate-auth", "--init-modules"];
      return [...(env.AZURE_CLIENT_SECRET ? ["--sp-env-auth"] : ["--az-cli-auth"]), "--init-modules"];
    case "azure":
      // A client secret in env: service principal; otherwise the session `azure/login` (OIDC) left for the az CLI.
      return [...(env.AZURE_CLIENT_SECRET ? ["--sp-env-auth"] : ["--az-cli-auth"]),
        ...(provider === "azure" ? scope("SAGENTIX_PROWLER_AZURE_SUBSCRIPTIONS", "--subscription-ids") : [])];
    case "kubernetes":
      return env.KUBECONFIG ? ["--kubeconfig-file", env.KUBECONFIG] : [];
    default:
      // aws: boto3's chain (AWS_* keys, or AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE); gcp: application default
      // credentials (GOOGLE_APPLICATION_CREDENTIALS); github, okta, cloudflare, googleworkspace: their own env names.
      return [];
  }
}

/**
 * Prowler reads its own variable names; the collector's native sources read theirs. So the same read-only credential
 * the client already stored serves both ways (2026-11-01: each control collected at least two ways): the collector's
 * name is copied to Prowler's when Prowler's is unset. Names from prowler/providers/<provider> in Prowler 5.47.0.
 */
export function prowlerEnv(provider: ProwlerProvider, env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const alias: Record<string, Record<string, string>> = {
    github: { GITHUB_PERSONAL_ACCESS_TOKEN: "GITHUB_TOKEN" },
    cloudflare: { CLOUDFLARE_API_TOKEN: "CLOUDFLARE_API_TOKEN_READONLY" },
    googleworkspace: { GOOGLEWORKSPACE_CREDENTIALS_FILE: "GOOGLE_SA_KEY_FILE", GOOGLEWORKSPACE_DELEGATED_USER: "GOOGLE_ADMIN_EMAIL" },
    m365: { AZURE_TENANT_ID: "ENTRA_TENANT_ID", AZURE_CLIENT_ID: "ENTRA_CLIENT_ID", AZURE_CLIENT_SECRET: "ENTRA_CLIENT_SECRET" },
    okta: { OKTA_ORG_DOMAIN: "OKTA_DOMAIN" },
  };
  const out = { ...env };
  for (const [theirs, ours] of Object.entries(alias[provider] ?? {})) if (!out[theirs] && env[ours]) out[theirs] = env[ours];
  return out;
}

// ── OCSF → results ──────────────────────────────────────────────────────────────────────────────────

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const s = (v: unknown): string => (typeof v === "string" ? v : "");

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

/** PASS → pass, FAIL → fail; MANUAL, a muted finding (OCSF status "Suppressed"), or anything else → skipped. */
export function outcomeOf(f: Obj): Outcome {
  if (s(f.status) === "Suppressed") return "skipped";
  const code = s(f.status_code).toUpperCase();
  return code === "PASS" ? "pass" : code === "FAIL" ? "fail" : "skipped";
}

export interface ParseSummary { findings: number; kept: number; dropped: number; droppedChecks: string[]; muted: number; manual: number; merged: number }

/**
 * Maps Prowler OCSF findings (Detection Findings), one at a time, to results. Findings whose check the catalogue does
 * not list are dropped and counted. Several findings on one (check, resource) merge into one result: fail if any
 * failed, else pass if any passed, else skipped; their details are joined (only as far as the 1,000 characters sent).
 */
class OcsfMerger {
  readonly summary: ParseSummary = { findings: 0, kept: 0, dropped: 0, droppedChecks: [], muted: 0, manual: 0, merged: 0 };
  private readonly dropped = new Set<string>();
  private readonly byKey = new Map<string, { r: Result; details: string[]; len: number }>();
  private readonly provider: string;
  private readonly known: ReadonlySet<string>;
  constructor(provider: string, known: ReadonlySet<string>) { this.provider = provider; this.known = known; }

  add(f: unknown): void {
    this.summary.findings++;
    if (!isObj(f)) return;
    const summary = this.summary;
    const meta = isObj(f.metadata) ? f.metadata : {};
    const info = isObj(f.finding_info) ? f.finding_info : {};
    const analytic = isObj(info.analytic) ? info.analytic : {};
    const checkId = s(meta.event_code) || s(analytic.uid);
    const unmapped = isObj(f.unmapped) ? f.unmapped : {};
    const prov = s(unmapped.provider) || this.provider;
    const check = `prowler.${prov}.${checkId}`;
    if (!checkId || !this.known.has(check)) { summary.dropped++; this.dropped.add(check); return; }
    if (s(f.status) === "Suppressed") summary.muted++;
    if (s(f.status_code).toUpperCase() === "MANUAL") summary.manual++;
    const res = Array.isArray(f.resources) && isObj(f.resources[0]) ? f.resources[0] : {};
    const cloud = isObj(f.cloud) ? f.cloud : {};
    const account = isObj(cloud.account) ? s(cloud.account.uid) : "";
    const region = s(res.region) || s(cloud.region) || (s(res.namespace) ? `namespace ${s(res.namespace)}` : "");
    let resource = s(res.uid) || s(res.name) || s(info.name) || account || "-";
    // An ARN names its resource uniquely already; anything else carries the account (subscription, project) it came from.
    if (account && !resource.startsWith("arn:") && !resource.includes(account)) resource = `${account} ${resource}`;
    if (region && !resource.includes(region.replace(/^namespace /, ""))) resource = `${resource} [${region}]`;
    resource = resource.replace(EMAIL, "[email]").slice(0, 300);
    const detail = (s(f.status_detail) || s(f.message)).replace(EMAIL, "[email]");
    const result = outcomeOf(f);
    const key = `${check}|${resource}`;
    const prev = this.byKey.get(key);
    if (!prev) { this.byKey.set(key, { r: { check, resource, result, detail: "" }, details: detail ? [detail] : [], len: detail.length }); return; }
    summary.merged++;
    const rank = (o: Outcome) => (o === "fail" ? 2 : o === "pass" ? 1 : 0);
    if (rank(result) > rank(prev.r.result)) prev.r.result = result;
    // Past 1,000 characters a further detail cannot change what is sent, so it is not kept (a large account merges
    // thousands of findings into one result).
    if (detail && prev.len < 1000 && !prev.details.includes(detail)) { prev.len += (prev.details.length ? 3 : 0) + detail.length; prev.details.push(detail); }
  }

  finish(): { results: Result[]; summary: ParseSummary } {
    const results = [...this.byKey.values()].map(({ r, details }) => ({ ...r, detail: details.join(" | ").slice(0, 1000) }));
    this.summary.kept = results.length;
    this.summary.droppedChecks = [...this.dropped].sort();
    return { results, summary: this.summary };
  }
}

/** The output is not OCSF: the file is wrong, whichever way it was made. */
export class OcsfError extends Error {}
export type Parsed = { results: Result[]; summary: ParseSummary };

const NOT_JSON = (why: string) => new OcsfError(`the Prowler output is not JSON (${why}); pass a json-ocsf file.`);
const NOT_ARRAY = () => new OcsfError("the Prowler output is not an OCSF array of findings; pass a json-ocsf file.");

/** Maps a Prowler OCSF array held in memory (tests, small files). */
export function parseOcsf(text: string, provider: string, known: ReadonlySet<string>): { results: Result[]; summary: ParseSummary } {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch (e) { throw NOT_JSON((e as Error).message); }
  if (!Array.isArray(doc)) throw NOT_ARRAY();
  const m = new OcsfMerger(provider, known);
  for (const f of doc) m.add(f);
  return m.finish();
}

const WS = (c: number) => c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09;

/**
 * The elements of a top-level JSON array, as text, read chunk by chunk: only one element is held at a time, so a
 * Prowler output of any size never becomes one string (V8 caps a string near 512 MiB; a large AWS organization's
 * OCSF file passes that). Strings and escapes are tracked so brackets inside them do not count. No regular expression.
 */
export async function* jsonArrayElements(chunks: AsyncIterable<string>): AsyncGenerator<string> {
  let buf = "", i = 0, start = -1, depth = 0, inStr = false, esc = false, state: "pre" | "in" | "post" = "pre", afterComma = false;
  for await (const chunk of chunks) {
    buf += chunk;
    for (; i < buf.length; i++) {
      const c = buf.charCodeAt(i);
      if (state === "pre") {
        if (WS(c) || c === 0xfeff) continue;
        if (c === 0x5b /* [ */) { state = "in"; continue; }
        throw NOT_ARRAY();
      }
      if (state === "post") { if (WS(c)) continue; throw NOT_JSON(`text after the closing bracket at offset ${i}`); }
      if (inStr) {
        if (esc) esc = false;
        else if (c === 0x5c /* \ */) esc = true;
        else if (c === 0x22 /* " */) inStr = false;
        continue;
      }
      if (c === 0x22) { inStr = true; if (start < 0) start = i; continue; }
      if (depth === 0) {
        if (c === 0x2c /* , */ || c === 0x5d /* ] */) {
          if (start >= 0) { yield buf.slice(start, i); start = -1; afterComma = c === 0x2c; }
          else if (c === 0x2c || afterComma) throw NOT_JSON("an empty array element");
          if (c === 0x5d) state = "post";
          continue;
        }
        if (WS(c)) continue;
        if (start < 0) start = i;
      }
      if (c === 0x7b /* { */ || c === 0x5b) depth++;
      else if (c === 0x7d /* } */ || c === 0x5d) { if (--depth < 0) throw NOT_JSON("unbalanced brackets"); }
    }
    // Drop what has been read; keep the element in progress.
    const keep = start >= 0 ? start : i;
    buf = buf.slice(keep);
    i -= keep;
    if (start >= 0) start = 0;
  }
  if (state === "pre") throw NOT_ARRAY();
  if (state !== "post") throw NOT_JSON("the file ends inside the array");
}

/** Maps a Prowler OCSF file, streamed (see jsonArrayElements). */
export async function parseOcsfFile(path: string, provider: string, known: ReadonlySet<string>): Promise<{ results: Result[]; summary: ParseSummary }> {
  const m = new OcsfMerger(provider, known);
  for await (const el of jsonArrayElements(createReadStream(path, { encoding: "utf8", highWaterMark: 1 << 20 }))) {
    let f: unknown;
    try { f = JSON.parse(el); } catch (e) { throw NOT_JSON((e as Error).message); }
    m.add(f);
  }
  return m.finish();
}

// ── Subprocess ──────────────────────────────────────────────────────────────────────────────────────

export interface ProwlerRun { code: number | null; stderr: string }
export type ProwlerSpawner = (bin: string, args: string[], env: NodeJS.ProcessEnv) => Promise<ProwlerRun>;

export const spawnProwler: ProwlerSpawner = (bin, args, env) => new Promise((resolve, reject) => {
  const p = spawn(bin, args, { env, stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  p.stderr.on("data", (d: Buffer) => { err = (err + d.toString()).slice(-4000); });
  p.on("error", reject);
  p.on("close", (code) => resolve({ code, stderr: err }));
});

/** Runs Prowler into a fresh directory and maps its OCSF file, streamed, before the directory goes. A non-zero exit is an error. */
export async function runProwler(provider: ProwlerProvider, o: { bin: string; extra: string[]; env: NodeJS.ProcessEnv; spawner: ProwlerSpawner; known: ReadonlySet<string> }): Promise<Parsed> {
  const bad = o.extra.filter((a) => REFUSED_ARGS.includes(a.split("=")[0]));
  if (bad.length) throw new Error(`--prowler-args may not carry ${bad.join(", ")}: the collector reads Prowler's output read-only and sends nothing elsewhere.`);
  const dir = mkdtempSync(join(tmpdir(), "sagentix-prowler-"));
  try {
    const args = [provider, "--output-formats", "json-ocsf", "--output-directory", dir, "--output-filename", "sagentix",
      "--no-banner", "--ignore-exit-code-3", ...authArgs(provider, o.env), ...o.extra];
    let run: ProwlerRun;
    try { run = await o.spawner(o.bin, args, o.env); } catch (e) {
      throw new Error(`cannot run ${o.bin} (${(e as NodeJS.ErrnoException).code ?? String(e)}); install prowler==${PROWLER_VERSION} or pass --prowler-bin.`);
    }
    if (run.code !== 0) throw new Error(`${o.bin} ${provider} exited ${run.code}: ${run.stderr.trim().split("\n").slice(-5).join(" / ")}`);
    const file = readdirSync(dir).find((f) => f.endsWith(".ocsf.json"));
    if (!file) throw new Error(`${o.bin} ${provider} wrote no .ocsf.json in ${dir}.`);
    return await parseOcsfFile(join(dir, file), provider, o.known);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Prowler scans run side by side, at most this many at once (each is a Python process of its own). */
export const PROWLER_PARALLEL = 2;

// ── Source ──────────────────────────────────────────────────────────────────────────────────────────

export const prowler: Source = {
  name: "prowler",
  options: {
    "prowler-provider": { type: "string", multiple: true, help: `Prowler providers to run, comma-separated: ${PROWLER_PROVIDERS.join(", ")} (one failing never stops the others)` },
    "prowler-bin": { type: "string", help: "the prowler executable (default prowler on PATH)" },
    "prowler-args": { type: "string", help: "extra Prowler options, written --prowler-args=\"--region us-east-1 ca-central-1\" (never output, send or fix options)" },
    "prowler-output": { type: "string", help: "read this json-ocsf file instead of running Prowler" },
  },
  emits: catalogIds(),
  describe(opts) {
    const p = providersOf(opts["prowler-provider"]).join(", ") || "(no provider)";
    return one(opts["prowler-output"]) ? `Prowler ${p} findings from a json-ocsf file` : `Prowler ${PROWLER_VERSION} ${p} scan`;
  },
  async run(ctx) {
    const providers = providersOf(ctx.opts["prowler-provider"]);
    const bad = providers.filter((p) => !(PROWLER_PROVIDERS as readonly string[]).includes(p));
    if (!providers.length || bad.length) {
      throw new Error(`--prowler-provider is required: one or more of ${PROWLER_PROVIDERS.join(", ")}${bad.length ? ` (not: ${bad.join(", ")})` : ""}.`);
    }
    const file = one(ctx.opts["prowler-output"]);
    if (file && providers.length > 1) throw new Error("--prowler-output reads one provider's file; name one --prowler-provider with it.");
    const known = new Set(catalogIds(one(ctx.opts.catalog) ?? DEFAULT_CATALOG_DIR));
    for (const provider of providers) {
      if (![...known].some((id) => id.startsWith(`prowler.${provider}.`))) {
        ctx.warn(`prowler: sos-app's catalogue lists no ${provider} check; every finding will be dropped.`);
      }
    }
    // Each provider read or scanned, PROWLER_PARALLEL at a time; the outcomes are then taken in the order given, so the
    // results and their order are those of one provider after another.
    const one_ = async (provider: ProwlerProvider): Promise<Parsed> => {
      if (file) {
        try { accessSync(file, constants.R_OK); } catch (e) { throw new Error(`cannot read --prowler-output ${file}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); }
        return parseOcsfFile(file, provider, known);
      }
      const spawner = (ctx.clients.prowler as ProwlerSpawner | undefined) ?? spawnProwler;
      const extra = one(ctx.opts["prowler-args"]) ? splitArgs(one(ctx.opts["prowler-args"])!) : [];
      return runProwler(provider, { bin: one(ctx.opts["prowler-bin"]) ?? "prowler", extra, env: prowlerEnv(provider, ctx.env), spawner, known });
    };
    const outcomes = await pool(providers as ProwlerProvider[], PROWLER_PARALLEL, one_);
    const results: Result[] = [];
    const failures: Error[] = [];
    for (const [i, o] of outcomes.entries()) {
      const provider = providers[i];
      if (o.status === "rejected") {
        // An output that is not OCSF is the file's fault, not the scan's: it stops the source, as it always has.
        if (o.reason instanceof OcsfError) throw o.reason;
        // A second way that fails leaves the control to its other ways: say so and go on with the next provider.
        failures.push(o.reason as Error);
        if (providers.length > 1) ctx.warn(`prowler: ${provider} did not run (${(o.reason as Error).message}); its controls keep their other ways.`);
        continue;
      }
      const { results: r, summary } = o.value;
      results.push(...r);
      ctx.warn(`prowler: ${summary.findings} findings; ${summary.kept} results (${summary.merged} merged into the same check and resource, ` +
        `${summary.muted} muted and ${summary.manual} manual sent as skipped); ${summary.dropped} findings dropped from ${summary.droppedChecks.length} checks not in the catalogue` +
        (summary.droppedChecks.length ? `: ${summary.droppedChecks.slice(0, 20).join(", ")}${summary.droppedChecks.length > 20 ? ", …" : ""}` : ""));
    }
    if (failures.length === providers.length) throw failures[0];
    return scrub(results, SECRET_ENVS.map((n) => ctx.env[n]));
  },
};
