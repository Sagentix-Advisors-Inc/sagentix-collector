// Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler) as an evidence engine. The collector runs
// `prowler <provider> --output-formats json-ocsf` as a subprocess with the read-only credentials already in
// the CI environment, or reads an OCSF file the customer produced (--prowler-output). Each OCSF Detection
// Finding becomes one result, `prowler.<provider>.<CheckID>`; a check sos-app's catalogue
// (apps/sos-app/src/data/checks/prowler_<provider>.json) does not list is dropped and counted.
//
// The collector never passes a Prowler option that writes, fixes or sends anywhere (Security Hub, S3,
// Slack, Shodan, Prowler Cloud, secret validation), and refuses one given in --prowler-args.

import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../catalog.ts";
import type { Outcome, OptionValue, Result, Source } from "../types.ts";
import { scrub } from "./shared-cloud.ts";

export const PROWLER_PROVIDERS = ["aws", "azure", "gcp", "kubernetes", "m365", "github", "googleworkspace", "okta", "cloudflare"] as const;
export type ProwlerProvider = (typeof PROWLER_PROVIDERS)[number];

/** The version the catalogues were built from (apps/sos-app/scripts/build_prowler_catalog.py). */
export const PROWLER_VERSION = "5.45.0";

/** Options that make Prowler write, fix or send, or that change the output the collector reads. */
export const REFUSED_ARGS = [
  "--push-to-cloud", "--security-hub", "--send-sh-only-fails", "--fixer", "--fixer-config", "--output-bucket",
  "--output-bucket-no-assume", "--slack", "--shodan", "--scan-secrets-validate",
  "--output-formats", "--output-modes", "-M", "--output-directory", "-o", "--output-filename", "-F", "--status",
];

/** Environment variables whose values never leave the machine, even if Prowler echoes them in a detail. */
const SECRET_ENVS = [
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

const one = (v: OptionValue): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

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
  switch (provider) {
    case "azure":
    case "m365":
      // A client secret in env: service principal; otherwise the session `azure/login` (OIDC) left for the az CLI.
      return env.AZURE_CLIENT_SECRET ? ["--sp-env-auth"] : ["--az-cli-auth"];
    case "kubernetes":
      return env.KUBECONFIG ? ["--kubeconfig-file", env.KUBECONFIG] : [];
    default:
      // aws: boto3's chain (AWS_* keys, or AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE); gcp: application default
      // credentials (GOOGLE_APPLICATION_CREDENTIALS); github, okta, cloudflare, googleworkspace: their own env names.
      return [];
  }
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
 * Maps a Prowler OCSF array (Detection Findings) to results. Findings whose check the catalogue does not list
 * are dropped and counted. Several findings on one (check, resource) merge into one result: fail if any
 * failed, else pass if any passed, else skipped; their details are joined.
 */
export function parseOcsf(text: string, provider: string, known: ReadonlySet<string>): { results: Result[]; summary: ParseSummary } {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch (e) { throw new Error(`the Prowler output is not JSON (${(e as Error).message}); pass a json-ocsf file.`); }
  if (!Array.isArray(doc)) throw new Error("the Prowler output is not an OCSF array of findings; pass a json-ocsf file.");
  const summary: ParseSummary = { findings: doc.length, kept: 0, dropped: 0, droppedChecks: [], muted: 0, manual: 0, merged: 0 };
  const dropped = new Set<string>();
  const byKey = new Map<string, { r: Result; details: string[] }>();
  for (const f of doc) {
    if (!isObj(f)) continue;
    const meta = isObj(f.metadata) ? f.metadata : {};
    const info = isObj(f.finding_info) ? f.finding_info : {};
    const analytic = isObj(info.analytic) ? info.analytic : {};
    const checkId = s(meta.event_code) || s(analytic.uid);
    const unmapped = isObj(f.unmapped) ? f.unmapped : {};
    const prov = s(unmapped.provider) || provider;
    const check = `prowler.${prov}.${checkId}`;
    if (!checkId || !known.has(check)) { summary.dropped++; dropped.add(check); continue; }
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
    const prev = byKey.get(key);
    if (!prev) { byKey.set(key, { r: { check, resource, result, detail: "" }, details: detail ? [detail] : [] }); continue; }
    summary.merged++;
    const rank = (o: Outcome) => (o === "fail" ? 2 : o === "pass" ? 1 : 0);
    if (rank(result) > rank(prev.r.result)) prev.r.result = result;
    if (detail && !prev.details.includes(detail)) prev.details.push(detail);
  }
  const results = [...byKey.values()].map(({ r, details }) => ({ ...r, detail: details.join(" | ").slice(0, 1000) }));
  summary.kept = results.length;
  summary.droppedChecks = [...dropped].sort();
  return { results, summary };
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

/** Runs Prowler into a fresh directory and returns the OCSF text. A non-zero exit is an error. */
export async function runProwler(provider: ProwlerProvider, o: { bin: string; extra: string[]; env: NodeJS.ProcessEnv; spawner: ProwlerSpawner }): Promise<string> {
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
    return readFileSync(join(dir, file), "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── Source ──────────────────────────────────────────────────────────────────────────────────────────

export const prowler: Source = {
  name: "prowler",
  options: {
    "prowler-provider": { type: "string", help: `Prowler provider to run: ${PROWLER_PROVIDERS.join(", ")}` },
    "prowler-bin": { type: "string", help: "the prowler executable (default prowler on PATH)" },
    "prowler-args": { type: "string", help: "extra Prowler options, written --prowler-args=\"--region us-east-1 ca-central-1\" (never output, send or fix options)" },
    "prowler-output": { type: "string", help: "read this json-ocsf file instead of running Prowler" },
  },
  emits: catalogIds(),
  describe(opts) {
    const p = one(opts["prowler-provider"]) ?? "(no provider)";
    return one(opts["prowler-output"]) ? `Prowler ${p} findings from a json-ocsf file` : `Prowler ${PROWLER_VERSION} ${p} scan`;
  },
  async run(ctx) {
    const provider = one(ctx.opts["prowler-provider"]) as ProwlerProvider | undefined;
    if (!provider || !(PROWLER_PROVIDERS as readonly string[]).includes(provider)) {
      throw new Error(`--prowler-provider is required: one of ${PROWLER_PROVIDERS.join(", ")}.`);
    }
    const known = new Set(catalogIds(one(ctx.opts.catalog) ?? DEFAULT_CATALOG_DIR));
    if (![...known].some((id) => id.startsWith(`prowler.${provider}.`))) {
      ctx.warn(`prowler: sos-app's catalogue lists no ${provider} check (Prowler maps none to a KSI or SP 800-53 control); every finding will be dropped.`);
    }
    const file = one(ctx.opts["prowler-output"]);
    let text: string;
    if (file) {
      try { text = readFileSync(file, "utf8"); } catch (e) { throw new Error(`cannot read --prowler-output ${file}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); }
    } else {
      const spawner = (ctx.clients.prowler as ProwlerSpawner | undefined) ?? spawnProwler;
      const extra = one(ctx.opts["prowler-args"]) ? splitArgs(one(ctx.opts["prowler-args"])!) : [];
      text = await runProwler(provider, { bin: one(ctx.opts["prowler-bin"]) ?? "prowler", extra, env: ctx.env, spawner });
    }
    const { results, summary } = parseOcsf(text, provider, known);
    ctx.warn(`prowler: ${summary.findings} findings; ${summary.kept} results (${summary.merged} merged into the same check and resource, ` +
      `${summary.muted} muted and ${summary.manual} manual sent as skipped); ${summary.dropped} findings dropped from ${summary.droppedChecks.length} checks not in the catalogue` +
      (summary.droppedChecks.length ? `: ${summary.droppedChecks.slice(0, 20).join(", ")}${summary.droppedChecks.length > 20 ? ", …" : ""}` : ""));
    return scrub(results, SECRET_ENVS.map((n) => ctx.env[n]));
  },
};
