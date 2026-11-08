#!/usr/bin/env node
// Sagentix evidence collector. Reads the customer's systems read-only, runs checks, signs the result
// with an Ed25519 key and pushes it OUT to sos-app. `run` never listens for connections (only the one-time
// `google-login` takes one redirect on 127.0.0.1), and sos-app never holds the customer's credentials.
// Every run also checks in (a signed update may be named) and sends a run report; a source that fails
// becomes skipped results and the run goes on (apps/sos-app/docs/COLLECTOR_CHANNEL.md).
//
//   collector keygen [--out <path>]
//   collector run --config collector.config.json [any option below, which overrides the file]
//   collector agent --config collector.config.json   stays connected (outbound WebSocket); runs when sos-app asks
//   collector config-schema                  prints the JSON schema of the config file
//   collector google-login --client <client JSON> [--token <file>]   one-time Google Workspace sign-in
//   collector policies --config collector.config.json   pushes the policy folders for sos-app to match (src/policies.ts)
//   collector doctor --config collector.config.json [--source x]   credentials and permissions per source; sends nothing (src/doctor.ts)
//   run options for every source: --concurrency <n> (default 4), --http-timeout <s> (default 60), --verbose, --debug
//   collector run --endpoint <url> --key-id <id> [--key <pem> | env SAGENTIX_COLLECTOR_KEY]
//                 --source cloudflare[,...] [source options] [--catalog <dir>] [--dry-run] [--out <file>]
//                 [--fedramp-target <id> [--class A|B|C|D]]
//
// Exit codes: 0 sent (or dry run), 1 error (bad key, network, a source that failed), 2 usage, 3 nothing to send,
// 4 sos-app refused the push (its message is printed); `agent` only: 75 a signed update was written, restart me.

import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "./catalog.ts";
import { publicKeyFromPrivate, signBody, writeNewKey } from "./keys.ts";
import { MAX_RESULTS, buildPayload, splitResults, vet } from "./payload.ts";
import { SOURCES } from "./sources/index.ts";
import { CONFIG_SCHEMA, loadConfig } from "./config.ts";
import { googleLogin } from "./google_login.ts";
import type { Clients, OptionValue, Result, Source } from "./types.ts";
import { V1_COLLECT_PATH, v1Payload } from "./v1/index.ts";
import { CLASSES, type FedClass } from "./v1/rules.ts";
import { EXIT_UPDATE, checkin, detectRunner, modeOf, type Channel } from "./channel.ts";
import { RunRecorder, buildReport, deliverReport, envSecrets, scrubText, type CallEvent, type RetryEvent, type SourceReport, type SourceStats } from "./report.ts";
import { pool } from "./pool.ts";
import { PROBES, doctorHint, type Check } from "./doctor.ts";
import { agent } from "./agent.ts";
import { VAULT_FILE, Vault, keyHolderFor, runEnv, type KeyHolder } from "./vault.ts";
import { applyRefs } from "./refs.ts";
import { credentialsIn, settingsOf, vaultBridge } from "./deliveries.ts";
import { APPROVED_DIR, DOCUMENTS_KEY_ENV, pullApproved, pushPolicies, writeApproved, type PoliciesConfig, type PolicyOutcome } from "./policies.ts";

export const COLLECT_PATH = "/api/collect";
export const KEY_ENV = "SAGENTIX_COLLECTOR_KEY";
/** Set by the agent on a connector test asked from sos-app (a dry run of one connector). */
export const TEST_ENV = "SAGENTIX_CONNECTOR_TEST";
/** `update` (75) is the agent's only: it wrote a signed update and exits so it is restarted on it. */
export const EXIT = { ok: 0, error: 1, usage: 2, nothing: 3, refused: 4, update: EXIT_UPDATE } as const;

export interface Deps {
  /** Used only for the POST to sos-app. */
  fetch: typeof fetch;
  /** The check-in and run report POSTs; default `fetch`. */
  channel?: typeof fetch;
  /** Where the run report and check-in files go when there is no --config; default the working directory. */
  cwd?: string;
  /** Clients the sources use; a source builds its own from env when one is missing. */
  clients: Clients;
  sources: readonly Source[];
  env: NodeJS.ProcessEnv;
  /** Where the vault key is (src/vault.ts); default the strongest place this computer offers. Tests give their own. */
  vaultKey?: (dir: string, keyId: string) => KeyHolder;
  now: () => Date;
  out: (s: string) => void;
  err: (s: string) => void;
}

export function defaultDeps(): Deps {
  return {
    fetch: globalThis.fetch,
    clients: {},
    sources: SOURCES,
    env: process.env,
    now: () => new Date(),
    out: (s) => process.stdout.write(s + "\n"),
    err: (s) => process.stderr.write(s + "\n"),
  };
}

const COMMON_OPTIONS = {
  endpoint: { type: "string" },
  "key-id": { type: "string" },
  key: { type: "string" },
  source: { type: "string", multiple: true },
  catalog: { type: "string" },
  "dry-run": { type: "boolean" },
  out: { type: "string" },
  "fedramp-target": { type: "string" },
  class: { type: "string" },
  "cpo-uri": { type: "string" },
  config: { type: "string" },
  concurrency: { type: "string" },
  "http-timeout": { type: "string" },
  verbose: { type: "boolean" },
  debug: { type: "boolean" },
} as const;

/** Sources run side by side, at most this many at once (--concurrency; 1 is the old one-after-another). */
export const DEFAULT_CONCURRENCY = 4;
export const MAX_CONCURRENCY = 16;
/** Seconds before an outbound call made by a source is abandoned (--http-timeout; 0 never). */
export const DEFAULT_HTTP_TIMEOUT_S = 60;

/** --concurrency and --http-timeout, or why they are wrong. */
export function runTuning(values: Record<string, OptionValue>): { concurrency: number; timeoutMs: number } | string {
  const c = values.concurrency === undefined ? DEFAULT_CONCURRENCY : Number(values.concurrency);
  if (!Number.isInteger(c) || c < 1 || c > MAX_CONCURRENCY) return `--concurrency must be a whole number from 1 to ${MAX_CONCURRENCY}.`;
  const t = values["http-timeout"] === undefined ? DEFAULT_HTTP_TIMEOUT_S : Number(values["http-timeout"]);
  if (!Number.isFinite(t) || t < 0 || t > 3600) return "--http-timeout must be a number of seconds from 0 (never) to 3600.";
  return { concurrency: c, timeoutMs: Math.round(t * 1000) };
}

function usage(sources: readonly Source[]): string {
  const opts = sources.flatMap((s) => Object.entries(s.options).map(([n, o]) =>
    `    --${n}${o.type === "string" ? " <value>" : ""}${o.multiple ? " (repeatable)" : ""}  [${s.name}] ${o.help}`));
  return `usage:
  collector keygen [--out sagentix-collector.pem]
  collector run --config collector.config.json [options that override the file]
  collector agent --config collector.config.json   (stays connected to sos-app; runs when it asks)
  collector config-schema
  collector google-login --client <Desktop app client JSON> [--token sagentix-google-token.json] [--port <n>] [--login-hint <email>] [--no-browser]
  collector doctor --config collector.config.json [--source <name>]   checks each source's credentials and permissions; collects and sends nothing
  collector run --endpoint <url> --key-id <id> [--key <pem file>] --source ${sources.map((s) => s.name).join("|")}[,...]
                [source options] [--catalog <checks dir>] [--dry-run] [--out <file>]
                [--concurrency <1-${MAX_CONCURRENCY}, default ${DEFAULT_CONCURRENCY}>] [--http-timeout <seconds, default ${DEFAULT_HTTP_TIMEOUT_S}>] [--verbose] [--debug]
                [--fedramp-target <id> [--class A|B|C|D] [--cpo-uri <url>]]
  The private key may come from ${KEY_ENV} (PEM text) instead of --key.
  --verbose prints each outbound call (method, host, path with ids as :id; never a query, header or body) and each retry;
  --debug also prints a failed source's stack. A table of every source (checks, calls, retries, time) ends each run.
  Source options:
${opts.join("\n")}
  Every run checks in first (an update sos-app names is taken only with a valid Sagentix release signature, and only
  as sagentix-collector.ref or .image beside the config, read on the next start) and ends by writing
  sagentix-run-report.json beside the config and sending it (a dry run writes it only).
  A source that fails gives skipped results; the run goes on, pushes the rest and exits 1.
  Exit codes: 0 sent or dry run, 1 error (or a source failed), 2 usage, 3 nothing to send, 4 sos-app refused the push;
  agent only: 75 a signed update was written (after any run in progress ended), so restart it on the new code.`;
}

/** https, or http on localhost; a bare origin gets the collect path appended. */
export function collectUrl(endpoint: string, path: string = COLLECT_PATH): string {
  const u = new URL(endpoint);
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(local && u.protocol === "http:")) throw new Error("--endpoint must be https (http only for localhost).");
  if (u.pathname === "/" || u.pathname === "") u.pathname = path;
  return u.toString();
}

function keygen(argv: string[], deps: Deps): number {
  const { values } = parseArgs({ args: argv, options: { out: { type: "string", default: "sagentix-collector.pem" } } });
  const path = resolve(values.out!);
  try {
    const { publicKey } = writeNewKey(path);
    deps.err(`Private key written to ${path} (mode 0600, readable by you only). Keep it where the collector runs (beside the script, or in your CI's secret store); never send it to anyone.`);
    deps.err("Register this public key in sos-app (Connect your environment, step 4; or Evidence > Collector keys):");
    deps.out(publicKey);
    return EXIT.ok;
  } catch (e) {
    deps.err(`keygen: ${(e as NodeJS.ErrnoException).code === "EEXIST" ? `${path} already exists; refusing to overwrite it.` : String(e)}`);
    return EXIT.error;
  }
}

/** The server's error as text: `error` plus any `problems`, or the raw body. */
function serverMessage(text: string): string {
  try {
    const j = JSON.parse(text);
    return [j.error, ...(Array.isArray(j.problems) ? j.problems.map((p: unknown) => `  ${typeof p === "string" ? p : JSON.stringify(p)}`) : [])].filter(Boolean).join("\n") || text;
  } catch {
    return text;
  }
}

/**
 * The connectors' secrets and settings, set in sos-app and sealed for this collector (src/vault.ts), when the run has a
 * config and a key id. A vault that cannot be opened is a warning: the sources that need its values fail on their own.
 */
async function vaultEnv(o: { configPath?: string; keyId?: string; dir: string; runner: ReturnType<typeof detectRunner>; deps: Deps; note: (w: string[]) => void }):
  Promise<{ env: NodeJS.ProcessEnv; cleanup: () => void; secrets: string[] }> {
  const { configPath, keyId, dir, runner, deps } = o;
  if (!configPath || !keyId) return { env: deps.env, cleanup: () => {}, secrets: [] };
  try {
    const creds = credentialsIn(resolve(configPath));
    const holder = deps.vaultKey?.(dir, keyId) ?? keyHolderFor(dir, keyId, { env: deps.env, platform: process.platform, runner });
    const r = runEnv(dir, holder, deps.env, (name) => settingsOf(creds, name));
    // Connectors read from the client's own vault (src/refs.ts) take all their names from there, after the local vault.
    const refs = existsSync(join(dir, VAULT_FILE)) ? new Vault(dir, holder).refs() : {};
    const f = Object.keys(refs).length ? await applyRefs(dir, refs, creds, r.env, deps.channel ?? deps.fetch) : null;
    const used = r.used.length + (f?.used.length ?? 0), warnings = [...r.warnings, ...(f?.warnings ?? [])];
    if (used) deps.err(`vault: ${used} value(s) from ${VAULT_FILE}${f ? " and your own vault" : ""}`);
    for (const w of warnings) deps.err(`warning: vault: ${w}`);
    if (warnings.length) o.note(warnings);
    return { env: f?.env ?? r.env, cleanup: () => { r.cleanup(); f?.cleanup(); }, secrets: [...r.secrets, ...(f?.secrets ?? [])] };
  } catch (e) {
    const w = `the vault could not be opened: ${String((e as Error)?.message ?? e)}`;
    deps.err(w);
    o.note([w]);
    return { env: deps.env, cleanup: () => {}, secrets: [] };
  }
}

/** One line of the --verbose call log: the call's shape, scrubbed of the run's secrets. */
function callLine(c: CallEvent, secrets: readonly string[]): string {
  return scrubText(`[${c.source}] ${c.method} ${c.host}${c.path} -> ${c.status || "no answer"} in ${c.ms} ms${c.error ? ` (${c.error})` : ""}`, secrets);
}

/** The end-of-run table, one row per source: what it judged, what it called, how long it took. */
export function summaryTable(reports: readonly SourceReport[], stats: ReadonlyMap<string, SourceStats>): string[] {
  const rows = reports.map((r) => {
    const st = stats.get(r.name) ?? { calls: 0, retries: 0, httpErrors: 0 };
    return [r.name, String(r.pass + r.fail + r.skipped), String(r.pass), String(r.fail), String(r.skipped), String(st.calls), String(st.retries), String(st.httpErrors),
      `${(r.ms / 1000).toFixed(1)} s`, r.error ? "ERROR" : r.pass + r.fail ? "read" : "nothing read"];
  });
  const head = ["source", "results", "pass", "fail", "skipped", "calls", "retries", "http errors", "time", "source status"];
  const total = rows.length > 1 ? [["total", ...[1, 2, 3, 4, 5, 6, 7].map((i) => String(rows.reduce((a, r) => a + Number(r[i]), 0))),
    `${(reports.reduce((a, r) => Math.max(a, r.ms), 0) / 1000).toFixed(1)} s max`, ""]] : [];
  const all = [head, ...rows, ...total];
  const w = head.map((_, i) => Math.max(...all.map((r) => r[i].length)));
  const line = (r: string[]) => r.map((c, i) => (i === 0 || i === r.length - 1 ? c.padEnd(w[i]) : c.padStart(w[i]))).join("  ").trimEnd();
  return [line(head), w.map((n) => "-".repeat(n)).join("  "), ...rows.map(line), ...(total.length ? [w.map((n) => "-".repeat(n)).join("  "), line(total[0])] : [])];
}

/** A short fix for each refused call in the results: source, check, HTTP status and what to grant (src/doctor.ts). */
export function problemLines(results: readonly Result[], max = 20): string[] {
  const seen = new Set<string>(), out: string[] = [];
  for (const r of results) {
    const st = r.apiError?.status;
    if (r.result !== "skipped" || st === undefined || (st !== 401 && st !== 403)) continue;
    const source = r.check.split(".")[0];
    const k = `${r.check}|${st}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (out.length < max) out.push(`  ${r.check} [${r.resource}]: HTTP ${st}${st === 401 ? " (credential refused)" : " (permission missing)"}; fix: ${doctorHint(source)}`);
  }
  if (seen.size > max) out.push(`  … and ${seen.size - max} more`);
  return out;
}

/** The run's options: the command line over the config file (--source adds to the file's), or the usage exit code. */
function parseRunArgs(argv: string[], deps: Deps): { values: Record<string, OptionValue>; configPath?: string } | number {
  const sourceOptions: Record<string, { type: "string" | "boolean"; multiple?: boolean }> = {};
  for (const s of deps.sources) {
    for (const [n, o] of Object.entries(s.options)) {
      if (n in COMMON_OPTIONS || n in sourceOptions) throw new Error(`option --${n} of source ${s.name} collides with another option.`);
      sourceOptions[n] = { type: o.type, ...(o.multiple ? { multiple: true } : {}) };
    }
  }
  let values: Record<string, OptionValue>;
  try {
    ({ values } = parseArgs({ args: argv, options: { ...COMMON_OPTIONS, ...sourceOptions }, strict: true }) as { values: Record<string, OptionValue> });
  } catch (e) {
    deps.err(`${(e as Error).message}\n${usage(deps.sources)}`);
    return EXIT.usage;
  }
  const configPath = typeof values.config === "string" ? values.config : undefined;
  if (typeof values.config === "string") {
    const c = loadConfig(values.config, deps.sources);
    if ("problems" in c) { deps.err(`${values.config} is not a valid collector config:\n  ${c.problems.join("\n  ")}`); return EXIT.usage; }
    const given = Object.fromEntries(Object.entries(values).filter(([k, v]) => v !== undefined && k !== "config"));
    // --source on the command line adds to the file's sources.
    const src = [...((c.values.source as string[] | undefined) ?? []), ...((given.source as string[] | undefined) ?? [])];
    values = { ...c.values, ...given, source: src };
  }
  return { values, configPath };
}

/**
 * `collector doctor`: per configured source, its credentials and one cheap read per permission it needs (src/doctor.ts),
 * printed as pass or fail with the fix. Nothing is collected, signed or sent: no check-in, no push, no run report.
 * With --config, --source narrows the file's sources to those named. Exit 0 when every check passes, 1 otherwise.
 */
export async function doctorCommand(argv: string[], deps: Deps): Promise<number> {
  const parsed = parseRunArgs(argv, deps);
  if (typeof parsed === "number") return parsed;
  const { values, configPath } = parsed;
  const tuning = runTuning(values);
  if (typeof tuning === "string") { deps.err(tuning); return EXIT.usage; }
  // From the config, --source picks among the file's sources rather than adding to them.
  const cli = argv.flatMap((a, i) => (a === "--source" ? [argv[i + 1]] : a.startsWith("--source=") ? [a.slice(9)] : [])).flatMap((s) => (s ?? "").split(",")).map((s) => s.trim()).filter(Boolean);
  const all = ((values.source as string[] | undefined) ?? []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);
  const names = [...new Set(configPath && cli.length ? cli : all)];
  if (!names.length) { deps.err(`doctor: name the sources (--config with a "sources" block, or --source ${deps.sources.map((s) => s.name).join("|")}).`); return EXIT.usage; }
  const unknown = names.filter((n) => !deps.sources.some((s) => s.name === n));
  if (unknown.length) { deps.err(`unknown source ${unknown.join(", ")}; known: ${deps.sources.map((x) => x.name).join(", ")}.`); return EXIT.usage; }
  const keyId = typeof values["key-id"] === "string" ? values["key-id"] : undefined;
  const dir = configPath ? dirname(resolve(configPath)) : (deps.cwd ?? process.cwd());
  const runner = detectRunner(deps.env);
  const lines: string[] = [];
  const out = (s: string) => lines.push(s);
  // The collector key, read and parsed locally; it is not used to sign anything here.
  const keyChecks: Check[] = [];
  let pem: string | undefined;
  if (typeof values.key === "string") {
    try { pem = readFileSync(values.key, "utf8"); } catch (e) { keyChecks.push({ what: "collector key", verdict: "fail", detail: `${values.key}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`, fix: "point keyFile (or --key) at the PEM `collector keygen` wrote" }); }
  } else pem = deps.env[KEY_ENV];
  if (pem) {
    try { keyChecks.push({ what: "collector key", verdict: "pass", detail: `Ed25519 public key ${publicKeyFromPrivate(pem).slice(0, 12)}…${keyId ? `, key id ${keyId}` : " (no keyId: only --dry-run runs)"}` }); }
    catch { keyChecks.push({ what: "collector key", verdict: "fail", detail: "not an Ed25519 private key", fix: "use the PEM `collector keygen` wrote" }); }
  } else if (!keyChecks.length) keyChecks.push({ what: "collector key", verdict: "skip", detail: `no --key and no ${KEY_ENV}: only --dry-run runs` });
  if (typeof values.endpoint === "string") {
    try { collectUrl(values.endpoint); keyChecks.push({ what: "endpoint", verdict: "pass", detail: new URL(values.endpoint).origin }); }
    catch (e) { keyChecks.push({ what: "endpoint", verdict: "fail", detail: (e as Error).message, fix: "set endpoint to your sos-app origin, https://…" }); }
  }
  const { env, cleanup, secrets } = await vaultEnv({ configPath, keyId, dir, runner, deps, note: () => {} });
  const scrub = [...new Set([...envSecrets(env), ...secrets.filter((v) => v.length >= 6)])].sort((a, b) => b.length - a.length);
  const results: { source: string; checks: Check[] }[] = [{ source: "collector", checks: keyChecks }];
  const now = deps.now();
  // One wrapper around fetch, with the run's timeout, so a probe that hangs ends like a run's call would.
  const rec = new RunRecorder(deps.now, undefined, { timeoutMs: tuning.timeoutMs });
  const release = rec.hold();
  try {
    const outcomes = await pool(names, tuning.concurrency, (name) => rec.source(name, async () => {
      const probe = PROBES[name];
      if (!probe) return [{ what: "self-test", verdict: "skip" as const, detail: "this source has no self-test; try `collector run --dry-run --source " + name + "`" }];
      return probe({ opts: values, env, clients: deps.clients, now, warn: () => {} });
    }));
    for (const [i, o] of outcomes.entries()) {
      const v = o.status === "fulfilled" ? o.value : { error: o.reason, value: undefined };
      results.push({ source: names[i], checks: v.value ?? [{ what: "self-test", verdict: "fail", detail: `the probe failed: ${String((v.error as Error)?.message ?? v.error)}`, fix: "report this to Sagentix with the line above" }] });
    }
  } finally { release(); cleanup(); }
  let failed = 0, passed = 0, skipped = 0;
  out(`collector doctor: ${names.length} source(s); read-only checks, nothing collected or sent`);
  for (const r of results) {
    out(r.source);
    const w = Math.min(44, Math.max(...r.checks.map((c) => c.what.length), 8));
    for (const c of r.checks) {
      if (c.verdict === "pass") passed++; else if (c.verdict === "fail") failed++; else skipped++;
      out(`  ${c.verdict.toUpperCase().padEnd(4)}  ${c.what.padEnd(w)}  ${c.detail}`);
      if (c.fix && c.verdict !== "pass") out(`        fix: ${c.fix}`);
    }
  }
  out(`doctor: ${passed} passed, ${failed} failed, ${skipped} skipped${failed ? "; fix the lines marked FAIL, then run the doctor again" : "; ready for `collector run`"}`);
  for (const l of lines) deps.out(scrubText(l, scrub));
  return failed ? EXIT.error : EXIT.ok;
}

export async function run(argv: string[], deps: Deps): Promise<number> {
  // Every line the run writes to stderr also goes into its report (scrubbed there); the --verbose call log and the
  // closing table go to stderr only (the report already holds every call, and every source's counts and time).
  const rec = new RunRecorder(deps.now);
  const rawErr = deps.err;
  deps = { ...deps, err: rec.tee(deps.err) };
  const parsed = parseRunArgs(argv, deps);
  if (typeof parsed === "number") return parsed;
  let { values } = parsed;
  const { configPath } = parsed;
  const dry = values["dry-run"] === true;
  const v1Target = typeof values["fedramp-target"] === "string" ? values["fedramp-target"] : undefined;
  const tuning = runTuning(values);
  if (typeof tuning === "string") { deps.err(tuning); return EXIT.usage; }
  const { concurrency } = tuning;
  const verbose = values.verbose === true || values.debug === true, debug = values.debug === true;
  // Read when a line is printed, by then holding the vault's values too.
  let lineSecrets: readonly string[] = envSecrets(deps.env);
  rec.options = {
    timeoutMs: tuning.timeoutMs,
    ...(verbose ? {
      onCall: (c: CallEvent) => rawErr(callLine(c, lineSecrets)),
      onRetry: (source: string, e: RetryEvent) => rawErr(scrubText(`[${source}] retry ${e.attempt} after ${e.status ? `HTTP ${e.status}` : "no answer"}, waiting ${e.waitMs} ms`, lineSecrets)),
    } : {}),
  };

  const names = ((values.source as string[] | undefined) ?? []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);
  if (!names.length) { deps.err(`--source is required (${deps.sources.map((s) => s.name).join(", ")}).`); return EXIT.usage; }
  const chosen: Source[] = [];
  for (const n of [...new Set(names)]) {
    const s = deps.sources.find((x) => x.name === n);
    if (!s) { deps.err(`unknown source ${n}; known: ${deps.sources.map((x) => x.name).join(", ")}.`); return EXIT.usage; }
    chosen.push(s);
  }
  for (const s of chosen) {
    const why = s.validate?.(values);
    if (why) { deps.err(`${s.name}: ${why}`); return EXIT.usage; }
  }
  const cls = String(values.class ?? "B").toUpperCase() as FedClass;
  if (v1Target && !(CLASSES as readonly string[]).includes(cls)) { deps.err("--class must be A, B, C or D."); return EXIT.usage; }
  if (v1Target && chosen.some((s) => s.name !== "cloudflare")) { deps.err("--fedramp-target (v1) carries Cloudflare checks only."); return EXIT.usage; }

  if (typeof values.endpoint !== "string") { deps.err("--endpoint is required (the sos-app origin, e.g. https://app.example)."); return EXIT.usage; }
  let url: string;
  try { url = collectUrl(values.endpoint, v1Target ? V1_COLLECT_PATH : COLLECT_PATH); } catch (e) { deps.err((e as Error).message); return EXIT.usage; }

  let pem: string | undefined;
  if (typeof values.key === "string") {
    try { pem = readFileSync(values.key, "utf8"); } catch (e) { deps.err(`cannot read --key ${values.key}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); return EXIT.error; }
  } else if (deps.env[KEY_ENV]) pem = deps.env[KEY_ENV];
  const keyId = typeof values["key-id"] === "string" ? values["key-id"] : undefined;
  if (!dry && (!pem || !keyId)) { deps.err(`--key-id and --key (or ${KEY_ENV}) are required unless --dry-run.`); return EXIT.usage; }

  const catalog = loadCatalog(typeof values.catalog === "string" ? values.catalog : DEFAULT_CATALOG_DIR);

  // From here on every run ends with a report; the check-in comes first, before any source reads.
  const runner = detectRunner(deps.env), mode = modeOf(deps.env);
  const dir = configPath ? dirname(resolve(configPath)) : (deps.cwd ?? process.cwd());
  const channel: Channel | undefined = pem && keyId
    ? { origin: new URL(url).origin, keyId, pem, fetch: deps.channel ?? deps.fetch, dir, runner, mode, env: deps.env, now: deps.now }
    : undefined;
  // A connector test asked from sos-app runs that connector dry: no check-in, and no run report, so the last real run's
  // report beside the config stays what sos-app shows.
  const connectorTest = dry && deps.env[TEST_ENV] === "1";
  if (connectorTest) { /* neither */ }
  else if (channel) {
    const vault = configPath && keyId ? vaultBridge({ configPath: resolve(configPath), keyId, now: deps.now, log: deps.err,
      holder: deps.vaultKey?.(dir, keyId) ?? keyHolderFor(dir, keyId, { env: deps.env, platform: process.platform, runner }) }) : undefined;
    rec.note("checkin", (await checkin(channel, { write: !dry, log: deps.err, vault })).warnings);
  }
  else deps.err("check-in skipped: a dry run without a key cannot sign one.");
  const { env, cleanup, secrets: vaultSecrets } = await vaultEnv({ configPath, keyId, dir, runner, deps, note: (w) => rec.note("vault", w) });
  lineSecrets = [...new Set([...envSecrets(env), ...vaultSecrets.filter((v) => v.length >= 6)])].sort((a, b) => b.length - a.length);
  let code: number;
  let judged: Result[] = [];
  try {
    code = await collect();
  } catch (e) {
    deps.err(`collector error: ${String((e as Error)?.message ?? e)}`);
    code = EXIT.error;
  } finally { cleanup(); }
  // The closing table (stderr only), and the refused calls with what to grant.
  const ran = rec.sources.filter((r) => chosen.some((s) => s.name === r.name));
  if (ran.length) {
    rawErr(`\nsummary (${ran.length} source(s), up to ${concurrency} at once):`);
    for (const l of summaryTable(ran, rec.stats)) rawErr(l);
    const problems = problemLines(judged);
    if (problems.length) { rawErr("refused calls (their checks were sent as skipped):"); for (const l of problems) rawErr(scrubText(l, lineSecrets)); }
  }
  // The report is scrubbed of every value in the run's environment, the vault's included.
  if (connectorTest) return code;
  await deliverReport(buildReport(rec, { now: deps.now(), exitCode: code, runner, mode, env, secrets: vaultSecrets }), { dry, channel, dir, log: deps.err });
  return code;

  async function collect(): Promise<number> {
    // Run every chosen source inside a guard, then keep only what the server will accept. A source that throws gives
    // one skipped result per check it declares, and the run goes on (section 1 of COLLECTOR_CHANNEL.md).
    const now = deps.now();
    const raw: Result[] = [];
    const failed: string[] = [];
    // The sources run side by side, at most --concurrency at once, under one fetch wrapper (src/report.ts) that counts each
    // call against its source. Their outcomes are then taken in the order the sources were named, so the results, and
    // the bytes signed, are those of a run one source after another (test/e2e.test.ts holds a golden copy).
    const release = rec.hold();
    let outcomes: Awaited<ReturnType<typeof rec.source<Result[]>>>[];
    try {
      outcomes = (await pool(chosen, concurrency, (s) => rec.source(s.name, () => s.run({ opts: values, env, clients: deps.clients, now, warn: deps.err }))))
        .map((o) => (o.status === "fulfilled" ? o.value : { error: o.reason, report: { name: "?", ms: 0, pass: 0, fail: 0, skipped: 0, error: null, warnings: [] } }));
    } finally { release(); }
    // The report lists the sources in the order named, not the order they finished.
    const order = new Map(chosen.map((s, i) => [s.name, i]));
    const ranked = rec.sources.filter((r) => order.has(r.name)).sort((a, b) => order.get(a.name)! - order.get(b.name)!);
    let k = 0;
    for (let i = 0; i < rec.sources.length; i++) if (order.has(rec.sources[i].name)) rec.sources[i] = ranked[k++];
    for (const [i, s] of chosen.entries()) {
      const { value, error, report } = outcomes[i];
      let got: Result[];
      if (error !== undefined || !Array.isArray(value)) {
        const message = error !== undefined ? String((error as Error)?.message ?? error) : "the source returned no list of results";
        if (!report.error) report.error = { message, stack: "" };
        deps.err(`error in source ${s.name}: ${message}; its ${s.emits.length} checks are sent as skipped and the run goes on. To see why: ${doctorHint(s.name)}.`);
        if (debug && report.error.stack) rawErr(scrubText(report.error.stack, lineSecrets));
        failed.push(s.name);
        got = s.emits.map((check) => ({ check, resource: `the ${s.name} source`, result: "skipped" as const, detail: `collector error in ${s.name}: ${message}` }));
      } else got = value;
      const stray = got.filter((r) => !s.emits.includes(r.check)).map((r) => r.check);
      if (stray.length) deps.err(`warning: source ${s.name} emitted checks it does not declare: ${[...new Set(stray)].join(", ")}`);
      for (const r of got) report[r.result === "pass" ? "pass" : r.result === "fail" ? "fail" : "skipped"]++;
      raw.push(...got);
    }
    judged = raw;
    // A failed source makes the run exit 1 once everything else is done, as a failed engine run always has.
    const done = (c: number) => (c === EXIT.ok || c === EXIT.nothing) && failed.length ? EXIT.error : c;
    const vetted = vet(raw, catalog);
    if (vetted.unknown.length) deps.err(`refused (not in the catalogue at ${typeof values.catalog === "string" ? values.catalog : DEFAULT_CATALOG_DIR}): ${vetted.unknown.join(", ")}`);
    if (vetted.duplicates.length) deps.err(`dropped duplicate results: ${vetted.duplicates.slice(0, 10).join(", ")}`);
    const results = vetted.results;
    const skipped = results.filter((r) => r.result === "skipped");
    if (v1Target && results.length > MAX_RESULTS) { deps.err(`${results.length} results; the v1 push takes at most ${MAX_RESULTS}. Narrow the run (e.g. --zone).`); return EXIT.error; }

    const issuedAt = now.toISOString();
    // One push, or several when the results exceed what sos-app takes at once (5,000 results, 4 MB). Each is signed alone.
    const pushes: { body: Uint8Array<ArrayBuffer>; signature?: string; bodyText: string; summary: unknown }[] = [];
    if (v1Target) {
      const cpoUri = typeof values["cpo-uri"] === "string" ? values["cpo-uri"] : new URL(`/api/fedramp/targets/${encodeURIComponent(v1Target)}/export/cpo`, url).toString();
      const v1 = v1Payload(results, catalog, { targetId: v1Target, cls, issuedAt, cpoUri });
      if (v1.problems.length) { deps.err(`The SDR is not valid against FedRAMP's schema:\n  ${v1.problems.join("\n  ")}`); return EXIT.error; }
      if (!dry && !v1.payload.results.length) { deps.err("Nothing to send: no KSI had a check that passed or failed."); return done(EXIT.nothing); }
      const body = new TextEncoder().encode(JSON.stringify(v1.payload));
      pushes.push({ body, bodyText: new TextDecoder().decode(body), summary: { ksis: v1.payload.results.map((r) => `${r.ksiId} ${r.status}`), omitted: v1.omitted } });
    } else {
      const sources = chosen.map((s) => ({ source: s.name, scope: s.describe(values) }));
      const parts = results.length ? splitResults(results) : [[]];
      if (parts.length > 1) deps.err(`${results.length} results go out as ${parts.length} signed pushes (sos-app takes at most ${MAX_RESULTS} results or 4 MB per push).`);
      for (const part of parts) {
        const body = new TextEncoder().encode(JSON.stringify(buildPayload({ issuedAt, results: part, sources })));
        pushes.push({ body, bodyText: new TextDecoder().decode(body),
          summary: { passed: part.filter((r) => r.result === "pass").length, failed: part.filter((r) => r.result === "fail").length, skipped: part.filter((r) => r.result === "skipped").length } });
      }
    }
    for (const p of pushes) p.signature = pem ? signBody(pem, p.body) : undefined;
    const publicKey = pem ? publicKeyFromPrivate(pem) : null;

    if (typeof values.out === "string") {
      // The customer's own copy: the exact bytes sent, and what verifies them (one entry per push when split).
      const copy = pushes.length === 1
        ? { endpoint: url, keyId: keyId ?? null, publicKey, signature: pushes[0].signature ?? null, body: pushes[0].bodyText }
        : { endpoint: url, keyId: keyId ?? null, publicKey, pushes: pushes.map((p) => ({ signature: p.signature ?? null, body: p.bodyText })) };
      writeFileSync(values.out, JSON.stringify(copy, null, 2) + "\n");
      deps.err(`signed payload written to ${values.out}`);
    }

    if (dry) {
      const head = (p: (typeof pushes)[number]) => ({ "x-sagentix-key-id": keyId ?? null, "x-sagentix-signature": p.signature ?? null });
      deps.out(JSON.stringify(pushes.length === 1
        ? { dryRun: true, endpoint: url, headers: head(pushes[0]), publicKey, summary: pushes[0].summary, payload: JSON.parse(pushes[0].bodyText) }
        : { dryRun: true, endpoint: url, publicKey, pushes: pushes.map((p) => ({ headers: head(p), summary: p.summary, payload: JSON.parse(p.bodyText) })) }, null, 2));
      return done(EXIT.ok);
    }

    if (!results.some((r) => r.result !== "skipped")) {
      deps.err("Nothing to send: every check was skipped. Run with --dry-run to see why.");
      for (const s of skipped.slice(0, 50)) deps.err(`  skipped ${s.check} [${s.resource}]: ${s.detail}`);
      return done(EXIT.nothing);
    }
    for (const s of skipped) deps.err(`skipped ${s.check} [${s.resource}]: ${s.detail}`);

    // A push that fails is recorded and ends the pushing (the later parts would fail the same way); the report still goes.
    for (const [i, p] of pushes.entries()) {
      const which = pushes.length > 1 ? ` (push ${i + 1} of ${pushes.length}${i ? `; pushes 1 to ${i} were accepted` : ""})` : "";
      let res: Response;
      try {
        res = await deps.fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-sagentix-key-id": keyId!, "x-sagentix-signature": p.signature! }, body: p.body });
      } catch (e) {
        deps.err(`POST ${url} failed${which}: ${String(e)}`);
        rec.pushes.push({ status: 0, error: String((e as Error)?.message ?? e) });
        return EXIT.error;
      }
      const text = await res.text();
      if (!res.ok) {
        deps.err(`sos-app refused the push${which} (HTTP ${res.status}): ${serverMessage(text)}`);
        rec.pushes.push({ status: res.status, error: serverMessage(text).slice(0, 500) });
        return EXIT.refused;
      }
      let runId: string | undefined;
      try { const j = JSON.parse(text); if (typeof j?.runId === "string") runId = j.runId; } catch { /* not JSON */ }
      rec.pushes.push({ status: res.status, ...(runId ? { runId } : {}) });
      deps.out(text);
    }
    return done(EXIT.ok);
  }
}

/** `collector policies --config <file>`: push each file of the config's policy folders for sos-app to match (src/policies.ts). */
export async function policiesCommand(argv: string[], deps: Deps): Promise<number> {
  let config: string | undefined;
  try { ({ values: { config } } = parseArgs({ args: argv, options: { config: { type: "string" } }, strict: true }) as { values: { config?: string } }); }
  catch (e) { deps.err((e as Error).message); return EXIT.usage; }
  if (!config) { deps.err("usage: collector policies --config <collector.config.json>"); return EXIT.usage; }
  const c = loadConfig(config, deps.sources);
  if ("problems" in c) { deps.err(`${config} is not a valid collector config:\n  ${c.problems.join("\n  ")}`); return EXIT.usage; }
  const doc = JSON.parse(readFileSync(config, "utf8").replace(/^\uFEFF/, "")) as { endpoint: string; policies?: PoliciesConfig };
  const p = doc.policies;
  if (!p) { deps.err(`${config} has no "policies" block (dir, keyId, organization): nothing to push.`); return EXIT.nothing; }
  const base = dirname(config);
  const dirs = (Array.isArray(p.dir) ? p.dir : [p.dir]).map((d) => (isAbsolute(d) ? d : join(base, d)));
  const pem = p.keyFile ? readFileSync(isAbsolute(p.keyFile) ? p.keyFile : join(base, p.keyFile), "utf8") : deps.env[DOCUMENTS_KEY_ENV];
  if (!pem) { deps.err(`No documents key: give policies.keyFile, or set ${DOCUMENTS_KEY_ENV}.`); return EXIT.usage; }
  let out: PolicyOutcome[];
  try { out = await pushPolicies({ endpoint: doc.endpoint, organization: p.organization, keyId: p.keyId, pem, dirs, fetch: deps.fetch, now: deps.now }); }
  catch (e) { deps.err(`policies: ${(e as Error).message}`); return EXIT.error; }
  for (const r of out) deps.out(`${r.outcome.padEnd(9)} ${r.file}: ${r.detail}`);
  // Then the approved versions back into <folder>/approved/, so the next edit starts from the text in force (2026-11-05).
  try {
    const approved = await pullApproved({ endpoint: doc.endpoint, organization: p.organization, keyId: p.keyId, pem, fetch: deps.fetch, now: deps.now });
    for (const w of writeApproved(dirs, approved)) if (w.outcome !== "present") deps.out(`${(w.outcome === "written" ? "approved" : "missing").padEnd(9)} ${APPROVED_DIR}/${w.file}: ${w.detail}`);
  } catch (e) { deps.err(`policies: the approved copies were not written: ${(e as Error).message}`); }
  const count = (k: PolicyOutcome["outcome"]) => out.filter((r) => r.outcome === k).length;
  deps.err(`policies: ${out.length} file(s); ${count("filed")} filed as drafts, ${count("duplicate")} unchanged, ${count("evidence")} as evidence, ${count("unmatched") + count("taken")} not matched, ${count("refused")} refused.`);
  if (!out.length) return EXIT.nothing;
  return count("refused") === out.length ? EXIT.refused : EXIT.ok;
}

export async function main(argv: string[], deps: Deps = defaultDeps()): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    if (cmd === "keygen") return keygen(rest, deps);
    if (cmd === "run") return await run(rest, deps);
    if (cmd === "agent") return await agent(rest, deps);
    if (cmd === "config-schema") { deps.out(JSON.stringify(CONFIG_SCHEMA, null, 2)); return EXIT.ok; }
    if (cmd === "google-login") return await googleLogin(rest, deps);
    if (cmd === "policies") return await policiesCommand(rest, deps);
    if (cmd === "doctor" || cmd === "selftest") return await doctorCommand(rest, deps);
  } catch (e) {
    deps.err(String((e as Error).message ?? e));
    return EXIT.error;
  }
  deps.err(usage(deps.sources));
  return cmd === "help" || cmd === "--help" ? EXIT.ok : EXIT.usage;
}

// realpath: an npm-installed `collector` runs through a symlink in node_modules/.bin, whose path is not this file's.
const invokedPath = (p: string) => { try { return realpathSync(p); } catch { return resolve(p); } };
if (process.argv[1] && invokedPath(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  // The agent exits for real (75 after an update) even should a closed socket's handle linger.
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; if (process.argv[2] === "agent") process.exit(code); });
}
