#!/usr/bin/env node
// Sagentix evidence collector. Reads the customer's systems read-only, runs checks, signs the result
// with an Ed25519 key and pushes it OUT to sos-app. It never listens for connections, and sos-app never
// holds the customer's credentials.
//
//   collector keygen [--out <path>]
//   collector run --endpoint <url> --key-id <id> [--key <pem> | env SAGENTIX_COLLECTOR_KEY]
//                 --source cloudflare[,...] [source options] [--catalog <dir>] [--dry-run] [--out <file>]
//                 [--fedramp-target <id> [--class A|B|C|D]]
//
// Exit codes: 0 sent (or dry run), 1 error (bad key, network), 2 usage, 3 nothing to send,
// 4 sos-app refused the push (its message is printed).

import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "./catalog.ts";
import { publicKeyFromPrivate, signBody, writeNewKey } from "./keys.ts";
import { MAX_RESULTS, buildPayload, splitResults, vet } from "./payload.ts";
import { SOURCES } from "./sources/index.ts";
import type { Clients, OptionValue, Result, Source } from "./types.ts";
import { V1_COLLECT_PATH, v1Payload } from "./v1/index.ts";
import { CLASSES, type FedClass } from "./v1/rules.ts";

export const COLLECT_PATH = "/api/collect";
export const KEY_ENV = "SAGENTIX_COLLECTOR_KEY";
export const EXIT = { ok: 0, error: 1, usage: 2, nothing: 3, refused: 4 } as const;

export interface Deps {
  /** Used only for the POST to sos-app. */
  fetch: typeof fetch;
  /** Clients the sources use; a source builds its own from env when one is missing. */
  clients: Clients;
  sources: readonly Source[];
  env: NodeJS.ProcessEnv;
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
} as const;

function usage(sources: readonly Source[]): string {
  const opts = sources.flatMap((s) => Object.entries(s.options).map(([n, o]) =>
    `    --${n}${o.type === "string" ? " <value>" : ""}${o.multiple ? " (repeatable)" : ""}  [${s.name}] ${o.help}`));
  return `usage:
  collector keygen [--out sagentix-collector.pem]
  collector run --endpoint <url> --key-id <id> [--key <pem file>] --source ${sources.map((s) => s.name).join("|")}[,...]
                [source options] [--catalog <checks dir>] [--dry-run] [--out <file>]
                [--fedramp-target <id> [--class A|B|C|D] [--cpo-uri <url>]]
  The private key may come from ${KEY_ENV} (PEM text) instead of --key.
  Source options:
${opts.join("\n")}
  Exit codes: 0 sent or dry run, 1 error, 2 usage, 3 nothing to send, 4 sos-app refused the push.`;
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
    deps.err(`Private key written to ${path} (mode 0600). Keep it in your CI secret store; never send it to anyone.`);
    deps.err("Register this public key in sos-app (Evidence > Collector keys):");
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

export async function run(argv: string[], deps: Deps): Promise<number> {
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
  const dry = values["dry-run"] === true;
  const v1Target = typeof values["fedramp-target"] === "string" ? values["fedramp-target"] : undefined;

  const names = ((values.source as string[] | undefined) ?? []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);
  if (!names.length) { deps.err(`--source is required (${deps.sources.map((s) => s.name).join(", ")}).`); return EXIT.usage; }
  const chosen: Source[] = [];
  for (const n of [...new Set(names)]) {
    const s = deps.sources.find((x) => x.name === n);
    if (!s) { deps.err(`unknown source ${n}; known: ${deps.sources.map((x) => x.name).join(", ")}.`); return EXIT.usage; }
    chosen.push(s);
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

  // Run every chosen source, then keep only what the server will accept.
  const now = deps.now();
  const raw: Result[] = [];
  for (const s of chosen) {
    const got = await s.run({ opts: values, env: deps.env, clients: deps.clients, now, warn: deps.err });
    const stray = got.filter((r) => !s.emits.includes(r.check)).map((r) => r.check);
    if (stray.length) deps.err(`warning: source ${s.name} emitted checks it does not declare: ${[...new Set(stray)].join(", ")}`);
    raw.push(...got);
  }
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
    if (!dry && !v1.payload.results.length) { deps.err("Nothing to send: no KSI had a check that passed or failed."); return EXIT.nothing; }
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
    return EXIT.ok;
  }

  if (!results.some((r) => r.result !== "skipped")) {
    deps.err("Nothing to send: every check was skipped. Run with --dry-run to see why.");
    for (const s of skipped.slice(0, 50)) deps.err(`  skipped ${s.check} [${s.resource}]: ${s.detail}`);
    return EXIT.nothing;
  }
  for (const s of skipped) deps.err(`skipped ${s.check} [${s.resource}]: ${s.detail}`);

  for (const [i, p] of pushes.entries()) {
    const which = pushes.length > 1 ? ` (push ${i + 1} of ${pushes.length}${i ? `; pushes 1 to ${i} were accepted` : ""})` : "";
    let res: Response;
    try {
      res = await deps.fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-sagentix-key-id": keyId!, "x-sagentix-signature": p.signature! }, body: p.body });
    } catch (e) {
      deps.err(`POST ${url} failed${which}: ${String(e)}`);
      return EXIT.error;
    }
    const text = await res.text();
    if (!res.ok) {
      deps.err(`sos-app refused the push${which} (HTTP ${res.status}): ${serverMessage(text)}`);
      return EXIT.refused;
    }
    deps.out(text);
  }
  return EXIT.ok;
}

export async function main(argv: string[], deps: Deps = defaultDeps()): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    if (cmd === "keygen") return keygen(rest, deps);
    if (cmd === "run") return await run(rest, deps);
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
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
