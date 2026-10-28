// The collector's channel to sos-app beside the evidence push (apps/sos-app/docs/COLLECTOR_CHANNEL.md): who this
// collector is (version, commit, runner), the signed POST every message uses, and the check-in that may name a
// signed update. Every connection goes out; nothing here listens, and nothing the server answers can make the
// collector run a command or change a configuration. The most it can do is have `sagentix-collector.ref` (or
// `.image`) written beside the config, which the generated script reads on its next start.

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { arch, platform, release } from "node:os";
import { dirname, join } from "node:path";
import { createPublicKey, verify } from "node:crypto";
import { fileURLToPath } from "node:url";
import { signBody } from "./keys.ts";
import { COLLECTOR_VERSION } from "./payload.ts";
import { RELEASE_PUBLIC_KEYS } from "./release_keys.ts";

export const CHECKIN_PATH = "/api/collect/checkin";
export const REPORT_PATH = "/api/collect/report";
export const CONNECT_PATH = "/api/collect/connect";
export const REF_FILE = "sagentix-collector.ref";
export const IMAGE_FILE = "sagentix-collector.image";
/** The agent's exit code after it wrote a signed update: the wrapper loop (Docker) or the service manager restarts it
 *  on the new image or commit (EX_TEMPFAIL, 75, from sysexits.h). `run` never exits with it. */
export const EXIT_UPDATE = 75;

export const RUNNERS = ["github", "server", "docker", "mac", "windows", "unknown"] as const;
export type Runner = (typeof RUNNERS)[number];
export type Mode = "run" | "agent";
/** Set by the agent on the `run` it starts, so that run's report says `mode: "agent"`. */
export const MODE_ENV = "SAGENTIX_COLLECTOR_MODE";

const HEX40 = /^[0-9a-f]{40}$/;
/** The only image a Docker runner accepts (section 3). */
export const RUNNER_IMAGE_RE = /^ghcr\.io\/sagentix-advisors-inc\/sagentix-collector-runner(:[A-Za-z0-9._-]{1,128})?@sha256:[0-9a-f]{64}$/;

const COLLECTOR_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
let commitCache: string | undefined;

/**
 * The commit of the collector's own checkout, or "unknown". Asked of git only when this file is tracked there, so a
 * copy inside node_modules of someone else's repository never reports that repository's commit. The runner image
 * has no .git; it may name its commit in SAGENTIX_COLLECTOR_COMMIT.
 */
export function collectorCommit(env: NodeJS.ProcessEnv = process.env): string {
  const given = env.SAGENTIX_COLLECTOR_COMMIT?.trim().toLowerCase();
  if (given && HEX40.test(given)) return given;
  if (commitCache !== undefined) return commitCache;
  commitCache = "unknown";
  try {
    const git = (...args: string[]) => spawnSync("git", ["-C", COLLECTOR_DIR, ...args], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] });
    if (git("ls-files", "--error-unmatch", "src/cli.ts").status === 0) {
      const head = git("rev-parse", "HEAD");
      const c = head.status === 0 ? head.stdout.trim() : "";
      if (HEX40.test(c)) commitCache = c;
    }
  } catch { /* no git: unknown */ }
  return commitCache;
}

export function collectorInfo(env: NodeJS.ProcessEnv = process.env) {
  return { version: COLLECTOR_VERSION, commit: collectorCommit(env) };
}

/** Where this run happens: SAGENTIX_RUNNER when the generated files set it, else what the machine shows. */
export function detectRunner(env: NodeJS.ProcessEnv, plat: NodeJS.Platform = platform(), hasDockerEnv: () => boolean = () => existsSync("/.dockerenv")): Runner {
  const given = env.SAGENTIX_RUNNER?.trim().toLowerCase();
  if (given && (RUNNERS as readonly string[]).includes(given)) return given as Runner;
  if (env.GITHUB_ACTIONS === "true") return "github";
  if (plat === "darwin") return "mac";
  if (plat === "win32") return "windows";
  if (hasDockerEnv()) return "docker";
  return "server";
}

export function modeOf(env: NodeJS.ProcessEnv): Mode {
  return env[MODE_ENV] === "agent" ? "agent" : "run";
}

export const osInfo = () => ({ platform: platform(), release: release(), arch: arch() });

/** What the collector needs to send anything on the channel. */
export interface Channel {
  /** The sos-app origin, e.g. https://app.example. */
  origin: string;
  keyId: string;
  pem: string;
  fetch: typeof fetch;
  /** The folder the report, pending report and ref files live in: the config's, else the working directory. */
  dir: string;
  runner: Runner;
  mode: Mode;
  env: NodeJS.ProcessEnv;
  now: () => Date;
}

/** POSTs exact bytes signed with the collector's key, as a push to /api/collect is. Throws on a network failure. */
export async function signedPost(c: Pick<Channel, "origin" | "keyId" | "pem" | "fetch">, path: string, body: Uint8Array<ArrayBuffer>): Promise<{ status: number; text: string }> {
  const res = await c.fetch(new URL(path, c.origin).toString(), {
    method: "POST",
    headers: { "content-type": "application/json", "x-sagentix-key-id": c.keyId, "x-sagentix-signature": signBody(c.pem, body) },
    body,
  });
  return { status: res.status, text: await res.text() };
}

/** Writes a file only its owner can read, also when it already existed with a wider mode. */
export function writePrivate(path: string, text: string): void {
  writeFileSync(path, text, { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* Windows: no POSIX modes */ }
}

// ── Check-in (section 3) ──────────────────────────────────────────────────────────────────────────

export interface Target { version: string; commit: string; image: string | null; date: string; signature: string }

/** The bytes the release key signs (section 4). */
export function releaseMessage(t: Omit<Target, "signature">): Uint8Array {
  return new TextEncoder().encode(`sagentix-collector-release/1\n${t.version}\n${t.commit}\n${t.image ?? ""}\n${t.date}`);
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** True when the target's signature verifies against one of the release public keys. */
export function verifyTarget(t: Target, keys: readonly string[] = RELEASE_PUBLIC_KEYS): boolean {
  const sig = Buffer.from(t.signature, "base64");
  if (sig.length !== 64) return false;
  const msg = releaseMessage(t);
  return keys.some((k) => {
    const raw = Buffer.from(k, "base64");
    if (raw.length !== 32) return false;
    try {
      return verify(null, msg, createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" }), sig);
    } catch { return false; }
  });
}

function targetOf(v: unknown): Target | string {
  if (typeof v !== "object" || v === null) return "the answer names no target";
  const t = v as Record<string, unknown>;
  for (const k of ["version", "commit", "date", "signature"] as const) if (typeof t[k] !== "string" || !t[k]) return `the target has no ${k}`;
  if (t.image !== null && t.image !== undefined && typeof t.image !== "string") return "the target's image is not a string";
  return { version: t.version as string, commit: t.commit as string, image: (t.image as string | null | undefined) ?? null, date: t.date as string, signature: t.signature as string };
}

export interface CheckinOutcome {
  action: "none" | "update" | "approval-needed" | "notify" | "failed";
  /** The file written for an update, when one was. */
  wrote?: string;
  /** For the report's warnings; also written to the log by the caller. */
  warnings: string[];
}

/**
 * POST /api/collect/checkin, and act on the answer. Never throws and never stops a run: a network failure, a 404
 * from an sos-app older than this collector or a malformed answer is a warning. `write: false` (a dry run) reads the
 * answer and writes nothing.
 */
export async function checkin(c: Channel, o: { write: boolean; keys?: readonly string[]; log: (s: string) => void }): Promise<CheckinOutcome> {
  const warnings: string[] = [];
  const warn = (s: string) => { warnings.push(s); o.log(`warning: check-in: ${s}`); };
  const body = new TextEncoder().encode(JSON.stringify({
    format: "sagentix-checkin/1", issuedAt: c.now().toISOString(), collector: collectorInfo(c.env),
    runner: c.runner, mode: c.mode, os: osInfo(), node: process.version,
  }));
  let res: { status: number; text: string };
  try { res = await signedPost(c, CHECKIN_PATH, body); } catch (e) { warn(`POST ${CHECKIN_PATH} failed: ${String((e as Error)?.message ?? e)}; the run goes on`); return { action: "failed", warnings }; }
  if (res.status !== 200) {
    warn(`HTTP ${res.status}${res.status === 404 ? " (this sos-app does not take check-ins yet)" : ""}; the run goes on`);
    return { action: "failed", warnings };
  }
  let a: { action?: unknown; target?: unknown; reason?: unknown };
  try { a = JSON.parse(res.text); } catch { warn("the answer is not JSON"); return { action: "failed", warnings }; }
  const reason = typeof a.reason === "string" ? a.reason.slice(0, 500) : "";
  switch (a.action) {
    case "none": return { action: "none", warnings };
    case "notify":
      o.log(`check-in: a newer collector is available, and this runner cannot update itself${reason ? `: ${reason}` : ""}`);
      return { action: "notify", warnings };
    case "approval-needed":
      o.log(`check-in: an update waits for your organization's approval in sos-app${reason ? `: ${reason}` : ""}`);
      return { action: "approval-needed", warnings };
    case "update": break;
    default: warn(`unknown action ${JSON.stringify(a.action)}; nothing done`); return { action: "failed", warnings };
  }
  const t = targetOf(a.target);
  if (typeof t === "string") { warn(`update refused: ${t}; nothing written`); return { action: "update", warnings }; }
  if (!HEX40.test(t.commit)) { warn(`update refused: target commit ${JSON.stringify(t.commit.slice(0, 60))} is not 40 hex; nothing written`); return { action: "update", warnings }; }
  if (!verifyTarget(t, o.keys)) { warn(`update to ${t.version} refused: its signature does not verify against a Sagentix release key; nothing written`); return { action: "update", warnings }; }
  const info = collectorInfo(c.env);
  if (t.commit === info.commit) return { action: "update", warnings };
  let file: string, text: string;
  if (c.runner === "docker") {
    if (!t.image || !RUNNER_IMAGE_RE.test(t.image)) { warn(`update to ${t.version} refused: the target names no runner image with a digest; nothing written`); return { action: "update", warnings }; }
    file = join(c.dir, IMAGE_FILE); text = `${t.image}\n`;
  } else if (c.runner === "server" || c.runner === "mac" || c.runner === "windows") {
    file = join(c.dir, REF_FILE); text = `${t.commit}\n${t.version}\n`;
  } else {
    warn(`update to ${t.version} offered, but a ${c.runner} runner pins its own commit; nothing written`);
    return { action: "update", warnings };
  }
  if (!o.write) { o.log(`check-in: signed update to ${t.version} (${t.commit}); dry run, so ${file} is not written`); return { action: "update", warnings }; }
  try { writePrivate(file, text); } catch (e) { warn(`cannot write ${file}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); return { action: "update", warnings }; }
  o.log(`check-in: signed update to ${t.version} (${t.commit}) written to ${file}; it takes effect on the next run${reason ? ` (${reason})` : ""}`);
  return { action: "update", wrote: file, warnings };
}
