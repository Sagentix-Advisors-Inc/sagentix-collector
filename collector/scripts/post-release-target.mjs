#!/usr/bin/env node
// Signs a collector release target and posts it to sos-app's channel (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section
// 14). Run by the `channel` job of .github/workflows/collector-release.yml, inside the protected GitHub environment
// `release`, after the npm and runner jobs:
//
//   node scripts/post-release-target.mjs --version 0.5.1 --commit <40 hex> [--image <image@sha256:…>] [--date YYYY-MM-DD]
//        [--fixes "<id> <id>…"] [--dry-run]
//
// Environment: COLLECTOR_RELEASE_SIGNING_KEY (Ed25519 private key, PKCS#8 DER, base64), COLLECTOR_RELEASE_POST_TOKEN
// (the bearer secret each sos-app environment holds), SOS_APP_ENDPOINTS (origins, space or comma separated). Optional
// NOTES_EN and NOTES_FR, the release notes.
//
// The key's public half must already be pinned in src/release_keys.ts, or the script stops before signing: a target
// the collector cannot verify is never posted. The private key is never printed. Each post carries a fresh nonce and
// timestamp, and is signed as a whole as well as the target inside it, so it cannot be replayed or altered.
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const POST_PATH = "/api/internal/collector/releases";
export const POST_FORMAT = "sagentix-collector-release-post/1";
const SIG_RE = /^[0-9a-f]{64}$/;
const VERSION_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]{1,40})?$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const IMAGE_RE = /^ghcr\.io\/sagentix-advisors-inc\/sagentix-collector-runner(:[\w.-]+)?@sha256:[0-9a-f]{64}$/;

export const releaseMessage = (r) => Buffer.from(`sagentix-collector-release/1\n${r.version}\n${r.commit}\n${r.image ?? ""}\n${r.date}`, "utf8");
export const postMessage = (ts, nonce, body) =>
  Buffer.from(`sagentix-release-post/1\n${POST_PATH}\n${ts}\n${nonce}\n${createHash("sha256").update(body).digest("hex")}`, "utf8");

/** The signature ids in a free text (the `fixes` input, Fixes-Signature trailers): 64 hex each; anything else refused. */
export function parseFixes(text) {
  const words = String(text ?? "").split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
  const bad = words.filter((w) => !SIG_RE.test(w));
  if (bad.length) throw new Error(`not a signature id (64 hex): ${bad.slice(0, 3).join(", ")}`);
  return [...new Set(words)];
}

export const rawPublicKey = (privateKey) => createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");

/** The post's body and headers for one release; `pinned` is the list of release public keys the collector trusts. */
export function buildPost({ keyB64, token, release, fixes = [], notes = null, pinned, now = Date.now(), nonce = randomBytes(24).toString("base64url") }) {
  if (!VERSION_RE.test(release.version ?? "")) throw new Error("version must look like 0.5.1");
  if (!COMMIT_RE.test(release.commit ?? "")) throw new Error("commit must be 40 hex");
  if (release.image !== null && !IMAGE_RE.test(release.image ?? "")) throw new Error("image must be the runner image with its digest, or empty");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(release.date ?? "")) throw new Error("date must be YYYY-MM-DD");
  const key = createPrivateKey({ key: Buffer.from(String(keyB64 ?? "").trim(), "base64"), format: "der", type: "pkcs8" });
  const pub = rawPublicKey(key);
  if (!pinned.includes(pub)) throw new Error(`this signing key's public key (${pub}) is not pinned in src/release_keys.ts; pin it in a collector release first`);
  const target = { version: release.version, commit: release.commit, image: release.image, date: release.date };
  target.signature = sign(null, releaseMessage(target), key).toString("base64");
  const body = JSON.stringify({ format: POST_FORMAT, release: target, fixes, ...(notes ? { notes } : {}) });
  const ts = String(now);
  return {
    body, target,
    headers: { "content-type": "application/json", authorization: `Bearer ${token}`, "x-sagentix-ts": ts, "x-sagentix-nonce": nonce,
               "x-sagentix-release-post-signature": sign(null, postMessage(ts, nonce, body), key).toString("base64") },
  };
}

async function main() {
  const { values: a } = parseArgs({ options: { version: { type: "string" }, commit: { type: "string" }, image: { type: "string", default: "" },
    date: { type: "string" }, fixes: { type: "string", default: "" }, "dry-run": { type: "boolean", default: false } }, strict: true });
  const { RELEASE_PUBLIC_KEYS } = await import(new URL("../src/release_keys.ts", import.meta.url).href);
  const env = process.env;
  const endpoints = String(env.SOS_APP_ENDPOINTS ?? "").split(/[\s,]+/).filter(Boolean);
  if (!env.COLLECTOR_RELEASE_SIGNING_KEY || !env.COLLECTOR_RELEASE_POST_TOKEN || !endpoints.length) {
    console.error("COLLECTOR_RELEASE_SIGNING_KEY, COLLECTOR_RELEASE_POST_TOKEN and SOS_APP_ENDPOINTS are required");
    process.exit(2);
  }
  const fixes = parseFixes(a.fixes);
  const notes = env.NOTES_EN && env.NOTES_FR ? { en: env.NOTES_EN, fr: env.NOTES_FR } : null;
  const release = { version: a.version, commit: a.commit, image: a.image ? a.image : null, date: a.date ?? new Date().toISOString().slice(0, 10) };
  let failed = 0;
  for (const origin of endpoints) {
    const url = new URL(POST_PATH, origin);
    if (url.protocol !== "https:") { console.error(`refusing ${origin}: https only`); failed++; continue; }
    // A fresh nonce and signature per environment: each sos-app keeps its own replay guard.
    const p = buildPost({ keyB64: env.COLLECTOR_RELEASE_SIGNING_KEY, token: env.COLLECTOR_RELEASE_POST_TOKEN, release, fixes, notes, pinned: RELEASE_PUBLIC_KEYS });
    if (a["dry-run"]) { console.log(`dry run: ${url.origin} ${p.body}`); continue; }
    const r = await fetch(url, { method: "POST", headers: p.headers, body: p.body });
    const text = (await r.text()).slice(0, 400);
    if (r.status === 201) console.log(`${url.origin}: ${release.version} is the candidate (${text})`);
    else if (r.status === 409 && /already published/.test(text)) console.log(`${url.origin}: ${release.version} was already published; nothing changed`);
    else { console.error(`${url.origin}: HTTP ${r.status} ${text}`); failed++; }
  }
  process.exit(failed ? 1 : 0);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main().catch((e) => { console.error(e.message); process.exit(1); });
