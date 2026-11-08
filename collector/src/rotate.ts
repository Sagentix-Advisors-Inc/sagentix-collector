// `collector rotate-key --config <file>` (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 10). Makes a new Ed25519 key
// pair and registers its public key with sos-app in a request signed (v2) by the current key. The key id stays the same,
// so the vault (its Keychain item and its sealed deliveries are named by the key id), the check-ins, the settings and the
// agents list stay with it; only the key material changes. sos-app keeps accepting the previous public key for 7 days,
// so a run already going (or an agent still connected) finishes, then retires it; an owner may retire it sooner.
//
// On disk: the current key goes to <keyFile>.previous (0600), the new key is written to <keyFile>.next and renamed over
// <keyFile>, so the key file is never half-written. A run deletes <keyFile>.previous once the overlap has passed.

import { existsSync, readFileSync, renameSync, statSync, unlinkSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { parseArgs } from "node:util";
import { ROTATE_PATH, signedPost, writePrivate } from "./channel.ts";
import { loadConfig } from "./config.ts";
import { generateKeyPair } from "./keys.ts";
import type { Deps } from "./cli.ts";

export const ROTATE_FORMAT = "sagentix-key-rotate/1";
export const OVERLAP_MS = 7 * 86_400_000;
export const PREVIOUS_SUFFIX = ".previous";

/** Where the config's keyFile is: beside the config when relative (the generated scripts run there), else as given. */
export function keyFilePath(configPath: string, keyFile: string): string {
  if (isAbsolute(keyFile)) return keyFile;
  const besideConfig = resolve(dirname(configPath), keyFile);
  return existsSync(besideConfig) ? besideConfig : resolve(keyFile);
}

/** Deletes <keyFile>.previous once the overlap (and a day's margin) has passed. Never throws. */
export function prunePreviousKey(keyPath: string, now: Date): boolean {
  const prev = keyPath + PREVIOUS_SUFFIX;
  try {
    if (existsSync(prev) && now.getTime() - statSync(prev).mtimeMs > OVERLAP_MS + 86_400_000) { unlinkSync(prev); return true; }
  } catch { /* left for the next run */ }
  return false;
}

export async function rotateKey(argv: string[], deps: Deps): Promise<number> {
  let config: string | undefined;
  try { ({ values: { config } } = parseArgs({ args: argv, options: { config: { type: "string" } }, strict: true }) as { values: { config?: string } }); }
  catch (e) { deps.err(`${(e as Error).message}\nusage: collector rotate-key --config collector.config.json`); return 2; }
  if (!config) { deps.err("usage: collector rotate-key --config collector.config.json"); return 2; }
  const configPath = resolve(config);
  const c = loadConfig(configPath, deps.sources);
  if ("problems" in c) { deps.err(`${config} is not a valid collector config:\n  ${c.problems.join("\n  ")}`); return 2; }
  const keyId = c.values["key-id"], keyFile = c.values.key;
  if (typeof keyId !== "string" || typeof keyFile !== "string") {
    deps.err("rotate-key needs keyId and keyFile in the config. A key given in SAGENTIX_COLLECTOR_KEY is rotated by hand: make a new one with `collector keygen`, register it in sos-app, then revoke the old one.");
    return 2;
  }
  let origin: string;
  try {
    const u = new URL(c.values.endpoint as string);
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(local && u.protocol === "http:")) throw new Error("the endpoint must be https (http only for localhost).");
    origin = u.origin;
  } catch (e) { deps.err((e as Error).message); return 2; }
  const keyPath = keyFilePath(configPath, keyFile);
  let pem: string;
  try { pem = readFileSync(keyPath, "utf8"); } catch (e) { deps.err(`cannot read keyFile ${keyPath}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); return 1; }

  const next = generateKeyPair();
  const body = new TextEncoder().encode(JSON.stringify({ format: ROTATE_FORMAT, issuedAt: deps.now().toISOString(), publicKey: next.publicKey }));
  let res: Awaited<ReturnType<typeof signedPost>>;
  try {
    res = await signedPost({ origin, keyId, pem, fetch: deps.channel ?? deps.fetch, now: deps.now, ...(deps.channelKeys ? { answerKeys: deps.channelKeys } : {}) }, ROTATE_PATH, body);
  } catch (e) { deps.err(`POST ${ROTATE_PATH} failed: ${String((e as Error)?.message ?? e)}; the key is unchanged.`); return 1; }
  if (res.status !== 201) {
    let msg = res.text;
    try { msg = (JSON.parse(res.text) as { error?: string }).error ?? res.text; } catch { /* not JSON */ }
    deps.err(`sos-app refused the rotation (HTTP ${res.status}): ${msg.slice(0, 500)}${res.status === 404 ? " (this sos-app does not take rotations yet)" : ""}; the key is unchanged.`);
    return 4;
  }
  // The answer names nothing to act on beyond "accepted", but a forged one would leave this collector on a key sos-app
  // never saw: refuse to switch when the channel signature does not verify (the old key keeps working; check the key's
  // overlap in sos-app, Evidence > Collector keys, and retire it there if this rotation was not yours).
  if (res.answer === "invalid") {
    deps.err("sos-app's answer to the rotation does not verify against a pinned channel key; the key file is unchanged. Check the key in sos-app (Evidence > Collector keys).");
    return 1;
  }
  if (res.answer === "unsigned") deps.err("warning: sos-app did not sign its answer (its channel key is not set up yet).");
  let until = "";
  try { until = String((JSON.parse(res.text) as { previousUntil?: unknown }).previousUntil ?? ""); } catch { /* not JSON */ }
  const prev = keyPath + PREVIOUS_SUFFIX, tmp = keyPath + ".next";
  try {
    writePrivate(prev, pem);
    writePrivate(tmp, next.privatePem);
    renameSync(tmp, keyPath);
  } catch (e) {
    deps.err(`sos-app took the new key, but writing it failed (${(e as NodeJS.ErrnoException).code ?? String(e)}). Its private key is in ${tmp} if that was written; `
      + `move it over ${keyPath} before ${until || "the overlap ends (7 days)"}, or revoke the key in sos-app and register a new one.`);
    return 1;
  }
  deps.err(`Key ${keyId} rotated: the new private key is in ${keyPath} (mode 0600); the previous one is kept in ${prev} and sos-app accepts it until ${until || "7 days from now"}, `
    + "then retires it (an owner may do that sooner in sos-app). The key id, the vault and the settings are unchanged; a running agent reconnects with the new key on its next start.");
  deps.out(next.publicKey);
  return 0;
}
