// Ed25519 keys and signatures with Node's built-in crypto. sos-app stores the raw 32-byte public
// key (base64). Since 0.5.0 every request is signed v2 (method, path, time, nonce and the body's hash), and sos-app's
// answers are checked against the pinned channel keys (src/channel_keys.ts).

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { writeFileSync } from "node:fs";

export function generateKeyPair(): { privatePem: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return { privatePem, publicKey: rawPublicKeyB64(publicKey.export({ format: "jwk" }).x!) };
}

function rawPublicKeyB64(jwkX: string): string {
  return Buffer.from(jwkX, "base64url").toString("base64");
}

/** The raw public key, base64, as pasted into sos-app. */
export function publicKeyFromPrivate(privatePem: string): string {
  const pub = createPublicKey(createPrivateKey(privatePem));
  return rawPublicKeyB64(pub.export({ format: "jwk" }).x!);
}

/** Writes a new private key with mode 0600; refuses to overwrite an existing file. */
export function writeNewKey(path: string): { publicKey: string } {
  const { privatePem, publicKey } = generateKeyPair();
  writeFileSync(path, privatePem, { mode: 0o600, flag: "wx" });
  return { publicKey };
}

/** Base64 Ed25519 signature over the body bytes. */
export function signBody(privatePem: string, body: Uint8Array): string {
  const key = createPrivateKey(privatePem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("the collector key must be an Ed25519 private key (run `collector keygen`).");
  return sign(null, body, key).toString("base64");
}

// ── Signature v2 (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 10) ────────────────────────────────────────────────

export const SIG_V2 = "sagentix-sig/2";
export const CONNECT_V2 = "sagentix-connect/2";
export const ANSWER_V1 = "sagentix-answer/1";

export const sha256Hex = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
/** 32 random bytes, base64url: a nonce sos-app accepts once in ten minutes. */
export const newNonce = () => randomBytes(24).toString("base64url");

/** The headers of a v2-signed request: the signature covers the method, the path, the time, a fresh nonce and the
 *  SHA-256 of `signed` (the body, or a document's manifest). */
export function signRequest(privatePem: string, keyId: string, method: string, path: string, signed: Uint8Array, nowMs: number, nonce = newNonce()):
    { headers: Record<string, string>; nonce: string } {
  const ts = String(Math.floor(nowMs));
  const msg = `${SIG_V2}\n${method.toUpperCase()}\n${path}\n${ts}\n${nonce}\n${sha256Hex(signed)}`;
  return { nonce, headers: { "x-sagentix-key-id": keyId, "x-sagentix-sig-version": "2", "x-sagentix-ts": ts, "x-sagentix-nonce": nonce,
                             "x-sagentix-signature": signBody(privatePem, new TextEncoder().encode(msg)) } };
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** True when `sigB64` is the Ed25519 signature of `message` by one of the raw 32-byte public keys (base64). */
export function verifyWithAny(keys: readonly string[], sigB64: string, message: Uint8Array): boolean {
  const sig = Buffer.from(sigB64, "base64");
  if (sig.length !== 64) return false;
  return keys.some((k) => {
    const raw = Buffer.from(k, "base64");
    if (raw.length !== 32) return false;
    try { return verify(null, message, createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" }), sig); }
    catch { return false; }
  });
}

/** What sos-app's channel key signs for an answer: the path, this request's nonce, and the answer body's SHA-256. */
export const answerMessage = (path: string, nonce: string, body: string) => new TextEncoder().encode(`${ANSWER_V1}\n${path}\n${nonce}\n${sha256Hex(body)}`);

export type AnswerCheck = "valid" | "unsigned" | "invalid";

/** Is this answer signed by a pinned channel key, for this path and this request's nonce? */
export function checkAnswer(keys: readonly string[], path: string, nonce: string, body: string, sig: string | null): AnswerCheck {
  if (!sig) return "unsigned";
  return verifyWithAny(keys, sig, answerMessage(path, nonce, body)) ? "valid" : "invalid";
}
