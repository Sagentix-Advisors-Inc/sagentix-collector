import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, publicKeyFromPrivate, signBody, writeNewKey } from "../src/keys.ts";

/** Verify the way sos-app does: WebCrypto, raw 32-byte public key, signature over the body bytes. */
async function serverVerify(publicKeyB64: string, signatureB64: string, body: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const raw = Buffer.from(publicKeyB64, "base64");
  assert.equal(raw.length, 32, "sos-app accepts only a raw 32-byte Ed25519 key");
  const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  const sig = Buffer.from(signatureB64, "base64");
  assert.equal(sig.length, 64);
  return crypto.subtle.verify({ name: "Ed25519" }, key, sig, body);
}

test("signature verifies with the raw public key, as sos-app checks it", async () => {
  const { privatePem, publicKey } = generateKeyPair();
  const body = new TextEncoder().encode(JSON.stringify({ format: "sagentix-fedramp-collect/1", nonce: "n" }));
  const sig = signBody(privatePem, body);
  assert.equal(await serverVerify(publicKey, sig, body), true);
  assert.equal(publicKeyFromPrivate(privatePem), publicKey);
});

test("a changed body does not verify", async () => {
  const { privatePem, publicKey } = generateKeyPair();
  const body = new TextEncoder().encode('{"a":1}');
  const sig = signBody(privatePem, body);
  assert.equal(await serverVerify(publicKey, sig, new TextEncoder().encode('{"a":2}')), false);
});

test("keygen writes a PKCS8 PEM with mode 0600 and refuses to overwrite it", () => {
  const dir = mkdtempSync(join(tmpdir(), "collector-key-"));
  const path = join(dir, "k.pem");
  const { publicKey } = writeNewKey(path);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  const pem = readFileSync(path, "utf8");
  assert.match(pem, /^-----BEGIN PRIVATE KEY-----/);
  assert.equal(publicKeyFromPrivate(pem), publicKey);
  assert.throws(() => writeNewKey(path), /EEXIST/);
});
