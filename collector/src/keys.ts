// Ed25519 keys and signatures with Node's built-in crypto. sos-app stores the raw 32-byte public
// key (base64) and verifies the signature over the exact bytes of the request body.

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
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
