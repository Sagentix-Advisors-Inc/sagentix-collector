// Sealing as sos-app's page does it, with WebCrypto only (apps/sos-app/frontend/src/environment/seal.ts), for the tests.
import { sealInfo, type Kind, type SealedValue } from "../src/vault.ts";

const b64url = (b: ArrayBuffer | Uint8Array) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("base64url");

/** Seals as sos-app's page does, with WebCrypto only (apps/sos-app/frontend/src/environment/seal.ts). */
export async function sealInBrowser(collectorPub: string, keyId: string, name: string, kind: Kind, value: string, bind: Record<string, string> = {}): Promise<SealedValue> {
  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const peer = await crypto.subtle.importKey("raw", Buffer.from(collectorPub, "base64url"), { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: peer }, eph.privateKey, 256);
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey) as ArrayBuffer);
  const info = new Uint8Array(sealInfo(keyId, name, kind, bind));
  const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array([...epk, ...Buffer.from(collectorPub, "base64url")]), info },
                                            hk, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: info }, aes, new TextEncoder().encode(value));
  return { name, kind, bind, epk: b64url(epk), iv: Buffer.from(iv).toString("base64"), data: Buffer.from(data).toString("base64") };
}

