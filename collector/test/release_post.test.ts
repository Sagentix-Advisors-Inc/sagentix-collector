// scripts/post-release-target.mjs: the release workflow's `channel` job signs the target and the post with the key from
// the protected `release` environment (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 14). The strings it signs must
// be exactly the ones sos-app verifies (apps/sos-app/src/routes/fleet.ts releasePostMessage, src/collector/release-keys.ts
// releaseMessage) and the one the collector verifies an update against (src/channel.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { fileURLToPath } from "node:url";
import { verifyTarget } from "../src/channel.ts";

const SCRIPT = fileURLToPath(new URL("../scripts/post-release-target.mjs", import.meta.url));
const mod = await import(new URL("../scripts/post-release-target.mjs", import.meta.url).href as string);

const pair = () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  return { b64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"), pub: mod.rawPublicKey(privateKey) as string };
};
const REL = { version: "0.5.1", commit: "a".repeat(40), image: null, date: "2026-11-08" };
const SIG = "3f9a1c0e7b2d4a6f8e1c3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5a";

test("release post: the target and the post are signed with the strings sos-app and the collector verify", () => {
  const k = pair();
  const p = mod.buildPost({ keyB64: k.b64, token: "tok", release: REL, fixes: [SIG], pinned: [k.pub], now: 1_762_560_000_000, nonce: "nonce-0123456789abcdef" });
  const body = JSON.parse(p.body);
  assert.equal(body.format, "sagentix-collector-release-post/1");
  assert.deepEqual(body.fixes, [SIG]);
  assert.equal(p.headers.authorization, "Bearer tok");
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(k.pub, "base64")]), format: "der", type: "spki" });
  assert.ok(verify(null, Buffer.from(`sagentix-collector-release/1\n0.5.1\n${"a".repeat(40)}\n\n2026-11-08`), pub, Buffer.from(body.release.signature, "base64")));
  const sha = createHash("sha256").update(p.body).digest("hex");
  assert.ok(verify(null, Buffer.from(`sagentix-release-post/1\n/api/internal/collector/releases\n1762560000000\nnonce-0123456789abcdef\n${sha}`), pub,
    Buffer.from(p.headers["x-sagentix-release-post-signature"], "base64")));
  // The collector takes the same target as an update.
  assert.ok(verifyTarget(body.release, [k.pub]));
});

test("release post: a key not pinned in release_keys.ts is refused before anything is signed; bad fields are refused", () => {
  const k = pair(), other = pair();
  assert.throws(() => mod.buildPost({ keyB64: k.b64, token: "t", release: REL, pinned: [other.pub] }), /not pinned/);
  assert.throws(() => mod.buildPost({ keyB64: k.b64, token: "t", release: { ...REL, commit: "nope" }, pinned: [k.pub] }), /40 hex/);
  assert.throws(() => mod.buildPost({ keyB64: k.b64, token: "t", release: { ...REL, image: "docker.io/x@sha256:1" }, pinned: [k.pub] }), /runner image/);
});

test("release post: fixes come from the input and Fixes-Signature trailers, 64 hex each, deduplicated", () => {
  assert.deepEqual(mod.parseFixes(`${SIG}, ${SIG.toUpperCase()}\n${"b".repeat(64)}`), [SIG, "b".repeat(64)]);
  assert.deepEqual(mod.parseFixes(""), []);
  assert.throws(() => mod.parseFixes("not-a-signature"), /64 hex/);
});

test("release post: without its secrets the script stops with exit 2 and prints no key", () => {
  let code = 0, err = "";
  try {
    execFileSync(process.execPath, [SCRIPT, "--version", "0.5.1", "--commit", "a".repeat(40)], { env: { PATH: process.env.PATH ?? "" }, stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) { code = (e as { status: number }).status; err = String((e as { stderr: Buffer }).stderr); }
  assert.equal(code, 2);
  assert.match(err, /COLLECTOR_RELEASE_SIGNING_KEY/);
});
