// `collector rotate-key` (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 10): a new key pair for the same key id,
// registered in a request signed v2 by the current key; the key file replaced atomically, the old one kept as .previous.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.ts";
import { generateKeyPair, publicKeyFromPrivate } from "../src/keys.ts";
import { keyFilePath, prunePreviousKey, OVERLAP_MS } from "../src/rotate.ts";
import { capture, NOW, signedAnswers, TEST_CHANNEL, verifiesV2 } from "./helpers.ts";

function setup(over: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "collector-rotate-"));
  const old = generateKeyPair();
  writeFileSync(join(dir, "k.pem"), old.privatePem, { mode: 0o600 });
  const cfg = join(dir, "sagentix-collector.config.json");
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", keyFile: "k.pem", sources: { cloudflare: {} }, ...over }));
  return { dir, cfg, old, keyPath: join(dir, "k.pem") };
}
const answer = (status: number, body: unknown, seen: { url: string; init: RequestInit }[] = []) =>
  (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response(JSON.stringify(body), { status }); }) as unknown as typeof fetch;

test("rotate-key registers the new public key with the old key's v2 signature, then swaps the key file and keeps .previous", async () => {
  const s = setup();
  const seen: { url: string; init: RequestInit }[] = [];
  const c = capture({ channel: answer(201, { keyId: "k-1", rotatedAt: NOW.toISOString(), previousUntil: "2026-10-22T12:00:00.000Z" }, seen) });
  assert.equal(await main(["rotate-key", "--config", s.cfg], c.deps), 0, c.stderr.join("\n"));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "https://sos.example.test/api/collect/rotate");
  const body = seen[0].init.body as Uint8Array;
  assert.ok(verifiesV2(s.old.publicKey, seen[0].init.headers, "POST", "/api/collect/rotate", body), "signed by the current key");
  const sent = JSON.parse(new TextDecoder().decode(body));
  assert.equal(sent.format, "sagentix-key-rotate/1");
  const now = readFileSync(s.keyPath, "utf8");
  assert.equal(sent.publicKey, publicKeyFromPrivate(now), "the key file holds the key registered");
  assert.equal(c.stdout.at(-1), sent.publicKey);
  assert.equal(readFileSync(s.keyPath + ".previous", "utf8"), s.old.privatePem);
  if (process.platform !== "win32") for (const p of [s.keyPath, s.keyPath + ".previous"]) assert.equal(statSync(p).mode & 0o777, 0o600);
  assert.equal(existsSync(s.keyPath + ".next"), false);
  assert.match(c.stderr.join("\n"), /accepts it until 2026-10-22T12:00:00.000Z/);
  // The config is untouched: the key id stays.
  assert.equal(JSON.parse(readFileSync(s.cfg, "utf8")).keyId, "k-1");
});

test("rotate-key changes nothing when sos-app refuses, cannot be reached, or answers with a forged signature", async () => {
  const cases: [typeof fetch, number, RegExp][] = [
    [answer(409, { error: "This public key is already registered." }), 4, /refused the rotation \(HTTP 409\): This public key is already registered/],
    [answer(404, "nope"), 4, /does not take rotations yet/],
    [(async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch, 1, /failed: fetch failed; the key is unchanged/],
  ];
  for (const [channel, code, msg] of cases) {
    const s = setup();
    const c = capture({ channel });
    assert.equal(await main(["rotate-key", "--config", s.cfg], c.deps), code);
    assert.match(c.stderr.join("\n"), msg);
    assert.equal(readFileSync(s.keyPath, "utf8"), s.old.privatePem);
    assert.equal(existsSync(s.keyPath + ".previous"), false);
  }
  const s = setup();
  const forged = capture({ channel: undefined, fetch: signedAnswers(answer(201, { keyId: "k-1" }), generateKeyPair().privatePem) });
  assert.equal(await main(["rotate-key", "--config", s.cfg], forged.deps), 1);
  assert.match(forged.stderr.join("\n"), /does not verify against a pinned channel key; the key file is unchanged/);
  assert.equal(readFileSync(s.keyPath, "utf8"), s.old.privatePem);
});

test("rotate-key with an unsigned answer warns and still swaps (sos-app has no channel key yet)", async () => {
  const s = setup();
  const c = capture({ channel: undefined, fetch: signedAnswers(answer(201, { keyId: "k-1" }), null) });
  assert.equal(await main(["rotate-key", "--config", s.cfg], c.deps), 0);
  assert.match(c.stderr.join("\n"), /did not sign its answer/);
  assert.match(c.stderr.join("\n"), /accepts it until 7 days from now/);
  assert.notEqual(readFileSync(s.keyPath, "utf8"), s.old.privatePem);
});

test("rotate-key usage: a config, a key file, an https endpoint", async () => {
  const c = capture();
  assert.equal(await main(["rotate-key"], c.deps), 2);
  assert.equal(await main(["rotate-key", "--nope"], c.deps), 2);
  assert.equal(await main(["rotate-key", "--config", "/nowhere/x.json"], c.deps), 2);
  const noFile = setup({ keyFile: undefined });
  assert.equal(await main(["rotate-key", "--config", noFile.cfg], c.deps), 2);
  assert.match(c.stderr.join("\n"), /SAGENTIX_COLLECTOR_KEY is rotated by hand/);
  assert.equal(await main(["rotate-key", "--config", setup({ endpoint: "http://sos.example.test" }).cfg], c.deps), 2);
  assert.equal(await main(["rotate-key", "--config", setup({ keyFile: "missing.pem" }).cfg], c.deps), 1);
});

test("the key file is found beside the config; .previous goes once the overlap has passed", () => {
  const s = setup();
  assert.equal(keyFilePath(s.cfg, "k.pem"), s.keyPath);
  assert.equal(keyFilePath(s.cfg, "/abs/k.pem"), "/abs/k.pem");
  writeFileSync(s.keyPath + ".previous", "old", { mode: 0o600 });
  assert.equal(prunePreviousKey(s.keyPath, new Date()), false, "kept during the overlap");
  const old = new Date(Date.now() - OVERLAP_MS - 2 * 86_400_000);
  utimesSync(s.keyPath + ".previous", old, old);
  assert.equal(prunePreviousKey(s.keyPath, new Date()), true);
  assert.equal(existsSync(s.keyPath + ".previous"), false);
  assert.equal(prunePreviousKey(s.keyPath, new Date()), false, "nothing left");
  void TEST_CHANNEL;
});
