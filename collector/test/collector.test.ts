// The CLI end to end with fakes: payload contract, signature, catalogue, exit codes, v1.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, collectUrl, EXIT } from "../src/cli.ts";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../src/catalog.ts";
import { generateKeyPair } from "../src/keys.ts";
import { COLLECTOR_VERSION, FORMAT, MAX_RESULTS } from "../src/payload.ts";
import { SOURCES } from "../src/sources/index.ts";
import type { Source } from "../src/types.ts";
import { sdrValidator } from "../src/v1/payload.ts";
import { loadRules } from "../src/v1/rules.ts";
import { ACCOUNT, ZONE, capture, errBody, fakeCloudflare, missingOpa, NO_MAPPINGS } from "./helpers.ts";

const catalog = loadCatalog();
const dir = mkdtempSync(join(tmpdir(), "collector-test-"));
const { privatePem, publicKey } = generateKeyPair();
const keyPath = join(dir, "key.pem");
writeFileSync(keyPath, privatePem, { mode: 0o600 });

/** Checks the server catalogue lists that no collector source emits (pushed by something else). */
const SERVER_ONLY: string[] = [];

const base = ["run", "--endpoint", "https://sos.example.test", "--key-id", "k-1", "--key", keyPath, "--source", "cloudflare"];

async function verify(pub: string, sigB64: string, body: Uint8Array<ArrayBuffer>) {
  const key = await crypto.subtle.importKey("raw", Buffer.from(pub, "base64"), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(sigB64, "base64"), body);
}

// ── Catalogue ─────────────────────────────────────────────────────────────────────────────────────

test("every check a source can emit is in the catalogue, and every catalogue check is emittable", () => {
  const emits = new Set(SOURCES.flatMap((s) => s.emits));
  for (const id of emits) assert.ok(catalog.has(id), `${id} is emitted but not in ${DEFAULT_CATALOG_DIR}`);
  for (const id of catalog.keys()) assert.ok(emits.has(id) || SERVER_ONLY.includes(id), `${id} is in the catalogue but no source emits it`);
  for (const s of SOURCES) for (const id of s.emits) assert.equal(catalog.get(id)!.source, s.name, id);
});

test("catalogue entries link to hub controls and KSIs that exist, with strict coverage", { skip: NO_MAPPINGS }, () => {
  const hub = JSON.parse(readFileSync(new URL("../../apps/sos-app/src/data/frameworks.json", import.meta.url), "utf8")).hub.controls;
  const ksis = new Set(loadRules().ksis.map((k) => k.id));
  for (const c of catalog.values()) {
    // Evidence for something. A Prowler check without Prowler's own SP 800-53 mapping counts toward its KSIs only.
    assert.ok(c.hub!.length || c.ksis!.length, c.id);
    for (const h of c.hub!) assert.ok(hub[h], `${c.id}: ${h} is not a hub control`);
    for (const k of c.ksis!) assert.ok(ksis.has(k), `${c.id}: ${k} is not a KSI`);
    assert.ok(c.coverage === "full" || c.coverage === "partial", c.id);
    assert.ok(c.title && c.scope && c.evidenceType, c.id);
  }
  // sos-app's own tests rely on these.
  assert.equal(catalog.get("cloudflare.dnssec")!.coverage, "full");
  assert.equal(catalog.get("cloudflare.min_tls_version")!.coverage, "partial");
  assert.equal(catalog.get("cloudflare.hsts")!.coverage, "partial");
});

test("source options do not collide with each other or with the CLI's own", async () => {
  const c = capture();
  // parseArgs would throw on a collision before anything runs; a dry run proves the option table builds.
  assert.equal(await main([...base, "--dry-run"], c.deps), EXIT.ok, c.stderr.join("\n"));
  const names = SOURCES.flatMap((s) => Object.keys(s.options));
  assert.equal(new Set(names).size, names.length);
});

test("a check id the catalogue does not know is refused, the rest still go", async () => {
  const rogue: Source = {
    name: "cloudflare", options: {}, emits: ["cloudflare.dnssec"], describe: () => "test",
    run: async () => [
      { check: "cloudflare.nope", resource: "zone x", result: "pass", detail: "?" },
      { check: "cloudflare.dnssec", resource: "zone x", result: "pass", detail: "active" },
    ],
  };
  const c = capture({ sources: [rogue] });
  assert.equal(await main([...base, "--dry-run"], c.deps), EXIT.ok);
  const report = JSON.parse(c.stdout.join("\n"));
  assert.deepEqual(report.payload.results.map((r: { check: string }) => r.check), ["cloudflare.dnssec"]);
  assert.match(c.stderr.join("\n"), /refused \(not in the catalogue.*cloudflare\.nope/);
});

// ── Payload and signature ─────────────────────────────────────────────────────────────────────────

test("the payload matches sos-app's sagentix-collect/3 contract", async () => {
  const c = capture();
  assert.equal(await main([...base, "--dry-run"], c.deps), EXIT.ok, c.stderr.join("\n"));
  const { payload } = JSON.parse(c.stdout.join("\n"));
  assert.deepEqual(Object.keys(payload).sort(), ["collector", "format", "issuedAt", "nonce", "results"]);
  assert.equal(payload.format, FORMAT);
  assert.equal(payload.format, "sagentix-collect/3");
  assert.equal(payload.issuedAt, "2026-10-15T12:00:00.000Z");
  assert.match(payload.nonce, /^[0-9a-f-]{36}$/);
  assert.equal(payload.collector.version, COLLECTOR_VERSION);
  assert.deepEqual(payload.collector.sources, [{ source: "cloudflare", scope: "accounts of the zones read / every zone the token lists" }]);
  assert.ok(payload.results.length >= 1 && payload.results.length <= MAX_RESULTS);
  const keys = new Set<string>();
  for (const r of payload.results) {
    // The four version 2 fields always; format 3's provenance fields only when a source knew them (sos-app migration 0040).
    const READ = ["apiError", "complete", "expected", "itemsRead", "method", "observed", "observedAt", "pagesRead"];
    assert.deepEqual(Object.keys(r).filter((k) => !READ.includes(k)).sort(), ["check", "detail", "resource", "result"]);
    assert.ok(catalog.has(r.check), r.check);
    assert.ok(["pass", "fail", "skipped"].includes(r.result));
    assert.ok(r.detail.length <= 1000 && r.resource.length <= 300 && r.resource.length > 0);
    keys.add(`${r.check}|${r.resource}`);
  }
  assert.equal(keys.size, payload.results.length, "(check, resource) is unique");
  assert.ok(payload.results.some((r: { check: string; resource: string }) => r.check === "cloudflare.dnssec" && r.resource === "zone example.com"));
});

test("the scope names --account and --zone when given", async () => {
  const c = capture();
  await main([...base, "--dry-run", "--account", ACCOUNT, "--zone", ZONE], c.deps);
  assert.equal(JSON.parse(c.stdout.join("\n")).payload.collector.sources[0].scope, `account ${ACCOUNT} / zones ${ZONE}`);
});

test("a run POSTs to /api/collect with the key id and a signature over the exact body bytes", async () => {
  const c = capture();
  assert.equal(await main(base, c.deps), EXIT.ok, c.stderr.join("\n"));
  assert.equal(c.posts.length, 1);
  const { url, init } = c.posts[0];
  assert.equal(url, "https://sos.example.test/api/collect");
  assert.equal(init.method, "POST");
  const h = init.headers as Record<string, string>;
  assert.equal(h["content-type"], "application/json");
  assert.equal(h["x-sagentix-key-id"], "k-1");
  const body = init.body as Uint8Array<ArrayBuffer>;
  assert.ok(await verify(publicKey, h["x-sagentix-signature"], body));
  // One byte off and it no longer verifies.
  const tampered = new Uint8Array(body); tampered[tampered.length - 2] ^= 1;
  assert.equal(await verify(publicKey, h["x-sagentix-signature"], tampered), false);
  assert.equal(JSON.parse(new TextDecoder().decode(body)).format, "sagentix-collect/3");
});

test("--out keeps the exact signed bytes, and they verify", async () => {
  const out = join(dir, "copy.json");
  const c = capture();
  assert.equal(await main([...base, "--out", out], c.deps), EXIT.ok);
  const copy = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(copy.keyId, "k-1");
  assert.equal(copy.publicKey, publicKey);
  const sent = new TextDecoder().decode(c.posts[0].init.body as Uint8Array);
  assert.equal(copy.body, sent);
  assert.ok(await verify(copy.publicKey, copy.signature, new TextEncoder().encode(copy.body)));
});

test("the key may come from SAGENTIX_COLLECTOR_KEY", async () => {
  const c = capture({ env: { SAGENTIX_COLLECTOR_KEY: privatePem } });
  const args = base.filter((a, i) => a !== "--key" && base[i - 1] !== "--key");
  assert.equal(await main(args, c.deps), EXIT.ok, c.stderr.join("\n"));
  const h = c.posts[0].init.headers as Record<string, string>;
  assert.ok(await verify(publicKey, h["x-sagentix-signature"], c.posts[0].init.body as Uint8Array<ArrayBuffer>));
});

// ── Exit codes ────────────────────────────────────────────────────────────────────────────────────

test("dry-run prints the payload and posts nothing, even without a key", async () => {
  const c = capture();
  assert.equal(await main(["run", "--endpoint", "https://sos.example.test", "--source", "cloudflare", "--dry-run"], c.deps), EXIT.ok, c.stderr.join("\n"));
  assert.equal(c.posts.length, 0);
  const report = JSON.parse(c.stdout.join("\n"));
  assert.equal(report.dryRun, true);
  assert.equal(report.endpoint, "https://sos.example.test/api/collect");
  assert.equal(report.headers["x-sagentix-signature"], null);
});

test("a replay (409) exits 4 and prints the server's message", async () => {
  const c = capture({}, { status: 409, body: { error: "This payload was already received." } });
  assert.equal(await main(base, c.deps), EXIT.refused);
  assert.match(c.stderr.join("\n"), /HTTP 409.*already received/);
});

test("a bad signature or revoked key (401) exits 4 and prints the server's message", async () => {
  const c = capture({}, { status: 401, body: { error: "Signature not accepted." } });
  assert.equal(await main(base, c.deps), EXIT.refused);
  assert.match(c.stderr.join("\n"), /HTTP 401.*Signature not accepted/);
});

test("an unknown check (400) exits 4 with the server's reason", async () => {
  const c = capture({}, { status: 400, body: { error: "cloudflare.x is not a check sos-app knows; update the collector or sos-app." } });
  assert.equal(await main(base, c.deps), EXIT.refused);
  assert.match(c.stderr.join("\n"), /HTTP 400.*not a check sos-app knows/);
});

test("nothing but skipped results: exit 3, nothing posted", async () => {
  const c = capture({ clients: { cloudflare: null, opa: missingOpa } });
  assert.equal(await main(base, c.deps), EXIT.nothing);
  assert.equal(c.posts.length, 0);
  assert.match(c.stderr.join("\n"), /every check was skipped/);
});

test("a token without any read permission: exit 3", async () => {
  const c = capture({ clients: { cloudflare: { get: async () => errBody(403) }, opa: missingOpa } });
  assert.equal(await main(base, c.deps), EXIT.nothing);
  assert.equal(c.posts.length, 0);
});

test("usage errors exit 2", async () => {
  const cases: string[][] = [
    ["run", "--endpoint", "https://a.test", "--dry-run"],                                   // no --source
    ["run", "--endpoint", "https://a.test", "--source", "no-such-source", "--dry-run"],    // unknown source
    ["run", "--source", "cloudflare", "--dry-run"],                                        // no endpoint
    ["run", "--endpoint", "http://a.test", "--source", "cloudflare", "--dry-run"],         // not https
    ["run", "--endpoint", "https://a.test", "--source", "cloudflare"],                      // no key, not dry
    ["run", "--endpoint", "https://a.test", "--source", "cloudflare", "--bogus", "--dry-run"], // unknown flag
    ["frobnicate"],
  ];
  for (const args of cases) {
    const c = capture();
    assert.equal(await main(args, c.deps), EXIT.usage, args.join(" "));
    assert.equal(c.posts.length, 0);
  }
});

test("endpoint must be https except on localhost", () => {
  assert.equal(collectUrl("https://a.test"), "https://a.test/api/collect");
  assert.equal(collectUrl("http://localhost:8787"), "http://localhost:8787/api/collect");
  assert.equal(collectUrl("https://a.test/custom/path"), "https://a.test/custom/path");
  assert.throws(() => collectUrl("http://a.test"));
});

// ── v1 (FedRAMP target) ───────────────────────────────────────────────────────────────────────────

test("--fedramp-target sends the v1 payload to /api/fedramp/collect with a valid SDR", async () => {
  const c = capture();
  assert.equal(await main([...base, "--fedramp-target", "t-1", "--class", "B"], c.deps), EXIT.ok, c.stderr.join("\n"));
  assert.equal(c.posts[0].url, "https://sos.example.test/api/fedramp/collect");
  const p = JSON.parse(new TextDecoder().decode(c.posts[0].init.body as Uint8Array));
  assert.equal(p.format, "sagentix-fedramp-collect/1");
  assert.deepEqual(sdrValidator(loadRules())(p.sdr), []);
  assert.deepEqual(p.results.map((r: { ksiId: string }) => r.ksiId).sort(), ["KSI-CMT-LMC", "KSI-CNA-RNT", "KSI-IAM-APM", "KSI-SVC-SIN", "KSI-SVC-VRI"]);
  const st = Object.fromEntries(p.results.map((r: { ksiId: string; status: string }) => [r.ksiId, r.status]));
  assert.equal(st["KSI-SVC-SIN"], "Implemented");
  assert.equal(st["KSI-IAM-APM"], "Partially Implemented", "2FA cannot show phishing resistance");
});

test("v1: a KSI outside the class is omitted (class A has no KSI-SVC-VRI); weak TLS is Partially Implemented", async () => {
  const c = capture({ clients: { cloudflare: fakeCloudflare({ [`/zones/${ZONE}/settings/min_tls_version`]: { status: 200, body: { success: true, result: { id: "min_tls_version", value: "1.0" } } } }), opa: missingOpa } });
  assert.equal(await main([...base, "--fedramp-target", "t-1", "--class", "A", "--dry-run"], c.deps), EXIT.ok, c.stderr.join("\n"));
  const r = JSON.parse(c.stdout.join("\n"));
  const ids = r.payload.results.map((x: { ksiId: string }) => x.ksiId);
  assert.ok(!ids.includes("KSI-SVC-VRI"));
  assert.equal(r.payload.results.find((x: { ksiId: string }) => x.ksiId === "KSI-SVC-SIN").status, "Partially Implemented");
});
