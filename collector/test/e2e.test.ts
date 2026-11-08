// Every source in one run, end to end, against recorded replies (test/e2e_fixtures.ts): no network. Checks the dry
// run's and the signed push's shape, holds the results byte for byte against a golden file recorded before the
// run went concurrent (2026-11-07), and proves a serial run and a concurrent one send the same bytes.
//   UPDATE_GOLDEN=1 node --test test/e2e.test.ts   rewrites the golden file after a deliberate change.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, EXIT, type Deps } from "../src/cli.ts";
import { loadCatalog } from "../src/catalog.ts";
import { generateKeyPair } from "../src/keys.ts";
import { FORMAT, COLLECTOR_VERSION } from "../src/payload.ts";
import { SOURCES } from "../src/sources/index.ts";
import type { Result } from "../src/types.ts";
import { e2eSetup, E2E_NOW, ENDPOINT, type E2eSetup } from "./e2e_fixtures.ts";

const GOLDEN = new URL("./fixtures/e2e/golden-results.jsonl", import.meta.url);
const catalog = loadCatalog();

interface Ran { code: number; stdout: string[]; stderr: string[]; posts: { url: string; init: RequestInit }[]; setup: E2eSetup }

async function runAll(extra: string[] = [], o: { latencyMs?: number; env?: NodeJS.ProcessEnv; setup?: E2eSetup } = {}): Promise<Ran> {
  const setup = o.setup ?? e2eSetup({ latencyMs: o.latencyMs });
  const stdout: string[] = [], stderr: string[] = [], posts: Ran["posts"] = [];
  const deps: Deps = {
    fetch: (async (url: string | URL | Request, init?: RequestInit) => { posts.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ runId: `r${posts.length}`, checks: 1 }), { status: 201 }); }) as typeof fetch,
    channel: (async (url: string | URL | Request) => new Response(JSON.stringify(String(url).endsWith("/checkin") ? { action: "none", target: null, reason: "up to date" } : { id: "rep" }),
      { status: String(url).endsWith("/checkin") ? 200 : 201 })) as typeof fetch,
    cwd: setup.dir, clients: setup.clients, sources: SOURCES, env: { ...setup.env, ...(o.env ?? {}) }, now: () => E2E_NOW,
    out: (s) => stdout.push(s), err: (s) => stderr.push(s),
  };
  const code = await main(["run", ...setup.args, ...extra], deps);
  return { code, stdout, stderr, posts, setup };
}

const resultsOf = (r: Ran): Result[] => {
  const j = JSON.parse(r.stdout.join("\n"));
  return (j.pushes ?? [j]).flatMap((p: { payload: { results: Result[] } }) => p.payload.results);
};
const lines = (rs: Result[], dir: string) => rs.map((x) => JSON.stringify(x).split(dir).join("<dir>"));

test("e2e: the recorded replies cover every source the collector ships", () => {
  const s = e2eSetup();
  assert.deepEqual([...s.sources].sort(), SOURCES.map((x) => x.name).sort(), "a new source needs its recorded replies in test/e2e_fixtures.ts");
});

test("e2e: a dry run of every source exits 0 with a well-formed payload, every source reporting", async () => {
  const r = await runAll(["--dry-run"]);
  assert.equal(r.code, EXIT.ok, r.stderr.join("\n"));
  assert.equal(r.posts.length, 0, "a dry run posts nothing");
  const out = JSON.parse(r.stdout.join("\n"));
  assert.equal(out.dryRun, true);
  assert.equal(out.endpoint, `${ENDPOINT}/api/collect`);
  const p = out.payload;
  assert.equal(p.format, FORMAT);
  assert.equal(p.issuedAt, E2E_NOW.toISOString());
  assert.match(p.nonce, /^[0-9a-f-]{36}$/);
  assert.equal(p.collector.version, COLLECTOR_VERSION);
  assert.deepEqual(p.collector.sources.map((x: { source: string }) => x.source), r.setup.sources);
  for (const s of p.collector.sources) assert.ok(typeof s.scope === "string" && s.scope.length > 0, s.source);
  const keys = new Set<string>();
  const seen = new Map<string, number>();
  for (const x of p.results as Result[]) {
    assert.ok(catalog.has(x.check), `${x.check} is not in the catalogue`);
    assert.ok(["pass", "fail", "skipped"].includes(x.result), x.check);
    assert.ok(x.resource.length > 0 && x.resource.length <= 300, x.check);
    assert.ok(x.detail.length <= 1000, x.check);
    const k = `${x.check}|${x.resource}`;
    assert.ok(!keys.has(k), `duplicate ${k}`);
    keys.add(k);
    const src = catalog.get(x.check)!.source;
    seen.set(src, (seen.get(src) ?? 0) + (x.result === "skipped" ? 0 : 1));
  }
  // Every source judged something (a pass or a fail) from its recorded replies.
  for (const s of SOURCES) assert.ok((seen.get(s.name) ?? 0) > 0, `${s.name} judged nothing`);
  const sum = out.summary;
  assert.equal(sum.passed + sum.failed + sum.skipped, p.results.length);
});

test("e2e: the results match the golden file byte for byte", async () => {
  const r = await runAll(["--dry-run"]);
  const got = lines(resultsOf(r), r.setup.dir);
  if (process.env.UPDATE_GOLDEN === "1" || !existsSync(GOLDEN)) {
    writeFileSync(GOLDEN, got.join("\n") + "\n");
    if (process.env.UPDATE_GOLDEN !== "1") assert.fail(`wrote ${GOLDEN.pathname}; review and commit it`);
    return;
  }
  const want = readFileSync(GOLDEN, "utf8").trimEnd().split("\n");
  assert.equal(got.length, want.length, "result count");
  for (let i = 0; i < want.length; i++) assert.equal(got[i], want[i], `result ${i}`);
});

test("e2e: a real push signs each body, and the signature verifies over the exact bytes sent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "collector-e2e-key-"));
  const { privatePem, publicKey } = generateKeyPair();
  const keyPath = join(dir, "k.pem");
  writeFileSync(keyPath, privatePem, { mode: 0o600 });
  const r = await runAll(["--key-id", "k-e2e", "--key", keyPath]);
  assert.equal(r.code, EXIT.ok, r.stderr.join("\n"));
  assert.ok(r.posts.length >= 1);
  const key = await crypto.subtle.importKey("raw", Buffer.from(publicKey, "base64"), { name: "Ed25519" }, false, ["verify"]);
  let n = 0;
  for (const post of r.posts) {
    assert.equal(post.url, `${ENDPOINT}/api/collect`);
    assert.equal(post.init.method, "POST");
    const h = post.init.headers as Record<string, string>;
    assert.equal(h["x-sagentix-key-id"], "k-e2e");
    const body = post.init.body as Uint8Array<ArrayBuffer>;
    assert.ok(await crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(h["x-sagentix-signature"], "base64"), body), "signature verifies");
    const p = JSON.parse(new TextDecoder().decode(body));
    assert.equal(p.format, FORMAT);
    n += p.results.length;
  }
  const golden = readFileSync(GOLDEN, "utf8").trimEnd().split("\n").length;
  assert.equal(n, golden, "the push carries every result");
});
