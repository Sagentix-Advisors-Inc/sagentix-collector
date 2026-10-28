// The collector channel (apps/sos-app/docs/COLLECTOR_CHANNEL.md): the guard around each source, the run report and
// its scrubbing, the check-in and signed updates, and the agent's protocol. Fakes only, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, EXIT } from "../src/cli.ts";
import { generateKeyPair } from "../src/keys.ts";
import { COLLECTOR_VERSION } from "../src/payload.ts";
import { IMAGE_FILE, REF_FILE, checkin, detectRunner, releaseMessage, verifyTarget, type Channel, type Target } from "../src/channel.ts";
import { MAX_LOG_LINES, PENDING_FILE, REPORT_FILE, RunRecorder, buildReport, envSecrets, scrubText, templatePath, trimReport } from "../src/report.ts";
import { AgentSession, BACKOFF_MAX_MS, PING_MS, agent, connectUrl, nextBackoff, type AgentIo, type ChildRun, type SocketLike } from "../src/agent.ts";
import { RELEASE_PUBLIC_KEYS } from "../src/release_keys.ts";
import type { Source } from "../src/types.ts";
import { capture, fakeCloudflare, missingOpa, NOW } from "./helpers.ts";
import { cloudflare } from "../src/sources/cloudflare.ts";

const dir = mkdtempSync(join(tmpdir(), "collector-channel-"));
const { privatePem, publicKey } = generateKeyPair();
const keyPath = join(dir, "key.pem");
writeFileSync(keyPath, privatePem, { mode: 0o600 });
const base = ["run", "--endpoint", "https://sos.example.test", "--key-id", "k-1", "--key", keyPath];

async function verify(pub: string, sigB64: string, body: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", Buffer.from(pub, "base64"), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(sigB64, "base64"), new Uint8Array(body));
}
const bodyOf = (p: { init: RequestInit }) => JSON.parse(new TextDecoder().decode(p.init.body as Uint8Array));
const reportsOf = (c: { channel: { url: string; init: RequestInit }[] }) => c.channel.filter((p) => p.url.endsWith("/api/collect/report"));

/** A source that throws partway, after a warning. */
const broken: Source = {
  name: "okta", options: {}, emits: ["okta.mfa_enrollment", "okta.password_policy"], describe: () => "test",
  run: async (ctx) => { ctx.warn("okta: reading the org"); throw new Error("Cannot read properties of undefined (reading 'id')"); },
};

// ── 1. The run never stops ────────────────────────────────────────────────────────────────────────

test("a throwing source gives one skipped result per declared check; the rest is pushed, the report sent, exit 1", async () => {
  const c = capture({ sources: [broken, cloudflare], clients: { cloudflare: fakeCloudflare(), opa: missingOpa } });
  // The check ids must exist in the catalogue for the skipped results to travel; use the real Okta ones.
  const { okta } = await import("../src/sources/okta.ts");
  broken.emits = okta.emits.slice(0, 3);
  const code = await main([...base, "--source", "okta,cloudflare"], c.deps);
  assert.equal(code, EXIT.error, c.stderr.join("\n"));
  assert.equal(c.posts.length, 1, "the push still went");
  const results = bodyOf(c.posts[0]).results as { check: string; result: string; detail: string }[];
  const mine = results.filter((r) => r.check.startsWith("okta."));
  assert.equal(mine.length, 3);
  for (const r of mine) {
    assert.equal(r.result, "skipped");
    assert.equal(r.detail, "collector error in okta: Cannot read properties of undefined (reading 'id')");
  }
  assert.ok(results.some((r) => r.check.startsWith("cloudflare.") && r.result === "pass"));
  const reps = reportsOf(c);
  assert.equal(reps.length, 1);
  const rep = bodyOf(reps[0]);
  assert.equal(rep.exitCode, EXIT.error);
  const s = rep.sources.find((x: { name: string }) => x.name === "okta");
  assert.equal(s.error.message, "Cannot read properties of undefined (reading 'id')");
  assert.match(s.error.stack, /Error: Cannot read/);
  assert.deepEqual(s.warnings, ["okta: reading the org"]);
  assert.equal(s.skipped, 3);
  const cf = rep.sources.find((x: { name: string }) => x.name === "cloudflare");
  assert.ok(cf.pass > 0 && cf.error === null);
  assert.deepEqual(rep.pushes, [{ status: 201, runId: "r1" }]);
});

test("a failed push is recorded in the report, the report is still sent, and the exit code is unchanged", async () => {
  const refused = capture({}, { status: 409, body: { error: "This payload was already received." } });
  assert.equal(await main([...base, "--source", "cloudflare"], refused.deps), EXIT.refused);
  assert.deepEqual(bodyOf(reportsOf(refused)[0]).pushes, [{ status: 409, error: "This payload was already received." }]);
  const down = capture({ fetch: (async () => { throw new TypeError("fetch failed"); }) as typeof fetch });
  assert.equal(await main([...base, "--source", "cloudflare"], down.deps), EXIT.error);
  const rep = bodyOf(reportsOf(down)[0]);
  assert.deepEqual(rep.pushes, [{ status: 0, error: "fetch failed" }]);
  assert.equal(rep.exitCode, EXIT.error);
});

test("nothing to send (every check skipped) still sends a report, exit 3", async () => {
  const c = capture({ clients: { cloudflare: null, opa: missingOpa } });
  assert.equal(await main([...base, "--source", "cloudflare"], c.deps), EXIT.nothing);
  assert.equal(c.posts.length, 0);
  const rep = bodyOf(reportsOf(c)[0]);
  assert.equal(rep.exitCode, EXIT.nothing);
  assert.deepEqual(rep.pushes, []);
});

// ── 2. The run report ─────────────────────────────────────────────────────────────────────────────

test("the report is signed, sent to /api/collect/report, and the same bytes are in sagentix-run-report.json (0600)", async () => {
  const c = capture();
  assert.equal(await main([...base, "--source", "cloudflare"], c.deps), EXIT.ok, c.stderr.join("\n"));
  const [r] = reportsOf(c);
  assert.equal(r.url, "https://sos.example.test/api/collect/report");
  const h = r.init.headers as Record<string, string>;
  assert.equal(h["x-sagentix-key-id"], "k-1");
  assert.ok(await verify(publicKey, h["x-sagentix-signature"], r.init.body as Uint8Array));
  const file = join(c.dir, REPORT_FILE);
  assert.equal(readFileSync(file, "utf8"), new TextDecoder().decode(r.init.body as Uint8Array));
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
  const rep = bodyOf(r);
  assert.equal(rep.format, "sagentix-run-report/1");
  assert.equal(rep.late, false);
  assert.equal(rep.collector.version, COLLECTOR_VERSION);
  assert.match(rep.collector.commit, /^([0-9a-f]{40}|unknown)$/);
  assert.equal(rep.mode, "run");
  assert.ok(["github", "server", "docker", "mac", "windows", "unknown"].includes(rep.runner));
  assert.deepEqual(Object.keys(rep.os).sort(), ["arch", "platform", "release"]);
  assert.equal(rep.node, process.version);
  assert.deepEqual(Object.keys(rep).sort(), ["calls", "collector", "endedAt", "exitCode", "format", "issuedAt", "late", "log", "mode", "node", "os", "pushes", "runner", "sources", "startedAt"]);
  // The check-in went first, before any source read.
  assert.ok(c.channel[0].url.endsWith("/api/collect/checkin"));
});

test("a config run writes the report beside the config; the agent's runs say mode agent", async () => {
  const cfgDir = mkdtempSync(join(tmpdir(), "collector-cfg-"));
  const cfg = join(cfgDir, "sagentix-collector.config.json");
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", keyFile: keyPath, sources: { cloudflare: {} } }));
  const c = capture({ env: { SAGENTIX_COLLECTOR_MODE: "agent" } });
  assert.equal(await main(["run", "--config", cfg], c.deps), EXIT.ok, c.stderr.join("\n"));
  assert.ok(existsSync(join(cfgDir, REPORT_FILE)));
  assert.ok(!existsSync(join(c.dir, REPORT_FILE)));
  assert.equal(JSON.parse(readFileSync(join(cfgDir, REPORT_FILE), "utf8")).mode, "agent");
});

test("a dry run writes the report and sends none", async () => {
  const c = capture();
  assert.equal(await main([...base, "--source", "cloudflare", "--dry-run"], c.deps), EXIT.ok);
  assert.equal(reportsOf(c).length, 0);
  assert.ok(existsSync(join(c.dir, REPORT_FILE)));
});

test("a report that cannot be sent is kept as the pending report and sent first, late, by the next run", async () => {
  const first = capture({ channel: (async (url: string) => {
    if (String(url).endsWith("/checkin")) return new Response("{}", { status: 404 });
    throw new TypeError("fetch failed");
  }) as unknown as typeof fetch });
  assert.equal(await main([...base, "--source", "cloudflare"], first.deps), EXIT.ok, "a lost report never changes the exit code");
  const pending = join(first.dir, PENDING_FILE);
  assert.ok(existsSync(pending));
  assert.equal(JSON.parse(readFileSync(pending, "utf8")).late, true);
  assert.match(first.stderr.join("\n"), /check-in: HTTP 404 \(this sos-app does not take check-ins yet\); the run goes on/);
  assert.match(first.stderr.join("\n"), /run report was not sent \(fetch failed\)/);

  const left = readFileSync(pending, "utf8");
  const second = capture({ cwd: first.dir });
  assert.equal(await main([...base, "--source", "cloudflare"], second.deps), EXIT.ok);
  const reps = reportsOf(second);
  assert.equal(reps.length, 2);
  assert.equal(bodyOf(reps[0]).late, true);
  assert.equal(new TextDecoder().decode(reps[0].init.body as Uint8Array), left, "the pending file's exact bytes");
  assert.equal(bodyOf(reps[1]).late, false);
  assert.ok(!existsSync(pending), "removed once sent");
  // The check-in warning of the first run is in its report.
  assert.ok(bodyOf(reps[0]).sources.find((s: { name: string }) => s.name === "checkin").warnings[0].includes("HTTP 404"));
});

test("a 400 or 413 for the report is not kept as pending (it would be refused forever)", async () => {
  const c = capture({ channel: (async (url: string) => new Response("{}", { status: String(url).endsWith("/checkin") ? 200 : 413 })) as unknown as typeof fetch });
  await main([...base, "--source", "cloudflare"], c.deps);
  assert.ok(!existsSync(join(c.dir, PENDING_FILE)));
  assert.match(c.stderr.join("\n"), /refused the run report \(HTTP 413\)/);
});

test("outbound calls are counted per source by shape: method, host, templated path, status; never a query", async () => {
  const seen: string[] = [];
  const fakeNet = (async (input: string | URL | Request) => { seen.push(String(input)); return new Response("{}", { status: String(input).includes("missing") ? 404 : 200 }); }) as typeof fetch;
  const caller: Source = {
    name: "okta", options: {}, emits: [], describe: () => "test",
    async run() {
      await fetch("https://acme.okta.com/api/v1/users/00u1abcdEFGH2345ijkl/factors?limit=200&filter=secret");
      await fetch("https://acme.okta.com/api/v1/users/00u9zyxwVUTS8765rqpo/factors");
      await fetch("https://acme.okta.com/api/v1/missing", { method: "get" });
      return [];
    },
  };
  const real = globalThis.fetch;
  globalThis.fetch = fakeNet;
  try {
    const c = capture({ sources: [caller, cloudflare] });
    await main([...base, "--source", "okta,cloudflare"], c.deps);
    assert.equal(globalThis.fetch, fakeNet, "restored after the source");
    const rep = bodyOf(reportsOf(c)[0]);
    assert.deepEqual(rep.calls.sort((a: { path: string }, b: { path: string }) => a.path.localeCompare(b.path)).map(({ ms: _ms, ...x }: { ms: number }) => x), [
      { source: "okta", method: "GET", host: "acme.okta.com", path: "/api/v1/missing", status: 404, count: 1 },
      { source: "okta", method: "GET", host: "acme.okta.com", path: "/api/v1/users/:id/factors", status: 200, count: 2 },
    ]);
    assert.ok(!JSON.stringify(rep).includes("limit=200"));
    assert.equal(seen.length, 3);
  } finally { globalThis.fetch = real; }
});

test("templatePath replaces numbers, UUIDs, account ids, long hex or base64 and emails; keeps words", () => {
  assert.equal(templatePath("/zones/0123456789abcdef0123456789abcdef/settings/min_tls_version"), "/zones/:id/settings/min_tls_version");
  assert.equal(templatePath("/123456789012/users/42"), "/:id/users/:id");
  assert.equal(templatePath("/v1.0/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/authentication/methods"), "/v1.0/users/:id/authentication/methods");
  assert.equal(templatePath("/admin/directory/v1/users/jane.doe%40example.com"), "/admin/directory/v1/users/:id");
  assert.equal(templatePath("/repos/acme/app/actions/runs?page=2"), "/repos/acme/app/actions/runs");
  assert.equal(templatePath("/beta/deviceManagement/deviceManagementConfigurations"), "/beta/deviceManagement/deviceManagementConfigurations");
  assert.equal(templatePath("/zones/x/leaked-credential-checks"), "/zones/x/leaked-credential-checks");
  assert.equal(templatePath("/blobs/QUJDREVGR0hJSktMTU5PUFFSU1RVVlc9"), "/blobs/:id");
});

test("scrubbing: environment secrets, JWTs, authorization values, PEM blocks, AWS key ids and emails", () => {
  const env = { CLOUDFLARE_API_TOKEN_READONLY: "nope", OKTA_API_TOKEN: "00abcdefghijklmnop", GOOGLE_SA_KEY_JSON: '{"private_key":"x"}', AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG", SAGENTIX_COLLECTOR_KEY: "pem-text-here", JIRA_PASSWORD: "abc", PATH: "/usr/bin:/bin" };
  const secrets = envSecrets(env);
  assert.ok(!secrets.includes("/usr/bin:/bin") && !secrets.includes("abc"), "only secret names, and only values of 6 or more");
  assert.ok(!secrets.includes("nope"), "the name ends in _READONLY, not _TOKEN");
  const jwt = ["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "c2lnbmF0dXJl"].join(".");   // built here so a secret scanner does not read a token
  const text = [
    "token 00abcdefghijklmnop refused", "sa {\"private_key\":\"x\"}", "aws wJalrXUtnFEMI/K7MDENG", "key pem-text-here",
    `jwt ${jwt}`, "Authorization: Bearer abc.def-ghi_123", "basic Basic dXNlcjpwYXNz", "SSWS 00aBcDeFgHiJkLmN",
    "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI\n-----END " + "PRIVATE KEY-----", "id AKIA" + "IOSFODNN7EXAMPLE and ASIA" + "IOSFODNN7EXAMPLE",
    "user jane.doe+ops@example.co.uk failed", "short abc stays",
  ].join("\n");
  const out = scrubText(text, secrets);
  for (const leak of ["00abcdefghijklmnop", "private_key", "wJalrXUtnFEMI", "pem-text-here", jwt, "abc.def-ghi_123", "dXNlcjpwYXNz", "00aBcDeFgHiJkLmN", "MC4CAQ", "AKIA" + "IOSFODNN7EXAMPLE", "ASIA" + "IOSFODNN7EXAMPLE", "jane.doe"]) assert.ok(!out.includes(leak), leak);
  assert.match(out, /Bearer <secret>/);
  assert.match(out, /user <email> failed/);
  assert.match(out, /short abc stays/);
});

test("the report scrubs what a source's warnings and errors say", async () => {
  const leaky: Source = {
    name: "okta", options: {}, emits: [], describe: () => "test",
    run: async (ctx) => { ctx.warn(`token ${ctx.env.OKTA_API_TOKEN} for admin@acme.example`); throw new Error(`HTTP 401 with Bearer ${ctx.env.OKTA_API_TOKEN}`); },
  };
  const c = capture({ sources: [leaky, cloudflare], env: { OKTA_API_TOKEN: "00SuperSecretValue1234" } });
  await main([...base, "--source", "okta,cloudflare"], c.deps);
  const sent = new TextDecoder().decode(reportsOf(c)[0].init.body as Uint8Array);
  assert.ok(!sent.includes("00SuperSecretValue1234"));
  assert.ok(!sent.includes("admin@acme.example"));
  assert.match(sent, /token <secret> for <email>/);
  assert.equal(readFileSync(join(c.dir, REPORT_FILE), "utf8"), sent, "the file on disk is scrubbed too");
});

test("limits: log lines, line length, warnings per source, and 512 KiB with log, then calls, then stacks trimmed", () => {
  const rec = new RunRecorder(() => NOW);
  const err = rec.tee(() => {});
  for (let i = 0; i < 1500; i++) err(`line ${i} ${"x".repeat(600)}`);
  const r = buildReport(rec, { now: NOW, exitCode: 0, runner: "server", mode: "run", env: {} });
  assert.ok(r.log.length <= MAX_LOG_LINES);
  assert.ok(r.log.every((l) => l.length <= 500));
  assert.match(r.log.at(-1)!, /log cut: 1500 lines/);

  const big = { ...r, log: Array.from({ length: 1000 }, (_, i) => `${i} ${"y".repeat(499)}`),
    calls: Array.from({ length: 3000 }, (_, i) => ({ source: "aws", method: "GET", host: `h${i}.example`, path: `/p/${"z".repeat(100)}`, status: 200, count: i, ms: 1 })),
    sources: [{ name: "aws", ms: 1, pass: 0, fail: 0, skipped: 0, error: { message: "boom", stack: "s".repeat(600_000) }, warnings: [] }] };
  const t = trimReport(big);
  assert.ok(Buffer.byteLength(JSON.stringify(t, null, 2)) <= 512 * 1024);
  assert.match(t.log.at(-1)!, /report trimmed to 524288 bytes: log 1000 to \d+ lines, calls 3000 to \d+, stacks removed/);
  assert.equal(t.sources[0].error!.stack, "");
  assert.equal(t.sources[0].error!.message, "boom");
  // Under the limit nothing changes.
  assert.equal(trimReport(r), r);

  const rec2 = new RunRecorder(() => NOW);
  return rec2.source("okta", async () => { const e = rec2.tee(() => {}); for (let i = 0; i < 80; i++) e(`w${i}`); }).then(({ report }) => assert.equal(report.warnings.length, 50));
});

// ── 3. Check-in ───────────────────────────────────────────────────────────────────────────────────

const release = generateKeyPairSync("ed25519");
const releasePub = Buffer.from(release.publicKey.export({ format: "jwk" }).x!, "base64url").toString("base64");
const COMMIT = "a".repeat(40);
const IMAGE = `ghcr.io/sagentix-advisors-inc/sagentix-collector-runner:0.3.1@sha256:${"b".repeat(64)}`;
function signed(t: Omit<Target, "signature">, key = release.privateKey): Target {
  return { ...t, signature: sign(null, releaseMessage(t), key).toString("base64") };
}
const target = signed({ version: "0.3.1", commit: COMMIT, image: IMAGE, date: "2026-10-29" });

function chan(answer: unknown, over: Partial<Channel> = {}, status = 200): Channel & { dir: string; sent: unknown[] } {
  const d = mkdtempSync(join(tmpdir(), "collector-ci-"));
  const sent: unknown[] = [];
  return {
    origin: "https://sos.example.test", keyId: "k-1", pem: privatePem, dir: d, runner: "server", mode: "run", env: {}, now: () => NOW,
    fetch: (async (_u: string, init: RequestInit) => { sent.push(JSON.parse(new TextDecoder().decode(init.body as Uint8Array))); return new Response(JSON.stringify(answer), { status }); }) as unknown as typeof fetch,
    sent, ...over,
  };
}
const quiet = () => {};

test("the check-in body names the collector, the runner and the mode", async () => {
  const c = chan({ action: "none", target: null, reason: "" });
  await checkin(c, { write: true, log: quiet, keys: [releasePub] });
  const b = c.sent[0] as Record<string, unknown>;
  assert.equal(b.format, "sagentix-checkin/1");
  assert.equal(b.issuedAt, NOW.toISOString());
  assert.deepEqual(Object.keys(b).sort(), ["collector", "format", "issuedAt", "mode", "node", "os", "runner"]);
  assert.equal((b.collector as { version: string }).version, COLLECTOR_VERSION);
});

test("update with a valid release signature writes sagentix-collector.ref (commit, version), mode 0600", async () => {
  const c = chan({ action: "update", target, reason: "stable is 0.3.1" });
  const out = await checkin(c, { write: true, log: quiet, keys: [releasePub] });
  assert.deepEqual(out.warnings, []);
  const file = join(c.dir, REF_FILE);
  assert.equal(out.wrote, file);
  assert.equal(readFileSync(file, "utf8"), `${COMMIT}\n0.3.1\n`);
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.ok(!existsSync(join(c.dir, IMAGE_FILE)));
});

test("a Docker runner writes sagentix-collector.image, and only for the runner image with a digest", async () => {
  const c = chan({ action: "update", target }, { runner: "docker" });
  await checkin(c, { write: true, log: quiet, keys: [releasePub] });
  assert.equal(readFileSync(join(c.dir, IMAGE_FILE), "utf8"), `${IMAGE}\n`);
  assert.ok(!existsSync(join(c.dir, REF_FILE)));
  for (const image of [null, "ghcr.io/evil/runner@sha256:" + "b".repeat(64), "ghcr.io/sagentix-advisors-inc/sagentix-collector-runner:0.3.1"]) {
    const d = chan({ action: "update", target: signed({ version: "0.3.1", commit: COMMIT, image, date: "2026-10-29" }) }, { runner: "docker" });
    const out = await checkin(d, { write: true, log: quiet, keys: [releasePub] });
    assert.ok(!existsSync(join(d.dir, IMAGE_FILE)), String(image));
    assert.match(out.warnings[0], /no runner image with a digest/);
  }
});

test("a bad signature, another key, a tampered field or a commit that is not 40 hex: nothing written, a warning", async () => {
  const other = generateKeyPairSync("ed25519").privateKey;
  const cases: unknown[] = [
    { ...target, signature: Buffer.alloc(64).toString("base64") },
    signed({ version: "0.3.1", commit: COMMIT, image: IMAGE, date: "2026-10-29" }, other),
    { ...target, version: "0.3.2" },
    { ...target, commit: "b".repeat(40) },
    signed({ version: "0.3.1", commit: "main", image: null, date: "2026-10-29" }),
    { ...target, signature: undefined },
    null,
  ];
  for (const t of cases) {
    const c = chan({ action: "update", target: t });
    const out = await checkin(c, { write: true, log: quiet, keys: [releasePub] });
    assert.ok(!existsSync(join(c.dir, REF_FILE)), JSON.stringify(t));
    assert.equal(out.warnings.length, 1, JSON.stringify(t));
    assert.match(out.warnings[0], /refused/);
  }
  assert.equal(verifyTarget(target, [releasePub]), true);
  assert.equal(verifyTarget(target, RELEASE_PUBLIC_KEYS), false, "the test key is not a Sagentix release key");
});

test("notify, approval-needed and none write nothing; a github runner never writes a ref", async () => {
  for (const action of ["notify", "approval-needed", "none"]) {
    const logs: string[] = [];
    const c = chan({ action, target, reason: "the workflow pins the commit" });
    const out = await checkin(c, { write: true, log: (s) => logs.push(s), keys: [releasePub] });
    assert.equal(out.action, action);
    assert.deepEqual(out.warnings, []);
    assert.ok(!existsSync(join(c.dir, REF_FILE)) && !existsSync(join(c.dir, IMAGE_FILE)));
    if (action === "notify") assert.match(logs.join("\n"), /cannot update itself: the workflow pins the commit/);
    if (action === "approval-needed") assert.match(logs.join("\n"), /waits for your organization's approval/);
  }
  const g = chan({ action: "update", target }, { runner: "github" });
  const out = await checkin(g, { write: true, log: quiet, keys: [releasePub] });
  assert.ok(!existsSync(join(g.dir, REF_FILE)));
  assert.match(out.warnings[0], /github runner pins its own commit/);
});

test("a dry run reads the update and writes nothing", async () => {
  const c = chan({ action: "update", target });
  const logs: string[] = [];
  await checkin(c, { write: false, log: (s) => logs.push(s), keys: [releasePub] });
  assert.ok(!existsSync(join(c.dir, REF_FILE)));
  assert.match(logs.join("\n"), /dry run, so .* is not written/);
});

test("end to end: run with a signed update writes the ref beside the config and still collects; a dry run does not", async () => {
  RELEASE_PUBLIC_KEYS.push(releasePub);
  try {
    const answer = (async (url: string) => new Response(JSON.stringify(String(url).endsWith("/checkin") ? { action: "update", target } : { id: "r" }), { status: String(url).endsWith("/checkin") ? 200 : 201 })) as unknown as typeof fetch;
    const dry = capture({ channel: answer, env: { SAGENTIX_RUNNER: "server" } });
    assert.equal(await main([...base, "--source", "cloudflare", "--dry-run"], dry.deps), EXIT.ok);
    assert.ok(!existsSync(join(dry.dir, REF_FILE)));
    const c = capture({ channel: answer, env: { SAGENTIX_RUNNER: "server" } });
    assert.equal(await main([...base, "--source", "cloudflare"], c.deps), EXIT.ok, c.stderr.join("\n"));
    assert.equal(readFileSync(join(c.dir, REF_FILE), "utf8"), `${COMMIT}\n0.3.1\n`);
    assert.equal(c.posts.length, 1);
    assert.equal(JSON.parse(readFileSync(join(c.dir, REPORT_FILE), "utf8")).runner, "server");
  } finally { RELEASE_PUBLIC_KEYS.pop(); }
});

test("a check-in that cannot reach sos-app never stops the run", async () => {
  const c = capture({ channel: (async () => { throw new TypeError("getaddrinfo ENOTFOUND"); }) as typeof fetch });
  assert.equal(await main([...base, "--source", "cloudflare"], c.deps), EXIT.ok);
  assert.equal(c.posts.length, 1);
  assert.match(c.stderr.join("\n"), /warning: check-in: POST \/api\/collect\/checkin failed: getaddrinfo ENOTFOUND; the run goes on/);
  const garbage = await checkin(chan("not an object at all"), { write: true, log: quiet, keys: [releasePub] });
  assert.equal(garbage.action, "failed");
});

test("runner detection: SAGENTIX_RUNNER, then GitHub Actions, then the platform and /.dockerenv", () => {
  assert.equal(detectRunner({ SAGENTIX_RUNNER: "docker", GITHUB_ACTIONS: "true" }, "darwin"), "docker");
  assert.equal(detectRunner({ SAGENTIX_RUNNER: "nonsense", GITHUB_ACTIONS: "true" }, "linux"), "github");
  assert.equal(detectRunner({}, "darwin"), "mac");
  assert.equal(detectRunner({}, "win32"), "windows");
  assert.equal(detectRunner({}, "linux", () => true), "docker");
  assert.equal(detectRunner({}, "linux", () => false), "server");
});

// ── 5. The agent ──────────────────────────────────────────────────────────────────────────────────

function child(): ChildRun & { end(code: number | null): void; killed: boolean } {
  let end!: (c: number | null) => void;
  const exit = new Promise<number | null>((r) => { end = r; });
  const c = { exit, killed: false, end: (code: number | null) => end(code), kill() { c.killed = true; } };
  return c;
}
const tick = () => new Promise((r) => setImmediate(r));

test("agent session: hello on open, pong for ping, one run at a time with its status, checkin, the rest ignored", async () => {
  const sent: string[] = [], logs: string[] = [], kids: ReturnType<typeof child>[] = [];
  let open = true, checkins = 0;
  const s = new AgentSession({
    send: (t) => { if (!open) return false; sent.push(t); return true; },
    startRun: () => { const k = child(); kids.push(k); return k; },
    checkin: async () => { checkins++; },
    log: (l) => logs.push(l),
    hello: { version: "0.3.0", commit: "unknown", runner: "mac" },
  });
  s.onOpen();
  assert.deepEqual(JSON.parse(sent[0]), { type: "hello", version: "0.3.0", commit: "unknown", runner: "mac" });
  s.onMessage('{"type":"ping"}');
  assert.deepEqual(JSON.parse(sent[1]), { type: "pong" });
  s.onMessage('{"type":"run","id":"u-1"}');
  assert.deepEqual(JSON.parse(sent[2]), { type: "status", id: "u-1", state: "started", exitCode: null });
  s.onMessage('{"type":"run","id":"u-2"}');
  assert.equal(kids.length, 1, "never two at once");
  assert.deepEqual(JSON.parse(sent[3]), { type: "status", id: "u-2", state: "failed", exitCode: null });
  kids[0].end(0); await tick();
  assert.deepEqual(JSON.parse(sent[4]), { type: "status", id: "u-1", state: "done", exitCode: 0 });
  assert.equal(s.running, undefined);
  s.onMessage('{"type":"run","id":"u-3"}');
  kids[1].end(3); await tick();
  assert.deepEqual(JSON.parse(sent.at(-1)!), { type: "status", id: "u-3", state: "failed", exitCode: 3 });
  s.onMessage('{"type":"checkin"}'); await tick();
  assert.equal(checkins, 1);
  const before = sent.length;
  for (const m of ['{"type":"exec","cmd":"rm -rf /"}', '{"type":"config","sources":{}}', "not json", "null", '{"type":"run"}', '{"type":"pong"}'])
    s.onMessage(m);
  s.onMessage(new Uint8Array([1, 2]));
  assert.equal(sent.length, before, "nothing is answered to anything else");
  assert.equal(kids.length, 2, "and nothing runs");
  assert.match(logs.join("\n"), /ignored a message of type "exec"/);
  // A final status that finds the socket closed goes after the next hello.
  s.onMessage('{"type":"run","id":"u-4"}');
  open = false; kids[2].end(0); await tick(); open = true;
  s.onOpen();
  assert.deepEqual(sent.slice(-2).map((t) => JSON.parse(t).type), ["hello", "status"]);
  assert.equal(JSON.parse(sent.at(-1)!).id, "u-4");
});

test("the connect URL is signed over sagentix-connect/1, key id and ts, base64url, on wss", async () => {
  const u = new URL(connectUrl("https://sos.example.test/api/collect", "k-1", privatePem, 1_761_652_800_000));
  assert.equal(u.protocol, "wss:");
  assert.equal(u.pathname, "/api/collect/connect");
  assert.equal(u.searchParams.get("key"), "k-1");
  assert.equal(u.searchParams.get("ts"), "1761652800000");
  const sig = u.searchParams.get("sig")!;
  assert.match(sig, /^[A-Za-z0-9_-]+$/);
  assert.ok(await verify(publicKey, Buffer.from(sig, "base64url").toString("base64"), new TextEncoder().encode("sagentix-connect/1\nk-1\n1761652800000")));
  assert.equal(new URL(connectUrl("http://localhost:8787", "k", privatePem, 1)).protocol, "ws:");
});

test("backoff: 1 s doubling to 5 min", () => {
  let ms = 1000; const seen = [ms];
  for (let i = 0; i < 12; i++) { ms = nextBackoff(ms); seen.push(ms); }
  assert.deepEqual(seen.slice(0, 5), [1000, 2000, 4000, 8000, 16000]);
  assert.equal(seen.at(-1), BACKOFF_MAX_MS);
});

type FakeSocket = SocketLike & { sent: string[]; url: string; readyState: number };
/** Sockets, timers and child runs the test drives by hand. `hold: true` keeps each run going until `end` is called. */
function fakeIo(o: { hold?: boolean } = {}) {
  const sockets: FakeSocket[] = [];
  const timers: { f: () => void; ms: number; kind: "timeout" | "interval"; live: boolean }[] = [];
  const runs: string[] = [], kids: ReturnType<typeof child>[] = [];
  let stopFn: () => void = () => {};
  const io: AgentIo = {
    socket(url) {
      const s = { url, readyState: 0, sent: [] as string[], onopen: null, onmessage: null, onclose: null, onerror: null,
        send(t: string) { s.sent.push(t); }, close() { s.readyState = 3; } } as FakeSocket;
      sockets.push(s);
      return s;
    },
    spawnRun(path) { runs.push(path); const k = child(); kids.push(k); if (!o.hold) setImmediate(() => k.end(0)); return k; },
    onStop(f) { stopFn = f; },
    setTimeout(f, ms) { const t = { f, ms, kind: "timeout" as const, live: true }; timers.push(t); return t; },
    clearTimeout(t) { (t as { live: boolean }).live = false; },
    setInterval(f, ms) { const t = { f, ms, kind: "interval" as const, live: true }; timers.push(t); return t; },
    clearInterval(t) { (t as { live: boolean }).live = false; },
  };
  return { io, sockets, timers, runs, kids, stop: () => stopFn() };
}
function agentConfig(): string {
  const cfgDir = mkdtempSync(join(tmpdir(), "collector-agent-"));
  const cfg = join(cfgDir, "sagentix-collector.config.json");
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", keyFile: keyPath, sources: { cloudflare: {} } }));
  return cfg;
}

test("agent loop: connects, says hello, checks in, pings, runs on request, reconnects with backoff, stops cleanly", async () => {
  const cfg = agentConfig();
  const { io, sockets, timers, runs, stop } = fakeIo();
  const c = capture();
  const done = agent(["--config", cfg], c.deps, io);
  await tick();
  assert.equal(sockets.length, 1);
  assert.match(sockets[0].url, /^wss:\/\/sos\.example\.test\/api\/collect\/connect\?key=k-1&ts=\d+&sig=/);
  const s = sockets[0];
  s.readyState = 1; s.onopen!({});
  await tick();
  assert.equal(JSON.parse(s.sent[0]).type, "hello");
  assert.equal(c.channel.filter((p) => p.url.endsWith("/checkin")).length, 1, "check-in on connect");
  const ping = timers.find((t) => t.kind === "interval" && t.ms === PING_MS)!;
  ping.f();
  assert.equal(s.sent.at(-1), '{"type":"ping"}');
  assert.ok(timers.some((t) => t.kind === "interval" && t.ms === 6 * 3600_000), "check-in every 6 h");
  s.onmessage!({ data: '{"type":"run","id":"r-9"}' });
  await tick(); await tick();
  assert.deepEqual(runs, [cfg]);
  assert.deepEqual(s.sent.slice(-2).map((t) => JSON.parse(t).state), ["started", "done"]);
  // The socket drops: a retry after 1 s, then 2 s if that fails too.
  s.readyState = 3; s.onclose!({ code: 1006 });
  assert.equal(ping.live, false);
  const r1 = timers.filter((t) => t.kind === "timeout" && t.live).at(-1)!;
  assert.equal(r1.ms, 1000);
  r1.f(); sockets[1].onclose!({ code: 1006 });
  assert.equal(timers.filter((t) => t.kind === "timeout").at(-1)!.ms, 2000);
  stop();
  assert.equal(await done, 0);
  assert.ok(timers.filter((t) => t.kind === "interval").every((t) => !t.live), "every timer cleared");
});

test("agent usage errors exit 2", async () => {
  const c = capture();
  assert.equal(await main(["agent"], c.deps), 2);
  assert.equal(await main(["agent", "--config", join(dir, "absent.json")], c.deps), 2);
});

const updating = (async (url: string) => new Response(JSON.stringify(String(url).endsWith("/checkin") ? { action: "update", target } : { id: "r" }), { status: String(url).endsWith("/checkin") ? 200 : 201 })) as unknown as typeof fetch;

test("agent: a signed update on connect writes the image (Docker) and exits 75", async () => {
  RELEASE_PUBLIC_KEYS.push(releasePub);
  try {
    const cfg = agentConfig();
    const { io, sockets, timers } = fakeIo();
    const c = capture({ channel: updating, env: { SAGENTIX_RUNNER: "docker" } });
    const done = agent(["--config", cfg], c.deps, io);
    await tick();
    sockets[0].readyState = 1; sockets[0].onopen!({});
    assert.equal(await done, EXIT.update);
    assert.equal(EXIT.update, 75);
    assert.equal(readFileSync(join(cfg, "..", IMAGE_FILE), "utf8"), `${IMAGE}\n`);
    assert.equal(sockets[0].readyState, 3, "socket closed");
    assert.ok(timers.filter((t) => t.kind === "interval").every((t) => !t.live));
  } finally { RELEASE_PUBLIC_KEYS.pop(); }
});

test("agent: an update during a run waits for the run to end, then exits 75 (script runner writes the ref)", async () => {
  RELEASE_PUBLIC_KEYS.push(releasePub);
  try {
    const cfg = agentConfig();
    const { io, sockets, kids } = fakeIo({ hold: true });
    let answer: unknown = { action: "none", target: null };
    const channel = (async () => new Response(JSON.stringify(answer), { status: 200 })) as unknown as typeof fetch;
    const c = capture({ channel, env: { SAGENTIX_RUNNER: "mac" } });
    let code: number | undefined;
    const done = agent(["--config", cfg], c.deps, io).then((x) => { code = x; return x; });
    await tick();
    const s = sockets[0];
    s.readyState = 1; s.onopen!({});
    await tick();
    s.onmessage!({ data: '{"type":"run","id":"r-1"}' });
    answer = { action: "update", target };
    s.onmessage!({ data: '{"type":"checkin"}' });
    await tick(); await tick();
    assert.equal(readFileSync(join(cfg, "..", REF_FILE), "utf8"), `${COMMIT}\n0.3.1\n`);
    assert.equal(code, undefined, "still running while the run goes on");
    assert.equal(kids[0].killed, false);
    kids[0].end(0);
    assert.equal(await done, EXIT.update);
    assert.equal(JSON.parse(s.sent.at(-1)!).state, "done", "the run's status went out before the exit");
  } finally { RELEASE_PUBLIC_KEYS.pop(); }
});

test("agent: notify or a refused signature never exits; run mode never exits 75", async () => {
  const cfg = agentConfig();
  const { io, sockets, stop } = fakeIo();
  const c = capture({ channel: updating, env: { SAGENTIX_RUNNER: "docker" } });   // the test key is not a release key
  let code: number | undefined;
  const done = agent(["--config", cfg], c.deps, io).then((x) => { code = x; return x; });
  await tick();
  sockets[0].readyState = 1; sockets[0].onopen!({});
  await tick(); await tick();
  assert.equal(code, undefined);
  assert.ok(!existsSync(join(cfg, "..", IMAGE_FILE)));
  stop();
  assert.equal(await done, 0);
});

// A provider's own retirement notice (RFC 9745 Deprecation, RFC 8594 Sunset) or a 410 lands in the report (2026-10-28).
test("deprecation and sunset headers, and a 410, become the source's warnings and the call's fields", async () => {
  const { RunRecorder } = await import("../src/report.ts");
  const rec = new RunRecorder(() => new Date("2026-10-28T12:00:00Z"));
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const u = String(input);
    if (u.endsWith("/old")) return new Response("{}", { status: 200, headers: { deprecation: "@1767225600", sunset: "Wed, 30 Jun 2027 00:00:00 GMT" } });
    if (u.endsWith("/gone")) return new Response("", { status: 410 });
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  try {
    const { report } = await rec.source("acme", async () => {
      await fetch("https://api.acme.example/v1/old");
      await fetch("https://api.acme.example/v1/old");
      await fetch("https://api.acme.example/v1/gone");
      await fetch("https://api.acme.example/v1/fine");
    });
    assert.equal(report.warnings.length, 2);
    assert.match(report.warnings[0], /deprecated, sunset Wed, 30 Jun 2027 .*GET api\.acme\.example\/v1\/old/);
    assert.match(report.warnings[1], /gone \(HTTP 410\): GET api\.acme\.example\/v1\/gone/);
    const old = rec.callList().find((c) => c.path === "/v1/old")!;
    assert.equal(old.count, 2);
    assert.equal(old.deprecation, "@1767225600");
    assert.equal(rec.callList().find((c) => c.path === "/v1/fine")!.deprecation, undefined);
  } finally {
    globalThis.fetch = original;
  }
});

test("agent: a run from sos-app goes through the generated script beside the config when there is one", async () => {
  const { runCommand } = await import("../src/agent.ts");
  const has = (names: string[]) => (p: string) => names.some((n) => p.endsWith(n));
  assert.deepEqual(runCommand("/w/sagentix-collector.config.json", has(["sagentix-collector.sh"]), "darwin"), ["/bin/bash", ["/w/sagentix-collector.sh"]]);
  const win = runCommand("C:/w/sagentix-collector.config.json", has(["sagentix-collector.ps1"]), "win32");
  assert.equal(win[0], "powershell.exe");
  assert.ok(win[1].includes("Bypass") && win[1].at(-1)!.endsWith("sagentix-collector.ps1"));
  const bare = runCommand("/w/sagentix-collector.config.json", () => false, "linux");
  assert.equal(bare[0], process.execPath);
  assert.deepEqual(bare[1].slice(-3), ["run", "--config", "/w/sagentix-collector.config.json"]);
});
