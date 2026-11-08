// The run's efficiency, debugging and smoke-test features (2026-11-07): sources side by side with the same bytes out,
// one token per credential, retries with Retry-After, timeouts, the --verbose log and closing table, the doctor, and
// a test that fails if a known secret reaches stdout, stderr, the payload or the run report.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Readable } from "node:stream";
import { main, EXIT, problemLines, runTuning, summaryTable, type Deps } from "../src/cli.ts";
import { pool } from "../src/pool.ts";
import { PROBES, judge, onPath } from "../src/doctor.ts";
import { REPORT_FILE, RunRecorder } from "../src/report.ts";
import { SOURCES } from "../src/sources/index.ts";
import { fetchCloudflareApi } from "../src/sources/cloudflare/api.ts";
import { memoDirectory, type Account, type Directory } from "../src/sources/directory.ts";
import { jsonArrayElements, parseOcsf, parseOcsfFile } from "../src/sources/prowler.ts";
import { withRetry as restRetry, type HttpResponse } from "../src/sources/readonly_http.ts";
import { withRetry as cloudRetry, type HttpReply } from "../src/sources/shared-cloud.ts";
import { loadCatalog } from "../src/catalog.ts";
import type { Result } from "../src/types.ts";
import { e2eSetup, E2E_NOW } from "./e2e_fixtures.ts";
import { capture, NOW } from "./helpers.ts";

interface Ran { code: number; stdout: string; stderr: string; dir: string; posts: number; channel: number }

/** `main` with every source's recorded replies (test/e2e_fixtures.ts), or with `clients: {}` so sources build their own. */
async function runMain(argv: string[], o: { latencyMs?: number; env?: NodeJS.ProcessEnv; clients?: Record<string, unknown>; setup?: ReturnType<typeof e2eSetup> } = {}): Promise<Ran> {
  const s = o.setup ?? e2eSetup({ latencyMs: o.latencyMs });
  const c = capture({ clients: o.clients ?? s.clients, env: { ...(o.clients ? {} : s.env), ...(o.env ?? {}) }, now: () => E2E_NOW, cwd: s.dir });
  const code = await main(argv, c.deps);
  return { code, stdout: c.stdout.join("\n"), stderr: c.stderr.join("\n"), dir: s.dir, posts: c.posts.length, channel: c.channel.length };
}

const payloadResults = (stdout: string): Result[] => { const j = JSON.parse(stdout); return (j.pushes ?? [j]).flatMap((p: { payload: { results: Result[] } }) => p.payload.results); };

// ── Efficiency ─────────────────────────────────────────────────────────────────────────────────────

test("pool: runs at most `limit` at once and returns each outcome at its item's index", async () => {
  let live = 0, peak = 0;
  const out = await pool([30, 5, 20, 1, 10], 2, async (ms, i) => {
    live++; peak = Math.max(peak, live);
    await new Promise((r) => setTimeout(r, ms));
    live--;
    if (i === 3) throw new Error("four");
    return ms * 2;
  });
  assert.equal(peak, 2);
  assert.deepEqual(out.map((o) => (o.status === "fulfilled" ? o.value : (o.reason as Error).message)), [60, 10, 40, "four", 20]);
  assert.deepEqual(await pool([], 4, async () => 1), []);
});

test("sources side by side send the same results, in the same order, as one after another; and faster", async () => {
  const t1 = performance.now();
  const serial = await runMain(["run", ...e2eSetup().args, "--dry-run", "--concurrency", "1"], { latencyMs: 4 });
  const ms1 = performance.now() - t1;
  const t8 = performance.now();
  const wide = await runMain(["run", ...e2eSetup().args, "--dry-run", "--concurrency", "8"], { latencyMs: 4 });
  const ms8 = performance.now() - t8;
  assert.equal(serial.code, EXIT.ok, serial.stderr);
  assert.equal(wide.code, EXIT.ok, wide.stderr);
  const a = JSON.stringify(payloadResults(serial.stdout)).split(serial.dir).join("<dir>");
  const b = JSON.stringify(payloadResults(wide.stdout)).split(wide.dir).join("<dir>");
  assert.equal(a, b, "byte-identical results");
  assert.ok(ms8 < ms1, `8 at once (${Math.round(ms8)} ms) is faster than 1 (${Math.round(ms1)} ms)`);
  // The report lists the sources in the order named, whatever order they finished in.
  const rep = JSON.parse(readFileSync(join(wide.dir, REPORT_FILE), "utf8"));
  assert.deepEqual(rep.sources.map((x: { name: string }) => x.name).filter((n: string) => SOURCES.some((s) => s.name === n)), e2eSetup().sources);
});

test("--concurrency and --http-timeout are checked: out of range exits 2", async () => {
  assert.deepEqual(runTuning({}), { concurrency: 4, timeoutMs: 60_000 });
  assert.deepEqual(runTuning({ concurrency: "1", "http-timeout": "0" }), { concurrency: 1, timeoutMs: 0 });
  for (const bad of [["--concurrency", "0"], ["--concurrency", "17"], ["--concurrency", "2.5"], ["--http-timeout", "-1"], ["--http-timeout", "x"]]) {
    const r = await runMain(["run", "--endpoint", "https://sos.example.test", "--source", "cloudflare", "--dry-run", ...bad]);
    assert.equal(r.code, EXIT.usage, bad.join(" "));
  }
});

/** A fake network for sources that build their own clients: `route` answers by URL; every request is recorded. */
function fakeNet(route: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const seen: { url: string; method: string; headers: Record<string, string> }[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    seen.push({ url, method: (init.method ?? "GET").toUpperCase(), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])) });
    return route(url, init);
  }) as typeof fetch;
  return { seen, restore: () => { globalThis.fetch = original; } };
}
const jsonRes = (status: number, body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("one token request per app and scope for the whole run: Entra ID, Intune and the HR join share it", async () => {
  const net = fakeNet((url) => {
    if (url.startsWith("https://login.microsoftonline.com/")) return jsonRes(200, { access_token: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.sig", expires_in: 3600 });
    if (url.includes("api.bamboohr.com") || url.includes("bamboohr.com/api")) return jsonRes(200, { data: [], meta: { page: { nextCursor: null } } });
    return jsonRes(200, { value: [] });
  });
  try {
    const r = await runMain(["run", "--endpoint", "https://sos.example.test", "--source", "entra,intune,bamboohr", "--bamboohr-company", "acme", "--bamboohr-idp", "entra", "--dry-run"],
      { clients: {}, env: { ENTRA_TENANT_ID: "t-1", ENTRA_CLIENT_ID: "c-1", ENTRA_CLIENT_SECRET: "s3cr3t-value-0123456789", BAMBOOHR_API_KEY: "bhr-key-0123456789" } });
    assert.equal(r.code, EXIT.ok, r.stderr);
    const tokens = net.seen.filter((s) => s.url.startsWith("https://login.microsoftonline.com/"));
    assert.equal(tokens.length, 1, `token requests: ${tokens.length}`);
    // The table counts each source's own calls.
    assert.match(r.stderr, /\nentra +\d+ +\d+ +\d+ +\d+ +[1-9]\d* /);
  } finally { net.restore(); }
});

test("directory lookups are kept for the run: a leaver both HR sources name is looked up once; an error is asked again", async () => {
  let n = 0;
  const d: Directory = { idp: "okta", lookup: async (e) => { n++; return (e === "bad@x" ? { state: "error", why: "HTTP 500" } : { state: "active", id: e }) as Account; } };
  const m = memoDirectory(d);
  await m.lookup("Fay@acme.example"); await m.lookup("fay@acme.example");
  assert.equal(n, 1);
  await m.lookup("bad@x"); await m.lookup("bad@x");
  assert.equal(n, 3);
});

// ── Retries and timeouts ───────────────────────────────────────────────────────────────────────────

test("REST retries: 503 twice then 200; a third 503 gives up; Retry-After is honoured; a thrown error is retried", async () => {
  const waits: number[] = [];
  const answers = (list: (HttpResponse | Error)[]) => { let i = 0; return { get: async () => { const a = list[Math.min(i++, list.length - 1)]; if (a instanceof Error) throw a; return a; } }; };
  const r = (status: number, headers: Record<string, string> = {}): HttpResponse => ({ status, headers, body: {} });
  let api = restRetry(answers([r(503, { "retry-after": "3" }), r(502), r(200)]), async (ms) => { waits.push(ms); });
  assert.equal((await api.get("/x")).status, 200);
  assert.deepEqual(waits, [3000, 2000]);
  api = restRetry(answers([r(503), r(503), r(503), r(200)]), async () => {});
  assert.equal((await api.get("/x")).status, 503, "two transient retries, then the 503 is the answer");
  api = restRetry(answers([new Error("ECONNRESET"), r(200)]), async () => {});
  assert.equal((await api.get("/x")).status, 200);
  api = restRetry(answers([r(500), r(200)]), async () => {});
  assert.equal((await api.get("/x")).status, 500, "a 500 is the request's fault: not retried");
  // Rate limits keep their own, larger budget.
  api = restRetry(answers([r(429), r(429), r(429), r(429), r(200)]), async () => {});
  assert.equal((await api.get("/x")).status, 200);
});

test("cloud retries: 502 and 504 are retried twice within the attempts; a thrown error once more", async () => {
  const seq = (list: (HttpReply | Error)[]) => { let i = 0; return async () => { const a = list[Math.min(i++, list.length - 1)]; if (a instanceof Error) throw a; return a; }; };
  const h = (status: number): HttpReply => ({ status, headers: {}, body: "" });
  assert.equal((await cloudRetry(seq([h(502), h(504), h(200)]), { sleep: async () => {} })).status, 200);
  assert.equal((await cloudRetry(seq([h(502), h(502), h(502), h(200)]), { sleep: async () => {} })).status, 502);
  assert.equal((await cloudRetry(seq([new Error("socket hang up"), h(200)]), { sleep: async () => {} })).status, 200);
  assert.equal((await cloudRetry(seq([h(403), h(200)]), { sleep: async () => {} })).status, 403);
});

test("Cloudflare's client now retries a 429 after its Retry-After, and a network failure becomes status 0 with the reason", async () => {
  const waits: number[] = [];
  let i = 0;
  const f = (async () => (i++ === 0 ? new Response("{}", { status: 429, headers: { "retry-after": "2" } }) : jsonRes(200, { success: true, result: [] }))) as unknown as typeof fetch;
  const api = fetchCloudflareApi("tok", f, undefined, async (ms) => { waits.push(ms); });
  assert.equal((await api.get("/zones")).status, 200);
  assert.deepEqual(waits, [2000]);
  const down = fetchCloudflareApi("tok", (async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch, undefined, async () => {});
  const r = await down.get("/zones");
  assert.equal(r.status, 0);
  assert.match(JSON.stringify(r.body), /request failed: TypeError: fetch failed/);
});

test("--http-timeout abandons a call that does not answer; the check is skipped with the reason, and retried first", async () => {
  const net = fakeNet((_url, init) => new Promise((_res, rej) => { init.signal?.addEventListener("abort", () => rej(init.signal!.reason)); }));
  try {
    const r = await runMain(["run", "--endpoint", "https://sos.example.test", "--source", "stripe", "--dry-run", "--http-timeout", "0.05", "--verbose"],
      { clients: { sleep: async () => {} }, env: { STRIPE_API_KEY: ["rk", "live", "abcdefgh12345678"].join("_") } });
    assert.equal(r.code, EXIT.ok, r.stderr);
    const res = payloadResults(r.stdout);
    assert.ok(res.every((x) => x.result === "skipped"));
    assert.match(res[0].detail, /no answer from api\.stripe\.com within 0 s \(--http-timeout\)/);
    assert.equal(net.seen.length, 3, "the first try and two retries");
    assert.match(r.stderr, /\[stripe\] retry 1 after no answer/);
  } finally { net.restore(); }
});

// ── Debugging: --verbose, the table, error hints, and no secret anywhere ────────────────────────────

test("--verbose logs each call by its shape (no query), the table closes the run, and a refused call names its fix", async () => {
  const net = fakeNet((url) => (url.includes("/api/v1/logs") ? jsonRes(403, { errorSummary: "You do not have permission" }) : jsonRes(200, [])));
  try {
    const r = await runMain(["run", "--endpoint", "https://sos.example.test", "--source", "okta", "--dry-run", "--verbose"],
      { clients: { sleep: async () => {} }, env: { OKTA_DOMAIN: "acme.okta.com", OKTA_API_TOKEN: "00okta-secret-token-0123456789" } });
    assert.equal(r.code, EXIT.ok, r.stderr);
    assert.match(r.stderr, /\[okta\] GET acme\.okta\.com\/api\/v1\/logs -> 403 in \d+ ms/);
    assert.doesNotMatch(r.stderr, /\?|limit=|filter=/, "no query string in the call log");
    assert.match(r.stderr, /summary \(1 source\(s\), up to 4 at once\):\nsource +results +pass +fail +skipped +calls +retries +http errors +time +source status/);
    assert.match(r.stderr, /refused calls \(their checks were sent as skipped\):\n  okta\.system_log_available \[[^\]]+\]: HTTP 403 \(permission missing\); fix: run `collector doctor --config <file> --source okta`/);
  } finally { net.restore(); }
});

test("a source that throws names itself, its error and the doctor; --debug adds the stack", async () => {
  const boom = { name: "cloudflare", options: {}, emits: ["cloudflare.dnssec"], describe: () => "x", run: async () => { throw new Error("kaboom"); } };
  const c = capture({ sources: [boom] });
  assert.equal(await main(["run", "--endpoint", "https://sos.example.test", "--source", "cloudflare", "--dry-run", "--debug"], c.deps), EXIT.error);
  const err = c.stderr.join("\n");
  assert.match(err, /error in source cloudflare: kaboom; its 1 checks are sent as skipped and the run goes on\. To see why: run `collector doctor --config <file> --source cloudflare`/);
  assert.match(err, /Error: kaboom\n\s+at /);
  assert.match(err, /cloudflare +1 +0 +0 +1 +0 +0 +0 +[\d.]+ s +ERROR/);
});

test("no secret reaches stdout, stderr, the payload or the run report, even when a provider echoes the credential", async () => {
  const SECRETS = {
    OKTA_API_TOKEN: "00oktaSECRETtoken0123456789abcdef",
    GITHUB_TOKEN: ["github", "pat", "SECRET0123456789abcdefghijklmnop"].join("_"),
    CLOUDFLARE_API_TOKEN_READONLY: "cfSECRETtoken0123456789abcdefghij",
    STRIPE_API_KEY: ["rk", "live", "SECRET0123456789abcdef"].join("_"),
    PAGERDUTY_TOKEN: "pdSECRETtoken0123456789",
    AWS_ACCESS_KEY_ID: ["AKIA", "IOSFODNN7SECRET1"].join(""),
    AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY",
    ENTRA_CLIENT_SECRET: "entra~SECRET~0123456789abcdef",
  };
  // Every answer is a 403 that echoes the request's credential and URL, as a careless proxy or provider might.
  const net = fakeNet((url, init) => {
    const h = (init.headers ?? {}) as Record<string, string>;
    const echo = `denied: authorization=${h.authorization ?? h.Authorization ?? ""} x-api-key=${h["x-api-key"] ?? ""} url=${url} body=${String(init.body ?? "")}`;
    if (url.startsWith("https://login.microsoftonline.com/")) return jsonRes(400, { error: "invalid_client", error_description: echo });
    if (url.includes("amazonaws.com")) return new Response(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>${echo.replace(/[<&]/g, "")}</Message></Error></ErrorResponse>`, { status: 403 });
    return jsonRes(403, { message: echo, errorSummary: echo, errors: [{ message: echo }], error: { message: echo } });
  });
  try {
    const r = await runMain(["run", "--endpoint", "https://sos.example.test", "--source", "okta,github,cloudflare,stripe,pagerduty,aws,entra", "--github-org", "acme", "--dry-run", "--verbose", "--debug"],
      { clients: { sleep: async () => {} }, env: { OKTA_DOMAIN: "acme.okta.com", ENTRA_TENANT_ID: "t-1", ENTRA_CLIENT_ID: "c-1", ...SECRETS } });
    assert.ok(net.seen.length > 10, "the sources did call out");
    // The echoes did reach the results, cut: the test would catch a client that stopped cutting.
    assert.ok((r.stdout.match(/\[redacted\]/g) ?? []).length >= 4, "echoed credentials were cut from the results");
    const report = existsSync(join(r.dir, REPORT_FILE)) ? readFileSync(join(r.dir, REPORT_FILE), "utf8") : "";
    assert.ok(report.length > 0, "the run report was written");
    for (const [where, text] of [["stdout (payload)", r.stdout], ["stderr", r.stderr], ["run report", report]] as const) {
      for (const [name, value] of Object.entries(SECRETS)) assert.ok(!text.includes(value), `${name} reached ${where}`);
      assert.doesNotMatch(text, /AKIA[0-9A-Z]{16}/, `an AWS key id reached ${where}`);
      assert.doesNotMatch(text, /\b(Bearer|SSWS|Basic) [A-Za-z0-9._~+/=-]{12,}/, `an Authorization value reached ${where}`);
      assert.doesNotMatch(text, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, `a private key reached ${where}`);
    }
  } finally { net.restore(); }
});

// ── Smoke test: collector doctor ───────────────────────────────────────────────────────────────────

test("doctor: every source has a self-test", () => {
  for (const s of SOURCES) assert.ok(PROBES[s.name], `${s.name} has no doctor probe in src/doctor.ts`);
});

test("doctor: every source passes against the recorded replies, and nothing is sent or written", async () => {
  const s = e2eSetup();
  const r = await runMain(["doctor", ...s.args], { setup: s });
  assert.equal(r.code, EXIT.ok, r.stdout);
  assert.equal(r.posts, 0, "no push");
  assert.equal(r.channel, 0, "no check-in, no report sent");
  assert.ok(!existsSync(join(r.dir, REPORT_FILE)), "no run report written");
  assert.match(r.stdout, /^collector doctor: 43 source\(s\); read-only checks, nothing collected or sent/);
  assert.doesNotMatch(r.stdout, /\bFAIL\b/);
  assert.match(r.stdout, /okta\n  PASS  credentials +OKTA_DOMAIN/);
  assert.match(r.stdout, /doctor: \d+ passed, 0 failed, 1 skipped; ready for `collector run`/);
  for (const name of s.sources) assert.match(r.stdout, new RegExp(`^${name}$`, "m"));
});

test("doctor: a missing permission is a FAIL naming the scope to grant; a refused credential names the variables; exit 1", async () => {
  const net = fakeNet((url) => (url.includes("/api/v1/logs") ? jsonRes(403, { errorSummary: "The access token provided does not contain the required scopes." })
    : url.includes("api.github.com") ? jsonRes(401, { message: "Bad credentials" }) : jsonRes(200, [])));
  try {
    const r = await runMain(["doctor", "--source", "okta,github,stripe", "--github-org", "acme"],
      { clients: { sleep: async () => {} }, env: { OKTA_DOMAIN: "acme.okta.com", OKTA_ACCESS_TOKEN: "eyJ0eXAi.okta-access.token", GITHUB_TOKEN: "ghx-0123456789abcdef" } });
    assert.equal(r.code, EXIT.error);
    assert.match(r.stdout, /FAIL  GET \/api\/v1\/logs +HTTP 403: The access token provided does not contain the required scopes\..*\n +fix: grant okta\.logs\.read/);
    assert.match(r.stdout, /github\n  PASS  credentials[^\n]*\n  FAIL  GET \/orgs\/acme +HTTP 401[^\n]*\n +fix: the credential was refused: check GITHUB_TOKEN/);
    assert.equal(r.stdout.match(/GET \/orgs\/acme/g)?.length, 1, "after a 401 the other probes of that source are not tried");
    assert.match(r.stdout, /stripe\n  FAIL  credentials +STRIPE_API_KEY is not set[^\n]*\n +fix: set STRIPE_API_KEY/);
    assert.ok(net.seen.every((s) => s.method === "GET"), "GET only");
  } finally { net.restore(); }
});

test("doctor: files, executables and hosts are checked without running anything", async () => {
  const r = await runMain(["doctor", "--source", "trivy,prowler,stig,web", "--trivy-report", "/nonexistent/trivy.json", "--prowler-provider", "aws",
    "--prowler-bin", "/nonexistent/prowler", "--web-url", "https://www.example.ca/"], { clients: {} });
  assert.equal(r.code, EXIT.error);
  assert.match(r.stdout, /FAIL  --trivy-report +\/nonexistent\/trivy\.json: ENOENT/);
  assert.match(r.stdout, /FAIL  executable +\/nonexistent\/prowler: not on PATH/);
  assert.match(r.stdout, /FAIL  input +no --stig-target or --cinc-report given/);
  assert.match(r.stdout, /FAIL  --web-url +www\.example\.ca: no --web-proof\n +fix: give --web-proof www\.example\.ca=/);
  assert.equal(onPath("node", { PATH: process.env.PATH }) !== undefined, true);
  assert.equal(onPath("surely-not-a-command-0123", { PATH: process.env.PATH }), undefined);
});

test("doctor: judge words each status; usage errors exit 2", async () => {
  const j = (status: number) => judge("x.read", "GET /x", { status, message: `HTTP ${status}` }, "X_TOKEN", "the scope x.read");
  assert.equal(j(200).verdict, "pass");
  assert.match(j(403).fix!, /^grant the scope x\.read$/);
  assert.match(j(401).fix!, /check X_TOKEN/);
  assert.match(j(404).fix!, /not found/);
  assert.match(j(429).fix!, /rate limited/);
  assert.match(j(0).fix!, /no answer/);
  assert.match(j(503).fix!, /HTTP 503/);
  assert.equal((await runMain(["doctor"], { clients: {} })).code, EXIT.usage);
  assert.equal((await runMain(["doctor", "--source", "nope"], { clients: {} })).code, EXIT.usage);
});

// ── Pieces ─────────────────────────────────────────────────────────────────────────────────────────

test("the closing table and the refused-call lines", () => {
  const t = summaryTable([{ name: "okta", ms: 1234, pass: 3, fail: 1, skipped: 2, error: null, warnings: [] }, { name: "aws", ms: 50, pass: 0, fail: 0, skipped: 4, error: { message: "x", stack: "" }, warnings: [] }],
    new Map([["okta", { calls: 9, retries: 2, httpErrors: 1 }]]));
  assert.match(t[2], /^okta +6 +3 +1 +2 +9 +2 +1 +1\.2 s +read$/);
  assert.match(t[3], /^aws +4 +0 +0 +4 +0 +0 +0 +0\.1 s +ERROR$/);
  assert.match(t[5], /^total +10 +3 +1 +6 +9 +2 +1 +1\.2 s max$/);
  const lines = problemLines([
    { check: "okta.a", resource: "r", result: "skipped", detail: "", apiError: { status: 403, message: "m" } },
    { check: "okta.a", resource: "r2", result: "skipped", detail: "", apiError: { status: 403, message: "m" } },
    { check: "okta.b", resource: "r", result: "skipped", detail: "", apiError: { status: 401, message: "m" } },
    { check: "okta.c", resource: "r", result: "skipped", detail: "", apiError: { status: 404, message: "m" } },
    { check: "okta.d", resource: "r", result: "pass", detail: "" },
  ]);
  assert.equal(lines.length, 2);
  assert.match(lines[1], /okta\.b \[r\]: HTTP 401 \(credential refused\)/);
});

test("the recorder counts calls per source when sources overlap, and only while they run", async () => {
  const rec = new RunRecorder(() => NOW);
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response("{}", { status: 200 })) as typeof fetch;
  try {
    await Promise.all([
      rec.source("a", async () => { for (let i = 0; i < 3; i++) { await fetch("https://a.example/x"); await new Promise((r) => setTimeout(r, 2)); } }),
      rec.source("b", async () => { await new Promise((r) => setTimeout(r, 1)); await fetch("https://b.example/y"); }),
    ]);
    await fetch("https://c.example/z");   // outside any source: not counted, and the wrapper is gone
    assert.equal(rec.stats.get("a")!.calls, 3);
    assert.equal(rec.stats.get("b")!.calls, 1);
    assert.deepEqual(rec.callList().map((c) => `${c.source} ${c.host}`).sort(), ["a a.example", "b b.example"]);
  } finally { globalThis.fetch = original; }
});

// ── Prowler's OCSF file, streamed ───────────────────────────────────────────────────────────────────

const chunks = (text: string, size: number) => Readable.from(Array.from({ length: Math.ceil(text.length / size) }, (_, i) => text.slice(i * size, (i + 1) * size)));
const collect = async (it: AsyncIterable<string>) => { const out: string[] = []; for await (const x of it) out.push(x); return out; };

test("jsonArrayElements: elements split across any chunk boundary, with brackets, commas and escapes inside strings", async () => {
  const doc = `﻿ [ {"a":"x],[{\\"y"} ,  [1,[2]], "s,]\\\\", 3 , {"b":{"c":[]}} ]  \n`;
  for (const size of [1, 2, 3, 7, 1000]) {
    const els = await collect(jsonArrayElements(chunks(doc, size)));
    assert.deepEqual(els.map((e) => JSON.parse(e)), [{ a: "x],[{\"y" }, [1, [2]], "s,]\\", 3, { b: { c: [] } }], `chunk ${size}`);
  }
  assert.deepEqual(await collect(jsonArrayElements(chunks("[]", 1))), []);
  for (const bad of ["{}", "", "[1,]", "[,1]", "[1", "[1] x", "[1]]"]) {
    await assert.rejects(collect(jsonArrayElements(chunks(bad, 2))), /not JSON|not an OCSF array/, JSON.stringify(bad));
  }
});

test("parseOcsfFile gives exactly parseOcsf's results on the recorded Prowler output", async () => {
  const file = new URL("./fixtures/prowler/prowler_aws.ocsf.json", import.meta.url).pathname;
  const known = new Set([...loadCatalog().values()].filter((c) => c.source === "prowler").map((c) => c.id));
  const a = parseOcsf(readFileSync(file, "utf8"), "aws", known);
  const b = await parseOcsfFile(file, "aws", known);
  assert.deepEqual(b, a);
  assert.ok(a.results.length > 0);
});

test("a merged Prowler result keeps the first 1,000 characters of its details exactly, however many findings merge", () => {
  const f = (i: number) => ({ metadata: { event_code: "iam_root_mfa_enabled" }, status_code: "FAIL", status_detail: `finding ${i} ${"z".repeat(90)}`,
    resources: [{ uid: "arn:aws:iam::1:root" }], cloud: { account: { uid: "1" } }, unmapped: { provider: "aws" } });
  const many = Array.from({ length: 500 }, (_, i) => f(i));
  const { results } = parseOcsf(JSON.stringify(many), "aws", new Set(["prowler.aws.iam_root_mfa_enabled"]));
  const want = many.map((x) => x.status_detail).join(" | ").slice(0, 1000);
  assert.equal(results.length, 1);
  assert.equal(results[0].detail, want);
});
