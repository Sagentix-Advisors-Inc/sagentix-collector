// Health telemetry and structured diagnostics (collector 0.5.0; apps/sos-app/docs/COLLECTOR_CHANNEL.md sections 3 and 10):
// the classification of every code, the frames and endpoints a diagnostic may carry, each source's status, the
// health file beside the report, check-in/2's fields, report/2's per-source fields, and a test that fails if a
// secret, an email or a provider's own text reaches a diagnostic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, EXIT } from "../src/cli.ts";
import { generateKeyPair } from "../src/keys.ts";
import { checkin, type Channel } from "../src/channel.ts";
import { CODES, ConfigError, OWNER, SchemaError, classify, codeForError, codeForStatus, collectorFrames, dedupe, diagnosticLine, endpointOf, hintFor,
         primary, setPermissionLookup, type Diagnostic } from "../src/diagnostics.ts";
import { CHECKIN_FORMAT, HEALTH_FILE, HEALTH_FORMAT, SCHEDULE_ENV, _resetSkew, checkinHealth, clockSkew, mergeConnectors, noteCheckin, noteRun,
         observeDate, readHealth, scheduleOf, sourceHealth, statusOf, updateStateOf, vaultState, writeHealth, type ConnectorHealth } from "../src/health.ts";
import { REPORT_FILE, RunRecorder, type SourceReport } from "../src/report.ts";
import { permissionFor, PROBES } from "../src/doctor.ts";
import { okta } from "../src/sources/okta.ts";
import type { Result, Source } from "../src/types.ts";
import { capture, NOW } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "collector-health-"));
const { privatePem } = generateKeyPair();
const keyPath = join(dir, "key.pem");
writeFileSync(keyPath, privatePem, { mode: 0o600 });
const base = ["run", "--endpoint", "https://sos.example.test", "--key-id", "k-1", "--key", keyPath];
const bodyOf = (p: { init: RequestInit }) => JSON.parse(new TextDecoder().decode(p.init.body as Uint8Array));

function fakeNet(route: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => route(String(input instanceof Request ? input.url : input), init)) as typeof fetch;
  return () => { globalThis.fetch = original; };
}
const jsonRes = (status: number, body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const errWith = (msg: string, extra: Record<string, unknown> = {}, ctor: ErrorConstructor = Error) => Object.assign(new ctor(msg), extra);

// ── Classification ────────────────────────────────────────────────────────────────────────────────

test("every code, from a status, a thrown error or a header; each with its owner", () => {
  const table: [Diagnostic["code"], Diagnostic][] = [
    ["AUTH_REFUSED", classify(undefined, { source: "okta", status: 401 })],
    ["AUTH_REFUSED", classify(new Error("invalid_grant: Token has been expired or revoked."), { source: "google_workspace" })],
    ["AUTH_REFUSED", classify(new Error("token request to login.microsoftonline.com failed: HTTP 401 invalid_client"), { source: "entra" })],
    ["PERMISSION_MISSING", classify(undefined, { source: "okta", status: 403 })],
    ["CONFIG_INVALID", classify(new ConfigError("anything"), { source: "web" })],
    ["CONFIG_INVALID", classify(new Error("give --checkov-report <file>; run checkov first."), { source: "checkov" })],
    ["CONFIG_INVALID", classify(new Error("--prowler-provider is required: one or more of aws"), { source: "prowler" })],
    ["CONFIG_INVALID", classify(new Error("cannot run prowler (ENOENT); install it"), { source: "prowler" })],
    ["CONFIG_INVALID", classify(errWith("open x", { code: "ENOENT" }), { source: "lms" })],
    ["CONFIG_INVALID", classify(new Error("JIRA_BASE_URL must be an https URL"), { source: "jira" })],
    ["RATE_LIMITED", classify(undefined, { source: "github", status: 429 })],
    ["TIMEOUT", classify(errWith("The operation was aborted due to timeout", { name: "TimeoutError" }), { source: "aws" })],
    ["TIMEOUT", classify(new Error("no answer from api.stripe.com within 60 s (--http-timeout)"), { source: "stripe" })],
    ["TIMEOUT", classify(undefined, { source: "stripe", status: 0, timedOut: true })],
    ["TIMEOUT", classify(undefined, { source: "stripe", status: 408 })],
    ["TIMEOUT", classify(errWith("x", { code: "ETIMEDOUT" }), { source: "aws" })],
    ["NETWORK", classify(errWith("fetch failed", { cause: errWith("getaddrinfo", { code: "ENOTFOUND" }) }, TypeError as ErrorConstructor), { source: "okta" })],
    ["NETWORK", classify(errWith("fetch failed", {}, TypeError as ErrorConstructor), { source: "okta" })],
    ["NETWORK", classify(undefined, { source: "okta", status: 0 })],
    ["NETWORK", classify(undefined, { source: "okta", status: 407 })],
    ["PROVIDER_5XX", classify(undefined, { source: "jamf", status: 503 })],
    ["PROVIDER_5XX", classify(new Error("token request to login.microsoftonline.com failed: HTTP 502 x"), { source: "entra" })],
    ["API_CHANGED", classify(undefined, { source: "github", status: 404 })],
    ["API_CHANGED", classify(undefined, { source: "github", status: 410 })],
    ["API_CHANGED", classify(undefined, { source: "github", status: 422 })],
    ["API_CHANGED", classify(undefined, { source: "okta", status: 200, headers: new Headers({ deprecation: "@1767225600" }) })],
    ["API_CHANGED", classify(undefined, { source: "okta", status: 200, headers: { Sunset: "Sat, 01 May 2027 00:00:00 GMT" } })],
    ["API_CHANGED", classify(new SchemaError("users[] is missing"), { source: "okta" })],
    ["PARSE_ERROR", classify(new SyntaxError("Unexpected token < in JSON at position 0"), { source: "jamf" })],
    ["PARSE_ERROR", classify(new TypeError("Cannot read properties of undefined (reading 'id')"), { source: "okta" })],
    ["PARSE_ERROR", classify(new Error("x.json is not a Checkov JSON report (no check_type)"), { source: "checkov" })],
    ["INTERNAL", classify(new RangeError("Maximum call stack size exceeded"), { source: "okta" })],
    ["INTERNAL", classify("a string thrown", { source: "okta" })],
    ["INTERNAL", classify(undefined, {})],
  ];
  for (const [want, d] of table) {
    assert.equal(d.code, want, JSON.stringify(d));
    assert.equal(d.owner, OWNER[want]);
    assert.ok(d.hint.length > 20 && !/undefined/.test(d.hint), d.hint);
  }
  assert.deepEqual(new Set(table.map(([c]) => c)), new Set(CODES), "the table covers every code");
  assert.equal(OWNER.AUTH_REFUSED, "customer"); assert.equal(OWNER.API_CHANGED, "sagentix"); assert.equal(OWNER.NETWORK, "provider");
  assert.equal(classify(undefined, {}).source, "collector");
  assert.equal(codeForStatus(0), "NETWORK");
  assert.equal(codeForError({ not: "an error" }), "INTERNAL");
  for (const c of CODES) assert.ok(hintFor(c, "okta").includes("okta"), c);
  assert.match(hintFor("PROVIDER_5XX", "jamf", { status: 503 }), /HTTP 503/);
  assert.match(hintFor("PERMISSION_MISSING", "okta", { permission: "okta.logs.read" }), /^Grant okta\.logs\.read, then run `collector doctor/);
});

test("a diagnostic carries the templated endpoint, the status, a provider page and collector frames; never a message", () => {
  const e = new TypeError("Cannot read properties of undefined (reading 'id') for jane@acme.example with token 00SECRETSECRET");
  const d = classify(e, { source: "okta", check: "okta.mfa", status: 403, method: "get", url: "https://acme.okta.com/api/v1/users/00u1234567890abcdefgh/factors?filter=x&token=abc",
                          providerDoc: "https://developer.okta.com/docs/api/" });
  assert.equal(d.endpoint, "GET acme.okta.com/api/v1/users/:id/factors");
  assert.equal(d.httpStatus, 403);
  assert.equal(d.check, "okta.mfa");
  assert.equal(d.providerDoc, "https://developer.okta.com/docs/api/");
  assert.ok(d.frames.every((f) => f.startsWith("src/")), "an error made in a test has no collector frame");
  const text = JSON.stringify(d);
  for (const leak of ["jane", "SECRET", "Cannot read", "filter=", "token=abc", "00u1234567890abcdefgh"]) assert.ok(!text.includes(leak), leak);
  // A provider page that is not https, and a status of 0, are left out.
  const n = classify(undefined, { source: "okta", status: 0, providerDoc: "javascript:alert(1)" });
  assert.equal(n.providerDoc, undefined);
  assert.equal(n.httpStatus, undefined);
  assert.equal(endpointOf("GET", "not a url"), undefined);
  assert.equal(endpointOf(undefined, "https://h.example/a/12345"), "GET h.example/a/:id");
  assert.equal(endpointOf("GET", undefined), undefined);
});

test("frames: only this package's src/, as file:line:function, at most 8; never node_modules, tests or Node's own", () => {
  const root = "/opt/collector";
  const stack = [
    "TypeError: Cannot read properties of undefined (reading 'id') at jane@acme.example",
    "    at parseUsers (file:///opt/collector/src/sources/okta.ts:120:15)",
    "    at async Object.run (/opt/collector/src/sources/okta.ts:214:9)",
    "    at /opt/collector/src/cli.ts:300:20",
    "    at new Thing (file:///opt/collector/src/x.ts:1:1)",
    "    at helper (file:///opt/collector/node_modules/ajv/dist/ajv.js:10:1)",
    "    at t (file:///opt/collector/test/health.test.ts:10:1)",
    "    at process.processTicksAndRejections (node:internal/process/task_queues:105:5)",
    "    at weird (file:///%E0%A4%A/src/x.ts:1:1)",
    ...Array.from({ length: 12 }, (_, i) => `    at f${i} (/opt/collector/src/y.ts:${i + 1}:1)`),
  ].join("\n");
  const f = collectorFrames(stack, root);
  assert.deepEqual(f.slice(0, 4), ["src/sources/okta.ts:120:parseUsers", "src/sources/okta.ts:214:run", "src/cli.ts:300:<anonymous>", "src/x.ts:1:Thing"]);
  assert.equal(f.length, 8);
  assert.ok(!f.some((x) => /node_modules|test\/|node:|jane/.test(x)));
  assert.deepEqual(collectorFrames(undefined), []);
  // The real stack of an error thrown here names this package's own frames only.
  const own = classify(new Error("x"), { source: "okta" }).frames;
  assert.ok(own.every((x) => x.startsWith("src/")), own.join(","));
});

test("primary, dedupe and the output line", () => {
  const a = classify(undefined, { source: "okta", status: 503 }), b = classify(undefined, { source: "okta", status: 403, check: "okta.x" });
  assert.equal(primary([a, b])!.code, "PERMISSION_MISSING");
  assert.equal(primary([]), undefined);
  assert.equal(dedupe([a, a, b]).length, 2);
  assert.equal(dedupe([a, b], 1).length, 1);
  assert.match(diagnosticLine(b), /^ {2}okta \[okta\.x\]: PERMISSION_MISSING \(yours to fix\), HTTP 403; A permission is missing/);
  assert.match(diagnosticLine(a), /PROVIDER_5XX \(transient\)/);
  assert.match(diagnosticLine(classify(new SyntaxError("x"), { source: "jamf", method: "GET", url: "https://j.example/api" })), /PARSE_ERROR \(Sagentix fixes it\), GET j\.example\/api;/);
});

test("the doctor's permission names a refused call's grant; unknown sources and paths name none", () => {
  assert.equal(permissionFor("okta", "/api/v1/logs"), "okta.logs.read");
  assert.equal(permissionFor("okta", "/api/v1/nothing"), undefined);
  assert.equal(permissionFor("no-such-source", "/x"), undefined);
  assert.equal(permissionFor("cloudflare", "/zones"), undefined, "not a REST probe");
  // github's paths need --github-org: without it the probe names only /rate_limit.
  assert.equal(permissionFor("github", "/orgs/acme/members"), undefined);
  // A lookup that throws names nothing, and the diagnostic still comes.
  try {
    setPermissionLookup(() => { throw new Error("x"); });
    const d = classify(undefined, { source: "okta", status: 403, url: "https://a.okta.com/api/v1/logs" });
    assert.equal(d.code, "PERMISSION_MISSING");
    assert.match(d.hint, /^A permission is missing/);
  } finally { setPermissionLookup(permissionFor); }
  const d = classify(undefined, { source: "okta", status: 403, method: "GET", url: "https://acme.okta.com/api/v1/logs?limit=1" });
  assert.match(d.hint, /^Grant okta\.logs\.read/);
});

// ── Each source's status ─────────────────────────────────────────────────────────────────────────

const rep = (o: Partial<SourceReport> = {}): SourceReport => ({ name: "okta", ms: 1, pass: 0, fail: 0, skipped: 0, error: null, warnings: [], ...o });

test("status: healthy, degraded, failing, unconfigured and skipped", () => {
  const perm = classify(undefined, { source: "okta", status: 403 }), cfg = classify(new ConfigError("x"), { source: "okta" });
  assert.equal(statusOf(rep({ pass: 2 }), []), "healthy");
  assert.equal(statusOf(rep({ pass: 2, skipped: 1 }), [perm]), "degraded");
  assert.equal(statusOf(rep({ skipped: 3 }), [perm]), "failing");
  assert.equal(statusOf(rep({ pass: 3, error: { message: "x", stack: "" } }), []), "failing");
  assert.equal(statusOf(rep({ skipped: 3 }), [cfg]), "unconfigured");
  assert.equal(statusOf(rep({ skipped: 3 }), []), "unconfigured");
  assert.equal(statusOf(rep(), []), "skipped");
});

test("sourceHealth: diagnostics from a throw, refused calls and deprecations; lastSuccessAt carried; the report entry gains v2 fields", async () => {
  const rec = new RunRecorder(() => NOW);
  const restore = fakeNet((url) => {
    if (url.includes("/denied")) return jsonRes(403, { message: "denied for jane@acme.example" });
    if (url.includes("/old")) return jsonRes(200, {}, { deprecation: "@1767225600", sunset: "Sat, 01 May 2027 00:00:00 GMT" });
    if (url.includes("/gone")) return jsonRes(410, {});
    if (url.includes("/down")) throw new TypeError("fetch failed");
    return jsonRes(200, {});
  });
  const results: Result[] = [
    { check: "okta.a", resource: "r", result: "pass", detail: "" },
    { check: "okta.b", resource: "r", result: "skipped", detail: "", apiError: { status: 403, message: "denied for jane@acme.example" } },
    { check: "github.x", resource: "r", result: "skipped", detail: "", apiError: { status: 403, message: "not okta's" } },
  ];
  try {
    await rec.source("okta", async () => { await fetch("https://acme.okta.com/api/v1/denied"); await fetch("https://acme.okta.com/api/v1/old"); await fetch("https://acme.okta.com/gone"); });
    await rec.source("jamf", async () => { await fetch("https://j.example/down"); });
    await rec.source("empty", async () => []);
    await rec.source("quiet", async () => []);
  } finally { restore(); }
  rec.sources.find((s) => s.name === "okta")!.pass = 1;
  rec.sources.find((s) => s.name === "okta")!.skipped = 1;
  rec.sources.find((s) => s.name === "empty")!.skipped = 2;
  const previous: ConnectorHealth[] = [{ source: "jamf", status: "healthy", lastRunAt: "2026-10-01T00:00:00.000Z", lastSuccessAt: "2026-10-01T00:00:00.000Z",
    results: { pass: 1, fail: 0, skipped: 0 }, calls: 1, retries: 0, httpErrors: {} }];
  const h = sourceHealth(rec, ["okta", "jamf", "empty", "quiet", "not-run"], results, NOW, previous);
  assert.deepEqual(h.map((x) => [x.source, x.status]), [["okta", "degraded"], ["jamf", "failing"], ["empty", "unconfigured"], ["quiet", "skipped"]]);
  const o = h[0];
  assert.equal(o.lastSuccessAt, NOW.toISOString());
  assert.deepEqual(o.httpErrors, { "403": 1, "410": 1 });
  assert.equal(o.calls, 3);
  assert.equal(o.error!.code, "PERMISSION_MISSING");
  assert.equal(o.error!.endpoint, "GET acme.okta.com/api/v1/denied");
  const okRep = rec.sources.find((s) => s.name === "okta")!;
  assert.deepEqual(okRep.diagnostics!.map((d) => d.code).sort(), ["API_CHANGED", "API_CHANGED", "PERMISSION_MISSING"]);
  assert.equal(okRep.status, "degraded");
  assert.equal(okRep.retries, 0);
  // jamf threw a network error: its diagnostic names the call that got no answer; its last success is the earlier one.
  assert.equal(h[1].error!.code, "NETWORK");
  assert.equal(h[1].error!.endpoint, "GET j.example/down");
  assert.equal(h[1].lastSuccessAt, "2026-10-01T00:00:00.000Z");
  assert.equal(h[2].error!.code, "CONFIG_INVALID");
  assert.equal(h[3].lastSuccessAt, null);
  assert.ok(!JSON.stringify(h).includes("jane"));
  // A source whose list was not a list (cli.ts sets the error itself, nothing thrown) classifies as INTERNAL.
  const r2 = new RunRecorder(() => NOW);
  await r2.source("x", async () => 1);
  r2.sources[0].error = { message: "the source returned no list of results", stack: "" };
  assert.equal(sourceHealth(r2, ["x"], [], NOW)[0].error!.code, "INTERNAL");
  assert.deepEqual(mergeConnectors(previous, h).map((c) => c.source), ["jamf", "okta", "empty", "quiet"]);
});

// ── The health file and the check-in's fields ─────────────────────────────────────────────────────

test("the health file: written 0600, read back, ignored when corrupt or not ours; a write that fails is a warning", () => {
  const d = mkdtempSync(join(tmpdir(), "collector-hf-"));
  assert.deepEqual(readHealth(d, NOW).connectors, []);
  noteRun(d, [{ source: "okta", status: "healthy", lastRunAt: NOW.toISOString(), lastSuccessAt: NOW.toISOString(), results: { pass: 1, fail: 0, skipped: 0 }, calls: 1, retries: 0, httpErrors: {} }], NOW);
  const file = join(d, HEALTH_FILE);
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(readHealth(d, NOW).format, HEALTH_FORMAT);
  assert.equal(readHealth(d, NOW).connectors[0].source, "okta");
  noteCheckin(d, { action: "update", wrote: "/x/ref", warnings: [] }, NOW);
  assert.deepEqual(readHealth(d, NOW).lastCheckin, { action: "update", wrote: true, at: NOW.toISOString() });
  noteCheckin(d, { action: "none", warnings: [] }, NOW, false);
  assert.equal(readHealth(d, NOW).lastCheckin!.action, "update", "a dry run writes nothing");
  writeFileSync(file, "not json");
  assert.deepEqual(readHealth(d, NOW).connectors, []);
  writeFileSync(file, JSON.stringify({ format: "other/1", connectors: [] }));
  assert.equal(readHealth(d, NOW).lastCheckin, null);
  const warned: string[] = [];
  writeHealth(join(d, "no", "such", "dir"), readHealth(d, NOW), (s) => warned.push(s));
  assert.match(warned[0], /^warning: cannot write .*ENOENT/);
  writeHealth(join(d, "no", "such", "dir"), readHealth(d, NOW));
});

test("vault state, update state and the schedule", () => {
  assert.equal(vaultState(false, undefined), "missing");
  assert.equal(vaultState(true, undefined), "locked");
  const s = { sealKey: null, protection: null, error: null, entries: [], envFile: [], refs: {}, credentials: {} };
  assert.equal(vaultState(true, { ...s, error: "cannot open" }), "locked");
  assert.equal(vaultState(true, s), "missing");
  assert.equal(vaultState(true, { ...s, sealKey: "k" }), "ok");
  assert.equal(updateStateOf(null), "unknown");
  const at = NOW.toISOString();
  assert.equal(updateStateOf({ action: "none", wrote: false, at }), "current");
  assert.equal(updateStateOf({ action: "update", wrote: true, at }), "pending-restart");
  assert.equal(updateStateOf({ action: "update", wrote: false, at }), "refused");
  assert.equal(updateStateOf({ action: "approval-needed", wrote: false, at }), "approval-needed");
  assert.equal(updateStateOf({ action: "notify", wrote: false, at }), "notify");
  assert.equal(updateStateOf({ action: "failed", wrote: false, at }), "unknown");
  assert.deepEqual(scheduleOf("agent", "docker", {}, NOW), { kind: "agent", intervalMinutes: 360, nextExpectedAt: "2026-10-15T18:00:00.000Z" });
  assert.equal(scheduleOf("run", "github", {}, NOW).kind, "ci");
  assert.equal(scheduleOf("run", "mac", {}, NOW).intervalMinutes, 1440);
  assert.equal(scheduleOf("run", "mac", { [SCHEDULE_ENV]: "60" }, NOW).intervalMinutes, 60);
  assert.equal(scheduleOf("run", "mac", { [SCHEDULE_ENV]: "1" }, NOW).intervalMinutes, 1440, "below 5 minutes: the default");
});

test("the clock skew comes from the Date header of sos-app's answers", async () => {
  _resetSkew();
  const f = observeDate((async () => new Response("{}", { headers: { date: "Thu, 15 Oct 2026 11:59:30 GMT" } })) as unknown as typeof fetch, () => NOW);
  await f("https://sos.example.test/x");
  assert.equal(clockSkew(), 30_000);
  await observeDate((async () => new Response("{}")) as unknown as typeof fetch)("https://x");
  assert.equal(clockSkew(), 30_000, "an answer without Date leaves the last skew");
  const h = checkinHealth({ dir: mkdtempSync(join(tmpdir(), "collector-ck-")), env: {}, mode: "run", runner: "server", now: NOW, vault: "missing", sources: ["okta"], uptime: 12.6 });
  assert.equal(h.agent.clockSkewMs, 30_000);
  assert.equal(h.agent.uptime, 13);
  assert.deepEqual(h.connectors, [{ source: "okta", status: "skipped", lastRunAt: null, lastSuccessAt: null, results: { pass: 0, fail: 0, skipped: 0 }, calls: 0, retries: 0, httpErrors: {} }]);
  _resetSkew();
  assert.equal(checkinHealth({ dir, env: {}, mode: "agent", runner: "docker", now: NOW, vault: "ok" }).agent.clockSkewMs, null);
});

test("check-in/2: the agent's health and each configured connector's last state, from the health file", async () => {
  const d = mkdtempSync(join(tmpdir(), "collector-ci2-"));
  noteRun(d, [{ source: "okta", status: "degraded", lastRunAt: NOW.toISOString(), lastSuccessAt: NOW.toISOString(), results: { pass: 1, fail: 0, skipped: 1 }, calls: 2, retries: 1,
    httpErrors: { "403": 1 }, error: classify(undefined, { source: "okta", status: 403 }) }], NOW);
  noteCheckin(d, { action: "approval-needed", warnings: [] }, NOW);
  const sent: Record<string, unknown>[] = [];
  const c: Channel = { origin: "https://sos.example.test", keyId: "k-1", pem: privatePem, dir: d, runner: "mac", mode: "run", env: {}, now: () => NOW,
    fetch: (async (_u: string, init: RequestInit) => { sent.push(JSON.parse(new TextDecoder().decode(init.body as Uint8Array))); return new Response(JSON.stringify({ action: "none" })); }) as unknown as typeof fetch };
  await checkin(c, { write: true, log: () => {}, sources: ["okta", "jamf"] });
  const b = sent[0] as { format: string; agent: Record<string, unknown>; connectors: ConnectorHealth[] };
  assert.equal(b.format, CHECKIN_FORMAT);
  assert.deepEqual(Object.keys(b.agent).sort(), ["clockSkewMs", "schedule", "updateState", "uptime", "vault"]);
  assert.equal(b.agent.vault, "missing");
  assert.equal(b.agent.updateState, "approval-needed");
  assert.deepEqual(b.agent.schedule, { kind: "cron", intervalMinutes: 1440, nextExpectedAt: "2026-10-16T12:00:00.000Z" });
  assert.deepEqual(b.connectors.map((x) => [x.source, x.status]), [["okta", "degraded"], ["jamf", "skipped"]]);
  assert.equal(b.connectors[0].error!.code, "PERMISSION_MISSING");
});

// ── End to end: report/2, the health file, the closing lines, the agent ───────────────────────────

test("a run sends report/2 with each source's health, keeps it beside the report, and prints the diagnostics", async () => {
  const flaky: Source = {
    name: "okta", options: {}, emits: okta.emits.slice(0, 2), describe: () => "t",
    run: async () => {
      await fetch("https://acme.okta.com/api/v1/logs?since=x");
      await fetch("https://acme.okta.com/api/v1/old");
      return [
        { check: okta.emits[0], resource: "org", result: "pass", detail: "ok" },
        { check: okta.emits[1], resource: "org", result: "skipped", detail: "logs not readable: HTTP 403", apiError: { status: 403, message: "Forbidden for jane@acme.example" } },
      ];
    },
  };
  const restore = fakeNet((url) => (url.includes("/logs") ? jsonRes(403, { errorSummary: "Forbidden for jane@acme.example" }) : jsonRes(200, {}, { deprecation: "true" })));
  const cfgDir = mkdtempSync(join(tmpdir(), "collector-run2-"));
  const cfg = join(cfgDir, "sagentix-collector.config.json");
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", keyFile: keyPath, sources: { okta: {} } }));
  const c = capture({ sources: [flaky], env: { OKTA_API_TOKEN: "00SuperSecretValue1234" } });
  try { assert.equal(await main(["run", "--config", cfg], c.deps), EXIT.ok, c.stderr.join("\n")); } finally { restore(); }
  const reports = c.channel.filter((p) => p.url.endsWith("/api/collect/report"));
  const r = bodyOf(reports[0]);
  assert.equal(r.format, "sagentix-run-report/2");
  const s = r.sources.find((x: { name: string }) => x.name === "okta");
  assert.equal(s.status, "degraded");
  assert.deepEqual(s.httpErrors, { "403": 1 });
  assert.equal(s.calls, 2);
  assert.deepEqual(s.diagnostics.map((d: Diagnostic) => d.code).sort(), ["API_CHANGED", "PERMISSION_MISSING"]);
  const perm = s.diagnostics.find((d: Diagnostic) => d.code === "PERMISSION_MISSING");
  assert.equal(perm.endpoint, "GET acme.okta.com/api/v1/logs");
  assert.match(perm.hint, /^Grant okta\.logs\.read/);
  // The health file beside the config, and the next check-in carries it.
  const hf = JSON.parse(readFileSync(join(cfgDir, HEALTH_FILE), "utf8"));
  assert.equal(hf.connectors[0].status, "degraded");
  assert.equal(hf.lastCheckin.action, "none");
  const err = c.stderr.join("\n");
  assert.match(err, /diagnostics \(sent to sos-app with the report; never a provider's own text\):\n {2}okta: API_CHANGED \(Sagentix fixes it\), HTTP 200, GET acme\.okta\.com\/api\/v1\/old;/);
  const c2 = capture({ sources: [flaky] });
  const restore2 = fakeNet(() => jsonRes(200, {}));
  try { await main(["run", "--config", cfg], c2.deps); } finally { restore2(); }
  const ci = bodyOf(c2.channel.find((p) => p.url.endsWith("/api/collect/checkin"))!);
  assert.equal(ci.connectors[0].status, "degraded", "the check-in carries the last run's state");
  assert.equal(ci.agent.updateState, "current");
  // A dry run writes no health.
  const c3 = capture({ sources: [flaky] });
  const restore3 = fakeNet(() => jsonRes(200, {}));
  try { await main([...base, "--source", "okta", "--dry-run"], c3.deps); } finally { restore3(); }
  assert.ok(!existsSync(join(c3.dir, HEALTH_FILE)));
  assert.ok(existsSync(join(c3.dir, REPORT_FILE)));
});

test("no secret, email or provider text reaches a diagnostic, the health file or the check-in, even when every provider echoes them", async () => {
  const SECRETS = {
    OKTA_API_TOKEN: "00oktaSECRETtoken0123456789abcdef",
    GITHUB_TOKEN: ["github", "pat", "SECRET0123456789abcdefghijklmnop"].join("_"),
    STRIPE_API_KEY: ["rk", "live", "SECRET0123456789abcdef"].join("_"),
    PAGERDUTY_TOKEN: "pdSECRETtoken0123456789",
    ENTRA_CLIENT_SECRET: "entra~SECRET~0123456789abcdef",
  };
  const PROVIDER = "PROVIDER-SAYS-zq9";
  const restore = fakeNet((url, init) => {
    const h = (init.headers ?? {}) as Record<string, string>;
    const echo = `${PROVIDER} denied jane.doe@acme.example: authorization=${h.authorization ?? h.Authorization ?? ""} url=${url}`;
    if (url.startsWith("https://login.microsoftonline.com/")) return jsonRes(400, { error: "invalid_client", error_description: echo });
    if (url.includes("pagerduty")) return jsonRes(500, { error: { message: echo } });
    if (url.includes("stripe")) throw Object.assign(new TypeError(`fetch failed ${echo}`), { cause: Object.assign(new Error(echo), { code: "ECONNRESET" }) });
    return jsonRes(403, { message: echo, errorSummary: echo, errors: [{ message: echo }] });
  });
  const cfgDir = mkdtempSync(join(tmpdir(), "collector-leak-"));
  const cfg = join(cfgDir, "sagentix-collector.config.json");
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", keyFile: keyPath,
    sources: { okta: {}, github: { "github-org": "acme" }, stripe: {}, pagerduty: {}, entra: {} } }));
  const c = capture({ clients: { sleep: async () => {} }, env: { OKTA_DOMAIN: "acme.okta.com", ENTRA_TENANT_ID: "t-1", ENTRA_CLIENT_ID: "c-1", ...SECRETS } });
  try { await main(["run", "--config", cfg], c.deps); } finally { restore(); }
  const report = bodyOf(c.channel.find((p) => p.url.endsWith("/api/collect/report"))!);
  const diagnostics = report.sources.flatMap((s: SourceReport) => s.diagnostics ?? []);
  assert.ok(diagnostics.length >= 5, JSON.stringify(diagnostics.map((d: Diagnostic) => d.code)));
  assert.ok(new Set(diagnostics.map((d: Diagnostic) => d.owner)).size >= 2);
  const health = readFileSync(join(cfgDir, HEALTH_FILE), "utf8");
  const c2 = capture({ clients: { sleep: async () => {} } });
  const restore2 = fakeNet(() => jsonRes(200, {}));
  try { await checkin({ origin: "https://sos.example.test", keyId: "k-1", pem: privatePem, dir: cfgDir, runner: "server", mode: "run", env: {}, now: () => NOW, fetch: c2.deps.channel! }, { write: false, log: () => {}, sources: ["okta"] }); }
  finally { restore2(); }
  const checkinBody = new TextDecoder().decode(c2.channel[0].init.body as Uint8Array);
  for (const [where, text] of [["diagnostics", JSON.stringify(diagnostics)], ["health file", health], ["check-in", checkinBody]] as const) {
    for (const [name, value] of Object.entries(SECRETS)) assert.ok(!text.includes(value), `${name} reached ${where}`);
    assert.ok(!text.includes(PROVIDER), `provider text reached ${where}`);
    assert.doesNotMatch(text, /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}/, `an email reached ${where}`);
    assert.doesNotMatch(text, /invalid_client|authorization=|denied/, `provider words reached ${where}`);
  }
});

test("the doctor names each failing check's code", async () => {
  const restore = fakeNet((url) => (url.includes("/api/v1/logs") ? jsonRes(403, {}) : jsonRes(200, [])));
  const c = capture({ clients: { sleep: async () => {} }, env: { OKTA_DOMAIN: "acme.okta.com", OKTA_API_TOKEN: "00okta-secret-token-0123456789" } });
  try { assert.equal(await main(["doctor", "--source", "okta"], c.deps), EXIT.error); } finally { restore(); }
  const out = c.stdout.join("\n");
  assert.match(out, /FAIL {2}GET \/api\/v1\/logs .*\n {8}fix: grant okta\.logs\.read\n {8}code: PERMISSION_MISSING \(yours to fix\)/);
  // A probe that throws is classified too.
  const saved = PROBES.okta;
  PROBES.okta = async () => { throw new SyntaxError("bad"); };
  try {
    const c2 = capture({ env: {} });
    await main(["doctor", "--source", "okta"], c2.deps);
    assert.match(c2.stdout.join("\n"), /code: PARSE_ERROR \(Sagentix fixes it\)/);
  } finally { PROBES.okta = saved; }
});
