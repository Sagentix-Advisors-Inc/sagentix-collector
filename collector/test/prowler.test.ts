// Prowler as an engine: OCSF parsing (fixture written by Prowler 5.45.0's own OCSF writer from real check
// metadata), unknown checks dropped, the subprocess path with a fake `prowler`, and push splitting.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { EXIT, main } from "../src/cli.ts";
import { DEFAULT_CATALOG_DIR, loadCatalog } from "../src/catalog.ts";
import { generateKeyPair } from "../src/keys.ts";
import { MAX_RESULTS, splitResults } from "../src/payload.ts";
import { REFUSED_ARGS, authArgs, parseOcsf, prowler, prowlerEnv, splitArgs } from "../src/sources/prowler.ts";
import type { Result, Source } from "../src/types.ts";
import { capture } from "./helpers.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/prowler/prowler_aws.ocsf.json", import.meta.url));
const catalog = loadCatalog();
const known = new Set([...catalog.values()].filter((c) => c.source === "prowler").map((c) => c.id));
// Since 2026-11-01 every Prowler check is catalogued, so the drop path is tested on a trimmed copy: two AWS checks of
// the fixture and the whole GitHub catalogue taken out.
const DROPPED = ["prowler.aws.account_maintain_current_contact_details", "prowler.aws.iam_avoid_root_usage"];
const trimmed = new Set([...known].filter((id) => !DROPPED.includes(id)));
const TRIM = mkdtempSync(join(tmpdir(), "collector-prowler-catalog-"));
for (const f of readdirSync(DEFAULT_CATALOG_DIR).filter((f) => f.endsWith(".json") && f !== "prowler_github.json")) {
  const doc = JSON.parse(readFileSync(join(DEFAULT_CATALOG_DIR, f), "utf8"));
  if (f === "prowler_aws.json") doc.checks = doc.checks.filter((c: { id: string }) => !DROPPED.includes(c.id));
  writeFileSync(join(TRIM, f), JSON.stringify(doc));
}
const dir = mkdtempSync(join(tmpdir(), "collector-prowler-"));
const { privatePem, publicKey } = generateKeyPair();
const keyPath = join(dir, "key.pem");
writeFileSync(keyPath, privatePem, { mode: 0o600 });
const dry = ["run", "--endpoint", "https://sos.example.test", "--source", "prowler", "--prowler-provider", "aws", "--dry-run", "--catalog", TRIM];
const push = ["run", "--endpoint", "https://sos.example.test", "--key-id", "k-1", "--key", keyPath];

async function verify(sigB64: string, body: Uint8Array<ArrayBuffer>) {
  const key = await crypto.subtle.importKey("raw", Buffer.from(publicKey, "base64"), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(sigB64, "base64"), body);
}

// ── Catalogue ─────────────────────────────────────────────────────────────────────────────────────

test("every Prowler catalogue shares the source prowler and the source emits exactly those checks", () => {
  assert.ok(known.size > 100);
  assert.deepEqual([...prowler.emits].sort(), [...known].sort());
  for (const id of known) assert.match(id, /^prowler\.(aws|azure|gcp|kubernetes|m365|github|googleworkspace|okta|cloudflare)\.[A-Za-z0-9_]+$/);
});

// ── OCSF → results ────────────────────────────────────────────────────────────────────────────────

test("OCSF findings map to results: PASS, FAIL, muted and MANUAL; unknown checks are dropped and counted", () => {
  const { results, summary } = parseOcsf(readFileSync(FIXTURE, "utf8"), "aws", trimmed);
  const by = new Map(results.map((r) => [`${r.check}|${r.resource}`, r]));
  assert.equal(summary.findings, 9);
  // account_maintain_current_contact_details (MANUAL) and iam_avoid_root_usage are not in the catalogue.
  assert.equal(summary.dropped, 2);
  assert.deepEqual(summary.droppedChecks, ["prowler.aws.account_maintain_current_contact_details", "prowler.aws.iam_avoid_root_usage"]);
  assert.equal(results.length, 7);
  assert.deepEqual(by.get("prowler.aws.iam_root_mfa_enabled|arn:aws:iam::123456789012:root [us-east-1]"),
    { check: "prowler.aws.iam_root_mfa_enabled", resource: "arn:aws:iam::123456789012:root [us-east-1]", result: "pass", detail: "MFA is enabled for root account." });
  assert.equal(by.get("prowler.aws.s3_bucket_default_encryption|arn:aws:s3:::logs-example [us-east-1]")!.result, "fail");
  assert.equal(by.get("prowler.aws.s3_bucket_default_encryption|arn:aws:s3:::app-data [ca-central-1]")!.result, "pass");
  // The region is already in an EC2 ARN, so it is not repeated.
  assert.equal(by.get("prowler.aws.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22|arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc")!.result, "fail");
  // Muted (OCSF status "Suppressed") goes as skipped even though Prowler's status_code says PASS.
  assert.equal(by.get("prowler.aws.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22|arn:aws:ec2:us-east-1:123456789012:security-group/sg-0def")!.result, "skipped");
  assert.equal(summary.muted, 1);
  for (const r of results) assert.ok(known.has(r.check) && r.detail.length <= 1000 && r.resource.length <= 300);
});

test("MANUAL becomes skipped; findings on one check and resource merge, fail first; email addresses are cut", () => {
  const f = (status_code: string, detail: string, uid = "arn:aws:iam::123456789012:user/x") => ({
    metadata: { event_code: "iam_root_mfa_enabled" }, status: "New", status_code, status_detail: detail,
    resources: [{ uid, region: "us-east-1" }], cloud: { account: { uid: "123456789012" } }, unmapped: { provider: "aws" },
  });
  const { results, summary } = parseOcsf(JSON.stringify([
    f("PASS", "ok for alice@example.com"), f("FAIL", "not ok"), f("PASS", "ok for alice@example.com"), f("MANUAL", "look", "arn:other"),
    { metadata: { event_code: "made_up_check" }, status_code: "FAIL" },
  ]), "aws", known);
  assert.equal(results.length, 2);
  assert.equal(results[0].result, "fail");
  assert.equal(results[0].detail, "ok for [email] | not ok");
  assert.equal(results[1].result, "skipped");
  assert.equal(summary.merged, 2);
  assert.equal(summary.manual, 1);
  assert.deepEqual(summary.droppedChecks, ["prowler.aws.made_up_check"]);
});

test("a file that is not an OCSF array is an error, not an empty push", () => {
  assert.throws(() => parseOcsf("{}", "aws", known), /not an OCSF array/);
  assert.throws(() => parseOcsf("nope", "aws", known), /not JSON/);
});

test("argument helpers: quoting, auth flags from env", () => {
  assert.deepEqual(splitArgs(`--region us-east-1 ca-central-1 --mutelist-file "my list.yaml"`), ["--region", "us-east-1", "ca-central-1", "--mutelist-file", "my list.yaml"]);
  assert.deepEqual(authArgs("azure", { AZURE_CLIENT_SECRET: "s" }), ["--sp-env-auth"]);
  assert.deepEqual(authArgs("m365", {}), ["--az-cli-auth", "--init-modules"]);
  assert.deepEqual(authArgs("m365", { M365_CERTIFICATE_CONTENT: "pfx" }), ["--certificate-auth", "--init-modules"]);
  assert.equal(prowlerEnv("okta", { OKTA_DOMAIN: "acme.okta.com" }).OKTA_ORG_DOMAIN, "acme.okta.com");
  assert.deepEqual(authArgs("kubernetes", { KUBECONFIG: "/k" }), ["--kubeconfig-file", "/k"]);
  assert.deepEqual(authArgs("aws", { AWS_ACCESS_KEY_ID: "x" }), []);
  assert.deepEqual(authArgs("aws", { SAGENTIX_PROWLER_AWS_REGIONS: "ca-central-1 us-east-1" }), ["--region", "ca-central-1", "us-east-1"]);
  assert.deepEqual(authArgs("azure", { SAGENTIX_PROWLER_AZURE_SUBSCRIPTIONS: "s1" }), ["--az-cli-auth", "--subscription-ids", "s1"]);
  assert.deepEqual(authArgs("gcp", { SAGENTIX_PROWLER_GCP_PROJECTS: "p1 p2" }), ["--project-ids", "p1", "p2"]);
});

// ── Through the CLI ───────────────────────────────────────────────────────────────────────────────

test("--prowler-output reads a customer's OCSF file; the stderr summary counts what was dropped", async () => {
  const c = capture();
  assert.equal(await main([...dry, "--prowler-output", FIXTURE], c.deps), EXIT.ok, c.stderr.join("\n"));
  const r = JSON.parse(c.stdout.join("\n"));
  assert.equal(r.payload.results.length, 7);
  assert.deepEqual(r.payload.collector.sources, [{ source: "prowler", scope: "Prowler aws findings from a json-ocsf file" }]);
  assert.match(c.stderr.join("\n"), /prowler: 9 findings; 7 results .* 2 findings dropped from 2 checks not in the catalogue/);
});

/** A stand-in `prowler`: records its argv, then writes the fixture where --output-directory/--output-filename say. */
function fakeProwler(exitCode = 0): { bin: string; argvFile: string } {
  const argvFile = join(dir, `argv-${exitCode}.json`);
  const bin = join(dir, `prowler-fake-${exitCode}.mjs`);
  writeFileSync(bin, `#!/usr/bin/env node
import { copyFileSync, writeFileSync } from "node:fs";
const a = process.argv.slice(2);
writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(a));
if (${exitCode} !== 0) { process.stderr.write("boom: credentials not found\\n"); process.exit(${exitCode}); }
copyFileSync(${JSON.stringify(FIXTURE)}, a[a.indexOf("--output-directory") + 1] + "/" + a[a.indexOf("--output-filename") + 1] + ".ocsf.json");
`);
  chmodSync(bin, 0o755);
  return { bin, argvFile };
}

test("the subprocess path runs prowler read-only into a temp directory and reads its OCSF output", async () => {
  const { bin, argvFile } = fakeProwler();
  const c = capture({ env: { PATH: process.env.PATH, AWS_SECRET_ACCESS_KEY: "secretsecretsecret" } });
  assert.equal(await main([...dry, "--prowler-bin", bin, "--prowler-args=--region us-east-1"], c.deps), EXIT.ok, c.stderr.join("\n"));
  const argv: string[] = JSON.parse(readFileSync(argvFile, "utf8"));
  assert.equal(argv[0], "aws");
  for (const a of ["--output-formats", "json-ocsf", "--no-banner", "--ignore-exit-code-3", "--region", "us-east-1"]) assert.ok(argv.includes(a), a);
  for (const a of ["--push-to-cloud", "--security-hub", "--fixer"]) assert.ok(!argv.includes(a), a);
  assert.equal(JSON.parse(c.stdout.join("\n")).payload.results.length, 7);
});

test("several providers run in one source; one that fails leaves the others' results and says so (2026-11-01)", async () => {
  // A stand-in that fails for github (no token) and writes the AWS fixture otherwise, noting (per provider: the two run side by side) the token Prowler would read.
  const bin = join(dir, "prowler-two.mjs"), seen = join(dir, "seen.json");
  writeFileSync(bin, `#!/usr/bin/env node
import { copyFileSync, writeFileSync } from "node:fs";
const a = process.argv.slice(2);
writeFileSync(${JSON.stringify(seen)}.replace(".json", "-" + a[0] + ".json"), JSON.stringify({ provider: a[0], pat: process.env.GITHUB_PERSONAL_ACCESS_TOKEN ?? null }));
if (a[0] === "github") { process.stderr.write("github: bad credentials\\n"); process.exit(1); }
copyFileSync(${JSON.stringify(FIXTURE)}, a[a.indexOf("--output-directory") + 1] + "/" + a[a.indexOf("--output-filename") + 1] + ".ocsf.json");
`);
  chmodSync(bin, 0o755);
  const c = capture({ env: { PATH: process.env.PATH, GITHUB_TOKEN: "github_pat_example" } });
  const args = ["run", "--endpoint", "https://sos.example.test", "--source", "prowler", "--prowler-provider", "aws,github", "--dry-run", "--catalog", TRIM, "--prowler-bin", bin];
  assert.equal(await main(args, c.deps), EXIT.ok, c.stderr.join("\n"));
  assert.equal(JSON.parse(c.stdout.join("\n")).payload.results.length, 7);
  assert.match(c.stderr.join("\n"), /prowler: github did not run \(.*github exited 1: github: bad credentials\); its controls keep their other ways/);
  assert.deepEqual(JSON.parse(readFileSync(seen.replace(".json", "-github.json"), "utf8")), { provider: "github", pat: "github_pat_example" });   // the collector's token, under Prowler's name
});

test("the collector's credential names are copied to Prowler's, never over one already set", () => {
  assert.equal(prowlerEnv("github", { GITHUB_TOKEN: "a" }).GITHUB_PERSONAL_ACCESS_TOKEN, "a");
  assert.equal(prowlerEnv("github", { GITHUB_TOKEN: "a", GITHUB_PERSONAL_ACCESS_TOKEN: "b" }).GITHUB_PERSONAL_ACCESS_TOKEN, "b");
  assert.equal(prowlerEnv("cloudflare", { CLOUDFLARE_API_TOKEN_READONLY: "c" }).CLOUDFLARE_API_TOKEN, "c");
  assert.deepEqual(Object.fromEntries(Object.entries(prowlerEnv("googleworkspace", { GOOGLE_SA_KEY_FILE: "k.json", GOOGLE_ADMIN_EMAIL: "it@x.ca" })).filter(([k]) => k.startsWith("GOOGLEWORKSPACE_"))),
    { GOOGLEWORKSPACE_CREDENTIALS_FILE: "k.json", GOOGLEWORKSPACE_DELEGATED_USER: "it@x.ca" });
  const m = prowlerEnv("m365", { ENTRA_TENANT_ID: "t", ENTRA_CLIENT_ID: "i", ENTRA_CLIENT_SECRET: "s" });
  assert.deepEqual([m.AZURE_TENANT_ID, m.AZURE_CLIENT_ID, m.AZURE_CLIENT_SECRET], ["t", "i", "s"]);
  assert.equal(prowlerEnv("aws", { GITHUB_TOKEN: "a" }).GITHUB_PERSONAL_ACCESS_TOKEN, undefined);
});

test("a failing prowler run is an error (exit 1), and send/fix/output options are refused", async () => {
  const bad = fakeProwler(2);
  let c = capture({ env: { PATH: process.env.PATH } });
  assert.equal(await main([...dry, "--prowler-bin", bad.bin], c.deps), EXIT.error);
  assert.match(c.stderr.join("\n"), /exited 2: boom: credentials not found/);
  for (const flag of ["--push-to-cloud", "--security-hub", "--output-directory=/tmp/x"]) {
    assert.ok(REFUSED_ARGS.includes(flag.split("=")[0]));
    c = capture();
    assert.equal(await main([...dry, "--prowler-bin", fakeProwler().bin, `--prowler-args=${flag}`], c.deps), EXIT.error);
    assert.match(c.stderr.join("\n"), /may not carry/);
  }
  c = capture();
  assert.equal(await main(["run", "--endpoint", "https://sos.example.test", "--source", "prowler", "--dry-run"], c.deps), EXIT.error);
  assert.match(c.stderr.join("\n"), /--prowler-provider is required/);
});

test("a provider with no mapped checks warns that every finding will be dropped", async () => {
  const c = capture();
  assert.equal(await main(["run", "--endpoint", "https://sos.example.test", "--source", "prowler", "--prowler-provider", "github", "--prowler-output", FIXTURE, "--dry-run", "--catalog", TRIM], c.deps), EXIT.ok);
  assert.match(c.stderr.join("\n"), /lists no github check/);
});

// ── Splitting ─────────────────────────────────────────────────────────────────────────────────────

const r = (i: number, detail = ""): Result => ({ check: "prowler.aws.iam_root_mfa_enabled", resource: `r${i}`, result: i % 3 ? "pass" : "fail", detail });

test("splitResults keeps order and caps each push by count and by bytes", () => {
  const many = Array.from({ length: 12_001 }, (_, i) => r(i));
  const parts = splitResults(many);
  assert.deepEqual(parts.map((p) => p.length), [MAX_RESULTS, MAX_RESULTS, 2001]);
  assert.deepEqual(parts.flat(), many);
  const fat = Array.from({ length: 10 }, (_, i) => r(i, "x".repeat(900)));
  const bytes = splitResults(fat, 5000, 3000);
  assert.ok(bytes.length > 1 && bytes.every((p) => Buffer.byteLength(JSON.stringify(p)) <= 3000 + 2));
  assert.deepEqual(splitResults([]), []);
});

test("more than 5,000 results go out as several signed pushes, each with its own nonce", async () => {
  const big: Source = { name: "prowler", options: {}, emits: ["prowler.aws.iam_root_mfa_enabled"], describe: () => "test", run: async () => Array.from({ length: 12_001 }, (_, i) => r(i)) };
  const c = capture({ sources: [big] });
  assert.equal(await main([...push, "--source", "prowler", "--out", join(dir, "copy.json")], c.deps), EXIT.ok, c.stderr.join("\n"));
  assert.equal(c.posts.length, 3);
  const nonces = new Set<string>();
  let total = 0;
  for (const p of c.posts) {
    const body = p.init.body as Uint8Array<ArrayBuffer>;
    assert.ok(await verify((p.init.headers as Record<string, string>)["x-sagentix-content-signature"], body));
    const payload = JSON.parse(new TextDecoder().decode(body));
    assert.ok(payload.results.length <= MAX_RESULTS);
    nonces.add(payload.nonce);
    total += payload.results.length;
  }
  assert.equal(nonces.size, 3);
  assert.equal(total, 12_001);
  assert.match(c.stderr.join("\n"), /12001 results go out as 3 signed pushes/);
  const copy = JSON.parse(readFileSync(join(dir, "copy.json"), "utf8"));
  assert.equal(copy.pushes.length, 3);
  assert.equal(copy.pushes[1].body, new TextDecoder().decode(c.posts[1].init.body as Uint8Array));
});

test("a refused second push stops the run, exits 4 and says the first was accepted", async () => {
  const big: Source = { name: "prowler", options: {}, emits: ["prowler.aws.iam_root_mfa_enabled"], describe: () => "test", run: async () => Array.from({ length: 6_000 }, (_, i) => r(i)) };
  let n = 0;
  const c = capture({ sources: [big], fetch: (async () => (++n === 2
    ? new Response(JSON.stringify({ error: "This payload was already received." }), { status: 409 })
    : new Response(JSON.stringify({ runId: `r${n}` }), { status: 201 }))) as typeof fetch });
  assert.equal(await main([...push, "--source", "prowler"], c.deps), EXIT.refused);
  assert.equal(n, 2);
  assert.match(c.stderr.join("\n"), /push 2 of 2; pushes 1 to 1 were accepted\) \(HTTP 409\)/);
});
