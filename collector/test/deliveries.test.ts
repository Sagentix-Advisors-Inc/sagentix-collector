// Deliveries to the vault (src/deliveries.ts; apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 8): only names the config
// lists, only with their kind, secrets only sealed for this collector and bound to the connector's settings; the env
// file moved in; a test only in resident mode; and a run that refuses a secret whose settings changed since.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ENV_FILE, settingsOf, vaultBridge, type Credential, type DeliveryResult } from "../src/deliveries.ts";
import { DOCKER_SECRET, Vault, keyHolderFor, runEnv } from "../src/vault.ts";
import { checkin, type Channel } from "../src/channel.ts";
import { generateKeyPair } from "../src/keys.ts";
import { sealInBrowser } from "./seal.ts";
import { signedAnswers, TEST_CHANNEL } from "./helpers.ts";

const CREDS: Record<string, Credential> = {
  jamf: { sources: ["jamf"], secrets: ["JAMF_CLIENT_SECRET"], settings: ["JAMF_URL", "JAMF_CLIENT_ID"] },
  google_workspace: { sources: ["google_workspace"], files: ["GOOGLE_SA_KEY_FILE"], settings: ["GOOGLE_ADMIN_EMAIL"] },
  endpoint_central: { sources: ["endpoint_central"], secrets: ["ENDPOINT_CENTRAL_CLIENT_SECRET"], settings: ["ENDPOINT_CENTRAL_URL"],
                      optional: { ENDPOINT_CENTRAL_ACCOUNTS_URL: "" } },
};
const now = () => new Date("2026-11-01T12:00:00Z");

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "collector-deliveries-"));
  const configPath = join(dir, "sagentix-collector.config.json");
  writeFileSync(configPath, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", sources: { jamf: {} }, credentials: CREDS }));
  const holder = keyHolderFor(dir, "k-1", { env: {}, platform: "linux", runner: "server", exists: (p) => p !== DOCKER_SECRET && existsSync(p) });
  const logs: string[] = [], tests: string[][] = [];
  const b = vaultBridge({ configPath, keyId: "k-1", holder, now, log: (s) => logs.push(s),
                          test: async (sources) => { tests.push(sources); return { exit: 0, passed: 3, failed: 1, skipped: 0, errors: ["error in source jamf: 401 for JAMF-SECRET-VALUE-1"] }; } });
  return { dir, configPath, holder, b, logs, tests, vault: () => new Vault(dir, holder) };
}
const ok = (r: DeliveryResult[], id: string) => r.find((x) => x.id === id)!;

test("reports names, kinds, dates, the sealing key and the settings' values, never a secret's", async () => {
  const t = setup();
  await t.b.apply([{ id: "d1", op: "set", name: "JAMF_URL", kind: "setting", value: "https://acme.jamfcloud.com" },
                   { id: "d2", op: "set", name: "JAMF_CLIENT_ID", kind: "setting", value: "c1" }], { agent: false });
  const sealed = await sealInBrowser(t.b.summary().sealKey!, "k-1", "JAMF_CLIENT_SECRET", "secret", "JAMF-SECRET-VALUE-1", { JAMF_URL: "https://acme.jamfcloud.com", JAMF_CLIENT_ID: "c1" });
  await t.b.apply([{ id: "d3", op: "set", name: "JAMF_CLIENT_SECRET", kind: "secret", sealed }], { agent: false });
  const s = t.b.summary();
  assert.equal(Buffer.from(s.sealKey!, "base64url").length, 32);
  assert.equal(s.protection, "file");
  assert.deepEqual(s.entries.map((e) => [e.name, e.kind, e.value]),
                   [["JAMF_CLIENT_ID", "setting", "c1"], ["JAMF_CLIENT_SECRET", "secret", undefined], ["JAMF_URL", "setting", "https://acme.jamfcloud.com"]]);
  assert.deepEqual(Object.keys(s.credentials), ["jamf", "google_workspace", "endpoint_central"]);
  assert.doesNotMatch(JSON.stringify(s), /JAMF-SECRET-VALUE/);
});

test("sets a sealed secret bound to its connector's settings, and refuses what sos-app may not ask", async () => {
  const t = setup(), pub = t.b.summary().sealKey!;
  const settings = [{ id: "s1", op: "set", name: "JAMF_URL", kind: "setting", value: "https://acme.jamfcloud.com" },
                    { id: "s2", op: "set", name: "JAMF_CLIENT_ID", kind: "setting", value: "client-1" }];
  const bind = { JAMF_URL: "https://acme.jamfcloud.com", JAMF_CLIENT_ID: "client-1" };
  // Before the settings: refused, so a secret is never stored unbound.
  const early = await sealInBrowser(pub, "k-1", "JAMF_CLIENT_SECRET", "secret", "JAMF-SECRET-VALUE-1", {});
  assert.match(ok(await t.b.apply([{ id: "e", op: "set", name: "JAMF_CLIENT_SECRET", kind: "secret", sealed: early }], { agent: false }), "e").error!, /set JAMF_URL, JAMF_CLIENT_ID first/);
  const sealed = await sealInBrowser(pub, "k-1", "JAMF_CLIENT_SECRET", "secret", "JAMF-SECRET-VALUE-1", bind);
  const r = await t.b.apply([...settings, { id: "d1", op: "set", name: "JAMF_CLIENT_SECRET", kind: "secret", sealed }], { agent: false });
  assert.ok(r.every((x) => x.ok), JSON.stringify(r));
  assert.equal(t.vault().get("JAMF_CLIENT_SECRET"), "JAMF-SECRET-VALUE-1");
  assert.ok(!t.logs.join("\n").includes("JAMF-SECRET-VALUE-1"), "a value is never logged");

  const refused = await t.b.apply([
    { id: "n1", op: "set", name: "AWS_SECRET_ACCESS_KEY", kind: "secret", sealed },                                  // not listed
    { id: "n2", op: "set", name: "JAMF_CLIENT_SECRET", kind: "setting", value: "clear text" },                        // wrong kind
    { id: "n3", op: "set", name: "JAMF_CLIENT_SECRET", kind: "secret" },                                              // not sealed
    { id: "n4", op: "set", name: "JAMF_CLIENT_SECRET", kind: "secret", sealed: { ...sealed, bind: { ...bind, JAMF_URL: "https://evil.example" } } },
    { id: "n5", op: "launch", name: "JAMF_URL" },
  ], { agent: false });
  assert.deepEqual(refused.map((x) => x.ok), [false, false, false, false, false]);
  assert.match(ok(refused, "n4").error!, /settings changed/);
  assert.equal(t.vault().get("JAMF_CLIENT_SECRET"), "JAMF-SECRET-VALUE-1");
});

test("a run stops using a secret once its connector points somewhere else, an added optional URL included", async () => {
  const t = setup(), pub = t.b.summary().sealKey!;
  await t.b.apply([{ id: "s", op: "set", name: "ENDPOINT_CENTRAL_URL", kind: "setting", value: "https://ec.acme.example" }], { agent: false });
  const sealed = await sealInBrowser(pub, "k-1", "ENDPOINT_CENTRAL_CLIENT_SECRET", "secret", "EC-SECRET-VALUE-1", { ENDPOINT_CENTRAL_URL: "https://ec.acme.example" });
  assert.ok(ok(await t.b.apply([{ id: "d", op: "set", name: "ENDPOINT_CENTRAL_CLIENT_SECRET", kind: "secret", sealed }], { agent: false }), "d").ok);
  const env = () => runEnv(t.dir, t.holder, {}, (n) => settingsOf(CREDS, n));
  assert.equal(env().env.ENDPOINT_CENTRAL_CLIENT_SECRET, "EC-SECRET-VALUE-1");
  await t.b.apply([{ id: "x", op: "set", name: "ENDPOINT_CENTRAL_ACCOUNTS_URL", kind: "setting", value: "https://evil.example" }], { agent: false });
  const r = env();
  assert.equal(r.env.ENDPOINT_CENTRAL_CLIENT_SECRET, undefined);
  assert.match(r.warnings[0], /ENDPOINT_CENTRAL_ACCOUNTS_URL changed since it was set/);
});

test("moves the env file's values into the vault, settings first, files by their contents, and keeps other lines", async () => {
  const t = setup();
  writeFileSync(join(t.dir, "sa.json"), "{\"private_key\":\"x\"}");
  writeFileSync(join(t.dir, ENV_FILE), "JAMF_URL=https://acme.jamfcloud.com\nJAMF_CLIENT_SECRET='JAMF-SECRET-VALUE-1'\nJAMF_CLIENT_ID=c1\nGOOGLE_SA_KEY_FILE=sa.json\nPATH_EXTRA=keep\n");
  assert.deepEqual(t.b.summary().envFile.sort(), ["GOOGLE_SA_KEY_FILE", "JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET", "JAMF_URL"]);
  const r = ok(await t.b.apply([{ id: "i", op: "import-env" }], { agent: false }), "i");
  assert.equal(r.ok, true);
  assert.deepEqual(r.leftFiles, ["sa.json"]);
  assert.equal(readFileSync(join(t.dir, ENV_FILE), "utf8"), "PATH_EXTRA=keep\n");
  assert.equal(t.vault().get("GOOGLE_SA_KEY_FILE"), "{\"private_key\":\"x\"}");
  assert.equal(runEnv(t.dir, t.holder, {}, (n) => settingsOf(CREDS, n)).env.JAMF_CLIENT_SECRET, "JAMF-SECRET-VALUE-1", "bound to the settings it came with");
});

test("runs a connector test only in resident mode, and cuts the vault's values from its errors", async () => {
  const t = setup(), pub = t.b.summary().sealKey!;
  await t.b.apply([{ id: "s1", op: "set", name: "JAMF_URL", kind: "setting", value: "u" }, { id: "s2", op: "set", name: "JAMF_CLIENT_ID", kind: "setting", value: "c" }], { agent: false });
  const sealed = await sealInBrowser(pub, "k-1", "JAMF_CLIENT_SECRET", "secret", "JAMF-SECRET-VALUE-1", { JAMF_URL: "u", JAMF_CLIENT_ID: "c" });
  await t.b.apply([{ id: "d", op: "set", name: "JAMF_CLIENT_SECRET", kind: "secret", sealed }], { agent: false });
  assert.deepEqual(await t.b.apply([{ id: "t", op: "test", connector: "jamf" }], { agent: false }), [], "a run leaves it for the agent");
  const r = ok(await t.b.apply([{ id: "t", op: "test", connector: "jamf" }], { agent: true }), "t");
  assert.deepEqual(t.tests, [["jamf"]]);
  assert.equal(r.test!.passed, 3);
  assert.deepEqual(r.test!.errors, ["error in source jamf: 401 for <secret>"]);
  assert.equal(ok(await t.b.apply([{ id: "u", op: "test", connector: "aws" }], { agent: true }), "u").ok, false);
});

test("the check-in reports the vault, applies the answer's deliveries and acknowledges them, signed; a dry run applies nothing", async () => {
  const t = setup(), { privatePem } = generateKeyPair(), posted: { path: string; body: Record<string, unknown> }[] = [];
  const answers = (async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname, body = JSON.parse(new TextDecoder().decode(init.body as Uint8Array));
    posted.push({ path, body });
    if (path === "/api/collect/checkin") return new Response(JSON.stringify({ action: "none", deliveries: [{ id: "d1", op: "set", name: "JAMF_URL", kind: "setting", value: "https://acme.jamfcloud.com" }] }));
    return new Response("{}");
  }) as typeof globalThis.fetch;
  // An unsigned answer (an sos-app without its channel key) or one signed by another key delivers nothing.
  for (const [key, warning] of [[null, /did not sign its answer/], [generateKeyPair().privatePem, /does not verify/]] as const) {
    const logs: string[] = [];
    const u: Channel = { origin: "https://sos.example.test", keyId: "k-1", pem: privatePem, fetch: signedAnswers(answers, key), dir: t.dir, runner: "server", mode: "run", env: {}, now,
                         answerKeys: [TEST_CHANNEL.publicKey] };
    await checkin(u, { write: true, log: (s) => logs.push(s), vault: t.b });
    assert.equal(t.vault().list().length, 0);
    assert.match(logs.join("\n"), warning);
  }
  posted.length = 0;
  const c: Channel = { origin: "https://sos.example.test", keyId: "k-1", pem: privatePem, fetch: signedAnswers(answers), dir: t.dir, runner: "server", mode: "run", env: {}, now,
                       answerKeys: [TEST_CHANNEL.publicKey] };
  await checkin(c, { write: false, log: () => {}, vault: t.b });
  assert.equal(t.vault().list().length, 0, "dry run");
  await checkin(c, { write: true, log: () => {}, vault: t.b });
  assert.equal(t.vault().get("JAMF_URL"), "https://acme.jamfcloud.com");
  const sent = posted.find((p) => p.path === "/api/collect/checkin")!.body as { vault: { sealKey: string } };
  assert.equal(Buffer.from(sent.vault.sealKey, "base64url").length, 32);
  const ackd = posted.find((p) => p.path === "/api/collect/vault/ack")!.body as { results: DeliveryResult[]; vault: { entries: unknown[] } };
  assert.deepEqual(ackd.results, [{ id: "d1", ok: true }]);
  assert.equal(ackd.vault.entries.length, 1);
});
