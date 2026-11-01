// A connector read from the client's own vault (src/refs.ts): the four providers, each token only to its own service,
// references checked on shape, and a connector taking every name from its one object or none at all. Fakes only.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyRefs, readRef, refProblem } from "../src/refs.ts";
import { vaultBridge, type Credential } from "../src/deliveries.ts";
import { DOCKER_SECRET, Vault, keyHolderFor } from "../src/vault.ts";

const JAMF: Credential = { sources: ["jamf"], secrets: ["JAMF_CLIENT_SECRET"], settings: ["JAMF_URL", "JAMF_CLIENT_ID"] };
const OBJ = { JAMF_URL: "https://acme.jamfcloud.com", JAMF_CLIENT_ID: "c1", JAMF_CLIENT_SECRET: "REF-SECRET-VALUE-1" };

/** A fake network: answers by host and path, and records every request with its headers. */
function net(routes: Record<string, (url: URL, init: RequestInit) => unknown>) {
  const seen: { url: string; headers: Record<string, string>; body?: string }[] = [];
  const f = (async (u: string, init: RequestInit = {}) => {
    const url = new URL(u), headers = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
    seen.push({ url: u, headers, body: typeof init.body === "string" ? init.body : undefined });
    const key = Object.keys(routes).find((k) => `${url.host}${url.pathname}`.startsWith(k));
    if (!key) return new Response("not here", { status: 404 });
    return new Response(JSON.stringify(routes[key](url, init)), { status: 200 });
  }) as typeof fetch;
  return { f, seen };
}

test("checks references on shape, so a token can only go to the provider's own service", () => {
  assert.equal(refProblem({ provider: "aws", id: "arn:aws:secretsmanager:ca-central-1:123456789012:secret:sagentix/jamf-AbCdEf" }), null);
  assert.equal(refProblem({ provider: "azure", id: "https://acme-kv.vault.azure.net/secrets/sagentix-jamf" }), null);
  assert.equal(refProblem({ provider: "gcp", id: "projects/acme-prod/secrets/sagentix-jamf" }), null);
  assert.equal(refProblem({ provider: "hashicorp", id: "secret/sagentix/jamf" }), null);
  for (const bad of [
    { provider: "azure", id: "https://acme.vault.azure.net.evil.example/secrets/x" },
    { provider: "azure", id: "http://acme.vault.azure.net/secrets/x" },
    { provider: "aws", id: "arn:aws:s3:::bucket" },
    { provider: "gcp", id: "https://evil.example/projects/p/secrets/s" },
    { provider: "hashicorp", id: "secret/../sys/raw" },
    { provider: "onepassword", id: "x" },
  ]) assert.notEqual(refProblem(bad), null, JSON.stringify(bad));
});

test("AWS Secrets Manager: GetSecretValue signed with the environment's credentials, in the ARN's region", async () => {
  const { f, seen } = net({ "secretsmanager.ca-central-1.amazonaws.com/": () => ({ SecretString: JSON.stringify(OBJ) }) });
  const got = await readRef({ provider: "aws", id: "arn:aws:secretsmanager:ca-central-1:123456789012:secret:sagentix/jamf-AbCdEf" },
                            { AWS_ACCESS_KEY_ID: "AKIAEXAMPLE", AWS_SECRET_ACCESS_KEY: "s" }, f);
  assert.deepEqual(got, OBJ);
  assert.equal(seen[0].headers["x-amz-target"], "secretsmanager.GetSecretValue");
  assert.match(seen[0].headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/ca-central-1\/secretsmanager\/aws4_request/);
  await assert.rejects(readRef({ provider: "aws", id: "arn:aws:secretsmanager:ca-central-1:123456789012:secret:x" }, {}, f), /no AWS credentials/);
});

test("Azure Key Vault: a vault-scoped token from the app registration, else the managed identity, sent to Key Vault only", async () => {
  const { f, seen } = net({
    "login.microsoftonline.com/": (_u, init) => { assert.match(String(init.body), /scope=https%3A%2F%2Fvault\.azure\.net%2F\.default/); return { access_token: "AZ-TOKEN" }; },
    "169.254.169.254/metadata/identity/oauth2/token": () => ({ access_token: "MI-TOKEN" }),
    "acme-kv.vault.azure.net/secrets/": () => ({ value: JSON.stringify(OBJ) }),
  });
  const id = "https://acme-kv.vault.azure.net/secrets/sagentix-jamf";
  assert.deepEqual(await readRef({ provider: "azure", id }, { AZURE_TENANT_ID: "t", AZURE_CLIENT_ID: "c", AZURE_CLIENT_SECRET: "s" }, f), OBJ);
  assert.deepEqual(await readRef({ provider: "azure", id }, {}, f), OBJ);
  const withToken = seen.filter((x) => x.headers.authorization);
  assert.deepEqual(withToken.map((x) => new URL(x.url).host), ["acme-kv.vault.azure.net", "acme-kv.vault.azure.net"]);
  assert.equal(seen.find((x) => x.url.includes("169.254.169.254"))!.headers.metadata, "true");
});

test("Google Cloud Secret Manager: the latest version, with the metadata server's token when there is no key file", async () => {
  const { f, seen } = net({
    "metadata.google.internal/": () => ({ access_token: "GCE-TOKEN" }),
    "secretmanager.googleapis.com/v1/projects/acme-prod/secrets/sagentix-jamf/versions/latest:access": () => ({ payload: { data: Buffer.from(JSON.stringify(OBJ)).toString("base64") } }),
  });
  assert.deepEqual(await readRef({ provider: "gcp", id: "projects/acme-prod/secrets/sagentix-jamf" }, {}, f), OBJ);
  assert.equal(seen[1].headers.authorization, "Bearer GCE-TOKEN");
});

test("HashiCorp Vault: key/value version 2 at this computer's VAULT_ADDR, with a token or an AppRole", async () => {
  const { f, seen } = net({
    "vault.acme.example/v1/auth/approle/login": () => ({ auth: { client_token: "VAULT-TOKEN" } }),
    "vault.acme.example/v1/secret/data/sagentix/jamf": () => ({ data: { data: OBJ } }),
  });
  const ref = { provider: "hashicorp" as const, id: "secret/sagentix/jamf" };
  assert.deepEqual(await readRef(ref, { VAULT_ADDR: "https://vault.acme.example", VAULT_ROLE_ID: "r", VAULT_SECRET_ID: "s", VAULT_NAMESPACE: "acme" }, f), OBJ);
  assert.equal(seen[1].headers["x-vault-token"], "VAULT-TOKEN");
  assert.equal(seen[1].headers["x-vault-namespace"], "acme");
  await assert.rejects(readRef(ref, { VAULT_ADDR: "http://vault.acme.example", VAULT_TOKEN: "t" }, f), /over https/);
  await assert.rejects(readRef(ref, { VAULT_TOKEN: "t" }, f), /VAULT_ADDR must be set/);
});

test("a connector read by reference takes every name from its object, or none: never a local secret with its URL", async () => {
  const dir = mkdtempSync(join(tmpdir(), "collector-refs-"));
  const ref = { provider: "hashicorp", id: "secret/sagentix/jamf" };
  const answer = (o: unknown) => net({ "vault.acme.example/v1/secret/data/sagentix/jamf": () => ({ data: { data: o } }) }).f;
  const base = { VAULT_ADDR: "https://vault.acme.example", VAULT_TOKEN: "t", JAMF_CLIENT_SECRET: "LOCAL-SECRET-VALUE", JAMF_URL: "https://old.example" };
  const ok = await applyRefs(dir, { jamf: ref }, { jamf: JAMF }, base, answer(OBJ));
  assert.equal(ok.env.JAMF_CLIENT_SECRET, "REF-SECRET-VALUE-1");
  assert.equal(ok.env.JAMF_URL, "https://acme.jamfcloud.com");
  assert.ok(ok.secrets.includes("REF-SECRET-VALUE-1") && !ok.secrets.includes("https://acme.jamfcloud.com"));
  // An object with only a URL (someone pointed the reference at a secret of their own): none of the connector's names.
  const partial = await applyRefs(dir, { jamf: ref }, { jamf: JAMF }, base, answer({ JAMF_URL: "https://evil.example" }));
  assert.equal(partial.env.JAMF_URL, undefined);
  assert.equal(partial.env.JAMF_CLIENT_SECRET, undefined);
  assert.match(partial.warnings[0], /lacks JAMF_CLIENT_ID, JAMF_CLIENT_SECRET/);
  // A file name's value becomes a private temporary file.
  const gw: Credential = { sources: ["google_workspace"], files: ["GOOGLE_SA_KEY_FILE"], settings: ["GOOGLE_ADMIN_EMAIL"] };
  const f = await applyRefs(dir, { google_workspace: ref }, { google_workspace: gw }, base, answer({ GOOGLE_SA_KEY_FILE: "{\"private_key\":\"x\"}", GOOGLE_ADMIN_EMAIL: "a@acme.example" }));
  assert.equal(readFileSync(f.env.GOOGLE_SA_KEY_FILE!, "utf8"), "{\"private_key\":\"x\"}");
  const path = f.env.GOOGLE_SA_KEY_FILE!;
  f.cleanup();
  assert.equal(existsSync(path), false);
});

test("sos-app may set and remove a connector's reference, only a well-formed one for a connector of the config", async () => {
  const dir = mkdtempSync(join(tmpdir(), "collector-refs-"));
  const configPath = join(dir, "c.json");
  writeFileSync(configPath, JSON.stringify({ endpoint: "https://sos.example.test", keyId: "k-1", sources: { jamf: {} }, credentials: { jamf: JAMF } }));
  const holder = keyHolderFor(dir, "k-1", { env: {}, platform: "linux", runner: "server", exists: (p) => p !== DOCKER_SECRET && existsSync(p) });
  const b = vaultBridge({ configPath, keyId: "k-1", holder, now: () => new Date("2026-11-01T12:00:00Z"), log: () => {} });
  const r = await b.apply([
    { id: "a", op: "set-ref", connector: "jamf", ref: { provider: "aws", id: "arn:aws:secretsmanager:ca-central-1:123456789012:secret:sagentix/jamf-AbCdEf" } },
    { id: "b", op: "set-ref", connector: "okta", ref: { provider: "aws", id: "arn:aws:secretsmanager:ca-central-1:123456789012:secret:x" } },
    { id: "c", op: "set-ref", connector: "jamf", ref: { provider: "azure", id: "https://evil.example/secrets/x" } },
  ], { agent: false });
  assert.deepEqual(r.map((x) => x.ok), [true, false, false]);
  assert.equal(b.summary().refs.jamf.provider, "aws");
  await b.apply([{ id: "d", op: "remove-ref", connector: "jamf" }], { agent: false });
  assert.deepEqual(new Vault(dir, holder).refs(), {});
});
