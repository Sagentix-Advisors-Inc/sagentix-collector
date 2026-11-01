// The collector's vault (src/vault.ts; apps/sos-app/docs/COLLECTOR_VAULT.md): values sealed one by one,
// bound to their names; the key kept by the strongest holder the computer has; a value sealed in a browser with
// WebCrypto for this collector opens here and nowhere else; and a run reads the vault into its environment.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DOCKER_SECRET, KEY_FILE, VAULT_FILE, Vault, keyHolderFor, runEnv, type Exec } from "../src/vault.ts";
import { sealInBrowser } from "./seal.ts";

const fresh = () => mkdtempSync(join(tmpdir(), "collector-vault-"));
const fileVault = (dir = fresh()) => new Vault(dir, keyHolderFor(dir, "k-1", { env: {}, platform: "linux", runner: "server", exists: (p) => p !== DOCKER_SECRET && existsSync(p) }));
const now = new Date("2026-11-01T12:00:00Z");

test("seals each value under its own name, mode 0600, and never writes a value in clear", () => {
  const dir = fresh(), v = fileVault(dir);
  v.set("OKTA_API_TOKEN", "00abc-very-secret", { kind: "secret", now });
  v.set("OKTA_DOMAIN", "acme.okta.com", { kind: "setting", now });
  assert.equal(v.get("OKTA_API_TOKEN"), "00abc-very-secret");
  assert.deepEqual(v.list(), [{ name: "OKTA_API_TOKEN", setAt: now.toISOString(), kind: "secret" }, { name: "OKTA_DOMAIN", setAt: now.toISOString(), kind: "setting" }]);
  const text = readFileSync(join(dir, VAULT_FILE), "utf8");
  assert.doesNotMatch(text, /very-secret|acme\.okta/);
  if (process.platform !== "win32") {
    assert.equal(statSync(join(dir, VAULT_FILE)).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, KEY_FILE)).mode & 0o777, 0o600);
  }
  // A value moved under another name does not open.
  const d = JSON.parse(text);
  d.entries.OKTA_DOMAIN = { ...d.entries.OKTA_API_TOKEN, kind: "setting" };
  writeFileSync(join(dir, VAULT_FILE), JSON.stringify(d));
  assert.throws(() => fileVault(dir).get("OKTA_DOMAIN"), /does not open/);
  assert.throws(() => v.set("okta lower", "x", { kind: "secret", now }), /not a name/);
  assert.equal(v.remove("OKTA_API_TOKEN"), true);
  assert.equal(v.get("OKTA_API_TOKEN"), undefined);
});

test("keeps the key in the strongest place: systemd credential, Docker secret, Keychain, DPAPI, else a 0600 file", () => {
  const dir = fresh(), credDir = fresh();
  writeFileSync(join(credDir, "sagentix-vault-key"), Buffer.alloc(32, 7));
  const yes = () => true, no = (p: string) => p !== DOCKER_SECRET && existsSync(p);
  assert.equal(keyHolderFor(dir, "k-1", { env: { CREDENTIALS_DIRECTORY: credDir }, platform: "linux", runner: "server", exists: no }).protection, "systemd");
  assert.equal(keyHolderFor(dir, "k-1", { env: {}, platform: "linux", runner: "docker", exists: yes }).protection, "docker");
  assert.equal(keyHolderFor(dir, "k-1", { env: {}, platform: "darwin", runner: "mac", exists: no }).protection, "keychain");
  assert.equal(keyHolderFor(dir, "k-1", { env: {}, platform: "darwin", runner: "docker", exists: no }).protection, "file");
  assert.equal(keyHolderFor(dir, "k-1", { env: {}, platform: "win32", runner: "windows", exists: no }).protection, "dpapi");
  assert.equal(keyHolderFor(dir, "k-1", { env: {}, platform: "linux", runner: "server", exists: no }).protection, "file");
  // A provided key that is missing is an error, never a new key in its place.
  const sys = keyHolderFor(dir, "k-1", { env: { CREDENTIALS_DIRECTORY: credDir }, platform: "linux", runner: "server", exists: no });
  assert.equal(sys.read()?.length, 32);
});

test("passes the Keychain and DPAPI keys on standard input, never on a command line", () => {
  const calls: { cmd: string; args: string[]; input: string }[] = [];
  const exec: Exec = (cmd, args, input) => {
    calls.push({ cmd, args, input });
    if (args[0] === "-NoProfile") return { status: 0, stdout: Buffer.from("dpapi-blob").toString("base64"), stderr: "" };
    return { status: 0, stdout: "", stderr: "" };
  };
  const dir = fresh();
  keyHolderFor(dir, "k-1", { env: {}, platform: "darwin", runner: "mac", exec, exists: () => false }).create();
  keyHolderFor(dir, "k-1", { env: {}, platform: "win32", runner: "windows", exec, exists: () => false }).create();
  for (const c of calls) for (const a of c.args) assert.ok(a.length < 300 && !/^[A-Za-z0-9+/]{43}=$/.test(a), `a key on the command line of ${c.cmd}`);
  assert.match(calls[0].input, /^add-generic-password -U -s sagentix-collector-vault -a k-1 /);
  assert.throws(() => keyHolderFor(dir, "k-1; rm -rf /", { env: {}, platform: "darwin", runner: "mac", exec, exists: () => false }), /key id/);
});

test("opens a value sealed with WebCrypto for this collector, and refuses it for another name, kind, collector or key", async () => {
  const v = fileVault(), pub = v.sealPublicKey();
  assert.equal(Buffer.from(pub, "base64url").length, 32);
  assert.equal(v.sealPublicKey(), pub, "one sealing key per vault");
  const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n";
  const s = await sealInBrowser(pub, "k-1", "ENTRA_CLIENT_CERT_FILE", "file", pem);
  assert.equal(v.openSealed("k-1", s), pem);
  assert.throws(() => v.openSealed("k-2", s), /does not open/);
  assert.throws(() => v.openSealed("k-1", { ...s, name: "OKTA_API_TOKEN" }), /does not open/);
  assert.throws(() => v.openSealed("k-1", { ...s, kind: "secret" }), /does not open/);
  const flipped = Buffer.from(s.data, "base64"); flipped[0] ^= 1;
  assert.throws(() => v.openSealed("k-1", { ...s, data: flipped.toString("base64") }), /does not open/);
  const other = fileVault();
  other.sealPublicKey();
  assert.throws(() => other.openSealed("k-1", s), /does not open/);
  // The sealing private key is itself sealed in the file.
  assert.doesNotMatch(readFileSync(v.path, "utf8"), /BEGIN|MC4CAQAw/);
});

test("a run reads the vault into its environment: values, files as private temporary files, and what is set already wins", () => {
  const dir = fresh(), v = fileVault(dir);
  v.set("OKTA_API_TOKEN", "00abc-very-secret", { kind: "secret", now });
  v.set("GOOGLE_SA_KEY_FILE", "{\"private_key\":\"x\"}", { kind: "file", now });
  v.set("OKTA_DOMAIN", "acme.okta.com", { kind: "setting", now });
  const holder = keyHolderFor(dir, "k-1", { env: {}, platform: "linux", runner: "server", exists: (p) => p !== DOCKER_SECRET && existsSync(p) });
  const r = runEnv(dir, holder, { OKTA_DOMAIN: "given.okta.com", PATH: "/bin" });
  assert.equal(r.env.OKTA_API_TOKEN, "00abc-very-secret");
  assert.equal(r.env.OKTA_DOMAIN, "given.okta.com");
  assert.equal(readFileSync(r.env.GOOGLE_SA_KEY_FILE!, "utf8"), "{\"private_key\":\"x\"}");
  if (process.platform !== "win32") assert.equal(statSync(r.env.GOOGLE_SA_KEY_FILE!).mode & 0o777, 0o600);
  assert.deepEqual(r.used.sort(), ["GOOGLE_SA_KEY_FILE", "OKTA_API_TOKEN"]);
  assert.ok(r.secrets.includes("00abc-very-secret"));
  const file = r.env.GOOGLE_SA_KEY_FILE!;
  r.cleanup();
  assert.equal(existsSync(file), false);
  assert.deepEqual(runEnv(fresh(), holder, { PATH: "/bin" }).used, [], "no vault: the environment as it is");
});
