// The collector's vault (apps/sos-app/docs/COLLECTOR_VAULT.md): the connectors' secrets and settings. A person
// types them in sos-app; the browser seals each one to this collector's own X25519 key, so sos-app stores and relays
// only what it cannot open; the collector opens it here, and each run reads the vault into its own environment, so the
// sources do not change.
//
// One file beside the config, sagentix-collector.vault (mode 0600): each value sealed on its own with AES-256-GCM, its
// name as additional data, so a value cannot be moved under another name. The names and dates are readable without
// the key (the check-in reports them to sos-app); the values are not. The file is only as safe as its 256-bit key, so the key lives
// in the strongest place the computer offers, in this order:
//
//   systemd     $CREDENTIALS_DIRECTORY/sagentix-vault-key: a systemd credential (LoadCredentialEncrypted=, sealed to
//               the TPM where there is one), never on disk in clear
//   docker      /run/secrets/sagentix-vault-key: a Docker secret
//   keychain    macOS: the Keychain item sagentix-collector-vault / <key id>, through `security` (base64 on stdin)
//   dpapi       Windows: sagentix-collector.vault.key.dpapi, the key protected by DPAPI for the collector's account
//               (the protection Windows Credential Manager uses), through PowerShell (base64 on stdin)
//   file        anywhere else: sagentix-collector.vault.key, mode 0600; sos-app says the protection is the
//               file's permission only, and how to seal it
//
// A value is never logged and never sent to sos-app in clear.

import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { writePrivate } from "./channel.ts";

export const VAULT_FILE = "sagentix-collector.vault";
export const KEY_FILE = "sagentix-collector.vault.key";
export const DPAPI_FILE = "sagentix-collector.vault.key.dpapi";
export const CREDENTIAL_NAME = "sagentix-vault-key";
export const DOCKER_SECRET = `/run/secrets/${CREDENTIAL_NAME}`;
export const KEYCHAIN_SERVICE = "sagentix-collector-vault";
/** A name the vault takes: an environment variable's. */
export const NAME = /^[A-Z][A-Z0-9_]{0,99}$/;
export const MAX_VALUE = 64 * 1024;

export type Protection = "systemd" | "docker" | "keychain" | "dpapi" | "file";

/** secret: a value never shown again; file: a file's contents (a key or certificate), handed to a run as a private
 *  temporary file whose path goes in the variable; setting: not secret (a URL, a tenant id); sos-app keeps it in clear and shows it, and sends it unsealed. */
export type Kind = "secret" | "file" | "setting";
export const KINDS: readonly Kind[] = ["secret", "file", "setting"];
/** `bind`: for a secret or file, the connector's settings when it was sealed. A run uses it only while they still hold,
 *  so changing where a connector points (JAMF_URL, OKTA_DOMAIN) can never send an existing secret somewhere new. */
interface Entry { iv: string; tag: string; data: string; setAt: string; kind: Kind; bind?: Record<string, string> }
interface Sealed { iv: string; tag: string; data: string }
/** `seal`: the collector's X25519 private key (PKCS #8), itself sealed with the vault key; its public half goes to sos-app. */
/** `refs`: connectors read from the client's own vault (src/refs.ts), a reference each, never a value. */
interface VaultDoc { format: "sagentix-vault/1"; entries: Record<string, Entry>; seal?: Sealed & { publicKey: string };
                     refs?: Record<string, { provider: string; id: string; setAt: string }> }

export const SEAL_FORMAT = "sagentix-seal/1";
/** What sos-app relays for one value: an ephemeral X25519 public key, a nonce, and the AES-256-GCM ciphertext with its tag. */
export interface SealedValue { name: string; kind: Kind; epk: string; iv: string; data: string; bind?: Record<string, string> }

/** The bytes both sides bind in: the format, the collector's key id, the name and the kind. A value sealed for one
 *  name, kind or collector does not open as another. */
export const sealInfo = (keyId: string, name: string, kind: Kind, bind: Record<string, string> = {}) =>
  Buffer.from(`${SEAL_FORMAT}\n${keyId}\n${name}\n${kind}\n${canonicalBind(bind)}`);

/** The settings a value is bound to, in one spelling both sides compute: names sorted, JSON. */
export const canonicalBind = (b: Record<string, string>) => JSON.stringify(Object.keys(b).sort().map((k) => [k, b[k]]));

/** Where the key is kept. `read` answers null when there is none yet; `create` makes and keeps a new one. */
export interface KeyHolder {
  protection: Protection;
  read(): Buffer | null;
  create(): Buffer;
}

/** Runs a program with text on its standard input, never on its command line. */
export type Exec = (cmd: string, args: string[], input: string) => { status: number | null; stdout: string; stderr: string };
export const realExec: Exec = (cmd, args, input) => {
  const r = spawnSync(cmd, args, { input, encoding: "utf8", timeout: 30_000, windowsHide: true });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

const key32 = (b: Buffer | null) => (b && b.length === 32 ? b : null);
const fromB64 = (s: string) => key32(Buffer.from(s.trim(), "base64"));

function fileHolder(path: string, protection: Protection, readOnly: boolean): KeyHolder {
  return {
    protection,
    read: () => {
      if (!existsSync(path)) return null;
      const raw = readFileSync(path);
      return raw.length === 32 ? raw : fromB64(raw.toString("utf8"));
    },
    create: () => {
      if (readOnly) throw new Error(`the vault key ${path} is provided by ${protection} and is missing or unreadable`);
      const k = randomBytes(32);
      writePrivate(path, k.toString("base64") + "\n");
      return k;
    },
  };
}

/** `keychain`: a keychain file other than the login one (the tests use a throwaway keychain). */
function keychainHolder(account: string, exec: Exec, keychain?: string): KeyHolder {
  // The account goes into a `security -i` command line: a key id only (letters, digits, -).
  if (!/^[A-Za-z0-9-]{1,80}$/.test(account)) throw new Error("the key id is not one the Keychain item may be named after");
  const kc = keychain ? [keychain] : [];
  return {
    protection: "keychain",
    read: () => {
      const r = exec("/usr/bin/security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w", ...kc], "");
      return r.status === 0 ? fromB64(r.stdout) : null;
    },
    create: () => {
      const k = randomBytes(32);
      // `security -i` reads its commands on standard input, so the key never appears in a process listing.
      const r = exec("/usr/bin/security", ["-i"], `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${account} -l "Sagentix collector vault" -w ${k.toString("base64")}${keychain ? ` "${keychain}"` : ""}\n`);
      if (r.status !== 0) throw new Error(`the Keychain refused the vault key (${r.stderr.trim() || r.status})`);
      return k;
    },
  };
}

const DPAPI_PROTECT = "$in=[Console]::In.ReadToEnd().Trim();Add-Type -AssemblyName System.Security;"
  + "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Convert]::FromBase64String($in),$null,'CurrentUser'))";
const DPAPI_UNPROTECT = "$in=[Console]::In.ReadToEnd().Trim();Add-Type -AssemblyName System.Security;"
  + "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($in),$null,'CurrentUser'))";
const PS = ["-NoProfile", "-NonInteractive", "-Command"];

function dpapiHolder(path: string, exec: Exec): KeyHolder {
  return {
    protection: "dpapi",
    read: () => {
      if (!existsSync(path)) return null;
      const r = exec("powershell.exe", [...PS, DPAPI_UNPROTECT], readFileSync(path, "utf8"));
      return r.status === 0 ? fromB64(r.stdout) : null;
    },
    create: () => {
      const k = randomBytes(32);
      const r = exec("powershell.exe", [...PS, DPAPI_PROTECT], k.toString("base64"));
      if (r.status !== 0 || !r.stdout.trim()) throw new Error(`DPAPI refused the vault key (${r.stderr.trim() || r.status})`);
      writePrivate(path, r.stdout.trim() + "\n");
      return k;
    },
  };
}

/** The strongest key holder this computer offers (see the top of this file). */
export function keyHolderFor(dir: string, keyId: string, o: { env: NodeJS.ProcessEnv; platform: NodeJS.Platform; runner: string; exec?: Exec; exists?: (p: string) => boolean;
                                                              keychain?: string }): KeyHolder {
  const exec = o.exec ?? realExec, exists = o.exists ?? existsSync;
  const credDir = o.env.CREDENTIALS_DIRECTORY;
  if (credDir && exists(join(credDir, CREDENTIAL_NAME))) return fileHolder(join(credDir, CREDENTIAL_NAME), "systemd", true);
  if (exists(DOCKER_SECRET)) return fileHolder(DOCKER_SECRET, "docker", true);
  if (o.runner !== "docker" && o.platform === "darwin") return keychainHolder(keyId, exec, o.keychain);
  if (o.runner !== "docker" && o.platform === "win32") return dpapiHolder(join(dir, DPAPI_FILE), exec);
  return fileHolder(join(dir, KEY_FILE), "file", false);
}

export interface Listed { name: string; setAt: string; kind: Kind; bind?: Record<string, string> }

export class Vault {
  readonly path: string;
  private holder: KeyHolder;
  private key: Buffer | null = null;

  constructor(dir: string, holder: KeyHolder) { this.path = join(dir, VAULT_FILE); this.holder = holder; }

  get protection(): Protection { return this.holder.protection; }

  private doc(): VaultDoc {
    if (!existsSync(this.path)) return { format: "sagentix-vault/1", entries: {} };
    const d = JSON.parse(readFileSync(this.path, "utf8")) as VaultDoc;
    if (d?.format !== "sagentix-vault/1" || typeof d.entries !== "object") throw new Error(`${this.path} is not a collector vault`);
    return d;
  }

  private write(d: VaultDoc) {
    // A new file renamed over the old one, so a crash mid-write never leaves half a vault.
    const tmp = `${this.path}.${randomBytes(4).toString("hex")}.tmp`;
    writePrivate(tmp, JSON.stringify(d, null, 1) + "\n");
    renameSync(tmp, this.path);
  }

  /** The key, made on the first write when there is none. Reading an empty vault needs no key. */
  private keyFor(create: boolean): Buffer | null {
    if (this.key) return this.key;
    this.key = this.holder.read();
    if (!this.key && create) this.key = this.holder.create();
    return this.key;
  }

  /** Names, dates and whether each is a secret: no value, no key needed. */
  list(): Listed[] {
    return Object.entries(this.doc().entries).map(([name, e]) => ({ name, setAt: e.setAt, kind: e.kind, ...(e.bind ? { bind: e.bind } : {}) })).sort((a, b) => a.name.localeCompare(b.name));
  }

  set(name: string, value: string, o: { kind: Kind; now: Date; bind?: Record<string, string> }): void {
    if (!KINDS.includes(o.kind)) throw new Error(`${o.kind} is not a kind of vault entry`);
    if (!NAME.test(name)) throw new Error(`${name} is not a name the vault takes (capital letters, digits and _)`);
    if (typeof value !== "string" || value.length === 0) throw new Error("the value is empty");
    if (Buffer.byteLength(value) > MAX_VALUE) throw new Error(`the value is larger than ${MAX_VALUE / 1024} KiB`);
    const key = this.keyFor(true)!;
    const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(Buffer.from(`sagentix-vault/1\n${name}`));
    const data = Buffer.concat([c.update(value, "utf8"), c.final()]);
    const d = this.doc();
    d.entries[name] = { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64"), setAt: o.now.toISOString(), kind: o.kind, ...(o.bind && o.kind !== "setting" ? { bind: o.bind } : {}) };
    this.write(d);
  }

  remove(name: string): boolean {
    const d = this.doc();
    if (!(name in d.entries)) return false;
    delete d.entries[name];
    this.write(d);
    return true;
  }

  /** One value, or undefined when it is not there. Throws when the key is missing or the value was tampered with. */
  get(name: string): string | undefined {
    const e = this.doc().entries[name];
    if (!e) return undefined;
    const key = this.keyFor(false);
    if (!key) throw new Error(`the vault key is missing (${this.holder.protection}); the vault cannot be read`);
    const d = createDecipheriv("aes-256-gcm", key, Buffer.from(e.iv, "base64"));
    d.setAAD(Buffer.from(`sagentix-vault/1\n${name}`));
    d.setAuthTag(Buffer.from(e.tag, "base64"));
    try { return Buffer.concat([d.update(Buffer.from(e.data, "base64")), d.final()]).toString("utf8"); }
    catch { throw new Error(`the vault value ${name} does not open with this key (changed, or sealed with another key)`); }
  }

  private sealWith(key: Buffer, plain: Buffer, aad: string): Sealed {
    const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(Buffer.from(aad));
    const data = Buffer.concat([c.update(plain), c.final()]);
    return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") };
  }

  /** This collector's sealing public key (32 bytes, base64url), made with the vault key on first use. */
  sealPublicKey(): string {
    const d = this.doc();
    if (d.seal) return d.seal.publicKey;
    const key = this.keyFor(true)!;
    const { privateKey, publicKey } = generateKeyPairSync("x25519");
    const raw = publicKey.export({ format: "jwk" }).x!;
    d.seal = { ...this.sealWith(key, privateKey.export({ type: "pkcs8", format: "der" }), "sagentix-vault/1\nseal"), publicKey: raw };
    this.write(d);
    return raw;
  }

  /** Opens a value sealed in the browser for this collector (ECDH X25519, HKDF-SHA256, AES-256-GCM); throws when it
   *  was sealed for another collector, name or kind, or changed on the way. */
  openSealed(keyId: string, v: SealedValue): string {
    const d = this.doc();
    if (!d.seal) throw new Error("this collector has no sealing key yet");
    const key = this.keyFor(false);
    if (!key) throw new Error(`the vault key is missing (${this.holder.protection})`);
    const dk = createDecipheriv("aes-256-gcm", key, Buffer.from(d.seal.iv, "base64"));
    dk.setAAD(Buffer.from("sagentix-vault/1\nseal"));
    dk.setAuthTag(Buffer.from(d.seal.tag, "base64"));
    const priv = createPrivateKey({ key: Buffer.concat([dk.update(Buffer.from(d.seal.data, "base64")), dk.final()]), format: "der", type: "pkcs8" });
    const epk = Buffer.from(v.epk, "base64url");
    if (epk.length !== 32) throw new Error("the sealed value's ephemeral key is not 32 bytes");
    const shared = diffieHellman({ privateKey: priv, publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: v.epk }, format: "jwk" }) });
    const info = sealInfo(keyId, v.name, v.kind, v.bind ?? {});
    const aes = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([epk, Buffer.from(d.seal.publicKey, "base64url")]), info, 32));
    const all = Buffer.from(v.data, "base64"), iv = Buffer.from(v.iv, "base64");
    if (iv.length !== 12 || all.length < 17) throw new Error("the sealed value is malformed");
    const dc = createDecipheriv("aes-256-gcm", aes, iv);
    dc.setAAD(info);
    dc.setAuthTag(all.subarray(all.length - 16));
    try { return Buffer.concat([dc.update(all.subarray(0, all.length - 16)), dc.final()]).toString("utf8"); }
    catch { throw new Error(`the sealed value for ${v.name} does not open with this collector's key`); }
  }

  /** The connectors read from the client's own vault. */
  refs(): Record<string, { provider: string; id: string; setAt: string }> { return { ...(this.doc().refs ?? {}) }; }

  setRef(connector: string, ref: { provider: string; id: string }, now: Date): void {
    const d = this.doc();
    d.refs = { ...(d.refs ?? {}), [connector]: { provider: ref.provider, id: ref.id, setAt: now.toISOString() } };
    this.write(d);
  }

  removeRef(connector: string): boolean {
    const d = this.doc();
    if (!d.refs?.[connector]) return false;
    delete d.refs[connector];
    this.write(d);
    return true;
  }

  /** Every entry with its value, for a run's environment. */
  all(): { name: string; kind: Kind; value: string; bind?: Record<string, string> }[] {
    return this.list().map(({ name, kind, bind }) => ({ name, kind, value: this.get(name)!, ...(bind ? { bind } : {}) }));
  }
}

export interface RunEnv { env: NodeJS.ProcessEnv; used: string[]; secrets: string[]; warnings: string[]; cleanup(): void }

/**
 * A run's environment: the process's own, plus each vault entry it does not already set (a variable set on purpose
 * wins). `settingsOf(name)`: the settings of the connector a secret belongs to (the config's credentials). A `file` entry is written to a private temporary folder beside the config, its path put in the variable, and
 * the folder removed by `cleanup` when the run ends. No vault file: the environment as it is.
 */
export function runEnv(dir: string, holder: KeyHolder, base: NodeJS.ProcessEnv, settingsOf: (name: string) => string[] = () => []): RunEnv {
  const v = new Vault(dir, holder);
  if (!existsSync(v.path)) return { env: base, used: [], secrets: [], warnings: [], cleanup: () => {} };
  const env: NodeJS.ProcessEnv = { ...base }, used: string[] = [], secrets: string[] = [], warnings: string[] = [];
  const all = v.all();
  for (const e of all) if (e.kind === "setting" && !env[e.name]) { env[e.name] = e.value; used.push(e.name); }
  let tmp: string | undefined;
  for (const e of all) {
    if (e.kind === "setting" || env[e.name]) continue;
    // A secret is used only while its connector's settings are the ones it was set with: all of them, so a setting
    // added since (an optional URL) counts as a change too.
    if (e.bind) {
      const now: Record<string, string> = {};
      for (const k of settingsOf(e.name)) if (env[k]) now[k] = env[k]!;
      if (canonicalBind(now) !== canonicalBind(e.bind)) {
        const changed = [...new Set([...Object.keys(now), ...Object.keys(e.bind)])].filter((k) => now[k] !== e.bind![k]);
        warnings.push(`${e.name} is not used: ${changed.join(", ")} changed since it was set; set ${e.name} again`);
        continue;
      }
    }
    if (e.kind === "file") {
      tmp ??= mkdtempSync(join(dir, ".sagentix-run-"));
      const p = join(tmp, e.name.toLowerCase());
      writePrivate(p, e.value);
      env[e.name] = p;
    } else env[e.name] = e.value;
    used.push(e.name);
    secrets.push(e.value, ...e.value.split(/\r?\n/).filter((l) => l.length >= 16));
  }
  return { env, used, secrets, warnings, cleanup: () => { if (tmp) rmSync(tmp, { recursive: true, force: true }); } };
}
