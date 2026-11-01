// What sos-app may deliver to the vault (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 8), and the vault's summary the
// check-in reports. A check-in answer may carry `deliveries`; each is one of four things, and nothing else:
//
//   set         a value for a name the config's `credentials` lists, with that name's kind: a secret or file sealed in
//               the browser to this collector's key (sos-app cannot open it), or a setting in clear
//   remove      the vault's value for such a name
//   import-env  move such names' values from sagentix-collector.env into the vault, then drop those lines
//   test        run one connector of the config dry (resident mode only), and report its counts
//
// A delivery for a name the config does not list, or with another kind, is refused and reported, never applied: what
// sos-app says cannot widen what this collector reads. No delivery can name a file, a command or a source option.
// The outcome of each goes back in a signed POST /api/collect/vault/ack, with the vault's new summary.

import { closeSync, existsSync, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { signedPost, writePrivate, type Channel } from "./channel.ts";
import { scrubText } from "./report.ts";
import { KINDS, MAX_VALUE, NAME, Vault, canonicalBind, type KeyHolder, type Kind, type Protection, type SealedValue } from "./vault.ts";

export const ACK_PATH = "/api/collect/vault/ack";
export const ENV_FILE = "sagentix-collector.env";
export const MAX_DELIVERIES = 50;
const ID = /^[A-Za-z0-9-]{1,64}$/;

/** What a connector reads, as sos-app wrote it in the config's `credentials` (collector/src/config.ts). */
export interface Credential { sources: string[]; secrets?: string[]; files?: string[]; settings?: string[]; optional?: Record<string, string>;
                              instead?: Record<string, string>; signIn?: boolean }

export interface Delivery { id: string; op: "set" | "remove" | "import-env" | "test"; name?: string; kind?: Kind; sealed?: SealedValue; value?: string; connector?: string }
export interface DeliveryResult { id: string; ok: boolean; error?: string; moved?: string[]; leftFiles?: string[];
                                  test?: { exit: number | null; passed: number; failed: number; skipped: number; errors: string[]; timedOut?: boolean } }

export interface VaultSummary {
  sealKey: string | null; protection: Protection | null; error: string | null;
  entries: { name: string; kind: Kind; setAt: string; bind?: Record<string, string>; value?: string }[];
  /** Names the config lists that sagentix-collector.env still holds in clear. */
  envFile: string[];
  credentials: Record<string, Credential>;
}

export type TestOutcome = NonNullable<DeliveryResult["test"]>;

/** Each name a connector reads, with its kind: the only names a delivery may touch. */
export function knownNames(creds: Record<string, Credential>): Map<string, Kind> {
  const m = new Map<string, Kind>();
  for (const c of Object.values(creds)) {
    for (const n of c.secrets ?? []) m.set(n, "secret");
    for (const n of c.files ?? []) m.set(n, "file");
    for (const n of Object.values(c.instead ?? {})) if (!m.has(n)) m.set(n, n.endsWith("_FILE") ? "file" : "secret");
    for (const n of [...(c.settings ?? []), ...Object.keys(c.optional ?? {})]) if (!m.has(n)) m.set(n, "setting");
  }
  return m;
}

/** The settings of the connector a secret belongs to, as the vault holds them now: what a sealed value binds to. */
export function bindFor(creds: Record<string, Credential>, name: string, v: Vault): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of settingsOf(creds, name)) { const val = v.get(k); if (val !== undefined) out[k] = val; }
  return out;
}

/** The settings (required and optional) of every connector that reads this secret or file. */
export function settingsOf(creds: Record<string, Credential>, name: string): string[] {
  const out = new Set<string>();
  for (const c of Object.values(creds)) {
    if (![...(c.secrets ?? []), ...(c.files ?? []), ...Object.values(c.instead ?? {})].includes(name)) continue;
    for (const k of [...(c.settings ?? []), ...Object.keys(c.optional ?? {})]) out.add(k);
  }
  return [...out];
}

/** The config's credentials, or none when the file cannot be read. */
export function credentialsIn(configPath: string): Record<string, Credential> {
  try { return (JSON.parse(readFileSync(configPath, "utf8").replace(/^\uFEFF/, "")) as { credentials?: Record<string, Credential> }).credentials ?? {}; }
  catch { return {}; }
}

/** A file's text when it exists and is at most MAX_VALUE bytes; one open, so the size checked is the file read. */
function readSmall(path: string): string | null {
  let fd: number;
  try { fd = openSync(path, "r"); } catch { return null; }
  try {
    if (fstatSync(fd).size > MAX_VALUE) return null;
    const buf = Buffer.alloc(MAX_VALUE + 1);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return n > MAX_VALUE ? null : buf.subarray(0, n).toString("utf8");
  } finally { closeSync(fd); }
}

export interface Bridge { summary(): VaultSummary; apply(ds: unknown, o: { agent: boolean }): Promise<DeliveryResult[]> }

/** The vault beside a config, as the check-in sees it. `test`: the agent's dry run of some sources (absent in `run`). */
export function vaultBridge(o: { configPath: string; keyId: string; holder: KeyHolder; now: () => Date; log: (s: string) => void;
                                 test?: (sources: string[]) => Promise<TestOutcome> }): Bridge {
  const dir = dirname(o.configPath), envPath = join(dir, ENV_FILE);
  let vault: Vault | undefined;
  const v = () => (vault ??= new Vault(dir, o.holder));
  const creds = (): Record<string, Credential> => {
    try { return (JSON.parse(readFileSync(o.configPath, "utf8").replace(/^﻿/, "")) as { credentials?: Record<string, Credential> }).credentials ?? {}; }
    catch { return {}; }
  };
  const envLines = (known: Map<string, Kind>) => !existsSync(envPath) ? [] : readFileSync(envPath, "utf8").split(/\r?\n/)
    .map((l) => /^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/.exec(l.trim()))
    .filter((m): m is RegExpExecArray => !!m && known.has(m[1]) && m[2].length > 0)
    .map((m) => ({ name: m[1], value: m[2].replace(/^(['"])(.*)\1$/, "$2") }));

  function summary(): VaultSummary {
    const c = creds(), known = knownNames(c);
    let sealKey: string | null = null, entries: VaultSummary["entries"] = [], error: string | null = null, protection: Protection | null = null;
    try {
      protection = v().protection;
      // A setting's value goes along (a URL, a tenant id), so sos-app shows it and the browser binds a secret to it.
      entries = v().list().map((e) => e.kind === "setting" ? { ...e, value: v().get(e.name) } : e);
      sealKey = Object.keys(c).length ? v().sealPublicKey() : null;
    } catch (e) { error = String((e as Error)?.message ?? e).slice(0, 300); }
    return { sealKey, protection, error, entries, envFile: [...new Set(envLines(known).map((l) => l.name))], credentials: c };
  }

  function importEnv(known: Map<string, Kind>): Pick<DeliveryResult, "moved" | "leftFiles" | "error"> {
    const moved: string[] = [], leftFiles: string[] = [], problems: string[] = [], c = creds();
    // Settings first, so each secret binds to the settings it came with.
    for (const l of envLines(known).sort((x, y) => Number(known.get(x.name) !== "setting") - Number(known.get(y.name) !== "setting"))) {
      const kind = known.get(l.name)!;
      try {
        if (kind === "file") {
          const path = isAbsolute(l.value) ? l.value : join(dir, l.value);
          const text = readSmall(path);
          if (text === null) { problems.push(`${l.name}: the file it names is missing or too large`); continue; }
          v().set(l.name, text, { kind, now: o.now(), bind: bindFor(c, l.name, v()) });
          leftFiles.push(l.value);
        } else v().set(l.name, l.value, { kind, now: o.now(), ...(kind !== "setting" ? { bind: bindFor(c, l.name, v()) } : {}) });
        moved.push(l.name);
      } catch (e) { problems.push(`${l.name}: ${String((e as Error)?.message ?? e)}`); }
    }
    if (moved.length) {
      const keep = readFileSync(envPath, "utf8").split(/\r?\n/).filter((l) => !moved.includes(/^(?:export\s+)?([A-Z][A-Z0-9_]*)=/.exec(l.trim())?.[1] ?? ""));
      writePrivate(envPath, keep.join("\n").replace(/\n*$/, "\n"));
    }
    return { moved, leftFiles, ...(problems.length ? { error: problems.join("; ") } : {}) };
  }

  async function apply(raw: unknown, a: { agent: boolean }): Promise<DeliveryResult[]> {
    if (!Array.isArray(raw)) return [];
    const c = creds(), known = knownNames(c), out: DeliveryResult[] = [];
    for (const d of raw.slice(0, MAX_DELIVERIES) as Delivery[]) {
      if (typeof d !== "object" || d === null || typeof d.id !== "string" || !ID.test(d.id)) continue;
      const refuse = (error: string) => { out.push({ id: d.id, ok: false, error }); o.log(`vault: refused delivery ${d.id}: ${error}`); };
      try {
        if (d.op === "set" || d.op === "remove") {
          const name = String(d.name ?? ""), kind = known.get(name);
          if (!NAME.test(name) || !kind) { refuse(`${name.slice(0, 100)} is not a name this collector's connectors read`); continue; }
          if (d.op === "remove") { v().remove(name); o.log(`vault: ${name} removed`); out.push({ id: d.id, ok: true }); continue; }
          if (d.kind !== kind || !KINDS.includes(d.kind)) { refuse(`${name} is a ${kind}, not a ${String(d.kind)}`); continue; }
          let value: string;
          if (kind === "setting") {
            if (typeof d.value !== "string" || !d.value.trim()) { refuse(`${name}: no value`); continue; }
            value = d.value.trim();
          } else {
            if (!d.sealed || d.sealed.name !== name || d.sealed.kind !== kind) { refuse(`${name}: a ${kind} must come sealed, for this name and kind`); continue; }
            // The connector's settings as they stand now must be the ones the person saw when sealing.
            const bind = d.sealed.bind ?? {}, want = bindFor(c, name, v());
            const missing = Object.values(c).filter((x) => [...(x.secrets ?? []), ...(x.files ?? []), ...Object.values(x.instead ?? {})].includes(name))
              .flatMap((x) => x.settings ?? []).filter((k) => want[k] === undefined);
            if (missing.length) { refuse(`${name}: set ${missing.join(", ")} first, so the secret is bound to where it goes`); continue; }
            if (canonicalBind(bind) !== canonicalBind(want)) { refuse(`${name}: the connector's settings changed since it was sealed; enter it again`); continue; }
            value = v().openSealed(o.keyId, d.sealed);
          }
          v().set(name, value, { kind, now: o.now(), ...(kind !== "setting" ? { bind: d.sealed!.bind ?? {} } : {}) });
          o.log(`vault: ${name} set`);
          out.push({ id: d.id, ok: true });
        } else if (d.op === "import-env") {
          const r = importEnv(known);
          o.log(`vault: ${r.moved?.length ?? 0} value(s) moved from ${ENV_FILE}`);
          out.push({ id: d.id, ok: !r.error, ...r });
        } else if (d.op === "test") {
          if (!a.agent || !o.test) continue;   // left for the resident agent, which can run it now
          const id = String(d.connector ?? ""), cred = c[id];
          if (!cred) { refuse(`${id.slice(0, 40)} is not a connector of this collector`); continue; }
          const t = await o.test(cred.sources);
          const secrets = v().all().filter((e) => e.kind !== "setting").map((e) => e.value).filter((x) => x.length >= 6);
          out.push({ id: d.id, ok: true, test: { ...t, errors: t.errors.slice(0, 10).map((e) => scrubText(e, secrets).slice(0, 500)) } });
        } else refuse(`unknown operation ${String(d.op).slice(0, 20)}`);
      } catch (e) { refuse(String((e as Error)?.message ?? e).slice(0, 300)); }
    }
    return out;
  }

  return { summary, apply };
}

/** Reports what the deliveries did, with the vault's summary after them. Never throws. */
export async function ack(c: Pick<Channel, "origin" | "keyId" | "pem" | "fetch">, results: DeliveryResult[], s: VaultSummary, log: (x: string) => void): Promise<void> {
  try {
    const r = await signedPost(c, ACK_PATH, new TextEncoder().encode(JSON.stringify({ format: "sagentix-vault-ack/1", results, vault: s })));
    if (r.status !== 200) log(`warning: vault ack: HTTP ${r.status}`);
  } catch (e) { log(`warning: vault ack failed: ${String((e as Error)?.message ?? e)}`); }
}
