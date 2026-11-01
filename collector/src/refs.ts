// A connector read from the client's own vault (apps/sos-app/docs/COLLECTOR_VAULT.md, section 5). sos-app stores a
// reference, never a value: one secret in the client's vault, a JSON object holding every name the connector reads
// (its settings and its secrets together). The collector reads it at run time with the identity the computer already has.
//
//   aws        AWS Secrets Manager: arn:aws:secretsmanager:<region>:<account>:secret:<name>, GetSecretValue, signed with
//              the AWS credentials in the environment (keys, or a role through a web identity token)
//   azure      Azure Key Vault: https://<vault>.vault.azure.net/secrets/<name>, with a token for https://vault.azure.net
//              from AZURE_TENANT_ID + AZURE_CLIENT_ID (+ secret or federated token), else the managed identity
//   gcp        Google Cloud Secret Manager: projects/<project>/secrets/<name> (latest version), with GCP_SA_KEY_FILE,
//              else the metadata server's service account
//   hashicorp  HashiCorp Vault, key/value version 2: <mount>/<path>, at VAULT_ADDR with VAULT_TOKEN or an AppRole
//              (VAULT_ROLE_ID, VAULT_SECRET_ID); VAULT_NAMESPACE when set
//
// Why the whole connector, settings included: the destination then comes from the client's vault too. sos-app (or anyone
// who changed its data) can only point a connector at another secret; it can never pair a real secret with an address of
// its choosing. For the same reason a connector read by reference takes ALL its names from that one object and nothing
// else (not the local vault, not the environment), and is refused when the object lacks one it needs. The addresses a
// token goes to are fixed here or come from this computer's own environment (VAULT_ADDR), never from sos-app.

import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { writePrivate } from "./channel.ts";
import type { Credential } from "./deliveries.ts";
import { envCredentials, fetchAwsTransport } from "./sources/aws/api.ts";
import { gcpKeyToken } from "./sources/gcp/api.ts";

export const PROVIDERS = ["aws", "azure", "gcp", "hashicorp"] as const;
export type Provider = (typeof PROVIDERS)[number];
export interface Ref { provider: Provider; id: string }

const AWS_ARN = /^arn:aws(-[a-z]+)*:secretsmanager:([a-z]{2}(-[a-z]+)+-\d):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const AZURE_ID = /^https:\/\/([a-z0-9-]{3,24})\.vault\.azure\.net\/secrets\/([A-Za-z0-9-]{1,127})(\/[0-9a-f]{32})?$/;
const GCP_ID = /^projects\/([a-z][a-z0-9-]{4,28}[a-z0-9]|\d{1,20})\/secrets\/([A-Za-z0-9_-]{1,255})$/;
const VAULT_PATH = /^[A-Za-z0-9_-]{1,64}\/[A-Za-z0-9_./-]{1,512}$/;

/** Why a reference is not usable, or null. Checked on both sides: sos-app before queueing, the collector before reading. */
export function refProblem(r: unknown): string | null {
  if (typeof r !== "object" || r === null) return "a reference is an object";
  const { provider, id } = r as Record<string, unknown>;
  if (!PROVIDERS.includes(provider as Provider)) return `provider must be one of ${PROVIDERS.join(", ")}`;
  if (typeof id !== "string") return "id must be text";
  const ok = provider === "aws" ? AWS_ARN.test(id) : provider === "azure" ? AZURE_ID.test(id) : provider === "gcp" ? GCP_ID.test(id)
    : VAULT_PATH.test(id) && !id.split("/").includes("..");
  return ok ? null : ({ aws: "an AWS Secrets Manager ARN (arn:aws:secretsmanager:<region>:<account>:secret:<name>)",
                        azure: "an Azure Key Vault secret URL (https://<vault>.vault.azure.net/secrets/<name>)",
                        gcp: "a Secret Manager name (projects/<project>/secrets/<name>)",
                        hashicorp: "a key/value path (<mount>/<path>)" } as Record<string, string>)[provider as string];
}

type Fetch = typeof fetch;
const json = async (res: Response, what: string) => {
  const text = await res.text();
  if (!res.ok) throw new Error(`${what}: HTTP ${res.status}`);
  try { return JSON.parse(text) as Record<string, unknown>; } catch { throw new Error(`${what}: the answer is not JSON`); }
};

async function aws(id: string, env: NodeJS.ProcessEnv, f: Fetch): Promise<string> {
  const region = AWS_ARN.exec(id)![2];
  const creds = await envCredentials(env, region, f);
  if (!creds) throw new Error("no AWS credentials in the environment (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_ROLE_ARN with AWS_WEB_IDENTITY_TOKEN_FILE)");
  if ("error" in creds) throw new Error(creds.error);
  const host = `secretsmanager.${region}.amazonaws.com`;
  const r = await fetchAwsTransport(creds, f).send({ service: "secretsmanager", region, method: "POST", host, path: "/", query: {}, action: "GetSecretValue",
    headers: { host, "content-type": "application/x-amz-json-1.1", "x-amz-target": "secretsmanager.GetSecretValue" }, body: JSON.stringify({ SecretId: id }) });
  if (r.status !== 200) throw new Error(`AWS Secrets Manager GetSecretValue: HTTP ${r.status}`);
  const b = JSON.parse(r.body) as { SecretString?: string; SecretBinary?: string };
  if (typeof b.SecretString === "string") return b.SecretString;
  if (typeof b.SecretBinary === "string") return Buffer.from(b.SecretBinary, "base64").toString("utf8");
  throw new Error("AWS Secrets Manager returned no secret");
}

async function azureToken(env: NodeJS.ProcessEnv, f: Fetch): Promise<string> {
  const scope = "https://vault.azure.net/.default";
  if (env.AZURE_TENANT_ID && env.AZURE_CLIENT_ID && (env.AZURE_CLIENT_SECRET || env.AZURE_FEDERATED_TOKEN_FILE)) {
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: env.AZURE_CLIENT_ID, scope });
    if (env.AZURE_FEDERATED_TOKEN_FILE) {
      const { readFileSync } = await import("node:fs");
      form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      form.set("client_assertion", readFileSync(env.AZURE_FEDERATED_TOKEN_FILE, "utf8").trim());
    } else form.set("client_secret", env.AZURE_CLIENT_SECRET!);
    const b = await json(await f(`https://login.microsoftonline.com/${encodeURIComponent(env.AZURE_TENANT_ID)}/oauth2/v2.0/token`,
      { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() }), "Azure token");
    if (typeof b.access_token !== "string") throw new Error("Azure token: no access_token");
    return b.access_token;
  }
  // The managed identity of the virtual machine or container the collector runs on.
  const b = await json(await f("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net",
    { headers: { Metadata: "true" } }), "Azure managed identity");
  if (typeof b.access_token !== "string") throw new Error("Azure managed identity: no access_token");
  return b.access_token;
}

async function azure(id: string, env: NodeJS.ProcessEnv, f: Fetch): Promise<string> {
  const token = await azureToken(env, f);
  // AZURE_ID allows only https://<vault>.vault.azure.net, so the token goes to Key Vault and nowhere else.
  const b = await json(await f(`${id}?api-version=7.4`, { headers: { authorization: `Bearer ${token}` } }), "Azure Key Vault");
  if (typeof b.value !== "string") throw new Error("Azure Key Vault returned no value");
  return b.value;
}

async function gcp(id: string, env: NodeJS.ProcessEnv, f: Fetch): Promise<string> {
  let token: string;
  const key = gcpKeyToken(env, f);
  if (typeof key === "string") throw new Error(key);
  if (key) token = await key();
  else {
    const b = await json(await f("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      { headers: { "Metadata-Flavor": "Google" } }), "Google metadata server");
    if (typeof b.access_token !== "string") throw new Error("Google metadata server: no access_token");
    token = b.access_token;
  }
  const b = await json(await f(`https://secretmanager.googleapis.com/v1/${id}/versions/latest:access`, { headers: { authorization: `Bearer ${token}` } }), "Secret Manager");
  const data = (b.payload as { data?: string } | undefined)?.data;
  if (typeof data !== "string") throw new Error("Secret Manager returned no payload");
  return Buffer.from(data, "base64").toString("utf8");
}

async function hashicorp(id: string, env: NodeJS.ProcessEnv, f: Fetch): Promise<string> {
  const addr = env.VAULT_ADDR;
  if (!addr || !/^https:\/\/[^/]+/.test(addr)) throw new Error("VAULT_ADDR must be set on this computer, over https");
  const base = addr.replace(/\/+$/, "");
  const ns: Record<string, string> = env.VAULT_NAMESPACE ? { "X-Vault-Namespace": env.VAULT_NAMESPACE } : {};
  let token = env.VAULT_TOKEN;
  if (!token && env.VAULT_ROLE_ID && env.VAULT_SECRET_ID) {
    const b = await json(await f(`${base}/v1/auth/approle/login`, { method: "POST", headers: { "content-type": "application/json", ...ns },
      body: JSON.stringify({ role_id: env.VAULT_ROLE_ID, secret_id: env.VAULT_SECRET_ID }) }), "Vault AppRole login");
    token = (b.auth as { client_token?: string } | undefined)?.client_token;
  }
  if (!token) throw new Error("no Vault token (VAULT_TOKEN, or VAULT_ROLE_ID and VAULT_SECRET_ID)");
  const [mount, ...rest] = id.split("/");
  const b = await json(await f(`${base}/v1/${encodeURIComponent(mount)}/data/${rest.map(encodeURIComponent).join("/")}`, { headers: { "X-Vault-Token": token, ...ns } }), "Vault read");
  const data = (b.data as { data?: unknown } | undefined)?.data;
  if (typeof data !== "object" || data === null) throw new Error("Vault returned no key/value data");
  return JSON.stringify(data);
}

/** The object the reference names, as name to value. */
export async function readRef(r: Ref, env: NodeJS.ProcessEnv, f: Fetch = fetch): Promise<Record<string, string>> {
  const p = refProblem(r);
  if (p) throw new Error(`the reference is not usable: ${p}`);
  const raw = await ({ aws, azure, gcp, hashicorp }[r.provider])(r.id, env, f);
  let o: unknown;
  try { o = JSON.parse(raw); } catch { throw new Error("the secret is not a JSON object of names and values"); }
  if (typeof o !== "object" || o === null || Array.isArray(o)) throw new Error("the secret is not a JSON object of names and values");
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(o)) if (typeof v === "string") out[k] = v;
  return out;
}

/** The names a connector must find in its object: its settings, and each secret or its alternative. */
export function required(c: Credential): { all: string[]; missing: (have: Record<string, string>) => string[] } {
  const instead = c.instead ?? {};
  const all = [...(c.secrets ?? []), ...(c.files ?? []), ...(c.settings ?? []), ...Object.keys(c.optional ?? {}), ...Object.values(instead)];
  return {
    all: [...new Set(all)],
    missing: (have) => [
      ...(c.settings ?? []).filter((k) => !have[k]),
      ...(c.secrets ?? []).filter((k) => !have[k] && !(instead[k] && have[instead[k]])),
      ...(c.files ?? []).filter((k) => !have[k] && !Object.values(instead).includes(k)),
    ],
  };
}

export interface Applied { env: NodeJS.ProcessEnv; secrets: string[]; warnings: string[]; used: string[]; cleanup(): void }

/**
 * A run's environment after its references: for each connector read from the client's vault, every name it reads comes
 * from that object and nothing else (a file name's value written to a private temporary file); a connector whose
 * object cannot be read, or lacks a name it needs, gets none of its names, so its source fails on its own and says why.
 */
export async function applyRefs(dir: string, refs: Record<string, { provider: string; id: string }>, creds: Record<string, Credential>,
                                base: NodeJS.ProcessEnv, f: Fetch = fetch): Promise<Applied> {
  const env: NodeJS.ProcessEnv = { ...base }, secrets: string[] = [], warnings: string[] = [], used: string[] = [];
  let tmp: string | undefined;
  for (const [connector, ref] of Object.entries(refs)) {
    const c = creds[connector];
    if (!c) continue;
    const need = required(c);
    for (const k of need.all) delete env[k];
    let got: Record<string, string>;
    try { got = await readRef(ref as Ref, env, f); }
    catch (e) { warnings.push(`${connector}: its secret in your vault could not be read: ${String((e as Error)?.message ?? e).slice(0, 300)}`); continue; }
    const missing = need.missing(got);
    if (missing.length) { warnings.push(`${connector}: its secret in your vault lacks ${missing.join(", ")}; none of its names are used`); continue; }
    const files = new Set([...(c.files ?? []), ...Object.values(c.instead ?? {}).filter((n) => n.endsWith("_FILE"))]);
    const settings = new Set([...(c.settings ?? []), ...Object.keys(c.optional ?? {})]);
    for (const k of need.all) {
      const v = got[k];
      if (v === undefined || v === "") continue;
      if (files.has(k)) {
        tmp ??= mkdtempSync(join(dir, ".sagentix-run-"));
        const p = join(tmp, k.toLowerCase());
        writePrivate(p, v);
        env[k] = p;
      } else env[k] = v;
      if (!settings.has(k)) secrets.push(v, ...v.split(/\r?\n/).filter((l) => l.length >= 16));
      used.push(k);
    }
  }
  return { env, secrets, warnings, used, cleanup: () => { if (tmp) rmSync(tmp, { recursive: true, force: true }); } };
}
