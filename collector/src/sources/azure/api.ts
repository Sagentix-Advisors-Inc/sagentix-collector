// Read-only Azure Resource Manager client. Every call to ARM is a GET to https://management.azure.com;
// the only POST is the OAuth2 token request to login.microsoftonline.com. Tests pass a fake transport,
// so nothing in tests touches the network.
//
// Credentials, in order (the first one present wins):
//   AZURE_ACCESS_TOKEN                                  a bearer token for https://management.azure.com
//                                                       (e.g. `az account get-access-token --query accessToken -o tsv`)
//   AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_FEDERATED_TOKEN_FILE   workload identity: the file holds an OIDC
//                                                       token (GitHub Actions, AKS), sent as client_assertion
//   AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET          a service principal secret

import { readFileSync } from "node:fs";
import { isObj, str, withRetry, type HttpReply, type Obj } from "../shared-cloud.ts";

export const ARM = "https://management.azure.com";
export const LOGIN = "https://login.microsoftonline.com";
export const ARM_SCOPE = "https://management.azure.com/.default";
export const CREDENTIAL_ENVS = ["AZURE_ACCESS_TOKEN", "AZURE_CLIENT_SECRET"] as const;

export interface AzureTransport {
  /** GET a full ARM URL (api-version included). */
  get(url: string): Promise<HttpReply>;
  /** Backoff sleep; tests pass one that records the waits. */
  sleep?: (ms: number) => Promise<void>;
}

/** The API versions used, each checked against Microsoft's REST reference (learn.microsoft.com/rest/api). */
export const API = {
  subscriptions: "2022-12-01",
  pricings: "2024-01-01",
  secureScores: "2020-01-01",
  diagnosticSettings: "2021-05-01-preview",
  keyVaults: "2024-11-01",
  storage: "2023-05-01",
  sql: "2021-11-01",
  network: "2023-09-01",
  policy: "2022-06-01",
  disks: "2023-10-02",
  recoveryServices: "2023-04-01",
  backup: "2023-04-01",
} as const;

const headersOf = (res: Response): Record<string, string> => {
  const h: Record<string, string> = {};
  res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
  return h;
};

export type TokenSource = () => Promise<string>;

/** A bearer token from the environment, or undefined when no credential is configured. */
export function tokenFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): TokenSource | undefined {
  const direct = env.AZURE_ACCESS_TOKEN;
  if (direct) return async () => direct;
  const tenant = env.AZURE_TENANT_ID, client = env.AZURE_CLIENT_ID;
  if (!tenant || !client) return undefined;
  const fileVar = env.AZURE_FEDERATED_TOKEN_FILE, secret = env.AZURE_CLIENT_SECRET;
  if (!fileVar && !secret) return undefined;
  let cached: string | undefined;
  return async () => {
    if (cached) return cached;
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: client, scope: ARM_SCOPE });
    if (fileVar) {
      form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      form.set("client_assertion", readFileSync(fileVar, "utf8").trim());
    } else form.set("client_secret", secret!);
    const res = await fetchFn(`${LOGIN}/${encodeURIComponent(tenant)}/oauth2/v2.0/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: form.toString(),
    });
    let body: unknown = null;
    try { body = await res.json(); } catch { body = null; }
    const tok = isObj(body) ? str(body.access_token) : undefined;
    if (!res.ok || !tok) {
      // error_description names the AADSTS code; it never carries the secret or the assertion.
      const why = isObj(body) ? String(body.error ?? "") : "";
      throw new Error(`Azure token request refused (HTTP ${res.status}${why ? ` ${why}` : ""})`);
    }
    cached = tok;
    return tok;
  };
}

/** The real transport: GET only, to management.azure.com only, with the bearer token. */
export function fetchAzure(token: TokenSource, fetchFn: typeof fetch = fetch): AzureTransport {
  return {
    async get(url: string) {
      if (!url.startsWith(`${ARM}/`)) return { status: 0, headers: {}, body: JSON.stringify({ error: { message: `refused a URL outside ${ARM}` } }) };
      let t: string;
      try { t = await token(); } catch (e) { return { status: 401, headers: {}, body: JSON.stringify({ error: { message: (e as Error).message } }) }; }
      const res = await fetchFn(url, { method: "GET", headers: { authorization: `Bearer ${t}`, accept: "application/json" } });
      return { status: res.status, headers: headersOf(res), body: await res.text() };
    },
  };
}

export interface ArmReply { status: number; json: unknown; reply: HttpReply }

export const okStatus = (s: number) => s >= 200 && s < 300;

/** One GET with retry on 429/503 (Retry-After honoured). */
export async function armGet(t: AzureTransport, url: string): Promise<ArmReply> {
  const reply = await withRetry(() => t.get(url), { sleep: t.sleep });
  let json: unknown = null;
  try { json = reply.body ? JSON.parse(reply.body) : null; } catch { json = null; }
  return { status: reply.status, json, reply };
}

/** ARM's error message (error.message or error.code), for a "skipped" detail. */
export function armMessage(r: ArmReply): string {
  const e = isObj(r.json) && isObj(r.json.error) ? r.json.error : undefined;
  if (e) return String(e.message ?? e.code ?? "");
  return r.reply.status === 0 ? r.reply.body.slice(0, 300) : "";
}

/**
 * Every item of an ARM list, following nextLink (up to maxPages). Returns the first failing reply
 * instead when a page cannot be read. A nextLink off management.azure.com is not followed.
 */
export async function listAll(t: AzureTransport, url: string, maxPages = 50): Promise<{ items: Obj[] } | { error: ArmReply }> {
  const items: Obj[] = [];
  let next: string | undefined = url;
  for (let page = 0; next && page < maxPages; page++) {
    const r = await armGet(t, next);
    if (!okStatus(r.status) || !isObj(r.json) || !Array.isArray(r.json.value)) return { error: r };
    items.push(...(r.json.value as unknown[]).filter(isObj));
    const n = str(r.json.nextLink);
    next = n && n.startsWith(`${ARM}/`) ? n : undefined;
  }
  return { items };
}

/** "<resource group>/<name>" from an ARM id, for result resources. */
export function rgName(id: unknown, name: unknown): string {
  const m = typeof id === "string" ? /\/resourceGroups\/([^/]+)\//i.exec(id) : null;
  return `${m ? `${m[1]}/` : ""}${String(name ?? "?")}`;
}
