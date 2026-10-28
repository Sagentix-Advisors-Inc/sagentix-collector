// Read-only Google Cloud REST client. GET only, plus POST to `:getIamPolicy` and `:getAncestry` (reads that Google
// exposes as POST); the fetch client refuses any other POST, so a bug here cannot change a project.
// The bearer token comes from GOOGLE_OAUTH_ACCESS_TOKEN (google-github-actions/auth with
// token_format: access_token), or, on a server or in a container (2026-10-28: Docker is the default runner, and an
// hour-long token cannot be scheduled), from a read-only service account's key file named by GCP_SA_KEY_FILE: the
// collector signs a JWT as the service account itself (no `sub`) and exchanges it for an hour's token, scope
// cloud-platform (the default of google-github-actions/auth); the service account's read-only roles bound what it reads.
// Tests pass a fake transport; nothing in tests touches the network.

import { readFileSync } from "node:fs";
import { isObj, str, withRetry, httpWhy, type HttpReply } from "../shared-cloud.ts";
import { cachedToken, googleAssertion, tokenRequest } from "../oauth.ts";
import { isGoogleTokenUri } from "../google_workspace.ts";

export const GCP_TOKEN_ENV = "GOOGLE_OAUTH_ACCESS_TOKEN";
export const GCP_KEY_ENV = "GCP_SA_KEY_FILE";
export const GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";

/** An access token from the key file in GCP_SA_KEY_FILE, renewed when it ends; why not, as text; undefined when unset. */
export function gcpKeyToken(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): (() => Promise<string>) | string | undefined {
  const file = env[GCP_KEY_ENV];
  if (!file) return undefined;
  let key: { client_email: string; private_key: string; token_uri?: string };
  try { key = JSON.parse(readFileSync(file, "utf8")); } catch (e) { return `${GCP_KEY_ENV} is not a readable service account key (${(e as NodeJS.ErrnoException).code ?? "bad JSON"})`; }
  if (typeof key.client_email !== "string" || typeof key.private_key !== "string") return `${GCP_KEY_ENV} has no client_email or private_key`;
  // Google's key format page shows token_uri "https://accounts.google.com/o/oauth2/token", and its OAuth page says the
  // assertion's aud "is always https://oauth2.googleapis.com/token" (both read 2026-10-28): the older address goes there.
  const named = key.token_uri ?? GOOGLE_TOKEN;
  const tokenUri = named === "https://accounts.google.com/o/oauth2/token" ? GOOGLE_TOKEN : named;
  // The key file names its own token endpoint; a tampered file could send the signed assertion elsewhere.
  if (!isGoogleTokenUri(tokenUri)) return `${GCP_KEY_ENV} names a token_uri outside googleapis.com over HTTPS`;
  return cachedToken(() => tokenRequest(tokenUri, {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: googleAssertion({ ...key, token_uri: tokenUri }, undefined, [GCP_SCOPE], Math.floor(Date.now() / 1000)),
  }, fetchFn));
}

/**
 * The two reads Google exposes as POST: :getIamPolicy, and Resource Manager v1 projects.getAncestry ("Gets a list of
 * ancestors in the resource hierarchy for the Project ... The caller must have read permissions for this Project",
 * cloudresourcemanager v1 discovery document revision 20261018, read 2026-10-26).
 */
export const READ_POSTS = /:(getIamPolicy|getAncestry)$/;

export interface GcpTransport {
  request(method: "GET" | "POST", url: string, body?: unknown): Promise<HttpReply>;
  sleep?: (ms: number) => Promise<void>;
}

export function fetchGcpTransport(token: string | (() => Promise<string>), fetchFn: typeof fetch = fetch): GcpTransport {
  return {
    async request(method, url, body) {
      if (method !== "GET" && !(method === "POST" && READ_POSTS.test(url.split("?")[0]))) {
        throw new Error(`refused: the GCP client only sends GET, and POST to :getIamPolicy or :getAncestry (${method} ${url.split("?")[0]})`);
      }
      const res = await fetchFn(url, {
        method,
        headers: { authorization: `Bearer ${typeof token === "string" ? token : await token()}`, accept: "application/json", ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      return { status: res.status, headers, body: await res.text() };
    },
  };
}

export interface GcpReply { status: number; json: unknown; raw: HttpReply }

export const okStatus = (r: GcpReply) => r.status >= 200 && r.status < 300 && isObj(r.json);

/** Google's error message from `{error: {message}}`, for a "skipped" detail. */
export function gWhy(r: GcpReply): string {
  const e = isObj(r.json) && isObj(r.json.error) ? str(r.json.error.message) ?? str(r.json.error.status) : undefined;
  return httpWhy(r.raw, e ?? (r.status === 0 ? r.raw.body : undefined));
}

export class Gcp {
  readonly t: GcpTransport;
  constructor(t: GcpTransport) { this.t = t; }

  async call(method: "GET" | "POST", url: string, body?: unknown): Promise<GcpReply> {
    const raw = await withRetry(() => this.t.request(method, url, body), { sleep: this.t.sleep });
    let json: unknown = null;
    try { json = raw.body ? JSON.parse(raw.body) : null; } catch { json = null; }
    return { status: raw.status, json, raw };
  }

  get(url: string) { return this.call("GET", url); }

  /**
   * Every item under `key` across pages (pageToken / nextPageToken). Returns the first failing reply
   * instead when a page cannot be read. Stops after maxPages.
   */
  async getAll(url: string, key: string, maxPages = 50): Promise<{ items: unknown[] } | { error: GcpReply }> {
    const items: unknown[] = [];
    let token: string | undefined;
    for (let i = 0; i < maxPages; i++) {
      const sep = url.includes("?") ? "&" : "?";
      const r = await this.get(token ? `${url}${sep}pageToken=${encodeURIComponent(token)}` : url);
      if (!okStatus(r)) return { error: r };
      const body = r.json as Record<string, unknown>;
      const page = body[key];
      if (Array.isArray(page)) items.push(...page);
      else if (isObj(page)) items.push(page); // aggregatedList: a map keyed by scope
      token = str(body.nextPageToken);
      if (!token) break;
    }
    return { items };
  }
}
