// Read-only Cloudflare API v4 client. It has a GET method and nothing else, so a bug here cannot
// change the customer's account. Tests pass a fake client; nothing in tests touches the network.

export interface CfResponse {
  status: number;
  body: unknown;
}

export interface CloudflareApi {
  get(path: string): Promise<CfResponse>;
}

export const CF_API_BASE = "https://api.cloudflare.com/client/v4";
export const TOKEN_ENV = "CLOUDFLARE_API_TOKEN_READONLY";

export function fetchCloudflareApi(token: string, fetchFn: typeof fetch = fetch, base = CF_API_BASE): CloudflareApi {
  return {
    async get(path: string) {
      const res = await fetchFn(`${base}${path}`, { method: "GET", headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
      let body: unknown = null;
      try { body = await res.json(); } catch { body = null; }
      return { status: res.status, body };
    },
  };
}

export type Obj = Record<string, unknown>;
export const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
export const resultOf = (r: CfResponse): unknown => (isObj(r.body) ? r.body.result : undefined);
export const ok = (r: CfResponse) => r.status >= 200 && r.status < 300 && isObj(r.body) && r.body.success !== false;
export const str = (v: unknown) => (typeof v === "string" ? v : undefined);
export const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Why a call gave no usable answer, for a "skipped" detail. */
export function why(r: CfResponse): string {
  const errs = isObj(r.body) ? arr(r.body.errors).map((e) => (isObj(e) ? String(e.message ?? "") : "")).filter(Boolean) : [];
  const hint = r.status === 401 || r.status === 403
    ? " (the token may lack the read permission for this call, or the feature is not on the plan)"
    : "";
  return `HTTP ${r.status}${errs.length ? `: ${errs.join("; ").slice(0, 300)}` : ""}${hint}`;
}

export async function safeGet(api: CloudflareApi, path: string): Promise<CfResponse> {
  try { return await api.get(path); } catch (e) { return { status: 0, body: { success: false, errors: [{ message: `request failed: ${String(e)}` }] } }; }
}

/**
 * Every item of a page/per_page list endpoint. Stops at result_info.total_pages, at a short page,
 * or after maxPages. Returns the first failing response instead when a page cannot be read.
 */
export async function getAll(api: CloudflareApi, path: string, perPage = 50, maxPages = 40): Promise<{ items: unknown[] } | { error: CfResponse }> {
  const items: unknown[] = [];
  const sep = path.includes("?") ? "&" : "?";
  for (let page = 1; page <= maxPages; page++) {
    const r = await safeGet(api, `${path}${sep}per_page=${perPage}&page=${page}`);
    if (!ok(r) || !Array.isArray(resultOf(r))) return { error: r };
    const list = resultOf(r) as unknown[];
    items.push(...list);
    const info = isObj(r.body) && isObj(r.body.result_info) ? r.body.result_info : {};
    const total = Number(info.total_pages);
    if (Number.isFinite(total) && total > 0 ? page >= total : list.length < perPage) break;
  }
  return { items };
}

/** Go-style duration ("24h", "2h45m", "30m", "300ms") in seconds; undefined when it does not parse. */
export function durationSeconds(s: string): number | undefined {
  const unit: Record<string, number> = { ns: 1e-9, us: 1e-6, "µs": 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };
  const parts = [...s.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)];
  if (!parts.length || parts.map((p) => p[0]).join("") !== s.trim()) return undefined;
  return parts.reduce((t, p) => t + Number(p[1]) * unit[p[2]], 0);
}
