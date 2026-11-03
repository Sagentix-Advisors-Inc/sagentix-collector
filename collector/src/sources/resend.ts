// Resend (transactional email), read-only use of its REST API: the sending domains' authentication and the API
// keys' age and use. GET only, with RESEND_API_KEY.
//
// Resend has no read-only key. Its API key permissions are full_access ("Can create, delete, get, and update any
// resource") and sending_access ("Can only send emails"), and a sending_access key cannot list domains or keys
// (resend.com/docs/api-reference/api-keys/create-api-key, read 2026-11-02). So this source needs a full_access key.
// The collector itself only ever sends GET (fetchRest refuses anything else and any other origin), but the key could
// do more in other hands: give it a name of its own (for example "Sagentix collector, read only"), keep it in the
// Keychain or a secrets vault, and expire it if the machine is lost. The checks below then flag it like any other key.
//
// Pages and schema, all read 2026-11-02:
//   resend.com/docs/api-reference/introduction: base https://api.resend.com, "Authorization: Bearer re_xxxxxxxxx", a
//     User-Agent header on every request (a request without one is refused with 403), 10 requests per second per team
//     by default, 429 above it.
//   resend.com/docs/api-reference/domains/list-domains: GET /domains?limit=1..100&after=<id> -> { object: "list",
//     has_more, data: [ { id, name, status, created_at, region, open_tracking, click_tracking, capabilities: { sending,
//     receiving } } ] }.
//   resend.com/docs/api-reference/domains/get-domain: GET /domains/{id} -> the domain with records: [ { record (SPF,
//     DKIM, Tracking, ...), name, type, ttl, status, value, priority } ].
//   resend.com/docs/api-reference/api-keys/list-api-keys: GET /api-keys?limit&after -> { has_more, data: [ { id, name,
//     created_at, last_used_at } ] }; the permission is not returned.
//   Resend's OpenAPI (github.com/resend/resend-openapi, resend.yaml, info.version 1.5.1, commit 0b2a456): Domain.status
//     enum pending, verified, failed, not_started, partially_verified, partially_failed; DomainRecord.record enum SPF,
//     DKIM, Receiving, Tracking, TrackingCAA; DomainRecord.status enum pending, verified, failed, temporary_failure,
//     not_started. A domain's TLS mode (opportunistic or enforced) can be set (PATCH /domains/{id}) but is not in the
//     Domain schema GET returns, so no check reads it; DMARC is a DNS record Resend does not manage (the web source's
//     --web-mail-domain reads it).
//
// Results carry domain names and key ids; never a key's name, value or a DNS record's value.

import type { Result, Source, SourceContext } from "../types.ts";
import { COLLECTOR_VERSION } from "../payload.ts";
import {
  DAY_MS, Emitter, arr, enc, fetchRest, firstIds, getAll, isObj, listRead, ok, realSleep, redact, str, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";
import { posNum } from "./report_files.ts";

export const RESEND_CHECKS = ["sending_domains_authenticated", "api_keys_rotated", "api_keys_in_use"] as const;
type C = (typeof RESEND_CHECKS)[number];

export const RESEND_BASE = "https://api.resend.com";
export const RESEND_ENV = { token: "RESEND_API_KEY" } as const;
export const RESEND_DEFAULTS = { keyMaxAgeDays: 365, inactiveDays: 90 } as const;
const UA = `sagentix-evidence-collector/${COLLECTOR_VERSION} (+https://github.com/Sagentix-Advisors-Inc/sagentix-collector)`;
const PAGE = 100;

export function resendFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const token = env[RESEND_ENV.token];
  if (!token) return `${RESEND_ENV.token} is not set`;
  if (!token.startsWith("re_")) return `${RESEND_ENV.token} does not look like a Resend API key (re_...)`;
  return fetchRest({ base: RESEND_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${token}`, "user-agent": UA }) });
}

/** Resend's timestamps look like "2026-04-08 00:11:13.110779+00"; Date.parse wants an ISO 8601 offset. */
export function resendTime(v: unknown): number | undefined {
  const s = str(v);
  if (!s) return undefined;
  const iso = s.trim().replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00").replace(/(\.\d{3})\d+/, "$1");
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : undefined;
}

const list = (api: RestApi, path: string) =>
  getAll(api, `${path}?limit=${PAGE}`, (b) => (isObj(b) && Array.isArray(b.data) ? b.data : undefined), (r: HttpResponse) => {
    const b = r.body;
    if (!isObj(b) || b.has_more !== true) return undefined;
    const last = arr(b.data).filter(isObj).at(-1);
    return last && str(last.id) ? `${path}?limit=${PAGE}&after=${enc(String(last.id))}` : undefined;
  }, 50);

export const resend: Source = {
  name: "resend",
  options: {
    "resend-key-max-age-days": { type: "string", help: `largest age of a Resend API key, in days (default ${RESEND_DEFAULTS.keyMaxAgeDays})` },
    "resend-inactive-days": { type: "string", help: `days without use after which a Resend API key counts as unused (default ${RESEND_DEFAULTS.inactiveDays})` },
  },
  emits: RESEND_CHECKS.map((c) => `resend.${c}`),
  describe: () => "resend team (the API key's)",
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Emitter<C>("resend", "resend team");
    const given = ctx.clients.resend as RestApi | null | undefined;
    const built = given !== undefined ? given : resendFromEnv(ctx.env);
    if (!built || typeof built === "string") { out.skipAll(RESEND_CHECKS, typeof built === "string" ? built : `${RESEND_ENV.token} is not set`); return out.results; }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const now = ctx.now.getTime();

    // Sending domains: verified, with every SPF and DKIM record verified.
    const doms = await list(api, "/domains");
    if ("error" in doms) out.skip("sending_domains_authenticated", doms.error, "domains");
    else {
      const sending = doms.items.filter(isObj).filter((d) => !isObj(d.capabilities) || d.capabilities.sending !== "disabled");
      if (!sending.length) out.add("sending_domains_authenticated", "skipped", `${doms.items.length} domain(s), none sending; nothing to judge`, "resend team", listRead(doms));
      for (const d of sending) {
        const name = str(d.name) ?? String(d.id);
        const r = await api.get(`/domains/${enc(String(d.id))}`);
        if (!ok(r) || !isObj(r.body)) { out.skip("sending_domains_authenticated", r, `domain ${name}`, `resend domain ${name}`); continue; }
        const recs = arr(r.body.records).filter(isObj).filter((x) => x.record === "SPF" || x.record === "DKIM");
        const bad = recs.filter((x) => x.status !== "verified").map((x: Obj) => `${String(x.record)} ${String(x.type ?? "")} ${String(x.status)}`.replace(/\s+/g, " "));
        const kinds = new Set(recs.map((x) => x.record));
        const missing = ["SPF", "DKIM"].filter((k) => !kinds.has(k));
        const status = String(r.body.status ?? d.status);
        const pass = status === "verified" && !bad.length && !missing.length;
        out.add("sending_domains_authenticated", pass ? "pass" : "fail",
          `domain status ${status}; ${recs.length} SPF/DKIM record(s), ${bad.length} not verified${firstIds(bad)}${missing.length ? `; no ${missing.join(" or ")} record listed` : ""}; status verified and every SPF and DKIM record verified required`,
          `resend domain ${name}`, { method: "config-read", itemsRead: recs.length, complete: true });
      }
    }

    // API keys: age and last use.
    const keys = await list(api, "/api-keys");
    if ("error" in keys) { out.skip("api_keys_rotated", keys.error, "API keys"); out.skip("api_keys_in_use", keys.error, "API keys"); }
    else {
      const ks = keys.items.filter(isObj);
      const read = listRead(keys);
      if (!ks.length) {
        out.add("api_keys_rotated", "skipped", "the team has no API key; nothing to judge", "resend team", read);
        out.add("api_keys_in_use", "skipped", "the team has no API key; nothing to judge", "resend team", read);
      } else {
        const maxAge = posNum(ctx.opts["resend-key-max-age-days"], RESEND_DEFAULTS.keyMaxAgeDays);
        const inactive = posNum(ctx.opts["resend-inactive-days"], RESEND_DEFAULTS.inactiveDays);
        const old: string[] = [], idle: string[] = [];
        for (const k of ks) {
          const id = String(k.id);
          const created = resendTime(k.created_at);
          if (created === undefined || (now - created) / DAY_MS > maxAge) old.push(created === undefined ? `${id}:unknown age` : `${id}:${Math.floor((now - created) / DAY_MS)}d`);
          const used = resendTime(k.last_used_at);
          if (used === undefined || (now - used) / DAY_MS > inactive) idle.push(used === undefined ? `${id}:never used` : `${id}:${Math.floor((now - used) / DAY_MS)}d`);
        }
        out.add("api_keys_rotated", old.length ? "fail" : "pass",
          `${ks.length} API key(s), ${old.length} older than ${maxAge} days${firstIds(old)}; every key created within ${maxAge} days required (--resend-key-max-age-days)`, "resend team", read);
        out.add("api_keys_in_use", idle.length ? "fail" : "pass",
          `${ks.length} API key(s), ${idle.length} not used in the last ${inactive} days${firstIds(idle)}; every key used within ${inactive} days required, or expire it (--resend-inactive-days)`, "resend team", read);
      }
    }
    return redact(out.results, [ctx.env[RESEND_ENV.token]]);
  },
};
