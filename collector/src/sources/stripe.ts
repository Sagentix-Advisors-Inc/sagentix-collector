// Stripe, read-only: the webhook endpoints that receive the account's events. GET only, with a RESTRICTED key
// (rk_live_... or rk_test_...) in STRIPE_API_KEY whose only permission is Webhook Endpoints: Read. A secret key
// (sk_...) is refused before any request: it "has unrestricted permissions on all Stripe APIs" and cannot be narrowed.
//
// Pages, all read 2026-11-02:
//   docs.stripe.com/keys: key types; restricted keys rk_live_/rk_test_, secret keys sk_live_/sk_test_; Stripe
//     recommends migrating secret key usage to restricted keys.
//   docs.stripe.com/keys/restricted-api-keys: per-resource permission None, Read or Write; "GET" maps to read; write
//     implies read.
//   docs.stripe.com/api/webhook_endpoints/list (Stripe-Version 2026-10-28.endive on the page): GET /v1/webhook_endpoints
//     ?limit=1..100&starting_after=<id> -> { object: "list", has_more, data: [ { id, url, status, enabled_events,
//     livemode, api_version, application } ] }.
//   Stripe's OpenAPI (github.com/stripe/openapi, openapi/spec3.json, info.version 2026-09-30.endive, commit 51610f5):
//     webhook_endpoint.status "The status of the webhook. It can be `enabled` or `disabled`."; enabled_events
//     "`['*']` indicates that all events are enabled, except those that require explicit selection."
//
// What the API does not show, and so stays manual evidence: team members and their two-step authentication, the API
// key inventory, key access policies (docs.stripe.com/keys#access-policies, Dashboard only) and Radar rules.
// Results carry webhook endpoint ids and URL hosts; never a path, query or signing secret.

import type { Result, Source, SourceContext } from "../types.ts";
import {
  Emitter, arr, enc, fetchRest, firstIds, getAll, isObj, listRead, realSleep, redact, str, withRetry,
  type HttpResponse, type RestApi, type Sleep,
} from "./readonly_http.ts";

export const STRIPE_CHECKS = ["webhooks_https", "webhook_events_scoped"] as const;
type C = (typeof STRIPE_CHECKS)[number];

export const STRIPE_BASE = "https://api.stripe.com";
export const STRIPE_ENV = { token: "STRIPE_API_KEY" } as const;
const PAGE = 100;

/** Why a key is refused, or undefined for a restricted key. */
export function stripeKeyProblem(key: string | undefined): string | undefined {
  if (!key) return `${STRIPE_ENV.token} is not set`;
  if (/^sk_(live|test)_/.test(key)) return `${STRIPE_ENV.token} is a secret key (sk_), which can do anything in the account; create a restricted key (rk_) with only Webhook Endpoints: Read`;
  if (!/^rk_(live|test)_/.test(key)) return `${STRIPE_ENV.token} is not a restricted Stripe key (rk_live_ or rk_test_)`;
  return undefined;
}

export function stripeFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const key = env[STRIPE_ENV.token];
  const bad = stripeKeyProblem(key);
  if (bad) return bad;
  return fetchRest({ base: STRIPE_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${key}` }) });
}

const host = (u: unknown) => { try { return new URL(String(u)).host || "(no host)"; } catch { return "(not a URL)"; } };

export const stripe: Source = {
  name: "stripe",
  options: {},
  emits: STRIPE_CHECKS.map((c) => `stripe.${c}`),
  describe: () => "stripe account (the restricted key's)",
  async run(ctx: SourceContext): Promise<Result[]> {
    const key = ctx.env[STRIPE_ENV.token];
    const mode = key?.startsWith("rk_test_") ? " (sandbox)" : "";
    const out = new Emitter<C>("stripe", `stripe account${mode}`);
    // The refusal of a secret key holds even when a client is handed in.
    const keyBad = key !== undefined ? stripeKeyProblem(key) : undefined;
    if (keyBad) { out.skipAll(STRIPE_CHECKS, keyBad); return redact(out.results, [key]); }
    const given = ctx.clients.stripe as RestApi | null | undefined;
    const built = given !== undefined ? given : stripeFromEnv(ctx.env);
    if (!built || typeof built === "string") { out.skipAll(STRIPE_CHECKS, typeof built === "string" ? built : `${STRIPE_ENV.token} is not set`); return out.results; }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);

    const got = await getAll(api, `/v1/webhook_endpoints?limit=${PAGE}`, (b) => (isObj(b) && Array.isArray(b.data) ? b.data : undefined), (r: HttpResponse) => {
      const b = r.body;
      if (!isObj(b) || b.has_more !== true) return undefined;
      const last = arr(b.data).filter(isObj).at(-1);
      return last && str(last.id) ? `/v1/webhook_endpoints?limit=${PAGE}&starting_after=${enc(String(last.id))}` : undefined;
    }, 20);
    if ("error" in got) { for (const c of STRIPE_CHECKS) out.skip(c, got.error, "webhook endpoints"); return redact(out.results, [key]); }
    const read = listRead(got);
    const on = got.items.filter(isObj).filter((w) => w.status !== "disabled");
    if (!on.length) {
      for (const c of STRIPE_CHECKS) out.add(c, "skipped", `${got.items.length} webhook endpoint(s), none enabled; nothing to judge`, undefined, read);
      return redact(out.results, [key]);
    }
    const plain = on.filter((w) => !String(w.url ?? "").startsWith("https://")).map((w) => `${String(w.id)}:${host(w.url)}`);
    out.add("webhooks_https", plain.length ? "fail" : "pass",
      `${on.length} enabled webhook endpoint(s), ${plain.length} not on https${firstIds(plain)}; every endpoint URL on https required`, undefined, read);
    const all = on.filter((w) => arr(w.enabled_events).includes("*")).map((w) => `${String(w.id)}:${host(w.url)}`);
    out.add("webhook_events_scoped", all.length ? "fail" : "pass",
      `${on.length} enabled webhook endpoint(s), ${all.length} subscribed to every event ('*')${firstIds(all)}; each endpoint limited to the events it handles required`, undefined, read);
    return redact(out.results, [key]);
  },
};
