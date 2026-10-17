// Google Workspace over the Admin SDK (GET only): a service account with domain-wide delegation that
// acts as a read-only admin. Scopes (Admin SDK discovery documents, admin.googleapis.com/$discovery):
//   GET /admin/directory/v1/users?customer=...                                 admin.directory.user.readonly
//   GET /admin/reports/v1/activity/users/all/applications/admin?maxResults=1   admin.reports.audit.readonly
//
// Users are read once with projection=basic; pages follow nextPageToken; a 429 or a 403
// rateLimitExceeded backs off. Personal data: counts and Google user ids only, never addresses.

import { readFileSync } from "node:fs";
import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, googleAssertion, tokenRequest } from "./oauth.ts";
import {
  DAY_MS, Emitter, enc, fetchRest, firstIds, getAll, intOpt, isObj, ok, realSleep, redact, str, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";

export const ADMIN_BASE = "https://admin.googleapis.com";
export const GOOGLE_ENV = { keyFile: "GOOGLE_SA_KEY_FILE", admin: "GOOGLE_ADMIN_EMAIL", customer: "GOOGLE_CUSTOMER_ID" } as const;
export const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
];
export const DEFAULTS = { maxSuperAdmins: 4, staleDays: 90 };
/** lastLoginTime for a user who never signed in. */
const NEVER = "1970-01-01T00:00:00.000Z";

export const GOOGLE_CHECKS = [
  "two_step_enrolled", "two_step_enforced", "admins_two_step", "super_admins_limited", "inactive_users", "audit_reports_available",
] as const;
type C = (typeof GOOGLE_CHECKS)[number];

/** True for an HTTPS token endpoint on googleapis.com, the only place a Google service-account assertion goes. */
export function isGoogleTokenUri(uri: string): boolean {
  try { const u = new URL(uri); return u.protocol === "https:" && (u.hostname === "oauth2.googleapis.com" || u.hostname.endsWith(".googleapis.com")); } catch { return false; }
}

export function googleFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const file = env[GOOGLE_ENV.keyFile], admin = env[GOOGLE_ENV.admin];
  if (!file || !admin) return `${GOOGLE_ENV.keyFile} and ${GOOGLE_ENV.admin} are not both set`;
  let key: { client_email: string; private_key: string; token_uri?: string };
  try { key = JSON.parse(readFileSync(file, "utf8")); } catch (e) { return `${GOOGLE_ENV.keyFile} is not a readable service account key (${(e as NodeJS.ErrnoException).code ?? "bad JSON"})`; }
  if (typeof key.client_email !== "string" || typeof key.private_key !== "string") return `${GOOGLE_ENV.keyFile} has no client_email or private_key`;
  const tokenUri = key.token_uri ?? "https://oauth2.googleapis.com/token";
  // The key file names its own token endpoint; a tampered file could send the signed assertion elsewhere.
  if (!isGoogleTokenUri(tokenUri)) return `${GOOGLE_ENV.keyFile} names a token_uri outside googleapis.com over HTTPS`;
  const token = cachedToken(() => tokenRequest(tokenUri, {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: googleAssertion(key, admin, GOOGLE_SCOPES, Math.floor(Date.now() / 1000)),
  }, fetchFn));
  return fetchRest({ base: ADMIN_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

export interface GoogleOptions { maxSuperAdmins: number; staleDays: number }

export async function googleChecks(api: RestApi, customer: string, o: GoogleOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("google_workspace", `workspace customer ${customer}`);
  const first = `/admin/directory/v1/users?customer=${enc(customer)}&maxResults=500&projection=basic`;
  const users = await getAll(api, first,
    (b) => (isObj(b) ? (Array.isArray(b.users) ? b.users : []) : undefined),
    (r: HttpResponse) => { const t = isObj(r.body) ? str(r.body.nextPageToken) : undefined; return t ? `${first}&pageToken=${enc(t)}` : undefined; }, 200);

  if ("error" in users) {
    for (const c of ["two_step_enrolled", "two_step_enforced", "admins_two_step", "super_admins_limited", "inactive_users"] as const) out.skip(c, users.error, "directory users");
  } else {
    const live = users.items.filter(isObj).filter((u) => u.suspended !== true && u.archived !== true);
    const suspended = users.items.length - live.length;
    const ids = (xs: Obj[]) => xs.map((u) => String(u.id ?? "?"));
    const trunc = users.truncated ? "; list truncated at 200 pages" : "";
    if (!live.length) out.skipAll(["two_step_enrolled", "two_step_enforced", "admins_two_step", "super_admins_limited", "inactive_users"], "the directory lists no active user");
    else {
      const notEnrolled = live.filter((u) => u.isEnrolledIn2Sv !== true);
      out.add("two_step_enrolled", notEnrolled.length ? "fail" : "pass",
        `${live.length - notEnrolled.length} of ${live.length} active user(s) enrolled in 2-Step Verification${firstIds(ids(notEnrolled))}; all required${trunc}`);
      const notEnforced = live.filter((u) => u.isEnforcedIn2Sv !== true);
      out.add("two_step_enforced", notEnforced.length ? "fail" : "pass",
        `2-Step Verification enforced for ${live.length - notEnforced.length} of ${live.length} active user(s)${firstIds(ids(notEnforced))}; all required${trunc}`);
      const admins = live.filter((u) => u.isAdmin === true || u.isDelegatedAdmin === true);
      const weakAdmins = admins.filter((u) => u.isEnrolledIn2Sv !== true);
      if (!admins.length) out.add("admins_two_step", "skipped", "no active super or delegated admin is listed");
      else out.add("admins_two_step", weakAdmins.length ? "fail" : "pass",
        `${admins.length - weakAdmins.length} of ${admins.length} super or delegated admin(s) enrolled in 2-Step Verification${firstIds(ids(weakAdmins))}; all required`);
      const supers = live.filter((u) => u.isAdmin === true);
      const over = supers.length > o.maxSuperAdmins;
      out.add("super_admins_limited", over ? "fail" : "pass",
        `${supers.length} active super admin(s)${over ? firstIds(ids(supers)) : ""}; at most ${o.maxSuperAdmins} allowed (--google-max-super-admins)`);
      const cutoff = now.getTime() - o.staleDays * DAY_MS;
      const stale = live.filter((u) => {
        const last = String(u.lastLoginTime ?? NEVER);
        const t = last === NEVER ? NaN : Date.parse(last);
        if (Number.isFinite(t)) return t < cutoff;
        const created = Date.parse(String(u.creationTime));
        return Number.isFinite(created) && created < cutoff;
      });
      out.add("inactive_users", stale.length ? "fail" : "pass",
        `${stale.length} of ${live.length} active user(s) have not signed in for ${o.staleDays} days${firstIds(ids(stale))}; ${suspended} suspended or archived not counted; none allowed (--google-stale-days)${trunc}`);
    }
  }

  const rep = await api.get("/admin/reports/v1/activity/users/all/applications/admin?maxResults=1");
  if (!ok(rep) || !isObj(rep.body)) out.skip("audit_reports_available", rep, "Admin console audit (Reports API)");
  else {
    const items = Array.isArray(rep.body.items) ? rep.body.items : [];
    const when = isObj(items[0]) && isObj(items[0].id) ? String(items[0].id.time) : "?";
    out.add("audit_reports_available", items.length ? "pass" : "fail",
      items.length ? `Admin console audit readable; latest event at ${when}` : "Admin console audit readable but returned no event");
  }
  return out.results;
}

export const googleWorkspace: Source = {
  name: "google_workspace",
  options: {
    "google-max-super-admins": { type: "string", help: `active super admins allowed (default ${DEFAULTS.maxSuperAdmins})` },
    "google-stale-days": { type: "string", help: `days without sign-in before an active user is inactive (default ${DEFAULTS.staleDays})` },
  },
  emits: GOOGLE_CHECKS.map((c) => `google_workspace.${c}`),
  describe: () => "Google Workspace customer in GOOGLE_CUSTOMER_ID (default my_customer), Admin SDK",
  async run(ctx: SourceContext) {
    const customer = ctx.env[GOOGLE_ENV.customer] || "my_customer";
    const given = ctx.clients.google as RestApi | null | undefined;
    const built = given !== undefined ? given : googleFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("google_workspace", `workspace customer ${customer}`);
      out.skipAll(GOOGLE_CHECKS, typeof built === "string" ? built : "no Admin SDK client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: GoogleOptions = {
      maxSuperAdmins: intOpt(ctx.opts["google-max-super-admins"], DEFAULTS.maxSuperAdmins),
      staleDays: intOpt(ctx.opts["google-stale-days"], DEFAULTS.staleDays),
    };
    return redact(await googleChecks(api, customer, o, ctx.now), []);
  },
};
