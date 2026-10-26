// Google Workspace over the Admin SDK (GET only): a service account with domain-wide delegation that
// acts as a read-only admin, or, with no key file, a Workspace admin's one-time browser sign-in
// (google_oauth.ts, `collector google-login`). Scopes (Admin SDK discovery documents, admin.googleapis.com/$discovery):
//   GET /admin/directory/v1/users?customer=...                                 admin.directory.user.readonly
//   GET /admin/reports/v1/activity/users/all/applications/admin?maxResults=1   admin.reports.audit.readonly
//
// Users are read once with projection=basic; pages follow nextPageToken; a 429 or a 403
// rateLimitExceeded backs off. Personal data: counts and Google user ids only, never addresses.
//
// Drive sharing (added 2026-10-20) comes from the Cloud Identity Policy API, the only read-only API that shows
// it; the Admin SDK Directory and Reports APIs do not. All pages below read 2026-10-20:
//   GET https://cloudidentity.googleapis.com/v1/policies?filter=...  cloud-identity.policies.readonly
//       (docs.cloud.google.com/identity/docs/reference/rest/v1/policies/list; filter is CEL on setting.type)
//   Setting drive_and_docs.external_sharing: external_sharing_mode DISALLOWED | ALLOWLISTED_DOMAINS | ALLOWED and
//       allow_publishing_files ("When sharing outside of CUSTOMER_NAME is allowed, users in ORGANIZATION_UNIT_NAME
//       can make files and published web content visible to anyone with the link"); defaults ALLOWED and true;
//       reducer Max, the policy with the greatest sortOrder wins (docs.cloud.google.com/identity/docs/concepts/
//       supported-policy-api-settings and .../concepts/policy-api-concepts). Those pages write the fields in
//       snake_case; both spellings are read, since the live casing was not observed.
//   "Only a super administrator can use the Cloud Identity Policy API" (.../identity/docs/concepts/overview-policies).
// The policy read gets its own token holding only that scope, as GOOGLE_POLICY_ADMIN_EMAIL (default
// GOOGLE_ADMIN_EMAIL): an install whose domain-wide delegation lacks the scope, or whose admin is not a super
// admin, gets drive_external_sharing_restricted skipped and keeps every other check.

import { readFileSync } from "node:fs";
import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, googleAssertion, tokenRequest } from "./oauth.ts";
import { OAUTH_ENV, googleOAuthFromEnv } from "./google_oauth.ts";
import { DAY_MS, Emitter, enc, fetchRest, firstIds, getAll, intOpt, isObj, ok, realSleep, redact, str, why, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";

export const ADMIN_BASE = "https://admin.googleapis.com";
export const GOOGLE_ENV = { keyFile: "GOOGLE_SA_KEY_FILE", admin: "GOOGLE_ADMIN_EMAIL", customer: "GOOGLE_CUSTOMER_ID" } as const;
export const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
];
export const POLICY_BASE = "https://cloudidentity.googleapis.com";
export const POLICY_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly";
export const POLICY_ADMIN_ENV = "GOOGLE_POLICY_ADMIN_EMAIL";
export const DEFAULTS = { maxSuperAdmins: 4, staleDays: 90 };
/** lastLoginTime for a user who never signed in. */
const NEVER = "1970-01-01T00:00:00.000Z";

export const GOOGLE_CHECKS = [
  "two_step_enrolled", "two_step_enforced", "admins_two_step", "super_admins_limited", "inactive_users", "audit_reports_available",
  "drive_external_sharing_restricted",
] as const;
type C = (typeof GOOGLE_CHECKS)[number];

/** True for an HTTPS token endpoint on googleapis.com, the only place a Google service-account assertion goes. */
export function isGoogleTokenUri(uri: string): boolean {
  try { const u = new URL(uri); return u.protocol === "https:" && (u.hostname === "oauth2.googleapis.com" || u.hostname.endsWith(".googleapis.com")); } catch { return false; }
}

export function googleFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const file = env[GOOGLE_ENV.keyFile], admin = env[GOOGLE_ENV.admin];
  // The service account when its key file is named; else the signed-in admin's token file.
  if (!file && env[OAUTH_ENV.clientFile]) {
    const userToken = googleOAuthFromEnv(env, GOOGLE_SCOPES, fetchFn);
    if (typeof userToken === "string") return userToken;
    return fetchRest({ base: ADMIN_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${await userToken()}` }) });
  }
  if (!file && !admin) return `set ${GOOGLE_ENV.keyFile} and ${GOOGLE_ENV.admin} (service account), or ${OAUTH_ENV.clientFile} after \`collector google-login\``;
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

/** A client for the Cloud Identity Policy API with a token that holds only POLICY_SCOPE. */
export function googlePolicyFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const file = env[GOOGLE_ENV.keyFile], admin = env[POLICY_ADMIN_ENV] || env[GOOGLE_ENV.admin];
  // The browser sign-in asks for the two Admin SDK scopes only, so this read needs the service account.
  if (!file && env[OAUTH_ENV.clientFile]) return `the browser sign-in does not ask for ${POLICY_SCOPE}; this check needs the service-account path (${GOOGLE_ENV.keyFile} with domain-wide delegation)`;
  if (!file || !admin) return `${GOOGLE_ENV.keyFile} and ${GOOGLE_ENV.admin} are not both set`;
  let key: { client_email: string; private_key: string; token_uri?: string };
  try { key = JSON.parse(readFileSync(file, "utf8")); } catch (e) { return `${GOOGLE_ENV.keyFile} is not a readable service account key (${(e as NodeJS.ErrnoException).code ?? "bad JSON"})`; }
  if (typeof key.client_email !== "string" || typeof key.private_key !== "string") return `${GOOGLE_ENV.keyFile} has no client_email or private_key`;
  const tokenUri = key.token_uri ?? "https://oauth2.googleapis.com/token";
  if (!isGoogleTokenUri(tokenUri)) return `${GOOGLE_ENV.keyFile} names a token_uri outside googleapis.com over HTTPS`;
  const token = cachedToken(() => tokenRequest(tokenUri, {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: googleAssertion(key, admin, [POLICY_SCOPE], Math.floor(Date.now() / 1000)),
  }, fetchFn));
  return fetchRest({ base: POLICY_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

const DRIVE_SHARING = "drive_and_docs.external_sharing";
const field = (v: Obj, camel: string, snake: string) => (v[camel] !== undefined ? v[camel] : v[snake]);

/** drive_external_sharing_restricted: no Drive sharing policy lets users publish files to anyone with the link. */
export async function driveSharingCheck(api: RestApi | string, customer: string): Promise<Result[]> {
  const out = new Emitter<C>("google_workspace", `workspace customer ${customer}`);
  const c = "drive_external_sharing_restricted";
  const needs = `the Cloud Identity Policy API needs ${POLICY_SCOPE} in domain-wide delegation and a super administrator as ${POLICY_ADMIN_ENV} or ${GOOGLE_ENV.admin}`;
  if (typeof api === "string") { out.add(c, "skipped", `${api}; ${needs}`); return out.results; }
  const filter = `setting.type.matches('${DRIVE_SHARING}$')` + (customer === "my_customer" ? "" : ` && customer == "customers/${customer}"`);
  const first = `${POLICY_BASE}/v1/policies?pageSize=100&filter=${enc(filter)}`;
  const got = await getAll(api, first,
    (b) => (isObj(b) ? (Array.isArray(b.policies) ? b.policies : []) : undefined),
    (r: HttpResponse) => { const t = isObj(r.body) ? str(r.body.nextPageToken) : undefined; return t ? `${first}&pageToken=${enc(t)}` : undefined; }, 50);
  if ("error" in got) { out.add(c, "skipped", `Drive sharing policies not readable: ${why(got.error)}; ${needs}`); return out.results; }
  const policies = got.items.filter(isObj).filter((p) => isObj(p.setting) && String(p.setting.type ?? "").endsWith(DRIVE_SHARING));
  if (!policies.length) {
    out.add(c, "fail", `no ${DRIVE_SHARING} policy is listed, so Google's defaults apply: external_sharing_mode ALLOWED and allow_publishing_files true`);
    return out.results;
  }
  const modes = new Map<string, number>(), open: string[] = [];
  let admin = 0, nonGoogle = 0;
  for (const p of policies) {
    const set = p.setting as Obj;
    const v = isObj(set.value) ? set.value : {};
    const mode = String(field(v, "externalSharingMode", "external_sharing_mode") ?? "ALLOWED");
    const publish = field(v, "allowPublishingFiles", "allow_publishing_files") !== false;
    modes.set(mode, (modes.get(mode) ?? 0) + 1);
    if (p.type === "ADMIN") admin++;
    if (mode === "ALLOWED" && field(v, "allowNonGoogleInvites", "allow_non_google_invites") !== false) nonGoogle++;
    const q = isObj(p.policyQuery) ? p.policyQuery : {};
    if (mode === "ALLOWED" && publish) open.push(str(q.orgUnit) || str(q.group) || str(p.name) || "?");
  }
  out.add(c, open.length ? "fail" : "pass",
    `${policies.length} ${DRIVE_SHARING} polic${policies.length === 1 ? "y" : "ies"} (${admin} set by an admin); external_sharing_mode ${[...modes].map(([m, n]) => `${m} ${n}`).join(", ")}; `
    + `${open.length} let users make files visible to anyone with the link${firstIds(open)}; ${nonGoogle} allow sharing with people who have no Google account (reported, not judged); `
    + `external_sharing_mode DISALLOWED or ALLOWLISTED_DOMAINS, or allow_publishing_files false, required in every policy`);
  return out.results;
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
    const from = out.results.length;
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
    stampRead(out.results, from, listRead(users));   // every user check reads this one list
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
    // A client given in ctx.clients (the tests' fake) answers both APIs by absolute URL.
    // With the browser sign-in the Admin SDK client cannot read the Policy API: that check says why, never "not readable".
    const signedIn = !ctx.env[GOOGLE_ENV.keyFile] && !!ctx.env[OAUTH_ENV.clientFile];
    const policy = ctx.clients.googlePolicy !== undefined ? ctx.clients.googlePolicy as RestApi | string : given && !signedIn ? given : googlePolicyFromEnv(ctx.env);
    const drive = await driveSharingCheck(typeof policy === "string" ? policy : withRetry(policy, (ctx.clients.sleep as Sleep | undefined) ?? realSleep), customer);
    return redact([...await googleChecks(api, customer, o, ctx.now), ...drive], []);
  },
};
