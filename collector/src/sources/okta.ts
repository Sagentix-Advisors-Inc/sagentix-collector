// Okta management API (GET only), with an API token of a Read-Only Administrator (SSWS) or an OAuth
// access token from a service app granted the okta.*.read scopes below.
//
// Endpoint → OAuth scope (Okta management OpenAPI,
// github.com/okta/okta-management-openapi-spec/blob/master/dist/current/management-minimal.yaml,
// info.version 2026.41.0 at commit 2bc3a36, read 2026-10-20; each path's `security` names the scope):
//   GET /api/v1/policies?type=MFA_ENROLL|OKTA_SIGN_ON|ACCESS_POLICY|PASSWORD   okta.policies.read
//   GET /api/v1/policies/{id}/rules                                           okta.policies.read
//   GET /api/v1/authenticators, /api/v1/authenticators/{id}/methods           okta.authenticators.read (Identity Engine)
//   GET /api/v1/iam/assignees/users, /api/v1/users/{id}/roles                 okta.roles.read
//   GET /api/v1/users?filter=status eq "ACTIVE"                              okta.users.read
//   GET /api/v1/logs                                                         okta.logs.read
//
// Pages follow the Link rel="next" header (or _links.next.href for role assignees); a 429 waits
// for X-Rate-Limit-Reset. Personal data: counts and Okta user ids only.

import type { Result, Source, SourceContext } from "../types.ts";
import { DAY_MS, Emitter, arr, enc, fetchRest, firstIds, getAll, intOpt, isObj, linkNext, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead } from "./readonly_http.ts";

export const OKTA_ENV = { domain: "OKTA_DOMAIN", token: "OKTA_API_TOKEN", access: "OKTA_ACCESS_TOKEN" } as const;
export const DEFAULTS = { maxSuperAdmins: 3, staleDays: 90, minPasswordLength: 12 };
/** Okta's own default is 10 attempts; 0 means no lockout. */
export const MAX_LOCKOUT_ATTEMPTS = 10;

export const OKTA_CHECKS = [
  "mfa_enroll_required", "phishing_resistant_authenticator", "global_session_requires_mfa", "app_policies_require_2fa",
  "password_policy", "account_lockout", "super_admins_limited", "inactive_users", "system_log_available",
] as const;
type C = (typeof OKTA_CHECKS)[number];

const arrayBody = (b: unknown) => (Array.isArray(b) ? b : undefined);
const list = (api: RestApi, path: string) => getAll(api, path, arrayBody, (r) => linkNext(r.headers), 100);

export function oktaFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const domain = env[OKTA_ENV.domain];
  const token = env[OKTA_ENV.token], access = env[OKTA_ENV.access];
  if (!domain || (!token && !access)) return `${OKTA_ENV.domain} and ${OKTA_ENV.token} (or ${OKTA_ENV.access}) are not all set`;
  const base = /^https:\/\//.test(domain) ? domain.replace(/\/+$/, "") : `https://${domain.replace(/\/+$/, "")}`;
  const auth = token ? `SSWS ${token}` : `Bearer ${access}`;
  return fetchRest({ base, fetchFn, headers: async () => ({ authorization: auth }) });
}

export interface OktaOptions { maxSuperAdmins: number; staleDays: number; minPasswordLength: number }

const active = (x: Obj) => x.status === undefined || x.status === "ACTIVE";
const label = (kind: string, p: Obj) => `okta ${kind} policy ${String(p.name ?? "")} (${String(p.id ?? "?")})`;

async function policies(api: RestApi, type: string) {
  const r = await list(api, `/api/v1/policies?type=${type}`);
  return "error" in r ? r : { items: r.items.filter(isObj).filter(active) };
}

async function rules(api: RestApi, p: Obj) {
  const r = await list(api, `/api/v1/policies/${enc(String(p.id))}/rules`);
  return "error" in r ? r : { items: r.items.filter(isObj).filter(active) };
}

export async function oktaChecks(api: RestApi, org: string, o: OktaOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("okta", `okta org ${org}`);

  // Authenticator enrollment: each active policy requires at least one authenticator besides the password.
  const enroll = await policies(api, "MFA_ENROLL");
  if ("error" in enroll) out.skip("mfa_enroll_required", enroll.error, "authenticator enrollment policies");
  else if (!enroll.items.length) out.add("mfa_enroll_required", "fail", "no active authenticator enrollment (MFA_ENROLL) policy");
  else for (const p of enroll.items) {
    const s = isObj(p.settings) ? p.settings : {};
    const oie = arr(s.authenticators).filter(isObj).filter((a) => isObj(a.enroll) && a.enroll.self === "REQUIRED" && a.key !== "okta_password").map((a) => String(a.key));
    const classic = isObj(s.factors) ? Object.entries(s.factors).filter(([, f]) => isObj(f) && isObj(f.enroll) && f.enroll.self === "REQUIRED").map(([k]) => k) : [];
    const req = [...oie, ...classic];
    out.add("mfa_enroll_required", req.length ? "pass" : "fail",
      `${req.length} authenticator(s) required at enrollment${req.length ? ` (${req.join(", ")})` : ""}; at least one besides the password required`, label("enrollment", p));
  }

  // Authenticators (Identity Engine).
  const auths = await list(api, "/api/v1/authenticators");
  if ("error" in auths) out.skip("phishing_resistant_authenticator", auths.error, "authenticators (Identity Engine only)");
  else {
    const on = auths.items.filter(isObj).filter((a) => a.status === "ACTIVE");
    const resistant = on.filter((a) => a.key === "webauthn" || a.key === "smart_card_idp").map((a) => String(a.key));
    const ov = on.find((a) => a.key === "okta_verify");
    if (ov) {
      const m = await api.get(`/api/v1/authenticators/${enc(String(ov.id))}/methods`);
      if (ok(m) && Array.isArray(m.body) && m.body.some((x) => isObj(x) && x.type === "signed_nonce" && x.status === "ACTIVE")) resistant.push("okta_verify FastPass (signed_nonce)");
    }
    out.add("phishing_resistant_authenticator", resistant.length ? "pass" : "fail",
      `active authenticators: ${on.map((a) => String(a.key)).join(", ") || "none"}; phishing-resistant: ${resistant.join(", ") || "none"}; at least one required`);
  }

  // App sign-in (authentication) policies: every active ALLOW rule asks for two factors. Read first, because a
  // global session rule may hand MFA to them (below).
  const asp = await policies(api, "ACCESS_POLICY");
  let apps: "all2fa" | "weak" | "unknown" = "unknown";
  if ("error" in asp) out.skip("app_policies_require_2fa", asp.error, "app sign-in policies (Identity Engine only)");
  else if (!asp.items.length) out.add("app_policies_require_2fa", "skipped", "no active app sign-in (ACCESS_POLICY) policy");
  else {
    const verdicts: string[] = [];
    for (const p of asp.items) {
      const r = await rules(api, p);
      if ("error" in r) { out.skip("app_policies_require_2fa", r.error, "the policy's rules", label("app sign-in", p)); verdicts.push("unknown"); continue; }
      const allow = r.items.filter((x) => isObj(x.actions) && isObj(x.actions.appSignOn) && x.actions.appSignOn.access === "ALLOW");
      const vm = (x: Obj) => { const a = ((x.actions as Obj).appSignOn as Obj).verificationMethod; return isObj(a) ? a : {}; };
      const chains = allow.filter((x) => vm(x).type === "AUTH_METHOD_CHAIN");
      const weak = allow.filter((x) => vm(x).type !== "AUTH_METHOD_CHAIN" && vm(x).factorMode !== "2FA").map((x) => JSON.stringify(String(x.name ?? x.id)));
      verdicts.push(weak.length ? "weak" : chains.length ? "unknown" : "all2fa");
      if (!weak.length && chains.length) out.add("app_policies_require_2fa", "skipped", `${chains.length} ALLOW rule(s) use an authentication method chain, which this check does not judge`, label("app sign-in", p));
      else out.add("app_policies_require_2fa", weak.length ? "fail" : "pass",
        `${allow.length} active ALLOW rule(s), ${weak.length} not requiring factorMode 2FA${weak.length ? ` (${weak.slice(0, 10).join(", ")})` : ""}; 2FA required on every ALLOW rule`,
        label("app sign-in", p));
    }
    apps = verdicts.includes("weak") ? "weak" : verdicts.every((v) => v === "all2fa") ? "all2fa" : "unknown";
  }

  // Global session policies: every active ALLOW rule requires a factor, or hands the session to app sign-in policies
  // that all require two. Okta's API (management OpenAPI 2026.42.1, read 2026-10-26) defines primaryFactor
  // PASSWORD_IDP_ANY_FACTOR as "users can use any factor required by the app's app sign-in policy to establish a
  // session", and Okta's default global session policy "allows access with a password, IdP, or any factor allowed by
  // the app sign-in policies" (help.okta.com, "Global session policies", read 2026-10-26). Such a rule without
  // requireFactor leaves MFA to the app sign-in policies, so it passes only when every one of them asks for 2FA.
  const gsp = await policies(api, "OKTA_SIGN_ON");
  if ("error" in gsp) out.skip("global_session_requires_mfa", gsp.error, "global session policies");
  else if (!gsp.items.length) out.add("global_session_requires_mfa", "fail", "no active global session (OKTA_SIGN_ON) policy");
  else for (const p of gsp.items) {
    const r = await rules(api, p);
    if ("error" in r) { out.skip("global_session_requires_mfa", r.error, "the policy's rules", label("global session", p)); continue; }
    const allow = r.items.filter((x) => isObj(x.actions) && isObj(x.actions.signon) && x.actions.signon.access === "ALLOW");
    const signon = (x: Obj) => ((x.actions as Obj).signon) as Obj;
    const noFactor = allow.filter((x) => signon(x).requireFactor !== true);
    const handed = noFactor.filter((x) => signon(x).primaryFactor === "PASSWORD_IDP_ANY_FACTOR");
    const weak = noFactor.filter((x) => !handed.includes(x) || apps === "weak").map((x) => JSON.stringify(String(x.name ?? x.id)));
    const appsNote = handed.length ? `; ${handed.length} rule(s) without requireFactor establish the session with any factor the app sign-in policies require (PASSWORD_IDP_ANY_FACTOR), and those policies ${apps === "all2fa" ? "all require 2FA" : apps === "weak" ? "do not all require 2FA" : "could not all be judged"}` : "";
    const result = weak.length ? "fail" : handed.length && apps === "unknown" ? "skipped" : "pass";
    out.add("global_session_requires_mfa", result,
      `${allow.length} active ALLOW rule(s), ${noFactor.length} without requireFactor${weak.length ? ` (${weak.slice(0, 10).join(", ")})` : ""}${appsNote}; MFA required on every ALLOW rule, here or in every app sign-in policy`,
      label("global session", p));
  }

  // Password policies: length, and a lockout.
  const pw = await policies(api, "PASSWORD");
  if ("error" in pw) { out.skip("password_policy", pw.error, "password policies"); out.skip("account_lockout", pw.error, "password policies"); }
  else if (!pw.items.length) out.skipAll(["password_policy", "account_lockout"], "no active password policy is listed");
  else for (const p of pw.items) {
    const pwd = isObj(p.settings) && isObj(p.settings.password) ? p.settings.password : {};
    const cx = isObj(pwd.complexity) ? pwd.complexity : {}, age = isObj(pwd.age) ? pwd.age : {}, lk = isObj(pwd.lockout) ? pwd.lockout : {};
    const len = Number(cx.minLength);
    if (!Number.isFinite(len)) out.add("password_policy", "skipped", "the policy shows no complexity.minLength", label("password", p));
    else out.add("password_policy", len >= o.minPasswordLength ? "pass" : "fail",
      `minLength ${len}, historyCount ${String(age.historyCount ?? "?")}, maxAgeDays ${String(age.maxAgeDays ?? "?")}; minLength ${o.minPasswordLength} or more required (--okta-min-password-length)`, label("password", p));
    const att = Number(lk.maxAttempts);
    if (!Number.isFinite(att)) out.add("account_lockout", "skipped", "the policy shows no lockout.maxAttempts", label("password", p));
    else out.add("account_lockout", att >= 1 && att <= MAX_LOCKOUT_ATTEMPTS ? "pass" : "fail",
      `lockout.maxAttempts ${att}${att === 0 ? " (no lockout)" : ""}, autoUnlockMinutes ${String(lk.autoUnlockMinutes ?? "?")}; 1 to ${MAX_LOCKOUT_ATTEMPTS} required`, label("password", p));
  }

  // Super Administrators.
  const holders = await getAll(api, "/api/v1/iam/assignees/users?limit=100",
    (b) => (isObj(b) && Array.isArray(b.value) ? b.value : undefined),
    (r) => linkNext(r.headers) ?? (isObj(r.body) && isObj(r.body._links) && isObj(r.body._links.next) ? str(r.body._links.next.href) : undefined), 50);
  if ("error" in holders) out.skip("super_admins_limited", holders.error, "users with admin roles");
  else {
    const supers: string[] = [];
    let unread: HttpResponse | undefined;
    for (const u of holders.items.filter(isObj)) {
      const id = String(u.id ?? "?");
      const r = await api.get(`/api/v1/users/${enc(id)}/roles`);
      if (!ok(r) || !Array.isArray(r.body)) { unread = r; break; }
      if (r.body.some((x) => isObj(x) && x.type === "SUPER_ADMIN")) supers.push(id);
    }
    if (unread) out.skip("super_admins_limited", unread, "a user's roles");
    else {
      const over = supers.length > o.maxSuperAdmins;
      out.add("super_admins_limited", over ? "fail" : "pass",
        `${supers.length} of ${holders.items.length} admin user(s) hold SUPER_ADMIN${over ? firstIds(supers) : ""}; at most ${o.maxSuperAdmins} allowed (--okta-max-super-admins)${holders.truncated ? "; the admin list stopped at 50 pages" : ""}`,
        out.resource, listRead(holders));
    }
  }

  // Inactive users.
  const users = await list(api, `/api/v1/users?limit=200&filter=${enc('status eq "ACTIVE"')}`);
  if ("error" in users) out.skip("inactive_users", users.error, "active users");
  else {
    const cutoff = now.getTime() - o.staleDays * DAY_MS;
    const all = users.items.filter(isObj);
    const stale = all.filter((u) => {
      const last = Date.parse(String(u.lastLogin));
      if (Number.isFinite(last)) return last < cutoff;
      const created = Date.parse(String(u.created));
      return Number.isFinite(created) && created < cutoff;
    }).map((u) => String(u.id ?? "?"));
    out.add("inactive_users", stale.length ? "fail" : "pass",
      `${stale.length} of ${all.length} ACTIVE user(s) have not signed in for ${o.staleDays} days${firstIds(stale)}; none allowed (--okta-stale-days)${users.truncated ? "; list truncated at 100 pages" : ""}`,
      out.resource, listRead(users));
  }

  // System Log.
  const lg = await api.get("/api/v1/logs?limit=1&sortOrder=DESCENDING");
  if (!ok(lg) || !Array.isArray(lg.body)) out.skip("system_log_available", lg, "System Log");
  else out.add("system_log_available", lg.body.length ? "pass" : "fail",
    lg.body.length ? `System Log readable; latest event at ${String(isObj(lg.body[0]) ? lg.body[0].published : "?")}` : "System Log readable but returned no event");

  return out.results;
}

export const okta: Source = {
  name: "okta",
  options: {
    "okta-max-super-admins": { type: "string", help: `users allowed to hold SUPER_ADMIN (default ${DEFAULTS.maxSuperAdmins})` },
    "okta-stale-days": { type: "string", help: `days without sign-in before an ACTIVE user is inactive (default ${DEFAULTS.staleDays})` },
    "okta-min-password-length": { type: "string", help: `minimum password length a password policy must set (default ${DEFAULTS.minPasswordLength})` },
  },
  emits: OKTA_CHECKS.map((c) => `okta.${c}`),
  describe: () => "Okta org in OKTA_DOMAIN (management API v1)",
  async run(ctx: SourceContext) {
    const org = (ctx.env[OKTA_ENV.domain] ?? "(unknown)").replace(/^https:\/\//, "").replace(/\/+$/, "");
    const given = ctx.clients.okta as RestApi | null | undefined;
    const built = given !== undefined ? given : oktaFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("okta", `okta org ${org}`);
      out.skipAll(OKTA_CHECKS, typeof built === "string" ? built : "no Okta client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: OktaOptions = {
      maxSuperAdmins: intOpt(ctx.opts["okta-max-super-admins"], DEFAULTS.maxSuperAdmins),
      staleDays: intOpt(ctx.opts["okta-stale-days"], DEFAULTS.staleDays),
      minPasswordLength: intOpt(ctx.opts["okta-min-password-length"], DEFAULTS.minPasswordLength),
    };
    return redact(await oktaChecks(api, org, o, ctx.now), [ctx.env[OKTA_ENV.token], ctx.env[OKTA_ENV.access]]);
  },
};
