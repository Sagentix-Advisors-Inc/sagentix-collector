// Microsoft Entra ID over Microsoft Graph v1.0 (GET only), as an app registration with application
// permissions and the client-credentials grant.
//
// Endpoint → least-privileged application permission (each API page's Permissions table on
// learn.microsoft.com/graph/api):
//   GET /reports/authenticationMethods/userRegistrationDetails     AuditLog.Read.All      (Entra ID P1 or P2)
//   GET /identity/conditionalAccess/policies                       Policy.Read.All        (P1)
//   GET /policies/identitySecurityDefaultsEnforcementPolicy        Policy.Read.All
//   GET /policies/authorizationPolicy                              Policy.Read.All
//   GET /roleManagement/directory/roleAssignments                  RoleManagement.Read.Directory
//   GET /roleManagement/directory/roleAssignmentSchedules          RoleManagement.Read.Directory (PIM, P2)
//   GET /roleManagement/directory/roleEligibilitySchedules         RoleManagement.Read.Directory (PIM, P2)
//   GET /users ($select=signInActivity)                            User.Read.All + AuditLog.Read.All (P1)
//   GET /auditLogs/directoryAudits                                 AuditLog.Read.All
//   GET /subscribedSkus                                            LicenseAssignment.Read.All
//
// Personal data: results carry counts and Entra object ids, never user principal names or names.

import { readFileSync } from "node:fs";
import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, entraClientAssertion, tokenRequest } from "./oauth.ts";
import {
  DAY_MS, Emitter, arr, enc, fetchRest, firstIds, getAll, intOpt, isObj, ok, realSleep, redact, str, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";

export const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
export const ENTRA_ENV = { tenant: "ENTRA_TENANT_ID", client: "ENTRA_CLIENT_ID", secret: "ENTRA_CLIENT_SECRET", cert: "ENTRA_CLIENT_CERT_FILE" } as const;
export const GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10";
export const DEFAULTS = { maxGlobalAdmins: 4, maxPermanentAdmins: 2, staleDays: 90 };

export const ENTRA_CHECKS = [
  "mfa_registered", "admins_phishing_resistant", "ca_mfa_all_users", "ca_blocks_legacy_auth", "security_defaults",
  "global_admins_limited", "pim_no_permanent_admins", "guest_invites_restricted", "stale_accounts",
  "audit_log_available", "risk_policies",
] as const;
type C = (typeof ENTRA_CHECKS)[number];

/** methodsRegistered values that resist phishing: FIDO2 security keys and passkeys, Windows Hello for Business, certificates. */
export const PHISHING_RESISTANT = /fido2|passkey|windowshello|x509|certificate/i;

const nextLink = (r: HttpResponse) => (isObj(r.body) ? str(r.body["@odata.nextLink"]) : undefined);
const values = (b: unknown) => (isObj(b) && Array.isArray(b.value) ? b.value : undefined);
const list = (api: RestApi, path: string) => getAll(api, path, values, nextLink, 200);

/** Builds a Graph client from ENTRA_* variables, or explains what is missing. */
export function entraFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const tenant = env[ENTRA_ENV.tenant], client = env[ENTRA_ENV.client], secret = env[ENTRA_ENV.secret], certFile = env[ENTRA_ENV.cert];
  if (!tenant || !client || (!secret && !certFile)) return `${ENTRA_ENV.tenant}, ${ENTRA_ENV.client} and ${ENTRA_ENV.secret} or ${ENTRA_ENV.cert} are not all set`;
  const url = `https://login.microsoftonline.com/${enc(tenant)}/oauth2/v2.0/token`;
  const token = cachedToken(() => {
    const form: Record<string, string> = { grant_type: "client_credentials", client_id: client, scope: "https://graph.microsoft.com/.default" };
    if (certFile) {
      form.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
      form.client_assertion = entraClientAssertion(readFileSync(certFile, "utf8"), tenant, client, Math.floor(Date.now() / 1000));
    } else form.client_secret = secret!;
    return tokenRequest(url, form, fetchFn);
  });
  return fetchRest({ base: GRAPH_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

export interface EntraOptions { maxGlobalAdmins: number; maxPermanentAdmins: number; staleDays: number }

interface Ca { readable: true; policies: Obj[]; mfaAll: Obj[] }
const enabled = (p: Obj) => p.state === "enabled";
const cond = (p: Obj) => (isObj(p.conditions) ? p.conditions : {});
const usersOf = (p: Obj) => (isObj(cond(p).users) ? (cond(p).users as Obj) : {});
const appsOf = (p: Obj) => (isObj(cond(p).applications) ? (cond(p).applications as Obj) : {});
const grant = (p: Obj) => (isObj(p.grantControls) ? p.grantControls : {});
const allUsers = (p: Obj) => arr(usersOf(p).includeUsers).includes("All");
const allApps = (p: Obj) => arr(appsOf(p).includeApplications).includes("All");
/** No risk, location, platform or client-app condition narrows when the policy applies. */
const unconditional = (p: Obj) => {
  const c = cond(p), apps = arr(c.clientAppTypes);
  return !arr(c.signInRiskLevels).length && !arr(c.userRiskLevels).length && !isObj(c.locations) && !isObj(c.platforms)
    && (!apps.length || apps.includes("all"));
};
const exclusions = (p: Obj) => ["excludeUsers", "excludeGroups", "excludeRoles"].reduce((n, k) => n + arr(usersOf(p)[k]).length, 0);
const name = (p: Obj) => JSON.stringify(String(p.displayName ?? p.id ?? "?"));

export async function entraChecks(api: RestApi, tenant: string, o: EntraOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("entra", `entra tenant ${tenant}`);

  // Licences decide whether a missing P2 feature is "skipped" rather than "fail".
  const skus = await list(api, "/subscribedSkus");
  const plans = "error" in skus ? undefined : new Set(skus.items.filter(isObj).filter((s) => s.capabilityStatus === undefined || s.capabilityStatus === "Enabled")
    .flatMap((s) => arr(s.servicePlans).filter(isObj).map((p) => String(p.servicePlanName))));
  const p2 = plans ? plans.has("AAD_PREMIUM_P2") : undefined;

  // Authentication methods registration.
  const regs = await list(api, "/reports/authenticationMethods/userRegistrationDetails");
  if ("error" in regs) {
    out.skip("mfa_registered", regs.error, "authentication methods registration report");
    out.skip("admins_phishing_resistant", regs.error, "authentication methods registration report");
  } else {
    const users = regs.items.filter(isObj);
    const without = users.filter((u) => u.isMfaRegistered !== true).map((u) => String(u.id ?? "?"));
    if (!users.length) out.add("mfa_registered", "skipped", "the registration report lists no user");
    else out.add("mfa_registered", without.length ? "fail" : "pass",
      `${users.length - without.length} of ${users.length} enabled users registered for MFA; ${without.length} not${firstIds(without)}; all required`);
    const admins = users.filter((u) => u.isAdmin === true);
    const weak = admins.filter((u) => !arr(u.methodsRegistered).some((m) => PHISHING_RESISTANT.test(String(m)))).map((u) => String(u.id ?? "?"));
    if (!admins.length) out.add("admins_phishing_resistant", "skipped", "the registration report flags no user as admin (isAdmin)");
    else out.add("admins_phishing_resistant", weak.length ? "fail" : "pass",
      `${admins.length - weak.length} of ${admins.length} admins have a phishing-resistant method registered (FIDO2 or passkey, Windows Hello for Business, certificate); ${weak.length} do not${firstIds(weak)}`);
  }

  // Conditional Access.
  const caR = await list(api, "/identity/conditionalAccess/policies");
  let ca: Ca | undefined;
  if ("error" in caR) {
    for (const c of ["ca_mfa_all_users", "ca_blocks_legacy_auth", "risk_policies"] as const) out.skip(c, caR.error, "Conditional Access policies");
  } else {
    const policies = caR.items.filter(isObj);
    const mfaAll = policies.filter((p) => enabled(p) && allUsers(p) && allApps(p) && unconditional(p)
      && (arr(grant(p).builtInControls).includes("mfa") || isObj(grant(p).authenticationStrength)));
    ca = { readable: true, policies, mfaAll };
    const reportOnly = policies.filter((p) => p.state === "enabledForReportingButNotEnforced").length;
    out.add("ca_mfa_all_users", mfaAll.length ? "pass" : "fail",
      `${policies.length} Conditional Access polic(ies), ${reportOnly} report-only; ${mfaAll.length} enabled for all users and all apps, without risk, location, platform or client-app conditions, requiring MFA or an authentication strength${mfaAll.length ? ` (${mfaAll.slice(0, 5).map((p) => `${name(p)} with ${exclusions(p)} exclusion(s)`).join(", ")})` : ""}; at least one required`);
    const legacy = policies.filter((p) => enabled(p) && allUsers(p) && arr(grant(p).builtInControls).includes("block")
      && ["exchangeActiveSync", "other"].every((t) => arr(cond(p).clientAppTypes).includes(t)));
    out.add("ca_blocks_legacy_auth", legacy.length ? "pass" : "fail",
      `${legacy.length} enabled polic(ies) block clientAppTypes exchangeActiveSync and other for all users${legacy.length ? ` (${legacy.slice(0, 5).map(name).join(", ")})` : ""}; at least one required`);
    const risk = policies.filter((p) => enabled(p) && (arr(cond(p).signInRiskLevels).length > 0 || arr(cond(p).userRiskLevels).length > 0));
    if (risk.length) out.add("risk_policies", "pass", `${risk.length} enabled polic(ies) act on sign-in or user risk (${risk.slice(0, 5).map(name).join(", ")})`);
    else if (p2 === false) out.add("risk_policies", "skipped", "no risk-based policy, and the tenant has no Entra ID P2 (AAD_PREMIUM_P2) to run one");
    else if (p2 === undefined) out.add("risk_policies", "skipped", "no risk-based policy; licences not readable, so P2 cannot be confirmed (/subscribedSkus)");
    else out.add("risk_policies", "fail", "the tenant has Entra ID P2 but no enabled Conditional Access policy acts on sign-in or user risk");
  }

  // Security defaults: on, or off because Conditional Access requires MFA for everyone.
  const sd = await api.get("/policies/identitySecurityDefaultsEnforcementPolicy");
  const sdOn = ok(sd) && isObj(sd.body) ? sd.body.isEnabled : undefined;
  if (typeof sdOn !== "boolean") out.skip("security_defaults", sd, "security defaults policy");
  else if (sdOn) out.add("security_defaults", "pass", "security defaults isEnabled is true");
  else if (!ca) out.add("security_defaults", "skipped", "security defaults are off and Conditional Access is not readable, so the replacement cannot be seen");
  else out.add("security_defaults", ca.mfaAll.length ? "pass" : "fail",
    `security defaults isEnabled is false; ${ca.mfaAll.length} enabled Conditional Access polic(ies) require MFA for all users and apps; one of the two is required`);

  // Global Administrators.
  const ga = await list(api, `/roleManagement/directory/roleAssignments?$filter=${enc(`roleDefinitionId eq '${GLOBAL_ADMIN_ROLE}'`)}`);
  if ("error" in ga) out.skip("global_admins_limited", ga.error, "Global Administrator role assignments");
  else {
    const principals = [...new Set(ga.items.filter(isObj).filter((a) => a.roleDefinitionId === undefined || a.roleDefinitionId === GLOBAL_ADMIN_ROLE).map((a) => String(a.principalId ?? "?")))];
    const over = principals.length > o.maxGlobalAdmins;
    out.add("global_admins_limited", over ? "fail" : "pass",
      `${principals.length} principal(s) hold Global Administrator as an active assignment${over ? firstIds(principals) : ""}; at most ${o.maxGlobalAdmins} allowed (--entra-max-global-admins)`);
  }

  // PIM: permanent active vs eligible Global Administrator.
  if (p2 === false) out.add("pim_no_permanent_admins", "skipped", "Privileged Identity Management needs Entra ID P2 (AAD_PREMIUM_P2); the tenant has none");
  else {
    const act = await list(api, "/roleManagement/directory/roleAssignmentSchedules");
    const elig = "error" in act ? act : await list(api, "/roleManagement/directory/roleEligibilitySchedules");
    if ("error" in act) out.skip("pim_no_permanent_admins", act.error, "role assignment schedules");
    else if ("error" in elig) out.skip("pim_no_permanent_admins", elig.error, "role eligibility schedules");
    else {
      const isGa = (s: Obj) => s.roleDefinitionId === GLOBAL_ADMIN_ROLE;
      const expiry = (s: Obj) => (isObj(s.scheduleInfo) && isObj(s.scheduleInfo.expiration) ? s.scheduleInfo.expiration.type : undefined);
      const permanent = act.items.filter(isObj).filter((s) => isGa(s) && s.assignmentType !== "Activated" && (expiry(s) === "noExpiration" || expiry(s) === undefined));
      const eligible = elig.items.filter(isObj).filter(isGa);
      const ids = permanent.map((s) => String(s.principalId ?? "?"));
      const over = permanent.length > o.maxPermanentAdmins;
      out.add("pim_no_permanent_admins", over ? "fail" : "pass",
        `${permanent.length} permanent active and ${eligible.length} eligible Global Administrator assignment(s)${over ? firstIds(ids) : ""}; at most ${o.maxPermanentAdmins} permanent (break-glass) allowed (--entra-max-permanent-admins)`);
    }
  }

  // Guests.
  const az = await api.get("/policies/authorizationPolicy");
  const azBody = ok(az) ? (isObj(az.body) && Array.isArray(az.body.value) ? az.body.value[0] : az.body) : undefined;
  const invites = isObj(azBody) ? str(azBody.allowInvitesFrom) : undefined;
  if (!invites) out.skip("guest_invites_restricted", az, "authorization policy (allowInvitesFrom)");
  else {
    const guests = await list(api, `/users?$filter=${enc("userType eq 'Guest'")}&$select=id&$top=999`);
    const count = "error" in guests ? "guest count not readable" : `${guests.items.length} guest account(s) in the directory`;
    const restricted = invites === "none" || invites === "adminsAndGuestInviters";
    out.add("guest_invites_restricted", restricted ? "pass" : "fail",
      `allowInvitesFrom is ${JSON.stringify(invites)}; "none" or "adminsAndGuestInviters" required; ${count}`);
  }

  // Stale accounts (signInActivity needs P1 and AuditLog.Read.All).
  const us = await list(api, "/users?$select=id,accountEnabled,userType,createdDateTime,signInActivity&$top=500");
  if ("error" in us) out.skip("stale_accounts", us.error, "users with signInActivity");
  else {
    const cutoff = now.getTime() - o.staleDays * DAY_MS;
    const live = us.items.filter(isObj).filter((u) => u.accountEnabled !== false);
    const stale = live.filter((u) => {
      const s = isObj(u.signInActivity) ? u.signInActivity : {};
      const times = [s.lastSignInDateTime, s.lastNonInteractiveSignInDateTime, s.lastSuccessfulSignInDateTime].map((t) => Date.parse(String(t))).filter(Number.isFinite);
      if (times.length) return Math.max(...times) < cutoff;
      const created = Date.parse(String(u.createdDateTime));
      return Number.isFinite(created) && created < cutoff;
    }).map((u) => String(u.id ?? "?"));
    out.add("stale_accounts", stale.length ? "fail" : "pass",
      `${stale.length} of ${live.length} enabled account(s) have not signed in for ${o.staleDays} days${firstIds(stale)}; none allowed (--entra-stale-days)${us.truncated ? "; list truncated at 200 pages" : ""}`);
  }

  // Directory audit log.
  const al = await api.get("/auditLogs/directoryAudits?$top=1");
  const first = ok(al) ? values(al.body) : undefined;
  if (!first) out.skip("audit_log_available", al, "directory audit log");
  else out.add("audit_log_available", first.length ? "pass" : "fail",
    first.length ? `directory audit log readable; latest entry at ${String(isObj(first[0]) ? first[0].activityDateTime : "?")}` : "directory audit log readable but empty");

  return out.results;
}

export const entra: Source = {
  name: "entra",
  options: {
    "entra-max-global-admins": { type: "string", help: `principals allowed to hold Global Administrator (default ${DEFAULTS.maxGlobalAdmins})` },
    "entra-max-permanent-admins": { type: "string", help: `permanent (non-PIM) Global Administrator assignments allowed (default ${DEFAULTS.maxPermanentAdmins})` },
    "entra-stale-days": { type: "string", help: `days without sign-in before an enabled account is stale (default ${DEFAULTS.staleDays})` },
  },
  emits: ENTRA_CHECKS.map((c) => `entra.${c}`),
  describe: () => "Entra ID tenant in ENTRA_TENANT_ID (Microsoft Graph v1.0)",
  async run(ctx: SourceContext) {
    const tenant = ctx.env[ENTRA_ENV.tenant] ?? "(unknown)";
    const given = ctx.clients.entra as RestApi | null | undefined;
    const built = given !== undefined ? given : entraFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("entra", `entra tenant ${tenant}`);
      out.skipAll(ENTRA_CHECKS, typeof built === "string" ? built : "no Graph client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: EntraOptions = {
      maxGlobalAdmins: intOpt(ctx.opts["entra-max-global-admins"], DEFAULTS.maxGlobalAdmins),
      maxPermanentAdmins: intOpt(ctx.opts["entra-max-permanent-admins"], DEFAULTS.maxPermanentAdmins),
      staleDays: intOpt(ctx.opts["entra-stale-days"], DEFAULTS.staleDays),
    };
    return redact(await entraChecks(api, tenant, o, ctx.now), [ctx.env[ENTRA_ENV.secret]]);
  },
};
