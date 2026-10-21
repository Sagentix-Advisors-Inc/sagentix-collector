// Microsoft Entra ID over Microsoft Graph v1.0 (GET only), as an app registration with application
// permissions and the client-credentials grant.
//
// Endpoint → application permission the collector asks for (each API page's Permissions table, v1.0,
// read 2026-10-20; the pages are listed below):
//   GET /reports/authenticationMethods/userRegistrationDetails     AuditLog.Read.All      (Entra ID P1 or P2)
//   GET /identity/conditionalAccess/policies                       Policy.Read.All        (P1)
//   GET /policies/identitySecurityDefaultsEnforcementPolicy        Policy.Read.All
//   GET /policies/authorizationPolicy                              Policy.Read.All
//   GET /roleManagement/directory/roleAssignments                  RoleManagement.Read.Directory
//   GET /roleManagement/directory/roleAssignmentSchedules          RoleManagement.Read.Directory (PIM: P2 or ID Governance)
//   GET /roleManagement/directory/roleEligibilitySchedules         RoleManagement.Read.Directory (PIM: P2 or ID Governance)
//   GET /users ($select=signInActivity)                            User.Read.All + AuditLog.Read.All (P1)
//   GET /auditLogs/directoryAudits                                 AuditLog.Read.All
//   GET /subscribedSkus                                            LicenseAssignment.Read.All
//   GET /users ($select=id,accountEnabled,userType,userPrincipalName) User.Read.All
//   GET /groups/{id}/transitiveMembers                             GroupMember.Read.All (see below)
//
// users_mfa_covered, written from these pages, all read 2026-10-20 (ms.date, then the page's updated_at):
//   https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0
//     2024-07-30, updated 2025-07-23. Application permission AuditLog.Read.All, no other listed (the
//     UserRegistrationDetails.Read.All we were asked about is on neither this page nor the permissions reference).
//     "This method doesn't work for disabled users."
//   https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0
//     2024-07-22, updated 2025-12-03. isMfaCapable: "registered a strong authentication method for multifactor
//     authentication. The method must be allowed by the authentication methods policy" (isMfaRegistered: "may not
//     necessarily be allowed"); userType member or guest; methodsRegistered values are given only by example
//     ("such as mobilePhone, email, passKeyDeviceBound"), so PHISHING_RESISTANT is a name match [Unverified].
//   https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity
//     2025-10-22, updated 2026-06-15. "A Microsoft Entra ID P1 or P2 license is required"; the sentence names
//     Usage and insights, and the resource page above points to it for the report's licence.
//   https://learn.microsoft.com/en-us/graph/api/authentication-list-methods?view=graph-rest-1.0
//     2024-09-13, updated 2026-06-19. Not used as a fallback: Microsoft does not recommend it "where you need to
//     iterate over your entire user population for auditing or security check purposes", it needs
//     UserAuthenticationMethod.Read.All, and its method objects carry phone numbers. A tenant without the report
//     gets skipped.
//   https://learn.microsoft.com/en-us/graph/throttling-limits  2025-01-14, updated 2026-09-17. Identity and access
//     reports: five requests per 10 seconds per app per tenant. The check makes no report call of its own: it
//     reuses the registration report read for mfa_registered. 429s are retried by withRetry.
//   https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0  2025-05-16, updated 2026-05-14.
//     User.Read.All; $top at most 999. The page also names "User.EnableDisableAccount.All + User.Read.All" for
//     "read and write" of accountEnabled; reading it with User.Read.All alone, as stale_accounts does, is [Unverified].
//   https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0
//     2024-07-22, updated 2024-11-21. include/exclude Users, Groups, Roles; includeUsers may be None, All or
//     GuestsOrExternalUsers. conditionalaccessguestsorexternalusers (2024-04-03, updated 2025-12-03):
//     guestOrExternalUserTypes is a string and may name b2bCollaborationMember, who have userType member.
//   https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0
//     2026-04-06, updated 2026-04-28. operator AND or OR; builtInControls; customAuthenticationFactors; termsOfUse;
//     authenticationStrength. authenticationstrengthpolicy (2024-07-22, updated 2026-02-13): requirementsSatisfied
//     none or mfa. conditionalaccessroot-list-policies (2024-10-17, updated 2025-07-23) shows the strength inline.
//   https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers?view=graph-rest-1.0
//     2024-05-20, updated 2025-07-23. The page names GroupMember.ReadBasic.All as least privileged, but the
//     permissions reference (https://learn.microsoft.com/en-us/graph/permissions-reference, 2026-09-14, updated
//     2026-09-15) has no such permission [Unverified]; GroupMember.Read.All, the page's next choice, is in both.
//     Default page size 100. Hidden-membership groups need Member.Read.Hidden; how they answer without it is
//     [Unverified], and an unreadable group never counts toward coverage.
//   https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults  2025-07-21, updated 2026-10-16. Admins
//     do MFA at every sign-in; other users "whenever necessary", as Microsoft decides.
//
// Each is the page's least-privileged application permission except for the two PIM schedules: their pages
// now name RoleAssignmentSchedule.Read.Directory and RoleEligibilitySchedule.Read.Directory as least
// privileged and list RoleManagement.Read.Directory as higher. The collector keeps RoleManagement.Read.Directory
// because roleAssignments needs it anyway, and it covers all three, so the app holds one permission, not three.
// With $select=signInActivity a page holds at most 500 users (user-list), hence $top=500.
//
// Pages: https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
//   https://learn.microsoft.com/graph/api/conditionalaccessroot-list-policies
//   https://learn.microsoft.com/graph/api/identitysecuritydefaultsenforcementpolicy-get
//   https://learn.microsoft.com/graph/api/authorizationpolicy-get
//   https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignments
//   https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignmentschedules
//   https://learn.microsoft.com/graph/api/rbacapplication-list-roleeligibilityschedules
//   https://learn.microsoft.com/graph/api/user-list
//   https://learn.microsoft.com/graph/api/directoryaudit-list
//   https://learn.microsoft.com/graph/api/subscribedsku-list
// Licences: https://learn.microsoft.com/graph/api/resources/authenticationmethods-usage-insights-overview (P1 or
// P2 for the registration report), https://learn.microsoft.com/entra/identity/conditional-access/overview (P1;
// risk-based policies need P2), https://learn.microsoft.com/entra/id-governance/licensing-fundamentals (PIM),
// all read 2026-10-20.
//
// Personal data: results carry counts and Entra object ids, never user principal names or names.

import { readFileSync } from "node:fs";
import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, entraClientAssertion, tokenRequest } from "./oauth.ts";
import {
  DAY_MS, Emitter, arr, enc, fetchRest, firstIds, getAll, intOpt, isObj, ok, realSleep, redact, str, why, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";

export const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
export const ENTRA_ENV = { tenant: "ENTRA_TENANT_ID", client: "ENTRA_CLIENT_ID", secret: "ENTRA_CLIENT_SECRET", cert: "ENTRA_CLIENT_CERT_FILE" } as const;
export const GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10";
export const DEFAULTS = { maxGlobalAdmins: 4, maxPermanentAdmins: 2, staleDays: 90 };
/** Groups and roles whose members users_mfa_covered may look up in one run. */
export const MAX_MEMBER_LOOKUPS = 100;

export const ENTRA_CHECKS = [
  "mfa_registered", "admins_phishing_resistant", "ca_mfa_all_users", "ca_blocks_legacy_auth", "security_defaults",
  "global_admins_limited", "pim_no_permanent_admins", "guest_invites_restricted", "stale_accounts",
  "audit_log_available", "risk_policies", "users_mfa_covered",
] as const;
type C = (typeof ENTRA_CHECKS)[number];

/** methodsRegistered values that resist phishing: FIDO2 security keys and passkeys, Windows Hello for Business, certificates. */
export const PHISHING_RESISTANT = /fido2|passkey|windowshello|x509|certificate/i;

const nextLink = (r: HttpResponse) => (isObj(r.body) ? str(r.body["@odata.nextLink"]) : undefined);
const values = (b: unknown) => (isObj(b) && Array.isArray(b.value) ? b.value : undefined);
const list = (api: RestApi, path: string) => getAll(api, path, values, nextLink, 200);
type Listed = Awaited<ReturnType<typeof list>>;
const listOpt = (v: unknown): string[] => (Array.isArray(v) ? v : typeof v === "string" ? [v] : [])
  .flatMap((x) => String(x).split(",")).map((x) => x.trim()).filter(Boolean);

/**
 * Builds a Graph client from ENTRA_* variables, or explains what is missing. `target` names another resource API
 * reached with the same client-credentials grant (the Defender for Endpoint API: defender_endpoint.ts).
 */
export function entraFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch,
  target: { base: string; scope: string } = { base: GRAPH_BASE, scope: "https://graph.microsoft.com/.default" }): RestApi | string {
  const tenant = env[ENTRA_ENV.tenant], client = env[ENTRA_ENV.client], secret = env[ENTRA_ENV.secret], certFile = env[ENTRA_ENV.cert];
  if (!tenant || !client || (!secret && !certFile)) return `${ENTRA_ENV.tenant}, ${ENTRA_ENV.client} and ${ENTRA_ENV.secret} or ${ENTRA_ENV.cert} are not all set`;
  const url = `https://login.microsoftonline.com/${enc(tenant)}/oauth2/v2.0/token`;
  const token = cachedToken(() => {
    const form: Record<string, string> = { grant_type: "client_credentials", client_id: client, scope: target.scope };
    if (certFile) {
      form.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
      form.client_assertion = entraClientAssertion(readFileSync(certFile, "utf8"), tenant, client, Math.floor(Date.now() / 1000));
    } else form.client_secret = secret!;
    return tokenRequest(url, form, fetchFn);
  });
  return fetchRest({ base: target.base, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

export interface EntraOptions {
  maxGlobalAdmins: number; maxPermanentAdmins: number; staleDays: number;
  /** --entra-mfa-exempt: object ids or user principal names (any case) that users_mfa_covered does not judge. */
  mfaExempt?: string[];
}

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

// ── users_mfa_covered ────────────────────────────────────────────────────────────────────────────────

/**
 * The policy makes MFA mandatory: mfa, or an authentication strength that grants the MFA claim, with no other
 * control that would do instead under OR (with mfa OR a device control, the device alone lets the user in).
 */
export const mfaMandatory = (p: Obj) => {
  const g = grant(p), builtIn = arr(g.builtInControls).map(String);
  const strength = isObj(g.authenticationStrength) ? g.authenticationStrength : undefined;
  // requirementsSatisfied is none or mfa; a strength returned without it is taken as MFA [Unverified].
  const viaStrength = strength !== undefined && strength.requirementsSatisfied !== "none";
  if (!builtIn.includes("mfa") && !viaStrength) return false;
  const others = builtIn.filter((c) => c !== "mfa").length + arr(g.customAuthenticationFactors).length + arr(g.termsOfUse).length;
  return g.operator === "AND" || others === 0;
};
/** guestOrExternalUserTypes is documented as a comma-separated string; a list is accepted too. */
const guestTypes = (v: unknown) => (isObj(v) ? [...arr(v.guestOrExternalUserTypes), ...(str(v.guestOrExternalUserTypes) ?? "").split(",")] : [])
  .map((t) => String(t).trim()).filter(Boolean);
const ids = (v: unknown) => arr(v).map(String);
const KEYWORDS = new Set(["All", "None", "GuestsOrExternalUsers"]);

interface Member { id: string; upn?: string; enabled: boolean; guest: boolean }
type Lookup = Set<string> | "unreadable";

/** Resolves groups and directory roles to user ids, each once, within MAX_MEMBER_LOOKUPS calls. */
class Directory {
  private cache = new Map<string, Lookup | "notGroup">();
  private calls = 0;
  failure?: string;
  private readonly api: RestApi;
  private readonly userIds: Set<string>;
  constructor(api: RestApi, userIds: Set<string>) { this.api = api; this.userIds = userIds; }
  private spend() {
    if (this.calls >= MAX_MEMBER_LOOKUPS) { this.failure ??= `more than ${MAX_MEMBER_LOOKUPS} group and role lookups were needed`; return false; }
    this.calls++;
    return true;
  }
  /** Transitive user members of a group; "notGroup" on 404 (a deleted group, or a principal that is not a group). */
  async group(id: string): Promise<Lookup | "notGroup"> {
    const hit = this.cache.get(`g:${id}`);
    if (hit) return hit;
    let v: Lookup | "notGroup";
    if (!this.spend()) v = "unreadable";
    else {
      const r = await list(this.api, `/groups/${enc(id)}/transitiveMembers`);
      if ("error" in r) {
        if (r.error.status === 404) v = "notGroup";
        else { v = "unreadable"; this.failure ??= `group members not readable: ${why(r.error)} (GroupMember.Read.All)`; }
      } else if (r.truncated) { v = "unreadable"; this.failure ??= "a group's member list was truncated at 200 pages"; }
      else v = new Set(r.items.filter(isObj)
        .filter((m) => m["@odata.type"] === undefined || m["@odata.type"] === "#microsoft.graph.user").map((m) => String(m.id)));
    }
    this.cache.set(`g:${id}`, v);
    return v;
  }
  async groups(gs: string[]): Promise<Lookup> {
    const out = new Set<string>();
    for (const g of gs) {
      const m = await this.group(g);
      if (m === "unreadable") return m;
      if (m !== "notGroup") for (const u of m) out.add(u);
    }
    return out;
  }
  /** Users holding a directory role (template id) by active assignment, directly or through a role-assignable group. */
  async role(id: string): Promise<Lookup> {
    const hit = this.cache.get(`r:${id}`);
    if (hit) return hit as Lookup;
    let v: Lookup;
    if (!this.spend()) v = "unreadable";
    else {
      const r = await list(this.api, `/roleManagement/directory/roleAssignments?$filter=${enc(`roleDefinitionId eq '${id}'`)}`);
      if ("error" in r) { v = "unreadable"; this.failure ??= `role assignments not readable: ${why(r.error)}`; }
      else {
        const holders = new Set<string>();
        v = holders;
        for (const pid of new Set(r.items.filter(isObj).map((a) => String(a.principalId ?? "")).filter(Boolean))) {
          if (this.userIds.has(pid)) { holders.add(pid); continue; }
          const m = await this.group(pid);   // a service principal answers 404 and holds no user
          if (m === "unreadable") { v = m; break; }
          if (m !== "notGroup") for (const u of m) holders.add(u);
        }
      }
    }
    this.cache.set(`r:${id}`, v);
    return v;
  }
  async roles(rs: string[]): Promise<Lookup> {
    const out = new Set<string>();
    for (const r of rs) {
      const m = await this.role(r);
      if (m === "unreadable") return m;
      for (const u of m) out.add(u);
    }
    return out;
  }
}

/** Who one policy covers, or why it is not credited. A failed include lookup only narrows the scope; a failed exclude lookup drops the policy. */
async function policyScope(p: Obj, dir: Directory): Promise<{ covers: (id: string) => boolean } | { dropped: string }> {
  const u = usersOf(p);
  if (guestTypes(u.excludeGuestsOrExternalUsers).includes("b2bCollaborationMember"))
    return { dropped: "excludes B2B collaboration members, member accounts this check cannot tell apart" };
  const exc = new Set(ids(u.excludeUsers));
  for (const part of [await dir.groups(ids(u.excludeGroups)), await dir.roles(ids(u.excludeRoles))]) {
    if (part === "unreadable") return { dropped: "has exclusions that could not be resolved" };
    for (const x of part) exc.add(x);
  }
  const all = ids(u.includeUsers).includes("All");
  const inc = new Set(ids(u.includeUsers).filter((x) => !KEYWORDS.has(x)));
  if (!all) for (const part of [await dir.groups(ids(u.includeGroups)), await dir.roles(ids(u.includeRoles))]) {
    if (part !== "unreadable") for (const x of part) inc.add(x);
  }
  return { covers: (id) => (all || inc.has(id)) && !exc.has(id) };
}

/**
 * Every enabled member account has a strong method registered and allowed by policy (isMfaCapable) and is in scope of
 * an MFA requirement: security defaults, or an enabled, unconditional, all-apps Conditional Access policy whose
 * include and exclude lists are resolved to users. Guests and disabled accounts are counted, not judged; accounts named
 * by --entra-mfa-exempt (break-glass) are listed by object id, not judged.
 */
async function usersMfaCovered(api: RestApi, out: Emitter<C>, regs: Listed, ca: Ca | undefined, sdOn: boolean | undefined, exempt: string[]) {
  const C_ = "users_mfa_covered" as const;
  if ("error" in regs) {
    out.add(C_, "skipped", `authentication methods registration report not readable: ${why(regs.error)}; the report needs AuditLog.Read.All and Entra ID P1 or P2`);
    return;
  }
  const report = new Map(regs.items.filter(isObj).map((r) => [String(r.id ?? "?"), r] as const));
  const guestType = (v: unknown) => String(v ?? "").toLowerCase() === "guest";

  // Who is judged: /users when readable, else the report itself (which leaves disabled users out).
  const us = await list(api, "/users?$select=id,accountEnabled,userType,userPrincipalName&$top=999");
  const people: Member[] = "error" in us
    ? [...report.values()].map((r) => ({ id: String(r.id ?? "?"), upn: str(r.userPrincipalName), enabled: true, guest: guestType(r.userType) }))
    : us.items.filter(isObj).map((u) => ({ id: String(u.id ?? "?"), upn: str(u.userPrincipalName), enabled: u.accountEnabled !== false, guest: guestType(u.userType) }));
  const truncated = regs.truncated || (!("error" in us) && us.truncated);

  const wanted = new Set(exempt.map((e) => e.toLowerCase()));
  const matched = new Set<string>();
  const isExempt = (m: Member) => {
    const hit = [m.id, m.upn, str(report.get(m.id)?.userPrincipalName)].filter((k): k is string => !!k).map((k) => k.toLowerCase()).filter((k) => wanted.has(k));
    for (const k of hit) matched.add(k);
    return hit.length > 0;
  };
  const live = people.filter((m) => !m.guest && m.enabled);
  const exempted = live.filter(isExempt);
  const judged = live.filter((m) => !exempted.includes(m));
  const capable = (id: string) => report.get(id)?.isMfaCapable === true;
  const resistant = (id: string) => arr(report.get(id)?.methodsRegistered).some((x) => PHISHING_RESISTANT.test(String(x)));

  const notes = [`not judged: ${people.filter((m) => m.guest).length} guest(s), ${people.filter((m) => !m.guest && !m.enabled).length} disabled`];
  if (exempted.length) notes.push(`${exempted.length} exempt by --entra-mfa-exempt${firstIds(exempted.map((m) => m.id))}, ${exempted.filter((m) => capable(m.id)).length} of them with a strong method registered`);
  if (wanted.size > matched.size) notes.push(`${wanted.size - matched.size} --entra-mfa-exempt value(s) matched no enabled member account`);
  if ("error" in us) notes.push(`accounts taken from the registration report because /users is not readable: ${why(us.error)}`);
  if (!judged.length) { out.add(C_, "skipped", `no enabled member account to judge; ${notes.join("; ")}`); return; }

  // Coverage: security defaults cover everyone; otherwise each credited Conditional Access policy covers its resolved scope.
  const dir = new Directory(api, new Set([...people.map((m) => m.id), ...report.keys()]));
  let covers: (id: string) => boolean;
  let how: string;
  if (sdOn === true) {
    covers = () => true;
    how = "security defaults are on (admins at every sign-in, other users when Microsoft judges it necessary)";
  } else if (ca) {
    const scopes: ((id: string) => boolean)[] = [], dropped: string[] = [];
    for (const p of ca.policies.filter((p) => enabled(p) && allApps(p) && unconditional(p) && mfaMandatory(p))) {
      const s = await policyScope(p, dir);
      if ("dropped" in s) dropped.push(`${name(p)} ${s.dropped}`);
      else scopes.push(s.covers);
    }
    covers = (id) => scopes.some((f) => f(id));
    how = `${scopes.length} enabled Conditional Access polic(ies) for all apps, without risk, location, platform or client-app conditions, make MFA mandatory`;
    if (dropped.length) notes.push(`not credited: ${dropped.slice(0, 3).join("; ")}`);
  } else {
    out.add(C_, "skipped", `${judged.length} enabled member account(s), but security defaults are ${sdOn === false ? "off" : "not readable"} and Conditional Access is not readable, so MFA coverage cannot be seen; ${notes.join("; ")}`);
    return;
  }

  const weak = judged.filter((m) => !capable(m.id)).map((m) => m.id);
  const absent = judged.filter((m) => !report.has(m.id)).length;
  const uncovered = judged.filter((m) => !covers(m.id)).map((m) => m.id);
  const pr = judged.filter((m) => capable(m.id) && resistant(m.id)).length;
  const summary = `${judged.length} enabled member account(s) judged; ${judged.length - weak.length} have a strong method registered and allowed by policy (isMfaCapable), ${pr} of them a phishing-resistant one; ${judged.length - uncovered.length} are in scope of MFA: ${how}`;
  const tail = notes.join("; ");
  if (!weak.length && !uncovered.length) {
    if (truncated) out.add(C_, "skipped", `${summary}; but a list was truncated at 200 pages, so not every account was seen; ${tail}`);
    else out.add(C_, "pass", `${summary}; ${tail}`);
  } else if (!weak.length && dir.failure) {
    out.add(C_, "skipped", `${summary}; ${uncovered.length} not shown covered${firstIds(uncovered)}, but ${dir.failure}; ${tail}`);
  } else {
    out.add(C_, "fail", `${summary}; ${weak.length} without a strong method${absent ? ` (${absent} missing from the registration report)` : ""}${firstIds(weak)}; ${uncovered.length} not covered${firstIds(uncovered)}; both required of every account${dir.failure ? `; ${dir.failure}` : ""}; ${tail}`);
  }
}

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

  // Per account: a strong method registered, and in scope of an MFA requirement.
  await usersMfaCovered(api, out, regs, ca, typeof sdOn === "boolean" ? sdOn : undefined, o.mfaExempt ?? []);

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
    "entra-mfa-exempt": { type: "string", multiple: true, help: "object id or user principal name of an account users_mfa_covered does not judge, such as a break-glass account (repeatable or comma-separated); results name it by object id only" },
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
      mfaExempt: listOpt(ctx.opts["entra-mfa-exempt"]),
    };
    return redact(await entraChecks(api, tenant, o, ctx.now), [ctx.env[ENTRA_ENV.secret]]);
  },
};
