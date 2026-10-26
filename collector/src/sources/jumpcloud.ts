// JumpCloud (GET only), with the API key of an administrator who holds the Read Only role. JumpCloud
// turns API access off for every new administrator; an Administrator with Billing enables it, and the
// key carries its administrator's role ("Role-based permissions apply to ... the API key of each
// administrator"). Read Only reads users, devices, organization settings, authentication policies and
// administrators, and System Insights (Admin Portal Roles table).
//
// Pages read 2026-10-20:
//   JumpCloud API 1.0 reference, docs.jumpcloud.com/api/1.0/index.html (OpenAPI index.yaml, last modified 2026-10-19)
//   JumpCloud API 2.0 reference, docs.jumpcloud.com/api/2.0/index.html (OpenAPI index.yaml, last modified 2026-10-19)
//   jumpcloud.com/support/jumpcloud-apis                  (API access off by default, x-api-key, jca_ prefix)
//   jumpcloud.com/support/admin-portal-roles              (Read Only scope; roles apply to the API key)
//   jumpcloud.com/support/best-practices-jumpcloud-api    (paginate with skip and sort=_id; back off on 429)
//   jumpcloud.com/support/require-mfa-for-users           (per-user requirement, conditional access policies)
//   jumpcloud.com/support/enable-mfa-for-the-admin-portal (Global MFA Requirement for admins)
//   jumpcloud.com/support/get-started-password-policies   (the organization's settings are the default policy)
//
// Endpoints (header x-api-key; x-org-id when --jumpcloud-org-id is given) → API key scope (x-scopes):
//   GET /api/organizations                                 organizations.readonly  -> { totalCount, results: [{ _id }] }
//   GET /api/organizations/{id}                            organizations.readonly  -> { settings: { requireAdminMFA,
//        passwordPolicy: { enableMinLength, minLength, enableMaxLoginAttempts, maxLoginAttempts, lockoutTimeInSeconds } } }
//   GET /api/v2/organizations/{id}/administratorlinks      organizations.readonly  -> [{ administrator, organization }]
//   GET /api/systemusers?limit&skip&sort=_id&fields        users.readonly          -> { totalCount, results: [{ _id, state
//        (STAGED|ACTIVATED|SUSPENDED), suspended, enable_user_portal_multifactor ("Whether to require MFA for user portal
//        login", PUT /systemusers/{id}/mfa/enforce), totp_enabled, mfaEnrollment: { overallStatus, totpStatus,
//        webAuthnStatus, pushStatus } }] }; a status is NOT_ENROLLED, DISABLED, PENDING_ACTIVATION, ENROLLMENT_EXPIRED,
//        IN_ENROLLMENT, PRE_ENROLLMENT or ENROLLED
//   GET /api/v2/authn/policies?limit&skip                  authn.readonly          -> [{ id, name, disabled, monitorOnly, type
//        (user_portal|application|ldap|admin_portal), effect: { action (allow|deny), obligations: { mfa: { required } } } }]
//   GET /api/systems?limit&skip&sort=_id&fields            systems.readonly        -> { totalCount, results: [{ _id, serialNumber,
//        os, osFamily, version, osVersionDetail: { version, majorNumber, minorNumber, patchNumber }, fde: { active } ("Indicates
//        if the Full Disk Encryption is active in the system"), lastContact }] }
// v1 lists and v2 lists take limit (at most 100) and skip; v1 answers { totalCount, results }, v2 a bare array.
//
// Not checked, because no documented GET shows it: a user's last sign-in (systemusers has no such field; sign-in events
// come from the Directory Insights API, which is POST only), each administrator's role and MFA (GET /administrators is not
// in the reference; /providers/{id}/administrators is for MSPs only), and a screen-lock policy (policy template names and
// their settings are not in the reference).
//
// Default Access Policies (the fallback applied when no conditional access policy matches) are not read either.
// Checked again on 2026-10-26: the API 2.0 OpenAPI file (docs.jumpcloud.com/api/2.0/index.yaml, Last-Modified
// 2026-10-26 14:52 GMT) declares the path /authn/policy/fallback/{resource_type} with only its path parameter
// (resource_type: userportal, adminportal, application, ldap) and no operation: no get, no response schema. The API 1.0
// file has no fallback path. GitHub code search over the TheJumpCloud organization (jcapi-go, jcapi-python,
// jcapi-powershell, jc-cli and the rest) finds no "policy/fallback" call, and the Terraform registry lists no
// JumpCloud-published provider. Reading an undocumented endpoint would mean guessing its reply, so it stays out.
//
// Personal data: users are named by their JumpCloud id and devices by id and serial. The user and system lists ask for
// the fields above only (fields=), so usernames, email addresses, hostnames and display names never reach the collector.

import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter, enc, fetchRest, firstIds, intOpt, isObj, ok, realSleep, redact, str, why, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, label, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const JUMPCLOUD_ENV = { key: "JUMPCLOUD_API_KEY", org: "JUMPCLOUD_ORG_ID" } as const;
export const JUMPCLOUD_CHECKS = [
  "users_mfa_enrolled", "users_mfa_required", "policies_require_mfa", "admin_mfa_required", "admins_limited",
  "password_policy", "account_lockout", "device_encrypted", "device_os_minimum", "device_last_contact",
] as const;
type C = (typeof JUMPCLOUD_CHECKS)[number];
const DEVICE_CHECKS = ["device_encrypted", "device_os_minimum", "device_last_contact"] as const;

/** The API servers in the OpenAPI documents' `servers` list. */
export const REGIONS: Record<string, string> = {
  us: "https://console.jumpcloud.com/api",
  eu: "https://console.eu.jumpcloud.com/api",
  in: "https://console.in.jumpcloud.com/api",
};
export const DEFAULTS = { minPasswordLength: 12, maxAdmins: 5, contactDays: 14, maxDevices: 5000, maxUsers: 20000 } as const;
/** As okta.ts: Okta's default of 10 attempts is the most this check allows. */
export const MAX_LOCKOUT_ATTEMPTS = 10;
export const PAGE = 100;
export const USER_FIELDS = "_id state suspended enable_user_portal_multifactor totp_enabled mfaEnrollment";
export const SYSTEM_FIELDS = "_id serialNumber os osFamily version osVersionDetail fde lastContact";
const fields = (f: string) => enc(f);
export const usersPath = (skip: number) => `/systemusers?limit=${PAGE}&skip=${skip}&sort=_id&fields=${fields(USER_FIELDS)}`;
export const systemsPath = (skip: number) => `/systems?limit=${PAGE}&skip=${skip}&sort=_id&fields=${fields(SYSTEM_FIELDS)}`;
export const policiesPath = (skip: number) => `/v2/authn/policies?limit=${PAGE}&skip=${skip}`;
export const adminLinksPath = (org: string, skip: number) => `/v2/organizations/${enc(org)}/administratorlinks?limit=${PAGE}&skip=${skip}`;

const ORG_ID = /^[0-9a-f]{24}$/i;

/** A JumpCloud client from JUMPCLOUD_API_KEY, or what is missing. */
export function jumpcloudFromEnv(env: NodeJS.ProcessEnv, o: { region?: string; orgId?: string } = {}, fetchFn: typeof fetch = fetch): RestApi | string {
  const key = env[JUMPCLOUD_ENV.key];
  if (!key) return `${JUMPCLOUD_ENV.key} is not set`;
  const region = (o.region ?? "us").toLowerCase();
  const base = REGIONS[region];
  if (!base) return `--jumpcloud-region must be one of ${Object.keys(REGIONS).join(", ")}`;
  const headers: Record<string, string> = { "x-api-key": key };
  if (o.orgId) headers["x-org-id"] = o.orgId;
  return fetchRest({ base, fetchFn, headers: async () => headers });
}

/** Every item of a skip/limit list: v1 pages are { totalCount, results }, v2 pages a bare array. */
async function list(api: RestApi, path: (skip: number) => string, max: number): Promise<{ items: Obj[]; total: number | undefined; truncated: boolean } | { error: HttpResponse }> {
  const items: Obj[] = [];
  let total: number | undefined;
  for (let skip = 0; items.length < max; skip += PAGE) {
    const r = await api.get(path(skip));
    const b = r.body;
    const page = !ok(r) ? undefined : Array.isArray(b) ? b : isObj(b) && Array.isArray(b.results) ? b.results : undefined;
    if (!page) return { error: r };
    if (isObj(b) && Number.isFinite(Number(b.totalCount))) total = Number(b.totalCount);
    items.push(...page.filter(isObj));
    if (page.length < PAGE || (total !== undefined && skip + PAGE >= total)) break;
  }
  return { items: items.slice(0, max), total, truncated: items.length > max || (total !== undefined && total > max) };
}

const sub = (o: Obj, k: string): Obj => (isObj(o[k]) ? (o[k] as Obj) : {});
const ENROLLED = "ENROLLED";
const FACTORS = [["totpStatus", "TOTP"], ["pushStatus", "Push"], ["webAuthnStatus", "WebAuthn"]] as const;
const isActive = (u: Obj) => (u.state !== undefined ? u.state === "ACTIVATED" : true) && u.suspended !== true;
const enforced = (p: Obj) => p.disabled !== true && p.monitorOnly !== true;
const allows = (p: Obj) => str(sub(p, "effect").action) === "allow";
const needsMfa = (p: Obj) => sub(sub(sub(p, "effect"), "obligations"), "mfa").required === true;
const policyName = (p: Obj) => `${label(p.name, 60)} (${String(p.type ?? "?")})`;

/** "macos", "windows", "linux", or the reported family in lower case: JumpCloud's os and osFamily values are not enumerated in the reference. */
export function platformOf(s: Obj): string {
  const t = `${String(s.osFamily ?? "")} ${String(s.os ?? "")}`;
  if (/darwin|mac/i.test(t)) return "macos";
  if (/windows/i.test(t)) return "windows";
  if (/linux|ubuntu|debian|red ?hat|rhel|centos|fedora|rocky|alma|amazon|suse/i.test(t)) return "linux";
  return String(s.osFamily ?? s.os ?? "unknown").toLowerCase();
}

/** The OS version: osVersionDetail.version, else its major/minor/patch numbers, else the version field. */
export function osVersionOf(s: Obj): { v: number[]; from: string } | undefined {
  const d = sub(s, "osVersionDetail");
  const a = versionIn(d.version);
  if (a) return { v: a, from: "osVersionDetail.version" };
  if (typeof d.majorNumber === "number") return { v: [d.majorNumber, Number(d.minorNumber ?? 0) || 0, Number(d.patchNumber ?? 0) || 0], from: "osVersionDetail numbers" };
  const b = versionIn(s.version);
  return b ? { v: b, from: "version" } : undefined;
}

export interface JumpcloudOptions { orgId?: string; minPasswordLength: number; maxAdmins: number; contactDays: number; maxDevices: number; minOs: Map<string, number[]> }

export async function jumpcloudChecks(api: RestApi, o: JumpcloudOptions, now: Date): Promise<Result[]> {
  // The organization: the one given, else the only one the key can see.
  let org = o.orgId, orgErr: string | undefined;
  if (!org) {
    const r = await api.get("/organizations?limit=10");
    const rs = ok(r) && isObj(r.body) && Array.isArray(r.body.results) ? r.body.results.filter(isObj) : undefined;
    if (!rs) orgErr = `the organization not readable: ${why(r)}`;
    else if (rs.length === 1 && str(rs[0]._id)) org = str(rs[0]._id);
    else orgErr = `the API key sees ${rs.length} organizations; name one with --jumpcloud-org-id`;
  }
  const out = new Emitter<C>("jumpcloud", `jumpcloud org ${org ?? "(unknown)"}`);

  // Organization settings: admin MFA, password policy, lockout.
  if (!org) out.skipAll(["admin_mfa_required", "password_policy", "account_lockout", "admins_limited"], orgErr!);
  else {
    const r = await api.get(`/organizations/${enc(org)}`);
    if (!ok(r) || !isObj(r.body)) for (const c of ["admin_mfa_required", "password_policy", "account_lockout"] as const) out.skip(c, r, "organization settings");
    else {
      const st = sub(r.body, "settings"), pw = sub(st, "passwordPolicy");
      if (typeof st.requireAdminMFA !== "boolean") out.add("admin_mfa_required", "skipped", "settings.requireAdminMFA not reported");
      else out.add("admin_mfa_required", st.requireAdminMFA ? "pass" : "fail", `settings.requireAdminMFA is ${st.requireAdminMFA}; true required (MFA on every Admin Portal login)`);

      const len = Number(pw.minLength);
      if (pw.enableMinLength === false) out.add("password_policy", "fail", `passwordPolicy.enableMinLength is false (no minimum length); ${o.minPasswordLength} or more required (--jumpcloud-min-password-length)`);
      else if (!Number.isFinite(len) || pw.minLength === undefined) out.add("password_policy", "skipped", "passwordPolicy.minLength not reported");
      else out.add("password_policy", len >= o.minPasswordLength ? "pass" : "fail",
        `passwordPolicy.minLength ${len} (enableMinLength ${String(pw.enableMinLength ?? "?")}); ${o.minPasswordLength} or more required (--jumpcloud-min-password-length); only the organization's default policy is read`);

      const att = Number(pw.maxLoginAttempts);
      const lockout = `lockoutTimeInSeconds ${String(pw.lockoutTimeInSeconds ?? "?")}`;
      if (pw.enableMaxLoginAttempts === false) out.add("account_lockout", "fail", `passwordPolicy.enableMaxLoginAttempts is false (no lockout); 1 to ${MAX_LOCKOUT_ATTEMPTS} attempts required`);
      else if (!Number.isFinite(att) || pw.maxLoginAttempts === undefined) out.add("account_lockout", "skipped", "passwordPolicy.maxLoginAttempts not reported");
      else out.add("account_lockout", att >= 1 && att <= MAX_LOCKOUT_ATTEMPTS ? "pass" : "fail",
        `passwordPolicy.maxLoginAttempts ${att} (enableMaxLoginAttempts ${String(pw.enableMaxLoginAttempts ?? "?")}), ${lockout}; 1 to ${MAX_LOCKOUT_ATTEMPTS} required`);
    }

    const links = await list(api, (skip) => adminLinksPath(org!, skip), 10_000);
    if ("error" in links) out.skip("admins_limited", links.error, "administrator links");
    else {
      const ids = [...new Set(links.items.map((l) => str(l.administrator)).filter((x): x is string => !!x))];
      const over = ids.length > o.maxAdmins;
      out.add("admins_limited", over ? "fail" : "pass",
        `${ids.length} administrator account(s) linked to the organization, every role counted (the collector's Read Only one too)${over ? firstIds(ids) : ""}; at most ${o.maxAdmins} allowed (--jumpcloud-max-admins)`);
    }
  }

  // Conditional access (authentication) policies.
  const pol = await list(api, policiesPath, 5_000);
  const policies = "error" in pol ? undefined : pol.items;
  if (!policies) out.skip("policies_require_mfa", (pol as { error: HttpResponse }).error, "authentication policies");
  else {
    const allow = policies.filter(enforced).filter(allows);
    const weak = allow.filter((p) => !needsMfa(p));
    if (!allow.length) out.add("policies_require_mfa", "skipped", `${policies.length} authentication polic(ies), none enabled with an allow action; MFA set on each user is judged by jumpcloud.users_mfa_required`);
    else out.add("policies_require_mfa", weak.length ? "fail" : "pass",
      `${allow.length} enabled allow polic(ies), ${weak.length} without obligations.mfa.required${weak.length ? `: ${weak.slice(0, 5).map(policyName).join(", ")}` : ""}; MFA required on every one`);
  }

  // Users.
  const us = await list(api, usersPath, DEFAULTS.maxUsers);
  if ("error" in us) { out.skip("users_mfa_enrolled", us.error, "users"); out.skip("users_mfa_required", us.error, "users"); }
  else {
    const active = us.items.filter(isActive);
    const notJudged = us.items.length - active.length;
    const skippedNote = `${notJudged} staged or suspended user(s) not judged${us.truncated ? `; only the first ${DEFAULTS.maxUsers} users read` : ""}`;
    const fromU = out.results.length;
    if (!active.length) out.skipAll(["users_mfa_enrolled", "users_mfa_required"], `no active user; ${skippedNote}`);
    else {
      // Enrolment: overallStatus, else a TOTP, Push or WebAuthn status, else totp_enabled.
      const counts = Object.fromEntries(FACTORS.map(([, n]) => [n, 0])) as Record<string, number>;
      const missing: string[] = [], unknown: string[] = [];
      for (const u of active) {
        const e = sub(u, "mfaEnrollment");
        for (const [k, n] of FACTORS) if (e[k] === ENROLLED) counts[n]++;
        const shown = e.overallStatus !== undefined || FACTORS.some(([k]) => e[k] !== undefined) || typeof u.totp_enabled === "boolean";
        const enrolled = e.overallStatus === ENROLLED || FACTORS.some(([k]) => e[k] === ENROLLED) || u.totp_enabled === true;
        if (enrolled) continue;
        (shown ? missing : unknown).push(String(u._id ?? "?"));
      }
      const by = FACTORS.map(([, n]) => `${n} ${counts[n]}`).join(", ");
      const enrolledDetail = `${active.length - missing.length - unknown.length} of ${active.length} active user(s) enrolled in MFA (${by}); ${missing.length} not enrolled${firstIds(missing)}${unknown.length ? `, ${unknown.length} not reported${firstIds(unknown)}` : ""}; every active user required; ${skippedNote}`;
      if (missing.length) out.add("users_mfa_enrolled", "fail", enrolledDetail);
      else if (unknown.length) out.add("users_mfa_enrolled", "skipped", `mfaEnrollment and totp_enabled not reported for some users: ${enrolledDetail}`);
      else out.add("users_mfa_enrolled", "pass", enrolledDetail);

      // Requirement: each user's own setting, or else a conditional access policy (which users it covers is not resolved).
      const unflagged = active.filter((u) => u.enable_user_portal_multifactor !== true).map((u) => String(u._id ?? "?"));
      const portal = policies?.filter(enforced).filter(allows).filter(needsMfa).filter((p) => p.type === "user_portal") ?? [];
      const head = `${active.length - unflagged.length} of ${active.length} active user(s) have enable_user_portal_multifactor set`;
      if (!unflagged.length) out.add("users_mfa_required", "pass", `${head}; ${skippedNote}`);
      else if (!active.some((u) => typeof u.enable_user_portal_multifactor === "boolean")) out.add("users_mfa_required", "skipped", `enable_user_portal_multifactor not reported for any of ${active.length} active user(s)`);
      else if (!policies) out.add("users_mfa_required", "skipped", `${head}; ${unflagged.length} without it${firstIds(unflagged)}, and authentication policies are not readable to show whether one requires MFA for them: ${why((pol as { error: HttpResponse }).error)}`);
      else if (portal.length) out.add("users_mfa_required", "skipped", `${head}; ${unflagged.length} without it${firstIds(unflagged)}, and ${portal.length} enabled User Portal polic(ies) require MFA (${portal.slice(0, 3).map(policyName).join(", ")}), whose user groups this check does not resolve`);
      else out.add("users_mfa_required", "fail", `${head}; ${unflagged.length} without it${firstIds(unflagged)}, and no enabled User Portal authentication policy requires MFA`);
    }
    stampRead(out.results, fromU, listRead(us));
  }

  // Devices.
  const sy = await list(api, systemsPath, o.maxDevices);
  if ("error" in sy) { for (const c of DEVICE_CHECKS) out.skip(c, sy.error, "systems"); return out.results; }
  if (!sy.items.length) { out.skipAll(DEVICE_CHECKS, "JumpCloud lists no device; nothing to judge"); return out.results; }
  const cap = sy.truncated ? `; only the first ${o.maxDevices} devices read (--jumpcloud-max-devices)` : "";
  const from = out.results.length;
  if (!o.minOs.size) out.add("device_os_minimum", "skipped", `no minimum OS version given (--jumpcloud-min-os, e.g. macos=15.0 or windows=10.0.22631); ${sy.items.length} device(s) not judged`);
  for (const s of sy.items) {
    const res = deviceResource("jumpcloud system", s._id, s.serialNumber);
    const plat = platformOf(s);
    const ver = osVersionOf(s);
    const where = ` (${String(s.os ?? plat)} ${ver ? showVersion(ver.v) : "version not reported"})`;

    const fde = sub(s, "fde");
    if (typeof fde.active === "boolean") out.add("device_encrypted", fde.active ? "pass" : "fail", `fde.active is ${fde.active}${where}${cap}`, res);
    else out.add("device_encrypted", "skipped", `fde.active not reported${where}`, res);

    if (o.minOs.size) {
      const floor = o.minOs.get(plat) ?? o.minOs.get("*");
      if (!floor) out.add("device_os_minimum", "skipped", `no --jumpcloud-min-os floor for ${plat}${where}`, res);
      else if (!ver) out.add("device_os_minimum", "skipped", `OS version not reported${where}`, res);
      else {
        const okv = cmpVersion(ver.v, floor) >= 0;
        out.add("device_os_minimum", okv ? "pass" : "fail", `${plat} ${showVersion(ver.v)} (${ver.from}) ${okv ? "meets" : "is below"} the --jumpcloud-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    const age = ageDays(s.lastContact, now);
    if (age === undefined) out.add("device_last_contact", "skipped", `lastContact not reported${where}`, res);
    else out.add("device_last_contact", age <= o.contactDays ? "pass" : "fail", `last contact ${age} day(s) ago; at most ${o.contactDays} allowed (--jumpcloud-contact-days)${where}`, res);
  }
  stampRead(out.results, from, listRead(sy));   // a capped list leaves devices unseen: format 3 says so
  return out.results;
}

export const jumpcloud: Source = {
  name: "jumpcloud",
  options: {
    "jumpcloud-org-id": { type: "string", help: `organization id (24 hex characters); sent as x-org-id. Default ${JUMPCLOUD_ENV.org}, else the only organization the key sees` },
    "jumpcloud-region": { type: "string", help: `data centre of the organization: ${Object.keys(REGIONS).join(", ")} (default us)` },
    "jumpcloud-min-password-length": { type: "string", help: `minimum password length the organization's password policy must set (default ${DEFAULTS.minPasswordLength})` },
    "jumpcloud-max-admins": { type: "string", help: `administrator accounts allowed, every role counted (default ${DEFAULTS.maxAdmins})` },
    "jumpcloud-min-os": { type: "string", multiple: true, help: "<platform>=<version> floor, e.g. macos=15.0 or windows=10.0.22631, or a bare version for every platform (repeatable; without it device_os_minimum is skipped)" },
    "jumpcloud-contact-days": { type: "string", help: `days since a device's last contact before device_last_contact fails (default ${DEFAULTS.contactDays})` },
    "jumpcloud-max-devices": { type: "string", help: `devices read, at most (default ${DEFAULTS.maxDevices})` },
  },
  emits: JUMPCLOUD_CHECKS.map((c) => `jumpcloud.${c}`),
  describe: () => "JumpCloud organization of JUMPCLOUD_API_KEY (API v1 and v2, Read Only administrator)",
  async run(ctx: SourceContext) {
    const orgOpt = str(ctx.opts["jumpcloud-org-id"]) ?? ctx.env[JUMPCLOUD_ENV.org];
    const region = str(ctx.opts["jumpcloud-region"]);
    const given = ctx.clients.jumpcloud as RestApi | null | undefined;
    const bad = orgOpt && !ORG_ID.test(orgOpt) ? "--jumpcloud-org-id must be 24 hexadecimal characters" : undefined;
    const built = bad ?? (given !== undefined ? given : jumpcloudFromEnv(ctx.env, { region, orgId: orgOpt }));
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("jumpcloud", `jumpcloud org ${orgOpt ?? "(unknown)"}`);
      out.skipAll(JUMPCLOUD_CHECKS, typeof built === "string" ? built : `${JUMPCLOUD_ENV.key} is not set`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: JumpcloudOptions = {
      orgId: orgOpt,
      minPasswordLength: intOpt(ctx.opts["jumpcloud-min-password-length"], DEFAULTS.minPasswordLength),
      maxAdmins: intOpt(ctx.opts["jumpcloud-max-admins"], DEFAULTS.maxAdmins),
      contactDays: posInt(ctx.opts["jumpcloud-contact-days"], DEFAULTS.contactDays),
      maxDevices: posInt(ctx.opts["jumpcloud-max-devices"], DEFAULTS.maxDevices),
      minOs: minOsOption(ctx.opts["jumpcloud-min-os"]),
    };
    return redact(await jumpcloudChecks(api, o, ctx.now), [ctx.env[JUMPCLOUD_ENV.key]]);
  },
};
