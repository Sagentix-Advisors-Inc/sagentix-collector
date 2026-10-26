// Per-account checks over the Cloudflare API (GET only).
//
// Endpoints and the read permission each needs (Cloudflare OpenAPI, x-api-token-group, unless noted):
//   GET /accounts/{a}                                      Account Settings Read
//   GET /accounts/{a}/members                              Account Settings Read
//   GET /accounts/{a}/audit_logs                           Account Settings Read
//   GET /accounts/{a}/tokens                               Account API Tokens Read
//   GET /accounts/{a}/alerting/v3/policies                 Notifications Read (or Account Settings Read)
//   GET /accounts/{a}/access/apps                          Access: Apps and Policies Read
//   GET /accounts/{a}/access/apps/{id}/policies            Access: Apps and Policies Read
//   GET /accounts/{a}/access/organizations                 Access: Organizations, Identity Providers, and Groups Read
//   GET /accounts/{a}/gateway/rules                        Zero Trust Read [unconfirmed: the OpenAPI names no group]
//   GET /accounts/{a}/devices/posture                      Zero Trust Read [unconfirmed: the OpenAPI names no group]
//   GET /accounts/{a}/gateway/locations                    Zero Trust Read (named by the OpenAPI at api-schemas bdeecc5c, read 2026-10-20)
//   GET /accounts/{a}/devices/physical-devices             Zero Trust Read [unconfirmed: the OpenAPI names no group]
//   GET /accounts/{a}/r2/buckets                           Workers R2 Storage Read
//   GET /accounts/{a}/r2/buckets/{b}/domains/managed       Workers R2 Storage Read (com.cloudflare.edge.r2.bucket.read)
//   GET /accounts/{a}/gateway/configuration                Zero Trust Read [unconfirmed: the OpenAPI names no group]

import type { Outcome, Read, Result } from "../../types.ts";
import { arr, durationSeconds, getAll, isObj, ok, resultOf, safeGet, str, why, type CfResponse, type CloudflareApi, type Obj } from "./api.ts";

export const ACCOUNT_CHECKS = [
  "account_enforces_2fa", "members_have_2fa", "super_admins_limited", "audit_log_available",
  "account_tokens_expire", "security_notifications", "access_apps_have_policies", "access_mfa_required",
  "access_session_duration", "gateway_dns_filtering", "device_posture_rules", "r2_public_access_off",
  "gateway_antivirus",
] as const;
export type AccountCheck = (typeof ACCOUNT_CHECKS)[number];

export const DEFAULT_MAX_SUPER_ADMINS = 3;
export const MAX_ACCESS_SESSION_SECONDS = 24 * 3600;
export const SUPER_ADMIN = "Super Administrator - All Privileges";

/** Notification types that tell someone about an attack or a security finding (Cloudflare's alert_type enum). */
export const SECURITY_ALERT_TYPES = new Set([
  "dos_attack_l4", "dos_attack_l7", "advanced_ddos_attack_l4_alert", "advanced_ddos_attack_l7_alert",
  "fbm_dosd_attack", "fbm_volumetric_attack", "clickhouse_alert_fw_anomaly", "clickhouse_alert_fw_ent_anomaly",
  "security_insights_alert", "bot_traffic_basic_alert", "custom_bot_detection_alert", "traffic_anomalies_alert",
  "bgp_hijack_notification", "scriptmonitor_alert_new_malicious_scripts", "scriptmonitor_alert_new_malicious_url",
  "scriptmonitor_alert_new_malicious_hosts", "scriptmonitor_alert_new_code_change_detections",
]);

/** Access application types that carry no access policies of their own. */
const NO_POLICY_APP_TYPES = new Set(["bookmark", "app_launcher", "warp", "biso"]);

const enc = encodeURIComponent;
const j = (v: unknown) => JSON.stringify(v);

class Out {
  results: Result[] = [];
  readonly resource: string;
  constructor(resource: string) { this.resource = resource; }
  add(check: AccountCheck, result: Outcome, detail: string, resource = this.resource, read?: Read) {
    this.results.push({ ...read, check: `cloudflare.${check}`, resource, result, detail });
  }
  skip(check: AccountCheck, r: CfResponse, what: string, resource = this.resource) {
    this.add(check, "skipped", `${what} not readable: ${why(r)}`, resource, { method: "config-read", apiError: { status: r.status, message: why(r) } });
  }
}

export function accountSkipped(resource: string, reason: string): Result[] {
  return ACCOUNT_CHECKS.map((c) => ({ check: `cloudflare.${c}`, resource, result: "skipped" as const, detail: reason }));
}

export interface AccountOptions { maxSuperAdmins: number }

export async function accountChecks(api: CloudflareApi, account: string, o: AccountOptions): Promise<Result[]> {
  const out = new Out(`account ${account}`);
  const ap = `/accounts/${enc(account)}`;

  const acct = await safeGet(api, ap);
  if (ok(acct)) {
    const r = resultOf(acct);
    const enforced = isObj(r) && isObj(r.settings) ? r.settings.enforce_twofactor : undefined;
    if (typeof enforced === "boolean") out.add("account_enforces_2fa", enforced ? "pass" : "fail", `enforce_twofactor is ${enforced}; true required`);
    else out.add("account_enforces_2fa", "skipped", "the API did not return settings.enforce_twofactor");
  } else out.skip("account_enforces_2fa", acct, "account");

  await members(api, ap, out, o.maxSuperAdmins);

  const al = await safeGet(api, `${ap}/audit_logs?per_page=1&direction=desc`);
  if (ok(al) && Array.isArray(resultOf(al))) {
    const first = (resultOf(al) as unknown[])[0];
    const when = isObj(first) ? first.when : undefined;
    out.add("audit_log_available", first ? "pass" : "fail",
      first ? `account audit log readable; latest entry at ${String(when)}` : "account audit log readable but empty");
  } else out.skip("audit_log_available", al, "audit log");

  await tokens(api, ap, out);
  await notifications(api, ap, out);
  await access(api, ap, out);

  const gw = await safeGet(api, `${ap}/gateway/rules`);
  if (!ok(gw) || !Array.isArray(resultOf(gw))) out.skip("gateway_dns_filtering", gw, "Gateway rules");
  else {
    const rules = (resultOf(gw) as unknown[]).filter(isObj);
    const dns = rules.filter((r) => r.enabled === true && arr(r.filters).includes("dns") && r.action === "block");
    const head = `${rules.length} Gateway rule(s), ${dns.length} enabled DNS block rule(s)${dns.length ? ` (${dns.slice(0, 5).map((r) => j(r.name)).join(", ")})` : ""}`;
    if (!dns.length) out.add("gateway_dns_filtering", "fail", `${head}; at least one required`);
    else {
      // A DNS rule filters nothing until a query reaches Gateway: through a DNS location (a network
      // pointed at Gateway's resolvers) or an enrolled device. The dashboard calls such rules
      // "inactive"; so does this check (2026-10-16).
      const loc = await safeGet(api, `${ap}/gateway/locations`);
      const dev = await safeGet(api, `${ap}/devices/physical-devices?per_page=1`);
      const count = (r: CfResponse) => ok(r) && Array.isArray(resultOf(r)) ? (resultOf(r) as unknown[]).length : undefined;
      const nLoc = count(loc), nDev = count(dev);
      if ((nLoc ?? 0) > 0 || (nDev ?? 0) > 0) {
        out.add("gateway_dns_filtering", "pass",
          `${head}; in force: ${nLoc ?? "?"} DNS location(s), ${nDev === undefined ? "?" : nDev > 0 ? "at least one" : "0"} enrolled device(s)`);
      } else if (nLoc === undefined || nDev === undefined) {
        out.skip("gateway_dns_filtering", nLoc === undefined ? loc : dev, nLoc === undefined ? "Gateway DNS locations" : "enrolled devices");
      } else {
        out.add("gateway_dns_filtering", "fail",
          `${head}, but 0 DNS locations and 0 enrolled devices send queries to Gateway, so the rules filter nothing; a location or an enrolled device required`);
      }
    }
  }

  const dp = await safeGet(api, `${ap}/devices/posture`);
  if (!ok(dp) || !Array.isArray(resultOf(dp))) out.skip("device_posture_rules", dp, "device posture rules");
  else {
    const rules = (resultOf(dp) as unknown[]).filter(isObj);
    const types = [...new Set(rules.map((r) => String(r.type)))];
    out.add("device_posture_rules", rules.length ? "pass" : "fail",
      `${rules.length} device posture rule(s)${types.length ? ` (types: ${types.join(", ")})` : ""}; at least one required`);
  }

  await r2(api, ap, out);
  await antivirus(api, ap, out);
  return out.results;
}

// Gateway anti-virus scanning. "Get Zero Trust account configuration" (developers.cloudflare.com/api/resources/
// zero_trust/subresources/gateway/subresources/configurations/methods/get/, read 2026-10-26): GET
// /accounts/{a}/gateway/configuration, result.settings.antivirus { enabled_download_phase, enabled_upload_phase,
// fail_closed } and settings.tls_decrypt.enabled ("whether to inspect encrypted HTTP traffic"). "AV scanning"
// (developers.cloudflare.com/cloudflare-one/traffic-policies/http-policies/antivirus-scanning/, last updated
// 2026-10-12, read 2026-10-26): Gateway "inspects files as they pass through the proxy and blocks any file that contains
// a known malicious payload". "TLS decryption" (.../http-policies/tls-decryption/, last updated 2026-10-15, read
// 2026-10-26): without inspection "you will lose the ability to ... perform AV scanning", so HTTPS downloads, most of
// them, are scanned only with TLS decryption on. Downloads are where malicious code comes in; uploads are reported.
// The OpenAPI (api-schemas 1a8429dc, read 2026-10-26) names no token group for this endpoint, as for gateway/rules:
// Zero Trust Read [unconfirmed].
async function antivirus(api: CloudflareApi, ap: string, out: Out): Promise<void> {
  const r = await safeGet(api, `${ap}/gateway/configuration`);
  const res = resultOf(r);
  if (!ok(r) || !isObj(res)) return out.skip("gateway_antivirus", r, "Gateway account configuration");
  const st = isObj(res.settings) ? res.settings : {};
  const av = isObj(st.antivirus) ? st.antivirus : {};
  const tls = isObj(st.tls_decrypt) ? st.tls_decrypt.enabled : undefined;
  const down = av.enabled_download_phase === true;
  out.add("gateway_antivirus", down && tls === true ? "pass" : "fail",
    `antivirus.enabled_download_phase ${j(av.enabled_download_phase ?? null)}, enabled_upload_phase ${j(av.enabled_upload_phase ?? null)}, fail_closed ${j(av.fail_closed ?? null)}; tls_decrypt.enabled ${j(tls ?? null)}; download scanning and TLS decryption on required (only traffic sent through Gateway is scanned)`);
}

async function members(api: CloudflareApi, ap: string, out: Out, maxSuper: number): Promise<void> {
  const m = await getAll(api, `${ap}/members`, 50, 20);
  if ("error" in m) {
    out.skip("members_have_2fa", m.error, "members");
    out.skip("super_admins_limited", m.error, "members");
    return;
  }
  // Emails are never sent to sos-app; member ids are.
  let with2fa = 0, unknown = 0;
  const without: string[] = [], supers: string[] = [];
  for (const x of m.items.filter(isObj)) {
    if (x.status !== undefined && x.status !== "accepted" && x.status !== "pending") continue;
    const roleNames = arr(x.roles).filter(isObj).map((r) => String(r.name));
    const groupNames = arr(x.policies).filter(isObj).flatMap((p) => (p.access === "deny" ? [] : arr(p.permission_groups).filter(isObj).map((g) => String(g.name))));
    if ([...roleNames, ...groupNames].includes(SUPER_ADMIN)) supers.push(String(x.id ?? "?"));
    if (x.status === "pending") continue;
    const tfa = isObj(x.user) ? x.user.two_factor_authentication_enabled : undefined;
    if (tfa === true) with2fa++;
    else if (tfa === false) without.push(String(x.id ?? "?"));
    else unknown++;
  }
  if (with2fa + without.length === 0) out.add("members_have_2fa", "skipped", "the API did not show two_factor_authentication_enabled for any accepted member");
  else out.add("members_have_2fa", without.length ? "fail" : "pass",
    `${with2fa} accepted member(s) with 2FA, ${without.length} without${without.length ? ` (member ids ${without.slice(0, 20).join(", ")})` : ""}${unknown ? `, ${unknown} not shown` : ""}; all required`);
  out.add("super_admins_limited", supers.length <= maxSuper ? "pass" : "fail",
    `${supers.length} member(s) hold "${SUPER_ADMIN}"${supers.length ? ` (member ids ${supers.slice(0, 20).join(", ")})` : ""}; at most ${maxSuper} allowed (--max-super-admins)`);
}

async function tokens(api: CloudflareApi, ap: string, out: Out): Promise<void> {
  const t = await getAll(api, `${ap}/tokens`, 50, 20);
  if ("error" in t) return out.skip("account_tokens_expire", t.error, "account-owned API tokens");
  const active = t.items.filter(isObj).filter((x) => x.status === undefined || x.status === "active");
  if (!active.length) return out.add("account_tokens_expire", "skipped", "no active account-owned API token is listed");
  for (const x of active) {
    const exp = str(x.expires_on);
    out.add("account_tokens_expire", exp ? "pass" : "fail",
      exp ? `expires_on ${exp}` : "no expires_on: the token never expires; an expiry is required",
      `api token ${String(x.name ?? "")} (${String(x.id ?? "?")})`.slice(0, 300));
  }
}

async function notifications(api: CloudflareApi, ap: string, out: Out): Promise<void> {
  const n = await safeGet(api, `${ap}/alerting/v3/policies`);
  if (!ok(n) || !Array.isArray(resultOf(n))) return out.skip("security_notifications", n, "notification policies");
  const all = (resultOf(n) as unknown[]).filter(isObj);
  const sec = all.filter((p) => p.enabled === true && SECURITY_ALERT_TYPES.has(String(p.alert_type)));
  const types = [...new Set(sec.map((p) => String(p.alert_type)))];
  out.add("security_notifications", sec.length ? "pass" : "fail",
    `${all.length} notification polic(ies), ${sec.length} enabled for attack or security alerts${types.length ? ` (${types.join(", ")})` : ""}; at least one required`);
}

type Rule = Obj;
const ruleKeys = (rules: unknown): string[] => arr(rules).filter(isObj).flatMap((r) => Object.keys(r));
const hasMfa = (rules: unknown) => arr(rules).filter(isObj).some((r) => isObj(r.auth_method) && r.auth_method.auth_method === "mfa");

// Access "independent MFA" prompts for a second factor in Access itself, so it works with any identity
// provider (the auth_method rule needs one that reports AMR: Okta, Entra ID, generic OIDC or SAML).
// Precedence is policy > application > organisation; an mfa_config with mfa_disabled turns it off at
// that level, one with authenticators turns it on, and none defers to the level above.
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/mfa-requirements/
type MfaLevel = "on" | "off" | "inherit";
const mfaLevel = (o: Obj): MfaLevel => {
  if (!isObj(o.mfa_config)) return "inherit";
  if (o.mfa_config.mfa_disabled === true) return "off";
  return arr(o.mfa_config.allowed_authenticators).length ? "on" : "inherit";
};
const independentMfa = (policy: Obj, app: Obj, orgOn: boolean): boolean => {
  for (const level of [mfaLevel(policy), mfaLevel(app)]) if (level !== "inherit") return level === "on";
  return orgOn;
};

async function access(api: CloudflareApi, ap: string, out: Out): Promise<void> {
  const checks: AccountCheck[] = ["access_apps_have_policies", "access_mfa_required", "access_session_duration"];
  const apps = await getAll(api, `${ap}/access/apps`, 50, 20);
  if ("error" in apps) { for (const c of checks) out.skip(c, apps.error, "Access applications"); return; }
  const list = apps.items.filter(isObj).filter((a) => !NO_POLICY_APP_TYPES.has(String(a.type)));
  if (!list.length) { for (const c of checks) out.add(c, "skipped", "the account has no Access application that takes policies"); return; }
  // An unreadable organisation counts as no organisation-wide MFA: the app and policy levels still show.
  const org = await safeGet(api, `${ap}/access/organizations`);
  const o = ok(org) && isObj(resultOf(org)) ? resultOf(org) as Obj : {};
  const orgOn = o.mfa_required_for_all_apps === true && isObj(o.mfa_config) && arr(o.mfa_config.allowed_authenticators).length > 0;
  for (const a of list) {
    const resource = `access app ${String(a.name ?? "")} (${String(a.domain ?? a.id ?? "?")})`.slice(0, 300);
    const sd = str(a.session_duration);
    const appSecs = sd === undefined ? MAX_ACCESS_SESSION_SECONDS : durationSeconds(sd);
    const appShown = sd === undefined ? "not set (Access default 24h)" : j(sd);

    const pr = await safeGet(api, `${ap}/access/apps/${enc(String(a.id))}/policies`);
    if (!ok(pr) || !Array.isArray(resultOf(pr))) {
      out.skip("access_apps_have_policies", pr, "the application's policies", resource);
      out.skip("access_mfa_required", pr, "the application's policies", resource);
      // A policy's own duration can be longer than the application's, so a short application value proves nothing alone.
      if (appSecs !== undefined && appSecs > MAX_ACCESS_SESSION_SECONDS) out.add("access_session_duration", "fail", `session_duration is ${appShown}; 24h or less required`, resource);
      else out.skip("access_session_duration", pr, "the application's policies (a policy session duration overrides the application's)", resource);
      continue;
    }
    const pols = (resultOf(pr) as unknown[]).filter(isObj) as Rule[];
    const allow = pols.filter((p) => p.decision === "allow");

    // The application token lasts the policy session duration, "which defaults to the application session
    // duration" (developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/,
    // last updated 2026-10-14, read 2026-10-26: "Policy session — Controls access to a specific application for
    // users matching a specific policy"). So the longest allow policy is what a user gets, not the application value.
    const lens = allow.map((p) => { const ps = str(p.session_duration); return { ps, secs: ps === undefined ? appSecs : durationSeconds(ps) }; });
    const own = lens.filter((l) => l.ps !== undefined);
    const unparsed = own.find((l) => l.secs === undefined);
    if (unparsed) out.add("access_session_duration", "skipped", `a policy session_duration ${j(unparsed.ps)} does not parse`, resource);
    else if (lens.some((l) => l.secs === undefined) || (!allow.length && appSecs === undefined)) out.add("access_session_duration", "skipped", `session_duration ${j(sd)} does not parse`, resource);
    else {
      const worst = Math.max(...(allow.length ? lens.map((l) => l.secs as number) : [appSecs as number]));
      const ownLongest = own.length ? Math.max(...own.map((l) => l.secs as number)) : 0;
      out.add("access_session_duration", worst <= MAX_ACCESS_SESSION_SECONDS ? "pass" : "fail",
        `session_duration is ${appShown}${own.length ? `; ${own.length} of ${allow.length} allow polic(ies) set their own, which overrides it (longest ${Math.round(ownLongest / 60)} min)` : ""}; 24h or less required for every allow policy`,
        resource);
    }

    // Service Auth (decision non_identity) admits a service token or a client certificate instead of a person:
    // "Service Auth rules in Cloudflare Access enforce authentication flows that do not require an identity
    // provider IdP login, such as service tokens and mutual TLS" (developers.cloudflare.com/cloudflare-one/
    // access-controls/policies/, last updated 2026-10-01, read 2026-10-26). One that names its tokens or
    // certificates counts as naming who may enter; one that includes everyone is as open as a bypass.
    const service = pols.filter((p) => p.decision === "non_identity" && ruleKeys(p.include).length && !ruleKeys(p.include).includes("everyone"));
    const openBypass = pols.filter((p) => (p.decision === "bypass" || p.decision === "non_identity") && ruleKeys(p.include).includes("everyone"));
    const openAllow = allow.filter((p) => ruleKeys(p.include).every((k) => k === "everyone") && !arr(p.require).length);
    const named = allow.length - openAllow.length + service.length;
    out.add("access_apps_have_policies", named > 0 && !openBypass.length ? "pass" : "fail",
      `${pols.length} polic(ies): ${allow.length} allow (${openAllow.length} let everyone in), ${service.length} service auth naming its tokens or certificates, ${openBypass.length} bypass or service-auth for everyone; an allow or service auth policy that names who may enter, and no bypass for everyone, required`,
      resource);
    const mfa = allow.filter((p) => hasMfa(p.require) || hasMfa(p.include) || independentMfa(p, a, orgOn));
    // A service-auth-only application admits no person, so there is no one to ask for a second factor.
    if (!allow.length && service.length) { out.add("access_mfa_required", "skipped", `no allow policy: the application admits only service tokens or certificates (${service.length} service auth polic(ies))`, resource); continue; }
    out.add("access_mfa_required", allow.length > 0 && mfa.length === allow.length ? "pass" : "fail",
      `${mfa.length} of ${allow.length} allow polic(ies) require MFA (an auth_method "mfa" rule, or Access independent MFA set on the policy, the application or the organisation); all required (MFA enforced only at the identity provider is not visible here)`,
      resource);
  }
}

async function r2(api: CloudflareApi, ap: string, out: Out): Promise<void> {
  const names: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 10; page++) {
    const b = await safeGet(api, `${ap}/r2/buckets?per_page=1000${cursor ? `&cursor=${enc(cursor)}` : ""}`);
    const res = resultOf(b);
    if (!ok(b) || !isObj(res)) return out.skip("r2_public_access_off", b, "R2 buckets");
    names.push(...arr(res.buckets).filter(isObj).map((x) => String(x.name)));
    cursor = isObj(b.body) && isObj((b.body as Obj).result_info) ? str(((b.body as Obj).result_info as Obj).cursor) : undefined;
    if (!cursor) break;
  }
  if (!names.length) return out.add("r2_public_access_off", "skipped", "the account has no R2 bucket");
  for (const name of names) {
    const resource = `r2 bucket ${name}`;
    const d = await safeGet(api, `${ap}/r2/buckets/${enc(name)}/domains/managed`);
    if (!ok(d) || !isObj(resultOf(d))) { out.skip("r2_public_access_off", d, "the bucket's r2.dev setting", resource); continue; }
    const en = (resultOf(d) as Obj).enabled;
    out.add("r2_public_access_off", en === false ? "pass" : "fail", `public access through r2.dev enabled is ${j(en)}; false required`, resource);
  }
}
