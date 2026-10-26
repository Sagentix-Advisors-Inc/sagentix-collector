// Per-zone checks over the Cloudflare API (GET only). Each check gives one result per zone (or per
// certificate pack / custom hostname). A call that is refused or not on the plan gives "skipped".
//
// Endpoints and the read permission each needs (Cloudflare OpenAPI, x-api-token-group):
//   GET /zones/{z}                                         Zone Read
//   GET /zones/{z}/settings/{setting}                      Zone Settings Read
//   GET /zones/{z}/dnssec                                  DNS Read
//   GET /zones/{z}/dns_records                             DNS Read (only to find Cloudflare Tunnel routes for bot_protection)
//   GET /zones/{z}/rulesets/phases/{phase}/entrypoint      Zone WAF Read (firewall_managed, firewall_custom, ratelimit)
//   GET /zones/{z}/leaked-credential-checks                Zone WAF Read
//   GET /zones/{z}/bot_management                          Bot Management Read
//   GET /zones/{z}/ssl/certificate_packs                   SSL and Certificates Read
//   GET /zones/{z}/custom_hostnames                        SSL and Certificates Read
//   GET /zones/{z}/page_shield                             Zone Settings Read (or Page Shield Read)
//   GET /zones/{z}/security-center/securitytxt             Zone Settings Read
// (each group checked against openapi.json at github.com/cloudflare/api-schemas commit bdeecc5c, read 2026-10-20)
//
// Not read: the security_level setting (check cloudflare.security_level, retired 2026-10-20). Cloudflare's Security
// Level page (developers.cloudflare.com/waf/tools/security-level/, last updated 2026-04-16, read 2026-10-20): the
// dashboard value is fixed at "Always protected", in the API and Terraform security_level now turns Under Attack mode
// on or off, and the threat score it acted on "is always 0". The API still takes off ... under_attack, but no value
// challenges visitors by IP reputation any more, so a pass on "medium" or a fail on "off" would show nothing.

import type { Outcome, Read, Result } from "../../types.ts";
import { arr, getAll, isObj, ok, resultOf, safeGet, str, why, type CfResponse, type CloudflareApi, type Obj } from "./api.ts";

export const ZONE_CHECKS = [
  "min_tls_version", "tls_1_3", "always_use_https", "automatic_https_rewrites", "ssl_mode", "hsts",
  "browser_integrity_check", "dnssec", "waf_managed_ruleset", "waf_custom_rules",
  "rate_limiting_rules", "bot_protection", "leaked_credential_checks", "edge_certificates_valid",
  "custom_hostname_min_tls", "page_shield", "security_txt",
] as const;
export type ZoneCheck = (typeof ZONE_CHECKS)[number];

/** Days of validity an edge certificate must have left: uploaded ones are renewed by people. */
export const CERT_MIN_DAYS_CUSTOM = 30;
/** Cloudflare renews managed certificates itself, about 30 days before a 90-day certificate ends. */
export const CERT_MIN_DAYS_MANAGED = 14;
// Cloudflare's "Validity periods and renewal" (developers.cloudflare.com/ssl/reference/certificate-validity-periods/,
// last updated 2026-10-15, read 2026-10-26): renewal attempts "start at the auto renewal period and continue up until
// 24 hours before expiration"; that period is 30 days for 1-year and 3-month certificates, 7 days for 1-month and
// 3 days for 2-week advanced certificates. A 14-day floor fails every healthy 2-week certificate and every 1-month
// one in its last fortnight, so the floor follows the pack's validity_days: about halfway into the renewal window,
// past which renewal has stalled rather than not yet run.
export const CERT_MIN_DAYS_MANAGED_BY_VALIDITY: Record<number, number> = { 365: 14, 90: 14, 30: 3, 14: 1 };
const CUSTOM_PACK_TYPES = new Set(["sni_custom", "mh_custom", "legacy_custom", "custom"]);

const SETTINGS: [ZoneCheck, string][] = [
  ["min_tls_version", "min_tls_version"],
  ["tls_1_3", "tls_1_3"],
  ["always_use_https", "always_use_https"],
  ["automatic_https_rewrites", "automatic_https_rewrites"],
  ["ssl_mode", "ssl"],
  ["hsts", "security_header"],
  ["browser_integrity_check", "browser_check"],
];

const CHALLENGE_OR_BLOCK = new Set(["block", "challenge", "js_challenge", "managed_challenge"]);
const enc = encodeURIComponent;
const j = (v: unknown) => JSON.stringify(v);

export interface ZoneRun { results: Result[]; accountId?: string; name?: string }

class Out {
  results: Result[] = [];
  readonly resource: string;
  constructor(resource: string) { this.resource = resource; }
  add(check: ZoneCheck, result: Outcome, detail: string, resource = this.resource, read?: Read) {
    this.results.push({ ...read, check: `cloudflare.${check}`, resource, result, detail });
  }
  skip(check: ZoneCheck, r: CfResponse, what: string, resource = this.resource) {
    this.add(check, "skipped", `${what} not readable: ${why(r)}`, resource, { method: "config-read", apiError: { status: r.status, message: why(r) } });
  }
}

/** Every zone check skipped for one reason (zone unreadable, no token). */
export function zoneSkipped(resource: string, reason: string): Result[] {
  return ZONE_CHECKS.map((c) => ({ check: `cloudflare.${c}`, resource, result: "skipped" as const, detail: reason }));
}

function judgeSetting(out: Out, check: ZoneCheck, id: string, value: unknown): void {
  const simple = (okValues: string[], want: string) =>
    out.add(check, okValues.includes(String(value)) ? "pass" : "fail", `${id} is ${j(value)}; ${want}`, out.resource,
      { method: "config-read", expected: okValues.join(" or "), observed: String(value), complete: true });
  switch (check) {
    case "min_tls_version": return simple(["1.2", "1.3"], "1.2 or 1.3 required");
    case "tls_1_3": return simple(["on", "zrt"], "on required");
    case "always_use_https": return simple(["on"], "on required");
    case "automatic_https_rewrites": return simple(["on"], "on required");
    // origin_pull is Strict (SSL-Only Origin Pull): "Regardless of whether the visitor-to-Cloudflare connection uses
    // HTTP or HTTPS, Cloudflare always connects to the origin over HTTPS with certificate validation"
    // (developers.cloudflare.com/ssl/origin-configuration/ssl-modes/, last updated 2026-04-16, read 2026-10-26),
    // so it validates the origin as Full (strict) does.
    case "ssl_mode": return simple(["strict", "origin_pull"], "strict (Full (strict)) or origin_pull (Strict (SSL-Only Origin Pull)) required");
    case "browser_integrity_check": return simple(["on"], "on required");
    case "hsts": {
      const h = isObj(value) && isObj(value.strict_transport_security) ? value.strict_transport_security : {};
      const pass = h.enabled === true && Number(h.max_age) >= 31536000 && h.include_subdomains === true;
      return out.add(check, pass ? "pass" : "fail",
        `HSTS enabled=${String(h.enabled)} max_age=${String(h.max_age)} include_subdomains=${String(h.include_subdomains)}; enabled, max_age >= 31536000 and include_subdomains required`);
    }
    default: return;
  }
}

/** The rules of a zone's phase entrypoint; null when the zone has none (Cloudflare answers 404). */
async function entrypoint(api: CloudflareApi, zone: string, phase: string): Promise<{ rules: Obj[] | null } | { error: CfResponse }> {
  const r = await safeGet(api, `/zones/${enc(zone)}/rulesets/phases/${phase}/entrypoint`);
  if (r.status === 404) return { rules: null };
  if (!ok(r)) return { error: r };
  const res = resultOf(r);
  return { rules: (isObj(res) ? arr(res.rules) : []).filter(isObj) };
}

const enabled = (r: Obj) => r.enabled !== false;

export async function zoneChecks(api: CloudflareApi, zoneId: string, now: Date): Promise<ZoneRun> {
  const z = await safeGet(api, `/zones/${enc(zoneId)}`);
  if (!ok(z) || !isObj(resultOf(z))) return { results: zoneSkipped(`zone ${zoneId}`, `zone not readable: ${why(z)}`) };
  const zr = resultOf(z) as Obj;
  const name = str(zr.name) ?? zoneId;
  const accountId = isObj(zr.account) ? str(zr.account.id) : undefined;
  const plan = isObj(zr.plan) ? String(zr.plan.legacy_id ?? zr.plan.name ?? "") : "";
  const out = new Out(`zone ${name}`);
  const zp = `/zones/${enc(zoneId)}`;

  // Zone settings, one call each (the all-settings endpoint is deprecated).
  let zoneMinTls: unknown;
  for (const [check, id] of SETTINGS) {
    const s = await safeGet(api, `${zp}/settings/${id}`);
    if (!ok(s) || !isObj(resultOf(s))) { out.skip(check, s, `setting ${id}`); continue; }
    const value = (resultOf(s) as Obj).value;
    if (check === "min_tls_version") zoneMinTls = value;
    judgeSetting(out, check, id, value);
  }

  const dn = await safeGet(api, `${zp}/dnssec`);
  if (ok(dn)) {
    const st = isObj(resultOf(dn)) ? (resultOf(dn) as Obj).status : undefined;
    out.add("dnssec", st === "active" ? "pass" : "fail", `DNSSEC status is ${j(st)}; active required`);
  } else out.skip("dnssec", dn, "DNSSEC");

  const managed = await entrypoint(api, zoneId, "http_request_firewall_managed");
  if ("error" in managed) out.skip("waf_managed_ruleset", managed.error, "managed WAF entrypoint");
  else {
    const ex = (managed.rules ?? []).filter((r) => r.action === "execute" && enabled(r));
    out.add("waf_managed_ruleset", ex.length ? "pass" : "fail", managed.rules === null
      ? "no ruleset in phase http_request_firewall_managed; an enabled execute rule is required"
      : `${ex.length} enabled execute rule(s) in phase http_request_firewall_managed${ex.length ? ` (rulesets ${ex.map((r) => (isObj(r.action_parameters) ? String(r.action_parameters.id) : "?")).join(", ")})` : ""}; at least one required`);
  }

  const custom = await entrypoint(api, zoneId, "http_request_firewall_custom");
  if ("error" in custom) out.skip("waf_custom_rules", custom.error, "custom WAF entrypoint");
  else {
    const all = custom.rules ?? [];
    const acting = all.filter((r) => enabled(r) && CHALLENGE_OR_BLOCK.has(String(r.action)));
    out.add("waf_custom_rules", acting.length ? "pass" : "fail",
      `${all.length} custom rule(s) in phase http_request_firewall_custom, ${acting.length} enabled with a block or challenge action; at least one required`);
  }

  const rl = await entrypoint(api, zoneId, "http_ratelimit");
  if ("error" in rl) out.skip("rate_limiting_rules", rl.error, "rate limiting entrypoint");
  else {
    const all = rl.rules ?? [];
    const on = all.filter(enabled);
    out.add("rate_limiting_rules", on.length ? "pass" : "fail",
      `${all.length} rate limiting rule(s) in phase http_ratelimit, ${on.length} enabled; at least one enabled rule required`);
  }

  const bm = await safeGet(api, `${zp}/bot_management`);
  if (!ok(bm) || !isObj(resultOf(bm))) out.skip("bot_protection", bm, "bot management settings");
  else {
    const b = resultOf(bm) as Obj;
    const sbfm = str(b.sbfm_definitely_automated);
    if (b.fight_mode === true) out.add("bot_protection", "pass", "Bot Fight Mode is on");
    else if (sbfm && CHALLENGE_OR_BLOCK.has(sbfm)) out.add("bot_protection", "pass", `Super Bot Fight Mode acts on definitely automated traffic: ${sbfm}`);
    else if (/enterprise/i.test(plan)) {
      out.add("bot_protection", "skipped", "Enterprise plan: Bot Management acts through rules on the bot score, which this check does not judge");
    } else if (sbfm === "allow" && await usesTunnel(api, zp)) {
      // Super Bot Fight Mode page (developers.cloudflare.com/bots/get-started/super-bot-fight-mode/, last updated
      // 2026-08-03, read 2026-10-26): "If your organization also uses Cloudflare Tunnel, keep Definitely Automated set
      // to Allow. Otherwise, Super Bot Fight Mode may block tunnel connections". Allow is then what Cloudflare asks
      // for, so only likely automated traffic (Business and up) can still show protection.
      const likely = str(b.sbfm_likely_automated);
      if (likely && CHALLENGE_OR_BLOCK.has(likely)) out.add("bot_protection", "pass", `the zone routes to Cloudflare Tunnel, so definitely automated traffic stays allowed as Cloudflare asks; Super Bot Fight Mode acts on likely automated traffic: ${likely}`);
      else out.add("bot_protection", "skipped", `the zone routes to Cloudflare Tunnel, where Cloudflare asks that definitely automated traffic stay allowed; sbfm_likely_automated is ${j(likely ?? null)}, so no bot protection this check can judge is on`);
    } else {
      out.add("bot_protection", "fail", `fight_mode is ${j(b.fight_mode)}, sbfm_definitely_automated is ${j(sbfm ?? null)}; Bot Fight Mode on, or Super Bot Fight Mode blocking or challenging definitely automated traffic, required`);
    }
  }

  const lc = await safeGet(api, `${zp}/leaked-credential-checks`);
  if (!ok(lc) || !isObj(resultOf(lc))) out.skip("leaked_credential_checks", lc, "leaked credential detection");
  else {
    const en = (resultOf(lc) as Obj).enabled;
    out.add("leaked_credential_checks", en === true ? "pass" : "fail", `leaked credential detection enabled is ${j(en)}; true required`);
  }

  await certificatePacks(api, zoneId, out, now);
  await customHostnames(api, zoneId, out, zoneMinTls);

  const ps = await safeGet(api, `${zp}/page_shield`);
  if (!ok(ps) || !isObj(resultOf(ps))) out.skip("page_shield", ps, "client-side security (Page Shield)");
  else {
    const en = (resultOf(ps) as Obj).enabled;
    out.add("page_shield", en === true ? "pass" : "fail", `client-side security (Page Shield) enabled is ${j(en)}; true required`);
  }

  const st = await safeGet(api, `${zp}/security-center/securitytxt`);
  // With nothing configured, Cloudflare answers success with result "" (seen on a live zone, 2026-10-15):
  // that is a fail (none served by Cloudflare), not an unreadable answer.
  if (ok(st) && (resultOf(st) === "" || resultOf(st) === null)) {
    out.add("security_txt", "fail", "no security.txt is configured in Cloudflare; enabled with a contact required (a security.txt served by the origin is not visible here)");
  } else if (!ok(st) || !isObj(resultOf(st))) out.skip("security_txt", st, "security.txt");
  else {
    const t = resultOf(st) as Obj;
    const contacts = arr(t.contact).filter((c) => typeof c === "string" && c);
    // RFC 9116 §2.5.5: Expires "MUST always be present", and after it the file "is considered stale and should not be
    // used"; Cloudflare's security.txt page marks Expires at as required (developers.cloudflare.com/security-center/
    // infrastructure/security-file/, last updated 2026-08-03, read 2026-10-26). A file past its date passes nothing.
    const exp = Date.parse(String(t.expires ?? ""));
    const current = Number.isFinite(exp) && exp > now.getTime();
    const pass = t.enabled === true && contacts.length > 0 && current;
    out.add("security_txt", pass ? "pass" : "fail",
      `Cloudflare-served security.txt enabled is ${j(t.enabled)} with ${contacts.length} contact(s), ${t.expires ? `expires ${String(t.expires)}${current ? "" : " (not after the run: the file is stale)"}` : "no expires"}; enabled with a contact and an expiry after the run required (a security.txt served by the origin is not visible here)`);
  }

  return { results: out.results, accountId, name };
}

async function certificatePacks(api: CloudflareApi, zoneId: string, out: Out, now: Date): Promise<void> {
  const packs = await getAll(api, `/zones/${enc(zoneId)}/ssl/certificate_packs`, 50, 10);
  if ("error" in packs) return out.skip("edge_certificates_valid", packs.error, "certificate packs");
  const list = packs.items.filter(isObj);
  if (!list.length) return out.add("edge_certificates_valid", "fail", "no edge certificate pack on the zone; HTTPS through Cloudflare needs one");
  for (const p of list) {
    const type = String(p.type ?? "unknown"), id = String(p.id ?? "?");
    const resource = `${out.resource} certificate pack ${type} ${id}`;
    const ends = arr(p.certificates).filter(isObj).map((c) => Date.parse(String(c.expires_on ?? ""))).filter(Number.isFinite);
    const minDays = CUSTOM_PACK_TYPES.has(type) ? CERT_MIN_DAYS_CUSTOM : CERT_MIN_DAYS_MANAGED_BY_VALIDITY[Number(p.validity_days)] ?? CERT_MIN_DAYS_MANAGED;
    if (p.status !== "active") {
      out.add("edge_certificates_valid", "fail", `pack status is ${j(p.status)}; active required`, resource);
    } else if (!ends.length) {
      out.add("edge_certificates_valid", "skipped", "pack is active but the API returned no certificate expiry", resource);
    } else {
      const left = Math.floor((Math.min(...ends) - now.getTime()) / 86_400_000);
      out.add("edge_certificates_valid", left > minDays ? "pass" : "fail",
        `active; earliest certificate expires ${new Date(Math.min(...ends)).toISOString().slice(0, 10)} (${left} days left); more than ${minDays} days required for a ${CUSTOM_PACK_TYPES.has(type) ? "custom (uploaded)" : "Cloudflare-managed"} pack`,
        resource);
    }
  }
}

/** Does a CNAME of the zone point at a Cloudflare Tunnel (<uuid>.cfargotunnel.com)? An unreadable list counts as no. */
async function usesTunnel(api: CloudflareApi, zp: string): Promise<boolean> {
  const r = await safeGet(api, `${zp}/dns_records?type=CNAME&content.endswith=.cfargotunnel.com&per_page=1`);
  return ok(r) && Array.isArray(resultOf(r)) && (resultOf(r) as unknown[]).length > 0;
}

async function customHostnames(api: CloudflareApi, zoneId: string, out: Out, zoneMinTls: unknown): Promise<void> {
  const hs = await getAll(api, `/zones/${enc(zoneId)}/custom_hostnames`, 50, 40);
  if ("error" in hs) return out.skip("custom_hostname_min_tls", hs.error, "custom hostnames (Cloudflare for SaaS)");
  const list = hs.items.filter(isObj);
  if (!list.length) return out.add("custom_hostname_min_tls", "skipped", "the zone has no custom hostnames");
  // A list cut at 40 pages leaves hostnames unseen: every result from it says so (format 3, complete: false).
  const read: Read = { method: "config-read", itemsRead: hs.items.length, pagesRead: hs.pages, complete: !hs.truncated };
  for (const h of list) {
    const set = isObj(h.ssl) && isObj(h.ssl.settings) ? h.ssl.settings.min_tls_version : undefined;
    const v = set ?? zoneMinTls;
    const pass = ["1.2", "1.3"].includes(String(v));
    out.add("custom_hostname_min_tls", v === undefined ? "skipped" : pass ? "pass" : "fail",
      v === undefined
        ? "no min_tls_version on the hostname and the zone's could not be read"
        : `min_tls_version is ${j(v)}${set === undefined ? " (not set on the hostname; the zone's value applies)" : ""}; 1.2 or 1.3 required${hs.truncated ? "; the hostname list stopped at 40 pages" : ""}`,
      `custom hostname ${String(h.hostname ?? h.id ?? "?")}`, { ...read, expected: "1.2 or 1.3", observed: v === undefined ? undefined : String(v) });
  }
}
