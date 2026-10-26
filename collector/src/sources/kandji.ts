// Iru Endpoint Management API (formerly Kandji; GET only), with a tenant API token whose permissions are the five GET
// endpoints below and nothing else. The vendor renamed Kandji to Iru; its API hosts are still *.api.kandji.io.
//
// Endpoints and fields, from the Iru Endpoint Management API reference (api-docs.kandji.io, which now redirects to
// api-docs.iru.com; Postman collection 15284493/TzCTZkBe, published 2026-05-15), read 2026-10-20:
//   API URL (Settings > Access): US https://<SubDomain>.api.kandji.io, EU https://<SubDomain>.api.eu.kandji.io.
//   Auth: Authorization: Bearer <api token>. Rate limit: 10,000 requests per hour per customer.
//   GET /api/v1/devices?platform=Mac&ordering=device_id&limit=300&offset=N                         List Devices
//        -> [ { device_id, serial_number, platform, os_version, last_check_in, mdm_enabled, ... } ]
//        limit has a hard upper bound of 300; offset is the starting record. last_check_in is the agent check-in
//        (the ordering parameter's own description). platform is one of Mac, iPad, iPhone, AppleTV, Android, Windows.
//   GET /api/v1/devices?platform=Mac&filevault_enabled=true|false&...       List Devices, filtered: "devices that
//        either have FileVault on (true) or off (false). This parameter only applies to macOS."
//   GET /api/v1/devices/{device_id}/status                                                    Get Device Status
//        -> { device_id, library_items: [ { item_id, name, status, type, ... } ], parameters: [ { item_id, name, status } ] }
//        library item status: AVAILABLE, ERROR (audit failure), EXCLUDED, INCOMPATIBLE, PASS, PENDING, failed (profile
//        failed to install), pending, success (profile installed); Get Device Library Items adds CACHED, CHANGE_PENDING,
//        DOWNLOADING, INSTALLING. Parameter status: ERROR (audit failure), INCOMPATIBLE, PASS, PENDING, REMEDIATED,
//        WARNING (muted alert).
//   GET /api/v1/prism/application_firewall?device_families=Mac&limit=300&cursor=      Prism, Application firewall
//        -> { data: [ { device_id, serial_number, status, block_all_incoming, stealth_mode, ... } ], cursor }
//   GET /api/v1/prism/gatekeeper_and_xprotect?...                                 Prism, Gatekeeper and XProtect
//        -> { data: [ { device_id, serial_number, gatekeeper_status, xprotect_version, ... } ], cursor }
//   GET /api/v1/prism/startup_settings?...                                                Prism, Startup settings
//        -> { data: [ { device_id, serial_number, sip, ssv, secure_boot_level, ... } ], cursor }
//   Prism pages by cursor: an empty cursor parameter asks for the first one, and each response's cursor is passed back
//   unchanged until it is null. limit has the same 300 upper bound.
// What a Prism category holds, from support.kandji.io/kb/prism (read 2026-10-20): Application Firewall is "the status
// of the built-in macOS application firewall"; Startup Settings holds "System Integrity Protection (SIP) status".
// Token permissions are granted per endpoint (path and method), as the audit log's api_token events show; the token
// is created under Settings > Access (support.kandji.io/kb/kandji-api, read 2026-10-20).
//
// Left out: the screen saver and lock settings. Prism's Desktop and Screensaver sample shows device fields only, no
// idle time or password setting, so no field could be confirmed. iPhone, iPad and Apple TV devices are not read.
//
// Personal data: a Mac is named by its device_id and serial. device_name, user (name, email, id), the Prism
// device__user_* and device__name fields, and every library item's log and last_audit_log are never read into a
// result.

import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter, enc, fetchRest, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, label, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const KANDJI_ENV = { url: "KANDJI_API_URL", token: "KANDJI_API_TOKEN" } as const;
export const KANDJI_CHECKS = ["filevault", "os_minimum", "last_checkin", "managed", "library_items", "parameters", "firewall", "gatekeeper", "sip"] as const;
type C = (typeof KANDJI_CHECKS)[number];

export const DEFAULTS = { checkinDays: 14, maxDevices: 1000 } as const;
export const PAGE = 300;
export const devicesPath = (offset: number, filevault?: boolean) =>
  `/v1/devices?platform=Mac${filevault === undefined ? "" : `&filevault_enabled=${filevault}`}&ordering=device_id&limit=${PAGE}&offset=${offset}`;
export const prismPath = (category: string, cursor = "") => `/v1/prism/${category}?device_families=Mac&limit=${PAGE}&cursor=${enc(cursor)}`;
export const statusPath = (id: string) => `/v1/devices/${enc(id)}/status`;

/** An Iru Endpoint Management API client from KANDJI_* variables, or what is missing. */
export function kandjiFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const url = env[KANDJI_ENV.url], token = env[KANDJI_ENV.token];
  if (!url || !token) return `${KANDJI_ENV.url} and ${KANDJI_ENV.token} are not both set`;
  let u: URL;
  try { u = new URL(url); } catch { return `${KANDJI_ENV.url} is not a URL`; }
  if (u.protocol !== "https:") return `${KANDJI_ENV.url} must be https`;
  return fetchRest({ base: `${u.origin}/api`, fetchFn, headers: async () => ({ authorization: `Bearer ${token}` }) });
}

type Listed = { items: Obj[]; truncated: boolean } | { error: HttpResponse };

/** List Devices pages (offset), up to `max` devices. */
async function listDevices(api: RestApi, max: number, filevault?: boolean): Promise<Listed> {
  const items: Obj[] = [];
  for (let offset = 0; ; offset += PAGE) {
    const r = await api.get(devicesPath(offset, filevault));
    if (!ok(r) || !Array.isArray(r.body)) return { error: r };
    const got = r.body.filter(isObj);
    items.push(...got);
    if (r.body.length < PAGE) return { items: items.slice(0, max), truncated: items.length > max };
    if (items.length >= max) return { items: items.slice(0, max), truncated: true };
  }
}

/** One Prism category's rows for Macs, by device_id, cursor-paged up to `max` rows. */
async function prism(api: RestApi, category: string, max: number): Promise<{ rows: Map<string, Obj> } | { error: HttpResponse }> {
  const rows = new Map<string, Obj>();
  let cursor = "";
  for (let page = 0; page <= Math.ceil(max / PAGE); page++) {
    const r = await api.get(prismPath(category, cursor));
    if (!ok(r) || !isObj(r.body) || !Array.isArray(r.body.data)) return { error: r };
    for (const row of r.body.data.filter(isObj)) { const id = str(row.device_id); if (id && !rows.has(id)) rows.set(id, row); }
    const next = str(r.body.cursor);
    if (!next || !r.body.data.length || rows.size >= max) break;
    cursor = next;
  }
  return { rows };
}

const FAIL_ITEM = new Set(["ERROR", "failed"]), PASS_ITEM = new Set(["PASS", "success"]);
const FAIL_PARAM = new Set(["ERROR", "WARNING"]), PASS_PARAM = new Set(["PASS", "REMEDIATED"]);
const names = (xs: Obj[]) => xs.slice(0, 5).map((x) => `${label(x.name, 60)} ${str(x.status)}`).join(", ") + (xs.length > 5 ? `, and ${xs.length - 5} more` : "");

function judge(out: Emitter<C>, check: C, list: unknown, fail: Set<string>, pass: Set<string>, what: string, res: string, where: string) {
  if (!Array.isArray(list)) { out.add(check, "skipped", `${what} not reported in the device status${where}`, res); return; }
  const items = list.filter(isObj);
  const bad = items.filter((x) => fail.has(String(x.status))), good = items.filter((x) => pass.has(String(x.status)));
  if (bad.length) out.add(check, "fail", `${bad.length} of ${items.length} ${what} not met: ${names(bad)}${where}`, res);
  else if (good.length) out.add(check, "pass", `${good.length} of ${items.length} ${what} met, none failing (the rest pending, excluded or not compatible)${where}`, res);
  else out.add(check, "skipped", `no ${what} has a pass or fail status yet (${items.length} listed)${where}`, res);
}

export async function kandjiChecks(api: RestApi, tenant: string, o: { checkinDays: number; maxDevices: number; minOs: Map<string, number[]> }, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("kandji", `kandji ${tenant}`);
  const got = await listDevices(api, o.maxDevices);
  if ("error" in got) { for (const c of KANDJI_CHECKS) out.skip(c, got.error, "device list"); return out.results; }
  if (!got.items.length) { out.skipAll(KANDJI_CHECKS, "Iru Endpoint Management lists no Mac; nothing to judge"); return out.results; }
  const cap = got.truncated ? `; only the first ${o.maxDevices} Macs read (--kandji-max-devices)` : "";
  const from = out.results.length;
  const floor = o.minOs.get("macos") ?? o.minOs.get("*");
  if (!floor) out.add("os_minimum", "skipped", `no minimum macOS version given (--kandji-min-os, e.g. 15.0); ${got.items.length} Mac(s) not judged`);

  // FileVault: which listed Macs fall under filevault_enabled=true and which under false.
  const fv = new Map<string, boolean>();
  let fvError: HttpResponse | undefined;
  for (const on of [true, false]) {
    const l = await listDevices(api, o.maxDevices, on);
    if ("error" in l) { fvError = l.error; break; }
    for (const d of l.items) { const id = str(d.device_id); if (id) fv.set(id, on); }
  }
  if (fvError) out.skip("filevault", fvError, "device list filtered by filevault_enabled");

  const PRISM: [C, string, string, string][] = [
    ["firewall", "application_firewall", "status", "Application firewall status"],
    ["gatekeeper", "gatekeeper_and_xprotect", "gatekeeper_status", "gatekeeper_status"],
    ["sip", "startup_settings", "sip", "System Integrity Protection (sip)"],
  ];
  const prisms = new Map<C, Map<string, Obj>>();
  for (const [check, category] of PRISM) {
    const p = await prism(api, category, o.maxDevices);
    if ("error" in p) out.skip(check, p.error, `Prism ${category}`);
    else prisms.set(check, p.rows);
  }

  let statusDenied: HttpResponse | undefined;
  for (const d of got.items) {
    const id = str(d.device_id) ?? "?";
    const res = deviceResource("kandji device", id, d.serial_number);
    const ver = str(d.os_version);
    const where = ` (macOS ${ver ?? "version not reported"})`;

    if (!fvError) {
      const on = fv.get(id);
      if (on === undefined) out.add("filevault", "skipped", `FileVault state not reported: in neither filevault_enabled=true nor false${where}${cap}`, res);
      else out.add("filevault", on ? "pass" : "fail", `listed under filevault_enabled=${on}${where}${cap}`, res);
    }

    if (floor) {
      const have = versionIn(ver);
      if (!have) out.add("os_minimum", "skipped", `os_version not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        out.add("os_minimum", okv ? "pass" : "fail", `macOS ${showVersion(have)} ${okv ? "meets" : "is below"} the --kandji-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    const age = ageDays(d.last_check_in, now);
    if (age === undefined) out.add("last_checkin", "skipped", `last_check_in not reported${where}`, res);
    else out.add("last_checkin", age <= o.checkinDays ? "pass" : "fail", `last agent check-in ${age} day(s) ago; at most ${o.checkinDays} allowed (--kandji-checkin-days)${where}`, res);

    if (typeof d.mdm_enabled === "boolean") out.add("managed", d.mdm_enabled ? "pass" : "fail", `mdm_enabled is ${d.mdm_enabled}${where}`, res);
    else out.add("managed", "skipped", `mdm_enabled not reported${where}`, res);

    for (const [check, , field, what] of PRISM) {
      const rows = prisms.get(check);
      if (!rows) continue;
      const row = rows.get(id);
      const v = row?.[field];
      if (typeof v === "boolean") out.add(check, v ? "pass" : "fail", `Prism ${what} is ${v}${where}`, res);
      else out.add(check, "skipped", `${row ? `Prism ${what} not reported` : "no Prism row for this Mac"}${where}`, res);
    }

    // Library items and parameters: one Get Device Status call per Mac. A 401 or 403 stops the calls.
    if (statusDenied) { out.skip("library_items", statusDenied, "device status", res); out.skip("parameters", statusDenied, "device status", res); continue; }
    const s = await api.get(statusPath(id));
    if (!ok(s) || !isObj(s.body)) {
      if (s.status === 401 || s.status === 403) statusDenied = s;
      out.skip("library_items", s, "device status", res); out.skip("parameters", s, "device status", res);
      continue;
    }
    judge(out, "library_items", s.body.library_items, FAIL_ITEM, PASS_ITEM, "library item(s)", res, where);
    judge(out, "parameters", s.body.parameters, FAIL_PARAM, PASS_PARAM, "parameter(s)", res, where);
  }
  stampRead(out.results, from, listRead(got));   // a capped list leaves devices unseen: format 3 says so
  return out.results;
}

export const kandji: Source = {
  name: "kandji",
  options: {
    "kandji-checkin-days": { type: "string", help: `days since a Mac's last agent check-in before last_checkin fails (default ${DEFAULTS.checkinDays})` },
    "kandji-min-os": { type: "string", help: "minimum macOS version for os_minimum, e.g. 15.0 (without it the check is skipped)" },
    "kandji-max-devices": { type: "string", help: `Macs read, at most (default ${DEFAULTS.maxDevices}); each costs one status call against the 10,000-an-hour limit` },
  },
  emits: KANDJI_CHECKS.map((c) => `kandji.${c}`),
  describe: () => "Iru Endpoint Management (formerly Kandji) tenant in KANDJI_API_URL (API token, GET permissions only)",
  async run(ctx: SourceContext) {
    const tenant = (() => { try { return new URL(ctx.env[KANDJI_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.kandji as RestApi | null | undefined;
    const built = given !== undefined ? given : kandjiFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("kandji", `kandji ${tenant}`);
      out.skipAll(KANDJI_CHECKS, typeof built === "string" ? built : `${KANDJI_ENV.token} is not set`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o = {
      checkinDays: posInt(ctx.opts["kandji-checkin-days"], DEFAULTS.checkinDays),
      maxDevices: posInt(ctx.opts["kandji-max-devices"], DEFAULTS.maxDevices),
      minOs: minOsOption(ctx.opts["kandji-min-os"]),
    };
    return redact(await kandjiChecks(api, tenant, o, ctx.now), [ctx.env[KANDJI_ENV.token]]);
  },
};
