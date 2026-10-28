// Ivanti Neurons for MDM (formerly MobileIron Cloud), read through its Customer Integration API with GET only, as a
// dedicated admin user that holds the Device Read Only role and nothing more. No token request is made: the API
// takes HTTP Basic authentication on every call.
//
// Pages read 2026-10-28 (help.ivanti.com, through r.jina.ai because the Mac's direct requests met a Cloudflare block):
//   Customer Integration API Guide, MDMCustomerIntegrationAPIGuide/ (revision history last entry 2026-10-15):
//     "MobileIron Cloud API Basics.htm": Basic Authentication on every call; when the admin portal requires a password
//       and PIN (MFA), Basic does not work and Token-Based Authentication must be used. Rows: at most 500 per page
//       (rows=, start=); device searches page efficiently with sortFields[0].name=id&sortFields[0].order=ASC and
//       searchAfterValues[0]=<last id>, and start must not be used at 10,000 or more. 401 means credentials missing or
//       wrong, 403 "a resource that does not belong to you". The device space id ("dmPartitionId", spaces were once
//       called partitions) is needed for device calls; the default one is defaultDmPartitionId in Get Tenant Metadata.
//       A GDPR profile on the API user obfuscates fields such as the serial number.
//     default.htm: integrations must handle 429 (rate limited) and 503 and retry later. No numeric limit is published.
//     "Device API Calls.htm": Get Device Details, GET /api/v1/device/{id} -> { errors, result: { id, platformType,
//       platformVersion, lastCheckin ("Last client checkin"), registrationState, serialNumber, complianceState,
//       passcodeCompliant (iOS only, null elsewhere), passcodeCompliantWithProfiles ("compliant with EMM profiles",
//       iOS and Android only), osxFdeEnabled, osxFirewallSettings, osxSystemIntegrityProtectionEnabled, ... } };
//       "Get Device without Signature Parameter", GET /api/v1/device -> { errors, result: { searchResults: [ ... ] } }
//       with bitLockerEncryptionStatus and an epoch-millisecond lastCheckin in its example. Both say "This call
//       requires Tenant Admin credentials"; "Key Concepts.htm" defines Tenant Admin as the API role "used for all other
//       API calls" (System Admin being for tenant creation and licensing).
//     "Token-Based Authentication.htm": POST /oauth2/token with an OIDC client's id and secret in a Basic header. Not
//       used here: oauth.ts sends the client secret in the form body only.
//   OpenAPI file https://help.ivanti.com/mi/help/en_us/CLD/8x/api/test.json (info.version NA2), linked from
//     "Test the APIs.htm": GET /api/v1/device (dmPartitionId required; rows, start, sortFields[0].name/order,
//     searchAfterValues), GET /api/v1/device/{id} (DeviceDetailView), GET /api/v1/metadata/tenant ("safe for
//     consumption by any authenticated user"; defaultDmPartitionId). Types: complianceState, osxFdeEnabled,
//     osxSystemIntegrityProtectionEnabled, passcodeCompliant(WithProfiles) boolean; osxFirewallSettings.firewallEnabled
//     boolean; bitLockerEncryptionStatus NOT_ENCRYPTED | FULLY_ENCRYPTED | PARTIALLY_ENCRYPTED | UNKNOWN; platformType
//     ANDROID | BLACKBERRY | IOS | OSX | WINDOWS_PHONE | CHROME_OS | UNKNOWN; registrationState ACTIVE, RETIRE_*, WIPE_*,
//     PROVISIONING, RELINQ_*; lastCheckin "date-time" (the guide's example is epoch milliseconds, so both are read).
//   Administrator Guide 128 (help.ivanti.com/mi/help/en_US/CLD/admin/ivanti/128/all/en-us/): User_Roles.htm, "Device
//     Read Only: Allows an administrator to view device groups, configurations and policies" (space-specific);
//     Assigning_Roles.htm (Users > Users > Actions > Assign Roles); Roles_Management.htm (a custom space-specific role
//     may hold only the "View Device" permission).
//
// [Unverified] The guide does not say which admin role GET /api/v1/device and GET /api/v1/device/{id} accept beyond
// "Tenant Admin credentials"; it names Device Read Only only for other device GETs (custom attributes, certificates).
// The collector only ever sends GET, so a role that falls short gives HTTP 403, reported as skipped.
// [Unverified] The platformType a Windows 10/11 desktop reports is not in the enum, so Windows encryption is read from
// bitLockerEncryptionStatus wherever a device reports one, whatever its platformType.
//
// Left out: Windows firewall (the example's firewallStatus -1 has no documented meaning), pending OS updates
// (availableOSUpdates is a bare string list with no description), and the idle time before lock (no field).
//
// Personal data: a device is named by its Ivanti id and serial number. deviceName, displayName, firstName, lastName,
// uid, emailAddress, phone numbers, IMEI, ICCID, location and IP addresses are never read into a result.

import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter, enc, fetchRest, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const IVANTI_MDM_ENV = { url: "IVANTI_MDM_URL", user: "IVANTI_MDM_USERNAME", password: "IVANTI_MDM_PASSWORD" } as const;
export const IVANTI_MDM_CHECKS = ["device_compliant", "disk_encryption", "os_minimum", "last_checkin", "passcode_compliant", "firewall", "system_integrity"] as const;
type C = (typeof IVANTI_MDM_CHECKS)[number];

export const DEFAULTS = { checkinDays: 14, maxDevices: 5000 } as const;
/** The documented ceiling for rows. */
export const PAGE = 500;
const SORT = "sortFields%5B0%5D.name=id&sortFields%5B0%5D.order=ASC";
export const metadataPath = "/metadata/tenant";
export const devicesPath = (space: string, after?: string) =>
  `/device?q=&rows=${PAGE}&dmPartitionId=${enc(space)}&${SORT}&nav=true${after === undefined ? "" : `&searchAfterValues%5B0%5D=${enc(after)}`}`;
export const detailPath = (id: string) => `/device/${enc(id)}`;

/** An Ivanti Neurons for MDM API client from IVANTI_MDM_* variables, or what is missing. */
export function ivantiMdmFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const url = env[IVANTI_MDM_ENV.url], user = env[IVANTI_MDM_ENV.user], password = env[IVANTI_MDM_ENV.password];
  if (!url || !user || !password) return `${IVANTI_MDM_ENV.url}, ${IVANTI_MDM_ENV.user} and ${IVANTI_MDM_ENV.password} are not all set`;
  let u: URL;
  try { u = new URL(url); } catch { return `${IVANTI_MDM_ENV.url} is not a URL`; }
  if (u.protocol !== "https:") return `${IVANTI_MDM_ENV.url} must be https`;
  const basic = Buffer.from(`${user}:${password}`).toString("base64");
  return fetchRest({ base: `${u.origin}/api/v1`, fetchFn, headers: async () => ({ authorization: `Basic ${basic}` }) });
}

/** The guide wraps answers in { errors, result }; the OpenAPI file shows them bare. Either is read. */
const unwrap = (b: unknown): Obj | undefined => (isObj(b) ? (isObj(b.result) ? (b.result as Obj) : b) : undefined);

type Listed = { items: Obj[]; truncated: boolean; pages: number } | { error: HttpResponse };

/** Every device in the space, sorted by id and paged with searchAfterValues, up to `max`. */
async function listDevices(api: RestApi, space: string, max: number): Promise<Listed> {
  const items: Obj[] = [];
  let after: string | undefined;
  for (let page = 0; ; page++) {
    const r = await api.get(devicesPath(space, after));
    const body = ok(r) ? unwrap(r.body) : undefined;
    const got = body && Array.isArray(body.searchResults) ? body.searchResults.filter(isObj) : undefined;
    if (!got) return { error: r };
    items.push(...got);
    const total = Number(body!.totalCount);
    const last = got.length ? got[got.length - 1].id : undefined;
    const done = !got.length || last === undefined || (Number.isFinite(total) ? items.length >= total : got.length < PAGE);
    if (items.length >= max) return { items: items.slice(0, max), truncated: items.length > max || !done, pages: page + 1 };
    if (done) return { items, truncated: false, pages: page + 1 };
    if (page >= Math.ceil(max / PAGE) + 1) return { items, truncated: true, pages: page + 1 };
    after = String(last);
  }
}

/** lastCheckin as epoch milliseconds (the guide's example) or an ISO date-time (the OpenAPI type), as ISO. */
function checkinIso(v: unknown): string | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d{10,}$/.test(v) ? Number(v) : NaN;
  if (Number.isFinite(n)) return new Date(n).toISOString();
  return typeof v === "string" ? v : undefined;
}

const BITLOCKER_FAIL = new Set(["NOT_ENCRYPTED", "PARTIALLY_ENCRYPTED"]);

export interface IvantiMdmOptions { space?: string; checkinDays: number; maxDevices: number; minOs: Map<string, number[]> }

export async function ivantiMdmChecks(api: RestApi, host: string, o: IvantiMdmOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("ivanti_mdm", `ivanti_mdm ${host}`);

  // The device space: --ivanti-mdm-space-id, else the tenant's default from Get Tenant Metadata.
  let space = o.space;
  if (!space) {
    const m = await api.get(metadataPath);
    const id = ok(m) ? unwrap(m.body)?.defaultDmPartitionId : undefined;
    if (id === undefined || id === null || id === "") {
      if (!ok(m)) for (const c of IVANTI_MDM_CHECKS) out.skip(c, m, "tenant metadata (default device space)");
      else out.skipAll(IVANTI_MDM_CHECKS, "tenant metadata gives no defaultDmPartitionId; set --ivanti-mdm-space-id");
      return out.results;
    }
    space = String(id);
  }
  const tenant = `ivanti_mdm ${host} space ${space}`;
  const tout = new Emitter<C>("ivanti_mdm", tenant);

  const got = await listDevices(api, space, o.maxDevices);
  if ("error" in got) { for (const c of IVANTI_MDM_CHECKS) tout.skip(c, got.error, "device search"); return tout.results; }
  const active = got.items.filter((d) => d.registrationState === undefined || d.registrationState === null || d.registrationState === "ACTIVE");
  const inactive = got.items.length - active.length;
  const note = inactive ? `; ${inactive} retired, wiped or pending device(s) not judged` : "";
  if (!active.length) { tout.skipAll(IVANTI_MDM_CHECKS, `the device space lists no active device${note}; nothing to judge`); return tout.results; }
  const cap = got.truncated ? `; only the first ${o.maxDevices} devices read (--ivanti-mdm-max-devices)` : "";
  const from = tout.results.length;
  if (!o.minOs.size) tout.add("os_minimum", "skipped", `no minimum OS version given (--ivanti-mdm-min-os, e.g. osx=15.0 or ios=18.0); ${active.length} device(s) not judged`);

  const isMac = (d: Obj) => d.platformType === "OSX";
  const macs = active.filter(isMac).length;
  if (!macs) for (const c of ["firewall", "system_integrity"] as const) tout.add(c, "skipped", `no active macOS (platformType OSX) device; the API documents ${c === "firewall" ? "firewall settings" : "System Integrity Protection"} for macOS only${note}`);
  const mobiles = active.filter((d) => d.platformType === "IOS" || d.platformType === "ANDROID").length;
  if (!mobiles) tout.add("passcode_compliant", "skipped", `no active iOS or Android device; passcodeCompliantWithProfiles is documented for those platforms only${note}`);
  let encJudged = 0;

  let detailDenied: HttpResponse | undefined;
  for (const d of active) {
    const id = String(d.id ?? "?");
    const res = deviceResource("ivanti device", id, d.serialNumber);
    const plat = str(d.platformType) ?? "UNKNOWN";
    const ver = str(d.platformVersion);
    const where = ` (${plat} ${ver ?? "version not reported"})`;

    if (typeof d.complianceState === "boolean") tout.add("device_compliant", d.complianceState ? "pass" : "fail", `complianceState is ${d.complianceState}${where}${cap}${note}`, res);
    else tout.add("device_compliant", "skipped", `complianceState not reported${where}${note}`, res);

    const age = ageDays(checkinIso(d.lastCheckin), now);
    if (age === undefined) tout.add("last_checkin", "skipped", `lastCheckin not reported${where}`, res);
    else tout.add("last_checkin", age <= o.checkinDays ? "pass" : "fail", `last client check-in ${age} day(s) ago; at most ${o.checkinDays} allowed (--ivanti-mdm-checkin-days)${where}`, res);

    if (o.minOs.size) {
      const key = plat.toLowerCase();
      const floor = o.minOs.get(key) ?? (key === "osx" ? o.minOs.get("macos") : undefined) ?? o.minOs.get("*");
      const have = versionIn(ver);
      if (!floor) tout.add("os_minimum", "skipped", `--ivanti-mdm-min-os names no floor for platformType ${plat}${where}`, res);
      else if (!have) tout.add("os_minimum", "skipped", `platformVersion not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        tout.add("os_minimum", okv ? "pass" : "fail", `platformVersion ${showVersion(have)} ${okv ? "meets" : "is below"} the --ivanti-mdm-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    if (plat === "IOS" || plat === "ANDROID") {
      const p = typeof d.passcodeCompliantWithProfiles === "boolean" ? ["passcodeCompliantWithProfiles", d.passcodeCompliantWithProfiles] as const
        : typeof d.passcodeCompliant === "boolean" ? ["passcodeCompliant", d.passcodeCompliant] as const : undefined;
      if (p) tout.add("passcode_compliant", p[1] ? "pass" : "fail", `${p[0]} is ${p[1]}${where}`, res);
      else tout.add("passcode_compliant", "skipped", `neither passcodeCompliantWithProfiles nor passcodeCompliant reported${where}`, res);
    }

    // Not a Mac: BitLocker from the search row, wherever a device reports it.
    if (!isMac(d)) {
      const bl = str(d.bitLockerEncryptionStatus);
      if (bl) {
        encJudged++;
        if (bl === "UNKNOWN") tout.add("disk_encryption", "skipped", `bitLockerEncryptionStatus is UNKNOWN${where}`, res);
        else tout.add("disk_encryption", bl === "FULLY_ENCRYPTED" ? "pass" : BITLOCKER_FAIL.has(bl) ? "fail" : "skipped", `bitLockerEncryptionStatus is ${bl}; FULLY_ENCRYPTED required${where}`, res);
      }
      continue;
    }

    // macOS: FileVault, firewall and SIP come from Get Device Details, one call per Mac. A 401 or 403 stops the calls.
    encJudged++;
    if (detailDenied) { for (const c of ["disk_encryption", "firewall", "system_integrity"] as const) tout.skip(c, detailDenied, "device details", res); continue; }
    const r = await api.get(detailPath(id));
    const det = ok(r) ? unwrap(r.body) : undefined;
    if (!det) {
      if (r.status === 401 || r.status === 403) detailDenied = r;
      for (const c of ["disk_encryption", "firewall", "system_integrity"] as const) tout.skip(c, r, "device details", res);
      continue;
    }
    if (typeof det.osxFdeEnabled === "boolean") tout.add("disk_encryption", det.osxFdeEnabled ? "pass" : "fail", `osxFdeEnabled (FileVault) is ${det.osxFdeEnabled}${where}`, res);
    else tout.add("disk_encryption", "skipped", `osxFdeEnabled not reported${where}`, res);
    const fw = isObj(det.osxFirewallSettings) ? det.osxFirewallSettings.firewallEnabled : undefined;
    if (typeof fw === "boolean") tout.add("firewall", fw ? "pass" : "fail", `osxFirewallSettings.firewallEnabled is ${fw}${where}`, res);
    else tout.add("firewall", "skipped", `osxFirewallSettings.firewallEnabled not reported${where}`, res);
    const sip = det.osxSystemIntegrityProtectionEnabled;
    if (typeof sip === "boolean") tout.add("system_integrity", sip ? "pass" : "fail", `osxSystemIntegrityProtectionEnabled is ${sip}${where}`, res);
    else tout.add("system_integrity", "skipped", `osxSystemIntegrityProtectionEnabled not reported${where}`, res);
  }
  if (!encJudged) tout.add("disk_encryption", "skipped", `no active device reports an encryption field the API documents (osxFdeEnabled for macOS, bitLockerEncryptionStatus for BitLocker); iOS and Android expose none${note}`);
  stampRead(tout.results, from, listRead(got));   // a capped list leaves devices unseen: format 3 says so
  return tout.results;
}

export const ivanti_mdm: Source = {
  name: "ivanti_mdm",
  options: {
    "ivanti-mdm-space-id": { type: "string", help: "device space id (dmPartitionId) to read (default: the tenant's defaultDmPartitionId)" },
    "ivanti-mdm-min-os": { type: "string", multiple: true, help: "<platformType>=<version> floor, e.g. osx=15.0, ios=18.0, android=14 (repeatable; without it os_minimum is skipped)" },
    "ivanti-mdm-checkin-days": { type: "string", help: `days since a device's last client check-in before last_checkin fails (default ${DEFAULTS.checkinDays})` },
    "ivanti-mdm-max-devices": { type: "string", help: `devices read, at most (default ${DEFAULTS.maxDevices}); each Mac costs one Get Device Details call` },
  },
  emits: IVANTI_MDM_CHECKS.map((c) => `ivanti_mdm.${c}`),
  describe: () => "Ivanti Neurons for MDM (formerly MobileIron Cloud) tenant in IVANTI_MDM_URL (Customer Integration API, GET only, Device Read Only admin)",
  async run(ctx: SourceContext) {
    const host = (() => { try { return new URL(ctx.env[IVANTI_MDM_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.ivanti_mdm as RestApi | null | undefined;
    const built = given !== undefined ? given : ivantiMdmFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("ivanti_mdm", `ivanti_mdm ${host}`);
      out.skipAll(IVANTI_MDM_CHECKS, typeof built === "string" ? built : `${IVANTI_MDM_ENV.password} is not set`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const space = typeof ctx.opts["ivanti-mdm-space-id"] === "string" && /^\d+$/.test(ctx.opts["ivanti-mdm-space-id"] as string) ? ctx.opts["ivanti-mdm-space-id"] as string : undefined;
    const o: IvantiMdmOptions = {
      space,
      checkinDays: posInt(ctx.opts["ivanti-mdm-checkin-days"], DEFAULTS.checkinDays),
      maxDevices: posInt(ctx.opts["ivanti-mdm-max-devices"], DEFAULTS.maxDevices),
      minOs: minOsOption(ctx.opts["ivanti-mdm-min-os"]),
    };
    const user = ctx.env[IVANTI_MDM_ENV.user], password = ctx.env[IVANTI_MDM_ENV.password];
    const basic = user && password ? Buffer.from(`${user}:${password}`).toString("base64") : undefined;
    return redact(await ivantiMdmChecks(api, host, o, ctx.now), [password, basic]);
  },
};
