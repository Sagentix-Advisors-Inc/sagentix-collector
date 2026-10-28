// NinjaOne (RMM and endpoint management) over the NinjaOne Public API v2 (GET only), as an API Services
// (machine-to-machine) client app whose only scope is Monitoring. The client-credentials token request is the only POST.
//
// Auth (NinjaOne Public API reference, app.ninjarmm.com/apidocs-beta/, articles read 2026-10-28):
//   /authorization/create-applications/machine-to-machine-apps: Configuration > Apps > API > Client App IDs > Add >
//     "API Services (machine-to-machine)". Scopes: "Monitoring: grants read-only access to monitoring data and
//     organization structure"; Management and Control modify devices or open remote access and are never asked for.
//   /authorization/flows/client-credentials-flow: POST /ws/oauth/token (form) grant_type=client_credentials, client_id,
//     client_secret, scope -> { access_token, expires_in (3600 in the example), scope, token_type: "Bearer" }.
//   Instances: app, us2, eu, ca and oc .ninjarmm.com each served this same reference (NinjaRMM-API-v2.yaml, 794,720
//     bytes, "NinjaOne Public API 2.0" version 2.0.9-draft) and answered /ws/oauth/token on 2026-10-28; the collector
//     takes the instance as NINJAONE_URL and refuses any other host.
//   The spec's global security requirement names the scopes monitoring, management and control and no operation below
//   overrides it, so that Monitoring alone answers these calls rests on the M2M page's wording: a 401 or 403 is skipped.
//
// Endpoints and fields (NinjaRMM-API-v2.yaml, read 2026-10-28):
//   GET /v2/devices?pageSize&after             List devices; `after` is "Last Node ID from previous page".
//        -> [ { id, nodeClass, approvalStatus (PENDING, STAGED, APPROVED, DECOMMISSIONED), offline, lastContact,
//               lastUpdate, ... } ]
//   GET /v2/queries/computer-systems?pageSize&cursor    -> { cursor: { name, offset, count, expires }, results: [ { deviceId, serialNumber, ... } ] }
//   GET /v2/queries/volumes?include=bl&pageSize&cursor  ("bl - BitLocker status")
//        -> results: [ { deviceId, driveLetter, bitLockerStatus: { conversionStatus (FULLY_DECRYPTED, FULLY_ENCRYPTED,
//             ENCRYPTION_IN_PROGRESS, DECRYPTION_IN_PROGRESS, ENCRYPTION_PAUSED, DECRYPTION_PAUSED, UNKNOWN),
//             protectionStatus (UNPROTECTED, PROTECTED, UNKNOWN, PENDING) } } ]
//   GET /v2/queries/operating-systems?pageSize&cursor   -> results: [ { deviceId, name, buildNumber, releaseId, needsReboot } ]
//   GET /v2/queries/device-health?pageSize&cursor       -> results: [ { deviceId, failedOSPatchesCount, pendingOSPatchesCount, ... } ]
//   The query reports answer with a named server-side cursor; the spec describes the `cursor` parameter only as
//   "Cursor name", so the collector passes the last answer's cursor.name back and stops at an empty page. lastContact is
//   a number whose unit the spec does not state: a value below 1e11 is read as epoch seconds, above as milliseconds.
//   The spec documents a 429 "Rate limit exceeded" answer; no request budget is published, and a 429 is retried after
//   its Retry-After.
//
// Left out, because no endpoint or field of the reference reports them: the firewall, the screen lock or passcode, and
// FileVault (the volume report's encryption block is BitLocker's, so Macs and Linux hosts are skipped for encryption).
//
// Personal data: a device is named by its NinjaOne id and the serial of the computer-systems report. displayName,
// systemName, dnsName, netbiosName, the assigned owner, userData, the logged-on user and tags are never read into a result.

import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, tokenRequest } from "./oauth.ts";
import { Emitter, enc, fetchRest, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep } from "./readonly_http.ts";
import { cmpVersion, deviceResource, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const NINJAONE_ENV = { url: "NINJAONE_URL", client: "NINJAONE_CLIENT_ID", secret: "NINJAONE_CLIENT_SECRET" } as const;
/** The instances whose hosts served the NinjaOne Public API reference on 2026-10-28. */
export const NINJAONE_HOSTS = ["app.ninjarmm.com", "us2.ninjarmm.com", "eu.ninjarmm.com", "ca.ninjarmm.com", "oc.ninjarmm.com"] as const;
export const NINJAONE_CHECKS = ["disk_encryption", "os_minimum", "os_patches", "last_contact", "approved"] as const;
type C = (typeof NINJAONE_CHECKS)[number];

export const DEFAULTS = { contactDays: 14, maxDevices: 5000, maxPendingPatches: 0 } as const;
export const PAGE = 500;
const WORKSTATIONS = new Set(["WINDOWS_WORKSTATION", "MAC", "LINUX_WORKSTATION"]);
const SERVERS = new Set(["WINDOWS_SERVER", "MAC_SERVER", "LINUX_SERVER"]);

export const devicesPath = (after?: number) => `/v2/devices?pageSize=${PAGE}${after === undefined ? "" : `&after=${after}`}`;
export const queryPath = (report: string, cursor?: string) =>
  `/v2/queries/${report}?${report === "volumes" ? "include=bl&" : ""}pageSize=${PAGE}${cursor ? `&cursor=${enc(cursor)}` : ""}`;

/** A NinjaOne Public API client from NINJAONE_* variables, or what is missing. */
export function ninjaoneFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const url = env[NINJAONE_ENV.url], client = env[NINJAONE_ENV.client], secret = env[NINJAONE_ENV.secret];
  if (!url || !client || !secret) return `${NINJAONE_ENV.url}, ${NINJAONE_ENV.client} and ${NINJAONE_ENV.secret} are not all set`;
  let u: URL;
  try { u = new URL(url); } catch { return `${NINJAONE_ENV.url} is not a URL`; }
  if (u.protocol !== "https:") return `${NINJAONE_ENV.url} must be https`;
  if (!(NINJAONE_HOSTS as readonly string[]).includes(u.host)) return `${NINJAONE_ENV.url} must be one of ${NINJAONE_HOSTS.map((h) => `https://${h}`).join(", ")}`;
  const form = { grant_type: "client_credentials", client_id: client, client_secret: secret, scope: "monitoring" };
  const token = cachedToken(() => tokenRequest(`${u.origin}/ws/oauth/token`, form, fetchFn));
  return fetchRest({ base: u.origin, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

type Listed = { items: Obj[]; truncated: boolean; pages: number } | { error: HttpResponse };

/** List devices, paged by the last node id, until an empty page or `max` devices. */
async function listDevices(api: RestApi, max: number): Promise<Listed> {
  const items: Obj[] = [];
  let after: number | undefined;
  for (let page = 0; ; page++) {
    const r = await api.get(devicesPath(after));
    if (!ok(r) || !Array.isArray(r.body)) return { error: r };
    const got = r.body.filter(isObj);
    items.push(...got);
    const last = got.length ? Number(got[got.length - 1].id) : NaN;
    if (!got.length || !Number.isFinite(last) || (after !== undefined && last <= after)) return { items: items.slice(0, max), truncated: items.length > max, pages: page + 1 };
    if (items.length >= max) return { items: items.slice(0, max), truncated: true, pages: page + 1 };
    after = last;
  }
}

/** One query report's rows by deviceId (several rows per device for volumes), following cursor.name until an empty page. */
async function report(api: RestApi, name: string, maxPages: number): Promise<{ rows: Map<number, Obj[]> } | { error: HttpResponse }> {
  const rows = new Map<number, Obj[]>();
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const r = await api.get(queryPath(name, cursor));
    if (!ok(r) || !isObj(r.body) || !Array.isArray(r.body.results)) return { error: r };
    const got = r.body.results.filter(isObj);
    for (const row of got) { const id = Number(row.deviceId); if (Number.isFinite(id)) rows.set(id, [...(rows.get(id) ?? []), row]); }
    const next = isObj(r.body.cursor) ? str(r.body.cursor.name) : undefined;
    if (!got.length || !next) break;
    cursor = next;
  }
  return { rows };
}

/** lastContact as a Date: epoch seconds below 1e11, milliseconds above (the spec gives no unit). */
export function contactDate(v: unknown): Date | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v) : NaN;
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return new Date(n < 1e11 ? n * 1000 : n);
}

const platformOf = (nodeClass: string) => (nodeClass.startsWith("WINDOWS") ? "windows" : nodeClass.startsWith("MAC") ? "macos" : nodeClass.startsWith("LINUX") ? "linux" : "other");

/** The OS version a floor is compared with: 10.0.<build> on Windows (buildNumber), else the dotted version in the name. */
export function osVersionOf(platform: string, os: Obj | undefined): number[] | undefined {
  if (!os) return undefined;
  if (platform === "windows") {
    const b = String(os.buildNumber ?? "").match(/^\d+/)?.[0];
    return b ? [10, 0, Number(b)] : undefined;
  }
  return versionIn(os.name);
}

export interface NinjaOneOptions { contactDays: number; maxDevices: number; maxPendingPatches: number; minOs: Map<string, number[]>; servers: boolean }

export async function ninjaoneChecks(api: RestApi, instance: string, o: NinjaOneOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("ninjaone", `ninjaone ${instance}`);
  const got = await listDevices(api, o.maxDevices);
  if ("error" in got) { for (const c of NINJAONE_CHECKS) out.skip(c, got.error, "device list"); return out.results; }
  const classes = o.servers ? new Set([...WORKSTATIONS, ...SERVERS]) : WORKSTATIONS;
  const devices = got.items.filter((d) => classes.has(String(d.nodeClass)));
  if (!devices.length) {
    out.skipAll(NINJAONE_CHECKS, `NinjaOne lists no ${o.servers ? "workstation or server" : "workstation (Windows, Mac or Linux)"} among ${got.items.length} device(s); nothing to judge`);
    return out.results;
  }
  const cap = got.truncated ? `; only the first ${o.maxDevices} devices read (--ninjaone-max-devices)` : "";
  const maxPages = Math.ceil(o.maxDevices / PAGE) * 4 + 4;   // volumes give several rows per device

  const reports = new Map<string, Map<number, Obj[]>>();
  const failed = new Map<string, HttpResponse>();
  for (const name of ["computer-systems", "volumes", "operating-systems", "device-health"]) {
    const r = await report(api, name, maxPages);
    if ("error" in r) failed.set(name, r.error); else reports.set(name, r.rows);
  }
  const floorsGiven = o.minOs.size > 0;
  if (!floorsGiven) out.add("os_minimum", "skipped", `no minimum OS version given (--ninjaone-min-os, e.g. windows=10.0.26100 or macos=15.0); ${devices.length} device(s) not judged`);
  for (const [check, name] of [["disk_encryption", "volumes"], ["os_minimum", "operating-systems"], ["os_patches", "device-health"]] as const) {
    const e = failed.get(name);
    if (e && (check !== "os_minimum" || floorsGiven)) out.skip(check, e, `query report ${name}`);
  }

  const from = out.results.length;
  for (const d of devices) {
    const id = Number(d.id);
    const nodeClass = String(d.nodeClass);
    const platform = platformOf(nodeClass);
    const serial = reports.get("computer-systems")?.get(id)?.[0]?.serialNumber;
    const res = deviceResource("ninjaone device", d.id, serial);
    const os = reports.get("operating-systems")?.get(id)?.[0];
    const where = ` (${nodeClass}${os?.buildNumber ? `, build ${String(os.buildNumber).slice(0, 30)}` : ""})`;

    // Disk encryption: BitLocker on the C: volume of a Windows device.
    const vols = reports.get("volumes");
    if (vols) {
      if (platform !== "windows") out.add("disk_encryption", "skipped", `NinjaOne reports BitLocker only; no FileVault or LUKS field for ${nodeClass}${where}`, res);
      else {
        const c = (vols.get(id) ?? []).find((v) => /^c:?\\?$/i.test(String(v.driveLetter ?? "").trim()));
        const bl = c && isObj(c.bitLockerStatus) ? c.bitLockerStatus : undefined;
        const conv = str(bl?.conversionStatus), prot = str(bl?.protectionStatus);
        if (!c) out.add("disk_encryption", "skipped", `no C: volume in the volumes report${where}`, res);
        else if (!bl || !conv || conv === "UNKNOWN") out.add("disk_encryption", "skipped", `C: has no BitLocker conversionStatus (${conv ?? "not reported"})${where}`, res);
        else {
          const pass = conv === "FULLY_ENCRYPTED" && prot === "PROTECTED";
          out.add("disk_encryption", pass ? "pass" : "fail", `C: BitLocker conversionStatus ${conv}, protectionStatus ${prot ?? "not reported"}; FULLY_ENCRYPTED and PROTECTED required${where}${cap}`, res);
        }
      }
    }

    // Minimum OS version.
    if (floorsGiven && reports.has("operating-systems")) {
      const floor = o.minOs.get(platform) ?? o.minOs.get("*");
      const have = osVersionOf(platform, os);
      if (!floor) out.add("os_minimum", "skipped", `no --ninjaone-min-os floor for ${platform}${where}`, res);
      else if (!have) out.add("os_minimum", "skipped", `${platform === "windows" ? "buildNumber" : "a version in the OS name"} not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        out.add("os_minimum", okv ? "pass" : "fail", `${platform} ${showVersion(have)} ${okv ? "meets" : "is below"} the --ninjaone-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    // OS patches: failed and pending counts from the device health report.
    const health = reports.get("device-health");
    if (health) {
      const h = health.get(id)?.[0];
      const failedN = h?.failedOSPatchesCount, pendingN = h?.pendingOSPatchesCount;
      if (typeof failedN !== "number" || typeof pendingN !== "number") out.add("os_patches", "skipped", `${h ? "failedOSPatchesCount or pendingOSPatchesCount not reported" : "no device health row"}${where}`, res);
      else {
        const pass = failedN === 0 && pendingN <= o.maxPendingPatches;
        out.add("os_patches", pass ? "pass" : "fail", `${failedN} failed and ${pendingN} pending OS patch(es); 0 failed and at most ${o.maxPendingPatches} pending allowed (--ninjaone-max-pending-patches)${where}`, res);
      }
    }

    const seen = contactDate(d.lastContact);
    if (!seen) out.add("last_contact", "skipped", `lastContact not reported${where}`, res);
    else {
      const age = Math.floor((now.getTime() - seen.getTime()) / 86_400_000);
      out.add("last_contact", age <= o.contactDays ? "pass" : "fail", `last contact ${age} day(s) ago; at most ${o.contactDays} allowed (--ninjaone-contact-days)${where}`, res);
    }

    const st = str(d.approvalStatus);
    if (st === "APPROVED") out.add("approved", "pass", `approvalStatus is APPROVED${where}`, res);
    else if (st === "PENDING" || st === "STAGED") out.add("approved", "fail", `approvalStatus is ${st}; APPROVED required${where}`, res);
    else out.add("approved", "skipped", `approvalStatus is ${st ?? "not reported"}${st === "DECOMMISSIONED" ? " (no longer managed, not judged)" : ""}${where}`, res);
  }
  const read = { method: "config-read" as const, itemsRead: devices.length, pagesRead: got.pages, complete: !got.truncated };
  for (let i = from; i < out.results.length; i++) if (out.results[i].method === undefined) Object.assign(out.results[i], read);
  return out.results;
}

export const ninjaone: Source = {
  name: "ninjaone",
  options: {
    "ninjaone-contact-days": { type: "string", help: `days since a device's last contact before last_contact fails (default ${DEFAULTS.contactDays})` },
    "ninjaone-min-os": { type: "string", multiple: true, help: "<platform>=<version> floor for os_minimum, platform windows, macos or linux, e.g. windows=10.0.26100 (repeatable; without it the check is skipped)" },
    "ninjaone-max-pending-patches": { type: "string", help: `pending OS patches a device may have before os_patches fails (default ${DEFAULTS.maxPendingPatches})` },
    "ninjaone-max-devices": { type: "string", help: `devices read, at most (default ${DEFAULTS.maxDevices})` },
    "ninjaone-include-servers": { type: "boolean", help: "also judge Windows, Mac and Linux servers (default: workstations only)" },
  },
  emits: NINJAONE_CHECKS.map((c) => `ninjaone.${c}`),
  describe: () => "NinjaOne instance in NINJAONE_URL (Public API v2, client credentials, Monitoring scope only)",
  async run(ctx: SourceContext) {
    const instance = (() => { try { return new URL(ctx.env[NINJAONE_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.ninjaone as RestApi | null | undefined;
    const built = given !== undefined ? given : ninjaoneFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("ninjaone", `ninjaone ${instance}`);
      out.skipAll(NINJAONE_CHECKS, typeof built === "string" ? built : `${NINJAONE_ENV.secret} is not set`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const pending = Number(ctx.opts["ninjaone-max-pending-patches"]);
    const o: NinjaOneOptions = {
      contactDays: posInt(ctx.opts["ninjaone-contact-days"], DEFAULTS.contactDays),
      maxDevices: posInt(ctx.opts["ninjaone-max-devices"], DEFAULTS.maxDevices),
      maxPendingPatches: Number.isInteger(pending) && pending >= 0 && ctx.opts["ninjaone-max-pending-patches"] !== undefined ? pending : DEFAULTS.maxPendingPatches,
      minOs: minOsOption(ctx.opts["ninjaone-min-os"]),
      servers: ctx.opts["ninjaone-include-servers"] === true,
    };
    return redact(await ninjaoneChecks(api, instance, o, ctx.now), [ctx.env[NINJAONE_ENV.secret]]);
  },
};
