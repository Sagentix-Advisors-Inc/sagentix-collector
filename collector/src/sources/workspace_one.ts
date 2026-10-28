// Omnissa Workspace ONE UEM (formerly VMware Workspace ONE, earlier AirWatch) over its REST API, GET only, as an
// OAuth client whose role holds the single REST permission "REST API Devices Read". The client-credentials token
// request is the only POST.
//
// Auth, regions and the role, from "Using UEM Functionality With a REST API" (docs.omnissa.com/WorkspaceONE-UEM-Console-
// Basics-VSaaS/UsingUEMFunctionalityWithRESTAPI, page dated 2026-08-25), read 2026-10-28:
//   OAuth 2.0 is "supported only in SaaS environments". Token URLs by data centre: United States and Canada
//   https://na.uemauth.workspaceone.com/connect/token; United Kingdom and Germany https://emea.uemauth.workspaceone.com/
//   connect/token; India, Japan, Singapore, Australia and Hong Kong https://apac.uemauth.workspaceone.com/connect/token;
//   UAT https://uat.uemauth.workspaceone.com/connect/token.
//   The client is made under Groups & Settings > Configurations > OAuth Client Management (Name, Description,
//   Organization Group, Role); the secret is shown once. grant_type=client_credentials, form-encoded.
//   Role permissions: REST > Devices > "REST API Devices Read", "Enables access to all READ only APIs in Devices
//   collection", marked Read Only. No other permission is needed.
// The request shapes, from the Omnissa Developer Portal "Getting started with the Bruno collection"
// (developer.omnissa.com/workspace-one-uem-apis/bruno/), read 2026-10-28: the REST API host comes from Groups and
// Settings > All Settings > System > Advanced > API > REST API (e.g. as1234.awmdm.com); the token is sent as
// "Authorization: Bearer <access_token>" with "Accept: application/json;version=<n>"; the token request sends
// client_id and client_secret in the form body.
// Endpoints and fields, from the OpenAPI documents of release 2607 (developer.omnissa.com/workspace-one-uem-apis/
// versions/2607/mdmv3.json and mdmv1.json), read 2026-10-28:
//   GET /api/mdm/devices/search?page=N&page_size=500     MDM API V3, Accept application/json;version=3
//       "maximum pagesize limit of 500"; page is "0 based"; answer { devices: [...], page, page_size, total }.
//       Device fields used: Uuid, Id.Value, serial_number, device_type (APPLE, ANDROID, WINDOWS_PC, APPLE_OS_X,
//       CHROME_OS, LINUX ...), operating_system, last_seen ("Time the device last reported any status"),
//       enrollment_status (ENROLLED, RETIRED, UNENROLLED ...), compliance_status (COMPLIANT, NOT_COMPLIANT, BLOCKED,
//       QUARANTINED, PENDING_COMPLIANCE_CHECK, NOT_AVAILABLE, UNKNOWN ...), compromised_status (boolean).
//   GET /api/mdm/devices/{uuid}/security/encryption-status MDM API V1, Accept application/json;version=1
//       -> { encryption_status: boolean } "Encryption status of an enrolled device." One call per device.
// Left out, with the reason:
//   Firewall: no device firewall field or endpoint in any of the four MDM documents.
//   Screen lock / passcode: the only per-device passcode fields (IsPasscodePresent, IsPasscodeCompliant) come from
//   GET /devices/{id}/security, whose same answer carries PersonalRecoveryKey, StaticRecoveryKey and UnlockPin. The
//   collector does not request an answer that holds recovery keys, so screen lock is not checked here; a passcode
//   rule set in a compliance policy still shows in compliant.
//   Rate limits: none is stated on the pages read; a 429 is retried after its Retry-After (readonly_http.ts).
//   On-premises consoles: OAuth is SaaS-only on the page above, so an on-premises UEM is not supported.
//
// Personal data: a device is named by its Uuid and serial. Device names, enrollment user names and email
// addresses, phone numbers, IMEI, MAC addresses and Wi-Fi SSIDs come back in the search answer and are never read
// into a result.

import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, tokenRequest } from "./oauth.ts";
import { Emitter, enc, fetchRest, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const WS1_ENV = { url: "WS1_API_URL", tokenUrl: "WS1_TOKEN_URL", client: "WS1_CLIENT_ID", secret: "WS1_CLIENT_SECRET" } as const;
export const WS1_CHECKS = ["disk_encryption", "os_minimum", "last_seen", "enrolled", "compliant", "compromised"] as const;
type C = (typeof WS1_CHECKS)[number];

export const DEFAULTS = { seenDays: 14, maxDevices: 2000 } as const;
export const PAGE = 500;
/** The four documented token hosts: na, emea, apac and uat. */
export const TOKEN_HOSTS = ["na", "emea", "apac", "uat"].map((r) => `${r}.uemauth.workspaceone.com`);
export const searchPath = (page: number) => `/mdm/devices/search?page=${page}&page_size=${PAGE}`;
export const encryptionPath = (uuid: string) => `/mdm/devices/${enc(uuid)}/security/encryption-status`;

/** device_type → the names --workspace-one-min-os accepts for it (the enum value itself always works). */
const PLATFORM_ALIASES: Record<string, string[]> = {
  APPLE_OS_X: ["macos"], WINDOWS_PC: ["windows"], APPLE: ["ios"], ANDROID: ["android"], CHROME_OS: ["chromeos"], CHROME_BOOK: ["chromeos"], LINUX: ["linux"],
};
/** Enrollment states of a device no longer in service: reported once as enrolled skipped, and not judged further. */
const GONE = new Set(["RETIRED", "UNENROLLED", "UNENROLLED_BY_FEEDBACK_SERVICE", "DEVICE_NOT_FOUND", "ENTERPRISE_WIPE_PENDING", "DEVICE_WIPE_PENDING", "WIPE_INITIATED", "BLACKLISTED"]);
const NOT_YET = new Set(["DISCOVERED", "REGISTERED", "ENROLLMENT_IN_PROGRESS", "PENDING_AGENT", "APP_CATALOG_ONLY"]);
const BAD_COMPLIANCE = new Set(["NOT_COMPLIANT", "BLOCKED", "QUARANTINED"]);

export interface Ws1Clients { v3: RestApi; v1: RestApi }

/** Workspace ONE UEM clients (search on version 3, encryption on version 1) from WS1_* variables, or what is missing. */
export function ws1FromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): Ws1Clients | string {
  const url = env[WS1_ENV.url], tokenUrl = env[WS1_ENV.tokenUrl], client = env[WS1_ENV.client], secret = env[WS1_ENV.secret];
  if (!url || !tokenUrl || !client || !secret) return `${WS1_ENV.url}, ${WS1_ENV.tokenUrl}, ${WS1_ENV.client} and ${WS1_ENV.secret} are not all set`;
  let u: URL, t: URL;
  try { u = new URL(url); } catch { return `${WS1_ENV.url} is not a URL`; }
  try { t = new URL(tokenUrl); } catch { return `${WS1_ENV.tokenUrl} is not a URL`; }
  if (u.protocol !== "https:") return `${WS1_ENV.url} must be https`;
  // The secret goes to the token URL, so only Omnissa's four documented token hosts are accepted.
  if (t.protocol !== "https:" || !TOKEN_HOSTS.includes(t.hostname) || t.pathname !== "/connect/token") return `${WS1_ENV.tokenUrl} must be one of ${TOKEN_HOSTS.map((h) => `https://${h}/connect/token`).join(", ")}`;
  const token = cachedToken(() => tokenRequest(t.href, { grant_type: "client_credentials", client_id: client, client_secret: secret }, fetchFn));
  const make = (version: number) => fetchRest({ base: `${u.origin}/api`, fetchFn,
    headers: async () => ({ authorization: `Bearer ${await token()}`, accept: `application/json;version=${version}` }) });
  return { v3: make(3), v1: make(1) };
}

async function listDevices(api: RestApi, max: number): Promise<{ items: Obj[]; truncated: boolean; pages: number } | { error: HttpResponse }> {
  const items: Obj[] = [];
  for (let page = 0; ; page++) {
    const r = await api.get(searchPath(page));
    const got = ok(r) && isObj(r.body) && Array.isArray(r.body.devices) ? r.body.devices.filter(isObj) : undefined;
    if (!got) return { error: r };
    items.push(...got);
    const total = isObj(r.body) ? Number(r.body.total) : NaN;
    if (items.length >= max) return { items: items.slice(0, max), truncated: items.length > max || (Number.isFinite(total) && total > max), pages: page + 1 };
    if (got.length < PAGE || (Number.isFinite(total) && items.length >= total)) return { items, truncated: false, pages: page + 1 };
  }
}

const uuidOf = (d: Obj) => str(d.Uuid) ?? str(d.uuid);
const idOf = (d: Obj) => uuidOf(d) ?? (isObj(d.Id) ? String(d.Id.Value ?? "?") : "?");

export interface Ws1Options { seenDays: number; maxDevices: number; minOs: Map<string, number[]> }

export async function ws1Checks(api: Ws1Clients, host: string, o: Ws1Options, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("workspace_one", `workspace one ${host}`);
  const got = await listDevices(api.v3, o.maxDevices);
  if ("error" in got) { for (const c of WS1_CHECKS) out.skip(c, got.error, "device search (MDM API V3)"); return out.results; }
  if (!got.items.length) { out.skipAll(WS1_CHECKS, "Workspace ONE UEM lists no device in this organization group; nothing to judge"); return out.results; }
  const cap = got.truncated ? `; only the first ${o.maxDevices} devices read (--workspace-one-max-devices)` : "";
  const from = out.results.length;
  if (!o.minOs.size) out.add("os_minimum", "skipped", `no minimum OS version given (--workspace-one-min-os, e.g. macos=15.0 or windows=10.0.26100); ${got.items.length} device(s) not judged`);

  let encDenied: HttpResponse | undefined;
  for (const d of got.items) {
    const id = idOf(d);
    const res = deviceResource("workspace one device", id, d.serial_number);
    const type = str(d.device_type) ?? "UNKNOWN";
    const where = ` (${type}, ${str(d.operating_system) ?? "OS version not reported"})`;
    const status = str(d.enrollment_status);

    if (status && GONE.has(status)) { out.skipAll(WS1_CHECKS.filter((c) => c !== "os_minimum" || o.minOs.size), `enrollment_status is ${status}: no longer in service, not judged${where}`, res); continue; }
    if (status === "ENROLLED") out.add("enrolled", "pass", `enrollment_status is ENROLLED${where}${cap}`, res);
    else if (status && NOT_YET.has(status)) out.add("enrolled", "fail", `enrollment_status is ${status}; ENROLLED required${where}`, res);
    else out.add("enrolled", "skipped", `enrollment_status is ${status ?? "not reported"}, which does not show enrollment${where}`, res);

    const cs = str(d.compliance_status);
    if (cs === "COMPLIANT") out.add("compliant", "pass", `compliance_status is COMPLIANT${where}`, res);
    else if (cs && BAD_COMPLIANCE.has(cs)) out.add("compliant", "fail", `compliance_status is ${cs}; COMPLIANT required${where}`, res);
    else out.add("compliant", "skipped", `compliance_status is ${cs ?? "not reported"}, which does not show compliance (no policy assigned, or not yet evaluated)${where}`, res);

    if (typeof d.compromised_status === "boolean") out.add("compromised", d.compromised_status ? "fail" : "pass", `compromised_status is ${d.compromised_status}${where}`, res);
    else out.add("compromised", "skipped", `compromised_status not reported${where}`, res);

    if (o.minOs.size) {
      const floor = [type.toLowerCase(), ...(PLATFORM_ALIASES[type] ?? [])].map((k) => o.minOs.get(k)).find(Boolean) ?? o.minOs.get("*");
      const have = versionIn(d.operating_system);
      if (!floor) out.add("os_minimum", "skipped", `no --workspace-one-min-os floor for ${type}${where}`, res);
      else if (!have) out.add("os_minimum", "skipped", `operating_system not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        out.add("os_minimum", okv ? "pass" : "fail", `operating_system ${showVersion(have)} ${okv ? "meets" : "is below"} the --workspace-one-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    const age = ageDays(d.last_seen, now);
    if (age === undefined) out.add("last_seen", "skipped", `last_seen not reported${where}`, res);
    else out.add("last_seen", age <= o.seenDays ? "pass" : "fail", `last reported ${age} day(s) ago; at most ${o.seenDays} allowed (--workspace-one-seen-days)${where}`, res);

    // Encryption: one call per device; a 401 or 403 stops the calls.
    const uuid = uuidOf(d);
    if (encDenied) { out.skip("disk_encryption", encDenied, "encryption status", res); continue; }
    if (!uuid) { out.add("disk_encryption", "skipped", `no Uuid in the search answer, so the encryption status cannot be asked${where}`, res); continue; }
    const e = await api.v1.get(encryptionPath(uuid));
    if (!ok(e) || !isObj(e.body)) {
      if (e.status === 401 || e.status === 403) encDenied = e;
      out.skip("disk_encryption", e, "encryption status (MDM API V1)", res);
      continue;
    }
    const v = e.body.encryption_status;
    if (typeof v === "boolean") out.add("disk_encryption", v ? "pass" : "fail", `encryption_status is ${v}${where}`, res);
    else out.add("disk_encryption", "skipped", `encryption_status not reported${where}`, res);
  }
  stampRead(out.results, from, listRead(got));   // a capped list leaves devices unseen: format 3 says so
  return out.results;
}

export const workspaceOne: Source = {
  name: "workspace_one",
  options: {
    "workspace-one-seen-days": { type: "string", help: `days since a device last reported before last_seen fails (default ${DEFAULTS.seenDays})` },
    "workspace-one-min-os": { type: "string", multiple: true, help: "<platform>=<version> floor for os_minimum, e.g. macos=15.0, windows=10.0.26100, ios=18.0 (or a device_type such as APPLE_OS_X; repeatable; without it the check is skipped)" },
    "workspace-one-max-devices": { type: "string", help: `devices read, at most (default ${DEFAULTS.maxDevices}); each costs one encryption-status call` },
  },
  emits: WS1_CHECKS.map((c) => `workspace_one.${c}`),
  describe: () => "Omnissa Workspace ONE UEM (SaaS) in WS1_API_URL (REST API, OAuth client with REST API Devices Read)",
  async run(ctx: SourceContext) {
    const host = (() => { try { return new URL(ctx.env[WS1_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.workspace_one as RestApi | Ws1Clients | null | undefined;
    const built = given !== undefined ? (given && "get" in given ? { v3: given, v1: given } : given) : ws1FromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("workspace_one", `workspace one ${host}`);
      out.skipAll(WS1_CHECKS, typeof built === "string" ? built : `${WS1_ENV.secret} is not set`);
      return out.results;
    }
    const sleep = (ctx.clients.sleep as Sleep | undefined) ?? realSleep;
    const api = { v3: withRetry(built.v3, sleep), v1: withRetry(built.v1, sleep) };
    const o: Ws1Options = {
      seenDays: posInt(ctx.opts["workspace-one-seen-days"], DEFAULTS.seenDays),
      maxDevices: posInt(ctx.opts["workspace-one-max-devices"], DEFAULTS.maxDevices),
      minOs: minOsOption(ctx.opts["workspace-one-min-os"]),
    };
    const secret = ctx.env[WS1_ENV.secret];
    return redact(await ws1Checks(api, host, o, ctx.now), [secret, ctx.env[WS1_ENV.client] && secret ? Buffer.from(`${ctx.env[WS1_ENV.client]}:${secret}`).toString("base64") : undefined]);
  },
};
