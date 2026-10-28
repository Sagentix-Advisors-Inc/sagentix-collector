// Google endpoint management: the devices a Google Workspace or Cloud Identity customer manages (Windows, macOS,
// Linux and ChromeOS desktops reporting through Endpoint Verification, and Android and iOS phones), read through the
// Cloud Identity Devices API with GET only. Same credential as google_workspace: the service account in
// GOOGLE_SA_KEY_FILE acting as GOOGLE_ADMIN_EMAIL through domain-wide delegation, with one more read-only scope.
//
// Pages, all read 2026-10-28:
//   GET https://cloudidentity.googleapis.com/v1/devices        devices.list (docs.cloud.google.com/identity/docs/
//       reference/rest/v1/devices/list, last updated 2025-12-16): customer "customers/my_customer" for your own
//       organization; pageSize "at most 20 ... The maximum value is 100"; pageToken, "Empty if there are no more
//       results" in nextPageToken; view USER_ASSIGNED_DEVICES "all devices with at least one user registered on the
//       device ... all device information, except for asset tags". Scopes: cloud-identity.devices.readonly (or the
//       read-write ones, never asked for here).
//   Device fields (discovery document cloudidentity v1, revision 20261026): name "devices/{device}", serialNumber,
//       deviceType (ANDROID, IOS, GOOGLE_SYNC, WINDOWS, MAC_OS, LINUX, CHROME_OS, GOOGLEBOOK), osVersion ("Android
//       8.1.0"), lastSyncTime ("Most recent time when device synced with this service"), encryptionState
//       (ENCRYPTED, NOT_ENCRYPTED, UNSUPPORTED_BY_DEVICE, ENCRYPTION_STATE_UNSPECIFIED), compromisedState (COMPROMISED,
//       UNCOMPROMISED, COMPROMISED_STATE_UNSPECIFIED), endpointVerificationSpecificAttributes.additionalSignals, whose
//       non-configurable attributes include is_os_native_firewall_enabled. The `name` description says "Device API
//       scopes require that you use domain-wide delegation to access the API".
//   docs.cloud.google.com/identity/docs/how-to/setup-devices (last updated 2026-10-26): "Authenticating directly to
//       the Devices API using a service account isn't supported", so a service account with domain-wide delegation
//       acting as an admin (with_subject) is the documented path.
//   docs.cloud.google.com/endpoint-verification/docs/device-information (last updated 2026-10-26):
//       is_os_native_firewall_enabled "indicates whether the operating system's built-in firewall is enabled", on
//       macOS, ChromeOS, Windows and Linux; device os_version examples "MacOS 13.4.0", "ChromeOs 14541.0.0",
//       "Windows 10.0.19045".
// Left out, with the reason:
//   Screen lock: is_secured_with_screenlock is an access-level attribute on that page, but the Devices API Device
//   resource has no such field, so it is not readable here.
//   Android security patch (securityPatchTime): Android only; not judged.
//   Rate limits: no Devices API quota page was found; a 429 or 403 rateLimitExceeded is retried (readonly_http.ts).
//   The browser sign-in of google_workspace (google_oauth.ts) asks for the Admin SDK scopes only, so this source
//   needs the service-account path.
//
// Personal data: a device is named by its id (from name) and serial. hostname, otherAccounts, wifiMacAddresses,
// imei, meid, assetTag and every browser profile attribute are never read into a result.

import { readFileSync } from "node:fs";
import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, googleAssertion, tokenRequest } from "./oauth.ts";
import { OAUTH_ENV } from "./google_oauth.ts";
import { GOOGLE_ENV, isGoogleTokenUri } from "./google_workspace.ts";
import { Emitter, enc, fetchRest, getAll, isObj, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const DEVICES_BASE = "https://cloudidentity.googleapis.com";
export const DEVICES_SCOPE = "https://www.googleapis.com/auth/cloud-identity.devices.readonly";
export const GE_CHECKS = ["disk_encryption", "firewall", "os_minimum", "last_sync", "compromised"] as const;
type C = (typeof GE_CHECKS)[number];

export const DEFAULTS = { syncDays: 14, maxDevices: 5000 } as const;
export const PAGE = 100;
export const devicesPath = (customer: string, pageToken?: string) =>
  `/v1/devices?customer=${enc(`customers/${customer}`)}&pageSize=${PAGE}&view=USER_ASSIGNED_DEVICES${pageToken ? `&pageToken=${enc(pageToken)}` : ""}`;

/** deviceType → the names --google-endpoints-min-os accepts for it (the lower-cased enum value always works). */
const ALIASES: Record<string, string[]> = { MAC_OS: ["macos"], CHROME_OS: ["chromeos"], WINDOWS: [], LINUX: [], ANDROID: [], IOS: [] };

/** A Cloud Identity client whose token holds only DEVICES_SCOPE, as GOOGLE_ADMIN_EMAIL, or what is missing. */
export function googleDevicesFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const file = env[GOOGLE_ENV.keyFile], admin = env[GOOGLE_ENV.admin];
  if (!file && env[OAUTH_ENV.clientFile]) return `the browser sign-in does not ask for ${DEVICES_SCOPE}; this source needs the service-account path (${GOOGLE_ENV.keyFile} with domain-wide delegation)`;
  if (!file || !admin) return `${GOOGLE_ENV.keyFile} and ${GOOGLE_ENV.admin} are not both set`;
  let key: { client_email: string; private_key: string; token_uri?: string };
  try { key = JSON.parse(readFileSync(file, "utf8")); } catch (e) { return `${GOOGLE_ENV.keyFile} is not a readable service account key (${(e as NodeJS.ErrnoException).code ?? "bad JSON"})`; }
  if (typeof key.client_email !== "string" || typeof key.private_key !== "string") return `${GOOGLE_ENV.keyFile} has no client_email or private_key`;
  const tokenUri = key.token_uri ?? "https://oauth2.googleapis.com/token";
  // The key file names its own token endpoint; a tampered file could send the signed assertion elsewhere.
  if (!isGoogleTokenUri(tokenUri)) return `${GOOGLE_ENV.keyFile} names a token_uri outside googleapis.com over HTTPS`;
  const token = cachedToken(() => tokenRequest(tokenUri, {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: googleAssertion(key, admin, [DEVICES_SCOPE], Math.floor(Date.now() / 1000)),
  }, fetchFn));
  return fetchRest({ base: DEVICES_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

const sub = (o: Obj, k: string): Obj => (isObj(o[k]) ? (o[k] as Obj) : {});

export interface GeOptions { syncDays: number; maxDevices: number; minOs: Map<string, number[]> }

export async function googleEndpointChecks(api: RestApi, customer: string, o: GeOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("google_endpoints", `google endpoints customer ${customer}`);
  const maxPages = Math.ceil(o.maxDevices / PAGE);
  const got = await getAll(api, devicesPath(customer),
    (b) => (isObj(b) ? (Array.isArray(b.devices) ? b.devices : []) : undefined),
    (r: HttpResponse) => { const t = isObj(r.body) ? str(r.body.nextPageToken) : undefined; return t ? devicesPath(customer, t) : undefined; }, maxPages);
  const need = `the service account's domain-wide delegation needs ${DEVICES_SCOPE}, acting as ${GOOGLE_ENV.admin}`;
  if ("error" in got) {
    for (const c of GE_CHECKS) out.skip(c, got.error, `Cloud Identity devices (${need})`);
    return out.results;
  }
  const devices = got.items.filter(isObj).slice(0, o.maxDevices);
  const truncated = got.truncated || got.items.length > o.maxDevices;
  if (!devices.length) { out.skipAll(GE_CHECKS, "Cloud Identity lists no device with a registered user; nothing to judge"); return out.results; }
  const cap = truncated ? `; only the first ${o.maxDevices} devices read (--google-endpoints-max-devices)` : "";
  const from = out.results.length;
  if (!o.minOs.size) out.add("os_minimum", "skipped", `no minimum OS version given (--google-endpoints-min-os, e.g. mac_os=15.0, windows=10.0.26100, chrome_os=16000); ${devices.length} device(s) not judged`);

  for (const d of devices) {
    const id = String(d.name ?? "?").replace(/^devices\//, "");
    const res = deviceResource("google device", id, d.serialNumber);
    const type = str(d.deviceType) ?? "DEVICE_TYPE_UNSPECIFIED";
    const where = ` (${type}, ${str(d.osVersion) ?? "OS version not reported"})`;

    const es = str(d.encryptionState);
    if (es === "ENCRYPTED") out.add("disk_encryption", "pass", `encryptionState is ENCRYPTED${where}${cap}`, res);
    else if (es === "NOT_ENCRYPTED") out.add("disk_encryption", "fail", `encryptionState is NOT_ENCRYPTED; ENCRYPTED required${where}`, res);
    else out.add("disk_encryption", "skipped", `encryptionState is ${es ?? "not reported"}, which does not show encryption${where}`, res);

    // Firewall: only Endpoint Verification reports it, in additionalSignals.
    const ev = d.endpointVerificationSpecificAttributes;
    const fw = isObj(ev) ? sub(ev, "additionalSignals").is_os_native_firewall_enabled : undefined;
    if (typeof fw === "boolean") out.add("firewall", fw ? "pass" : "fail", `Endpoint Verification is_os_native_firewall_enabled is ${fw}${where}`, res);
    else out.add("firewall", "skipped", `${isObj(ev) ? "Endpoint Verification reports no is_os_native_firewall_enabled" : "not an Endpoint Verification device, so no firewall signal"}${where}`, res);

    if (o.minOs.size) {
      const floor = [type.toLowerCase(), ...(ALIASES[type] ?? [])].map((k) => o.minOs.get(k)).find(Boolean) ?? o.minOs.get("*");
      const have = versionIn(d.osVersion);
      if (!floor) out.add("os_minimum", "skipped", `no --google-endpoints-min-os floor for ${type}${where}`, res);
      else if (!have) out.add("os_minimum", "skipped", `osVersion not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        out.add("os_minimum", okv ? "pass" : "fail", `osVersion ${showVersion(have)} ${okv ? "meets" : "is below"} the --google-endpoints-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    const age = ageDays(d.lastSyncTime, now);
    if (age === undefined) out.add("last_sync", "skipped", `lastSyncTime not reported${where}`, res);
    else out.add("last_sync", age <= o.syncDays ? "pass" : "fail", `last synced ${age} day(s) ago; at most ${o.syncDays} allowed (--google-endpoints-sync-days)${where}`, res);

    const cs = str(d.compromisedState);
    if (cs === "UNCOMPROMISED") out.add("compromised", "pass", `compromisedState is UNCOMPROMISED${where}`, res);
    else if (cs === "COMPROMISED") out.add("compromised", "fail", `compromisedState is COMPROMISED${where}`, res);
    else out.add("compromised", "skipped", `compromisedState is ${cs ?? "not reported"}${where}`, res);
  }
  stampRead(out.results, from, listRead({ items: devices, truncated, pages: got.pages }));   // a capped list leaves devices unseen
  return out.results;
}

export const googleEndpoints: Source = {
  name: "google_endpoints",
  options: {
    "google-endpoints-sync-days": { type: "string", help: `days since a device last synced before last_sync fails (default ${DEFAULTS.syncDays})` },
    "google-endpoints-min-os": { type: "string", multiple: true, help: "<deviceType>=<version> floor for os_minimum, e.g. mac_os=15.0, windows=10.0.26100, chrome_os=16000, android=15, ios=18.0 (repeatable; without it the check is skipped)" },
    "google-endpoints-max-devices": { type: "string", help: `devices read, at most (default ${DEFAULTS.maxDevices})` },
  },
  emits: GE_CHECKS.map((c) => `google_endpoints.${c}`),
  describe: () => "Google endpoint management for the customer in GOOGLE_CUSTOMER_ID (default my_customer), Cloud Identity Devices API",
  async run(ctx: SourceContext) {
    const customer = ctx.env[GOOGLE_ENV.customer] || "my_customer";
    const given = ctx.clients.google_endpoints as RestApi | null | undefined;
    const built = given !== undefined ? given : googleDevicesFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("google_endpoints", `google endpoints customer ${customer}`);
      out.skipAll(GE_CHECKS, typeof built === "string" ? built : "no Cloud Identity client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: GeOptions = {
      syncDays: posInt(ctx.opts["google-endpoints-sync-days"], DEFAULTS.syncDays),
      maxDevices: posInt(ctx.opts["google-endpoints-max-devices"], DEFAULTS.maxDevices),
      minOs: minOsOption(ctx.opts["google-endpoints-min-os"]),
    };
    return redact(await googleEndpointChecks(api, customer, o, ctx.now), []);
  },
};
