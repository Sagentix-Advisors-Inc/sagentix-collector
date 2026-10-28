// ManageEngine Endpoint Central (cloud edition) over its REST API (GET only), with a Zoho self client whose refresh
// token was generated for READ operations only: DesktopCentralCloud.Inventory.READ and DesktopCentralCloud.PatchMgmt.READ.
// The refresh-token exchange at the Zoho accounts server is the only POST.
//
// Auth (manageengine.com/products/desktop-central/help/api/cloud/, read 2026-10-28):
//   oauth-authentication-self-client-authorization-code-flow.html: a self client in the Zoho API console generates a
//     code for comma-separated scopes; POST {accounts-server-url}/oauth/v2/token with the query parameters client_id,
//     client_secret, grant_type=authorization_code, code gives a refresh_token that "won't expire"; the same endpoint with
//     grant_type=refresh_token and refresh_token gives an access_token valid one hour (expires_in). The parameters are
//     sent as the page shows them, in the query string, over https.
//   Scopes are service.scope.operation; every endpoint below lists its scope with the operation READ (api-index.html).
//   Header: "Authorization: Zoho-oauthtoken <access token>".
//   oauth-authentication-endpoint-domain.md: nine data centres, EndpointCentral_Server_URI
//     https://endpointcentral.manageengine.{com,eu,in,com.au,cn,jp,ca,uk,sa} with ZohoAccounts_Server_URI
//     https://accounts.zoho.{com,eu,in,com.au,cn,jp,ca,uk,sa}. accounts.zoho.com/oauth/serverinfo (read the same day)
//     gives https://accounts.zohocloud.ca for Canada instead, so ENDPOINT_CENTRAL_ACCOUNTS_URL can override the default.
//   The token acts as the user who generated it, and "UAC_UNAUTHORIZED - user lacks the required uem-roles" is a 401: the
//   predefined Guest role has "Read Access" to Inventory and Patch Management (help/access-management/
//   user_role_and_permission.html, read 2026-10-28).
//
// Endpoints and fields (each page under help/api/cloud/, read 2026-10-28):
//   GET /dcapi/inventory/viewData/scanComputers?toolID=2131     Accept: application/InventoryMobileAPI.v1+json
//        -> { metadata: { limit, page }, totalRecords, totalPages, Links: { next, prev }, messageResponse: [ { resource_id,
//             servicetag, os_platform (1 Windows, 2 Mac, 3 Linux), os_version, build_number, installation_status
//             (21 yet to install, 22 installed, 23 uninstalled, 24 yet to uninstall, 29 installation failure),
//             agent_last_contact_time (epoch ms), resource_name, domain_netbios_name, ... } ] }   Threshold 120 a minute.
//   GET /dcapi/inventory/computers/{resourceID}/diskEncryptionStatus     Accept: application/diskEncryptionStatus.v1+json
//        -> { diskEncryptionStatusDetails: [ { logicalDriveName, encryptionStatus ("Encrypted", "Not Encrypted"),
//             logicalDiskType, encryptionMethod } ] }   Threshold 120 a minute.
//   GET /dcapi/inventory/computers/{resourceID}/firewall                 Accept: application/firewallInfo.v1+json
//        -> { windowsFirewallDetails: [ { domainProfileStatus, privateProfileStatus, publicProfileStatus,
//             isExternalFirewallEnabled, externalFirewallName } ], externalFirewallDetails: [ { firewallName,
//             protectionStatus, ... } ] }   Threshold 120 a minute.
//   GET /dcapi/patch/reports/systemHealth?page&pageLimit                 (scope DesktopCentralCloud.PatchMgmt.READ)
//        -> { totalPages, Links: { next }, messageResponse: [ { ComputerName, Domain, Health, MissingOsPatches,
//             Critical, Important, ... } ] }   Threshold 50 a minute.
//   Each page states "Lock period: 5 minutes" once a threshold is passed, so the per-computer calls are spaced by
//   --endpoint-central-call-gap-ms (default 600 ms: 100 computers a minute, under 120). Pages follow Links.next, a path
//   such as "/dcapi/patch/reports/systemHealth?page=2&pageLimit=25", until it is null.
//   The patch report carries no resource id, so a row is matched to a computer by ComputerName and Domain (the scan
//   list's resource_name and domain_netbios_name); a name that two computers share is skipped, never guessed.
//
// Left out: the screen lock (no Inventory or Patch endpoint reports it), and the on-premises edition: its documented API
// (/api/1.4/desktop/authentication) signs in with a console user's password, and no page documents the /dcapi
// endpoints or a read-only API key for it.
//
// Personal data: a computer is named by its resource_id and service tag. resource_name, the logged-on user (name), FQDN,
// IP and MAC addresses, and the patch report's owner and user fields are never put in a result.

import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, tokenRequest } from "./oauth.ts";
import { Emitter, enc, fetchRest, isObj, ok, realSleep, redact, str, why, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { cmpVersion, deviceResource, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const EC_ENV = {
  url: "ENDPOINT_CENTRAL_URL", client: "ENDPOINT_CENTRAL_CLIENT_ID", secret: "ENDPOINT_CENTRAL_CLIENT_SECRET",
  refresh: "ENDPOINT_CENTRAL_REFRESH_TOKEN", accounts: "ENDPOINT_CENTRAL_ACCOUNTS_URL",
} as const;
/** Data centre suffixes from the "Multiple data centres" page: endpointcentral.manageengine.<suffix>, accounts.zoho.<suffix>. */
export const EC_SUFFIXES = ["com", "eu", "in", "com.au", "cn", "jp", "ca", "uk", "sa"] as const;
export const EC_SCOPES = ["DesktopCentralCloud.Inventory.READ", "DesktopCentralCloud.PatchMgmt.READ"] as const;
export const EC_CHECKS = ["disk_encryption", "firewall", "os_minimum", "os_patches", "last_contact", "agent_installed"] as const;
type C = (typeof EC_CHECKS)[number];

export const DEFAULTS = { contactDays: 14, maxComputers: 500, gapMs: 600, maxMissingOsPatches: 0 } as const;
export const PATCH_PAGE = 100;
export const SCAN_PATH = "/dcapi/inventory/viewData/scanComputers?toolID=2131";
export const healthPath = (page: number) => `/dcapi/patch/reports/systemHealth?page=${page}&pageLimit=${PATCH_PAGE}`;
export const encryptionPath = (id: string) => `/dcapi/inventory/computers/${enc(id)}/diskEncryptionStatus`;
export const firewallPath = (id: string) => `/dcapi/inventory/computers/${enc(id)}/firewall`;

/** The Accept header each endpoint's page marks Mandatory. */
export function acceptFor(path: string): string {
  if (path.includes("/viewData/scanComputers")) return "application/InventoryMobileAPI.v1+json";
  if (path.includes("/diskEncryptionStatus")) return "application/diskEncryptionStatus.v1+json";
  if (path.includes("/firewall")) return "application/firewallInfo.v1+json";
  return "application/json";
}

/** The data centre suffix of an Endpoint Central cloud URL, or undefined for any other host. */
export function suffixOf(host: string): string | undefined {
  const m = host.match(/^endpointcentral\.manageengine\.(.+)$/);
  return m && (EC_SUFFIXES as readonly string[]).includes(m[1]) ? m[1] : undefined;
}

/** An Endpoint Central cloud client from ENDPOINT_CENTRAL_* variables, or what is missing. */
export function endpointCentralFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const url = env[EC_ENV.url], client = env[EC_ENV.client], secret = env[EC_ENV.secret], refresh = env[EC_ENV.refresh];
  if (!url || !client || !secret || !refresh) return `${EC_ENV.url}, ${EC_ENV.client}, ${EC_ENV.secret} and ${EC_ENV.refresh} are not all set`;
  let u: URL;
  try { u = new URL(url); } catch { return `${EC_ENV.url} is not a URL`; }
  if (u.protocol !== "https:") return `${EC_ENV.url} must be https`;
  const suffix = suffixOf(u.host);
  if (!suffix) return `${EC_ENV.url} must be https://endpointcentral.manageengine.<${EC_SUFFIXES.join("|")}> (the cloud edition; on-premises servers are not supported)`;
  let accounts = `https://accounts.zoho.${suffix}`;
  if (env[EC_ENV.accounts]) {
    let a: URL;
    try { a = new URL(env[EC_ENV.accounts]!); } catch { return `${EC_ENV.accounts} is not a URL`; }
    if (a.protocol !== "https:" || !/^accounts\.(zoho|zohocloud)\.[a-z.]+$/.test(a.host)) return `${EC_ENV.accounts} must be a https Zoho accounts server, e.g. https://accounts.zoho.eu`;
    accounts = a.origin;
  }
  const qs = new URLSearchParams({ client_id: client, client_secret: secret, grant_type: "refresh_token", refresh_token: refresh }).toString();
  let current = "";
  const token = cachedToken(async () => { const t = await tokenRequest(`${accounts}/oauth/v2/token?${qs}`, {}, fetchFn); current = t.token; return t; });
  const clients = new Map<string, RestApi>();
  const clientFor = (accept: string) => {
    let c = clients.get(accept);
    if (!c) {
      c = fetchRest({ base: u.origin, fetchFn, headers: async () => ({ authorization: `Zoho-oauthtoken ${await token()}`, accept }) });
      clients.set(accept, c);
    }
    return c;
  };
  return {
    async get(path: string) {
      const r = await clientFor(acceptFor(path)).get(path);
      // fetchRest cuts the whole header value out of an answer; the bare access token is cut here.
      if (current.length >= 8 && JSON.stringify(r.body ?? "").includes(current)) {
        const text = JSON.stringify(r.body).split(current).join("[redacted]");
        return { ...r, body: JSON.parse(text) };
      }
      return r;
    },
  };
}

const rowsOf = (b: unknown) => (isObj(b) && Array.isArray(b.messageResponse) ? b.messageResponse.filter(isObj) : undefined);
const nextOf = (b: unknown) => (isObj(b) && isObj(b.Links) ? str(b.Links.next) : undefined);

/** The scan computers list, following Links.next, up to `max` computers. */
async function listComputers(api: RestApi, max: number): Promise<{ items: Obj[]; truncated: boolean; pages: number } | { error: HttpResponse }> {
  const items: Obj[] = [];
  let url: string | undefined = SCAN_PATH;
  let pages = 0;
  const seen = new Set<string>();
  while (url && !seen.has(url)) {
    seen.add(url);
    const r = await api.get(url);
    const got = ok(r) ? rowsOf(r.body) : undefined;
    if (!got) return { error: r };
    pages++;
    items.push(...got);
    if (items.length >= max) return { items: items.slice(0, max), truncated: items.length > max || !!nextOf(r.body), pages };
    url = nextOf(r.body);
  }
  return { items, truncated: false, pages };
}

/** The system health report's rows, by lower-cased "ComputerName|Domain"; a key two rows share maps to null. */
async function systemHealth(api: RestApi, maxPages: number): Promise<{ rows: Map<string, Obj | null> } | { error: HttpResponse }> {
  const rows = new Map<string, Obj | null>();
  for (let page = 1; page <= maxPages; page++) {
    const r = await api.get(healthPath(page));
    const got = ok(r) ? rowsOf(r.body) : undefined;
    if (!got) return { error: r };
    for (const row of got) {
      const k = `${String(row.ComputerName ?? "").toLowerCase()}|${String(row.Domain ?? "").toLowerCase()}`;
      rows.set(k, rows.has(k) ? null : row);
    }
    const total = isObj(r.body) ? Number(r.body.totalPages) : NaN;
    if (!got.length || !nextOf(r.body) || (Number.isFinite(total) && page >= total)) break;
  }
  return { rows };
}

const PLATFORM: Record<string, string> = { "1": "windows", "2": "macos", "3": "linux" };
const INSTALL: Record<string, string> = { "21": "yet to install", "22": "installed", "23": "uninstalled", "24": "yet to uninstall", "29": "installation failure" };
const n = (v: unknown) => { const x = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN; return Number.isFinite(x) ? x : undefined; };

function judgeEncryption(body: unknown): { result: "pass" | "fail" | "skipped"; detail: string } {
  const list = isObj(body) && Array.isArray(body.diskEncryptionStatusDetails) ? body.diskEncryptionStatusDetails.filter(isObj) : undefined;
  if (!list) return { result: "skipped", detail: "diskEncryptionStatusDetails not reported" };
  const known = list.filter((d) => d.encryptionStatus === "Encrypted" || d.encryptionStatus === "Not Encrypted");
  if (!known.length) return { result: "skipped", detail: `no drive reports an encryptionStatus of Encrypted or Not Encrypted (${list.length} listed)` };
  const off = known.filter((d) => d.encryptionStatus === "Not Encrypted");
  const name = (d: Obj) => String(d.logicalDriveName ?? "?").replace(/[^A-Za-z0-9:/\\._-]/g, "").slice(0, 40);
  if (off.length) return { result: "fail", detail: `${off.length} of ${known.length} drive(s) Not Encrypted: ${off.slice(0, 5).map(name).join(", ")}; every reported drive must be Encrypted` };
  return { result: "pass", detail: `all ${known.length} drive(s) report Encrypted (${known.slice(0, 5).map((d) => `${name(d)} ${String(d.encryptionMethod ?? "").slice(0, 20)}`.trim()).join(", ")})` };
}

function judgeFirewall(body: unknown): { result: "pass" | "fail" | "skipped"; detail: string } {
  if (!isObj(body)) return { result: "skipped", detail: "firewall details not reported" };
  const win = Array.isArray(body.windowsFirewallDetails) ? body.windowsFirewallDetails.filter(isObj)[0] : undefined;
  const ext = Array.isArray(body.externalFirewallDetails) ? body.externalFirewallDetails.filter(isObj) : [];
  const extOn = ext.filter((e) => e.protectionStatus === "Enabled");
  if (extOn.length) return { result: "pass", detail: `a third-party firewall reports protectionStatus Enabled (${extOn.length} of ${ext.length} listed)` };
  if (!win) return { result: "skipped", detail: `no Windows Firewall profile and no enabled third-party firewall reported (${ext.length} third-party listed)` };
  const prof = { domain: str(win.domainProfileStatus), private: str(win.privateProfileStatus), public: str(win.publicProfileStatus) };
  const shown = Object.entries(prof).map(([k, v]) => `${k} ${v ?? "not reported"}`).join(", ");
  if (Object.values(prof).every((v) => v === "Enabled")) return { result: "pass", detail: `Windows Firewall profiles: ${shown}` };
  if (Object.values(prof).some((v) => v === undefined)) return { result: "skipped", detail: `Windows Firewall profiles not all reported: ${shown}` };
  return { result: "fail", detail: `Windows Firewall profiles: ${shown}; all three must be Enabled, and no third-party firewall reports Enabled` };
}

export interface EcOptions { contactDays: number; maxComputers: number; gapMs: number; maxMissingOsPatches: number; minOs: Map<string, number[]> }

export async function endpointCentralChecks(api: RestApi, server: string, o: EcOptions, now: Date, sleep: Sleep): Promise<Result[]> {
  const out = new Emitter<C>("endpoint_central", `endpoint_central ${server}`);
  const got = await listComputers(api, o.maxComputers);
  if ("error" in got) { for (const c of EC_CHECKS) out.skip(c, got.error, "scan computers list"); return out.results; }
  if (!got.items.length) { out.skipAll(EC_CHECKS, "Endpoint Central lists no computer; nothing to judge"); return out.results; }
  const cap = got.truncated ? `; only the first ${o.maxComputers} computers read (--endpoint-central-max-computers)` : "";
  const from = out.results.length;
  if (!o.minOs.size) out.add("os_minimum", "skipped", `no minimum OS version given (--endpoint-central-min-os, e.g. windows=10.0.26100 or macos=15.0); ${got.items.length} computer(s) not judged`);

  const health = await systemHealth(api, Math.ceil(o.maxComputers / PATCH_PAGE) + 2);
  if ("error" in health) out.skip("os_patches", health.error, "patch system health report");

  const denied = new Map<"disk_encryption" | "firewall", HttpResponse>();
  let calls = 0;
  for (const c of got.items) {
    const id = String(c.resource_id ?? "");
    const res = deviceResource("endpoint_central computer", id || "?", c.servicetag);
    const platform = PLATFORM[String(c.os_platform)] ?? "unknown";
    const ver = str(c.os_version);
    const where = ` (${platform}${ver ? ` ${ver.slice(0, 30)}` : ""})`;
    const inst = String(c.installation_status ?? "");

    if (inst === "22") out.add("agent_installed", "pass", `installation_status 22 (installed)${where}${cap}`, res);
    else if (INSTALL[inst]) out.add("agent_installed", "fail", `installation_status ${inst} (${INSTALL[inst]}); 22 (installed) required${where}`, res);
    else out.add("agent_installed", "skipped", `installation_status ${inst || "not reported"}${where}`, res);

    const ms = n(c.agent_last_contact_time);
    if (ms === undefined || ms <= 0) out.add("last_contact", "skipped", `agent_last_contact_time not reported${where}`, res);
    else {
      const age = Math.floor((now.getTime() - ms) / 86_400_000);
      out.add("last_contact", age <= o.contactDays ? "pass" : "fail", `agent last contact ${age} day(s) ago; at most ${o.contactDays} allowed (--endpoint-central-contact-days)${where}`, res);
    }

    if (o.minOs.size) {
      const floor = o.minOs.get(platform) ?? o.minOs.get("*");
      const have = versionIn(ver);
      if (!floor) out.add("os_minimum", "skipped", `no --endpoint-central-min-os floor for ${platform}${where}`, res);
      else if (!have) out.add("os_minimum", "skipped", `os_version not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        out.add("os_minimum", okv ? "pass" : "fail", `${platform} ${showVersion(have)} ${okv ? "meets" : "is below"} the --endpoint-central-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    if (!("error" in health)) {
      const key = `${String(c.resource_name ?? "").toLowerCase()}|${String(c.domain_netbios_name ?? "").toLowerCase()}`;
      const row = health.rows.get(key);
      const missing = row ? n(row.MissingOsPatches) : undefined;
      if (row === null) out.add("os_patches", "skipped", `two or more patch report rows share this computer's name and domain; not matched${where}`, res);
      else if (!row) out.add("os_patches", "skipped", `no row for this computer in the patch system health report${where}`, res);
      else if (missing === undefined) out.add("os_patches", "skipped", `MissingOsPatches not reported (Health ${String(row.Health ?? "not reported").slice(0, 30)})${where}`, res);
      else {
        const pass = missing <= o.maxMissingOsPatches;
        out.add("os_patches", pass ? "pass" : "fail", `${missing} missing OS patch(es) (Critical ${String(row.Critical ?? "?").slice(0, 8)}, Important ${String(row.Important ?? "?").slice(0, 8)}, Health ${String(row.Health ?? "?").slice(0, 30)}); at most ${o.maxMissingOsPatches} allowed (--endpoint-central-max-missing-os-patches)${where}`, res);
      }
    }

    // One disk-encryption and one firewall call per computer with an installed agent, spaced under the 120-a-minute threshold.
    for (const [check, path, judge] of [["disk_encryption", encryptionPath, judgeEncryption], ["firewall", firewallPath, judgeFirewall]] as const) {
      const stop = denied.get(check);
      if (stop) { out.skip(check, stop, check === "firewall" ? "computer firewall details" : "disk encryption status", res); continue; }
      if (!id) { out.add(check, "skipped", `no resource_id${where}`, res); continue; }
      if (inst !== "22") { out.add(check, "skipped", `the agent is not installed (installation_status ${inst || "not reported"}), so inventory has no current value${where}`, res); continue; }
      if (calls++ > 0 && o.gapMs > 0) await sleep(o.gapMs);
      const r = await api.get(path(id));
      if (!ok(r)) {
        if (r.status === 401 || r.status === 403) denied.set(check, r);
        out.add(check, "skipped", `${check === "firewall" ? "computer firewall details" : "disk encryption status"} not readable: ${why(r)}${where}`, res, { method: "config-read", apiError: { status: r.status, message: why(r) } });
        continue;
      }
      const v = judge(r.body);
      out.add(check, v.result, `${v.detail}${where}`, res);
    }
  }
  stampRead(out.results, from, listRead(got));
  return out.results;
}

export const endpoint_central: Source = {
  name: "endpoint_central",
  options: {
    "endpoint-central-contact-days": { type: "string", help: `days since a computer's last agent contact before last_contact fails (default ${DEFAULTS.contactDays})` },
    "endpoint-central-min-os": { type: "string", multiple: true, help: "<platform>=<version> floor for os_minimum, platform windows, macos or linux, e.g. windows=10.0.26100 (repeatable; without it the check is skipped)" },
    "endpoint-central-max-missing-os-patches": { type: "string", help: `missing OS patches a computer may have before os_patches fails (default ${DEFAULTS.maxMissingOsPatches})` },
    "endpoint-central-max-computers": { type: "string", help: `computers read, at most (default ${DEFAULTS.maxComputers}); each costs two inventory calls` },
    "endpoint-central-call-gap-ms": { type: "string", help: `pause between per-computer calls, in ms (default ${DEFAULTS.gapMs}: under the documented 120 calls a minute)` },
  },
  emits: EC_CHECKS.map((c) => `endpoint_central.${c}`),
  describe: () => "ManageEngine Endpoint Central cloud server in ENDPOINT_CENTRAL_URL (Zoho self client, Inventory and PatchMgmt READ scopes)",
  async run(ctx: SourceContext) {
    const server = (() => { try { return new URL(ctx.env[EC_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.endpoint_central as RestApi | null | undefined;
    const built = given !== undefined ? given : endpointCentralFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("endpoint_central", `endpoint_central ${server}`);
      out.skipAll(EC_CHECKS, typeof built === "string" ? built : `${EC_ENV.refresh} is not set`);
      return out.results;
    }
    const sleep = (ctx.clients.sleep as Sleep | undefined) ?? realSleep;
    const api = withRetry(built, sleep);
    const nonNeg = (v: unknown, d: number) => { const x = typeof v === "string" && v.trim() !== "" ? Number(v) : NaN; return Number.isInteger(x) && x >= 0 ? x : d; };
    const o: EcOptions = {
      contactDays: posInt(ctx.opts["endpoint-central-contact-days"], DEFAULTS.contactDays),
      maxComputers: posInt(ctx.opts["endpoint-central-max-computers"], DEFAULTS.maxComputers),
      gapMs: nonNeg(ctx.opts["endpoint-central-call-gap-ms"], DEFAULTS.gapMs),
      maxMissingOsPatches: nonNeg(ctx.opts["endpoint-central-max-missing-os-patches"], DEFAULTS.maxMissingOsPatches),
      minOs: minOsOption(ctx.opts["endpoint-central-min-os"]),
    };
    return redact(await endpointCentralChecks(api, server, o, ctx.now, sleep), [ctx.env[EC_ENV.secret], ctx.env[EC_ENV.refresh]]);
  },
};
