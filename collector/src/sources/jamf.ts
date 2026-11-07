// Jamf Pro API (GET only), as an API client whose API role holds two privileges, "Read Computers" and "View MDM command
// information in Jamf Pro API" (the second since 2026-11-07, for erase records). The token request is the only POST.
//
// Endpoints and fields (developer.jamf.com/jamf-pro/reference, read 2026-10-15):
//   POST /api/v1/oauth/token  form grant_type=client_credentials, client_id, client_secret
//        -> { access_token, token_type, scope, expires_in }  (older servers: /api/oauth/token)
//   GET /api/{v4|v3|v2|v1}/computers-inventory?section=GENERAL&section=DISK_ENCRYPTION
//        &section=OPERATING_SYSTEM&section=HARDWARE&page&page-size&sort=id:asc     Read Computers
//        -> { totalCount, results: [ { id, general: { reportDate, remoteManagement: { managed } },
//             diskEncryption: { fileVault2Enabled, bootPartitionEncryptionDetails: { partitionFileVault2State } },
//             operatingSystem: { version }, hardware: { serialNumber } } ] }
//   v1, v2 and v3 are marked deprecated; v4 is tried first and the next older version answers when a
//   server does not have it (404). partitionFileVault2State is one of UNKNOWN, UNENCRYPTED,
//   INELIGIBLE, DECRYPTED, DECRYPTING, ENCRYPTED, ENCRYPTING, RESTART_NEEDED, OPTIMIZING,
//   DECRYPTING_PAUSED, ENCRYPTING_PAUSED.
//
// Erase records (device_wipe_recorded, 2026-11-07), privilege "View MDM command information in Jamf Pro API":
//   GET /api/v2/mdm/commands?filter=command==ERASE_DEVICE;dateSent=ge=<ISO time>&page&page-size&sort=dateSent:asc
//        -> { totalCount, results: [ { uuid, dateSent, dateCompleted, client: { managementId, clientType },
//             commandState, commandType } ] }
//   commandState is PENDING, ACKNOWLEDGED, NOT_NOW, ERROR or COMMAND_FORMAT_ERROR; clientType includes COMPUTER and
//   MOBILE_DEVICE. The filter is RSQL and needs at least one field (filterable: command, status, clientType, dateSent,
//   ...). Jamf Pro has no "unmanage" command type, so only erases are judged; an unmanaged computer is the managed check.
//   https://developer.jamf.com/jamf-pro/reference/get_v2-mdm-commands (read 2026-11-07); GET /api/v1/mdm/commands is
//   deprecated (https://developer.jamf.com/jamf-pro/reference/get_v1-mdm-commands, read 2026-11-07).
//   general.managementId (GENERAL section) ties a command's client to a computer's id and serial.
//
// Personal data: a computer is named by its Jamf id and serial. general.name, the USER_AND_LOCATION
// section (never requested), diskEncryption.fileVault2EnabledUserNames and the last-logged-in
// usernames are never read into a result.

import type { Result, Source, SourceContext } from "../types.ts";
import { cachedToken, tokenRequest } from "./oauth.ts";
import { Emitter, fetchRest, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { WIPE_DEFAULTS, ageDays, cmpVersion, deviceResource, judgeWipes, minOsOption, posInt, showVersion, versionIn, type WipeAction } from "./device_common.ts";

export const JAMF_ENV = { url: "JAMF_URL", client: "JAMF_CLIENT_ID", secret: "JAMF_CLIENT_SECRET" } as const;
export const JAMF_CHECKS = ["filevault", "os_minimum", "last_inventory", "managed", "device_wipe_recorded"] as const;
type C = (typeof JAMF_CHECKS)[number];

export const DEFAULTS = { inventoryDays: 14, maxComputers: 5000, wipeDays: WIPE_DEFAULTS.periodDays } as const;
export const commandsPath = (sinceIso: string, page: number) =>
  `/v2/mdm/commands?filter=${encodeURIComponent(`command==ERASE_DEVICE;dateSent=ge=${sinceIso}`)}&page=${page}&page-size=${PAGE}&sort=dateSent%3Aasc`;
const ERASE_STATE: Record<string, WipeAction["state"]> = { ACKNOWLEDGED: "done", ERROR: "failed", COMMAND_FORMAT_ERROR: "failed", PENDING: "pending", NOT_NOW: "pending" };

/** Every ERASE_DEVICE command sent since `sinceIso` (at most 50 pages). */
async function eraseCommands(api: RestApi, sinceIso: string): Promise<{ items: Obj[]; truncated: boolean; pages: number } | { error: HttpResponse }> {
  const items: Obj[] = [];
  for (let page = 0; page < 50; page++) {
    const r = await api.get(commandsPath(sinceIso, page));
    if (!ok(r) || !isObj(r.body) || !Array.isArray(r.body.results)) return { error: r };
    const got = r.body.results.filter(isObj);
    items.push(...got);
    const total = Number(r.body.totalCount);
    if (got.length < PAGE || (Number.isFinite(total) && items.length >= total)) return { items, truncated: false, pages: page + 1 };
  }
  return { items, truncated: true, pages: 50 };
}
export const PAGE = 100;
export const VERSIONS = ["v4", "v3", "v2", "v1"] as const;
const SECTIONS = ["GENERAL", "DISK_ENCRYPTION", "OPERATING_SYSTEM", "HARDWARE"].map((s) => `section=${s}`).join("&");
export const inventoryPath = (v: string, page: number) => `/${v}/computers-inventory?${SECTIONS}&page=${page}&page-size=${PAGE}&sort=id%3Aasc`;

/** A Jamf Pro API client from JAMF_* variables, or what is missing. */
export function jamfFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const url = env[JAMF_ENV.url], client = env[JAMF_ENV.client], secret = env[JAMF_ENV.secret];
  if (!url || !client || !secret) return `${JAMF_ENV.url}, ${JAMF_ENV.client} and ${JAMF_ENV.secret} are not all set`;
  let u: URL;
  try { u = new URL(url); } catch { return `${JAMF_ENV.url} is not a URL`; }
  if (u.protocol !== "https:") return `${JAMF_ENV.url} must be https`;
  const form = { grant_type: "client_credentials", client_id: client, client_secret: secret };
  const token = cachedToken(async () => {
    try { return await tokenRequest(`${u.origin}/api/v1/oauth/token`, form, fetchFn); }
    catch (e) {
      if (!/HTTP 404/.test(String((e as Error).message))) throw e;
      return tokenRequest(`${u.origin}/api/oauth/token`, form, fetchFn);
    }
  });
  return fetchRest({ base: `${u.origin}/api`, fetchFn, headers: async () => ({ authorization: `Bearer ${await token()}` }) });
}

async function listComputers(api: RestApi, max: number): Promise<{ items: Obj[]; version: string; truncated: boolean } | { error: HttpResponse }> {
  let version: string | undefined, first: HttpResponse | undefined;
  for (const v of VERSIONS) {
    first = await api.get(inventoryPath(v, 0));
    if (first.status !== 404) { version = v; break; }
  }
  const results = (r: HttpResponse) => (ok(r) && isObj(r.body) && Array.isArray(r.body.results) ? r.body.results.filter(isObj) : undefined);
  if (!version || !first || !results(first)) return { error: first! };
  const items: Obj[] = [...results(first)!];
  const total = isObj(first.body) ? Number(first.body.totalCount) : NaN;
  for (let page = 1; items.length < max && (Number.isFinite(total) ? page * PAGE < total : results(first)!.length === PAGE); page++) {
    const r = await api.get(inventoryPath(version, page));
    const got = results(r);
    if (!got) return { error: r };
    if (!got.length) break;
    items.push(...got);
  }
  return { items: items.slice(0, max), version, truncated: items.length > max || (Number.isFinite(total) && total > max) };
}

const sub = (o: Obj, k: string): Obj => (isObj(o[k]) ? (o[k] as Obj) : {});

export async function jamfChecks(api: RestApi, server: string, o: { inventoryDays: number; maxComputers: number; minOs: Map<string, number[]>; wipeDays?: number }, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("jamf", `jamf ${server}`);
  const got = await listComputers(api, o.maxComputers);

  // Erase commands of the period, tied to a computer's id and serial when the inventory names its management id.
  const wipeDays = o.wipeDays ?? DEFAULTS.wipeDays, since = now.getTime() - wipeDays * 86_400_000;
  const erases = await eraseCommands(api, new Date(since).toISOString());
  if ("error" in erases) out.skip("device_wipe_recorded", erases.error, "MDM commands (privilege: View MDM command information in Jamf Pro API)");
  else {
    const byMgmt = new Map<string, string>();
    if (!("error" in got)) for (const c of got.items) {
      const m = str(sub(c, "general").managementId);
      if (m) byMgmt.set(m, deviceResource("jamf computer", c.id, sub(c, "hardware").serialNumber));
    }
    const actions: WipeAction[] = erases.items.filter((x) => x.commandType === undefined || str(x.commandType) === "ERASE_DEVICE").map((x) => {
      const cl = sub(x, "client"), m = str(cl.managementId) ?? "?";
      const kind = str(cl.clientType) === "COMPUTER" || cl.clientType === undefined ? "jamf computer management id"
        : `jamf ${String(cl.clientType).toLowerCase().replace(/[^a-z]+/g, " ").trim()} management id`;
      return { resource: byMgmt.get(m) ?? deviceResource(kind, m, undefined), action: "ERASE_DEVICE", state: ERASE_STATE[String(x.commandState)] ?? "pending",
        stateRaw: String(x.commandState ?? "not reported"), requested: String(x.dateSent ?? ""), completed: str(x.dateCompleted) };
    });
    const from = out.results.length;
    const n = judgeWipes(actions, { since, graceDays: WIPE_DEFAULTS.graceDays, now, where: "" }, (res, result, detail) => out.add("device_wipe_recorded", result, detail, res));
    if (!n) out.add("device_wipe_recorded", "skipped", `no ERASE_DEVICE command in the last ${wipeDays} days (--jamf-wipe-days); nothing to judge`);
    stampRead(out.results, from, listRead(erases));
  }

  const INV_CHECKS = JAMF_CHECKS.filter((c) => c !== "device_wipe_recorded");
  if ("error" in got) { for (const c of INV_CHECKS) out.skip(c, got.error, "computer inventory"); return out.results; }
  if (!got.items.length) { out.skipAll(INV_CHECKS, "Jamf Pro lists no computer; nothing to judge"); return out.results; }
  const cap = got.truncated ? `; only the first ${o.maxComputers} computers read (--jamf-max-computers)` : "";
  const from = out.results.length;
  const floor = o.minOs.get("macos") ?? o.minOs.get("*");
  if (!floor) out.add("os_minimum", "skipped", `no minimum macOS version given (--jamf-min-os, e.g. 15.0); ${got.items.length} computer(s) not judged`);

  for (const c of got.items) {
    const gen = sub(c, "general"), de = sub(c, "diskEncryption"), os = sub(c, "operatingSystem"), hw = sub(c, "hardware");
    const res = deviceResource("jamf computer", c.id, hw.serialNumber);
    const ver = str(os.version);
    const where = ` (macOS ${ver ?? "version not reported"}; Jamf Pro API ${got.version})`;

    // FileVault: the boot partition's state, else fileVault2Enabled.
    const state = str(sub(de, "bootPartitionEncryptionDetails").partitionFileVault2State);
    if (state && state !== "UNKNOWN") out.add("filevault", state === "ENCRYPTED" ? "pass" : "fail", `boot partition FileVault 2 state is ${state}; ENCRYPTED required${where}${cap}`, res);
    else if (typeof de.fileVault2Enabled === "boolean") out.add("filevault", de.fileVault2Enabled ? "pass" : "fail", `fileVault2Enabled is ${de.fileVault2Enabled} (boot partition state ${state ?? "not reported"})${where}`, res);
    else out.add("filevault", "skipped", `FileVault state not reported${where}`, res);

    if (floor) {
      const have = versionIn(ver);
      if (!have) out.add("os_minimum", "skipped", `operatingSystem.version not reported${where}`, res);
      else {
        const okv = cmpVersion(have, floor) >= 0;
        out.add("os_minimum", okv ? "pass" : "fail", `macOS ${showVersion(have)} ${okv ? "meets" : "is below"} the --jamf-min-os floor ${showVersion(floor)}${where}`, res);
      }
    }

    const age = ageDays(gen.reportDate, now);
    if (age === undefined) out.add("last_inventory", "skipped", `general.reportDate not reported${where}`, res);
    else out.add("last_inventory", age <= o.inventoryDays ? "pass" : "fail", `last inventory ${age} day(s) ago; at most ${o.inventoryDays} allowed (--jamf-inventory-days)${where}`, res);

    const managed = sub(gen, "remoteManagement").managed;
    if (typeof managed === "boolean") out.add("managed", managed ? "pass" : "fail", `remoteManagement.managed is ${managed}${where}`, res);
    else out.add("managed", "skipped", `remoteManagement.managed not reported${where}`, res);
  }
  stampRead(out.results, from, listRead(got));   // a capped list leaves devices unseen: format 3 says so
  return out.results;
}

export const jamf: Source = {
  name: "jamf",
  options: {
    "jamf-inventory-days": { type: "string", help: `days since a computer's last inventory before last_inventory fails (default ${DEFAULTS.inventoryDays})` },
    "jamf-min-os": { type: "string", help: "minimum macOS version for os_minimum, e.g. 15.0 (without it the check is skipped)" },
    "jamf-wipe-days": { type: "string", help: `days of ERASE_DEVICE commands judged by device_wipe_recorded (default ${DEFAULTS.wipeDays})` },
    "jamf-max-computers": { type: "string", help: `computers read, at most (default ${DEFAULTS.maxComputers})` },
  },
  emits: JAMF_CHECKS.map((c) => `jamf.${c}`),
  describe: () => "Jamf Pro server in JAMF_URL (Jamf Pro API: Read Computers, View MDM command information)",
  async run(ctx: SourceContext) {
    const server = (() => { try { return new URL(ctx.env[JAMF_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.jamf as RestApi | null | undefined;
    const built = given !== undefined ? given : jamfFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("jamf", `jamf ${server}`);
      out.skipAll(JAMF_CHECKS, typeof built === "string" ? built : `${JAMF_ENV.secret} is not set`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o = {
      inventoryDays: posInt(ctx.opts["jamf-inventory-days"], DEFAULTS.inventoryDays),
      maxComputers: posInt(ctx.opts["jamf-max-computers"], DEFAULTS.maxComputers),
      minOs: minOsOption(ctx.opts["jamf-min-os"]),
      wipeDays: posInt(ctx.opts["jamf-wipe-days"], DEFAULTS.wipeDays),
    };
    return redact(await jamfChecks(api, server, o, ctx.now), [ctx.env[JAMF_ENV.secret]]);
  },
};
