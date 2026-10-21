// Microsoft Intune over Microsoft Graph v1.0 (GET only), as an Entra app registration with
// application permissions and the client-credentials grant (the same token path as entra.ts).
//
// Endpoint → least-privileged application permission (each API page's Permissions table on
// learn.microsoft.com/graph/api/overview, read 2026-10-15):
//   GET /deviceManagement/managedDevices                                   DeviceManagementManagedDevices.Read.All
//   GET /deviceManagement/deviceCompliancePolicies                         DeviceManagementConfiguration.Read.All
//   GET /deviceManagement/deviceCompliancePolicies/{id}/assignments        DeviceManagementConfiguration.Read.All
// managedDevice fields used: id, serialNumber, operatingSystem, osVersion, complianceState (unknown,
// compliant, noncompliant, conflict, error, inGracePeriod, configManager), isEncrypted, lastSyncDateTime.
// The device list asks for exactly those with $select, so deviceName, userPrincipalName, emailAddress
// and userDisplayName never reach the collector.
// Compliance policy fields (windows10CompliancePolicy, macOSCompliancePolicy): storageRequireEncryption,
// bitLockerEnabled (Windows), passwordRequired, passwordMinutesOfInactivityBeforeLock, osMinimumVersion.
// The Graph API for Intune needs an active Intune licence on the tenant.
//
// Env: INTUNE_TENANT_ID, INTUNE_CLIENT_ID and INTUNE_CLIENT_SECRET or INTUNE_CLIENT_CERT_FILE; each
// falls back to its ENTRA_* twin, so one app registration can serve both sources.

import type { Result, Source, SourceContext } from "../types.ts";
import { entraFromEnv } from "./entra.ts";
import {
  Emitter, enc, getAll, isObj, ok, realSleep, redact, str, why, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, label, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const INTUNE_ENV = { tenant: "INTUNE_TENANT_ID", client: "INTUNE_CLIENT_ID", secret: "INTUNE_CLIENT_SECRET", cert: "INTUNE_CLIENT_CERT_FILE" } as const;
export const INTUNE_CHECKS = [
  "policy_requires_encryption", "policy_requires_screen_lock", "policy_min_os",
  "device_compliant", "device_encrypted", "device_os_minimum", "device_last_sync",
] as const;
type C = (typeof INTUNE_CHECKS)[number];
const POLICY_CHECKS = ["policy_requires_encryption", "policy_requires_screen_lock", "policy_min_os"] as const;
const DEVICE_CHECKS = ["device_compliant", "device_encrypted", "device_os_minimum", "device_last_sync"] as const;

export const DEFAULTS = { syncDays: 14, maxLockMinutes: 15 } as const;
export const DEVICE_SELECT = "id,serialNumber,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime";

/** The laptop platforms whose compliance policies are judged: policy @odata.type → managedDevice operatingSystem. */
export const PLATFORMS = [
  { os: "Windows", type: "#microsoft.graph.windows10CompliancePolicy" },
  { os: "macOS", type: "#microsoft.graph.macOSCompliancePolicy" },
] as const;

const nextLink = (r: HttpResponse) => (isObj(r.body) ? str(r.body["@odata.nextLink"]) : undefined);
const values = (b: unknown) => (isObj(b) && Array.isArray(b.value) ? b.value : undefined);
const list = (api: RestApi, path: string, maxPages = 200) => getAll(api, path, values, nextLink, maxPages);

/** Builds a Graph client from INTUNE_* (or ENTRA_*) variables, or explains what is missing. */
export function intuneFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const pick = (k: keyof typeof INTUNE_ENV) => env[INTUNE_ENV[k]] ?? env[`ENTRA_${INTUNE_ENV[k].slice("INTUNE_".length)}`];
  const tenant = pick("tenant"), client = pick("client"), secret = pick("secret"), cert = pick("cert");
  if (!tenant || !client || (!secret && !cert)) return `${INTUNE_ENV.tenant}, ${INTUNE_ENV.client} and ${INTUNE_ENV.secret} or ${INTUNE_ENV.cert} (or their ENTRA_* equivalents) are not all set`;
  return entraFromEnv({ ENTRA_TENANT_ID: tenant, ENTRA_CLIENT_ID: client, ENTRA_CLIENT_SECRET: secret, ENTRA_CLIENT_CERT_FILE: cert }, fetchFn);
}

export interface IntuneOptions { syncDays: number; maxLockMinutes: number; minOs: Map<string, number[]> }

const sameOs = (a: unknown, b: string) => String(a ?? "").toLowerCase() === b.toLowerCase();

export async function intuneChecks(api: RestApi, tenant: string, o: IntuneOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("intune", `intune tenant ${tenant}`);

  // Devices first: they decide which platforms the policy checks must cover.
  const devR = await list(api, `/deviceManagement/managedDevices?$select=${DEVICE_SELECT}`);
  const devices = "error" in devR ? undefined : devR.items.filter(isObj);

  // Compliance policies of the laptop platforms, with their assignments.
  const polR = await list(api, "/deviceManagement/deviceCompliancePolicies", 50);
  const policies = new Map<string, { p: Obj; assigned: number | HttpResponse }[]>();
  if (!("error" in polR)) {
    for (const p of polR.items.filter(isObj)) {
      const plat = PLATFORMS.find((x) => x.type === p["@odata.type"]);
      if (!plat) continue;
      const a = await api.get(`/deviceManagement/deviceCompliancePolicies/${enc(String(p.id))}/assignments`);
      const vs = ok(a) ? values(a.body) : undefined;
      policies.set(plat.os, [...(policies.get(plat.os) ?? []), { p, assigned: vs ? vs.length : a }]);
    }
  }

  // Platforms judged: those with a managed device; when devices are unreadable, those with a policy.
  const platforms = PLATFORMS.filter((x) => (devices ? devices.some((d) => sameOs(d.operatingSystem, x.os)) : policies.has(x.os)));
  const policyFloor = new Map<string, number[]>();
  if ("error" in polR) for (const c of POLICY_CHECKS) out.skip(c, polR.error, "device compliance policies");
  else if (!platforms.length) out.skipAll(POLICY_CHECKS, devices ? "no Windows or macOS device is managed; no laptop compliance policy to judge" : "no Windows or macOS compliance policy, and managed devices are not readable to show whether one is needed");
  else {
    for (const plat of platforms) {
      const res = `intune tenant ${tenant} ${plat.os}`;
      const mine = policies.get(plat.os) ?? [];
      const unread = mine.find((x) => typeof x.assigned !== "number");
      const assigned = mine.filter((x) => typeof x.assigned === "number" && x.assigned > 0).map((x) => x.p);
      const n = `${mine.length} ${plat.os} compliance polic(ies), ${assigned.length} assigned`;
      const judge = (check: (typeof POLICY_CHECKS)[number], hit: (p: Obj) => boolean, need: string, show: (p: Obj) => string) => {
        const good = assigned.filter(hit);
        if (good.length) return out.add(check, "pass", `${n}; ${good.length} assigned polic(ies) ${need}: ${good.slice(0, 5).map((p) => `${label(p.displayName)} (${show(p)})`).join(", ")}`, res);
        if (unread) return out.add(check, "skipped", `${n}; no readable assigned policy ${need}, and the assignments of ${label(unread.p.displayName)} are not readable: ${why(unread.assigned as HttpResponse)}`, res);
        out.add(check, "fail", `${n}; none of the assigned ones ${need}`, res);
      };
      judge("policy_requires_encryption", (p) => p.storageRequireEncryption === true || (plat.os === "Windows" && p.bitLockerEnabled === true),
        plat.os === "Windows" ? "require encryption (storageRequireEncryption or bitLockerEnabled)" : "require encryption (storageRequireEncryption)",
        (p) => `storageRequireEncryption ${String(p.storageRequireEncryption)}${plat.os === "Windows" ? `, bitLockerEnabled ${String(p.bitLockerEnabled)}` : ""}`);
      judge("policy_requires_screen_lock", (p) => p.passwordRequired === true && typeof p.passwordMinutesOfInactivityBeforeLock === "number" && p.passwordMinutesOfInactivityBeforeLock >= 1 && p.passwordMinutesOfInactivityBeforeLock <= o.maxLockMinutes,
        `require a password and lock after 1 to ${o.maxLockMinutes} minutes idle (--intune-max-lock-minutes)`,
        (p) => `passwordRequired ${String(p.passwordRequired)}, passwordMinutesOfInactivityBeforeLock ${String(p.passwordMinutesOfInactivityBeforeLock)}`);
      const want = o.minOs.get(plat.os.toLowerCase()) ?? o.minOs.get("*");
      judge("policy_min_os", (p) => { const v = versionIn(p.osMinimumVersion); return !!v && (!want || cmpVersion(v, want) >= 0); },
        `set osMinimumVersion${want ? ` at or above ${showVersion(want)} (--intune-min-os)` : ""}`,
        (p) => `osMinimumVersion ${label(p.osMinimumVersion, 30)}`);
      const floors = assigned.map((p) => versionIn(p.osMinimumVersion)).filter((v): v is number[] => !!v);
      if (floors.length) policyFloor.set(plat.os.toLowerCase(), floors.reduce((a, b) => (cmpVersion(a, b) >= 0 ? a : b)));
    }
  }

  // Each managed device.
  if (!devices) { for (const c of DEVICE_CHECKS) out.skip(c, (devR as { error: HttpResponse }).error, "managed devices"); return out.results; }
  if (!devices.length) { out.skipAll(DEVICE_CHECKS, "Intune lists no managed device; nothing to judge"); return out.results; }
  const cap = !("error" in devR) && devR.truncated ? "; device list truncated at 200 pages" : "";
  for (const d of devices) {
    const res = deviceResource("intune device", d.id, d.serialNumber);
    const os = String(d.operatingSystem ?? "?");
    const where = ` (${os} ${String(d.osVersion ?? "version not reported")})`;

    const cs = str(d.complianceState);
    if (cs === "compliant") out.add("device_compliant", "pass", `complianceState is compliant${where}${cap}`, res);
    else if (cs && ["noncompliant", "conflict", "error", "inGracePeriod"].includes(cs)) out.add("device_compliant", "fail", `complianceState is ${cs}; compliant required${where}`, res);
    else out.add("device_compliant", "skipped", `complianceState is ${cs ?? "not reported"}, which does not show compliance${cs === "configManager" ? " (Configuration Manager holds it)" : ""}${where}`, res);

    if (typeof d.isEncrypted === "boolean") out.add("device_encrypted", d.isEncrypted ? "pass" : "fail", `isEncrypted is ${d.isEncrypted}${where}`, res);
    else out.add("device_encrypted", "skipped", `isEncrypted not reported${where}`, res);

    const floor = o.minOs.get(os.toLowerCase()) ?? policyFloor.get(os.toLowerCase()) ?? o.minOs.get("*");
    const fromOpt = o.minOs.has(os.toLowerCase()) || (!policyFloor.has(os.toLowerCase()) && o.minOs.has("*"));
    const have = versionIn(d.osVersion);
    if (!floor) out.add("device_os_minimum", "skipped", `no minimum OS version for ${os}: no assigned compliance policy sets osMinimumVersion and --intune-min-os names none${where}`, res);
    else if (!have) out.add("device_os_minimum", "skipped", `osVersion not reported${where}`, res);
    else {
      const okv = cmpVersion(have, floor) >= 0;
      out.add("device_os_minimum", okv ? "pass" : "fail", `osVersion ${showVersion(have)} ${okv ? "meets" : "is below"} the minimum ${showVersion(floor)} (${fromOpt ? "--intune-min-os" : "highest osMinimumVersion of the assigned compliance policies"})${where}`, res);
    }

    const age = ageDays(d.lastSyncDateTime, now);
    if (age === undefined) out.add("device_last_sync", "skipped", `lastSyncDateTime not reported${where}`, res);
    else out.add("device_last_sync", age <= o.syncDays ? "pass" : "fail", `last synced ${age} day(s) ago; at most ${o.syncDays} allowed (--intune-sync-days)${where}`, res);
  }
  return out.results;
}

export const intune: Source = {
  name: "intune",
  options: {
    "intune-sync-days": { type: "string", help: `days since a device's last Intune sync before device_last_sync fails (default ${DEFAULTS.syncDays})` },
    "intune-max-lock-minutes": { type: "string", help: `longest idle time before lock a compliance policy may allow (default ${DEFAULTS.maxLockMinutes})` },
    "intune-min-os": { type: "string", multiple: true, help: "<operatingSystem>=<version> floor, e.g. Windows=10.0.22631 or macOS=14.0 (repeatable; default the assigned policies' osMinimumVersion)" },
  },
  emits: INTUNE_CHECKS.map((c) => `intune.${c}`),
  describe: () => "Intune in the tenant INTUNE_TENANT_ID or ENTRA_TENANT_ID (Microsoft Graph v1.0)",
  async run(ctx: SourceContext) {
    const tenant = ctx.env[INTUNE_ENV.tenant] ?? ctx.env.ENTRA_TENANT_ID ?? "(unknown)";
    const given = ctx.clients.intune as RestApi | null | undefined;
    const built = given !== undefined ? given : intuneFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("intune", `intune tenant ${tenant}`);
      out.skipAll(INTUNE_CHECKS, typeof built === "string" ? built : "no Graph client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: IntuneOptions = {
      syncDays: posInt(ctx.opts["intune-sync-days"], DEFAULTS.syncDays),
      maxLockMinutes: posInt(ctx.opts["intune-max-lock-minutes"], DEFAULTS.maxLockMinutes),
      minOs: minOsOption(ctx.opts["intune-min-os"]),
    };
    return redact(await intuneChecks(api, tenant, o, ctx.now), [ctx.env[INTUNE_ENV.secret], ctx.env.ENTRA_CLIENT_SECRET]);
  },
};
