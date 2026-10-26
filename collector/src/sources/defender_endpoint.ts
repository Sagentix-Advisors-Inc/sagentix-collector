// Microsoft Defender for Endpoint over its own REST API (GET only), as an Entra app registration with
// WindowsDefenderATP application permissions and the client-credentials grant (the token path of entra.ts).
//
// Which API: Microsoft Graph has no device list or antivirus health resource for Defender for Endpoint. Graph
// replaces only advanced hunting (the old /api/advancedhunting/run is retired and stops returning data on
// 2027-02-01) and the legacy alerts API (retired 2026-10-15); neither is used here. Machines, antivirus health,
// vulnerabilities and recommendations stay on https://api.security.microsoft.com/api, version V1.0.
//   learn.microsoft.com/graph/api/resources/security-api-overview?view=graph-rest-1.0      ms.date 2026-01-21
//   learn.microsoft.com/defender-endpoint/api/exposed-apis-list                              ms.date 2025-03-21
// Token: scope https://api.securitycenter.microsoft.com/.default. Microsoft says some APIs still want a token for
// that legacy resource and answer 403 to any other audience, even on api.security.microsoft.com.
//   learn.microsoft.com/defender-endpoint/api/exposed-apis-create-app-webapp                 ms.date 2026-07-28
//
// Endpoint → application permission (each page's Permissions table), its limits, the fields used. All pages read
// 2026-10-20.
//   GET /api/machines                                       Machine.Read.All
//     get-machines (ms.date 2026-06-28): $top at most 10,000, $skip; 100 calls/minute, 1,500/hour; 404 when no
//     recent machine. machine (ms.date 2025-12-11): id, osPlatform, onboardingStatus (onboarded, CanBeOnboarded,
//     Unsupported, InsufficientInfo), healthStatus (Active, Inactive, ImpairedCommunication, NoSensorData,
//     NoSensorDataImpairedCommunication, Unknown), lastSeen (last full device report, typically every 24 hours),
//     exposureLevel (None, Low, Medium, High).
//   GET /api/deviceavinfo                                   Machine.Read.All
//     device-health-export-antivirus-health-report-api (ms.date 2026-02-05) and device-health-api-methods-properties
//     (ms.date 2025-11-11): paged by @odata.nextLink, $top at most 10,000; 30 calls/minute, 1,000/hour. Fields:
//     machineId, osKind (windows, mac, linux), avMode ("0" Active, "1" Passive, "2" Disabled, "3" or "" Other,
//     "4" EDRBlocked, "5" PassiveAudit), avIsSignatureUpToDate and avIsEngineUpToDate ("True", "False", "Unknown"),
//     lastSeenTime.
//   GET /api/vulnerabilities/machinesVulnerabilities        Vulnerability.Read.All
//     get-all-vulnerabilities-by-machines (ms.date 2025-11-16): $filter on severity, $top at most 10,000, $skip;
//     machineId, severity, fixingKbId. vulnerability (ms.date 2025-11-16): severity is Low, Medium, High or Critical.
//   GET /api/recommendations                                SecurityRecommendation.Read.All
//   GET /api/recommendations/{id}/machineReferences         SecurityRecommendation.Read.All
//     get-all-recommendations and get-recommendation-machines (ms.date 2025-11-13), recommendation (2025-11-13):
//     $filter on recommendationCategory (SecurityControls), recommendationName, status (Active, Exception),
//     exposedMachinesCount. tamper-protection-overview (ms.date 2026-09-09): Defender Vulnerability Management lists
//     devices without tamper protection under the recommendation "Turn on Tamper Protection".
//
// Not checked: real-time protection. No documented field of these APIs reports it (deviceavinfo gives the mode,
// not the real-time setting), so there is no check for it rather than a guess.
//
// Personal data: the machines and antivirus APIs offer no $select, so computerDnsName and lastIpAddress arrive in
// the response; no result ever carries them. A device is named by its Defender machine id.
//
// Env: DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID and DEFENDER_CLIENT_SECRET or DEFENDER_CLIENT_CERT_FILE; each falls
// back to its ENTRA_* twin, so one app registration can carry Graph and WindowsDefenderATP permissions.

import type { Result, Source, SourceContext } from "../types.ts";
import { entraFromEnv } from "./entra.ts";
import { Emitter, enc, firstIds, intOpt, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, deviceResource, posInt } from "./device_common.ts";

export const DEFENDER_BASE = "https://api.security.microsoft.com";
export const DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default";
export const DEFENDER_ENV = { tenant: "DEFENDER_TENANT_ID", client: "DEFENDER_CLIENT_ID", secret: "DEFENDER_CLIENT_SECRET", cert: "DEFENDER_CLIENT_CERT_FILE" } as const;
export const DEFENDER_CHECKS = [
  "device_onboarded", "sensor_healthy", "av_active_mode", "av_signatures_current",
  "high_exposure_devices", "critical_vulnerability_devices", "tamper_protection",
] as const;
type C = (typeof DEFENDER_CHECKS)[number];
const MACHINE_CHECKS = ["device_onboarded", "sensor_healthy", "high_exposure_devices"] as const;
const AV_CHECKS = ["av_active_mode", "av_signatures_current"] as const;

export const DEFAULTS = { seenDays: 14, maxExposure: 0, maxDevices: 10_000 } as const;
/** The largest $top the list APIs accept. */
export const PAGE_MAX = 10_000;
/** Rows of critical vulnerabilities read at most (one row per device, CVE and software). */
export const MAX_VULN_ROWS = 200_000;
const TAMPER = /\btamper protection\b/i;

const nextLink = (r: HttpResponse) => (isObj(r.body) ? str(r.body["@odata.nextLink"]) : undefined);
const values = (b: unknown) => (isObj(b) && Array.isArray(b.value) ? b.value : undefined);

/**
 * Every item of a list, at most `maxItems`. Follows @odata.nextLink when the API gives one (deviceavinfo), else
 * pages with $top and $skip while a page comes back full (machines, vulnerabilities, recommendations).
 */
export async function pages(api: RestApi, path: string, pageSize: number, maxItems: number, emptyOn404 = false):
  Promise<{ items: Obj[]; truncated: boolean } | { error: HttpResponse }> {
  const size = Math.max(1, Math.min(PAGE_MAX, pageSize, maxItems));
  const at = (skip: number) => `${path}${path.includes("?") ? "&" : "?"}$top=${size}&$skip=${skip}`;
  const out: Obj[] = [];
  let url: string | undefined = at(0), skip = 0;
  for (let page = 0; url; page++) {
    if (page >= 1000) return { items: out, truncated: true };
    const r = await api.get(url);
    if (emptyOn404 && page === 0 && r.status === 404) return { items: [], truncated: false };
    const got = ok(r) ? values(r.body) : undefined;
    if (!got) return { error: r };
    out.push(...got.filter(isObj));
    const next = nextLink(r);
    const more = !!next || got.length >= size;
    if (out.length >= maxItems) return { items: out.slice(0, maxItems), truncated: more || out.length > maxItems };
    skip += got.length;
    url = next ?? (got.length >= size ? at(skip) : undefined);
  }
  return { items: out, truncated: false };
}

/** Builds a Defender for Endpoint client from DEFENDER_* (or ENTRA_*) variables, or explains what is missing. */
export function defenderFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const pick = (k: keyof typeof DEFENDER_ENV) => env[DEFENDER_ENV[k]] ?? env[`ENTRA_${DEFENDER_ENV[k].slice("DEFENDER_".length)}`];
  const tenant = pick("tenant"), client = pick("client"), secret = pick("secret"), cert = pick("cert");
  if (!tenant || !client || (!secret && !cert)) return `${DEFENDER_ENV.tenant}, ${DEFENDER_ENV.client} and ${DEFENDER_ENV.secret} or ${DEFENDER_ENV.cert} (or their ENTRA_* equivalents) are not all set`;
  return entraFromEnv({ ENTRA_TENANT_ID: tenant, ENTRA_CLIENT_ID: client, ENTRA_CLIENT_SECRET: secret, ENTRA_CLIENT_CERT_FILE: cert }, fetchFn,
    { base: DEFENDER_BASE, scope: DEFENDER_SCOPE });
}

export interface DefenderOptions { seenDays: number; maxExposure: number; maxDevices: number; allowPassive: boolean; pageSize?: number }

const AV_MODE: Record<string, string> = { "0": "Active", "1": "Passive", "2": "Disabled", "3": "Other", "": "Other", "4": "EDRBlocked", "5": "PassiveAudit" };
const PASSIVE = new Set(["1", "4", "5"]);
const SENSOR_BAD = new Set(["inactive", "impairedcommunication", "nosensordata", "nosensordataimpairedcommunication"]);
const low = (v: unknown) => String(v ?? "").toLowerCase();
const onboarding = (m: Obj) => str(m.onboardingStatus) ?? str(m.onboardingstatus);
const devRes = (id: unknown) => deviceResource("defender device", id, undefined);

export async function defenderChecks(api: RestApi, tenant: string, o: DefenderOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("defender_endpoint", `defender tenant ${tenant}`);
  const size = o.pageSize ?? PAGE_MAX;
  const capped = (t: boolean) => (t ? `; list capped at ${o.maxDevices} (--defender-max-devices)` : "");

  // Machines: onboarding, sensor health, exposure level.
  const mR = await pages(api, "/api/machines", size, o.maxDevices, true);
  if ("error" in mR) for (const c of MACHINE_CHECKS) out.skip(c, mR.error, "machines");
  else if (!mR.items.length) out.skipAll(MACHINE_CHECKS, "Defender for Endpoint lists no machine seen within the retention period; nothing to judge");
  else {
    const cap = capped(mR.truncated), fromM = out.results.length;
    const onboarded: Obj[] = [];
    for (const m of mR.items) {
      const res = devRes(m.id), where = ` (${String(m.osPlatform ?? "platform not reported")})`;
      const st = onboarding(m);
      if (low(st) === "onboarded") { onboarded.push(m); out.add("device_onboarded", "pass", `onboardingStatus is ${st}${where}${cap}`, res); }
      else if (low(st) === "canbeonboarded") out.add("device_onboarded", "fail", `onboardingStatus is ${st}: discovered on the network but not onboarded${where}`, res);
      else out.add("device_onboarded", "skipped", `onboardingStatus is ${st ?? "not reported"}, which does not show whether the device should be onboarded${where}`, res);
    }
    if (!onboarded.length) out.skipAll(["sensor_healthy", "high_exposure_devices"], `no onboarded machine among ${mR.items.length} listed`);
    else {
      for (const m of onboarded) {
        const res = devRes(m.id), where = ` (${String(m.osPlatform ?? "platform not reported")})`;
        const hs = str(m.healthStatus), age = ageDays(m.lastSeen, now);
        if (hs && SENSOR_BAD.has(low(hs))) out.add("sensor_healthy", "fail", `healthStatus is ${hs}; Active required${age === undefined ? "" : `, last full report ${age} day(s) ago`}${where}`, res);
        else if (low(hs) !== "active") out.add("sensor_healthy", "skipped", `healthStatus is ${hs ?? "not reported"}, which does not show the sensor's health${where}`, res);
        else if (age === undefined) out.add("sensor_healthy", "skipped", `healthStatus is Active but lastSeen is not reported${where}`, res);
        else out.add("sensor_healthy", age <= o.seenDays ? "pass" : "fail", `healthStatus is Active; last full report ${age} day(s) ago, at most ${o.seenDays} allowed (--defender-seen-days)${where}`, res);
      }
      const high = onboarded.filter((m) => low(m.exposureLevel) === "high").map((m) => String(m.id));
      const known = onboarded.filter((m) => typeof m.exposureLevel === "string" && m.exposureLevel).length;
      const n = `${high.length} of ${onboarded.length} onboarded machine(s) at exposureLevel High; at most ${o.maxExposure} allowed (--defender-max-exposure)`;
      if (!known) out.add("high_exposure_devices", "skipped", `no onboarded machine reports an exposureLevel (Defender Vulnerability Management may not be licensed)${cap}`);
      else if (high.length > o.maxExposure) out.add("high_exposure_devices", "fail", `${n}${firstIds(high)}${cap}`);
      else out.add("high_exposure_devices", mR.truncated ? "skipped" : "pass", `${n}; ${onboarded.length - known} report no level${mR.truncated ? `; the machine list was capped at ${o.maxDevices}, so the count is incomplete` : ""}`);
    }
    stampRead(out.results, fromM, listRead(mR));   // a capped machine list leaves machines unseen
  }

  // Antivirus health, one result per machine (the export holds one row per machine and state; the latest wins).
  const aR = await pages(api, "/api/deviceavinfo", size, o.maxDevices);
  if ("error" in aR) for (const c of AV_CHECKS) out.skip(c, aR.error, "antivirus health (deviceavinfo)");
  else if (!aR.items.length) out.skipAll(AV_CHECKS, "the antivirus health export lists no device (Microsoft Defender Antivirus reports none)");
  else {
    const cap = capped(aR.truncated), fromA = out.results.length;
    const latest = new Map<string, Obj>();
    for (const r of aR.items) {
      const id = String(r.machineId ?? r.id ?? "?");
      const prev = latest.get(id);
      if (!prev || String(r.lastSeenTime ?? "") > String(prev.lastSeenTime ?? "")) latest.set(id, r);
    }
    for (const [id, r] of latest) {
      const res = devRes(id), where = ` (${String(r.osKind ?? "os not reported")})`;
      const mode = r.avMode === undefined || r.avMode === null ? undefined : String(r.avMode);
      const name = mode === undefined ? undefined : AV_MODE[mode];
      if (mode === "0") out.add("av_active_mode", "pass", `avMode 0 (Active)${where}${cap}`, res);
      else if (mode !== undefined && PASSIVE.has(mode)) out.add("av_active_mode", o.allowPassive ? "pass" : "fail",
        `avMode ${mode} (${name}): Microsoft Defender Antivirus is not the active antivirus${o.allowPassive ? "; accepted by --defender-allow-passive (another antivirus is primary)" : "; Active required, or --defender-allow-passive where another antivirus is primary"}${where}`, res);
      else if (mode === "2") out.add("av_active_mode", "fail", `avMode 2 (Disabled)${where}`, res);
      else out.add("av_active_mode", "skipped", `avMode ${mode === undefined ? "not reported" : `"${mode}" (${name ?? "undocumented value"})`}, which does not show the antivirus mode${where}`, res);

      const sig = low(r.avIsSignatureUpToDate), eng = low(r.avIsEngineUpToDate);
      const seen = `avIsSignatureUpToDate ${String(r.avIsSignatureUpToDate ?? "not reported")}, avIsEngineUpToDate ${String(r.avIsEngineUpToDate ?? "not reported")}`;
      if (sig === "false" || eng === "false") out.add("av_signatures_current", "fail", `${seen}; both True required${where}`, res);
      else if (sig === "true" && eng === "true") out.add("av_signatures_current", "pass", `${seen}${where}`, res);
      else out.add("av_signatures_current", "skipped", `${seen}, which does not show whether they are current${where}`, res);
    }
    stampRead(out.results, fromA, listRead(aR));
  }

  // Devices with at least one critical vulnerability.
  const vR = await pages(api, `/api/vulnerabilities/machinesVulnerabilities?$filter=${enc("severity eq 'Critical'")}`, size, MAX_VULN_ROWS);
  if ("error" in vR) out.skip("critical_vulnerability_devices", vR.error, "vulnerabilities by machine");
  else {
    const rows = vR.items.filter((v) => low(v.severity) === "critical");
    const devs = [...new Set(rows.map((v) => String(v.machineId ?? "?")))];
    const kb = new Set(rows.filter((v) => str(v.fixingKbId)).map((v) => String(v.machineId ?? "?")));
    const n = `${devs.length} device(s) with at least one critical vulnerability (${kb.size} of them fixed by a Microsoft update not yet installed, fixingKbId); at most ${o.maxExposure} allowed (--defender-max-exposure)`;
    if (devs.length > o.maxExposure) out.add("critical_vulnerability_devices", "fail", `${n}${firstIds(devs)}`);
    else if (vR.truncated) out.add("critical_vulnerability_devices", "skipped", `${n}, but the list stopped at ${MAX_VULN_ROWS} rows, so the count is incomplete`);
    else out.add("critical_vulnerability_devices", "pass", n, out.resource, listRead(vR));
  }

  // Tamper protection, from the "Turn on Tamper Protection" security recommendation.
  const rR = await pages(api, `/api/recommendations?$filter=${enc("recommendationCategory eq 'SecurityControls'")}`, size, 50_000);
  if ("error" in rR) out.skip("tamper_protection", rR.error, "security recommendations");
  else {
    const rec = rR.items.find((x) => TAMPER.test(String(x.recommendationName ?? "")));
    const exposed = rec && typeof rec.exposedMachinesCount === "number" ? rec.exposedMachinesCount : undefined;
    if (!rec) out.add("tamper_protection", "skipped", `no security recommendation named "Turn on Tamper Protection" among ${rR.items.length} security-control recommendation(s); its absence does not show tamper protection is on`);
    else if (exposed === undefined) out.add("tamper_protection", "skipped", `the "Turn on Tamper Protection" recommendation reports no exposedMachinesCount`);
    else if (exposed === 0) out.add("tamper_protection", "pass", `"Turn on Tamper Protection" lists 0 exposed devices (status ${String(rec.status ?? "not reported")})`);
    else {
      const refs = await pages(api, `/api/recommendations/${enc(String(rec.id))}/machineReferences`, size, 50);
      const ids = "error" in refs ? [] : refs.items.map((m) => String(m.id));
      out.add("tamper_protection", "fail", `"Turn on Tamper Protection" lists ${exposed} exposed device(s) without tamper protection${low(rec.status) === "exception" ? " (status Exception: an exception covers it, the devices are still exposed)" : ""}${firstIds(ids)}`);
    }
  }
  return out.results;
}

export const defender_endpoint: Source = {
  name: "defender_endpoint",
  options: {
    "defender-seen-days": { type: "string", help: `days since a machine's last full Defender report before sensor_healthy fails (default ${DEFAULTS.seenDays})` },
    "defender-max-exposure": { type: "string", help: `most devices allowed at exposureLevel High, and most with a critical vulnerability (default ${DEFAULTS.maxExposure})` },
    "defender-max-devices": { type: "string", help: `most machines (and antivirus rows) read (default ${DEFAULTS.maxDevices})` },
    "defender-allow-passive": { type: "boolean", help: "accept Microsoft Defender Antivirus in passive or EDR block mode, where another antivirus is primary" },
  },
  emits: DEFENDER_CHECKS.map((c) => `defender_endpoint.${c}`),
  describe: () => "Defender for Endpoint in the tenant DEFENDER_TENANT_ID or ENTRA_TENANT_ID (api.security.microsoft.com)",
  async run(ctx: SourceContext) {
    const tenant = ctx.env[DEFENDER_ENV.tenant] ?? ctx.env.ENTRA_TENANT_ID ?? "(unknown)";
    const given = ctx.clients.defender_endpoint as RestApi | null | undefined;
    const built = given !== undefined ? given : defenderFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("defender_endpoint", `defender tenant ${tenant}`);
      out.skipAll(DEFENDER_CHECKS, typeof built === "string" ? built : "no Defender for Endpoint client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: DefenderOptions = {
      seenDays: posInt(ctx.opts["defender-seen-days"], DEFAULTS.seenDays),
      maxExposure: intOpt(ctx.opts["defender-max-exposure"], DEFAULTS.maxExposure),
      maxDevices: posInt(ctx.opts["defender-max-devices"], DEFAULTS.maxDevices),
      allowPassive: ctx.opts["defender-allow-passive"] === true,
    };
    return redact(await defenderChecks(api, tenant, o, ctx.now), [ctx.env[DEFENDER_ENV.secret], ctx.env.ENTRA_CLIENT_SECRET]);
  },
};
