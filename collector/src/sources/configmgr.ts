// Microsoft Configuration Manager (ConfigMgr, formerly MECM / SCCM), read through the administration service, the
// SMS Provider's REST API, with GET only. On-premises: the collector runs on a domain-joined Windows host that reaches
// the SMS Provider over HTTPS (port 443), as a domain service account that is a Configuration Manager administrative
// user holding the built-in "Read-only Analyst" role. No secret is stored: the request carries that account's own
// Windows credentials.
//
// Pages, all read 2026-10-28 (learn.microsoft.com/intune/configmgr/..., "last updated" in brackets):
//   develop/adminservice/overview [2023-11-07]: an OData v4 REST API; the WMI route
//       https://<SMSProviderFQDN>/AdminService/wmi/<ClassName> "supports both GET and POST commands to over 700
//       classes"; class names are case-sensitive; "your user account needs to be an administrative user in
//       Configuration Manager. If you access the administration service via a cloud management gateway, you need to
//       have an account in Microsoft Entra ID."
//   develop/adminservice/usage [2022-10-04]: Invoke-RestMethod -Method 'Get' -Uri "https://SMSProviderFQDN/AdminService/
//       wmi/SMS_Site" -UseDefaultCredentials; $filter on the WMI route (SMS_Collection?$filter=startswith(Name,'All')
//       eq true); Power BI connects with "Windows Authentication".
//   develop/adminservice/set-up [2022-10-04]: the site's self-signed certificate is bound by default ("open HTTPS
//       port 443"), or a PKI certificate; the CMG endpoint replaces the FQDN for internet access.
//   develop/adminservice/faq [2026-08-28]: "the administration service currently doesn't publish an OpenAPI (Swagger)
//       document"; it "still uses Configuration Manager built-in role-based authorization".
//   core/understand/fundamentals-of-role-based-administration [2022-10-04]: Read-only Analyst "Grants permissions to
//       view all Configuration Manager objects."
//   core/servers/deploy/configure/configure-role-based-administration [2025-07-17]: Administration > Security >
//       Administrative Users > Add User or Group; "you can only specify domain users or domain security groups".
//   Classes (develop/reference/...):
//     SMS_CombinedDeviceResources [2022-10-04]: ResourceID, SerialNumber, IsClient, IsObsolete, Unknown,
//       LastActiveTime ("Comes from Client Health. Represents the last reported time the client was active"),
//       LastPolicyRequest, EPEnabled, EPAntivirusEnabled, EPAntivirusSignatureLastUpdateDateTime. Name, UserName and
//       UserDomainName come back too and are never read into a result.
//     SMS_SoftwareUpdate / SMS_SoftwareUpdateBase [2022-10-10]: CI_ID, IsDeployed ("true if the software update has
//       been deployed"), IsExpired, DatePosted ("when the software update was published"), SeverityName.
//     SMS_UpdateComplianceStatus [2022-10-10]: MachineID, CI_ID, ArticleID, Status 0 "Detection state unknown",
//       1 "Update is not required", 2 "Update is required", 3 "Update is installed".
//     SMS_G_System_CI_ComplianceState [2022-10-04]: ResourceID, CI_ID, LocalizedDisplayName, ComplianceState 0
//       "Compliance State Unknown", 1 "Compliant", 2 "Non-Compliant", 4 "Error".
//   Invoke-WebRequest (powershell/module/microsoft.powershell.utility/invoke-webrequest, 5.1) [ms.date 2026-01-20]:
//       -UseDefaultCredentials "uses the credentials of the current user to send the web request"; -UseBasicParsing
//       is "required when Internet Explorer is not installed"; -MaximumRedirection 0 "prevents all redirection".
//
// Why PowerShell: the administration service authenticates with Windows authentication on premises, which Node's
// fetch cannot send. Each GET runs Windows PowerShell 5.1 Invoke-WebRequest -Method Get -UseDefaultCredentials (the
// documented call, with the status code kept), started with -EncodedCommand so no quoting reaches a shell; the URL
// is passed base-64 inside the script and must stay under https://<CONFIGMGR_PROVIDER>/AdminService/. Through a
// cloud management gateway the service wants a Microsoft Entra token for a user account; no page documents an
// app-only (client credentials) token for it, so that path is not built.
//
// Left out, with the reason: disk encryption (BitLocker), firewall, OS version and screen lock. No documented server
// class carries them: BitLocker management reports (protect/deploy-use/bitlocker/view-reports [2021-11-23]) read
// hardware inventory classes the reference does not document, SMS_R_System and SMS_CombinedDeviceResources give
// only a free-form OS string, and firewall and screen lock are not inventoried by default. A configuration baseline
// that tests them shows in baselines_compliant. Paging: @odata.nextLink is followed when the service gives one; no
// page documents the administration service's paging or rate limits.

import { execFile } from "node:child_process";
import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter, getAll, isObj, realSleep, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead, DAY_MS } from "./readonly_http.ts";
import { deviceResource, label, posInt } from "./device_common.ts";
import { CMD, encode, type Run, type WinExec } from "./windows.ts";

export const CONFIGMGR_ENV = { provider: "CONFIGMGR_PROVIDER" } as const;
export const CONFIGMGR_CHECKS = ["client_installed", "last_seen", "antimalware_enabled", "antimalware_signatures_current", "updates_installed", "baselines_compliant"] as const;
type C = (typeof CONFIGMGR_CHECKS)[number];

export const DEFAULTS = { seenDays: 14, signatureDays: 7, patchDays: 30, maxDevices: 10000 } as const;
export const PATHS = {
  devices: "/SMS_CombinedDeviceResources",
  updates: "/SMS_SoftwareUpdate?$filter=IsDeployed eq true",
  updateStatus: "/SMS_UpdateComplianceStatus?$filter=Status eq 2 or Status eq 0",
  baselines: "/SMS_G_System_CI_ComplianceState",
} as const;

const FQDN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/** The PowerShell script for one GET: prints {"status":n,"body":"..."} as one ASCII line. */
export function getScript(url: string): string {
  return [
    "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'",
    `$u = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(url, "utf8").toString("base64")}'))`,
    "function out($o) { [regex]::Replace((ConvertTo-Json -InputObject $o -Compress -Depth 4), '[^\\x00-\\x7F]', { param($m) '\\u{0:x4}' -f [int][char]$m.Value }) }",
    "try { $r = Invoke-WebRequest -Uri $u -Method Get -UseDefaultCredentials -UseBasicParsing -MaximumRedirection 0 -Headers @{ Accept = 'application/json' }",
    "  out @{ status = [int]$r.StatusCode; body = [string]$r.Content } }",
    "catch { $resp = $_.Exception.Response",
    "  if ($resp) { $t = ''; try { $t = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch { }; out @{ status = [int]$resp.StatusCode; body = $t } }",
    "  else { out @{ status = 0; body = [string]$_.Exception.Message } } }",
  ].join("\n");
}

/** Like windows.ts realExec, with room for a large device list (256 MiB, five minutes). */
export const bigExec: WinExec = (cmd, args, timeoutMs = 300_000) => new Promise((resolve) => {
  execFile(cmd, [...args], { timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
    const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
    resolve({ code: e ? (typeof e.code === "number" ? e.code : -1) : 0, stdout: String(stdout), stderr: String(stderr), missing: e?.code === "ENOENT" });
  });
});

/** A GET-only administration service client that sends the running account's Windows credentials, or what is missing. */
export function configmgrFromEnv(env: NodeJS.ProcessEnv, exec: WinExec = bigExec, platform: string = process.platform): RestApi | string {
  const host = (env[CONFIGMGR_ENV.provider] ?? "").trim().replace(/^https:\/\//i, "").replace(/\/+$/, "");
  if (!host) return `${CONFIGMGR_ENV.provider} is not set (the SMS Provider's FQDN, e.g. cm01.corp.example.com)`;
  if (!FQDN.test(host)) return `${CONFIGMGR_ENV.provider} must be a host name, e.g. cm01.corp.example.com`;
  if (platform !== "win32") return "the administration service takes Windows authentication: run the collector on a domain-joined Windows host, as the Read-only Analyst service account";
  const base = `https://${host}/AdminService/wmi`;
  return {
    async get(url: string): Promise<HttpResponse> {
      const full = /^https?:\/\//i.test(url) ? url : `${base}${url}`;
      const t = new URL(full);
      // The account's credentials go with every request, so only this provider's administration service is asked.
      if (t.protocol !== "https:" || t.origin !== new URL(`https://${host}`).origin) return { status: 0, headers: {}, body: { message: `refused a request to ${t.origin}; this client reads https://${host} only` } };
      if (!/^\/adminservice\//i.test(t.pathname)) return { status: 0, headers: {}, body: { message: `refused ${t.pathname}: outside /AdminService/` } };
      const r: Run = await exec(CMD.powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encode(getScript(t.href))]);
      if (r.missing) return { status: 0, headers: {}, body: { message: "powershell.exe not found" } };
      let o: unknown;
      try { o = JSON.parse(r.stdout.trim().split(/\r?\n/).pop() ?? ""); } catch { return { status: 0, headers: {}, body: { message: `PowerShell gave no answer (exit ${r.code})` } }; }
      if (!isObj(o)) return { status: 0, headers: {}, body: { message: "PowerShell gave no answer" } };
      const status = Number(o.status) || 0;
      let body: unknown = o.body;
      try { body = typeof o.body === "string" && o.body ? JSON.parse(o.body) : o.body; } catch { /* keep text */ }
      if (status === 0) body = { message: String(o.body ?? "request failed").replace(/\s+/g, " ").slice(0, 300) };
      return { status, headers: {}, body };
    },
  };
}

const values = (b: unknown) => (isObj(b) && Array.isArray(b.value) ? b.value : undefined);
const nextLink = (r: HttpResponse) => (isObj(r.body) ? str(r.body["@odata.nextLink"]) : undefined);
const list = (api: RestApi, path: string, maxPages = 500) => getAll(api, path, values, nextLink, maxPages);

/** A date as the administration service may write it: ISO 8601, or a WMI DMTF datetime (yyyymmddHHMMSS.mmmmmm+UUU). */
export function cmDate(v: unknown): number | undefined {
  if (typeof v !== "string" || !v) return undefined;
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d{6}([+-])(\d{3})$/);
  if (m) {
    const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) - (m[7] === "+" ? 1 : -1) * Number(m[8]) * 60_000;
    return Number.isFinite(t) ? t : undefined;
  }
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : undefined;
}
const age = (v: unknown, now: Date) => { const t = cmDate(v); return t === undefined ? undefined : Math.floor((now.getTime() - t) / DAY_MS); };
const num = (v: unknown) => (typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v)) ? Number(v) : undefined);

export interface CmOptions { seenDays: number; signatureDays: number; patchDays: number; maxDevices: number }

export async function configmgrChecks(api: RestApi, provider: string, o: CmOptions, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("configmgr", `configmgr ${provider}`);
  const devR = await list(api, PATHS.devices);
  if ("error" in devR) { for (const c of CONFIGMGR_CHECKS) out.skip(c, devR.error, "SMS_CombinedDeviceResources"); return out.results; }
  const all = devR.items.filter(isObj).filter((d) => d.Unknown !== true && d.IsObsolete !== true);
  const devices = all.slice(0, o.maxDevices);
  const truncated = devR.truncated || all.length > o.maxDevices;
  if (!devices.length) { out.skipAll(CONFIGMGR_CHECKS, "Configuration Manager lists no device (unknown and obsolete records not counted); nothing to judge"); return out.results; }
  const cap = truncated ? `; only the first ${o.maxDevices} devices read (--configmgr-max-devices)` : "";

  // Software updates: the deployed ones, and each device's required or unknown rows for them.
  const updR = await list(api, PATHS.updates);
  const staR = "error" in updR ? undefined : await list(api, PATHS.updateStatus);
  const deployed = new Map<number, Obj>();
  if (!("error" in updR)) for (const u of updR.items.filter(isObj)) { const id = num(u.CI_ID); if (id !== undefined) deployed.set(id, u); }
  const rowsBy = new Map<number, Obj[]>();
  if (staR && !("error" in staR)) for (const s of staR.items.filter(isObj)) {
    const m = num(s.MachineID), ci = num(s.CI_ID);
    if (m === undefined || ci === undefined || !deployed.has(ci)) continue;
    rowsBy.set(m, [...(rowsBy.get(m) ?? []), s]);
  }
  const updErr = "error" in updR ? updR.error : staR && "error" in staR ? staR.error : undefined;

  const ciR = await list(api, PATHS.baselines);
  const ciBy = new Map<number, Obj[]>();
  if (!("error" in ciR)) for (const s of ciR.items.filter(isObj)) { const m = num(s.ResourceID); if (m !== undefined) ciBy.set(m, [...(ciBy.get(m) ?? []), s]); }

  const from = out.results.length;
  for (const d of devices) {
    const rid = num(d.ResourceID);
    const res = deviceResource("configmgr device", d.ResourceID, d.SerialNumber);
    const client = d.IsClient;

    if (typeof client === "boolean") out.add("client_installed", client ? "pass" : "fail", `IsClient is ${client}${client ? "" : ": discovered, but no Configuration Manager client reports from it"}${cap}`, res);
    else out.add("client_installed", "skipped", "IsClient not reported", res);
    if (client !== true) {
      for (const c of CONFIGMGR_CHECKS.filter((x) => x !== "client_installed")) out.add(c, "skipped", "no Configuration Manager client on this device, so nothing it reports", res);
      continue;
    }

    const seenField = d.LastActiveTime ? "LastActiveTime" : "LastPolicyRequest";
    const a = age(d[seenField], now);
    if (a === undefined) out.add("last_seen", "skipped", "neither LastActiveTime nor LastPolicyRequest is reported", res);
    else out.add("last_seen", a <= o.seenDays ? "pass" : "fail", `${seenField} ${a} day(s) ago; at most ${o.seenDays} allowed (--configmgr-seen-days)`, res);

    if (typeof d.EPEnabled !== "boolean") {
      for (const c of ["antimalware_enabled", "antimalware_signatures_current"] as const) out.add(c, "skipped", "Endpoint Protection status not reported (EPEnabled empty): Configuration Manager does not manage this device's antimalware", res);
    } else {
      const on = d.EPEnabled === true && d.EPAntivirusEnabled === true;
      out.add("antimalware_enabled", on ? "pass" : "fail", `EPEnabled is ${d.EPEnabled}, EPAntivirusEnabled is ${String(d.EPAntivirusEnabled)}`, res);
      const s = age(d.EPAntivirusSignatureLastUpdateDateTime, now);
      if (s === undefined) out.add("antimalware_signatures_current", "skipped", "EPAntivirusSignatureLastUpdateDateTime not reported", res);
      else out.add("antimalware_signatures_current", s <= o.signatureDays ? "pass" : "fail", `antivirus signatures updated ${s} day(s) ago; at most ${o.signatureDays} allowed (--configmgr-signature-days)`, res);
    }

    if (updErr) out.skip("updates_installed", updErr, "software update compliance");
    else {
      const rows = rid === undefined ? [] : rowsBy.get(rid) ?? [];
      const late = rows.filter((r) => num(r.Status) === 2).filter((r) => {
        const u = deployed.get(num(r.CI_ID)!)!;
        const posted = age(u.DatePosted, now);
        return u.IsExpired !== true && posted !== undefined && posted > o.patchDays;
      });
      const unknown = rows.filter((r) => num(r.Status) === 0);
      const show = (xs: Obj[]) => xs.slice(0, 5).map((r) => { const u = deployed.get(num(r.CI_ID)!)!; return `${label(r.ArticleID ? `KB${r.ArticleID}` : r.CI_ID, 20)} ${label(u.SeverityName, 20)}`; }).join(", ") + (xs.length > 5 ? `, and ${xs.length - 5} more` : "");
      if (late.length) out.add("updates_installed", "fail", `${late.length} deployed update(s) published more than ${o.patchDays} days ago are still required (--configmgr-patch-days): ${show(late)}`, res);
      else if (unknown.length) out.add("updates_installed", "skipped", `no late required update, but ${unknown.length} deployed update(s) have detection state unknown on this device`, res);
      else out.add("updates_installed", "pass", `no deployed update published more than ${o.patchDays} days ago is required (${deployed.size} deployed update(s) known to the site)`, res);
    }

    if ("error" in ciR) out.skip("baselines_compliant", ciR.error, "SMS_G_System_CI_ComplianceState", res);
    else {
      const rows = rid === undefined ? [] : ciBy.get(rid) ?? [];
      const bad = rows.filter((r) => [2, 4].includes(num(r.ComplianceState) ?? -1)), good = rows.filter((r) => num(r.ComplianceState) === 1);
      const names = (xs: Obj[]) => xs.slice(0, 5).map((r) => `${label(r.LocalizedDisplayName, 60)} ${num(r.ComplianceState) === 4 ? "Error" : "Non-Compliant"}`).join(", ") + (xs.length > 5 ? `, and ${xs.length - 5} more` : "");
      if (bad.length) out.add("baselines_compliant", "fail", `${bad.length} of ${rows.length} configuration item(s) not compliant: ${names(bad)}`, res);
      else if (good.length) out.add("baselines_compliant", "pass", `${good.length} of ${rows.length} configuration item(s) Compliant, none Non-Compliant or Error`, res);
      else out.add("baselines_compliant", "skipped", rows.length ? `${rows.length} configuration item(s), none with a known compliance state yet` : "no configuration baseline reports a state for this device", res);
    }
  }
  stampRead(out.results, from, listRead({ items: devices, truncated, pages: devR.pages }));
  return out.results;
}

export const configmgr: Source = {
  name: "configmgr",
  options: {
    "configmgr-seen-days": { type: "string", help: `days since a client was last active before last_seen fails (default ${DEFAULTS.seenDays})` },
    "configmgr-signature-days": { type: "string", help: `days since the Endpoint Protection antivirus signatures updated before antimalware_signatures_current fails (default ${DEFAULTS.signatureDays})` },
    "configmgr-patch-days": { type: "string", help: `days a deployed update may stay required after it was published (default ${DEFAULTS.patchDays})` },
    "configmgr-max-devices": { type: "string", help: `devices judged, at most (default ${DEFAULTS.maxDevices})` },
  },
  emits: CONFIGMGR_CHECKS.map((c) => `configmgr.${c}`),
  describe: () => "Configuration Manager site through the administration service on CONFIGMGR_PROVIDER (Windows authentication, Read-only Analyst)",
  async run(ctx: SourceContext) {
    const provider = (ctx.env[CONFIGMGR_ENV.provider] ?? "").trim().replace(/^https:\/\//i, "").replace(/\/+$/, "") || "(unknown)";
    const given = ctx.clients.configmgr as RestApi | null | undefined;
    const built = given !== undefined ? given : configmgrFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("configmgr", `configmgr ${provider}`);
      out.skipAll(CONFIGMGR_CHECKS, typeof built === "string" ? built : "no administration service client");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: CmOptions = {
      seenDays: posInt(ctx.opts["configmgr-seen-days"], DEFAULTS.seenDays),
      signatureDays: posInt(ctx.opts["configmgr-signature-days"], DEFAULTS.signatureDays),
      patchDays: posInt(ctx.opts["configmgr-patch-days"], DEFAULTS.patchDays),
      maxDevices: posInt(ctx.opts["configmgr-max-devices"], DEFAULTS.maxDevices),
    };
    // No secret is held: the Windows credentials never pass through the collector.
    return configmgrChecks(api, provider, o, ctx.now);
  },
};
