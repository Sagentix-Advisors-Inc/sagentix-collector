// The Windows 10 or 11 PC the collector runs on, read through Windows' own tools: for a firm with no device
// management (no Intune), often a few laptops each run by its owner. The Windows counterpart of macos.ts. Runs as
// the signed-in user with no elevation, no credential and no network call; nothing is written to the machine.
//
// Every query is Windows PowerShell 5.1 (%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe, part of
// Windows 10 and 11) started with -NoProfile -NonInteractive -EncodedCommand (the script as base-64 UTF-16LE, so
// no quoting reaches a shell), plus whoami.exe. Each script prints one line of JSON: {"ok":true,"value":…} or
// {"ok":false,"type":…,"id":…,"hresult":…,"message":…} from its catch block; dates are written as ISO 8601 inside
// the script, so no locale or time zone reaches the parser. Non-ASCII characters are escaped (\uXXXX) before
// printing, since the pipe carries the console code page.
//
// Written from Microsoft's documentation, read 2026-10-20 (each page's "updated" date in brackets). Sagentix ran
// it on 2026-10-20 on a Windows 11 Pro 25H2 PC (build 26200, a Parallels VM), as a standard user and elevated, and
// checked each result against the same cmdlets run by hand; test/windows.test.ts uses outputs shaped from these pages' examples.
//   Get-CimInstance Win32_OperatingSystem      Version "10.0.26200", BuildNumber "26200" (string)
//       learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem [2023-11-09]
//   Get-CimInstance Win32_BIOS                 SerialNumber (the PC's serial; the only identifier sent)
//       learn.microsoft.com/windows/win32/cimwin32prov/win32-bios [2023-11-09]
//   Get-BitLockerVolume -MountPoint $env:SystemDrive    VolumeStatus "FullyEncrypted" | "FullyDecrypted" |
//       "EncryptionInProgress" …; ProtectionStatus "On" | "Off"; EncryptionPercentage; EncryptionMethod "XtsAes128" …
//       learn.microsoft.com/powershell/module/bitlocker/get-bitlockervolume [2025-05-14]. It reads
//       Win32_EncryptableVolume, whose page says "You must have administrator privileges" and gives ProtectionStatus
//       1 = "PROTECTION ON: the volume is fully encrypted and the encryption key ... is not available in the clear"
//       (learn.microsoft.com/windows/win32/secprov/win32-encryptablevolume [2024-01-03]). No documented read works
//       without elevation (manage-bde -status uses the same provider), so a standard user's run skips this check.
//   Get-MpComputerStatus                       AMRunningMode "Normal" | "Passive" | "EDR Block Mode" | "SxS Passive Mode";
//       AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled (boolean); AntivirusSignatureLastUpdated (local
//       time, null if never); AntivirusSignatureAge (days, 65535 if never)
//       learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus [2025-05-14];
//       fields: learn.microsoft.com/previous-versions/windows/desktop/defender/msft-mpcomputerstatus [2021-10-26];
//       modes: learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows [2026-09-08]. With another
//       antivirus installed on a PC not onboarded to Defender for Endpoint, Defender goes to "disabled mode"
//       automatically (learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-compatibility [2026-09-11]).
//   Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct   displayName only. Microsoft has no
//       reference page for this class (Learn search, 2026-10-20), and productState is undocumented; the documented
//       Windows Security Center API (IWSCProductList, WSC_SECURITY_PRODUCT_STATE, learn.microsoft.com/windows/win32/
//       api/iwscapi [2024-02-22]) inherits IUnknown and cannot be called from a script. So a third-party antivirus
//       is named, and whether it is on is left to a person.
//   Get-NetFirewallProfile -PolicyStore ActiveStore    one per profile (Domain, Private, Public); Enabled is uint16,
//       "Whether the firewall is enabled on this profile". ActiveStore is "the sum of all policy stores", Group
//       Policy included; without -PolicyStore the cmdlet reads only the local persistent store.
//       learn.microsoft.com/powershell/module/netsecurity/get-netfirewallprofile [2025-05-14];
//       learn.microsoft.com/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallprofile [2026-04-15]
//   Registry, read with Get-ItemProperty (learn.microsoft.com/powershell/module/microsoft.powershell.management/
//   get-itemproperty [2026-06-15]):
//     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System  InactivityTimeoutSecs (REG_DWORD, seconds;
//       0 or absent = never): "Interactive logon: Machine inactivity limit". Set, it locks "when inactive time
//       exceeds the inactivity limit, but also when the screensaver activates or when the display turns off".
//       learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-
//       settings/interactive-logon-machine-inactivity-limit [2026-04-27]
//     HKCU\Control Panel\Desktop  ScreenSaveActive, ScreenSaverIsSecure ("1"/"0"), ScreenSaveTimeOut (seconds), REG_SZ;
//       the same names under HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop when set by policy, which
//       "have precedence". learn.microsoft.com/troubleshoot/windows-server/remote/troubleshoot-unexpected-rds-session-
//       locks-or-disconnections [2026-02-19]; policy key and names: learn.microsoft.com/windows/client-management/
//       mdm/policy-csp-admx-controlpaneldisplay [2025-03-12]
//     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon  AutoAdminLogon only ("1" = automatic sign-in).
//       DefaultUserName and DefaultPassword sit beside it and are never read.
//       learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon [2026-02-19]
//     HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU  NoAutoUpdate (1 = Automatic Updates disabled),
//       AUOptions (1 = disabled, 2 = notify of download and installation, 3 and 4 download automatically).
//       learn.microsoft.com/windows/deployment/update/waas-wu-settings [2026-02-12]
//   New-Object -ComObject Microsoft.Update.AutoUpdate   (the program identifier the Windows Update Agent page names)
//       .ServiceEnabled: "whether all the components that Automatic Updates requires are available";
//       .Results.LastInstallationSuccessDate: "the last time and UTC date when Automatic Updates successfully
//       installed any updates". learn.microsoft.com/windows/win32/api/wuapi/nn-wuapi-iautomaticupdates2 and
//       nf-wuapi-iautomaticupdatesresults-get_lastinstallationsuccessdate [2024-02-22]. "Any updates" includes
//       Defender's daily definitions, so this date alone can look fresh on a PC whose Windows updates stall.
//   Get-HotFix                                 the newest InstalledOn (HotFixID kept, InstalledBy never read). Weak, by
//       Microsoft's own words: Win32_QuickFixEngineering "returns only the updates supplied by Component Based
//       Servicing"; updates from MSI "or the Windows update site ... are not returned", and InstalledOn may be empty.
//       learn.microsoft.com/powershell/module/microsoft.powershell.management/get-hotfix [2026-06-15];
//       learn.microsoft.com/windows/win32/cimwin32prov/win32-quickfixengineering [2023-11-09]. os_updates_installed
//       therefore asks both dates to be recent: the agent's date for "Windows Update is installing", the CBS
//       package date so that definition updates alone cannot pass it.
//   Get-CimInstance Win32_Service -Filter Name='wuauserv'   StartMode "Auto" | "Manual" | "Disabled"
//       learn.microsoft.com/windows/win32/cimwin32prov/win32-service [2023-11-09]
//   Minimum build: Windows release information lists, per version, the end of updates for Home and Pro. On
//       2026-10-20 Windows 11 24H2 (26100) had reached it and 25H2 (26200) runs to 2027-10-12, so the default
//       --windows-min-build is 26200; Enterprise and Education 24H2 is updated to 2027-10-12, and such a firm lowers
//       the option. Windows 10 22H2 (19045) is past its end of updates; Extended Security Updates enrolment is not
//       readable here. learn.microsoft.com/windows/release-health/windows11-release-information and
//       release-information [both 2026-10-13]
//   whoami.exe /groups /fo csv /nh             "Group Name","Type","SID","Attributes" per group in the signed-in
//       user's token; the SID column only (names and attributes are localized). learn.microsoft.com/windows-server/
//       administration/windows-commands/whoami [2026-02-16]. S-1-5-32-544 is the built-in Administrators group
//       (learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers [2026-10-20]); a
//       member's token holds it elevated or not, nested groups included.
//   (Get-LocalGroupMember -SID S-1-5-32-544).Count    how many accounts and groups are local administrators; no
//       name is read. learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember [2025-07-24]
//   Confirm-SecureBootUEFI                     True | False; "Cmdlet not supported on this platform" on a BIOS PC;
//       "This cmdlet requires that Windows PowerShell be run in administrator mode", so a standard user's run skips.
//       learn.microsoft.com/powershell/module/secureboot/confirm-securebootuefi [2025-05-14]
//   Shell: -EncodedCommand learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
//       [2025-09-29]; ConvertTo-Json -Compress -Depth (default depth 2) .../microsoft.powershell.utility/convertto-json
//       [2026-06-16]; Get-CimInstance (default namespace root/CIMV2) .../cimcmdlets/get-ciminstance [2026-01-16].
//
// Needs an administrator: disk_encryption and secure_boot. A standard user's daily run reports them as skipped,
// naming the reason; running the collector once from an elevated PowerShell fills them. Nothing else needs it.
//
// Personal data: the PC is named by its BIOS serial only, never its computer name or a user name. Error messages
// are cut short and have any C:\Users\<name> path and email address removed before they go into a result.

import { execFile } from "node:child_process";
import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter } from "./readonly_http.ts";
import { ageDays, cleanSerial, posInt } from "./device_common.ts";

export const WINDOWS_CHECKS = ["disk_encryption", "os_updates_installed", "automatic_updates", "os_supported", "malware_protection",
  "malware_definitions_current", "firewall", "screen_lock", "auto_login_off", "user_not_admin", "secure_boot"] as const;
type C = (typeof WINDOWS_CHECKS)[number];

export const DEFAULTS = { lockSeconds: 900, signatureDays: 7, updateDays: 35, minBuild: 26200 } as const;
export const ADMINISTRATORS_SID = "S-1-5-32-544";

export interface Run { code: number; stdout: string; stderr: string; missing?: boolean }
/** Runs one fixed program with fixed arguments, never through a shell. */
export type WinExec = (cmd: string, args: readonly string[], timeoutMs?: number) => Promise<Run>;

const ROOT = (process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows").replace(/[\\/]+$/, "");
export const CMD = {
  powershell: `${ROOT}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`,
  whoami: `${ROOT}\\System32\\whoami.exe`,
} as const;

export const realExec: WinExec = (cmd, args, timeoutMs = 60_000) => new Promise((resolve) => {
  execFile(cmd, [...args], { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
    const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
    resolve({ code: e ? (typeof e.code === "number" ? e.code : -1) : 0, stdout: String(stdout), stderr: String(stderr), missing: e?.code === "ENOENT" });
  });
});

/** The scripts, one per reading. Each body's last value is what the wrapper prints as `value`. */
export const QUERIES = {
  os: `$o = Get-CimInstance -ClassName Win32_OperatingSystem
$b = Get-CimInstance -ClassName Win32_BIOS
[pscustomobject]@{ version = [string]$o.Version; build = [string]$o.BuildNumber; serial = [string]$b.SerialNumber }`,
  bitlocker: `$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
[pscustomobject]@{ volumeStatus = [string]$v.VolumeStatus; protectionStatus = [string]$v.ProtectionStatus; percent = $v.EncryptionPercentage; method = [string]$v.EncryptionMethod }`,
  defender: `$s = Get-MpComputerStatus
$u = $s.AntivirusSignatureLastUpdated
[pscustomobject]@{ mode = [string]$s.AMRunningMode; amService = [bool]$s.AMServiceEnabled; antivirus = [bool]$s.AntivirusEnabled
  realTime = [bool]$s.RealTimeProtectionEnabled; signatureAge = $s.AntivirusSignatureAge; signatureVersion = [string]$s.AntivirusSignatureVersion
  signatureUpdated = $(if ($u) { $u.ToUniversalTime().ToString('o') } else { $null }) }`,
  antivirus: `@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [string]$_.displayName })`,
  firewall: `@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; enabled = [int]$_.Enabled } })`,
  screenLock: `function v($k, $n) { $i = Get-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue; if ($i) { [string]$i.$n } else { $null } }
$m = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
$p = 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop'
$u = 'HKCU:\\Control Panel\\Desktop'
[pscustomobject]@{ inactivity = v $m 'InactivityTimeoutSecs'
  policyActive = v $p 'ScreenSaveActive'; policySecure = v $p 'ScreenSaverIsSecure'; policyTimeout = v $p 'ScreenSaveTimeOut'
  userActive = v $u 'ScreenSaveActive'; userSecure = v $u 'ScreenSaverIsSecure'; userTimeout = v $u 'ScreenSaveTimeOut' }`,
  autoLogon: `$i = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue
$(if ($i) { [string]$i.AutoAdminLogon } else { $null })`,
  wua: `$au = New-Object -ComObject Microsoft.Update.AutoUpdate
$d = $au.Results.LastInstallationSuccessDate
[pscustomobject]@{ serviceEnabled = [bool]$au.ServiceEnabled; lastInstall = $(if ($d) { ([datetime]$d).ToString('yyyy-MM-ddTHH:mm:ss') + 'Z' } else { $null }) }`,
  hotfix: `$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object -Property InstalledOn, HotFixID | Select-Object -Last 1
$(if ($h) { [pscustomobject]@{ id = [string]$h.HotFixID; installedOn = $h.InstalledOn.ToString('yyyy-MM-dd') } } else { $null })`,
  updatePolicy: `$a = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue
$s = Get-CimInstance -ClassName Win32_Service -Filter 'Name=''wuauserv'''
[pscustomobject]@{ startMode = [string]$s.StartMode
  noAutoUpdate = $(if ($a -and $null -ne $a.NoAutoUpdate) { [int]$a.NoAutoUpdate } else { $null })
  auOptions = $(if ($a -and $null -ne $a.AUOptions) { [int]$a.AUOptions } else { $null }) }`,
  adminCount: `@(Get-LocalGroupMember -SID '${ADMINISTRATORS_SID}').Count`,
  secureBoot: `[bool](Confirm-SecureBootUEFI)`,
} as const;
export type Query = keyof typeof QUERIES;
/** The cmdlet each query depends on, for a "not on this PC" reason. */
const NEEDS: Record<Query, string> = {
  os: "Get-CimInstance", bitlocker: "Get-BitLockerVolume", defender: "Get-MpComputerStatus", antivirus: "Get-CimInstance root/SecurityCenter2",
  firewall: "Get-NetFirewallProfile", screenLock: "Get-ItemProperty", autoLogon: "Get-ItemProperty", wua: "Microsoft.Update.AutoUpdate",
  hotfix: "Get-HotFix", updatePolicy: "Get-CimInstance Win32_Service", adminCount: "Get-LocalGroupMember", secureBoot: "Confirm-SecureBootUEFI",
};

/** The full script for a query: its body inside a try/catch that prints one ASCII line of JSON. */
export function script(q: Query): string {
  return [
    "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'",
    "function out($o) { [regex]::Replace((ConvertTo-Json -InputObject $o -Compress -Depth 4), '[^\\x00-\\x7F]', { param($m) '\\u{0:x4}' -f [int][char]$m.Value }) }",
    `try { $v = & {\n${QUERIES[q]}\n}; out @{ ok = $true; value = $v } }`,
    "catch { $e = $_.Exception; out @{ ok = $false; type = $e.GetType().FullName; id = [string]$_.FullyQualifiedErrorId; hresult = $e.HResult; message = [string]$e.Message } }",
  ].join("\n");
}
/** powershell.exe -EncodedCommand takes the script as base-64 UTF-16LE. */
export const encode = (s: string) => Buffer.from(s, "utf16le").toString("base64");
export const psArgs = (q: Query) => ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encode(script(q))];

export type Reading<T> = { ok: true; value: T } | { ok: false; why: string; denied: boolean; missing: boolean };

const ACCESS_DENIED_HRESULTS = new Set([-2147024891 /* 0x80070005 E_ACCESSDENIED */, -2147217405 /* 0x80041003 WBEM_E_ACCESS_DENIED */]);
const NOT_REGISTERED_HRESULTS = new Set([-2147221164 /* 0x80040154 REGDB_E_CLASSNOTREG */, -2147217394 /* 0x8004100E WBEM_E_INVALID_NAMESPACE */]);
/** An error message as sent: one line, at most 160 characters, no user folder or email address. */
export function cleanMessage(m: unknown): string {
  return String(m ?? "").replace(/[A-Za-z]:\\Users\\[^\\\s"']+/gi, "C:\\Users\\[user]").replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email]")
    .replace(/\s+/g, " ").trim().slice(0, 160);
}

/** One query's JSON line, classified: a value, or why there is none (access denied, not on this PC, or another error). */
export function parseReading<T = unknown>(r: Run, q: Query): Reading<T> {
  if (r.missing) return { ok: false, why: "Windows PowerShell (powershell.exe) is not on this PC", denied: false, missing: true };
  const line = r.stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith("{")).pop();
  let j: Record<string, unknown> | undefined;
  try { j = line ? JSON.parse(line) : undefined; } catch { j = undefined; }
  if (!j || typeof j !== "object") return { ok: false, why: `${NEEDS[q]} gave no readable answer (exit ${r.code}${r.stderr.trim() ? `: ${cleanMessage(r.stderr)}` : ""})`, denied: false, missing: false };
  if (j.ok === true) return { ok: true, value: j.value as T };
  const type = String(j.type ?? ""), id = String(j.id ?? ""), hr = Number(j.hresult), msg = cleanMessage(j.message);
  if (/UnauthorizedAccess|AccessDenied|0x80070005|0x80041003/i.test(`${type} ${id}`) || ACCESS_DENIED_HRESULTS.has(hr) || /access (is |was )?denied|administrator mode/i.test(msg))
    return { ok: false, why: `${NEEDS[q]} needs an administrator (access denied)`, denied: true, missing: false };
  if (/CommandNotFoundException/.test(`${type} ${id}`) || NOT_REGISTERED_HRESULTS.has(hr))
    return { ok: false, why: `${NEEDS[q]} is not on this PC`, denied: false, missing: true };
  return { ok: false, why: `${NEEDS[q]} failed: ${type.split(".").pop() || "error"}${msg ? `: ${msg}` : ""}`, denied: false, missing: false };
}

/** PowerShell writes one item as itself and none as null; a list is always a list here. */
export const asList = <T>(v: unknown): T[] => (Array.isArray(v) ? v : v === null || v === undefined ? [] : [v]) as T[];

/** SIDs in the signed-in user's token, from `whoami /groups /fo csv /nh` (the third column). */
export function tokenSids(csv: string): string[] {
  const out: string[] = [];
  for (const line of csv.split(/\r?\n/)) {
    const f = [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1]);
    if (f.length >= 3 && /^S-1-[\d-]+$/.test(f[2])) out.push(f[2]);
  }
  return out;
}

export interface ScreenValues {
  inactivity?: string | null; policyActive?: string | null; policySecure?: string | null; policyTimeout?: string | null;
  userActive?: string | null; userSecure?: string | null; userTimeout?: string | null;
}
const num = (v: unknown) => { const n = typeof v === "string" && v.trim() !== "" ? Number(v.trim()) : typeof v === "number" ? v : NaN; return Number.isFinite(n) ? n : undefined; };
const set = (v: unknown) => v !== null && v !== undefined && String(v).trim() !== "";

/** Seconds of inactivity before Windows locks, or null when nothing read locks it. Policy values win over the user's own. */
export function lockAfter(v: ScreenValues): { total: number | null; why: string } {
  const parts: string[] = [], onsets: number[] = [];
  const limit = num(v.inactivity);
  if (limit && limit > 0) { onsets.push(limit); parts.push(`machine inactivity limit ${limit} s`); }
  else parts.push("no machine inactivity limit");
  const pick = (p: unknown, u: unknown) => (set(p) ? { v: String(p).trim(), by: "policy" } : set(u) ? { v: String(u).trim(), by: "user setting" } : undefined);
  const active = pick(v.policyActive, v.userActive), secure = pick(v.policySecure, v.userSecure), timeout = pick(v.policyTimeout, v.userTimeout);
  const t = num(timeout?.v);
  if (active?.v === "1" && secure?.v === "1" && t && t > 0) { onsets.push(t); parts.push(`password-protected screen saver after ${t} s (${timeout!.by})`); }
  else if (active?.v !== "1") parts.push(`screen saver off${active ? ` (${active.by})` : ""}`);
  else if (secure?.v !== "1") parts.push(`screen saver not password-protected${secure ? ` (${secure.by})` : ""}`);
  else parts.push("screen saver timeout not set");
  return { total: onsets.length ? Math.min(...onsets) : null, why: parts.join("; ") };
}

/** Microsoft's own antivirus as Security Center lists it; anchored, since "Bitdefender" contains "defender". */
const DEFENDER = /^(windows defender|microsoft defender( antivirus)?)$/i;
const days = (d: number) => `${d} day(s)`;

export async function runWindows(exec: WinExec, o: { lockSeconds: number; signatureDays: number; updateDays: number; minBuild: number }, now: Date): Promise<Result[]> {
  const ps = async <T>(q: Query, t?: number) => parseReading<T>(await exec(CMD.powershell, psArgs(q), t), q);
  const os = await ps<{ version?: string; build?: string; serial?: string }>("os");
  const v = os.ok ? os.value : undefined;
  const raw = v?.serial && !/o\.?e\.?m|default string|system serial|^0+$|^none$/i.test(v.serial) ? v.serial : undefined;
  const serial = cleanSerial(raw), version = typeof v?.version === "string" && /^[\d.]+$/.test(v.version) ? v.version : undefined;
  const out = new Emitter<C>("windows", `pc${serial ? ` serial ${serial}` : ""}${version ? ` Windows ${version}` : ""}`);
  const skip = (c: C, r: { why: string }) => out.add(c, "skipped", r.why);

  // Disk encryption: the OS volume only.
  const bl = await ps<{ volumeStatus?: string; protectionStatus?: string; percent?: number; method?: string }>("bitlocker");
  if (!bl.ok) skip("disk_encryption", bl.denied ? { why: `${bl.why}; run the collector once from an elevated PowerShell to read BitLocker` } : bl);
  else {
    const b = bl.value ?? {}, vs = String(b.volumeStatus ?? ""), prot = String(b.protectionStatus ?? "");
    if (!vs || !prot) out.add("disk_encryption", "skipped", "Get-BitLockerVolume returned no status for the system drive; it reads BitLocker only as an administrator");
    else if (vs === "FullyEncrypted" && prot === "On") out.add("disk_encryption", "pass", `BitLocker protects the system drive (FullyEncrypted, protection On${b.method ? `, ${String(b.method).slice(0, 20)}` : ""})`);
    else out.add("disk_encryption", "fail", `the system drive is ${vs.slice(0, 40)}${Number.isFinite(b.percent) ? ` (${b.percent}% encrypted)` : ""}, BitLocker protection ${prot.slice(0, 20)}`
      + (vs === "FullyEncrypted" && prot !== "On" ? ": encrypted, but its key protectors are suspended or absent" : ""));
  }

  // Windows Update: both dates recent, and nothing switches automatic updates off.
  const [wua, hf, pol] = [await ps<{ serviceEnabled?: boolean; lastInstall?: string | null }>("wua"), await ps<{ id?: string; installedOn?: string } | null>("hotfix"),
    await ps<{ startMode?: string; noAutoUpdate?: number | null; auOptions?: number | null }>("updatePolicy")];
  const wuaAge = wua.ok && wua.value?.lastInstall ? ageDays(wua.value.lastInstall, now) : undefined;
  const hfAge = hf.ok && hf.value?.installedOn ? ageDays(`${hf.value.installedOn}T00:00:00Z`, now) : undefined;
  if (wuaAge === undefined && hfAge === undefined) {
    out.add("os_updates_installed", "skipped", [wua.ok ? "Windows Update reports no successful installation" : wua.why,
      hf.ok ? "Get-HotFix lists no update with an install date" : hf.why].join("; "));
  } else {
    const old = [wuaAge, hfAge].some((a) => a !== undefined && a > o.updateDays);
    const said = [
      wuaAge !== undefined ? `Windows Update last installed an update ${days(wuaAge)} ago` : `Windows Update's last installation date is not readable (${wua.ok ? "none recorded" : wua.why})`,
      hfAge !== undefined ? `the newest Windows package, ${String(hf.ok && hf.value?.id || "?").replace(/[^\w-]/g, "").slice(0, 20)}, was installed ${days(hfAge)} ago` : "Get-HotFix gives no install date, judged on Windows Update's date alone",
    ];
    out.add("os_updates_installed", old ? "fail" : "pass", `${said.join("; ")} (at most ${o.updateDays})`);
  }
  {
    const p = pol.ok ? pol.value ?? {} : {}, bad: string[] = [], good: string[] = [];
    if (pol.ok) {
      if (p.noAutoUpdate === 1) bad.push("policy NoAutoUpdate = 1 (Automatic Updates disabled)"); else good.push(`NoAutoUpdate ${p.noAutoUpdate ?? "not set"}`);
      if (p.auOptions === 1 || p.auOptions === 2) bad.push(`policy AUOptions = ${p.auOptions} (${p.auOptions === 1 ? "disabled" : "notify only, nothing downloads"})`);
      else good.push(`AUOptions ${p.auOptions ?? "not set"}`);
      if (/^disabled$/i.test(String(p.startMode ?? ""))) bad.push("the Windows Update service (wuauserv) is disabled");
      else if (p.startMode) good.push(`wuauserv start mode ${String(p.startMode).slice(0, 12)}`);
    }
    if (wua.ok && wua.value?.serviceEnabled === false) bad.push("Automatic Updates reports its components unavailable (ServiceEnabled false)");
    // A pass needs the policy read; a failing reading from the update agent alone is enough to fail.
    if (bad.length) out.add("automatic_updates", "fail", bad.join("; "));
    else if (!pol.ok) out.add("automatic_updates", "skipped", pol.why);
    else out.add("automatic_updates", "pass", `nothing turns automatic updates off: ${good.join(", ")}`);
  }

  const build = Number(v?.build);
  if (!os.ok) skip("os_supported", os);
  else if (!Number.isInteger(build) || build <= 0) out.add("os_supported", "skipped", "Win32_OperatingSystem gave no build number");
  else out.add("os_supported", build >= o.minBuild ? "pass" : "fail", `Windows build ${build} (at least ${o.minBuild}, --windows-min-build)`);

  // Malware protection: Microsoft Defender Antivirus when it is the active antivirus; another product is named, not judged.
  const [def, avs] = [await ps<{ mode?: string; amService?: boolean; antivirus?: boolean; realTime?: boolean; signatureAge?: number; signatureUpdated?: string | null; signatureVersion?: string }>("defender"),
    await ps<unknown>("antivirus")];
  const others = avs.ok ? asList<unknown>(avs.value).map((n) => String(n ?? "").replace(/[^\w .()&+-]/g, "").trim().slice(0, 60)).filter((n) => n && !DEFENDER.test(n)) : [];
  const mode = def.ok ? String(def.value?.mode ?? "") : "";
  const third = others.length ? `${others.join(", ")} ${others.length === 1 ? "is" : "are"} registered with Windows Security Center` : "";
  const notJudged = `${third}; Microsoft documents no way to read a third-party antivirus's state from a script, so a person confirms it scans in real time`;
  // "EDR Block Mode" can be active or passive Defender (Microsoft: check ForceDefenderPassiveMode); judged only when no other antivirus is registered.
  if (def.ok && (mode === "Normal" || (mode === "EDR Block Mode" && !others.length))) {
    const d = def.value, off = [d.amService !== true && "the antimalware service is off", d.antivirus !== true && "antivirus is off", d.realTime !== true && "real-time protection is off"].filter(Boolean);
    out.add("malware_protection", off.length ? "fail" : "pass", off.length ? `Microsoft Defender Antivirus: ${off.join("; ")}` : "Microsoft Defender Antivirus is the active antivirus, with real-time protection on");
    const age = d.signatureUpdated ? ageDays(d.signatureUpdated, now) : typeof d.signatureAge === "number" && d.signatureAge < 65535 ? d.signatureAge : undefined;
    if (age === undefined) out.add("malware_definitions_current", "fail", "Microsoft Defender Antivirus reports that its definitions have never been updated");
    else out.add("malware_definitions_current", age <= o.signatureDays ? "pass" : "fail",
      `Defender definitions ${String(d.signatureVersion ?? "?").replace(/[^\d.]/g, "").slice(0, 20) || "?"} updated ${days(age)} ago (at most ${o.signatureDays})`);
  } else if (others.length) {
    const why = `${def.ok ? `Microsoft Defender Antivirus is in ${mode.slice(0, 20) || "an unknown"} mode` : `Microsoft Defender Antivirus is not active (${def.why})`}; ${notJudged}`;
    out.add("malware_protection", "skipped", why);
    out.add("malware_definitions_current", "skipped", why);
  } else if (def.ok) {
    out.add("malware_protection", "fail", `Microsoft Defender Antivirus is in ${mode.slice(0, 20) || "an unknown"} mode and no other antivirus is registered with Windows Security Center`);
    out.add("malware_definitions_current", "skipped", "Microsoft Defender Antivirus is not the active antivirus");
  } else {
    const why = `${def.why}${avs.ok ? "; no other antivirus is registered with Windows Security Center" : `; ${avs.why}`}`;
    skip("malware_protection", { why }); skip("malware_definitions_current", { why });
  }

  const fw = await ps<unknown>("firewall");
  if (!fw.ok) skip("firewall", fw);
  else {
    const profiles = asList<{ name?: string; enabled?: number }>(fw.value).filter((p) => p && typeof p === "object");
    const name = (p: { name?: string }) => String(p.name ?? "?").replace(/[^\w]/g, "").slice(0, 12);
    const off = profiles.filter((p) => p.enabled === 0).map(name), unknown = profiles.filter((p) => p.enabled !== 0 && p.enabled !== 1).map(name);
    const missing = ["Domain", "Private", "Public"].filter((n) => !profiles.some((p) => name(p).toLowerCase() === n.toLowerCase()));
    if (!profiles.length) out.add("firewall", "skipped", "Get-NetFirewallProfile returned no profile");
    else if (off.length) out.add("firewall", "fail", `Windows Firewall is off for the ${off.join(", ")} profile(s)`);
    else if (unknown.length || missing.length) out.add("firewall", "skipped", `Windows Firewall state not determined for: ${[...unknown, ...missing].join(", ")}`);
    else out.add("firewall", "pass", `Windows Firewall is on for the ${profiles.map(name).join(", ")} profiles (active policy)`);
  }

  const sl = await ps<ScreenValues>("screenLock");
  if (!sl.ok) skip("screen_lock", sl);
  else {
    const l = lockAfter(sl.value ?? {});
    out.add("screen_lock", l.total !== null && l.total <= o.lockSeconds ? "pass" : "fail",
      `${l.total === null ? "never locks on inactivity" : `locks after ${l.total} s`} (at most ${o.lockSeconds}): ${l.why}`);
  }

  const al = await ps<string | null>("autoLogon");
  if (!al.ok) skip("auto_login_off", al);
  else out.add("auto_login_off", String(al.value ?? "").trim() === "1" ? "fail" : "pass",
    String(al.value ?? "").trim() === "1" ? "automatic sign-in is on (Winlogon AutoAdminLogon = 1)" : "automatic sign-in is off");

  const who = await exec(CMD.whoami, ["/groups", "/fo", "csv", "/nh"]);
  const sids = who.code === 0 ? tokenSids(who.stdout) : [];
  if (!sids.length) out.add("user_not_admin", "skipped", who.missing ? "whoami.exe is not on this PC" : `whoami /groups gave no group (exit ${who.code})`);
  else {
    const n = await ps<number>("adminCount");
    const count = n.ok && Number.isInteger(n.value) ? `; the local Administrators group has ${n.value} member(s)` : `; member count not read (${n.ok ? "no number" : n.why})`;
    const admin = sids.includes(ADMINISTRATORS_SID);
    out.add("user_not_admin", admin ? "fail" : "pass",
      (admin ? "the signed-in account is a local administrator (its token holds S-1-5-32-544, elevated or not)" : "the signed-in account is not a local administrator") + count);
  }

  const sb = await ps<boolean>("secureBoot");
  if (sb.ok) out.add("secure_boot", sb.value === true ? "pass" : "fail", sb.value === true ? "Secure Boot is on" : "Secure Boot is supported but off");
  else if (/not supported on this platform|PlatformNotSupported/i.test(sb.why)) out.add("secure_boot", "fail", "this PC does not support Secure Boot or starts in BIOS (legacy) mode");
  else skip("secure_boot", sb.denied ? { why: `${sb.why}; run the collector once from an elevated PowerShell to read it` } : sb);
  return out.results;
}

export const windows: Source = {
  name: "windows",
  options: {
    "windows-max-lock-seconds": { type: "string", help: `seconds of inactivity before Windows must lock (default ${DEFAULTS.lockSeconds})` },
    "windows-signature-days": { type: "string", help: `days since Defender's definitions were updated before malware_definitions_current fails (default ${DEFAULTS.signatureDays})` },
    "windows-update-days": { type: "string", help: `days since the last Windows update installation before os_updates_installed fails (default ${DEFAULTS.updateDays})` },
    "windows-min-build": { type: "string", help: `lowest Windows build still updated, e.g. 26100 for Enterprise 24H2 (default ${DEFAULTS.minBuild}, Windows 11 25H2)` },
  },
  emits: WINDOWS_CHECKS.map((c) => `windows.${c}`),
  describe: () => "this Windows PC (PowerShell and built-in tools, no administrator)",
  async run(ctx: SourceContext) {
    const exec = (ctx.clients.windows as WinExec | undefined) ?? (process.platform === "win32" ? realExec : undefined);
    if (!exec) {
      const out = new Emitter<C>("windows", "pc");
      out.skipAll(WINDOWS_CHECKS, `the windows source runs only on Windows (this is ${process.platform})`);
      return out.results;
    }
    return runWindows(exec, { lockSeconds: posInt(ctx.opts["windows-max-lock-seconds"], DEFAULTS.lockSeconds),
                              signatureDays: posInt(ctx.opts["windows-signature-days"], DEFAULTS.signatureDays),
                              updateDays: posInt(ctx.opts["windows-update-days"], DEFAULTS.updateDays),
                              minBuild: posInt(ctx.opts["windows-min-build"], DEFAULTS.minBuild) }, ctx.now);
  },
};
