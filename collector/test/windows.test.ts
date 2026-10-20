// The Windows source against a fake command runner. Each output is the
// JSON line the source's own wrapper prints, with values shaped from the examples on Microsoft Learn (2026-10-20):
// Get-MpComputerStatus, Get-BitLockerVolume, Get-NetFirewallProfile, whoami /groups /fo csv.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ADMINISTRATORS_SID, CMD, QUERIES, asList, cleanMessage, encode, lockAfter, parseReading, psArgs, runWindows, script, tokenSids, windows,
  type Query, type Run, type WinExec,
} from "../src/sources/windows.ts";

const NOW = new Date("2026-10-20T20:00:00Z");
const ok = (value: unknown): Run => ({ code: 0, stdout: `${JSON.stringify({ ok: true, value })}\r\n`, stderr: "" });
const err = (type: string, message: string, extra: Record<string, unknown> = {}): Run =>
  ({ code: 0, stdout: JSON.stringify({ ok: false, type, id: extra.id ?? "", hresult: extra.hresult ?? -2146233088, message }), stderr: "" });
const DENIED = err("System.UnauthorizedAccessException", "Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))", { hresult: -2147024891 });
const NOT_FOUND = (cmd: string) => err("System.Management.Automation.CommandNotFoundException", `The term '${cmd}' is not recognized as the name of a cmdlet`, { id: "CommandNotFoundException" });

// whoami /groups /fo csv /nh, as a standard user and as an administrator (filtered token, not elevated).
const WHO_USER = `"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"\r
"BUILTIN\\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"\r
"NT AUTHORITY\\INTERACTIVE","Well-known group","S-1-5-4","Mandatory group, Enabled by default, Enabled group"\r
"Mandatory Label\\Medium Mandatory Level","Label","S-1-16-8192",""\r
`;
const WHO_ADMIN = WHO_USER.replace('"BUILTIN\\Users"', `"BUILTIN\\Administrators","Alias","${ADMINISTRATORS_SID}","Group used for deny only"\r\n"BUILTIN\\Users"`);

const GOOD: Record<Query, Run> = {
  os: ok({ version: "10.0.26200", build: "26200", serial: "DDC2H2J" }),
  bitlocker: ok({ volumeStatus: "FullyEncrypted", protectionStatus: "On", percent: 100, method: "XtsAes128" }),
  defender: ok({ mode: "Normal", amService: true, antivirus: true, realTime: true, signatureAge: 0, signatureVersion: "1.441.312.0", signatureUpdated: "2026-10-20T09:12:40.0000000Z" }),
  antivirus: ok("Windows Defender"),                                   // one product: PowerShell prints it bare, not as a list
  firewall: ok([{ name: "Domain", enabled: 1 }, { name: "Private", enabled: 1 }, { name: "Public", enabled: 1 }]),
  screenLock: ok({ inactivity: "600", policyActive: null, policySecure: null, policyTimeout: null, userActive: "1", userSecure: "0", userTimeout: "900" }),
  autoLogon: ok("0"),
  wua: ok({ serviceEnabled: true, lastInstall: "2026-10-19T14:02:11Z" }),
  hotfix: ok({ id: "KB5066835", installedOn: "2026-10-15" }),
  updatePolicy: ok({ startMode: "Manual", noAutoUpdate: null, auOptions: null }),
  adminCount: ok(2),
  secureBoot: ok(true),
};

function fake(over: Partial<Record<Query, Run>> = {}, who: Run = { code: 0, stdout: WHO_USER, stderr: "" }): { exec: WinExec; calls: string[] } {
  const table = { ...GOOD, ...over }, byArg = new Map((Object.keys(QUERIES) as Query[]).map((q) => [encode(script(q)), q]));
  const calls: string[] = [];
  return { calls, exec: async (cmd, args) => {
    if (cmd === CMD.whoami) { calls.push(`whoami ${args.join(" ")}`); return who; }
    assert.equal(cmd, CMD.powershell);
    assert.deepEqual(args.slice(0, 4), ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]);
    const q = byArg.get(args[4]);
    assert.ok(q, "an unknown script was run");
    calls.push(q);
    return table[q];
  } };
}
const byCheck = (rs: Awaited<ReturnType<typeof runWindows>>) => Object.fromEntries(rs.map((r) => [r.check.replace("windows.", ""), r]));
const O = { lockSeconds: 900, signatureDays: 7, updateDays: 35, minBuild: 26200 };

test("a well-kept PC (BitLocker and Secure Boot answered, as on an elevated run) passes every check, named by serial only", async () => {
  const rs = await runWindows(fake({}, { code: 0, stdout: WHO_USER, stderr: "" }).exec, O, NOW);
  assert.equal(rs.length, windows.emits.length);
  for (const r of rs) {
    assert.equal(r.result, "pass", `${r.check}: ${r.detail}`);
    assert.equal(r.resource, "pc serial DDC2H2J Windows 10.0.26200");
  }
  const c = byCheck(rs);
  assert.match(c.screen_lock.detail, /^locks after 600 s \(at most 900\): machine inactivity limit 600 s; screen saver not password-protected \(user setting\)$/);
  assert.match(c.os_updates_installed.detail, /1 day\(s\) ago; the newest Windows package, KB5066835, was installed 5 day\(s\) ago \(at most 35\)/);
  assert.match(c.user_not_admin.detail, /not a local administrator; the local Administrators group has 2 member\(s\)/);
  assert.match(c.malware_definitions_current.detail, /^Defender definitions 1\.441\.312\.0 updated 0 day\(s\) ago/);
});

test("each check fails on the setting it reads", async () => {
  const rs = byCheck(await runWindows(fake({
    bitlocker: ok({ volumeStatus: "FullyDecrypted", protectionStatus: "Off", percent: 0, method: "None" }),
    defender: ok({ mode: "Normal", amService: true, antivirus: true, realTime: false, signatureAge: 30, signatureVersion: "1.400.0.0", signatureUpdated: "2026-09-01T00:00:00Z" }),
    firewall: ok([{ name: "Domain", enabled: 1 }, { name: "Private", enabled: 1 }, { name: "Public", enabled: 0 }]),
    screenLock: ok({ inactivity: "0", policyActive: null, policySecure: null, policyTimeout: null, userActive: "1", userSecure: "1", userTimeout: "1800" }),
    autoLogon: ok("1"),
    wua: ok({ serviceEnabled: true, lastInstall: "2026-10-20T03:00:00Z" }),   // a definition update today …
    hotfix: ok({ id: "KB5060000", installedOn: "2026-07-08" }),               // … but no Windows package since July
    updatePolicy: ok({ startMode: "Disabled", noAutoUpdate: 1, auOptions: 2 }),
    os: ok({ version: "10.0.19045", build: "19045", serial: "DDC2H2J" }),
    secureBoot: ok(false),
  }, { code: 0, stdout: WHO_ADMIN, stderr: "" }).exec, O, NOW));
  for (const [c, r] of Object.entries(rs)) assert.equal(r.result, "fail", `${c}: ${r.detail}`);
  assert.equal(rs.disk_encryption.detail, "the system drive is FullyDecrypted (0% encrypted), BitLocker protection Off");
  assert.equal(rs.malware_protection.detail, "Microsoft Defender Antivirus: real-time protection is off");
  assert.equal(rs.firewall.detail, "Windows Firewall is off for the Public profile(s)");
  assert.match(rs.screen_lock.detail, /^locks after 1800 s \(at most 900\)/);
  assert.match(rs.os_updates_installed.detail, /KB5060000, was installed 104 day\(s\) ago/);
  assert.equal(rs.automatic_updates.detail, "policy NoAutoUpdate = 1 (Automatic Updates disabled); policy AUOptions = 2 (notify only, nothing downloads); the Windows Update service (wuauserv) is disabled");
  assert.equal(rs.os_supported.detail, "Windows build 19045 (at least 26200, --windows-min-build)");
  assert.match(rs.user_not_admin.detail, /^the signed-in account is a local administrator \(its token holds S-1-5-32-544, elevated or not\)/);
});

test("a standard user's run skips BitLocker and Secure Boot with the reason, never fails them", async () => {
  const rs = byCheck(await runWindows(fake({
    bitlocker: DENIED,
    secureBoot: err("System.UnauthorizedAccessException", "Unable to set proper privileges. Access was denied."),
  }).exec, O, NOW));
  assert.equal(rs.disk_encryption.result, "skipped");
  assert.match(rs.disk_encryption.detail, /^Get-BitLockerVolume needs an administrator \(access denied\); run the collector once from an elevated PowerShell/);
  assert.equal(rs.secure_boot.result, "skipped");
  assert.match(rs.secure_boot.detail, /^Confirm-SecureBootUEFI needs an administrator/);
  // A BitLocker answer with no status (the provider hides it) is skipped too.
  const empty = byCheck(await runWindows(fake({ bitlocker: ok({ volumeStatus: "", protectionStatus: "" }) }).exec, O, NOW));
  assert.equal(empty.disk_encryption.result, "skipped");
  // A WMI access-denied (0x80041003) is recognised by its HRESULT alone.
  const wmi = byCheck(await runWindows(fake({ bitlocker: err("Microsoft.Management.Infrastructure.CimException", "", { hresult: -2147217405 }) }).exec, O, NOW));
  assert.match(wmi.disk_encryption.detail, /needs an administrator/);
});

test("a missing cmdlet, a missing PowerShell and an error are skipped, never passed", async () => {
  const rs = byCheck(await runWindows(fake({
    bitlocker: NOT_FOUND("Get-BitLockerVolume"),
    defender: err("Microsoft.Management.Infrastructure.CimException", "Operation failed with the following error: 0x800106ba", { hresult: -2146233088 }),
    antivirus: ok(null),
    firewall: ok([]),
    adminCount: err("System.InvalidOperationException", "Failed to compare two elements in the array."),
  }).exec, O, NOW));
  assert.equal(rs.disk_encryption.result, "skipped");
  assert.equal(rs.disk_encryption.detail, "Get-BitLockerVolume is not on this PC");
  assert.equal(rs.malware_protection.result, "skipped");
  assert.match(rs.malware_protection.detail, /^Get-MpComputerStatus failed: CimException: Operation failed .*; no other antivirus is registered/);
  assert.equal(rs.firewall.result, "skipped");
  assert.equal(rs.user_not_admin.result, "pass");                       // the token decides; the count is only context
  assert.match(rs.user_not_admin.detail, /member count not read \(Get-LocalGroupMember failed: InvalidOperationException/);

  const none: WinExec = async () => ({ code: -1, stdout: "", stderr: "", missing: true });
  const all = await runWindows(none, O, NOW);
  assert.ok(all.every((r) => r.result === "skipped"), JSON.stringify(all.filter((r) => r.result !== "skipped")));
  assert.equal(all[0].resource, "pc");
  assert.match(byCheck(all).firewall.detail, /powershell\.exe\) is not on this PC/);
  assert.equal(byCheck(all).user_not_admin.detail, "whoami.exe is not on this PC");
});

test("a third-party antivirus is named and left to a person; Defender off with nothing else fails", async () => {
  const third = byCheck(await runWindows(fake({
    defender: ok({ mode: "Passive", amService: true, antivirus: true, realTime: false, signatureAge: 3 }),
    antivirus: ok(["Windows Defender", "Bitdefender Antivirus"]),
  }).exec, O, NOW));
  assert.equal(third.malware_protection.result, "skipped");
  assert.match(third.malware_protection.detail, /^Microsoft Defender Antivirus is in Passive mode; Bitdefender Antivirus is registered with Windows Security Center; Microsoft documents no way/);
  assert.equal(third.malware_definitions_current.result, "skipped");
  // Defender disabled automatically by the other product: Get-MpComputerStatus fails, the other product is still named.
  const disabled = byCheck(await runWindows(fake({ defender: err("Microsoft.Management.Infrastructure.CimException", "0x800106ba"), antivirus: ok("ESET Security") }).exec, O, NOW));
  assert.match(disabled.malware_protection.detail, /not active .*ESET Security is registered/);
  const nothing = byCheck(await runWindows(fake({ defender: ok({ mode: "SxS Passive Mode", amService: true, antivirus: true, realTime: false }), antivirus: ok("Windows Defender") }).exec, O, NOW));
  assert.equal(nothing.malware_protection.result, "fail");
  assert.equal(nothing.malware_definitions_current.result, "skipped");
  const never = byCheck(await runWindows(fake({ defender: ok({ mode: "Normal", amService: true, antivirus: true, realTime: true, signatureAge: 65535, signatureUpdated: null }) }).exec, O, NOW));
  assert.equal(never.malware_definitions_current.result, "fail");
});

test("updates: no readable date is skipped; an agent date alone is judged and says so; a Settings-only failure needs the policy", async () => {
  const none = byCheck(await runWindows(fake({ wua: ok({ serviceEnabled: true, lastInstall: null }), hotfix: ok(null) }).exec, O, NOW));
  assert.equal(none.os_updates_installed.result, "skipped");
  const agent = byCheck(await runWindows(fake({ hotfix: ok(null) }).exec, O, NOW));
  assert.equal(agent.os_updates_installed.result, "pass");
  assert.match(agent.os_updates_installed.detail, /Get-HotFix gives no install date, judged on Windows Update's date alone/);
  const noPolicy = byCheck(await runWindows(fake({ updatePolicy: DENIED }).exec, O, NOW));
  assert.equal(noPolicy.automatic_updates.result, "skipped");
  const agentOff = byCheck(await runWindows(fake({ updatePolicy: DENIED, wua: ok({ serviceEnabled: false, lastInstall: null }) }).exec, O, NOW));
  assert.equal(agentOff.automatic_updates.result, "fail");
  const options3 = byCheck(await runWindows(fake({ updatePolicy: ok({ startMode: "Auto", noAutoUpdate: 0, auOptions: 3 }) }).exec, O, NOW));
  assert.equal(options3.automatic_updates.result, "pass");
  assert.match(options3.automatic_updates.detail, /NoAutoUpdate 0, AUOptions 3, wuauserv start mode Auto/);
  const legacy = byCheck(await runWindows(fake({ secureBoot: err("System.PlatformNotSupportedException", "Cmdlet not supported on this platform.") }).exec, O, NOW));
  assert.equal(legacy.secure_boot.result, "fail");
});

test("no personal data: no user folder, email, computer name or user name reaches a result", async () => {
  const rs = await runWindows(fake({
    defender: err("System.IO.IOException", "Cannot open C:\\Users\\anna.tremblay\\AppData\\x for anna@example.ca"),
    antivirus: ok(null),
    os: ok({ version: "10.0.26200", build: "26200", serial: "To be filled by O.E.M." }),
  }).exec, O, NOW);
  const s = JSON.stringify(rs);
  assert.ok(!/anna/i.test(s), s);
  assert.match(s, /C:\\\\Users\\\\\[user\]/);
  assert.equal(rs[0].resource, "pc Windows 10.0.26200");                // an OEM placeholder is not a serial
});

test("parsers", () => {
  assert.deepEqual(tokenSids(WHO_ADMIN).includes(ADMINISTRATORS_SID), true);
  assert.deepEqual(tokenSids(WHO_USER), ["S-1-1-0", "S-1-5-32-545", "S-1-5-4", "S-1-16-8192"]);
  assert.deepEqual(tokenSids("garbage\r\n"), []);
  assert.deepEqual(asList("a"), ["a"]);
  assert.deepEqual(asList(null), []);
  assert.deepEqual(asList(["a", "b"]), ["a", "b"]);
  // Policy wins over the user's own value; either the limit or a secure saver locks; the earlier one counts.
  assert.equal(lockAfter({ policyActive: "1", policySecure: "1", policyTimeout: "300", userActive: "0", userSecure: "0", userTimeout: "0" }).total, 300);
  assert.equal(lockAfter({ policyActive: "0", userActive: "1", userSecure: "1", userTimeout: "300" }).total, null);
  assert.equal(lockAfter({ inactivity: "1200", userActive: "1", userSecure: "1", userTimeout: "600" }).total, 600);
  assert.equal(lockAfter({}).total, null);
  assert.equal(lockAfter({ inactivity: "", userActive: "1", userSecure: "1", userTimeout: "" }).why, "no machine inactivity limit; screen saver timeout not set");
  // A banner or a warning before the JSON line, and non-JSON output, are handled.
  assert.deepEqual(parseReading({ code: 0, stdout: "WARNING: x\r\n{\"ok\":true,\"value\":5}\r\n", stderr: "" }, "adminCount"), { ok: true, value: 5 });
  const bad = parseReading({ code: 1, stdout: "not json", stderr: "boom" }, "os");
  assert.equal(bad.ok, false);
  assert.match((bad as { why: string }).why, /no readable answer \(exit 1: boom\)/);
  assert.equal(cleanMessage("a\n  b ".repeat(100)).length <= 160, true);
});

test("the scripts are fixed, read-only, and go through -EncodedCommand as UTF-16LE", () => {
  for (const q of Object.keys(QUERIES) as Query[]) {
    const s = script(q), a = psArgs(q);
    assert.equal(Buffer.from(a[4], "base64").toString("utf16le"), s);
    // Nothing that writes: no Set-, New-Item, Remove-, Enable-, Disable- or Add- cmdlet, no registry write, no network.
    assert.ok(!/\b(Set|Remove|Enable|Disable|Add|Clear|Start|Stop|Restart|Invoke)-[A-Z]|New-Item|reg(\.exe)? add|Invoke-WebRequest|DownloadString|Update-MpSignature/i.test(QUERIES[q]), q);
  }
  assert.ok(!/DefaultPassword|DefaultUserName|InstalledBy|CSName|RegisteredUser/.test(Object.values(QUERIES).join("\n")));
});

test("off Windows, every check is skipped", { skip: process.platform === "win32" && "runs real commands on Windows" }, async () => {
  const rs = await windows.run({ opts: {}, env: {}, clients: {}, now: NOW, warn: () => {} });
  assert.ok(rs.length === windows.emits.length && rs.every((r) => r.result === "skipped"));
  assert.match(rs[0].detail, /runs only on Windows/);
});

test("options reach the checks", async () => {
  const exec = fake().exec;
  const rs = byCheck(await windows.run({ opts: { "windows-max-lock-seconds": "300", "windows-min-build": "26300", "windows-update-days": "3", "windows-signature-days": "1" },
    env: {}, clients: { windows: exec }, now: NOW, warn: () => {} }));
  assert.equal(rs.screen_lock.result, "fail");
  assert.equal(rs.os_supported.result, "fail");
  assert.equal(rs.os_updates_installed.result, "fail");
  assert.equal(rs.malware_definitions_current.result, "pass");
});
