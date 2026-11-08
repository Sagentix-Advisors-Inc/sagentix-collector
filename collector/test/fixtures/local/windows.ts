// Fixtures for the windows source, shared by test/windows.test.ts and the end-to-end run (test/e2e.test.ts).
import assert from "node:assert/strict";
import {
  ADMINISTRATORS_SID, CMD, QUERIES, asList, buildSupported, cleanMessage, encode, lockAfter, parseReading, psArgs, runWindows, script, tokenSids, windows,
  type Query, type Run, type WinExec,
} from "../../../src/sources/windows.ts";

export const NOW = new Date("2026-10-20T20:00:00Z");
export const ok = (value: unknown): Run => ({ code: 0, stdout: `${JSON.stringify({ ok: true, value })}\r\n`, stderr: "" });
export const err = (type: string, message: string, extra: Record<string, unknown> = {}): Run =>
  ({ code: 0, stdout: JSON.stringify({ ok: false, type, id: extra.id ?? "", hresult: extra.hresult ?? -2146233088, message }), stderr: "" });
export const DENIED = err("System.UnauthorizedAccessException", "Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))", { hresult: -2147024891 });
export const NOT_FOUND = (cmd: string) => err("System.Management.Automation.CommandNotFoundException", `The term '${cmd}' is not recognized as the name of a cmdlet`, { id: "CommandNotFoundException" });

// whoami /groups /fo csv /nh, as a standard user and as an administrator (filtered token, not elevated).
export const WHO_USER = `"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"\r
"BUILTIN\\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"\r
"NT AUTHORITY\\INTERACTIVE","Well-known group","S-1-5-4","Mandatory group, Enabled by default, Enabled group"\r
"Mandatory Label\\Medium Mandatory Level","Label","S-1-16-8192",""\r
`;
export const WHO_ADMIN = WHO_USER.replace('"BUILTIN\\Users"', `"BUILTIN\\Administrators","Alias","${ADMINISTRATORS_SID}","Group used for deny only"\r\n"BUILTIN\\Users"`);

export const GOOD: Record<Query, Run> = {
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

export function fake(over: Partial<Record<Query, Run>> = {}, who: Run = { code: 0, stdout: WHO_USER, stderr: "" }): { exec: WinExec; calls: string[] } {
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