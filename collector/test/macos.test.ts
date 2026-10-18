// The macOS source against a fake command runner whose outputs are copied from macOS 26.6.2 (25G83), 2026-10-17.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cccHistory, lockSeconds, macos, pendingUpdates, plistBool, runMacos, timeMachine, type MacExec, type Run } from "../src/sources/macos.ts";

const NOW = new Date("2026-10-17T20:00:00Z");
const ok = (stdout: string, stderr = ""): Run => ({ code: 0, stdout, stderr });
const SU_NONE = "Software Update Tool\n\nFinding available software\nNo new software available.\n";
const SU_SOME = `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: Safari27.0TahoeAuto-27.0
\tTitle: Safari, Version: 27.0, Size: 249465KiB, Recommended: YES, 
* Label: macOS Tahoe 26.7.1-25G241
\tTitle: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 2960823KiB, Recommended: YES, Action: restart, 
* Label: macOS 27.0.1-26A434
\tTitle: macOS 27.0.1, Version: 27.0.1, Size: 11713682KiB, Recommended: YES, Action: restart, 
`;
// Time Machine's plist and CCC's history, trimmed from this Mac (2026-10-18); names kept to show they are never sent.
const tmPlist = (state: string, last: string) => `<?xml version="1.0"?><plist version="1.0"><dict><key>AutoBackup</key><integer>1</integer>
<key>Destinations</key><array><dict><key>AttemptDates</key><array><date>2026-10-17T21:42:04Z</date></array>
<key>LastKnownEncryptionState</key><string>${state}</string><key>LastKnownVolumeName</key><string>Anna TM</string>
<key>SnapshotDates</key><array><date>2026-02-12T03:07:21Z</date><date>${last}</date></array></dict></array>
<key>LastDestinationID</key><string>x</string><key>SnapshotDates</key><array><date>2024-09-20T17:03:10Z</date></array></dict></plist>`;
const CCC = `"Clone to CCC-B","Macintosh HD","CCC-Anna-B","1792303982","13:02","111.46 GB","Success","59500"
"Clone to CCC-A","Macintosh HD","CCC-Anna-A","1792303200","","Zero KB","Failed","0"
"Clone to CCC-A","Macintosh HD","CCC-Anna-A","1791000000","13:00","90 GB","Success","1"
`;
const DISK = (fv: boolean) => ok(`<?xml version="1.0"?><plist version="1.0"><dict><key>FileVault</key><${fv}/></dict></plist>`);
const BZ = "/Library/Backblaze.bzpkg/bzdata";
const plist = (keys: Record<string, boolean>) => `<?xml version="1.0"?><plist version="1.0"><dict>${Object.entries(keys).map(([k, v]) => `<key>${k}</key><${v}/>`).join("")}</dict></plist>`;

function fake(over: Record<string, Run> = {}): { exec: MacExec; calls: string[] } {
  const calls: string[] = [];
  const base: Record<string, Run> = {
    "/usr/bin/sw_vers -productVersion": ok("26.6.2\n"),
    "/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice": ok('    "IOPlatformSerialNumber" = "JCF17L6NN4"\n    "IOPlatformUUID" = "x"\n'),
    "/usr/bin/fdesetup status": ok("FileVault is On.\n"),
    "/usr/sbin/softwareupdate --list": ok(SU_NONE),
    "/usr/bin/defaults export /Library/Preferences/com.apple.SoftwareUpdate -": ok(plist({ AutomaticDownload: true, CriticalUpdateInstall: true, ConfigDataInstall: true })),
    "/usr/sbin/spctl --status": ok("assessments enabled\n"),
    "/usr/bin/xprotect status --json": ok('{"xprotect_launch_scans":true,"xprotect_background_scans":true}'),
    "/usr/bin/xprotect version --json": ok('{"xprotect_bundle_version":"5367","xprotect_bundle_install_date":"2026-10-14T07:39:52Z"}'),
    "/usr/bin/csrutil status": ok("System Integrity Protection status: enabled.\n"),
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": ok("Firewall is enabled. (State = 1)\n"),
    "/usr/sbin/sysadminctl -screenLock status": ok("", "2026-10-17 20:07:50.653 sysadminctl[6993:1] screenLock delay is 5 seconds\n"),
    "/usr/bin/pmset -g": ok(" sleep                1\n displaysleep         10\n"),
    "/usr/bin/defaults -currentHost read com.apple.screensaver idleTime": ok("300\n"),
    "/usr/bin/defaults export /Library/Preferences/com.apple.loginwindow -": ok(plist({ GuestEnabled: false })),
    "/usr/bin/defaults export /Library/Preferences/com.apple.TimeMachine -": ok(tmPlist("Encrypted", "2026-10-16T23:16:25Z")),
    "/Applications/Carbon Copy Cloner.app/Contents/MacOS/ccc -h -c -d": ok(CCC),
    "/usr/sbin/diskutil info -plist /Volumes/CCC-Anna-B": DISK(true),
    "/usr/sbin/diskutil info -plist /Volumes/CCC-Anna-A": { code: 1, stdout: "", stderr: "Could not find disk" },
    [`/bin/cat ${BZ}/bzreports/bzstat_lastbackupcompleted.xml`]: ok('<contents>\n<lastbackupcompleted gmt_millis="1792345446100" localdatetime="20261018134406" />\n</contents>\n'),
  };
  const table = { ...base, ...over };
  return { calls, exec: async (cmd, args) => { const k = [cmd, ...args].join(" "); calls.push(k); return table[k] ?? { code: 127, stdout: "", stderr: "", missing: true }; } };
}
const byCheck = (rs: Awaited<ReturnType<typeof runMacos>>) => Object.fromEntries(rs.map((r) => [r.check.replace("macos.", ""), r]));
const O = { lockSeconds: 900, xprotectDays: 14, backupDays: 7 };

test("a well-kept Mac passes every check, named by serial only", async () => {
  const rs = await runMacos(fake().exec, O, NOW);
  assert.equal(rs.length, macos.emits.length);
  for (const r of rs) {
    assert.equal(r.result, "pass", `${r.check}: ${r.detail}`);
    assert.equal(r.resource, "mac serial JCF17L6NN4 macOS 26.6.2");
  }
  assert.match(byCheck(rs).screen_lock.detail, /locks after 305 s/);   // screen saver at 300 s, then 5 s
});

test("each check fails on the setting it reads (outputs from a real Mac)", async () => {
  const rs = byCheck(await runMacos(fake({
    "/usr/bin/fdesetup status": ok("FileVault is Off.\n"),
    "/usr/sbin/softwareupdate --list": ok(SU_SOME),
    "/usr/bin/defaults export /Library/Preferences/com.apple.SoftwareUpdate -": ok(plist({ CriticalUpdateInstall: false })),
    "/usr/sbin/spctl --status": ok("assessments disabled\n"),
    "/usr/bin/xprotect version --json": ok('{"xprotect_bundle_version":"5300","xprotect_bundle_install_date":"2026-08-01T00:00:00Z"}'),
    "/usr/bin/csrutil status": ok("System Integrity Protection status: disabled.\n"),
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": ok("Firewall is disabled. (State = 0)\n"),
    "/usr/sbin/sysadminctl -screenLock status": ok("", "x screenLock delay is 28800 seconds\n"),
    "/usr/bin/pmset -g": ok(" displaysleep         30\n"),
    "/usr/bin/defaults -currentHost read com.apple.screensaver idleTime": { code: 1, stdout: "", stderr: "does not exist" },
    "/usr/bin/defaults export /Library/Preferences/com.apple.loginwindow -": ok(plist({}).replace("</dict>", "<key>autoLoginUser</key><string>anna</string></dict>")),
    "/usr/bin/defaults export /Library/Preferences/com.apple.TimeMachine -": ok(tmPlist("NotEncrypted", "2026-09-01T00:00:00Z")),
  }).exec, O, new Date("2026-10-18T20:00:00Z")));
  for (const [c, r] of Object.entries(rs)) assert.equal(r.result, "fail", `${c}: ${r.detail}`);
  assert.equal(rs.os_updates_installed.detail, "2 update(s) waiting to install: Safari 27.0; macOS Tahoe 26.7.1; a newer macOS is offered, not judged: macOS 27.0.1");
  assert.match(rs.screen_lock.detail, /locks after 30600 s/);
  assert.match(rs.automatic_updates.detail, /CriticalUpdateInstall/);
  assert.ok(!JSON.stringify(rs).includes("anna"), "the auto-login user's name is never sent");
  assert.match(rs.backup_recent.detail, /^Time Machine 47 day\(s\) ago/);
  assert.match(rs.backup_encrypted.detail, /^1 of 1 Time Machine destination\(s\) not encrypted;/);
  assert.ok(!/Anna/.test(JSON.stringify(rs)), "volume names are never sent");
});

test("backups: an away rotation drive is not judged, an unencrypted connected one fails, no tool is skipped", async () => {
  const good = byCheck(await runMacos(fake().exec, O, NOW));
  assert.equal(good.backup_encrypted.detail, "Time Machine (1 destination(s)) encrypted; 1 Carbon Copy Cloner destination(s) encrypted; 1 not connected, not judged; Backblaze's private encryption key is not readable on the Mac, not judged");
  const plain = byCheck(await runMacos(fake({ "/usr/sbin/diskutil info -plist /Volumes/CCC-Anna-B": DISK(false) }).exec, O, NOW));
  assert.equal(plain.backup_encrypted.result, "fail");
  const none = byCheck(await runMacos(fake({
    "/usr/bin/defaults export /Library/Preferences/com.apple.TimeMachine -": { code: 1, stdout: "", stderr: "Domain does not exist" },
    "/Applications/Carbon Copy Cloner.app/Contents/MacOS/ccc -h -c -d": { code: 127, stdout: "", stderr: "", missing: true },
    [`/bin/cat ${BZ}/bzreports/bzstat_lastbackupcompleted.xml`]: { code: 1, stdout: "", stderr: "No such file or directory" },
  }).exec, O, NOW));
  assert.equal(none.backup_recent.result, "skipped");
  assert.equal(none.backup_encrypted.result, "skipped");
});

test("a newer macOS major alone is reported, not failed; unknown output is skipped, never passed", async () => {
  const only27 = SU_SOME.split("* Label: Safari")[0] + "* Label: macOS 27.0.1-26A434\n\tTitle: macOS 27.0.1, Version: 27.0.1, Recommended: YES,\n";
  const rs = byCheck(await runMacos(fake({
    "/usr/sbin/softwareupdate --list": ok(only27),
    "/usr/bin/fdesetup status": { code: 1, stdout: "", stderr: "error" },
    "/usr/bin/xprotect status --json": { code: 1, stdout: "Command needs to be ran as root", stderr: "" },
  }).exec, O, NOW));
  assert.equal(rs.os_updates_installed.result, "pass");
  assert.match(rs.os_updates_installed.detail, /not judged: macOS 27\.0\.1/);
  assert.equal(rs.disk_encryption.result, "skipped");
  assert.equal(rs.malware_protection.result, "skipped");
});

test("parsers", () => {
  assert.equal(plistBool(plist({ A: false }), "A"), false);
  assert.equal(plistBool(plist({}), "A"), undefined);
  assert.deepEqual(pendingUpdates(SU_NONE, "26.6.2"), { known: true, pending: [], upgrades: [] });
  assert.equal(pendingUpdates("garbage", "26.6.2").known, false);
  assert.equal(lockSeconds("screenLock is off", " displaysleep 10\n", undefined).total, null);
  assert.equal(lockSeconds("screenLock delay is immediate", " displaysleep 0\n", undefined).total, null);   // nothing starts on idle
  assert.equal(lockSeconds("screenLock delay is immediate", " displaysleep 2\n", "0").total, 120);
  const tm = timeMachine(tmPlist("Encrypted", "2026-10-16T23:16:25Z"));   // the nested AttemptDates array does not end the list
  assert.deepEqual(tm, [{ encrypted: true, last: new Date("2026-10-16T23:16:25Z") }]);
  assert.deepEqual(cccHistory(CCC).map((t) => [t.destination, t.last?.toISOString()]), [["CCC-Anna-B", "2026-10-18T06:13:02.000Z"], ["CCC-Anna-A", "2026-10-03T04:00:00.000Z"]]);
});

test("off macOS, every check is skipped", { skip: process.platform === "darwin" && "runs real commands on a Mac" }, async () => {
  const rs = await macos.run({ opts: {}, env: {}, clients: {}, now: NOW, warn: () => {} });
  assert.ok(rs.length === macos.emits.length && rs.every((r) => r.result === "skipped"));
});
