// The Mac the collector runs on, read through macOS's own command-line tools: for a firm with no MDM, often
// one owner's laptop (Sagentix's own CPCSC self-assessment, 2026-10-17). Runs as the signed-in user with no
// sudo, no credential and no network call except `softwareupdate --list`, which asks Apple's catalogue.
//
// Commands and outputs (each man page as installed with macOS 26.6, and run on macOS 26.6.2 build 25G83,
// read 2026-10-17; Apple's pages cited where the man page is silent):
//   fdesetup status                       "FileVault is On." | "FileVault is Off."
//   spctl --status                        "assessments enabled" | "assessments disabled"            (Gatekeeper)
//   xprotect status --json                {"xprotect_launch_scans":true,"xprotect_background_scans":true}
//   xprotect version --json               {"xprotect_bundle_version":"5367","xprotect_bundle_install_date":"2026-10-14T07:39:52Z"}
//       Apple: XProtect signatures update "automatically—independent from system updates", checked daily
//       (Apple Platform Security, "Protecting against malware in macOS", support.apple.com/guide/security/sec469d47bd8).
//   csrutil status                        "System Integrity Protection status: enabled." | "... disabled."
//   socketfilterfw --getglobalstate       "Firewall is enabled. (State = 1)" | "Firewall is disabled. (State = 0)"
//   sysadminctl -screenLock status        on stderr: "screenLock delay is 300 seconds" | "screenLock delay is immediate" | "screenLock is off"
//   pmset -g custom                       "Battery Power:" / "AC Power:" blocks, each with " displaysleep 10" (minutes; 0 = never);
//                                         plain pmset -g (the source in use) only when -g custom gives no block
//   defaults -currentHost read com.apple.screensaver idleTime     seconds; absent or 0 = never
//   defaults export /Library/Preferences/com.apple.SoftwareUpdate -    XML plist. Keys and defaults (all true when absent)
//       from developer.apple.com/documentation/devicemanagement/softwareupdate: that MDM payload is deprecated in
//       macOS 26 and removed in 27, so automatic_updates is backed by os_updates_installed, which asks macOS itself.
//   softwareupdate --list                 "No new software available." | "* Label: …" then "\tTitle: …, Version: …, Recommended: YES, …"
//   defaults export /Library/Preferences/com.apple.loginwindow -      only whether autoLoginUser is present
//   ioreg -rd1 -c IOPlatformExpertDevice  "IOPlatformSerialNumber" = "…"
//   sw_vers -productVersion               "26.6.2"
//
// Backups (2026-10-18, read on macOS 26.6.2 with Carbon Copy Cloner 7.2.1 and Backblaze 10.0.3):
//   defaults export /Library/Preferences/com.apple.TimeMachine -     XML plist, world-readable. Per destination:
//       LastKnownEncryptionState "Encrypted" and SnapshotDates (completed backups). Apple does not document these
//       keys; Apple documents encrypting a Time Machine disk (support.apple.com/guide/mac-help/mh21241).
//   ccc -h -c -d                          CCC's own CLI usage text: "Print a summary of task history", "-c prints in CSV
//       format", "-d prints dates in seconds since Midnight Jan 1, 1970". Rows: "task","source","destination",
//       "epoch","duration","size","Success"|"Failed","files". A rotated drive that is away shows "Failed".
//   diskutil info -plist /Volumes/<CCC destination>   FileVault true|false; absent when the drive is not connected.
//   cat /Library/Backblaze.bzpkg/bzdata/bzreports/bzstat_lastbackupcompleted.xml   gmt_millis of the last completed
//       backup; observed, not documented. Its presence is how the source knows Backblaze is installed.
//   Backblaze's private encryption key is NOT read: no local file records whether one is set. bzinfo.xml's
//   lock_PEK sits beside lock_exclusion and lock_schedule (settings an administrator can lock), and was misread as
//   the key's state until 2026-10-18. Whether Backblaze holds the key (backblaze.com/computer-backup/docs/encryption)
//   is a person's answer, so backup_encrypted names Backblaze as not judged.
//
// Personal data: the Mac is named by its serial only, never its computer name or host name; the auto-login
// user's name is never read into a result.

import { execFile } from "node:child_process";
import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter } from "./readonly_http.ts";
import { ageDays, cleanSerial, posInt } from "./device_common.ts";

export const MACOS_CHECKS = ["disk_encryption", "os_updates_installed", "automatic_updates", "malware_protection", "malware_definitions_current",
  "system_integrity", "firewall", "screen_lock", "auto_login_off", "backup_recent", "backup_encrypted"] as const;
type C = (typeof MACOS_CHECKS)[number];

export const DEFAULTS = { lockSeconds: 900, xprotectDays: 14, backupDays: 7 } as const;
/** The software-update preferences that must not be false (absent means true, Apple's default). */
export const UPDATE_KEYS = ["AutomaticCheckEnabled", "AutomaticDownload", "AutomaticallyInstallMacOSUpdates", "CriticalUpdateInstall", "ConfigDataInstall"] as const;

export interface Run { code: number; stdout: string; stderr: string; missing?: boolean }
/** Runs one fixed command with fixed arguments, never through a shell. */
export type MacExec = (cmd: string, args: readonly string[], timeoutMs?: number) => Promise<Run>;

export const realExec: MacExec = (cmd, args, timeoutMs = 30_000) => new Promise((resolve) => {
  execFile(cmd, [...args], { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" } }, (err, stdout, stderr) => {
    const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
    resolve({ code: e ? (typeof e.code === "number" ? e.code : -1) : 0, stdout: String(stdout), stderr: String(stderr), missing: e?.code === "ENOENT" });
  });
});

const CMD = {
  fdesetup: "/usr/bin/fdesetup", spctl: "/usr/sbin/spctl", xprotect: "/usr/bin/xprotect", csrutil: "/usr/bin/csrutil",
  firewall: "/usr/libexec/ApplicationFirewall/socketfilterfw", sysadminctl: "/usr/sbin/sysadminctl", pmset: "/usr/bin/pmset",
  defaults: "/usr/bin/defaults", softwareupdate: "/usr/sbin/softwareupdate", ioreg: "/usr/sbin/ioreg", swVers: "/usr/bin/sw_vers",
  ccc: "/Applications/Carbon Copy Cloner.app/Contents/MacOS/ccc", diskutil: "/usr/sbin/diskutil", cat: "/bin/cat",
} as const;
const BZ = "/Library/Backblaze.bzpkg/bzdata";

const json = (s: string): Record<string, unknown> | undefined => { try { const v = JSON.parse(s); return v && typeof v === "object" ? v : undefined; } catch { return undefined; } };
/** A boolean key of an XML plist: true, false, or undefined when absent. */
export function plistBool(xml: string, key: string): boolean | undefined {
  const m = xml.match(new RegExp(`<key>${key}</key>\\s*<(true|false)\\s*/>`));
  return m ? m[1] === "true" : undefined;
}
const major = (v: string) => Number(v.split(".")[0]);

/** Time Machine destinations from its preferences plist: encryption state and the newest completed backup. */
export function timeMachine(xml: string): { encrypted: boolean; last: Date | undefined }[] {
  const at = xml.search(/<key>Destinations<\/key>\s*<array>/);
  if (at < 0) return [];
  // Walk the tags so a nested <array> (AttemptDates, SnapshotDates) does not end the destinations list.
  const body = xml.slice(xml.indexOf("<array>", at) + "<array>".length), dicts: string[] = [];
  let depth = 0, start = -1;
  for (const m of body.matchAll(/<(\/?)(array|dict)>/g)) {
    if (m[1]) { depth--; if (depth === 0 && m[2] === "dict") dicts.push(body.slice(start, m.index)); if (depth < 0) break; }
    else { if (depth === 0 && m[2] === "dict") start = m.index!; depth++; }
  }
  return dicts.map((d) => {
    const snaps = d.match(/<key>SnapshotDates<\/key>\s*<array>([\s\S]*?)<\/array>/)?.[1] ?? "";
    const ts = [...snaps.matchAll(/<date>([^<]+)<\/date>/g)].map((m) => Date.parse(m[1])).filter(Number.isFinite);
    return { encrypted: /<key>LastKnownEncryptionState<\/key>\s*<string>Encrypted<\/string>/.test(d), last: ts.length ? new Date(Math.max(...ts)) : undefined };
  });
}

/** CCC task history (ccc -h -c -d): per task, the newest successful run and its destination volume. */
export function cccHistory(csv: string): { task: string; destination: string; last: Date | undefined }[] {
  const tasks = new Map<string, { task: string; destination: string; last: Date | undefined }>();
  for (const line of csv.split("\n")) {
    const f = [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1]);
    if (f.length < 7) continue;
    const t = tasks.get(f[0]) ?? { task: f[0], destination: f[2], last: undefined };
    const at = Number(f[3]) * 1000;
    if (f[6] === "Success" && Number.isFinite(at) && (!t.last || at > t.last.getTime())) t.last = new Date(at);
    tasks.set(f[0], t);
  }
  return [...tasks.values()];
}

/** Pending updates from `softwareupdate --list`: recommended ones, and newer macOS majors (an upgrade, reported, not judged). */
export function pendingUpdates(out: string, osVersion: string | undefined): { known: boolean; pending: string[]; upgrades: string[] } {
  if (/No new software available/i.test(out)) return { known: true, pending: [], upgrades: [] };
  const titles = [...out.matchAll(/^\s*Title:\s*([^,\n]+),\s*Version:\s*([^,\n]+)(.*)$/gm)];
  if (!titles.length) return { known: false, pending: [], upgrades: [] };
  const pending: string[] = [], upgrades: string[] = [];
  for (const [, title, version, rest] of titles) {
    const name = title.trim().endsWith(version.trim()) ? title.trim() : `${title.trim()} ${version.trim()}`;
    if (/^macOS\b/.test(title.trim()) && osVersion && major(version.trim()) > major(osVersion)) upgrades.push(name);
    else if (!/Recommended:\s*NO/i.test(rest)) pending.push(name);
  }
  return { known: true, pending, upgrades };
}

/** Seconds of inactivity before the Mac asks for a password, or null when it never does. */
export function lockSeconds(screenLock: string, pmset: string, idleTime: string | undefined): { total: number | null; why: string } {
  if (/screenLock is off/i.test(screenLock)) return { total: null, why: "no password is asked after sleep or the screen saver (screenLock is off)" };
  const d = /immediate/i.test(screenLock) ? 0 : Number(screenLock.match(/delay is (\d+) seconds/)?.[1] ?? NaN);
  if (!Number.isFinite(d)) return { total: null, why: "sysadminctl did not report the screen-lock delay" };
  const display = Number(pmset.match(/^\s*displaysleep\s+(\d+)/m)?.[1] ?? 0) * 60, saver = Number(idleTime ?? 0);
  const onsets = [display, saver].filter((x) => Number.isFinite(x) && x > 0);
  if (!onsets.length) return { total: null, why: `neither the display nor the screen saver turns on when idle (password delay ${d} s)` };
  const onset = Math.min(...onsets);
  return { total: onset + d, why: `idle ${onset} s before the display sleeps or the screen saver starts, then ${d} s before a password is asked` };
}

/**
 * The pmset settings of each power source, from `pmset -g custom` ("Battery Power:", "AC Power:", "UPS Power:",
 * each followed by its settings). man pmset (macOS 27.0.1, read 2026-10-26): "-g (with no argument) will display the
 * settings currently in use" and "-g custom displays custom settings for all power sources". A laptop on its charger
 * shows only the AC values under plain -g, so its battery display sleep went unseen.
 */
export function powerSources(custom: string): [string, string][] {
  const out: [string, string][] = [];
  for (const block of custom.split(/^(?=\S[^\n]*Power:\s*$)/m)) {
    const name = block.match(/^(\S[^\n]*Power):\s*$/m)?.[1];
    if (name && /displaysleep/.test(block)) out.push([name, block]);
  }
  return out;
}

export async function runMacos(exec: MacExec, o: { lockSeconds: number; xprotectDays: number; backupDays: number }, now: Date): Promise<Result[]> {
  const sh = (c: string, a: string[], t?: number) => exec(c, a, t);
  const [ver, serialOut] = await Promise.all([sh(CMD.swVers, ["-productVersion"]), sh(CMD.ioreg, ["-rd1", "-c", "IOPlatformExpertDevice"])]);
  const osVersion = ver.code === 0 ? ver.stdout.trim() : undefined;
  const serial = cleanSerial(serialOut.stdout.match(/"IOPlatformSerialNumber"\s*=\s*"([^"]+)"/)?.[1]);
  const out = new Emitter<C>("macos", `mac${serial ? ` serial ${serial}` : ""}${osVersion ? ` macOS ${osVersion}` : ""}`);
  const gone = (r: Run, what: string, c: C) => { out.add(c, "skipped", r.missing ? `${what} is not on this Mac` : `${what} answered exit ${r.code}`); };

  const fv = await sh(CMD.fdesetup, ["status"]);
  if (/FileVault is On/.test(fv.stdout)) out.add("disk_encryption", "pass", "FileVault is on");
  else if (/FileVault is Off/.test(fv.stdout)) out.add("disk_encryption", "fail", "FileVault is off");
  else gone(fv, "fdesetup status", "disk_encryption");

  const su = await sh(CMD.softwareupdate, ["--list"], 180_000);
  const p = pendingUpdates(`${su.stdout}\n${su.stderr}`, osVersion);
  if (!p.known) gone(su, "softwareupdate --list", "os_updates_installed");
  else out.add("os_updates_installed", p.pending.length ? "fail" : "pass",
    (p.pending.length ? `${p.pending.length} update(s) waiting to install: ${p.pending.join("; ")}` : "no update waiting")
    + (p.upgrades.length ? `; a newer macOS is offered, not judged: ${p.upgrades.join("; ")}` : ""));

  const prefs = await sh(CMD.defaults, ["export", "/Library/Preferences/com.apple.SoftwareUpdate", "-"]);
  if (prefs.code !== 0 && !prefs.missing) out.add("automatic_updates", "pass", `no software-update preference is set, so every automatic option is on (Apple's default)`);
  else if (prefs.missing) gone(prefs, "defaults", "automatic_updates");
  else {
    // macOS 27 dropped the "Check for updates" switch: Apple's "Software Update settings on Mac" (support.apple.com/
    // guide/mac-help/mchla7037245, macOS 27 edition, read 2026-10-26) lists only "Download new updates when available",
    // "Install macOS updates" and "Install Security Responses and system files", and the SoftwareUpdate payload marks
    // AutomaticCheckEnabled "Removed: macOS 27+" (developer.apple.com/documentation/devicemanagement/softwareupdate,
    // read 2026-10-26). A leftover false there can be neither seen nor changed in Settings, so from 27 it is not judged.
    const major = Number((osVersion ?? "").split(".")[0]);
    const keys = major >= 27 ? UPDATE_KEYS.filter((k) => k !== "AutomaticCheckEnabled") : [...UPDATE_KEYS];
    const note = keys.length < UPDATE_KEYS.length ? "; AutomaticCheckEnabled not judged on macOS 27 or later" : "";
    const off = keys.filter((k) => plistBool(prefs.stdout, k) === false);
    out.add("automatic_updates", off.length ? "fail" : "pass", off.length ? `turned off: ${off.join(", ")}${note}` : `on: ${keys.join(", ")} (absent keys default to on)${note}`);
  }

  const [gk, xs] = await Promise.all([sh(CMD.spctl, ["--status"]), sh(CMD.xprotect, ["status", "--json"])]);
  const st = json(xs.stdout), gkOn = /assessments enabled/.test(gk.stdout) ? true : /assessments disabled/.test(gk.stdout) ? false : undefined;
  if (gkOn === undefined || !st) out.add("malware_protection", "skipped", gkOn === undefined ? "spctl --status did not answer" : "xprotect status did not answer");
  else {
    const bad = [!gkOn && "Gatekeeper assessments disabled", st.xprotect_launch_scans !== true && "XProtect launch scans off",
                 st.xprotect_background_scans !== true && "XProtect background scans off"].filter(Boolean);
    out.add("malware_protection", bad.length ? "fail" : "pass", bad.length ? bad.join("; ") : "Gatekeeper assessments enabled; XProtect launch and background scans on");
  }

  const xv = json((await sh(CMD.xprotect, ["version", "--json"])).stdout);
  const installed = typeof xv?.xprotect_bundle_install_date === "string" ? xv.xprotect_bundle_install_date : undefined;
  const age = installed ? ageDays(installed, now) : undefined;
  if (age === undefined) out.add("malware_definitions_current", "skipped", "xprotect version did not report an install date");
  else out.add("malware_definitions_current", age <= o.xprotectDays ? "pass" : "fail",
    `XProtect ${String(xv!.xprotect_bundle_version ?? "?").slice(0, 20)} installed ${Math.floor(age)} day(s) ago (at most ${o.xprotectDays})`);

  const sip = await sh(CMD.csrutil, ["status"]);
  if (/status: enabled/.test(sip.stdout)) out.add("system_integrity", "pass", "System Integrity Protection is enabled");
  else if (/status: disabled/.test(sip.stdout) || /status: unknown/.test(sip.stdout)) out.add("system_integrity", "fail", "System Integrity Protection is not fully enabled");
  else gone(sip, "csrutil status", "system_integrity");

  const fw = await sh(CMD.firewall, ["--getglobalstate"]);
  const state = fw.stdout.match(/State = (\d)/)?.[1];
  if (state === undefined) gone(fw, "socketfilterfw --getglobalstate", "firewall");
  else out.add("firewall", state === "0" ? "fail" : "pass", state === "0" ? "the macOS application firewall is off" : `the macOS application firewall is on (state ${state})`);

  const [sl, pmc, idle] = await Promise.all([sh(CMD.sysadminctl, ["-screenLock", "status"]), sh(CMD.pmset, ["-g", "custom"]),
    sh(CMD.defaults, ["-currentHost", "read", "com.apple.screensaver", "idleTime"])]);
  if (!/screenLock/i.test(`${sl.stdout}${sl.stderr}`)) gone(sl, "sysadminctl -screenLock status", "screen_lock");
  else {
    // Every power source is judged and the worst one counts; plain -g (the source in use) only when -g custom says nothing.
    let sources = pmc.code === 0 ? powerSources(pmc.stdout) : [];
    if (!sources.length) sources = [["the power source in use", (await sh(CMD.pmset, ["-g"])).stdout]];
    const saver = idle.code === 0 ? idle.stdout.trim() : undefined;
    const each = sources.map(([name, txt]) => ({ name, ...lockSeconds(`${sl.stdout}\n${sl.stderr}`, txt, saver) }));
    const l = each.find((x) => x.total === null) ?? each.reduce((a, b) => ((b.total as number) > (a.total as number) ? b : a));
    const on = sources.length > 1 ? ` on ${l.name}` : "";
    out.add("screen_lock", l.total !== null && l.total <= o.lockSeconds ? "pass" : "fail",
      `${l.total === null ? "never locks" : `locks after ${l.total} s`}${on} (at most ${o.lockSeconds}): ${l.why}${sources.length > 1 ? ` (worst of ${sources.map(([n]) => n).join(", ")})` : ""}`);
  }

  const lw = await sh(CMD.defaults, ["export", "/Library/Preferences/com.apple.loginwindow", "-"]);
  if (lw.missing) gone(lw, "defaults", "auto_login_off");
  else out.add("auto_login_off", /<key>autoLoginUser<\/key>/.test(lw.stdout) ? "fail" : "pass",
    /<key>autoLoginUser<\/key>/.test(lw.stdout) ? "automatic login is on" : "automatic login is off");

  // Backups. A tool that is not installed is left out; volume and task names never go into a result.
  const recent: string[] = [], stale: string[] = [], plain: string[] = [], sealed: string[] = [];
  const days = (d: Date) => Math.floor(ageDays(d.toISOString(), now)!);
  const tm = await sh(CMD.defaults, ["export", "/Library/Preferences/com.apple.TimeMachine", "-"]);
  const tmd = tm.code === 0 ? timeMachine(tm.stdout) : [];
  if (tmd.length) {
    const last = tmd.map((d) => d.last).filter((d): d is Date => !!d).sort((a, b) => b.getTime() - a.getTime())[0];
    (last && days(last) <= o.backupDays ? recent : stale).push(`Time Machine ${last ? `${days(last)} day(s) ago` : "has no completed backup"}`);
    const n = tmd.filter((d) => !d.encrypted).length;
    (n ? plain : sealed).push(n ? `${n} of ${tmd.length} Time Machine destination(s) not encrypted` : `Time Machine (${tmd.length} destination(s)) encrypted`);
  }
  const cc = await sh(CMD.ccc, ["-h", "-c", "-d"]);
  const tasks = cc.code === 0 ? cccHistory(cc.stdout) : [];
  if (tasks.length) {
    const last = tasks.map((x) => x.last).filter((d): d is Date => !!d).sort((a, b) => b.getTime() - a.getTime())[0];
    (last && days(last) <= o.backupDays ? recent : stale).push(`Carbon Copy Cloner ${last ? `${days(last)} day(s) ago` : "has no successful run"} (${tasks.length} task(s))`);
    let on = 0, off = 0, away = 0;
    for (const dest of new Set(tasks.map((x) => x.destination))) {
      if (!/^[\w .-]{1,64}$/.test(dest) || dest.includes("..")) { away++; continue; }
      const di = await sh(CMD.diskutil, ["info", "-plist", `/Volumes/${dest}`]);
      const fv = di.code === 0 ? plistBool(di.stdout, "FileVault") : undefined;
      if (fv === undefined) away++; else if (fv) on++; else off++;
    }
    const tail = away ? `; ${away} not connected, not judged` : "";
    if (off) plain.push(`${off} Carbon Copy Cloner destination(s) not encrypted${tail}`);
    else if (on) sealed.push(`${on} Carbon Copy Cloner destination(s) encrypted${tail}`);
    else sealed.push(`Carbon Copy Cloner destinations not connected, not judged`);
  }
  const lb = await sh(CMD.cat, [`${BZ}/bzreports/bzstat_lastbackupcompleted.xml`]);
  if (lb.code === 0) {
    sealed.push("Backblaze's private encryption key is not readable on the Mac, not judged");
    const ms = Number(lb.stdout.match(/gmt_millis="(\d+)"/)?.[1]);
    const last = Number.isFinite(ms) && ms > 0 ? new Date(ms) : undefined;
    (last && days(last) <= o.backupDays ? recent : stale).push(`Backblaze ${last ? `${days(last)} day(s) ago` : "has no completed backup"}`);
  }
  if (!recent.length && !stale.length) out.add("backup_recent", "skipped", "no Time Machine, Carbon Copy Cloner or Backblaze backup found");
  else out.add("backup_recent", stale.length ? "fail" : "pass", `${[...stale, ...recent].join("; ")} (at most ${o.backupDays})`);
  if (!plain.length && !sealed.length) out.add("backup_encrypted", "skipped", "no Time Machine, Carbon Copy Cloner or Backblaze backup found");
  else out.add("backup_encrypted", plain.length ? "fail" : "pass", [...plain, ...sealed].join("; "));
  return out.results;
}

export const macos: Source = {
  name: "macos",
  options: {
    "macos-max-lock-seconds": { type: "string", help: `seconds of inactivity before the Mac must ask for a password (default ${DEFAULTS.lockSeconds})` },
    "macos-xprotect-days": { type: "string", help: `days since XProtect's last update before malware_definitions_current fails (default ${DEFAULTS.xprotectDays})` },
    "macos-backup-days": { type: "string", help: `days since each backup tool's last completed backup before backup_recent fails (default ${DEFAULTS.backupDays})` },
  },
  emits: MACOS_CHECKS.map((c) => `macos.${c}`),
  describe: () => "this Mac (macOS command-line tools, no sudo)",
  async run(ctx: SourceContext) {
    const exec = (ctx.clients.macos as MacExec | undefined) ?? (process.platform === "darwin" ? realExec : undefined);
    if (!exec) {
      const out = new Emitter<C>("macos", "mac");
      out.skipAll(MACOS_CHECKS, `the macos source runs only on macOS (this is ${process.platform})`);
      return out.results;
    }
    return runMacos(exec, { lockSeconds: posInt(ctx.opts["macos-max-lock-seconds"], DEFAULTS.lockSeconds),
                            xprotectDays: posInt(ctx.opts["macos-xprotect-days"], DEFAULTS.xprotectDays),
                            backupDays: posInt(ctx.opts["macos-backup-days"], DEFAULTS.backupDays) }, ctx.now);
  },
};
