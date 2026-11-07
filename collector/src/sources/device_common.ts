// Helpers shared by the device sources (Fleet, Intune, Jamf Pro): a device's resource string with
// no person in it, version comparison for "minimum OS" checks, and the age of a timestamp.
//
// A device is named by the vendor's own id and its hardware serial, never by its hostname, computer
// name or display name, which often carry the owner's name ("Anna's MacBook Pro").

import { DAY_MS } from "./readonly_http.ts";

/** A serial number as sent: letters, digits and dashes only, at most 64 characters. */
export function cleanSerial(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const s = v.replace(/[^A-Za-z0-9-]/g, "").slice(0, 64);
  return s || undefined;
}

/** "<kind> <id> serial <serial>", e.g. "fleet host 12 serial C02XK0AAJGH6". */
export function deviceResource(kind: string, id: unknown, serial: unknown): string {
  const sid = String(id ?? "?").replace(/[^A-Za-z0-9._:-]/g, "").slice(0, 80) || "?";
  const sn = cleanSerial(serial);
  return `${kind} ${sid}${sn ? ` serial ${sn}` : ""}`;
}

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
/** Admin-authored text (a policy name) with any email address cut out, quoted and shortened. */
export const label = (v: unknown, max = 80) => JSON.stringify(String(v ?? "").replace(EMAIL, "[email]").replace(/\s+/g, " ").trim().slice(0, max));

/** The dotted version inside an OS string. Windows builds ("Microsoft Windows 11 Pro 23H2 10.0.22631.4602") take the last one, others the first. */
export function versionIn(os: unknown): number[] | undefined {
  if (typeof os !== "string") return undefined;
  const all = os.match(/\d+(?:\.\d+)+|\b\d+\b/g);
  if (!all?.length) return undefined;
  const dotted = all.filter((x) => x.includes("."));
  const pick = /windows/i.test(os) && dotted.length ? dotted[dotted.length - 1] : (dotted[0] ?? all[0]);
  return pick.split(".").map(Number);
}

/** <0, 0 or >0 as a is older than, equal to or newer than b; missing parts count as 0. */
export function cmpVersion(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

/**
 * `--x-min-os` values: "darwin=15.0", "windows=10.0.22631", "macOS=14" (repeatable or comma
 * separated). Keys are lower-cased; a bare version ("14.5") applies to every platform as key "*".
 */
export function minOsOption(v: unknown): Map<string, number[]> {
  const out = new Map<string, number[]>();
  const items = (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => String(s).split(","));
  for (const it of items) {
    const [k, ver] = it.includes("=") ? it.split("=", 2) : ["*", it];
    const parsed = versionIn(ver.trim());
    if (k.trim() && parsed) out.set(k.trim().toLowerCase(), parsed);
  }
  return out;
}

export const showVersion = (v: number[]) => v.join(".");

/** Whole days between `when` and `now`, or undefined when `when` is not a date. */
export function ageDays(when: unknown, now: Date): number | undefined {
  const t = typeof when === "string" ? Date.parse(when) : NaN;
  return Number.isFinite(t) ? Math.floor((now.getTime() - t) / DAY_MS) : undefined;
}

/** A positive integer option, else the default. */
export const posInt = (v: unknown, dflt: number) => {
  const n = typeof v === "string" ? Number(v) : NaN;
  return Number.isInteger(n) && n > 0 ? n : dflt;
};

/** Values of a repeatable string option. */
export const many = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === "string" ? [v] : []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);

// ── Wipe and retire records (2026-11-07; SOC 2 CC6.5, SP 800-53 mp-6 and sr-12): a device leaving service is wiped or
// retired by a recorded MDM action that finished. Each source reads its own action log into WipeAction rows.
export const WIPE_DEFAULTS = { periodDays: 365, graceDays: 7 } as const;
export type WipeState = "done" | "failed" | "pending";
export interface WipeAction {
  /** The device's resource string (deviceResource). */
  resource: string;
  /** The action in the vendor's words (factoryReset, removeCompanyData, ERASE_DEVICE, EraseDevice). */
  action: string;
  /** An action that removes the device's record without wiping or retiring it (Intune "delete"). */
  removalOnly?: boolean;
  state: WipeState;
  /** The vendor's own state value, quoted in the detail. */
  stateRaw: string;
  requested: string;
  completed?: string;
}

/**
 * One result per device with a wipe, retire or removal action in the period: pass when a wipe or retire finished; fail
 * when it failed, stayed pending past the grace days, or the device was only removed from management with no wipe or
 * retire recorded; skipped while a recent one is pending. Returns how many devices it judged.
 */
export function judgeWipes(actions: WipeAction[], o: { since: number; graceDays: number; now: Date; where: string },
  add: (resource: string, result: "pass" | "fail" | "skipped", detail: string) => void): number {
  const by = new Map<string, WipeAction[]>();
  for (const a of actions) {
    const t = Date.parse(a.requested);
    if (!Number.isFinite(t) || t < o.since || t > o.now.getTime()) continue;
    by.set(a.resource, [...(by.get(a.resource) ?? []), a]);
  }
  const show = (a: WipeAction) => `${a.action} ${a.stateRaw}, requested ${a.requested.slice(0, 10)}${a.completed ? `, completed ${a.completed.slice(0, 10)}` : ""}`;
  for (const [res, xs] of by) {
    xs.sort((a, b) => Date.parse(a.requested) - Date.parse(b.requested));
    const wipes = xs.filter((a) => !a.removalOnly);
    const done = wipes.find((a) => a.state === "done");
    if (done) { add(res, "pass", `${show(done)}${o.where}`); continue; }
    if (!wipes.length) { add(res, "fail", `removed from management (${xs.map(show).join("; ")}) with no wipe or retire recorded${o.where}`); continue; }
    const last = wipes[wipes.length - 1];
    if (last.state === "failed") { add(res, "fail", `${show(last)}; a finished wipe or retire is required${o.where}`); continue; }
    const age = Math.floor((o.now.getTime() - Date.parse(last.requested)) / DAY_MS);
    if (age > o.graceDays) add(res, "fail", `${show(last)}, not finished after ${age} days (at most ${o.graceDays} allowed)${o.where}`);
    else add(res, "skipped", `${show(last)}, pending for ${age} day(s); judged once it finishes or ${o.graceDays} days pass${o.where}`);
  }
  return by.size;
}
