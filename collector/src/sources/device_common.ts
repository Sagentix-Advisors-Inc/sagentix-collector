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
