// Helpers for the sources that read a report file another tool already wrote (ScubaGoggles,
// ScubaGear, Trivy, Grype, Syft, Gitleaks, OpenSSF Scorecard). Nothing here touches the network: the
// customer's pipeline runs the tool, and the collector reads what it wrote.

import { closeSync, fstatSync, openSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import type { OptionValue } from "../types.ts";

/** Largest report read, in bytes. A Trivy or Grype report of a big image stays well under this. */
export const MAX_REPORT_BYTES = 256 * 1024 * 1024;
const MAX_IDS = 50;

export type Read<T> = { data: T; path: string; mtime: Date } | { error: string; path: string };

/** A JSON file, with a UTF-8 BOM (Windows PowerShell 5.1 writes one) removed. Never throws. */
export function readJsonFile(path: string): Read<unknown> {
  const unreadable = (e: unknown) => ({ path, error: `${basename(path)} not readable (${(e as NodeJS.ErrnoException).code ?? "error"})` });
  // One open, then checks and the read on that descriptor: the file cannot be swapped between them (CodeQL js/file-system-race).
  let fd: number;
  try { fd = openSync(path, "r"); } catch (e) { return unreadable(e); }
  let st, text: string;
  try {
    st = fstatSync(fd);
    if (!st.isFile()) return { path, error: `${basename(path)} is not a file` };
    if (st.size > MAX_REPORT_BYTES) return { path, error: `${basename(path)} is larger than ${MAX_REPORT_BYTES / 1024 / 1024} MB` };
    text = readFileSync(fd, "utf8");
  } catch (e) { return unreadable(e); } finally { closeSync(fd); }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try { return { path, data: JSON.parse(text), mtime: st.mtime }; } catch {
    return { path, error: `${basename(path)} is not valid JSON` };
  }
}

/**
 * The file itself, or, for a directory, the most recently modified file whose name matches `pattern`
 * up to `depth` levels down (ScubaGoggles and ScubaGear write into a dated subfolder).
 */
export function resolveReport(pathOrDir: string, pattern: RegExp, depth = 3): string | { error: string } {
  let st;
  try { st = statSync(pathOrDir); } catch (e) {
    return { error: `${basename(pathOrDir)} not readable (${(e as NodeJS.ErrnoException).code ?? "error"})` };
  }
  if (st.isFile()) return pathOrDir;
  let best: { p: string; t: number } | undefined;
  const walk = (dir: string, d: number) => {
    let names: string[];
    try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      const p = join(dir, n);
      let s;
      try { s = statSync(p); } catch { continue; }
      if (s.isDirectory()) { if (d > 0) walk(p, d - 1); }
      else if (pattern.test(n) && (!best || s.mtimeMs > best.t)) best = { p, t: s.mtimeMs };
    }
  };
  walk(pathOrDir, depth);
  return best ? best.p : { error: `no file named like ${pattern.source} under ${basename(pathOrDir)}` };
}

/** A repeatable path option as a list (each value may also be comma-separated). */
export const paths = (v: OptionValue): string[] =>
  (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);

/** A positive number option, or the default. */
export const posNum = (v: OptionValue, d: number): number => {
  const n = Number(typeof v === "string" ? v : NaN);
  return Number.isFinite(n) && n > 0 ? n : d;
};

/** A non-negative number option (0 allowed), or the default. */
export const nonNegNum = (v: OptionValue, d: number): number => {
  const n = Number(typeof v === "string" && v.trim() !== "" ? v : NaN);
  return Number.isFinite(n) && n >= 0 ? n : d;
};

/** Why a report is too old to count, or undefined when it is fresh enough. `when` is any date string. */
export function staleness(when: string | undefined, now: Date, maxDays: number, what = "report"): string | undefined {
  if (!when) return `the ${what} carries no date, so its age cannot be told`;
  const t = Date.parse(when);
  if (!Number.isFinite(t)) return `the ${what} date ${JSON.stringify(when.slice(0, 40))} does not parse`;
  const days = (now.getTime() - t) / 86_400_000;
  if (days > maxDays) return `the ${what} is from ${new Date(t).toISOString().slice(0, 10)}, ${Math.floor(days)} days old; at most ${maxDays} allowed`;
  return undefined;
}

/** " (a, b, c, and 7 more)" for up to 50 ids, or "" when there are none. */
export const idList = (xs: string[], label = "", max = MAX_IDS): string =>
  xs.length ? ` (${label}${xs.slice(0, max).join(", ")}${xs.length > max ? `, and ${xs.length - max} more` : ""})` : "";

/** "CRITICAL 2, HIGH 5" from a count map, in the order given. */
export const bySeverity = (counts: Map<string, number>, order: readonly string[]): string =>
  order.filter((s) => (counts.get(s) ?? 0) > 0).map((s) => `${s} ${counts.get(s)}`).join(", ") || "none";

/**
 * A scanned target's name without the local path above it: "/Users/<person>/work/app" becomes ".../work/app". An
 * absolute path carries the account's home folder, often a person's name (found in the 2026-10-18 practice run).
 * Image references and relative paths pass unchanged.
 */
export function localTarget(name: string): string {
  if (!/^(\/|~|[A-Za-z]:[\\/]|\\\\)/.test(name)) return name;
  // The folder right under Users or home is the account name: it becomes "~" even when it is among the last two.
  const parts = name.split(/[\\/]+/).filter(Boolean).map((p, i, a) => (i > 0 && /^(Users|home)$/i.test(a[i - 1]) ? "~" : p));
  return `.../${parts.slice(-2).join("/")}`;
}
