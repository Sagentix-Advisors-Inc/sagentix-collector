// Training records (LMS): no single API, so the customer exports two CSV files from its LMS and HR
// system and the collector reads them locally. Nothing goes over the network.
//
//   --training-csv  columns person_id, course, completed_on (ISO date)
//   --roster-csv    columns person_id, role
//
// Results report counts and person ids exactly as the customer gives them. No course name beyond the
// configured patterns, and no other column (names, emails), is ever copied into a result.

import { readFileSync } from "node:fs";
import { basename } from "node:path";
import type { OptionValue, Result, Source, SourceContext } from "../types.ts";
import { Results, allSkipped, list } from "./shared-cloud.ts";

export const LMS_CHECKS = ["security_awareness_current", "role_based_training_current", "training_records_complete"] as const;
export type LmsCheck = (typeof LMS_CHECKS)[number];

export const LMS_DEFAULTS = {
  awarenessCourse: "security awareness",
  roleCourse: "role-based",
  privilegedRoles: ["admin", "administrator", "privileged"],
  maxAgeDays: 365,
} as const;
const MAX_IDS = 50;

/** RFC 4180 CSV: quoted fields, "" inside quotes, CRLF or LF, a leading BOM. Returns rows of cells. */
export function parseCsv(text: string): string[][] {
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [], cell = "", q = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === '"') {
        if (s[i + 1] === '"') { cell += '"'; i++; } else q = false;
      } else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(cell); rows.push(row); row = []; cell = "";
    } else cell += c;
  }
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => !(r.length === 1 && r[0].trim() === ""));
}

type Table = { rows: Record<string, string>[] } | { error: string };

/** A CSV file as records keyed by lower-case header, keeping only the columns asked for. */
export function readTable(path: string, want: string[]): Table {
  let text: string;
  try { text = readFileSync(path, "utf8"); } catch (e) {
    return { error: `${basename(path)} not readable (${(e as NodeJS.ErrnoException).code ?? "error"})` };
  }
  const rows = parseCsv(text);
  if (!rows.length) return { error: `${basename(path)} is empty` };
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const missing = want.filter((w) => !head.includes(w));
  if (missing.length) return { error: `${basename(path)} has no column ${missing.join(", ")} (columns needed: ${want.join(", ")})` };
  const idx = want.map((w) => head.indexOf(w));
  return { rows: rows.slice(1).map((r) => Object.fromEntries(want.map((w, k) => [w, (r[idx[k]] ?? "").trim()]))) };
}

const ids = (xs: string[]) => (xs.length ? ` (person ids ${xs.slice(0, MAX_IDS).join(", ")}${xs.length > MAX_IDS ? `, and ${xs.length - MAX_IDS} more` : ""})` : "");
const optStr = (v: OptionValue) => (typeof v === "string" && v.trim() ? v.trim() : undefined);

export const lms: Source = {
  name: "lms",
  options: {
    "training-csv": { type: "string", help: "LMS export: person_id, course, completed_on (ISO date)" },
    "roster-csv": { type: "string", help: "people in scope: person_id, role" },
    "lms-awareness-course": { type: "string", help: `course name text that marks security awareness (default "${LMS_DEFAULTS.awarenessCourse}")` },
    "lms-role-course": { type: "string", help: `course name text that marks role-based training (default "${LMS_DEFAULTS.roleCourse}")` },
    "lms-privileged-roles": { type: "string", help: `roles that need role-based training (default ${LMS_DEFAULTS.privilegedRoles.join(",")})` },
    "lms-max-age-days": { type: "string", help: `days a completion stays current (default ${LMS_DEFAULTS.maxAgeDays})` },
  },
  emits: LMS_CHECKS.map((c) => `lms.${c}`),
  describe(opts) {
    const r = optStr(opts["roster-csv"]), t = optStr(opts["training-csv"]);
    return `roster ${r ? basename(r) : "(none)"} / training ${t ? basename(t) : "(none)"}`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const o = ctx.opts;
    const rosterPath = optStr(o["roster-csv"]), trainingPath = optStr(o["training-csv"]);
    if (!rosterPath || !trainingPath) return allSkipped("lms", LMS_CHECKS, "roster", "give --training-csv and --roster-csv");
    const resource = `roster ${basename(rosterPath)}`;
    const roster = readTable(rosterPath, ["person_id", "role"]);
    if ("error" in roster) return allSkipped("lms", LMS_CHECKS, resource, roster.error);
    const training = readTable(trainingPath, ["person_id", "course", "completed_on"]);
    if ("error" in training) return allSkipped("lms", LMS_CHECKS, resource, training.error);

    const awareness = (optStr(o["lms-awareness-course"]) ?? LMS_DEFAULTS.awarenessCourse).toLowerCase();
    const roleCourse = (optStr(o["lms-role-course"]) ?? LMS_DEFAULTS.roleCourse).toLowerCase();
    const privileged = new Set((list(o["lms-privileged-roles"]).length ? list(o["lms-privileged-roles"]) : [...LMS_DEFAULTS.privilegedRoles]).map((r) => r.toLowerCase()));
    const n = Number(optStr(o["lms-max-age-days"]));
    const maxAge = Number.isFinite(n) && n > 0 ? n : LMS_DEFAULTS.maxAgeDays;
    const cutoff = ctx.now.getTime() - maxAge * 86_400_000;

    const people = new Map<string, string>();
    for (const r of roster.rows) if (r.person_id) people.set(r.person_id, r.role.toLowerCase());

    const anyRecord = new Set<string>(), aware = new Set<string>(), roleDone = new Set<string>();
    let badDates = 0, offRoster = 0;
    for (const t of training.rows) {
      if (!t.person_id) continue;
      if (!people.has(t.person_id)) { offRoster++; continue; }
      anyRecord.add(t.person_id);
      const when = Date.parse(t.completed_on);
      if (!/^\d{4}-\d{2}-\d{2}/.test(t.completed_on) || !Number.isFinite(when)) { badDates++; continue; }
      if (when < cutoff || when > ctx.now.getTime()) continue;
      const course = t.course.toLowerCase();
      if (course.includes(awareness)) aware.add(t.person_id);
      if (course.includes(roleCourse)) roleDone.add(t.person_id);
    }
    const dateNote = badDates ? `; ${badDates} training row(s) with an unreadable completed_on were not counted` : "";
    const out = new Results<LmsCheck>("lms");
    const all = [...people.keys()];
    if (!all.length) {
      out.skipAll(LMS_CHECKS, resource, "the roster lists nobody; nothing to judge");
      return out.results;
    }

    const notAware = all.filter((p) => !aware.has(p));
    out.add("security_awareness_current", resource, notAware.length ? "fail" : "pass",
      `${all.length - notAware.length} of ${all.length} people completed a "${awareness}" course in the last ${maxAge} days, ${notAware.length} did not${ids(notAware)}${dateNote}; all required`);

    const priv = all.filter((p) => privileged.has(people.get(p) ?? ""));
    if (!priv.length) out.skip("role_based_training_current", resource, `nobody on the roster holds a privileged role (${[...privileged].join(", ")}); nothing to judge`);
    else {
      const notRole = priv.filter((p) => !roleDone.has(p));
      out.add("role_based_training_current", resource, notRole.length ? "fail" : "pass",
        `${priv.length - notRole.length} of ${priv.length} people in a privileged role completed a "${roleCourse}" course in the last ${maxAge} days, ${notRole.length} did not${ids(notRole)}${dateNote}; all required`);
    }

    const none = all.filter((p) => !anyRecord.has(p));
    out.add("training_records_complete", resource, none.length ? "fail" : "pass",
      `${all.length - none.length} of ${all.length} people have at least one training record, ${none.length} have none${ids(none)}; ${offRoster} training row(s) name people not on the roster; a record for everyone required`);
    return out.results;
  },
};
