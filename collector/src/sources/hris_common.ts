// What an HR system shows about joiners and leavers, judged the same way for every HR source (bamboohr.ts, rippling.ts).
// Each source reads its own API into Person rows; this module turns them into the five checks below, one result per
// person in the period, so an auditor's population (leavers, hires) is the list of results and a sample is a subset of it.
//
//   leaver_access_removed   each person whose employment ended in the period lost identity-provider access within N hours
//                           of the end of their last day (joined with the identity provider in directory.ts)
//   hire_acknowledgement    each person hired in the period has a recorded acknowledgement of the code of conduct or
//                           acceptable-use rules (a date field the customer names)
//   hire_training           each person hired in the period completed security awareness training within N days of
//                           starting (the LMS export the lms source reads, joined by employee id or work email)
//   hire_background_check   each person hired in the period has a background check recorded (a date field the customer
//                           names); skipped when the customer names none, because policy decides who needs one
//   org_chart_complete      each active person has a manager and a job title, and at most N people have no manager
//
// Personal data: a person is named by the HR system's employee id. Emails, names and field values other than dates never
// reach a result; the email is used only to look the person up in the identity provider and the LMS export.

import type { Read, Result, SourceContext } from "../types.ts";
import { directoryFor, type Account, type Directory } from "./directory.ts";
import { readTable } from "./lms.ts";
import { DAY_MS, firstIds, intOpt, type HttpResponse } from "./readonly_http.ts";

export const HRIS_CHECKS = ["leaver_access_removed", "hire_acknowledgement", "hire_training", "hire_background_check", "org_chart_complete"] as const;
export type HrisCheck = (typeof HRIS_CHECKS)[number];

export const HRIS_DEFAULTS = { periodDays: 365, accessHours: 24, trainingDays: 30, maxRoots: 1, maxLookups: 500, course: "security awareness" } as const;

export interface Person {
  id: string;
  email?: string;
  /** "active", "terminated", or the provider's other value in lower case. */
  status: string;
  hired?: string;
  /** The last day of employment (YYYY-MM-DD). */
  left?: string;
  managerId?: string;
  title?: string;
  /** Values of the customer-named date fields, by option key. */
  dates: { ack?: string; background?: string };
}

export interface HrisOptions {
  since: Date; accessHours: number; trainingDays: number; maxRoots: number; maxLookups: number;
  idp?: string; trainingCsv?: string; course: string;
  ackField?: string; backgroundField?: string;
}

/** The common options every HR source takes, under its own prefix (--bamboohr-idp, --rippling-idp, ...). */
export function hrisOptionSpecs(p: string) {
  return {
    [`${p}-idp`]: { type: "string" as const, help: "identity provider to join leavers with: okta, entra, google_workspace or jumpcloud (its own variables are used)" },
    [`${p}-since`]: { type: "string" as const, help: `start of the period, YYYY-MM-DD (default ${HRIS_DEFAULTS.periodDays} days ago)` },
    [`${p}-access-hours`]: { type: "string" as const, help: `hours after a last day by which access must be gone (default ${HRIS_DEFAULTS.accessHours})` },
    [`${p}-training-days`]: { type: "string" as const, help: `days after a start date by which training must be done (default ${HRIS_DEFAULTS.trainingDays}); reads --training-csv` },
    [`${p}-max-without-manager`]: { type: "string" as const, help: `active people allowed no manager, the top of the chart (default ${HRIS_DEFAULTS.maxRoots})` },
    [`${p}-ack-field`]: { type: "string" as const, help: "the date field that records the code of conduct or acceptable-use acknowledgement" },
    [`${p}-background-field`]: { type: "string" as const, help: "the date field that records a completed background check" },
  };
}

const optStr = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const DAY = /^\d{4}-\d{2}-\d{2}$/;
export const isoDay = (v: unknown): string | undefined => {
  const s = typeof v === "string" ? v.trim().slice(0, 10) : "";
  return DAY.test(s) && s !== "0000-00-00" && Number.isFinite(Date.parse(s)) ? s : undefined;
};

export function hrisOptions(p: string, ctx: SourceContext): HrisOptions | string {
  const o = ctx.opts;
  const sinceRaw = optStr(o[`${p}-since`]);
  const since = sinceRaw ? new Date(`${isoDay(sinceRaw) ?? "x"}T00:00:00Z`) : new Date(ctx.now.getTime() - HRIS_DEFAULTS.periodDays * DAY_MS);
  if (!Number.isFinite(since.getTime())) return `--${p}-since must be a date such as 2026-01-01`;
  return {
    since,
    accessHours: intOpt(o[`${p}-access-hours`], HRIS_DEFAULTS.accessHours),
    trainingDays: intOpt(o[`${p}-training-days`], HRIS_DEFAULTS.trainingDays),
    maxRoots: intOpt(o[`${p}-max-without-manager`], HRIS_DEFAULTS.maxRoots),
    maxLookups: HRIS_DEFAULTS.maxLookups,
    idp: optStr(o[`${p}-idp`]),
    trainingCsv: optStr(o["training-csv"]),
    course: (optStr(o["lms-awareness-course"]) ?? HRIS_DEFAULTS.course).toLowerCase(),
    ackField: optStr(o[`${p}-ack-field`]),
    backgroundField: optStr(o[`${p}-background-field`]),
  };
}

const dayMs = (d: string) => Date.parse(`${d}T00:00:00Z`);
const inPeriod = (d: string | undefined, o: HrisOptions, now: Date): d is string =>
  !!d && dayMs(d) >= o.since.getTime() && dayMs(d) <= now.getTime();
const hours = (ms: number) => Math.round(ms / 3_600_000);

/** Results for one HR source. `resource` names the HR tenant; `read` is how the people list was read. */
export async function hrisChecks(prefix: string, resource: string, people: Person[], read: Read, o: HrisOptions, ctx: SourceContext,
  dir?: Directory | string): Promise<Result[]> {
  const out: Result[] = [];
  const add = (check: HrisCheck, res: string, result: Result["result"], detail: string, extra: Read = read) =>
    out.push({ ...extra, check: `${prefix}.${check}`, resource: res.slice(0, 300), result, detail: detail.slice(0, 1000) });
  const now = ctx.now, period = `since ${o.since.toISOString().slice(0, 10)}`;
  const who = (p: Person) => `${resource} employee ${p.id}`;

  // ── Leavers.
  const leavers = people.filter((p) => inPeriod(p.left, o, now));
  if (!leavers.length) add("leaver_access_removed", resource, "skipped", `no employment ended ${period}; nothing to judge`);
  else {
    const d: Directory | string = dir ?? (o.idp ? directoryFor(o.idp, ctx) : `no identity provider named (--${prefix}-idp okta|entra|google_workspace|jumpcloud)`);
    let looked = 0;
    for (const p of leavers) {
      const res = `${who(p)} left ${p.left}`;
      if (typeof d === "string") { add("leaver_access_removed", res, "skipped", `access not checked: ${d}`); continue; }
      if (!p.email) { add("leaver_access_removed", res, "skipped", "no work email in the HR record, so no account could be looked up"); continue; }
      if (looked++ >= o.maxLookups) { add("leaver_access_removed", res, "skipped", `not looked up: at most ${o.maxLookups} leavers are looked up in one run`); continue; }
      const deadline = dayMs(p.left!) + DAY_MS + o.accessHours * 3_600_000;   // end of the last day, plus N hours
      const a: Account = await d.lookup(p.email);
      const lookupRead: Read = { method: "config-read", observedAt: now.toISOString(), expected: `${d.idp} access gone within ${o.accessHours} h of the end of ${p.left}` };
      if (a.state === "error") { add("leaver_access_removed", res, "skipped", `${d.idp} not readable: ${a.why}`, { ...lookupRead, apiError: { status: 0, message: a.why } }); continue; }
      if (a.state === "active") {
        if (now.getTime() <= deadline) add("leaver_access_removed", res, "skipped", `${d.idp} account ${a.id} is still active, but the ${o.accessHours} h after the last day have not passed yet`, lookupRead);
        else add("leaver_access_removed", res, "fail", `${d.idp} account ${a.id} is still active ${hours(now.getTime() - dayMs(p.left!) - DAY_MS)} h after the last day ended; removal within ${o.accessHours} h required`, { ...lookupRead, observed: "active" });
        continue;
      }
      if (a.state === "absent") {
        add("leaver_access_removed", res, "pass", `no ${d.idp} account under the work email; when access ended is not recorded`, { ...lookupRead, observed: "no account", complete: false });
        continue;
      }
      const at = a.at ? Date.parse(a.at) : NaN;
      if (!Number.isFinite(at)) { add("leaver_access_removed", res, "pass", `${a.how}${a.id ? ` (account ${a.id})` : ""}; when is not recorded, so the ${o.accessHours} h limit is not shown`, { ...lookupRead, observed: a.state, complete: false }); continue; }
      const lag = at - (dayMs(p.left!) + DAY_MS);
      const okv = at <= deadline;
      add("leaver_access_removed", res, okv ? "pass" : "fail",
        `${a.how} at ${new Date(at).toISOString()}, ${lag <= 0 ? `${hours(-lag)} h before` : `${hours(lag)} h after`} the last day ended; within ${o.accessHours} h required`,
        { ...lookupRead, observed: `${a.state} ${new Date(at).toISOString()}` });
    }
  }

  // ── Hires.
  const hires = people.filter((p) => inPeriod(p.hired, o, now));
  const noHires = `nobody started ${period}; nothing to judge`;

  if (!o.ackField) add("hire_acknowledgement", resource, "skipped", `no acknowledgement field named (--${prefix}-ack-field); the date field that records the code of conduct or acceptable-use acknowledgement`);
  else if (!hires.length) add("hire_acknowledgement", resource, "skipped", noHires);
  else for (const p of hires) {
    const d = p.dates.ack;
    add("hire_acknowledgement", `${who(p)} started ${p.hired}`, d ? "pass" : "fail",
      d ? `${o.ackField} recorded on ${d}${dayMs(d) > dayMs(p.hired!) + 30 * DAY_MS ? " (more than 30 days after the start)" : ""}` : `${o.ackField} is empty; an acknowledgement is required of every hire`);
  }

  if (!o.backgroundField) add("hire_background_check", resource, "skipped", `no background-check field named (--${prefix}-background-field); which hires need a check is the organization's policy`);
  else if (!hires.length) add("hire_background_check", resource, "skipped", noHires);
  else for (const p of hires) {
    const d = p.dates.background;
    add("hire_background_check", `${who(p)} started ${p.hired}`, d ? "pass" : "fail",
      d ? `${o.backgroundField} recorded on ${d}` : `${o.backgroundField} is empty; a recorded background check is required`);
  }

  if (!o.trainingCsv) add("hire_training", resource, "skipped", "no training export given (--training-csv, columns person_id, course, completed_on)");
  else if (!hires.length) add("hire_training", resource, "skipped", noHires);
  else {
    const t = readTable(o.trainingCsv, ["person_id", "course", "completed_on"]);
    if ("error" in t) add("hire_training", resource, "skipped", t.error);
    else {
      const done = new Map<string, number>();
      for (const r of t.rows) {
        const day = isoDay(r.completed_on);
        if (!day || !r.course.toLowerCase().includes(o.course)) continue;
        const k = r.person_id.toLowerCase(), v = dayMs(day);
        if (!done.has(k) || v < done.get(k)!) done.set(k, v);
      }
      for (const p of hires) {
        const res = `${who(p)} started ${p.hired}`;
        const when = done.get(p.id.toLowerCase()) ?? (p.email ? done.get(p.email.toLowerCase()) : undefined);
        const due = dayMs(p.hired!) + o.trainingDays * DAY_MS;
        if (when === undefined) {
          if (now.getTime() <= due) add("hire_training", res, "skipped", `no "${o.course}" completion yet, but the ${o.trainingDays} days to complete it have not passed`);
          else add("hire_training", res, "fail", `no "${o.course}" completion in the export; due within ${o.trainingDays} days of the start`);
        } else {
          const days = Math.round((when - dayMs(p.hired!)) / DAY_MS);
          add("hire_training", res, when <= due ? "pass" : "fail", `"${o.course}" completed ${new Date(when).toISOString().slice(0, 10)}, ${days} day(s) after the start; within ${o.trainingDays} required`);
        }
      }
    }
  }

  // ── Org chart.
  const active = people.filter((p) => p.status === "active");
  if (!active.length) add("org_chart_complete", resource, "skipped", "the HR system lists no active person; nothing to judge");
  else {
    const ids = new Set(people.map((p) => p.id));
    const roots = active.filter((p) => !p.managerId), dangling = active.filter((p) => p.managerId && !ids.has(p.managerId));
    const noTitle = active.filter((p) => !p.title);
    const bad = roots.length > o.maxRoots || dangling.length > 0 || noTitle.length > 0;
    add("org_chart_complete", resource, bad ? "fail" : "pass",
      `${active.length} active people: ${roots.length} without a manager${firstIds(roots.map((p) => p.id))} (at most ${o.maxRoots} allowed, --${prefix}-max-without-manager), ` +
      `${dangling.length} whose manager is not in the HR system${firstIds(dangling.map((p) => p.id))}, ${noTitle.length} without a job title${firstIds(noTitle.map((p) => p.id))}`);
  }
  return out;
}

/** Every HR check skipped with the same reason (no credentials, the people list unreadable). */
export const hrisSkipped = (prefix: string, resource: string, detail: string, r?: HttpResponse): Result[] =>
  HRIS_CHECKS.map((c) => ({ check: `${prefix}.${c}`, resource, result: "skipped" as const, detail,
    ...(r ? { method: "config-read" as const, apiError: { status: r.status, message: detail.slice(0, 300) } } : {}) }));
