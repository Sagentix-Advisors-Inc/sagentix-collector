// PagerDuty REST API v2, read-only: incidents and their reviews, escalation policies, on-call
// coverage and response automation. GET only, with a read-only API key (env PAGERDUTY_TOKEN; an
// admin creates it under Integrations > API Access Keys with "Read-only API Key" ticked).
//
// Every endpoint, parameter and field below was checked in PagerDuty's published OpenAPI document
// (github.com/PagerDuty/api-schema, reference/REST/openapiv3.json, info.version 2.0.0):
//   GET /incidents?since&until&statuses[]=resolved&urgencies[]&service_ids[]&limit&offset   incidents.read
//       -> { incidents: [ { id, incident_number, created_at, resolved_at, urgency, service } ], more, offset, limit }
//   GET /incidents/{id}/notes                       -> { notes: [ { content, created_at } ] }   incidents.read
//   GET /incidents/{id}/custom_fields/values        -> { custom_fields: [ { name, value } ] }   incidents.read
//   GET /services?limit&offset                      -> { services: [ { id, status, escalation_policy: { id } } ], more }   services.read
//   GET /escalation_policies?limit&offset           -> { escalation_policies: [ { id, escalation_rules: [ { targets: [ { id, type } ] } ] } ], more }
//   GET /schedules/{id}?since&until                 -> { schedule: { final_schedule: { rendered_coverage_percentage } } }   schedules.read
//   GET /incident_workflows?limit&offset            -> { incident_workflows: [ { id, is_enabled } ], more }   incident_workflows.read
//   GET /automation_actions/actions?limit&cursor    -> { actions: [ { id } ], next_cursor }
// Auth header `Authorization: Token token=<key>`, Accept `application/vnd.pagerduty+json;version=2`.
//
// PagerDuty has no REST field for a postmortem (its postmortem endpoints belong to status pages), so a
// review counts when an incident note matches the configured pattern (default: postmortem,
// post-mortem, retrospective, post-incident review, PIR) or, with --pagerduty-review-field, when that
// incident custom field holds a value. Note text is matched locally and never sent. Results carry
// incident numbers and PagerDuty's opaque service, policy and schedule ids; never a user's name or email.

import type { Result, Source, SourceContext } from "../types.ts";
import {
  DAY_MS, Emitter, arr, fetchRest, getAll, isObj, ok, realSleep, redact, str, why, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";
import { idList, paths, posNum } from "./report_files.ts";

export const PAGERDUTY_CHECKS = ["incident_reviews_linked", "escalation_multi_level", "oncall_24x7", "response_automation"] as const;
type C = (typeof PAGERDUTY_CHECKS)[number];

export const PAGERDUTY_BASE = "https://api.pagerduty.com";
const EU_BASE = "https://api.eu.pagerduty.com";
export const PAGERDUTY_ENV = { token: "PAGERDUTY_TOKEN", base: "PAGERDUTY_API_URL" } as const;
export const DEFAULTS = {
  lookbackDays: 90, minLevels: 2, maxIncidents: 200, coverageDays: 7,
  reviewPattern: "postmortem|post-mortem|retrospective|post-incident review|\\bPIR\\b",
} as const;
const PAGE = 100;

export function pagerdutyFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const token = env[PAGERDUTY_ENV.token];
  if (!token) return `${PAGERDUTY_ENV.token} is not set`;
  const base = (env[PAGERDUTY_ENV.base] ?? PAGERDUTY_BASE).replace(/\/+$/, "");
  if (base !== PAGERDUTY_BASE && base !== EU_BASE) return `${PAGERDUTY_ENV.base} must be ${PAGERDUTY_BASE} or ${EU_BASE}`;
  return fetchRest({ base, fetchFn, headers: async () => ({ authorization: `Token token=${token}`, accept: "application/vnd.pagerduty+json;version=2" }) });
}

/** The next offset page of a classic PagerDuty list, from `more`, `offset` and `limit`. */
const offsetNext = (path: string) => (r: HttpResponse): string | undefined => {
  const b = r.body;
  if (!isObj(b) || b.more !== true) return undefined;
  const offset = Number(b.offset ?? 0) + Number(b.limit ?? PAGE);
  return `${path}${path.includes("?") ? "&" : "?"}limit=${PAGE}&offset=${offset}`;
};
const list = (api: RestApi, path: string, key: string, maxPages = 100) =>
  getAll(api, `${path}${path.includes("?") ? "&" : "?"}limit=${PAGE}&offset=0`, (b) => (isObj(b) && Array.isArray(b[key]) ? b[key] as unknown[] : undefined), offsetNext(path), maxPages);

const qs = (k: string, vs: string[]) => vs.map((v) => `&${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("");
const fieldValue = (v: unknown): unknown => (isObj(v) && "value" in v ? v.value : v);
const filled = (v: unknown) => v !== null && v !== undefined && v !== false && !(typeof v === "string" && !v.trim()) && !(Array.isArray(v) && !v.length);

async function incidentReviews(api: RestApi, out: Emitter<C>, ctx: SourceContext, services: string[]) {
  const o = ctx.opts;
  const days = Math.min(180, posNum(o["pagerduty-lookback-days"], DEFAULTS.lookbackDays));
  const urgency = typeof o["pagerduty-urgency"] === "string" ? o["pagerduty-urgency"].trim().toLowerCase() : "high";
  const field = typeof o["pagerduty-review-field"] === "string" && o["pagerduty-review-field"].trim() ? o["pagerduty-review-field"].trim() : undefined;
  let pattern: RegExp;
  try { pattern = new RegExp(typeof o["pagerduty-review-note"] === "string" && o["pagerduty-review-note"].trim() ? o["pagerduty-review-note"] : DEFAULTS.reviewPattern, "i"); }
  catch { return out.add("incident_reviews_linked", "skipped", "--pagerduty-review-note is not a valid regular expression"); }
  const max = posNum(o["pagerduty-max-incidents"], DEFAULTS.maxIncidents);
  const since = new Date(ctx.now.getTime() - days * DAY_MS).toISOString(), until = ctx.now.toISOString();
  const path = `/incidents?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}${qs("statuses[]", ["resolved"])}${urgency === "all" ? "" : qs("urgencies[]", [urgency === "low" ? "low" : "high"])}${qs("service_ids[]", services)}`;
  const got = await list(api, path, "incidents");
  if ("error" in got) return out.skip("incident_reviews_linked", got.error, "incidents");
  const incidents = got.items.filter(isObj);
  if (!incidents.length) return out.add("incident_reviews_linked", "skipped", `no resolved ${urgency === "all" ? "" : `${urgency}-urgency `}incident in the last ${days} days; nothing to judge`);
  const judged = incidents.slice(0, max);
  const missing: string[] = [];
  let byNote = 0, byField = 0;
  for (const inc of judged) {
    const id = encodeURIComponent(String(inc.id));
    const num = `#${String(inc.incident_number ?? inc.id)}`;
    if (field) {
      const cf = await api.get(`/incidents/${id}/custom_fields/values`);
      if (!ok(cf)) return out.skip("incident_reviews_linked", cf, "incident custom fields");
      const f = arr(isObj(cf.body) ? cf.body.custom_fields : []).filter(isObj).find((x) => x.name === field || x.display_name === field);
      if (f && filled(fieldValue(f.value))) { byField++; continue; }
    }
    const notes = await api.get(`/incidents/${id}/notes`);
    if (!ok(notes)) return out.skip("incident_reviews_linked", notes, "incident notes");
    if (arr(isObj(notes.body) ? notes.body.notes : []).filter(isObj).some((n) => pattern.test(String(n.content ?? "")))) { byNote++; continue; }
    missing.push(num);
  }
  const cap = incidents.length > judged.length ? `; the first ${judged.length} of ${incidents.length} judged (--pagerduty-max-incidents)` : "";
  out.add("incident_reviews_linked", missing.length ? "fail" : "pass",
    `${judged.length} resolved ${urgency === "all" ? "" : `${urgency}-urgency `}incident(s) in the last ${days} days: ${byNote} with a review note${field ? `, ${byField} with ${field} set` : ""}, ${missing.length} without${idList(missing, "incidents ")}${cap}; a review for every one required`);
}

export const pagerduty: Source = {
  name: "pagerduty",
  options: {
    "pagerduty-service": { type: "string", multiple: true, help: "service id of a production service (repeatable; default every service that is not disabled)" },
    "pagerduty-lookback-days": { type: "string", help: `days of resolved incidents judged, at most 180 (default ${DEFAULTS.lookbackDays})` },
    "pagerduty-urgency": { type: "string", help: "incidents that need a review: high, low or all (default high)" },
    "pagerduty-review-note": { type: "string", help: "regular expression a note must match to count as the review link (default postmortem|post-mortem|retrospective|post-incident review|PIR)" },
    "pagerduty-review-field": { type: "string", help: "incident custom field name whose value marks the review (checked before notes)" },
    "pagerduty-max-incidents": { type: "string", help: `incidents whose notes are read, at most (default ${DEFAULTS.maxIncidents})` },
    "pagerduty-min-levels": { type: "string", help: `escalation levels each production service's policy needs (default ${DEFAULTS.minLevels})` },
  },
  emits: PAGERDUTY_CHECKS.map((c) => `pagerduty.${c}`),
  describe(opts) {
    const s = paths(opts["pagerduty-service"]);
    return `pagerduty ${s.length ? `services ${s.join(", ")}` : "every service"}; incidents of the last ${Math.min(180, posNum(opts["pagerduty-lookback-days"], DEFAULTS.lookbackDays))} days`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Emitter<C>("pagerduty", "pagerduty account");
    const given = ctx.clients.pagerduty as RestApi | null | undefined;
    const built = given !== undefined ? given : pagerdutyFromEnv(ctx.env);
    if (!built || typeof built === "string") { out.skipAll(PAGERDUTY_CHECKS, typeof built === "string" ? built : `${PAGERDUTY_ENV.token} is not set`); return out.results; }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const wanted = paths(ctx.opts["pagerduty-service"]);
    const minLevels = posNum(ctx.opts["pagerduty-min-levels"], DEFAULTS.minLevels);

    await incidentReviews(api, out, ctx, wanted);

    // Services, their escalation policies, and the schedules behind each policy's first level.
    const svc = await list(api, "/services", "services");
    const pol = await list(api, "/escalation_policies", "escalation_policies");
    if ("error" in svc || "error" in pol) {
      const r = "error" in svc ? svc.error : (pol as { error: HttpResponse }).error;
      out.skip("escalation_multi_level", r, "error" in svc ? "services" : "escalation policies");
      out.skip("oncall_24x7", r, "error" in svc ? "services" : "escalation policies");
    } else {
      const policies = new Map(pol.items.filter(isObj).map((p) => [String(p.id), p]));
      let services = svc.items.filter(isObj).filter((s) => s.status !== "disabled");
      if (wanted.length) services = services.filter((s) => wanted.includes(String(s.id)));
      if (!services.length) {
        const why_ = wanted.length ? `none of the services ${wanted.join(", ")} exists or is enabled` : "the account has no enabled service";
        out.add("escalation_multi_level", "skipped", `${why_}; nothing to judge`);
        out.add("oncall_24x7", "skipped", `${why_}; nothing to judge`);
      } else {
        const rulesOf = (s: Obj) => {
          const ep = isObj(s.escalation_policy) ? policies.get(String(s.escalation_policy.id)) : undefined;
          return ep ? arr(ep.escalation_rules).filter(isObj) : undefined;
        };
        const thin: string[] = [];
        for (const s of services) { const rs = rulesOf(s); if (!rs || rs.length < minLevels) thin.push(`${String(s.id)}:${rs ? rs.length : "no policy"}`); }
        out.add("escalation_multi_level", thin.length ? "fail" : "pass",
          `${services.length} service(s), ${services.length - thin.length} with an escalation policy of ${minLevels} or more levels, ${thin.length} with fewer${idList(thin, "service:levels ")}; ${minLevels} levels required`);

        // On call around the clock: the first level names a user directly, or a schedule that covers
        // 100% of the next 7 days.
        const since = ctx.now.toISOString(), until = new Date(ctx.now.getTime() + DEFAULTS.coverageDays * DAY_MS).toISOString();
        const coverage = new Map<string, number | string>();
        const gaps: string[] = [], unknown: string[] = [];
        for (const s of services) {
          const first = rulesOf(s)?.[0];
          const targets = first ? arr(first.targets).filter(isObj) : [];
          if (!targets.length) { gaps.push(`${String(s.id)}:no first level`); continue; }
          if (targets.some((t) => t.type === "user_reference" || t.type === "user")) continue;
          let best = -1, unread = "";
          for (const t of targets) {
            const id = String(t.id);
            if (t.type === "schedule_v3_reference") { unread = `schedule ${id} is a v3 schedule, whose coverage this check does not read`; continue; }
            if (!coverage.has(id)) {
              const r = await api.get(`/schedules/${encodeURIComponent(id)}?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}`);
              const pct = ok(r) && isObj(r.body) && isObj(r.body.schedule) && isObj(r.body.schedule.final_schedule) ? Number(r.body.schedule.final_schedule.rendered_coverage_percentage) : NaN;
              coverage.set(id, Number.isFinite(pct) ? pct : why(r));
            }
            const c = coverage.get(id)!;
            if (typeof c === "number") best = Math.max(best, c); else unread = `schedule ${id}: ${c}`;
          }
          if (best >= 100) continue;
          if (best < 0) unknown.push(`${String(s.id)} (${unread})`); else gaps.push(`${String(s.id)}:${best}%`);
        }
        if (gaps.length) out.add("oncall_24x7", "fail", `${services.length} service(s): ${gaps.length} whose first escalation level is not on call for all of the next ${DEFAULTS.coverageDays} days${idList(gaps, "service:coverage ")}${unknown.length ? `; ${unknown.length} not readable` : ""}; 100% required`);
        else if (unknown.length) out.add("oncall_24x7", "skipped", `coverage not shown for ${unknown.length} service(s)${idList(unknown)}`);
        else out.add("oncall_24x7", "pass", `${services.length} service(s), each with a first escalation level that names a user or a schedule covering 100% of the next ${DEFAULTS.coverageDays} days (${coverage.size} schedule(s) read)`);
      }
    }

    // Response automation: an enabled incident workflow, or an automation action.
    const wf = await list(api, "/incident_workflows", "incident_workflows", 20);
    const aa = await getAll(api, `/automation_actions/actions?limit=${PAGE}`,
      (b) => (isObj(b) && Array.isArray(b.actions) ? b.actions : undefined),
      (r) => { const c = isObj(r.body) ? str(r.body.next_cursor) : undefined; return c ? `/automation_actions/actions?limit=${PAGE}&cursor=${encodeURIComponent(c)}` : undefined; }, 20);
    const enabled = "error" in wf ? undefined : wf.items.filter(isObj).filter((w) => w.is_enabled !== false).length;
    const actions = "error" in aa ? undefined : aa.items.length;
    if (enabled === undefined && actions === undefined) out.skip("response_automation", (wf as { error: HttpResponse }).error, "incident workflows and automation actions");
    else {
      const parts = [enabled === undefined ? `incident workflows not readable (${why((wf as { error: HttpResponse }).error)})` : `${enabled} enabled incident workflow(s)`,
        actions === undefined ? `automation actions not readable (${why((aa as { error: HttpResponse }).error)})` : `${actions} automation action(s)`];
      const any = (enabled ?? 0) + (actions ?? 0) > 0;
      out.add("response_automation", any ? "pass" : "fail", `${parts.join(", ")}; at least one required`);
    }
    return redact(out.results, [ctx.env[PAGERDUTY_ENV.token], `Token token=${ctx.env[PAGERDUTY_ENV.token] ?? ""}`]);
  },
};
