// Jira Cloud: records of changes, incidents, security issues and recurring governance reviews (REST v3
// enhanced search, GET only).
//
// The collector reads with an API token of a read-only account (JIRA_BASE_URL, JIRA_EMAIL,
// JIRA_API_TOKEN). The account needs the "Browse projects" project permission on the projects the
// queries name. It asks only for the fields it judges (created, resolutiondate, the approval field,
// issuelinks) and reports counts and issue keys, never summaries or descriptions. issuelinks carries
// each linked issue's key, type and status (IssueLink -> LinkedIssue.fields in Atlassian's OpenAPI,
// swagger-v3.v3.json); only the linked issue's type is read.
//
// The review checks each take their own JQL and pass when an issue it selects was resolved inside the
// allowed age: a DR test, an access review, a security roadmap review, an RTO/RPO review, a review of
// who can read logs, an availability review. They show the record exists, not that the review was good.
//
//   GET /rest/api/3/search/jql?jql=…&fields=…&maxResults=100&nextPageToken=…
//   response: { issues: [{ key, fields }], nextPageToken?, isLast? }

import type { OptionSpec, OptionValue, Result, Source, SourceContext } from "../types.ts";
import { Results, allSkipped, arr, httpWhy, isObj, scrub, str, withRetry, type HttpReply, type Obj } from "./shared-cloud.ts";

export const JIRA_CHECKS = [
  "change_approval", "incident_sla", "security_issue_age",
  "post_incident_reviews", "dr_test_recent", "log_review_cadence", "access_review_recent",
  "security_roadmap_reviewed", "recovery_objectives_reviewed", "data_deletion_requests",
  "log_access_review_recent", "availability_review_recent",
] as const;
export type JiraCheck = (typeof JIRA_CHECKS)[number];

export const JIRA_ENV = { base: "JIRA_BASE_URL", email: "JIRA_EMAIL", token: "JIRA_API_TOKEN" } as const;
export const DEFAULTS = {
  slaHours: 72, securityMaxAgeDays: 30, lookbackDays: 90, reviewIssueType: "Post-incident review",
  logReviewEveryDays: 7, deletionSlaDays: 30,
} as const;

/** The "an issue was resolved recently" checks: option stem, default allowed age, what is reviewed. */
export const RECENT_REVIEWS = {
  dr_test_recent: { opt: "jira-dr-test", days: 365, what: "disaster recovery test" },
  access_review_recent: { opt: "jira-access-review", days: 90, what: "access review" },
  security_roadmap_reviewed: { opt: "jira-roadmap-review", days: 365, what: "security roadmap or investment review" },
  recovery_objectives_reviewed: { opt: "jira-recovery-objectives", days: 365, what: "RTO/RPO review" },
  log_access_review_recent: { opt: "jira-log-access-review", days: 90, what: "review of who can read logs" },
  availability_review_recent: { opt: "jira-availability-review", days: 365, what: "availability and recovery design review" },
} as const satisfies Partial<Record<JiraCheck, { opt: string; days: number; what: string }>>;
const PAGE = 100;
const MAX_PAGES = 50;
const MAX_KEYS = 50;

export interface JiraTransport {
  /** GET a path with query under the base URL. */
  get(pathAndQuery: string): Promise<HttpReply>;
  sleep?: (ms: number) => Promise<void>;
}

/** The real client: GET only, https only, Basic auth with the account's email and API token. */
export function fetchJira(base: string, email: string, token: string, fetchFn: typeof fetch = fetch): JiraTransport {
  const u = new URL(base);
  if (u.protocol !== "https:") throw new Error(`${JIRA_ENV.base} must be an https URL`);
  const root = u.origin + u.pathname.replace(/\/+$/, "");
  const auth = `Basic ${Buffer.from(`${email}:${token}`).toString("base64")}`;
  return {
    async get(pathAndQuery) {
      const res = await fetchFn(`${root}${pathAndQuery}`, { method: "GET", headers: { authorization: auth, accept: "application/json" } });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      return { status: res.status, headers, body: await res.text() };
    },
  };
}

const num = (v: OptionValue, d: number) => {
  const n = Number(typeof v === "string" ? v : NaN);
  return Number.isFinite(n) && n > 0 ? n : d;
};
const optStr = (v: OptionValue) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const short = (jql: string) => (jql.length > 120 ? `${jql.slice(0, 117)}...` : jql);
const keysOf = (ks: string[]) => (ks.length ? ` (${ks.slice(0, MAX_KEYS).join(", ")}${ks.length > MAX_KEYS ? `, and ${ks.length - MAX_KEYS} more` : ""})` : "");

type Search = { issues: { key: string; fields: Obj }[] } | { error: string };

/** Every issue matching the JQL, following nextPageToken. Returns the reason instead when a page fails. */
export async function searchAll(t: JiraTransport, jql: string, fields: string[]): Promise<Search> {
  const issues: { key: string; fields: Obj }[] = [];
  let token: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const q = new URLSearchParams({ jql, fields: fields.join(","), maxResults: String(PAGE) });
    if (token) q.set("nextPageToken", token);
    const r = await withRetry(() => t.get(`/rest/api/3/search/jql?${q.toString()}`), { sleep: t.sleep });
    let body: unknown = null;
    try { body = JSON.parse(r.body); } catch { body = null; }
    if (r.status < 200 || r.status >= 300 || !isObj(body)) {
      const msgs = isObj(body) ? [...arr(body.errorMessages).map(String), ...Object.values(isObj(body.errors) ? body.errors : {}).map(String)] : [];
      return { error: httpWhy(r, msgs.join("; ")) };
    }
    for (const i of arr(body.issues).filter(isObj)) issues.push({ key: String(i.key ?? i.id ?? "?"), fields: isObj(i.fields) ? i.fields : {} });
    token = str(body.nextPageToken);
    if (!token || body.isLast === true) break;
  }
  return { issues };
}

const filled = (v: unknown) => v !== null && v !== undefined && !(typeof v === "string" && !v.trim()) && !(Array.isArray(v) && !v.length);

async function changeApproval(t: JiraTransport, out: Results<JiraCheck>, jql: string | undefined, field: string | undefined, days: number) {
  if (!jql || !field) return out.skip("change_approval", "jira changes", "give --jira-change-jql and --jira-approval-field");
  const q = `(${jql}) AND created >= -${days}d`;
  const resource = `jira changes (${short(jql)})`;
  const s = await searchAll(t, q, ["created", field]);
  if ("error" in s) return out.skip("change_approval", resource, `search not readable: ${s.error}`);
  if (!s.issues.length) return out.skip("change_approval", resource, `no change record created in the last ${days} days; nothing to judge`);
  const missing = s.issues.filter((i) => !filled(i.fields[field])).map((i) => i.key);
  out.add("change_approval", resource, missing.length ? "fail" : "pass",
    `${s.issues.length} change(s) created in the last ${days} days, ${s.issues.length - missing.length} with ${field} set, ${missing.length} without${keysOf(missing)}; all required`);
}

async function incidentSla(t: JiraTransport, out: Results<JiraCheck>, jql: string | undefined, slaHours: number, days: number, now: Date) {
  if (!jql) return out.skip("incident_sla", "jira incidents", "give --jira-incident-jql");
  const resource = `jira incidents (${short(jql)})`;
  const s = await searchAll(t, `(${jql}) AND created >= -${days}d`, ["created", "resolutiondate"]);
  if ("error" in s) return out.skip("incident_sla", resource, `search not readable: ${s.error}`);
  if (!s.issues.length) return out.skip("incident_sla", resource, `no incident created in the last ${days} days; nothing to judge`);
  const slaMs = slaHours * 3_600_000;
  let inSla = 0, open = 0, badDate = 0;
  const breached: string[] = [];
  for (const i of s.issues) {
    const c = Date.parse(String(i.fields.created ?? ""));
    if (!Number.isFinite(c)) { badDate++; continue; }
    const rd = i.fields.resolutiondate;
    if (rd) {
      const r = Date.parse(String(rd));
      if (!Number.isFinite(r)) { badDate++; continue; }
      if (r - c <= slaMs) inSla++; else breached.push(i.key);
    } else if (now.getTime() - c > slaMs) breached.push(i.key);
    else open++;
  }
  out.add("incident_sla", resource, breached.length ? "fail" : "pass",
    `${s.issues.length} incident(s) created in the last ${days} days: ${inSla} resolved within ${slaHours} h, ${open} open and still inside ${slaHours} h, ${breached.length} past ${slaHours} h${keysOf(breached)}${badDate ? `, ${badDate} with an unreadable date` : ""}; none past the SLA required`);
}

async function securityAge(t: JiraTransport, out: Results<JiraCheck>, jql: string | undefined, maxAge: number) {
  if (!jql) return out.skip("security_issue_age", "jira security issues", "give --jira-security-jql");
  const resource = `jira security issues (${short(jql)})`;
  const s = await searchAll(t, `(${jql}) AND statusCategory != Done AND created <= -${maxAge}d`, ["created"]);
  if ("error" in s) return out.skip("security_issue_age", resource, `search not readable: ${s.error}`);
  const keys = s.issues.map((i) => i.key);
  out.add("security_issue_age", resource, keys.length ? "fail" : "pass",
    `${keys.length} security issue(s) not done and created more than ${maxAge} days ago${keysOf(keys)}; none required`);
}

async function postIncidentReviews(t: JiraTransport, out: Results<JiraCheck>, jql: string | undefined, type: string, days: number) {
  if (!jql) return out.skip("post_incident_reviews", "jira incidents", "give --jira-incident-jql (and --jira-review-issue-type)");
  const resource = `jira incidents (${short(jql)})`;
  const s = await searchAll(t, `(${jql}) AND created >= -${days}d AND statusCategory = Done`, ["issuelinks"]);
  if ("error" in s) return out.skip("post_incident_reviews", resource, `search not readable: ${s.error}`);
  if (!s.issues.length) return out.skip("post_incident_reviews", resource, `no incident created in the last ${days} days is resolved; nothing to judge`);
  const want = type.toLowerCase();
  const missing: string[] = [];
  let reviewsDone = 0;
  for (const i of s.issues) {
    const linked = arr(i.fields.issuelinks).filter(isObj).flatMap((l) => [l.inwardIssue, l.outwardIssue]).filter(isObj)
      .filter((li) => isObj(li.fields) && isObj(li.fields.issuetype) && String(li.fields.issuetype.name ?? "").toLowerCase() === want);
    if (!linked.length) { missing.push(i.key); continue; }
    if (linked.some((li) => isObj(li.fields) && isObj(li.fields.status) && isObj(li.fields.status.statusCategory) && li.fields.status.statusCategory.key === "done")) reviewsDone++;
  }
  out.add("post_incident_reviews", resource, missing.length ? "fail" : "pass",
    `${s.issues.length} resolved incident(s) created in the last ${days} days, ${s.issues.length - missing.length} linked to a "${type}" issue (${reviewsDone} of those reviews done), ${missing.length} not${keysOf(missing)}; a linked review for every one required`);
}

async function recentReview(t: JiraTransport, out: Results<JiraCheck>, check: keyof typeof RECENT_REVIEWS, jql: string | undefined, days: number) {
  const spec = RECENT_REVIEWS[check];
  if (!jql) return out.skip(check, `jira ${spec.what}`, `give --${spec.opt}-jql`);
  const resource = `jira ${spec.what} (${short(jql)})`;
  const s = await searchAll(t, `(${jql}) AND statusCategory = Done AND resolved >= -${days}d`, ["resolutiondate"]);
  if ("error" in s) return out.skip(check, resource, `search not readable: ${s.error}`);
  const dated = s.issues.map((i) => ({ key: i.key, at: Date.parse(String(i.fields.resolutiondate ?? "")) })).filter((x) => Number.isFinite(x.at)).sort((a, b) => b.at - a.at);
  if (!s.issues.length) return out.add(check, resource, "fail", `no ${spec.what} resolved in the last ${days} days; one at least every ${days} days required`);
  const last = dated[0];
  out.add(check, resource, "pass",
    `${s.issues.length} ${spec.what}(s) resolved in the last ${days} days${last ? `, the latest ${last.key} on ${new Date(last.at).toISOString().slice(0, 10)}` : ""}${keysOf(s.issues.map((i) => i.key))}; one at least every ${days} days required`);
}

async function logReviewCadence(t: JiraTransport, out: Results<JiraCheck>, jql: string | undefined, every: number, days: number, now: Date) {
  if (!jql) return out.skip("log_review_cadence", "jira log reviews", "give --jira-log-review-jql");
  const resource = `jira log reviews (${short(jql)})`;
  const s = await searchAll(t, `(${jql}) AND resolved >= -${days}d`, ["resolutiondate"]);
  if ("error" in s) return out.skip("log_review_cadence", resource, `search not readable: ${s.error}`);
  const allowed = every * 1.5;
  const start = now.getTime() - days * 86_400_000;
  const times = s.issues.map((i) => Date.parse(String(i.fields.resolutiondate ?? ""))).filter(Number.isFinite).sort((a, b) => a - b);
  const points = [start, ...times, now.getTime()];
  let worst = 0;
  for (let k = 1; k < points.length; k++) worst = Math.max(worst, (points[k] - points[k - 1]) / 86_400_000);
  const ok = times.length > 0 && worst <= allowed;
  out.add("log_review_cadence", resource, ok ? "pass" : "fail",
    `${times.length} log review(s) resolved in the last ${days} days; the longest stretch without one is ${Math.round(worst * 10) / 10} days; a review every ${every} days (at most ${allowed} days apart, the window's start and today included) required`);
}

async function dataDeletion(t: JiraTransport, out: Results<JiraCheck>, jql: string | undefined, slaDays: number, days: number, now: Date) {
  if (!jql) return out.skip("data_deletion_requests", "jira deletion requests", "give --jira-deletion-jql");
  const resource = `jira deletion requests (${short(jql)})`;
  const s = await searchAll(t, `(${jql}) AND created >= -${days}d`, ["created", "resolutiondate"]);
  if ("error" in s) return out.skip("data_deletion_requests", resource, `search not readable: ${s.error}`);
  if (!s.issues.length) return out.skip("data_deletion_requests", resource, `no deletion request created in the last ${days} days; nothing to judge`);
  const slaMs = slaDays * 86_400_000;
  let inSla = 0, open = 0, badDate = 0;
  const late: string[] = [];
  for (const i of s.issues) {
    const c = Date.parse(String(i.fields.created ?? ""));
    if (!Number.isFinite(c)) { badDate++; continue; }
    const rd = i.fields.resolutiondate;
    if (rd) {
      const r = Date.parse(String(rd));
      if (!Number.isFinite(r)) { badDate++; continue; }
      if (r - c <= slaMs) inSla++; else late.push(i.key);
    } else if (now.getTime() - c > slaMs) late.push(i.key);
    else open++;
  }
  out.add("data_deletion_requests", resource, late.length ? "fail" : "pass",
    `${s.issues.length} deletion request(s) created in the last ${days} days: ${inSla} closed within ${slaDays} days, ${open} open and still inside ${slaDays} days, ${late.length} past ${slaDays} days${keysOf(late)}${badDate ? `, ${badDate} with an unreadable date` : ""}; none past the SLA required`);
}

export const jira: Source = {
  name: "jira",
  options: {
    "jira-change-jql": { type: "string", help: "JQL that selects change records (the last --jira-lookback-days are judged)" },
    "jira-approval-field": { type: "string", help: "field id that holds the approval or reviewer, e.g. customfield_10050" },
    "jira-incident-jql": { type: "string", help: "JQL that selects incidents" },
    "jira-incident-sla-hours": { type: "string", help: `hours from created to resolved an incident may take (default ${DEFAULTS.slaHours})` },
    "jira-security-jql": { type: "string", help: "JQL that selects security issues (vulnerabilities, findings)" },
    "jira-security-max-age-days": { type: "string", help: `days a security issue may stay open (default ${DEFAULTS.securityMaxAgeDays})` },
    "jira-lookback-days": { type: "string", help: `days of changes, incidents, log reviews and deletion requests judged (default ${DEFAULTS.lookbackDays})` },
    "jira-review-issue-type": { type: "string", help: `issue type of the review linked to a resolved incident (default "${DEFAULTS.reviewIssueType}")` },
    "jira-log-review-jql": { type: "string", help: "JQL that selects log review tasks" },
    "jira-log-review-every-days": { type: "string", help: `days between log reviews; a gap up to 1.5 times this passes (default ${DEFAULTS.logReviewEveryDays})` },
    "jira-deletion-jql": { type: "string", help: "JQL that selects customer data deletion requests" },
    "jira-deletion-sla-days": { type: "string", help: `days from created to resolved a deletion request may take (default ${DEFAULTS.deletionSlaDays})` },
    ...Object.fromEntries(Object.values(RECENT_REVIEWS).flatMap((r) => [
      [`${r.opt}-jql`, { type: "string", help: `JQL that selects ${r.what} issues` }],
      [`${r.opt}-max-age-days`, { type: "string", help: `days since the last resolved ${r.what} (default ${r.days})` }],
    ])) as Record<string, OptionSpec>,
  },
  emits: JIRA_CHECKS.map((c) => `jira.${c}`),
  describe(opts) {
    const parts = [
      optStr(opts["jira-change-jql"]) ? "changes" : "",
      optStr(opts["jira-incident-jql"]) ? "incidents" : "",
      optStr(opts["jira-security-jql"]) ? "security issues" : "",
      optStr(opts["jira-log-review-jql"]) ? "log reviews" : "",
      optStr(opts["jira-deletion-jql"]) ? "deletion requests" : "",
      ...Object.values(RECENT_REVIEWS).map((r) => (optStr(opts[`${r.opt}-jql`]) ? `${r.what}s` : "")),
    ].filter(Boolean);
    return `jira ${parts.length ? parts.join(", ") : "(no query given)"}; last ${num(opts["jira-lookback-days"], DEFAULTS.lookbackDays)} days`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const base = ctx.env[JIRA_ENV.base], email = ctx.env[JIRA_ENV.email], token = ctx.env[JIRA_ENV.token];
    let t: JiraTransport | null;
    if (ctx.clients.jira !== undefined) t = ctx.clients.jira as JiraTransport | null;
    else if (base && email && token) {
      try { t = fetchJira(base, email, token); } catch (e) {
        return allSkipped("jira", JIRA_CHECKS, "jira", `${(e as Error).message}`);
      }
    } else t = null;
    if (!t) return allSkipped("jira", JIRA_CHECKS, "jira", `${JIRA_ENV.base}, ${JIRA_ENV.email} and ${JIRA_ENV.token} are not all set`);
    const o = ctx.opts;
    const days = num(o["jira-lookback-days"], DEFAULTS.lookbackDays);
    const out = new Results<JiraCheck>("jira");
    await changeApproval(t, out, optStr(o["jira-change-jql"]), optStr(o["jira-approval-field"]), days);
    await incidentSla(t, out, optStr(o["jira-incident-jql"]), num(o["jira-incident-sla-hours"], DEFAULTS.slaHours), days, ctx.now);
    await securityAge(t, out, optStr(o["jira-security-jql"]), num(o["jira-security-max-age-days"], DEFAULTS.securityMaxAgeDays));
    await postIncidentReviews(t, out, optStr(o["jira-incident-jql"]), optStr(o["jira-review-issue-type"]) ?? DEFAULTS.reviewIssueType, days);
    for (const [check, r] of Object.entries(RECENT_REVIEWS) as [keyof typeof RECENT_REVIEWS, (typeof RECENT_REVIEWS)[keyof typeof RECENT_REVIEWS]][]) {
      await recentReview(t, out, check, optStr(o[`${r.opt}-jql`]), num(o[`${r.opt}-max-age-days`], r.days));
    }
    await logReviewCadence(t, out, optStr(o["jira-log-review-jql"]), num(o["jira-log-review-every-days"], DEFAULTS.logReviewEveryDays), days, ctx.now);
    await dataDeletion(t, out, optStr(o["jira-deletion-jql"]), num(o["jira-deletion-sla-days"], DEFAULTS.deletionSlaDays), days, ctx.now);
    const basic = email && token ? Buffer.from(`${email}:${token}`).toString("base64") : undefined;
    return scrub(out.results, [token, basic]);
  },
};
