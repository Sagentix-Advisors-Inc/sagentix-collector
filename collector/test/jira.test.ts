// The Jira source against a fake REST v3 enhanced search: pass and fail per check, refusals,
// pagination, throttling and secret hygiene. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { JIRA_CHECKS, fetchJira, jira, type JiraTransport } from "../src/sources/jira.ts";
import type { HttpReply } from "../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../src/types.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const ago = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();
const reply = (status: number, body: unknown, headers: Record<string, string> = {}): HttpReply => ({ status, headers, body: JSON.stringify(body) });

const OPTS: Record<string, OptionValue> = {
  "jira-change-jql": "project = CHG",
  "jira-approval-field": "customfield_10050",
  "jira-incident-jql": "project = INC",
  "jira-security-jql": "labels = security",
  "jira-dr-test-jql": "project = OPS AND labels = DRTEST",
  "jira-log-review-jql": "project = OPS AND labels = LOGREV",
  "jira-access-review-jql": "project = OPS AND labels = ACCREV",
  "jira-roadmap-review-jql": "project = GOV AND labels = ROADMAP",
  "jira-recovery-objectives-jql": "project = GOV AND labels = RTORPO",
  "jira-deletion-jql": "project = PRIV AND labels = DELREQ",
  "jira-log-access-review-jql": "project = OPS AND labels = LOGACC",
  "jira-availability-review-jql": "project = GOV AND labels = AVAIL",
};

/** The JQL keyword each fixture list answers to, most specific first. */
const ROUTES = ["DRTEST", "LOGREV", "ACCREV", "ROADMAP", "RTORPO", "DELREQ", "LOGACC", "AVAIL", "CHG", "INC", "security"] as const;

type Issues = { key: string; fields: Record<string, unknown> }[];
interface Fixture { changes: Issues; incidents: Issues; security: Issues; [kw: string]: Issues }
const review = (key: string, hoursAgo: number) => ({ key, fields: { resolutiondate: ago(hoursAgo), created: ago(hoursAgo + 48) } });
const pir = (key: string, type = "Post-incident review", done = true) => ({ type: { name: "Relates" }, outwardIssue: { key, fields: { summary: "never read", issuetype: { name: type }, status: { statusCategory: { key: done ? "done" : "new" } } } } });
const strong = (): Fixture => ({
  changes: [{ key: "CHG-1", fields: { created: ago(48), customfield_10050: { accountId: "abc" } } }, { key: "CHG-2", fields: { created: ago(24), customfield_10050: "approved" } }],
  incidents: [{ key: "INC-1", fields: { created: ago(200), resolutiondate: ago(190), issuelinks: [pir("PIR-1")] } }, { key: "INC-2", fields: { created: ago(10), resolutiondate: null } }],
  security: [],
  DRTEST: [review("OPS-10", 24 * 200)],
  LOGREV: Array.from({ length: 13 }, (_, k) => review(`OPS-${100 + k}`, 24 * (3 + 7 * k))),
  ACCREV: [review("OPS-20", 24 * 30)],
  ROADMAP: [review("GOV-1", 24 * 100)],
  RTORPO: [review("GOV-2", 24 * 300)],
  DELREQ: [{ key: "PRIV-1", fields: { created: ago(24 * 40), resolutiondate: ago(24 * 35) } }, { key: "PRIV-2", fields: { created: ago(24 * 2), resolutiondate: null } }],
  LOGACC: [review("OPS-30", 24 * 60)],
  AVAIL: [review("GOV-3", 24 * 200)],
});

function fakeJira(f: Fixture, calls: string[] = [], over?: (path: string) => HttpReply | undefined): JiraTransport {
  return {
    sleep: async () => {},
    async get(p) {
      calls.push(p);
      const o = over?.(p);
      if (o) return o;
      const jql = new URL(`https://x${p}`).searchParams.get("jql") ?? "";
      const kw = ROUTES.find((k) => jql.includes(k)) ?? "security";
      let issues = kw === "CHG" ? f.changes : kw === "INC" ? f.incidents : kw === "security" ? f.security : f[kw] ?? [];
      // The fake applies the one filter the source relies on Jira for: resolved only.
      if (jql.includes("statusCategory = Done")) issues = issues.filter((i) => i.fields.resolutiondate);
      return reply(200, { issues, isLast: true });
    },
  };
}

const run = (t: JiraTransport | null, opts = OPTS, env: NodeJS.ProcessEnv = {}): Promise<Result[]> =>
  jira.run({ opts, env, clients: { jira: t }, now: NOW, warn: () => {} });
const one = (rs: Result[], c: string) => { const m = rs.filter((r) => r.check === `jira.${c}`); assert.equal(m.length, 1, c); return m[0]; };

test("every check passes on a well-kept project", async () => {
  const rs = await run(fakeJira(strong()));
  for (const c of JIRA_CHECKS) assert.equal(one(rs, c).result, "pass", `${c}: ${one(rs, c).detail}`);
});

test("change_approval fails when a change has no approval field, naming the key", async () => {
  const f = strong(); f.changes.push({ key: "CHG-3", fields: { created: ago(5), customfield_10050: null } });
  const r = one(await run(fakeJira(f)), "change_approval");
  assert.equal(r.result, "fail"); assert.match(r.detail, /CHG-3/); assert.match(r.detail, /3 change/);
});

test("incident_sla fails on a late resolution and on an open incident past the SLA", async () => {
  const f = strong();
  f.incidents.push({ key: "INC-3", fields: { created: ago(300), resolutiondate: ago(100) } }, { key: "INC-4", fields: { created: ago(100), resolutiondate: null } });
  const r = one(await run(fakeJira(f)), "incident_sla");
  assert.equal(r.result, "fail"); assert.match(r.detail, /INC-3, INC-4/); assert.match(r.detail, /1 open and still inside/);
});

test("security_issue_age fails when an old open security issue exists; the JQL adds the age and status filter", async () => {
  const f = strong(); f.security = [{ key: "SEC-9", fields: { created: ago(24 * 60) } }];
  const calls: string[] = [];
  const r = one(await run(fakeJira(f, calls)), "security_issue_age");
  assert.equal(r.result, "fail"); assert.match(r.detail, /SEC-9/);
  const jql = calls.map((c) => new URL(`https://x${c}`).searchParams.get("jql")).find((q) => q?.includes("security"));
  assert.equal(jql, "(labels = security) AND statusCategory != Done AND created <= -30d");
});

test("no query or no records gives skipped, never pass", async () => {
  let rs = await run(fakeJira(strong()), {});
  for (const r of rs) assert.equal(r.result, "skipped", r.check);
  rs = await run(fakeJira({ changes: [], incidents: [], security: [] }));
  assert.equal(one(rs, "post_incident_reviews").result, "skipped");
  assert.equal(one(rs, "data_deletion_requests").result, "skipped");
  assert.equal(one(rs, "change_approval").result, "skipped");
  assert.equal(one(rs, "incident_sla").result, "skipped");
});

test("a 403 gives skipped for every check, with the reason", async () => {
  const rs = await run(fakeJira(strong(), [], () => reply(403, { errorMessages: ["You do not have permission"] })));
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 403/); }
});

test("missing env: every check skipped", async () => {
  const rs = await jira.run({ opts: OPTS, env: {}, clients: {}, now: NOW, warn: () => {} });
  assert.equal(rs.length, JIRA_CHECKS.length);
  for (const r of rs) assert.equal(r.result, "skipped");
});

test("nextPageToken pagination: issues on both pages are counted", async () => {
  const calls: string[] = [];
  const page2 = [{ key: "CHG-7", fields: { created: ago(3) } }];
  const t = fakeJira(strong(), calls, (p) => {
    const q = new URL(`https://x${p}`).searchParams;
    if (!q.get("jql")?.includes("CHG")) return undefined;
    return q.get("nextPageToken") === "tok2" ? reply(200, { issues: page2, isLast: true }) : reply(200, { issues: strong().changes, nextPageToken: "tok2", isLast: false });
  });
  const r = one(await run(t), "change_approval");
  assert.match(r.detail, /^3 change/); assert.equal(r.result, "fail"); assert.match(r.detail, /CHG-7/);
  assert.equal(calls.filter((c) => c.includes("CHG")).length, 2);
});

test("a 429 is retried after Retry-After, then the answer is used", async () => {
  let n = 0; const waits: number[] = [];
  const base = fakeJira(strong());
  const t: JiraTransport = { sleep: async (ms) => { waits.push(ms); }, async get(p) { if (n++ === 0) return reply(429, {}, { "retry-after": "2" }); return base.get(p); } };
  const rs = await run(t);
  assert.equal(one(rs, "change_approval").result, "pass");
  assert.deepEqual(waits, [2000]);
});

test("only created, resolutiondate and the approval field are asked for; never summary or description", async () => {
  const calls: string[] = [];
  await run(fakeJira(strong(), calls));
  for (const c of calls) {
    const fields = new URL(`https://x${c}`).searchParams.get("fields")!.split(",");
    for (const f of fields) assert.ok(["created", "resolutiondate", "customfield_10050", "issuelinks"].includes(f), f);
  }
});

test("no secret reaches a result, even when the server echoes it", async () => {
  const token = "ATATT3xFfGF0-secret-token-value";
  const email = "reader@example.com";
  const basic = Buffer.from(`${email}:${token}`).toString("base64");
  const t = fakeJira(strong(), [], () => reply(401, { errorMessages: [`bad token ${token} / ${basic}`] }));
  const rs = await run(t, OPTS, { JIRA_BASE_URL: "https://x.atlassian.net", JIRA_EMAIL: email, JIRA_API_TOKEN: token });
  const all = JSON.stringify(rs);
  assert.ok(!all.includes(token)); assert.ok(!all.includes(basic)); assert.match(all, /\[redacted\]/);
});

test("the real client sends GET with Basic auth only, and refuses a non-https base URL", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const t = fetchJira("https://acme.atlassian.net/", "a@b.c", "tok", (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ issues: [] }), { status: 200 });
  }) as unknown as typeof fetch);
  await t.get("/rest/api/3/search/jql?jql=x");
  assert.equal(seen[0].url, "https://acme.atlassian.net/rest/api/3/search/jql?jql=x");
  assert.equal(seen[0].init.method, "GET");
  assert.equal(seen[0].init.body, undefined);
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, `Basic ${Buffer.from("a@b.c:tok").toString("base64")}`);
  assert.throws(() => fetchJira("http://acme.atlassian.net", "a", "b"), /https/);
});

// ── Governance reviews ────────────────────────────────────────────────────────────────────────────

test("post_incident_reviews: a resolved incident without a linked review of the configured type fails", async () => {
  const f = strong();
  f.incidents.push({ key: "INC-5", fields: { created: ago(100), resolutiondate: ago(90), issuelinks: [pir("TASK-9", "Task")] } });
  let r = one(await run(fakeJira(f)), "post_incident_reviews");
  assert.equal(r.result, "fail"); assert.match(r.detail, /INC-5/); assert.match(r.detail, /^2 resolved incident/);
  assert.ok(!r.detail.includes("never read"));
  r = one(await run(fakeJira(f), { ...OPTS, "jira-review-issue-type": "task" }), "post_incident_reviews");
  assert.match(r.detail, /INC-1/);   // now INC-1's "Post-incident review" link is the wrong type
});

test("the recent-review checks pass on a resolution inside the allowed age and fail when there is none", async () => {
  const calls: string[] = [];
  const rs = await run(fakeJira(strong(), calls));
  const jql = (kw: string) => calls.map((c) => new URL(`https://x${c}`).searchParams.get("jql")!).find((q) => q.includes(kw));
  assert.equal(jql("DRTEST"), "(project = OPS AND labels = DRTEST) AND statusCategory = Done AND resolved >= -365d");
  assert.equal(jql("ACCREV"), "(project = OPS AND labels = ACCREV) AND statusCategory = Done AND resolved >= -90d");
  assert.match(one(rs, "dr_test_recent").detail, /the latest OPS-10 on 2026-03-29/);
  const f = strong(); f.DRTEST = []; f.ACCREV = [];
  const weak = await run(fakeJira(f));
  for (const c of ["dr_test_recent", "access_review_recent"]) { assert.equal(one(weak, c).result, "fail"); assert.match(one(weak, c).detail, /^no /); }
  assert.equal(one(await run(fakeJira(strong()), { ...OPTS, "jira-access-review-max-age-days": "180" }), "access_review_recent").result, "pass");
});

test("log_review_cadence: weekly reviews pass; a three-week gap fails", async () => {
  const f = strong();
  f.LOGREV = f.LOGREV.filter((_, k) => k < 4 || k > 6);   // drop three consecutive weeks
  const r = one(await run(fakeJira(f)), "log_review_cadence");
  assert.equal(r.result, "fail"); assert.match(r.detail, /longest stretch without one is 28 days/);
  f.LOGREV = [];
  assert.equal(one(await run(fakeJira(f)), "log_review_cadence").result, "fail");
});

test("data_deletion_requests: a request closed late, or open past the SLA, fails with its key", async () => {
  const f = strong();
  f.DELREQ.push({ key: "PRIV-3", fields: { created: ago(24 * 50), resolutiondate: null } });
  const r = one(await run(fakeJira(f)), "data_deletion_requests");
  assert.equal(r.result, "fail"); assert.match(r.detail, /PRIV-3/); assert.match(r.detail, /1 open and still inside 30 days/);
  assert.equal(one(await run(fakeJira(f), { ...OPTS, "jira-deletion-sla-days": "60" }), "data_deletion_requests").result, "pass");
});
