// Fixtures for the jira source, shared by test/jira.test.ts and the end-to-end run (test/e2e.test.ts).
import { JIRA_CHECKS, fetchJira, jira, type JiraTransport } from "../../../src/sources/jira.ts";
import type { HttpReply } from "../../../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../../../src/types.ts";

export const NOW = new Date("2026-10-15T12:00:00Z");
export const ago = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();
export const reply = (status: number, body: unknown, headers: Record<string, string> = {}): HttpReply => ({ status, headers, body: JSON.stringify(body) });

export const OPTS: Record<string, OptionValue> = {
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
export const ROUTES = ["DRTEST", "LOGREV", "ACCREV", "ROADMAP", "RTORPO", "DELREQ", "LOGACC", "AVAIL", "CHG", "INC", "security"] as const;

export type Issues = { key: string; fields: Record<string, unknown> }[];
export interface Fixture { changes: Issues; incidents: Issues; security: Issues; [kw: string]: Issues }
export const review = (key: string, hoursAgo: number) => ({ key, fields: { resolutiondate: ago(hoursAgo), created: ago(hoursAgo + 48) } });
export const pir = (key: string, type = "Post-incident review", done = true) => ({ type: { name: "Relates" }, outwardIssue: { key, fields: { summary: "never read", issuetype: { name: type }, status: { statusCategory: { key: done ? "done" : "new" } } } } });
export const strong = (): Fixture => ({
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

export function fakeJira(f: Fixture, calls: string[] = [], over?: (path: string) => HttpReply | undefined): JiraTransport {
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
