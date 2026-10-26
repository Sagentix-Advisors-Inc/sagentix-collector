// The PagerDuty source against a fake REST v2 API shaped like PagerDuty's OpenAPI (reference/REST/openapiv3.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGERDUTY_BASE, pagerduty, pagerdutyFromEnv } from "../src/sources/pagerduty.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const ok = (b: unknown) => res(200, b);
const page = (key: string, items: unknown[], more = false, offset = 0) => ok({ [key]: items, limit: 100, offset, more, total: null });

const policy = (id: string, levels: { id: string; type: string }[][]) => ({ id, type: "escalation_policy", num_loops: 0,
  escalation_rules: levels.map((targets, i) => ({ id: `R${id}${i}`, escalation_delay_in_minutes: 30, targets })) });

function strong(): Routes {
  return {
    "/incidents": page("incidents", [
      { id: "PINC1", incident_number: 101, status: "resolved", urgency: "high", created_at: "2026-09-01T00:00:00Z", resolved_at: "2026-09-01T03:00:00Z" },
      { id: "PINC2", incident_number: 102, status: "resolved", urgency: "high", created_at: "2026-09-20T00:00:00Z", resolved_at: "2026-09-20T01:00:00Z" },
    ]),
    "/incidents/PINC1/notes": ok({ notes: [{ id: "n1", content: "Postmortem: https://wiki.example/pm-101 (by Alice Smith)", created_at: "2026-09-02T00:00:00Z" }] }),
    "/incidents/PINC2/notes": ok({ notes: [{ id: "n2", content: "Retrospective scheduled", created_at: "2026-09-21T00:00:00Z" }] }),
    "/services": page("services", [
      { id: "PSVC1", name: "api", status: "active", escalation_policy: { id: "PEP1", type: "escalation_policy_reference" } },
      { id: "PSVC2", name: "web", status: "warning", escalation_policy: { id: "PEP2", type: "escalation_policy_reference" } },
      { id: "PSVC3", name: "old", status: "disabled", escalation_policy: { id: "PEP3", type: "escalation_policy_reference" } },
    ]),
    "/escalation_policies": page("escalation_policies", [
      policy("PEP1", [[{ id: "PSCH1", type: "schedule_reference" }], [{ id: "PUSR1", type: "user_reference" }]]),
      policy("PEP2", [[{ id: "PUSR2", type: "user_reference" }], [{ id: "PSCH1", type: "schedule_reference" }]]),
      policy("PEP3", [[{ id: "PUSR3", type: "user_reference" }]]),
    ]),
    "/schedules/PSCH1": ok({ schedule: { id: "PSCH1", time_zone: "UTC", final_schedule: { name: "Final Schedule", rendered_coverage_percentage: 100, rendered_schedule_entries: [] } } }),
    "/incident_workflows": page("incident_workflows", [{ id: "PWF1", name: "Major incident", is_enabled: true }]),
    "/automation_actions/actions": ok({ actions: [], limit: 100, next_cursor: null }),
  };
}

const C: Contract = {
  source: pagerduty, clientKey: "pagerduty", base: PAGERDUTY_BASE, prefix: "pagerduty", strong,
  env: { PAGERDUTY_TOKEN: "x" },
  rateLimited: { path: "/services", check: "escalation_multi_level" },
  fails: {
    incident_reviews_linked: { "/incidents/PINC2/notes": ok({ notes: [{ id: "n2", content: "restarted the pod" }] }) },
    escalation_multi_level: { "/escalation_policies": page("escalation_policies", [policy("PEP1", [[{ id: "PUSR1", type: "user_reference" }]]), policy("PEP2", [[{ id: "PUSR2", type: "user_reference" }], [{ id: "PUSR1", type: "user_reference" }]])]) },
    oncall_24x7: { "/schedules/PSCH1": ok({ schedule: { id: "PSCH1", final_schedule: { name: "Final Schedule", rendered_coverage_percentage: 71.4 } } }) },
    response_automation: { "/incident_workflows": page("incident_workflows", [{ id: "PWF1", is_enabled: false }]) },
  },
};

contractSuite(C);

test("pagerduty: the incident query asks for resolved high-urgency incidents of the last 90 days, follows offset pages and never sends note text", async () => {
  const calls: string[] = [];
  const routes = strong();
  routes["/incidents"] = (url) => new URL(`https://x${url}`).searchParams.get("offset") === "100"
    ? page("incidents", [{ id: "PINC3", incident_number: 103, status: "resolved" }], false, 100)
    : page("incidents", (strong()["/incidents"] as { body: { incidents: unknown[] } }).body.incidents, true, 0);
  routes["/incidents/PINC3/notes"] = ok({ notes: [] });
  const rs = await runWith(C, fakeRest(PAGERDUTY_BASE, routes, calls));
  const q = new URL(`https://x${calls.find((c) => c.startsWith("/incidents?"))!}`).searchParams;
  assert.deepEqual(q.getAll("statuses[]"), ["resolved"]);
  assert.deepEqual(q.getAll("urgencies[]"), ["high"]);
  assert.equal(q.get("until"), "2026-10-15T12:00:00.000Z");
  assert.equal(q.get("since"), "2026-07-17T12:00:00.000Z");
  const r = of(rs, "pagerduty.incident_reviews_linked")[0];
  assert.equal(r.result, "fail"); assert.match(r.detail, /incidents #103/); assert.match(r.detail, /^3 resolved/);
  assert.ok(!JSON.stringify(rs).includes("Alice") && !JSON.stringify(rs).includes("wiki.example"));
});

test("pagerduty: a configured custom field marks the review before notes are read", async () => {
  const calls: string[] = [];
  const routes = { ...strong(), ...C.fails.incident_reviews_linked,
    "/incidents/PINC1/custom_fields/values": ok({ custom_fields: [{ name: "postmortem_url", value: "https://wiki/pm-101" }] }),
    "/incidents/PINC2/custom_fields/values": ok({ custom_fields: [{ name: "postmortem_url", value: { value: "https://wiki/pm-102" } }] }) };
  const rs = await runWith(C, fakeRest(PAGERDUTY_BASE, routes, calls), { opts: { "pagerduty-review-field": "postmortem_url" } });
  assert.equal(of(rs, "pagerduty.incident_reviews_linked")[0].result, "pass");
  assert.ok(!calls.some((c) => c.endsWith("/notes")));
});

test("pagerduty: a completed Post-Incident Review (GET /incidents/{id}/review) counts without a note; started does not", async () => {
  const review = (status: string) => ok({ incident_review: { id: "AGOB1", incident_id: "PINC2", title: "Database outage review", status } });
  const calls: string[] = [];
  const done = of(await runWith(C, fakeRest(PAGERDUTY_BASE, { ...strong(), ...C.fails.incident_reviews_linked, "/incidents/PINC2/review": review("completed") }, calls)), "pagerduty.incident_reviews_linked")[0];
  assert.equal(done.result, "pass", done.detail);
  assert.match(done.detail, /1 with a completed Post-Incident Review/);
  assert.ok(!calls.includes("/incidents/PINC2/notes"));
  assert.ok(!done.detail.includes("Database outage"), "review titles are not copied");
  assert.equal(of(await runWith(C, fakeRest(PAGERDUTY_BASE, { ...strong(), ...C.fails.incident_reviews_linked, "/incidents/PINC2/review": review("started") })), "pagerduty.incident_reviews_linked")[0].result, "fail");
  const noPlan = of(await runWith(C, fakeRest(PAGERDUTY_BASE, { ...strong(), "/incidents/PINC1/review": res(403, { error: { message: "Access Denied", code: 2010 } }) })), "pagerduty.incident_reviews_linked")[0];
  assert.equal(noPlan.result, "pass", noPlan.detail);   // falls back to the notes, which name the reviews
  assert.match(noPlan.detail, /Post-Incident Reviews not readable/);
});

test("pagerduty: disabled services are left out; --pagerduty-service narrows the set; no incidents gives skipped", async () => {
  let rs = await runWith(C, fakeRest(PAGERDUTY_BASE, strong()));
  assert.match(of(rs, "pagerduty.escalation_multi_level")[0].detail, /^2 service/);
  rs = await runWith(C, fakeRest(PAGERDUTY_BASE, { ...strong(), "/incidents": page("incidents", []) }), { opts: { "pagerduty-service": ["PSVC2"] } });
  assert.match(of(rs, "pagerduty.escalation_multi_level")[0].detail, /^1 service/);
  assert.equal(of(rs, "pagerduty.incident_reviews_linked")[0].result, "skipped");
});

test("pagerduty: the real client sends GET with the Token header and the v2 Accept, and only to PagerDuty's US or EU API", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const api = pagerdutyFromEnv({ PAGERDUTY_TOKEN: "u+abcdefgh12345" }, (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch);
  assert.ok(typeof api !== "string");
  await api.get("/services?limit=100&offset=0");
  assert.equal(seen[0].url, "https://api.pagerduty.com/services?limit=100&offset=0");
  assert.equal(seen[0].init.method, "GET");
  const h = seen[0].init.headers as Record<string, string>;
  assert.equal(h.authorization, "Token token=u+abcdefgh12345");
  assert.equal(h.accept, "application/vnd.pagerduty+json;version=2");
  assert.equal(typeof pagerdutyFromEnv({ PAGERDUTY_TOKEN: "x", PAGERDUTY_API_URL: "https://evil.example" }), "string");
  assert.equal(typeof pagerdutyFromEnv({ PAGERDUTY_TOKEN: "x", PAGERDUTY_API_URL: "https://api.eu.pagerduty.com" }), "object");
});
