// The PagerDuty source against a fake REST v2 API shaped like PagerDuty's OpenAPI (reference/REST/openapiv3.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGERDUTY_BASE, pagerduty, pagerdutyFromEnv } from "../src/sources/pagerduty.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { ok, page, policy, strong, C } from "./fixtures/rest/pagerduty.ts";

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
