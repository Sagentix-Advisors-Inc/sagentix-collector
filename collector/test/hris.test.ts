// The HR sources (BambooHR, Rippling) against fakes shaped like their list-employees and list-workers references, joined
// with fake identity providers shaped like Okta's users search, Graph's users and directory audits, the Admin SDK's
// users.get and the Reports API, and JumpCloud's systemusers. Fixtures are written by hand from the documented fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bamboohr, bamboohrFromEnv, employeesPath } from "../src/sources/bamboohr.ts";
import { customField, rippling, ripplingFromEnv, WORKERS } from "../src/sources/rippling.ts";
import { entraDirectory, googleDirectory, jumpcloudDirectory, oktaDirectory } from "../src/sources/directory.ts";
import { HRIS_CHECKS } from "../src/sources/hris_common.ts";
import type { HttpResponse, RestApi } from "../src/sources/readonly_http.ts";
import type { OptionValue, Result } from "../src/types.ts";
import { NOW } from "./helpers.ts";
import { fakeRest, of, res } from "./rest_fakes.ts";
import { ok, BHR, q, active, inactive, page, bambooRoutes, OKTA, oktaUsers, okta, csvDir, trainingCsv, BOPTS, RIP, workers, ripRoutes, ROPTS } from "./fixtures/local/hris.ts";

async function runBamboo(api: RestApi | null, o: { opts?: Record<string, OptionValue>; clients?: Record<string, unknown>; env?: Record<string, string> } = {}): Promise<Result[]> {
  return bamboohr.run({ opts: { ...BOPTS, ...(o.opts ?? {}) }, env: { BAMBOOHR_API_KEY: "bhr-key-0123456789", ...(o.env ?? {}) },
    clients: { bamboohr: api, okta: okta(), sleep: async () => {}, ...(o.clients ?? {}) }, now: NOW, warn: () => {} });
}

test("bamboohr: reads active and inactive employees with only the fields it needs, one GET per status", async () => {
  const calls: string[] = [];
  await runBamboo(fakeRest(BHR, bambooRoutes(), calls));
  assert.deepEqual(calls.map((c) => q(c).get("filter[status]")), ["active", "inactive"]);
  assert.equal(q(calls[0]).get("fields"), "workEmail,hireDate,terminationDate,supervisorEId,jobTitle,customCodeOfConduct,customBackground");
  assert.equal(calls[0], employeesPath("active", ["workEmail", "hireDate", "terminationDate", "supervisorEId", "jobTitle", "customCodeOfConduct", "customBackground"]));
});

test("bamboohr.leaver_access_removed: one result per leaver of the period, joined with Okta; late or active fails", async () => {
  const rs = await runBamboo(fakeRest(BHR, bambooRoutes()));
  const l = of(rs, "bamboohr.leaver_access_removed");
  assert.deepEqual(l.map((r) => [r.resource, r.result]), [["bamboohr acme employee 3 left 2026-09-30", "pass"], ["bamboohr acme employee 4 left 2026-10-10", "fail"]]);
  assert.match(l[0].detail, /DEPROVISIONED at 2026-10-01T05:00:00.000Z, 5 h after the last day ended; within 24 h required/);
  assert.match(l[1].detail, /account 00u-gus is still active/);
  // Nobody's name or email reaches a result, nor the key.
  const all = JSON.stringify(rs);
  for (const s of ["Fay", "Gus", "Dana", "acme.example", "bhr-key"]) assert.ok(!all.includes(s), `${s} leaked`);
});

test("bamboohr.leaver_access_removed: a disable after the window fails; no account passes but is marked incomplete; no IdP named skips", async () => {
  oktaUsers["fay@acme.example"] = { ...(oktaUsers["fay@acme.example"] as object), statusChanged: "2026-10-03T00:00:00.000Z" };
  let l = of(await runBamboo(fakeRest(BHR, bambooRoutes())), "bamboohr.leaver_access_removed");
  assert.equal(l[0].result, "fail");
  assert.match(l[0].detail, /48 h after/);
  oktaUsers["fay@acme.example"] = { ...(oktaUsers["fay@acme.example"] as object), statusChanged: "2026-10-01T05:00:00.000Z" };
  const gone = await runBamboo(fakeRest(BHR, bambooRoutes({ inactive: [{ ...inactive()[0], workEmail: "nobody@acme.example" }] })));
  l = of(gone, "bamboohr.leaver_access_removed");
  assert.equal(l[0].result, "pass");
  assert.equal(l[0].complete, false);
  l = of(await runBamboo(fakeRest(BHR, bambooRoutes()), { opts: { "bamboohr-idp": undefined } }), "bamboohr.leaver_access_removed");
  assert.ok(l.every((r) => r.result === "skipped" && /--bamboohr-idp/.test(r.detail)));
});

test("bamboohr: hires are judged on acknowledgement, background check and training; the org chart on managers and titles", async () => {
  const csv = trainingCsv("2,Security Awareness 2026,2026-06-10\n");
  let rs = await runBamboo(fakeRest(BHR, bambooRoutes()), { opts: { "training-csv": csv } });
  for (const id of ["hire_acknowledgement", "hire_background_check", "hire_training"]) {
    assert.deepEqual(of(rs, `bamboohr.${id}`).map((r) => [r.resource, r.result]), [["bamboohr acme employee 2 started 2026-06-01", "pass"]], id);
  }
  assert.equal(of(rs, "bamboohr.org_chart_complete")[0].result, "pass");
  // Weakened: no acknowledgement, no background check, training too late, a second person without a manager.
  const weak = active();
  delete (weak[1] as Record<string, unknown>).customCodeOfConduct;
  delete (weak[1] as Record<string, unknown>).customBackground;
  weak[1].supervisorEId = null;
  rs = await runBamboo(fakeRest(BHR, bambooRoutes({ active: weak })), { opts: { "training-csv": trainingCsv("2,Security Awareness 2026,2026-09-01\n") } });
  for (const id of ["hire_acknowledgement", "hire_background_check", "hire_training", "org_chart_complete"]) assert.equal(of(rs, `bamboohr.${id}`)[0].result, "fail", id);
  assert.match(of(rs, "bamboohr.org_chart_complete")[0].detail, /2 without a manager/);
  // Without the named fields or the export, those checks are skipped, never passed.
  rs = await runBamboo(fakeRest(BHR, bambooRoutes()), { opts: { "bamboohr-ack-field": undefined, "bamboohr-background-field": undefined } });
  for (const id of ["hire_acknowledgement", "hire_background_check", "hire_training"]) assert.equal(of(rs, `bamboohr.${id}`)[0].result, "skipped", id);
});

test("bamboohr: a field the key's user cannot read is reported as unreadable, not as a failing hire", async () => {
  const a = active();
  (a[1] as Record<string, unknown>).customBackground = null;
  a[1]._restrictedFields = ["customBackground"] as never;
  const rs = await runBamboo(fakeRest(BHR, bambooRoutes({ active: a })));
  const b = of(rs, "bamboohr.hire_background_check");
  assert.deepEqual(b.map((r) => r.result), ["skipped"]);
  assert.match(b[0].detail, /cannot read the field customBackground/);
});

test("bamboohr: no key, a bad subdomain or a 403 gives skipped for every check; the key never reaches a result", async () => {
  for (const rs of [
    await runBamboo(null),
    await bamboohr.run({ opts: { ...BOPTS, "bamboohr-company": "acme.evil.com/x" }, env: { BAMBOOHR_API_KEY: "k-0123456789" }, clients: {}, now: NOW, warn: () => {} }),
    await runBamboo({ get: async () => res(403, { message: "Forbidden for key bhr-key-0123456789" }) }),
  ]) {
    assert.deepEqual(rs.map((r) => r.check).sort(), HRIS_CHECKS.map((c) => `bamboohr.${c}`).sort());
    for (const r of rs) assert.equal(r.result, "skipped");
    assert.ok(!JSON.stringify(rs).includes("bhr-key-0123456789"));
  }
  assert.equal(typeof bamboohrFromEnv({}, "acme"), "string");
  assert.equal(bamboohr.validate?.({ "bamboohr-ack-field": "bad field;" }) !== undefined, true);
});

test("bamboohr: the real client sends GET with HTTP Basic (key, x) to https://<company>.bamboohr.com/api only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("{\"data\":[]}", { status: 200 }); }) as unknown as typeof fetch;
  const api = bamboohrFromEnv({ BAMBOOHR_API_KEY: "key-0123456789" }, "acme", f);
  assert.ok(typeof api !== "string");
  await api.get("/v1/employees?filter%5Bstatus%5D=active");
  assert.equal(seen[0].url, "https://acme.bamboohr.com/api/v1/employees?filter%5Bstatus%5D=active");
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, `Basic ${Buffer.from("key-0123456789:x").toString("base64")}`);
  assert.equal((await api.get("https://elsewhere.example/v1/employees")).status, 0);
});

// ── Rippling.
const runRip = (api: RestApi | null, opts: Record<string, OptionValue> = {}) =>
  rippling.run({ opts: { ...ROPTS, ...opts }, env: { RIPPLING_API_TOKEN: "rip-token-0123456789" }, clients: { rippling: api, okta: okta(), sleep: async () => {} }, now: NOW, warn: () => {} });

test("rippling: follows next_link, joins leavers with the identity provider, reads custom fields of either shape", async () => {
  const calls: string[] = [];
  const rs = await runRip(fakeRest(RIP, ripRoutes(), calls));
  assert.equal(calls[0], WORKERS);
  assert.equal(calls.length, 2);
  assert.deepEqual(of(rs, "rippling.leaver_access_removed").map((r) => [r.resource, r.result]), [["rippling acme.example employee w3 left 2026-09-30", "pass"]]);
  assert.equal(of(rs, "rippling.hire_acknowledgement")[0].result, "pass");
  assert.equal(of(rs, "rippling.hire_background_check")[0].result, "pass");
  assert.equal(of(rs, "rippling.org_chart_complete")[0].result, "pass");
  assert.ok(!/Fay|Eli|acme\.example"|rip-token/.test(JSON.stringify(rs.map((r) => r.detail))));
  assert.equal(customField(workers()[1], "background check"), "2026-05-25");
});

test("rippling: a custom field no worker carries is reported as misnamed, not as failing hires; 401 skips everything", async () => {
  let rs = await runRip(fakeRest(RIP, ripRoutes()), { "rippling-ack-field": "Handbook signed" });
  assert.deepEqual(of(rs, "rippling.hire_acknowledgement").map((r) => r.result), ["skipped"]);
  assert.match(of(rs, "rippling.hire_acknowledgement")[0].detail, /no worker carries the custom field "Handbook signed"/);
  rs = await runRip({ get: async () => res(401, { detail: "Invalid token rip-token-0123456789" }) });
  for (const r of rs) assert.equal(r.result, "skipped");
  assert.ok(!JSON.stringify(rs).includes("rip-token-0123456789"));
  assert.equal(typeof ripplingFromEnv({}), "string");
});

// ── Identity-provider lookups.
test("directory: Okta searches by profile.email, which also returns DEPROVISIONED users", async () => {
  const calls: string[] = [];
  const d = oktaDirectory(okta(calls));
  assert.deepEqual(await d.lookup("fay@acme.example"), { state: "disabled", id: "00u-fay", at: "2026-10-01T05:00:00.000Z", how: "Okta status DEPROVISIONED" });
  assert.deepEqual(await d.lookup("gus@acme.example"), { state: "active", id: "00u-gus" });
  assert.deepEqual(await d.lookup("x@acme.example"), { state: "absent" });
  assert.equal(q(calls[0]).get("search"), 'profile.email eq "fay@acme.example"');
});

test("directory: Entra reads accountEnabled, dates the disable from the directory audit, and finds deleted users", async () => {
  const G = "https://graph.microsoft.com/v1.0";
  const calls: string[] = [];
  const api = fakeRest(G, {
    "/users": (url) => (/fay@/.test(q(url).get("$filter") ?? "") ? ok({ value: [{ id: "u-fay", accountEnabled: false }] })
      : /gus@/.test(q(url).get("$filter") ?? "") ? ok({ value: [{ id: "u-gus", accountEnabled: true }] }) : ok({ value: [] })),
    "/auditLogs/directoryAudits": ok({ value: [{ id: "a1", activityDisplayName: "Disable account", activityDateTime: "2026-10-01T02:00:00Z" }] }),
    "/directory/deletedItems/microsoft.graph.user": (url) => (/hal@/.test(q(url).get("$filter") ?? "") ? ok({ value: [{ id: "u-hal", deletedDateTime: "2026-10-02T00:00:00Z" }] }) : ok({ value: [] })),
  }, calls);
  const d = entraDirectory(api);
  assert.deepEqual(await d.lookup("fay@acme.example"), { state: "disabled", id: "u-fay", at: "2026-10-01T02:00:00Z", how: "Entra accountEnabled false" });
  assert.deepEqual(await d.lookup("gus@acme.example"), { state: "active", id: "u-gus" });
  assert.deepEqual(await d.lookup("hal@acme.example"), { state: "deleted", id: "u-hal", at: "2026-10-02T00:00:00Z", how: "Entra deleted user" });
  assert.equal(q(calls.find((c) => c.startsWith("/auditLogs"))!).get("$filter"), "activityDisplayName eq 'Disable account' and targetResources/any(t:t/id eq 'u-fay')");
  // A quote in an address is escaped for OData, never left to end the literal.
  await d.lookup("o'neil@acme.example");
  assert.match(q(calls.filter((c) => c.startsWith("/users")).pop()!).get("$filter")!, /o''neil@/);
});

test("directory: Google reads suspended and suspensionTime, and a deleted user's DELETE_USER event", async () => {
  const A = "https://admin.googleapis.com";
  const api = fakeRest(A, {
    "/admin/directory/v1/users/fay%40acme.example": ok({ id: "g-fay", suspended: true, suspensionTime: "2026-10-01T03:00:00Z", name: { fullName: "Fay" } }),
    "/admin/directory/v1/users/gus%40acme.example": ok({ id: "g-gus", suspended: false }),
    "/admin/directory/v1/users/hal%40acme.example": res(404, { error: { code: 404, message: "Resource Not Found: userKey" } }),
    "/admin/reports/v1/activity/users/all/applications/admin": ok({ items: [{ id: { time: "2026-10-02T09:00:00.000Z" }, events: [{ name: "DELETE_USER" }] }] }),
    "/admin/directory/v1/users/err%40acme.example": res(403, { error: { code: 403, message: "Not Authorized to access this resource/api" } }),
  });
  const d = googleDirectory(api);
  assert.deepEqual(await d.lookup("fay@acme.example"), { state: "disabled", id: "g-fay", at: "2026-10-01T03:00:00Z", how: "Google suspended" });
  assert.deepEqual(await d.lookup("gus@acme.example"), { state: "active", id: "g-gus" });
  assert.deepEqual(await d.lookup("hal@acme.example"), { state: "deleted", at: "2026-10-02T09:00:00.000Z", how: "Google DELETE_USER event" });
  assert.equal((await d.lookup("err@acme.example")).state, "error");
});

test("directory: JumpCloud gives the state only (no time is recorded), so a pass is incomplete", async () => {
  const api = fakeRest("https://console.jumpcloud.com/api", {
    "/systemusers": (url) => (/fay@/.test(q(url).get("filter") ?? "") ? ok({ totalCount: 1, results: [{ _id: "j-fay", suspended: true, state: "SUSPENDED" }] }) : ok({ totalCount: 0, results: [] })),
  });
  const d = jumpcloudDirectory(api);
  assert.deepEqual(await d.lookup("fay@acme.example"), { state: "disabled", id: "j-fay", how: "JumpCloud suspended (no time recorded)" });
  const rs = await runBamboo(fakeRest(BHR, bambooRoutes({ inactive: [inactive()[0]] })), { opts: { "bamboohr-idp": "jumpcloud" }, clients: { jumpcloud: api } });
  const l = of(rs, "bamboohr.leaver_access_removed")[0];
  assert.equal(l.result, "pass");
  assert.equal(l.complete, false);
});

test("hris: an identity provider that refuses gives a skipped leaver result with the HTTP status, never a pass", async () => {
  const denied: RestApi = { get: async (): Promise<HttpResponse> => res(403, { errorSummary: "You do not have permission" }) };
  const rs = await runBamboo(fakeRest(BHR, bambooRoutes()), { clients: { okta: denied } });
  for (const r of of(rs, "bamboohr.leaver_access_removed")) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 403/); }
});
