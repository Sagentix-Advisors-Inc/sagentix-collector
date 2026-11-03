// The Vercel source against a fake REST API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { SECRET_NAME, VERCEL_BASE, teamQuery, vercel, vercelFromEnv } from "../src/sources/vercel.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const ok = (b: unknown) => res(200, b);
const TEAM = "team_abc123";
const PAGE2 = `/v10/projects?limit=100&from=cursor2&teamId=${TEAM}`;

const project = (id: string, name: string, over: Record<string, unknown> = {}) => ({
  id, name, gitForkProtection: true,
  ssoProtection: { deploymentType: "all_except_custom_domains" }, passwordProtection: null,
  security: { firewallEnabled: true }, ...over,
});

function strong(): Routes {
  return {
    [`/v2/teams/${TEAM}`]: ok({ id: TEAM, slug: "acme", saml: { enforced: true, connection: { type: "OktaSAML", status: "linked" } } }),
    [`/v3/teams/${TEAM}/members`]: ok({ members: [{ uid: "u1", role: "OWNER" }, { uid: "u2", role: "OWNER" }, { uid: "u3", role: "DEVELOPER" }], pagination: { hasNext: false, count: 3, next: null } }),
    "/v3/events": ok({ events: [{ id: "e1", type: "login", createdAt: Date.parse(daysAgo(1)) }] }),
    [`/v10/projects?limit=100&teamId=${TEAM}`]: ok({ projects: [{ id: "prj_web", name: "web" }], pagination: { count: 1, next: "cursor2" } }),
    [PAGE2]: ok({ projects: [{ id: "prj_api", name: "api" }], pagination: { count: 1, next: null } }),
    "/v9/projects/prj_web": ok(project("prj_web", "web")),
    "/v9/projects/prj_api": ok(project("prj_api", "api", { ssoProtection: null, passwordProtection: { deploymentType: "preview" } })),
    "/v10/projects/prj_web/env": ok({ envs: [{ key: "DATABASE_URL", type: "encrypted" }, { key: "NEXT_PUBLIC_SITE", type: "plain" }] }),
    "/v10/projects/prj_api/env": ok({ envs: [{ key: "STRIPE_SECRET_KEY", type: "sensitive" }] }),
  };
}

const W = "/v9/projects/prj_web";
const C: Contract = {
  source: vercel, clientKey: "vercel", base: VERCEL_BASE, prefix: "vercel", strong,
  opts: { "vercel-team": TEAM }, env: { VERCEL_TOKEN: "x" },
  rateLimited: { path: `/v3/teams/${TEAM}/members`, check: "team_owners_limited" },
  fails: {
    team_saml_enforced: { [`/v2/teams/${TEAM}`]: ok({ id: TEAM, saml: { enforced: false, connection: { type: "OktaSAML" } } }) },
    team_owners_limited: { [`/v3/teams/${TEAM}/members`]: ok({ members: [1, 2, 3, 4].map((n) => ({ uid: `u${n}`, role: "OWNER" })), pagination: { hasNext: false } }) },
    activity_log_available: { "/v3/events": ok({ events: [] }) },
    deployment_protection: { [W]: ok(project("prj_web", "web", { ssoProtection: null })) },
    git_fork_protection: { [W]: ok(project("prj_web", "web", { gitForkProtection: false })) },
    firewall_enabled: { [W]: ok(project("prj_web", "web", { security: { firewallEnabled: false } })) },
    no_plain_secret_envs: { "/v10/projects/prj_web/env": ok({ envs: [{ key: "RESEND_API_KEY", type: "plain" }] }) },
  },
};

contractSuite(C);

test("vercel: a team without SAML gets team_saml_enforced skipped, not failed (2FA enforcement is not in the API)", async () => {
  const rs = await runWith(C, fakeRest(VERCEL_BASE, { ...strong(), [`/v2/teams/${TEAM}`]: ok({ id: TEAM, saml: null }) }));
  const r = of(rs, "vercel.team_saml_enforced");
  assert.equal(r.length, 1);
  assert.equal(r[0].result, "skipped");
  assert.match(r[0].detail, /two-factor/);
});

test("vercel: no --vercel-team skips the team checks and still judges the account's projects", async () => {
  const calls: string[] = [];
  const routes: Routes = {
    "/v10/projects?limit=100": ok({ projects: [{ id: "prj_web" }], pagination: { next: null } }),
    "/v9/projects/prj_web": ok(project("prj_web", "web")),
    "/v10/projects/prj_web/env": ok({ envs: [] }),
  };
  const rs = await runWith(C, fakeRest(VERCEL_BASE, routes, calls), { opts: { "vercel-team": "" } });
  for (const c of ["team_saml_enforced", "team_owners_limited", "activity_log_available"]) assert.equal(of(rs, `vercel.${c}`)[0].result, "skipped");
  assert.equal(of(rs, "vercel.deployment_protection")[0].result, "pass");
  assert.ok(calls.every((u) => !u.includes("teamId=") && !u.includes("slug=")), JSON.stringify(calls));
});

test("vercel: every request is a GET with the team named, and decrypt is never asked", async () => {
  const calls: string[] = [];
  await runWith(C, fakeRest(VERCEL_BASE, strong(), calls));
  assert.ok(calls.length > 0);
  for (const u of calls) {
    assert.match(u, /[?&]teamId=team_abc123/, u);
    assert.doesNotMatch(u, /decrypt/i, u);
  }
  assert.ok(calls.includes(PAGE2), "the second project page is followed");
});

test("vercel: a slug is sent as slug=, an id as teamId=", () => {
  assert.equal(teamQuery("team_x"), "teamId=team_x");
  assert.equal(teamQuery("acme"), "slug=acme");
  assert.equal(teamQuery(undefined), "");
});

test("vercel: a credential-looking plain variable fails by name only; its value never appears", async () => {
  const rs = await runWith(C, fakeRest(VERCEL_BASE, { ...strong(), "/v10/projects/prj_web/env": ok({ envs: [{ key: "GITHUB_TOKEN", type: "plain", value: "ghp_value_never_sent" }] }) }));
  const r = of(rs, "vercel.no_plain_secret_envs").find((x) => x.resource === "vercel project web");
  assert.equal(r?.result, "fail");
  assert.match(r!.detail, /GITHUB_TOKEN/);
  assert.ok(!JSON.stringify(rs).includes("ghp_value_never_sent"));
  for (const k of ["NEXT_PUBLIC_SITE_URL", "NODE_ENV", "VERCEL_ENV"]) assert.doesNotMatch(k, SECRET_NAME, k);
});

test("vercel: project ids from the list are capped at --vercel-max-projects, with a warning", async () => {
  const warns: string[] = [];
  const rs = await vercel.run({ opts: { "vercel-team": TEAM, "vercel-max-projects": "1" }, env: { VERCEL_TOKEN: "x" },
    clients: { vercel: fakeRest(VERCEL_BASE, strong()), sleep: async () => {} }, now: new Date(), warn: (s) => warns.push(s) });
  assert.equal(of(rs, "vercel.firewall_enabled").length, 1);
  assert.ok(warns.some((w) => /--vercel-max-projects/.test(w)));
});

test("vercel: vercelFromEnv needs VERCEL_TOKEN and refuses another origin", async () => {
  assert.equal(vercelFromEnv({}), "VERCEL_TOKEN is not set");
  const seen: string[] = [];
  const api = vercelFromEnv({ VERCEL_TOKEN: "x".repeat(12) }, (async (u: string, init: RequestInit) => {
    seen.push(`${init.method} ${u}`);
    return new Response("{}", { status: 200 });
  }) as typeof fetch);
  assert.ok(typeof api !== "string");
  const far = await api.get("https://evil.example.com/v2/user");
  assert.equal(far.status, 0);
  await api.get("/v2/user");
  assert.deepEqual(seen, ["GET https://api.vercel.com/v2/user"]);
});
