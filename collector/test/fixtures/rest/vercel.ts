// Fixtures for the vercel source, shared by test/vercel.test.ts and the end-to-end run (test/e2e.test.ts).
import { SECRET_NAME, VERCEL_BASE, teamQuery, vercel, vercelFromEnv } from "../../../src/sources/vercel.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const ok = (b: unknown) => res(200, b);
export const TEAM = "team_abc123";
export const PAGE2 = `/v10/projects?limit=100&from=cursor2&teamId=${TEAM}`;

export const project = (id: string, name: string, over: Record<string, unknown> = {}) => ({
  id, name, gitForkProtection: true,
  ssoProtection: { deploymentType: "all_except_custom_domains" }, passwordProtection: null,
  security: { firewallEnabled: true }, ...over,
});

export function strong(): Routes {
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

export const W = "/v9/projects/prj_web";
export const C: Contract = {
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
