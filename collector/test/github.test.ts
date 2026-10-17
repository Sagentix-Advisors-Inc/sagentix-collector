// The GitHub source against a fake REST API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { GITHUB_BASE, github, githubFromEnv } from "../src/sources/github.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const ok = (b: unknown, h: Record<string, string> = {}) => res(200, b, h);
const REPOS1 = "/orgs/acme/repos?type=all&per_page=100";
const REPOS2 = "/orgs/acme/repos?type=all&per_page=100&page=2";

const classic = {
  required_status_checks: { strict: true, contexts: ["ci"], checks: [{ context: "ci", app_id: 15368 }] },
  required_pull_request_reviews: { dismiss_stale_reviews: true, require_code_owner_reviews: true, required_approving_review_count: 1 },
  required_signatures: { enabled: true }, allow_force_pushes: { enabled: false }, enforce_admins: { enabled: true },
};

function repoRoutes(full: string, branch: string): Routes {
  const rp = `/repos/${full}`;
  return {
    [rp]: ok({ full_name: full, default_branch: branch, archived: false, security_and_analysis: { secret_scanning: { status: "enabled" }, secret_scanning_push_protection: { status: "enabled" } } }),
    [`${rp}/branches/${branch}/protection`]: ok(classic),
    [`${rp}/rules/branches/${branch}`]: ok([]),
    [`${rp}/contents/.github/CODEOWNERS`]: ok({ type: "file", path: ".github/CODEOWNERS" }),
    [`${rp}/vulnerability-alerts`]: res(204, null),
    [`${rp}/dependabot/alerts`]: ok([{ number: 7, state: "open", created_at: daysAgo(3), security_advisory: { severity: "high" } }]),
    [`${rp}/code-scanning/analyses`]: ok([{ id: 1, tool: { name: "CodeQL" }, created_at: daysAgo(1) }]),
  };
}

function strong(): Routes {
  return {
    "/orgs/acme": ok({ login: "acme", two_factor_requirement_enabled: true }),
    "/orgs/acme/actions/permissions/workflow": ok({ default_workflow_permissions: "read", can_approve_pull_request_reviews: false }),
    "/orgs/acme/actions/permissions": ok({ enabled_repositories: "all", allowed_actions: "selected", sha_pinning_required: true }),
    "/orgs/acme/members?role=admin&per_page=100": ok([{ id: 1, login: "owner-one" }, { id: 2, login: "owner-two" }]),
    "/orgs/acme/outside_collaborators": ok([]),
    "/orgs/acme/audit-log": ok([{ "@timestamp": Date.parse(daysAgo(0)), action: "repo.create" }]),
    [REPOS1]: ok([{ full_name: "acme/api", archived: false }], { link: `<${GITHUB_BASE}${REPOS2}>; rel="next", <${GITHUB_BASE}${REPOS2}>; rel="last"` }),
    [REPOS2]: ok([{ full_name: "acme/web", archived: false }, { full_name: "acme/old", archived: true }]),
    ...repoRoutes("acme/api", "main"),
    ...repoRoutes("acme/web", "trunk"),
  };
}

const A = "/repos/acme/api";
const C: Contract = {
  source: github, clientKey: "github", base: GITHUB_BASE, prefix: "github", strong,
  opts: { "github-org": "acme" }, env: { GITHUB_TOKEN: "x" },
  rateLimited: { path: "/orgs/acme/actions/permissions/workflow", check: "actions_token_read_only" },
  fails: {
    org_requires_2fa: { "/orgs/acme": ok({ login: "acme", two_factor_requirement_enabled: false }), "/orgs/acme/members?filter=2fa_disabled&per_page=100": ok([{ id: 9 }]) },
    actions_token_read_only: { "/orgs/acme/actions/permissions/workflow": ok({ default_workflow_permissions: "write", can_approve_pull_request_reviews: false }) },
    actions_allowed_restricted: { "/orgs/acme/actions/permissions": ok({ enabled_repositories: "all", allowed_actions: "all" }) },
    org_owners_limited: { "/orgs/acme/members?role=admin&per_page=100": ok([1, 2, 3, 4].map((id) => ({ id }))) },
    outside_collaborators: { "/orgs/acme/outside_collaborators": ok([{ id: 77, login: "contractor" }]) },
    audit_log_available: { "/orgs/acme/audit-log": ok([]) },
    default_branch_reviews: { [`${A}/branches/main/protection`]: ok({ ...classic, required_pull_request_reviews: { required_approving_review_count: 0 } }) },
    default_branch_dismiss_stale: { [`${A}/branches/main/protection`]: ok({ ...classic, required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: false } }) },
    default_branch_status_checks: { [`${A}/branches/main/protection`]: ok({ ...classic, required_status_checks: null }) },
    default_branch_no_force_push: { [`${A}/branches/main/protection`]: res(404, { message: "Branch not protected" }) },
    default_branch_signed_commits: { [`${A}/branches/main/protection`]: ok({ ...classic, required_signatures: { enabled: false } }) },
    codeowners: { [`${A}/contents/.github/CODEOWNERS`]: res(404, { message: "Not Found" }) },
    secret_scanning: { [A]: ok({ full_name: "acme/api", default_branch: "main", security_and_analysis: { secret_scanning: { status: "disabled" }, secret_scanning_push_protection: { status: "disabled" } } }) },
    push_protection: { [A]: ok({ full_name: "acme/api", default_branch: "main", security_and_analysis: { secret_scanning: { status: "enabled" }, secret_scanning_push_protection: { status: "disabled" } } }) },
    dependabot_alerts_enabled: { [`${A}/vulnerability-alerts`]: res(404, { message: "Not Found" }) },
    dependabot_aged_critical_high: { [`${A}/dependabot/alerts`]: ok([{ number: 3, state: "open", created_at: daysAgo(45), security_advisory: { severity: "critical" } }]) },
    code_scanning_enabled: { [`${A}/code-scanning/analyses`]: res(404, { message: "no analysis found" }) },
  },
};

contractSuite(C);

test("github: repositories are read across Link pages; archived ones are left out", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(GITHUB_BASE, strong(), calls));
  assert.ok(calls.includes(REPOS2));
  const repos = new Set(of(rs, "github.codeowners").map((r) => r.resource));
  assert.deepEqual([...repos].sort(), ["repo acme/api", "repo acme/web"]);
  assert.ok(of(rs, "github.default_branch_reviews").some((r) => r.resource === "repo acme/web branch trunk"));
});

test("github: an active ruleset passes where classic protection is off", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(),
    [`${A}/branches/main/protection`]: res(404, { message: "Branch not protected" }),
    [`${A}/rules/branches/main`]: ok([
      { type: "pull_request", parameters: { required_approving_review_count: 2, dismiss_stale_reviews_on_push: true } },
      { type: "required_status_checks", parameters: { required_status_checks: [{ context: "ci" }] } },
      { type: "non_fast_forward" }, { type: "required_signatures" },
    ]) }));
  for (const c of ["default_branch_reviews", "default_branch_dismiss_stale", "default_branch_status_checks", "default_branch_no_force_push", "default_branch_signed_commits"]) {
    const r = of(rs, `github.${c}`).find((x) => x.resource === "repo acme/api branch main")!;
    assert.equal(r.result, "pass", `${c}: ${r.detail}`);
  }
});

test("github: classic protection unreadable and no ruleset → skipped, not fail", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), [`${A}/branches/main/protection`]: res(403, { message: "Resource not accessible by personal access token" }) }));
  const r = of(rs, "github.default_branch_reviews").find((x) => x.resource === "repo acme/api branch main")!;
  assert.equal(r.result, "skipped");
});

test("github: two_factor_requirement_enabled hidden from a non-owner is skipped", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme": ok({ login: "acme" }) }));
  assert.equal(of(rs, "github.org_requires_2fa")[0].result, "skipped");
});

test("github: GitHub's primary rate limit (403, x-ratelimit-remaining 0) is retried", async () => {
  const waits: number[] = [];
  const reset = String(Math.floor(Date.now() / 1000) + 3);
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(),
    "/orgs/acme": (u, n) => (n === 1 ? res(403, { message: "API rate limit exceeded" }, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": reset }) : ok({ two_factor_requirement_enabled: true })) }), { waits });
  assert.equal(waits.length, 1);
  assert.equal(of(rs, "github.org_requires_2fa")[0].result, "pass");
});

test("github: --github-repo limits the run and skips the repository list", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(GITHUB_BASE, strong(), calls), { opts: { "github-repo": ["api"] } });
  assert.ok(!calls.some((c) => c.startsWith("/orgs/acme/repos")));
  assert.deepEqual([...new Set(of(rs, "github.codeowners").map((r) => r.resource))], ["repo acme/api"]);
});

test("github: no --github-org skips every check", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, strong()), { opts: { "github-org": undefined } });
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /--github-org/); }
});

test("github: the fetch client sends GET with the bearer token and API version; the token never reaches a result", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    const h = init.headers as Record<string, string>;
    return new Response(JSON.stringify({ message: `Resource not accessible by personal access token ${h.authorization}` }), { status: 403 });
  }) as unknown as typeof fetch;
  const env = { GITHUB_TOKEN: "github_pat_11AAAAAAA0123456789" };
  const api = githubFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string");
  const rs = await runWith(C, api, { env });
  for (const s of seen) {
    const h = s.init.headers as Record<string, string>;
    assert.equal(s.init.method, "GET");
    assert.equal(s.init.body, undefined);
    assert.ok(s.url.startsWith(`${GITHUB_BASE}/`));
    assert.equal(h.authorization, "Bearer github_pat_11AAAAAAA0123456789");
    assert.equal(h["x-github-api-version"], "2022-11-28");
  }
  assert.ok(!JSON.stringify(rs).includes("github_pat_11AAAAAAA0123456789"));
  for (const r of rs) assert.equal(r.result, "skipped");
});
