// The GitHub source against a fake REST API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { GITHUB_BASE, github, githubFromEnv } from "../src/sources/github.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { ok, REPOS1, REPOS2, classic, repoRoutes, ORG, strong, A, C } from "./fixtures/rest/github.ts";

contractSuite(C);

test("github: actions_allowed_restricted fails \"selected\" whose list allows everything (*, */*, */*@*), and passes a real allowlist", async () => {
  for (const pats of [["*"], ["*", "!space-org/action@*"], ["*/*"], ["docker/*", "*/*@*"]]) {
    const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme/actions/permissions/selected-actions": ok({ github_owned_allowed: true, verified_allowed: false, patterns_allowed: pats }) }));
    const r = of(rs, "github.actions_allowed_restricted")[0];
    assert.equal(r.result, "fail", `${JSON.stringify(pats)}: ${r.detail}`);
    assert.match(r.detail, /allowing every action/);
  }
  const good = of(await runWith(C, fakeRest(GITHUB_BASE, strong())), "github.actions_allowed_restricted")[0];
  assert.equal(good.result, "pass", good.detail);
  const unread = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme/actions/permissions/selected-actions": res(403, { message: "Resource not accessible" }) }));
  assert.equal(of(unread, "github.actions_allowed_restricted")[0].result, "skipped");
});

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

test("github: a Team organization's audit log (404) is skipped with its plan named, never failed", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(),
    "/orgs/acme": ok({ ...ORG, plan: { name: "team", seats: 5, filled_seats: 4 } }),
    "/orgs/acme/audit-log": res(404, { message: "Not Found" }) }));
  const r = of(rs, "github.audit_log_available")[0];
  assert.equal(r.result, "skipped");
  assert.equal(r.detail, "the audit-log API is available only on GitHub Enterprise Cloud; this organization's plan is team");
});

test("github: a Free organization's audit log (403) is skipped with its plan named", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(),
    "/orgs/acme": ok({ ...ORG, plan: { name: "free" } }),
    "/orgs/acme/audit-log": res(403, { message: "Resource not accessible by personal access token" }) }));
  const r = of(rs, "github.audit_log_available")[0];
  assert.equal(r.result, "skipped");
  assert.match(r.detail, /available only on GitHub Enterprise Cloud; this organization's plan is free$/);
});

test("github: audit log 404 with the plan hidden from the token is skipped and says the plan was not shown", async () => {
  const rs = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme/audit-log": res(404, { message: "Not Found" }) }));
  const r = of(rs, "github.audit_log_available")[0];
  assert.equal(r.result, "skipped");
  assert.match(r.detail, /^the audit-log API is available only on GitHub Enterprise Cloud; GitHub answered 404 .*plan\.name to organization owners only/);
});

test("github: an Enterprise Cloud organization's readable audit log passes; an unreadable one names the owner requirement", async () => {
  const ent = { ...ORG, plan: { name: "enterprise" } };
  const pass = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme": ok(ent) }));
  assert.equal(of(pass, "github.audit_log_available")[0].result, "pass");
  const denied = await runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme": ok(ent),
    "/orgs/acme/audit-log": res(403, { message: "Must have admin rights to Repository." }) }));
  const r = of(denied, "github.audit_log_available")[0];
  assert.equal(r.result, "skipped");
  assert.match(r.detail, /the plan is enterprise, so the token needs an organization owner with Organization: Administration \(read\)/);
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

test("github: base permission and public repositories are judged from GET /orgs/{org}, and skipped when GitHub hides them", async () => {
  const run = (org: Record<string, unknown>) => runWith(C, fakeRest(GITHUB_BASE, { ...strong(), "/orgs/acme": ok(org) }));
  const none = await run({ ...ORG, default_repository_permission: "none", members_can_create_repositories: false, members_can_create_public_repositories: undefined });
  assert.equal(of(none, "github.org_base_permission_read")[0].result, "pass");
  assert.equal(of(none, "github.org_public_repos_restricted")[0].result, "pass", of(none, "github.org_public_repos_restricted")[0].detail);
  const admin = await run({ ...ORG, default_repository_permission: "admin", members_can_create_public_repositories: true });
  assert.match(of(admin, "github.org_base_permission_read")[0].detail, /"admin"; "read" or "none" required/);
  assert.equal(of(admin, "github.org_public_repos_restricted")[0].result, "fail");
  // A token whose owner is not an organization owner sees the public profile only.
  const member = await run({ login: "acme", name: "Acme" });
  for (const id of ["github.org_base_permission_read", "github.org_public_repos_restricted"]) {
    assert.equal(of(member, id)[0].result, "skipped");
    assert.match(of(member, id)[0].detail, /shows the full organization to its owners only/);
  }
});

test("github: a repository of another owner is checked too, with that owner's token; no token reaches a result (2026-11-05)", async () => {
  const seen: { url: string; auth: string }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    const auth = (init.headers as Record<string, string>).authorization;
    seen.push({ url, auth });
    return new Response(JSON.stringify({ message: `not here ${auth}` }), { status: 404 });
  }) as unknown as typeof fetch;
  const env = { GITHUB_TOKEN: "github_pat_ORG_0123456789", GITHUB_TOKEN_STEPHANE_RABY1: "github_pat_USER_0123456789" };
  const api = githubFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string");
  const rs = await runWith(C, api, { env, opts: { "github-org": "acme", "github-also-repo": ["stephane-raby1/site"] } });
  const user = seen.filter((s) => s.url.includes("/repos/stephane-raby1/"));
  assert.ok(user.length > 0, "the other owner's repository is read");
  for (const s of user) assert.equal(s.auth, "Bearer github_pat_USER_0123456789");
  for (const s of seen.filter((x) => x.url.includes("/acme"))) assert.equal(s.auth, "Bearer github_pat_ORG_0123456789");
  // A next-page link is a full URL; it keeps its owner's token.
  await api.get(`${GITHUB_BASE}/repos/stephane-raby1/site/dependabot/alerts?page=2`);
  assert.equal(seen.at(-1)!.auth, "Bearer github_pat_USER_0123456789");
  assert.ok(of(rs, "github.codeowners").some((r) => r.resource.includes("stephane-raby1/site")));
  const text = JSON.stringify(rs);
  assert.ok(!text.includes("github_pat_ORG_0123456789") && !text.includes("github_pat_USER_0123456789"));
});

test("github: only api.github.com's own path picks a per-owner token; a look-alike host keeps the main one (CodeQL)", async () => {
  const seen: string[] = [];
  const fetchFn = (async (_u: string, init: RequestInit) => { seen.push((init.headers as Record<string, string>).authorization); return new Response("[]", { status: 200 }); }) as unknown as typeof fetch;
  const api = githubFromEnv({ GITHUB_TOKEN: "github_pat_ORG_0123456789", GITHUB_TOKEN_BOB: "github_pat_BOB_0123456789" }, fetchFn);
  assert.ok(typeof api !== "string");
  await api.get("/repos/bob/x").catch(() => {});
  await api.get("https://api.github.com.evil.example/repos/bob/x").catch(() => {});
  assert.equal(seen[0], "Bearer github_pat_BOB_0123456789");
  assert.ok(!seen.slice(1).includes("Bearer github_pat_BOB_0123456789"), "a look-alike host never gets the per-owner token");
});
