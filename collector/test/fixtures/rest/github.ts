// Fixtures for the github source, shared by test/github.test.ts and the end-to-end run (test/e2e.test.ts).
import { GITHUB_BASE, github, githubFromEnv } from "../../../src/sources/github.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const ok = (b: unknown, h: Record<string, string> = {}) => res(200, b, h);
export const REPOS1 = "/orgs/acme/repos?type=all&per_page=100";
export const REPOS2 = "/orgs/acme/repos?type=all&per_page=100&page=2";

export const classic = {
  required_status_checks: { strict: true, contexts: ["ci"], checks: [{ context: "ci", app_id: 15368 }] },
  required_pull_request_reviews: { dismiss_stale_reviews: true, require_code_owner_reviews: true, required_approving_review_count: 1 },
  required_signatures: { enabled: true }, allow_force_pushes: { enabled: false }, enforce_admins: { enabled: true },
};

export function repoRoutes(full: string, branch: string): Routes {
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

export const ORG = { login: "acme", two_factor_requirement_enabled: true, default_repository_permission: "read",
  members_can_create_repositories: true, members_can_create_public_repositories: false, members_can_create_private_repositories: true, members_can_change_repo_visibility: false };

export function strong(): Routes {
  return {
    "/orgs/acme": ok(ORG),
    "/orgs/acme/actions/permissions/workflow": ok({ default_workflow_permissions: "read", can_approve_pull_request_reviews: false }),
    "/orgs/acme/actions/permissions": ok({ enabled_repositories: "all", allowed_actions: "selected", sha_pinning_required: true }),
    "/orgs/acme/actions/permissions/selected-actions": ok({ github_owned_allowed: true, verified_allowed: false, patterns_allowed: ["docker/*", "*/octocat**@*"] }),
    "/orgs/acme/members?role=admin&per_page=100": ok([{ id: 1, login: "owner-one" }, { id: 2, login: "owner-two" }]),
    "/orgs/acme/outside_collaborators": ok([]),
    "/orgs/acme/audit-log": ok([{ "@timestamp": Date.parse(daysAgo(0)), action: "repo.create" }]),
    [REPOS1]: ok([{ full_name: "acme/api", archived: false }], { link: `<${GITHUB_BASE}${REPOS2}>; rel="next", <${GITHUB_BASE}${REPOS2}>; rel="last"` }),
    [REPOS2]: ok([{ full_name: "acme/web", archived: false }, { full_name: "acme/old", archived: true }]),
    ...repoRoutes("acme/api", "main"),
    ...repoRoutes("acme/web", "trunk"),
  };
}

export const A = "/repos/acme/api";
export const C: Contract = {
  source: github, clientKey: "github", base: GITHUB_BASE, prefix: "github", strong,
  opts: { "github-org": "acme" }, env: { GITHUB_TOKEN: "x" },
  rateLimited: { path: "/orgs/acme/actions/permissions/workflow", check: "actions_token_read_only" },
  fails: {
    org_requires_2fa: { "/orgs/acme": ok({ ...ORG, two_factor_requirement_enabled: false }), "/orgs/acme/members?filter=2fa_disabled&per_page=100": ok([{ id: 9 }]) },
    actions_token_read_only: { "/orgs/acme/actions/permissions/workflow": ok({ default_workflow_permissions: "write", can_approve_pull_request_reviews: false }) },
    actions_allowed_restricted: { "/orgs/acme/actions/permissions": ok({ enabled_repositories: "all", allowed_actions: "all" }) },
    org_owners_limited: { "/orgs/acme/members?role=admin&per_page=100": ok([1, 2, 3, 4].map((id) => ({ id }))) },
    outside_collaborators: { "/orgs/acme/outside_collaborators": ok([{ id: 77, login: "contractor" }]) },
    audit_log_available: { "/orgs/acme/audit-log": ok([]) },
    org_base_permission_read: { "/orgs/acme": ok({ ...ORG, default_repository_permission: "write" }) },
    org_public_repos_restricted: { "/orgs/acme": ok({ ...ORG, members_can_change_repo_visibility: true }) },
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
