// GitHub organization and its repositories over the REST API (GET only), with a fine-grained personal
// access token or a GitHub App installation token in GITHUB_TOKEN.
//
// Endpoint → fine-grained permission, read (docs.github.com/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens):
//   GET /orgs/{org}                                         none (two_factor_requirement_enabled shows to owners only)
//     default_repository_permission ("read", "write", "admin" or "none"), members_can_create_repositories,
//     members_can_create_public_repositories and members_can_change_repo_visibility, from "Get an organization"
//     (docs.github.com/rest/orgs/orgs#get-an-organization, read 2026-10-20: "To see the full details about an
//     organization, the authenticated user must be an organization owner"). The settings behind them: base
//     permissions (docs.github.com/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization),
//     repository creation and visibility changes (docs.github.com/organizations/managing-organization-settings/
//     restricting-repository-creation-in-your-organization and …/restricting-repository-visibility-changes-in-your-organization), all read 2026-10-20.
//   GET /orgs/{org}/members?role=admin|filter=2fa_disabled  Organization: Members
//   GET /orgs/{org}/outside_collaborators                   Organization: Members
//   GET /orgs/{org}/actions/permissions[/workflow]          Organization: Administration
//   GET /orgs/{org}/audit-log                               Organization: Administration (Enterprise Cloud only)
//   GET /orgs/{org}/repos, /repos/{o}/{r}                    Repository: Metadata
//   GET /repos/{o}/{r}/rules/branches/{b}                   Repository: Metadata
//   GET /repos/{o}/{r}/branches/{b}/protection              Repository: Administration
//   GET /repos/{o}/{r}/vulnerability-alerts                 Repository: Administration
//   GET /repos/{o}/{r}/contents/{path}                      Repository: Contents
//   GET /repos/{o}/{r}/dependabot/alerts                    Repository: Dependabot alerts
//   GET /repos/{o}/{r}/code-scanning/analyses               Repository: Code scanning alerts
//   security_and_analysis on /repos/{o}/{r}                 shown to admins of the repository
//
// Pages follow the Link header; a 429, or a 403 with x-ratelimit-remaining 0 or retry-after, waits
// and retries. Personal data: counts and numeric GitHub user ids only.

import type { Outcome, Result, Source, SourceContext } from "../types.ts";
import {
  DAY_MS, Emitter, arr, enc, fetchRest, firstIds, getAll, intOpt, isObj, linkNext, ok, realSleep, redact, str, why, withRetry,
  type HttpResponse, type Obj, type RestApi, type Sleep,
} from "./readonly_http.ts";

export const GITHUB_BASE = "https://api.github.com";
export const GITHUB_TOKEN_ENV = "GITHUB_TOKEN";
export const DEFAULTS = { maxOwners: 3, maxOutsideCollaborators: 0, alertDays: 30, maxRepos: 200 };
export const CODEOWNERS_PATHS = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

export const ORG_CHECKS = [
  "org_requires_2fa", "actions_token_read_only", "actions_allowed_restricted", "org_owners_limited", "outside_collaborators", "audit_log_available",
  "org_base_permission_read", "org_public_repos_restricted",
] as const;
export const REPO_CHECKS = [
  "default_branch_reviews", "default_branch_dismiss_stale", "default_branch_status_checks", "default_branch_no_force_push",
  "default_branch_signed_commits", "codeowners", "secret_scanning", "push_protection", "dependabot_alerts_enabled",
  "dependabot_aged_critical_high", "code_scanning_enabled",
] as const;
type C = (typeof ORG_CHECKS)[number] | (typeof REPO_CHECKS)[number];

const arrayBody = (b: unknown) => (Array.isArray(b) ? b : undefined);
const list = (api: RestApi, path: string, maxPages = 50) => getAll(api, path, arrayBody, (r) => linkNext(r.headers), maxPages);

export function githubFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const token = env[GITHUB_TOKEN_ENV];
  if (!token) return `${GITHUB_TOKEN_ENV} is not set`;
  return fetchRest({ base: GITHUB_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" }) });
}

export interface GithubOptions { org: string; repos: string[]; maxRepos: number; maxOwners: number; maxOutsideCollaborators: number; alertDays: number }

async function orgChecks(api: RestApi, o: GithubOptions, out: Emitter<C>): Promise<void> {
  const org = enc(o.org);
  const g = await api.get(`/orgs/${org}`);
  const tfa = ok(g) && isObj(g.body) ? g.body.two_factor_requirement_enabled : undefined;
  if (typeof tfa !== "boolean") out.add("org_requires_2fa", "skipped", ok(g)
    ? "two_factor_requirement_enabled is not shown; GitHub shows it to organization owners only"
    : `organization not readable: ${why(g)}`);
  else {
    const off = tfa ? undefined : await list(api, `/orgs/${org}/members?filter=2fa_disabled&per_page=100`);
    const n = off && !("error" in off) ? `; ${off.items.length} member(s) without 2FA` : "";
    out.add("org_requires_2fa", tfa ? "pass" : "fail", `two_factor_requirement_enabled is ${tfa}; true required${n}`);
  }
  orgAccessChecks(g, out);

  const wf = await api.get(`/orgs/${org}/actions/permissions/workflow`);
  if (!ok(wf) || !isObj(wf.body) || typeof wf.body.default_workflow_permissions !== "string") out.skip("actions_token_read_only", wf, "Actions default workflow permissions");
  else {
    const d = wf.body.default_workflow_permissions, a = wf.body.can_approve_pull_request_reviews;
    out.add("actions_token_read_only", d === "read" && a !== true ? "pass" : "fail",
      `default_workflow_permissions is ${JSON.stringify(d)}, can_approve_pull_request_reviews is ${JSON.stringify(a)}; "read" and false required`);
  }

  const ap = await api.get(`/orgs/${org}/actions/permissions`);
  if (!ok(ap) || !isObj(ap.body)) out.skip("actions_allowed_restricted", ap, "Actions permissions");
  else {
    const en = ap.body.enabled_repositories, al = ap.body.allowed_actions;
    const pass = en === "none" || (typeof al === "string" && al !== "all");
    out.add("actions_allowed_restricted", pass ? "pass" : "fail",
      `enabled_repositories ${JSON.stringify(en)}, allowed_actions ${JSON.stringify(al ?? null)}, sha_pinning_required ${JSON.stringify(ap.body.sha_pinning_required ?? null)}; allowed_actions "local_only" or "selected" (or Actions off) required`);
  }

  const owners = await list(api, `/orgs/${org}/members?role=admin&per_page=100`);
  if ("error" in owners) out.skip("org_owners_limited", owners.error, "organization owners");
  else {
    const ids = owners.items.filter(isObj).map((m) => String(m.id ?? "?"));
    const over = ids.length > o.maxOwners;
    out.add("org_owners_limited", over ? "fail" : "pass",
      `${ids.length} organization owner(s)${over ? `; user ids${firstIds(ids)}` : ""}; at most ${o.maxOwners} allowed (--github-max-owners)`);
  }

  const oc = await list(api, `/orgs/${org}/outside_collaborators?per_page=100`);
  if ("error" in oc) out.skip("outside_collaborators", oc.error, "outside collaborators");
  else {
    const ids = oc.items.filter(isObj).map((m) => String(m.id ?? "?"));
    const over = ids.length > o.maxOutsideCollaborators;
    out.add("outside_collaborators", over ? "fail" : "pass",
      `${ids.length} outside collaborator(s)${over ? `; user ids${firstIds(ids)}` : ""}; at most ${o.maxOutsideCollaborators} allowed (--github-max-outside-collaborators)`);
  }

  const al = await api.get(`/orgs/${org}/audit-log?per_page=1`);
  if (!ok(al) || !Array.isArray(al.body)) out.skip("audit_log_available", al, "organization audit log (GitHub Enterprise Cloud only)");
  else {
    const e = al.body[0];
    out.add("audit_log_available", e ? "pass" : "fail",
      e ? `organization audit log readable; latest event at ${eventTime(e)}` : "organization audit log readable but empty");
  }
}

/** Base repository permission and who may make a repository public, from the same GET /orgs/{org}. */
function orgAccessChecks(g: HttpResponse, out: Emitter<C>): void {
  const b = ok(g) && isObj(g.body) ? g.body : undefined;
  const hidden = (field: string) => (b ? `${field} is not shown; GitHub shows the full organization to its owners only` : `organization not readable: ${why(g)}`);

  const base = b ? str(b.default_repository_permission) : undefined;
  if (!base || !["read", "write", "admin", "none"].includes(base)) out.add("org_base_permission_read", "skipped", hidden("default_repository_permission"));
  else out.add("org_base_permission_read", base === "read" || base === "none" ? "pass" : "fail",
    `default_repository_permission is ${JSON.stringify(base)}; "read" or "none" required, so a member gets more only by a grant on the repository`);

  const create = b?.members_can_create_repositories, pub = b?.members_can_create_public_repositories, vis = b?.members_can_change_repo_visibility;
  if (typeof vis !== "boolean" || (typeof pub !== "boolean" && create !== false)) out.add("org_public_repos_restricted", "skipped", hidden("members_can_create_public_repositories or members_can_change_repo_visibility"));
  else {
    const canCreate = create !== false && pub === true;
    out.add("org_public_repos_restricted", !canCreate && !vis ? "pass" : "fail",
      `members_can_create_repositories ${JSON.stringify(create ?? null)}, members_can_create_public_repositories ${JSON.stringify(pub ?? null)}, members_can_change_repo_visibility ${vis}; members may neither create a public repository nor change a repository's visibility (owners always can)`);
  }
}

const eventTime = (e: unknown) => {
  const t = isObj(e) ? Number(e["@timestamp"] ?? e.created_at) : NaN;
  return Number.isFinite(t) ? new Date(t).toISOString() : "?";
};

/** Branch protection seen through classic protection and rulesets together. */
interface Protection { classic?: Obj | null; rules?: Obj[] }

function judge(p: Protection, test: (classic: Obj | null | undefined, rules: Obj[] | undefined) => { classic?: boolean; rules?: boolean }): Outcome {
  const t = test(p.classic, p.rules);
  if (t.classic === true || t.rules === true) return "pass";
  // Fail only when both views were readable and neither shows the setting.
  return p.classic !== undefined && p.rules !== undefined ? "fail" : "skipped";
}

const ruleOf = (rules: Obj[] | undefined, type: string) => (rules ?? []).filter((r) => r.type === type);
const params = (r: Obj) => (isObj(r.parameters) ? r.parameters : {});
const enabledFlag = (v: unknown) => isObj(v) && v.enabled === true;

async function repoChecks(api: RestApi, full: string, o: GithubOptions, now: Date, out: Emitter<C>): Promise<void> {
  const res = `repo ${full}`;
  const [owner, name] = full.split("/");
  const rp = `/repos/${enc(owner)}/${enc(name)}`;
  const repo = await api.get(rp);
  if (!ok(repo) || !isObj(repo.body)) { for (const c of REPO_CHECKS) out.skip(c, repo, "repository", res); return; }
  const branch = str(repo.body.default_branch) ?? "main";
  const b = enc(branch);

  // Default branch: classic protection (Administration) and active ruleset rules (Metadata).
  const cl = await api.get(`${rp}/branches/${b}/protection`);
  const rl = await api.get(`${rp}/rules/branches/${b}?per_page=100`);
  const p: Protection = {
    classic: ok(cl) && isObj(cl.body) ? cl.body : cl.status === 404 ? null : undefined,
    rules: ok(rl) && Array.isArray(rl.body) ? rl.body.filter(isObj) : undefined,
  };
  const views = `classic protection ${p.classic ? "on" : p.classic === null ? "off" : `not readable (${why(cl)})`}, rulesets ${p.rules ? `${p.rules.length} active rule(s)` : `not readable (${why(rl)})`}`;
  const rpr = (c: Obj | null | undefined) => (c && isObj(c.required_pull_request_reviews) ? c.required_pull_request_reviews : undefined);
  const branchRes = `${res} branch ${branch}`;

  const reviews = (c: Obj | null | undefined, r: Obj[] | undefined) => ({
    classic: Number(rpr(c)?.required_approving_review_count ?? 0) >= 1,
    rules: ruleOf(r, "pull_request").some((x) => Number(params(x).required_approving_review_count ?? 0) >= 1),
  });
  out.add("default_branch_reviews", judge(p, reviews), `pull request with at least 1 approving review required on ${branch}: ${JSON.stringify(reviews(p.classic, p.rules))}; ${views}`, branchRes);

  const stale = (c: Obj | null | undefined, r: Obj[] | undefined) => ({
    classic: rpr(c)?.dismiss_stale_reviews === true,
    rules: ruleOf(r, "pull_request").some((x) => params(x).dismiss_stale_reviews_on_push === true),
  });
  out.add("default_branch_dismiss_stale", judge(p, stale), `stale approvals dismissed on push: ${JSON.stringify(stale(p.classic, p.rules))}; ${views}`, branchRes);

  const checks = (c: Obj | null | undefined, r: Obj[] | undefined) => ({
    classic: !!c && isObj(c.required_status_checks) && (arr(c.required_status_checks.contexts).length + arr(c.required_status_checks.checks).length) > 0,
    rules: ruleOf(r, "required_status_checks").some((x) => arr(params(x).required_status_checks).length > 0),
  });
  out.add("default_branch_status_checks", judge(p, checks), `at least one required status check: ${JSON.stringify(checks(p.classic, p.rules))}; ${views}`, branchRes);

  const force = (c: Obj | null | undefined, r: Obj[] | undefined) => ({
    classic: !!c && isObj(c.allow_force_pushes) && c.allow_force_pushes.enabled === false,
    rules: ruleOf(r, "non_fast_forward").length > 0,
  });
  out.add("default_branch_no_force_push", judge(p, force), `force pushes blocked: ${JSON.stringify(force(p.classic, p.rules))}; ${views}`, branchRes);

  const signed = (c: Obj | null | undefined, r: Obj[] | undefined) => ({
    classic: !!c && enabledFlag(c.required_signatures),
    rules: ruleOf(r, "required_signatures").length > 0,
  });
  out.add("default_branch_signed_commits", judge(p, signed), `signed commits required: ${JSON.stringify(signed(p.classic, p.rules))}; ${views}`, branchRes);

  // CODEOWNERS in one of the three places GitHub looks.
  let found: string | undefined, refused: HttpResponse | undefined;
  for (const path of CODEOWNERS_PATHS) {
    const r = await api.get(`${rp}/contents/${path.split("/").map(enc).join("/")}`);
    if (ok(r)) { found = path; break; }
    if (r.status !== 404) refused = r;
  }
  if (found) out.add("codeowners", "pass", `CODEOWNERS present at ${found}`, res);
  else if (refused) out.skip("codeowners", refused, "repository contents", res);
  else out.add("codeowners", "fail", `no CODEOWNERS at ${CODEOWNERS_PATHS.join(", ")}`, res);

  // Secret scanning and push protection (security_and_analysis shows to repository admins).
  const sa = isObj(repo.body.security_and_analysis) ? repo.body.security_and_analysis : undefined;
  for (const [check, key] of [["secret_scanning", "secret_scanning"], ["push_protection", "secret_scanning_push_protection"]] as const) {
    const st = sa && isObj(sa[key]) ? str(sa[key].status) : undefined;
    if (!st) out.add(check, "skipped", `security_and_analysis.${key} is not shown; GitHub shows it to repository admins`, res);
    else out.add(check, st === "enabled" ? "pass" : "fail", `security_and_analysis.${key}.status is ${JSON.stringify(st)}; "enabled" required`, res);
  }

  // Dependabot.
  const va = await api.get(`${rp}/vulnerability-alerts`);
  if (va.status === 204) out.add("dependabot_alerts_enabled", "pass", "Dependabot alerts are enabled (vulnerability-alerts answered 204)", res);
  else if (va.status === 404) out.add("dependabot_alerts_enabled", "fail", "Dependabot alerts are disabled (vulnerability-alerts answered 404)", res);
  else out.skip("dependabot_alerts_enabled", va, "Dependabot alerts setting", res);

  const da = await list(api, `${rp}/dependabot/alerts?state=open&severity=critical,high&per_page=100`, 20);
  if ("error" in da) out.skip("dependabot_aged_critical_high", da.error, "Dependabot alerts", res);
  else {
    const cutoff = now.getTime() - o.alertDays * DAY_MS;
    const all = da.items.filter(isObj);
    const aged = all.filter((a) => Date.parse(String(a.created_at)) < cutoff).map((a) => `#${String(a.number ?? "?")}`);
    out.add("dependabot_aged_critical_high", aged.length ? "fail" : "pass",
      `${all.length} open critical or high Dependabot alert(s), ${aged.length} open longer than ${o.alertDays} days${firstIds(aged)}; none allowed (--github-alert-days)`, res);
  }

  // Code scanning: at least one analysis.
  const cs = await api.get(`${rp}/code-scanning/analyses?per_page=1`);
  if (ok(cs) && Array.isArray(cs.body)) out.add("code_scanning_enabled", cs.body.length ? "pass" : "fail",
    cs.body.length ? `code scanning analyses present; latest by ${String(isObj(cs.body[0]) && isObj(cs.body[0].tool) ? cs.body[0].tool.name : "?")} at ${String(isObj(cs.body[0]) ? cs.body[0].created_at : "?")}` : "code scanning returned no analysis", res);
  else if (cs.status === 404) out.add("code_scanning_enabled", "fail", `no code scanning analysis: ${why(cs)}`, res);
  else out.skip("code_scanning_enabled", cs, "code scanning analyses", res);
}

export async function githubChecks(api: RestApi, o: GithubOptions, now: Date, warn: (s: string) => void = () => {}): Promise<Result[]> {
  const out = new Emitter<C>("github", `github org ${o.org}`);
  await orgChecks(api, o, out);
  let repos = o.repos.map((r) => (r.includes("/") ? r : `${o.org}/${r}`));
  if (!repos.length) {
    const r = await list(api, `/orgs/${enc(o.org)}/repos?type=all&per_page=100`, Math.ceil(o.maxRepos / 100) + 1);
    if ("error" in r) {
      for (const c of REPO_CHECKS) out.skip(c, r.error, "the organization's repositories", `repo ${o.org}/(list)`);
      return out.results;
    }
    const live = r.items.filter(isObj).filter((x) => x.archived !== true && x.disabled !== true).map((x) => String(x.full_name));
    if (live.length > o.maxRepos) warn(`github: ${live.length} repositories; checking the first ${o.maxRepos} (--github-max-repos, or name them with --github-repo)`);
    repos = live.slice(0, o.maxRepos);
    if (!repos.length) for (const c of REPO_CHECKS) out.add(c, "skipped", "the organization has no active repository the token can see", `repo ${o.org}/(none)`);
  }
  for (const full of repos) await repoChecks(api, full, o, now, out);
  return out.results;
}

const listOpt = (v: unknown): string[] => (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => String(s).split(",")).map((s) => s.trim()).filter(Boolean);

export const github: Source = {
  name: "github",
  options: {
    "github-org": { type: "string", help: "GitHub organization to check (required for this source)" },
    "github-repo": { type: "string", multiple: true, help: "repository name or owner/name; default: every active repository of the organization" },
    "github-max-repos": { type: "string", help: `repositories checked when none is named (default ${DEFAULTS.maxRepos})` },
    "github-max-owners": { type: "string", help: `organization owners allowed (default ${DEFAULTS.maxOwners})` },
    "github-max-outside-collaborators": { type: "string", help: `outside collaborators allowed (default ${DEFAULTS.maxOutsideCollaborators})` },
    "github-alert-days": { type: "string", help: `days an open critical or high Dependabot alert may stay open (default ${DEFAULTS.alertDays})` },
  },
  emits: [...ORG_CHECKS, ...REPO_CHECKS].map((c) => `github.${c}`),
  describe(opts) {
    const org = typeof opts["github-org"] === "string" ? opts["github-org"] : "(no --github-org)";
    const r = listOpt(opts["github-repo"]);
    return `organization ${org} / ${r.length ? `repos ${r.join(",")}` : "every active repository"}`;
  },
  async run(ctx: SourceContext) {
    const org = typeof ctx.opts["github-org"] === "string" ? ctx.opts["github-org"] : "";
    const given = ctx.clients.github as RestApi | null | undefined;
    const built = given !== undefined ? given : githubFromEnv(ctx.env);
    if (!org || !built || typeof built === "string") {
      const out = new Emitter<C>("github", `github org ${org || "(none)"}`);
      const reason = !org ? "--github-org is not given" : typeof built === "string" ? built : "no GitHub client";
      out.skipAll(ORG_CHECKS, reason);
      out.skipAll(REPO_CHECKS, reason, `repo ${org || "(none)"}/(none)`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: GithubOptions = {
      org, repos: listOpt(ctx.opts["github-repo"]),
      maxRepos: intOpt(ctx.opts["github-max-repos"], DEFAULTS.maxRepos),
      maxOwners: intOpt(ctx.opts["github-max-owners"], DEFAULTS.maxOwners),
      maxOutsideCollaborators: intOpt(ctx.opts["github-max-outside-collaborators"], DEFAULTS.maxOutsideCollaborators),
      alertDays: intOpt(ctx.opts["github-alert-days"], DEFAULTS.alertDays),
    };
    return redact(await githubChecks(api, o, ctx.now, ctx.warn), [ctx.env[GITHUB_TOKEN_ENV]]);
  },
};
