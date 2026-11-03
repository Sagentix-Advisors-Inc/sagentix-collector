// Vercel: a team (or a personal account) and its projects over the REST API (GET only), with an access token
// in VERCEL_TOKEN. Vercel has no read-only token: a token carries a scope (Full Account, a team with All
// Projects, or one project) and acts with its creator's role ("How do I use a Vercel API Access Token?",
// vercel.com/kb/guide/how-do-i-use-a-vercel-api-access-token, last updated 2026-10-01, read 2026-11-02). Use a
// team-scoped token with a short expiration, created by a member with the least role that can read the team's
// settings; the collector sends GET requests only and never asks Vercel to decrypt a value.
//
// Endpoints, each checked on 2026-11-02 in Vercel's OpenAPI (openapi.vercel.sh, info.version 0.0.1, 12,070,294
// bytes, sha256 8e3342453cdf0a81…) and on its reference page under https://vercel.com/docs/rest-api (the page named
// below, each last updated 2026-11-02). A team is named with ?teamId=team_… or ?slug=… on every call.
//   GET /v2/teams/{teamId}                 teams/get-a-team: saml.enforced ("When `true`, interactions with the Team
//                                          **must** be done with an authentication token that has been authenticated
//                                          with the Team's SAML Single Sign-On provider"), saml.connection.
//   GET /v3/teams/{teamId}/members         teams/list-team-members: members[].role (OWNER, MEMBER, DEVELOPER, SECURITY,
//                                          BILLING, VIEWER, VIEWER_FOR_PLUS, CONTRIBUTOR), members[].uid; pages by
//                                          ?until=<pagination.next> while pagination.hasNext.
//   GET /v3/events?limit=1                 user/list-user-events: events[].createdAt, the team's activity log.
//   GET /v10/projects?limit=100            projects/retrieve-a-list-of-projects: projects[].id/name; ?from=<pagination.next>
//                                          ("Query only projects updated after the given timestamp or continuation token").
//   GET /v9/projects/{idOrName}            projects/find-a-project-by-id-or-name: ssoProtection.deploymentType and
//                                          passwordProtection.deploymentType (all, all_except_custom_domains, preview,
//                                          prod_deployment_urls_and_all_previews; null when off), gitForkProtection,
//                                          security.firewallEnabled.
//   GET /v10/projects/{idOrName}/env       projects/retrieve-the-environment-variables-of-a-project-by-id-or-name:
//                                          envs[].key and envs[].type (encrypted, plain, secret, sensitive, system).
//                                          Only key and type are read; `decrypt` is never sent, and no value leaves memory.
//
// What the settings mean, read 2026-11-02:
//   Deployment Protection (vercel.com/docs/deployment-protection, last updated 2026-09-15): every protection scope,
//     Standard Protection included, covers preview URLs; none set means anyone with a preview URL can open it.
//   Git Fork Protection (vercel.com/docs/git/vercel-for-github, last updated 2026-09-17): "If you receive a pull request
//     from a fork of your repository, Vercel will require authorization from you or a team member to deploy".
//   Vercel WAF (vercel.com/docs/vercel-firewall/vercel-waf, last updated 2026-07-29): "available on all plans".
//   SAML SSO (vercel.com/docs/saml, last updated 2026-08-28): "available on Enterprise and Pro plans". Two-factor
//     enforcement for a team exists (vercel.com/docs/two-factor-enforcement, last updated 2026-08-28) but the team
//     object in the OpenAPI has no field for it, so a team without SAML gets team_saml_enforced skipped, never failed.
//   The team "Enforce Sensitive Environment Variables" policy is deprecated (last updated 2026-08-28,
//     https://vercel.com/docs/environment-variables/sensitive-environment-variables), so no check reads it.
//
// Personal data: counts and Vercel user ids only, never an email.

import type { Result, Source, SourceContext } from "../types.ts";
import {
  Emitter, enc, fetchRest, firstIds, getAll, intOpt, isObj, ok, realSleep, redact, str, withRetry,
  type HttpResponse, type RestApi, type Sleep,
} from "./readonly_http.ts";

export const VERCEL_BASE = "https://api.vercel.com";
export const VERCEL_TOKEN_ENV = "VERCEL_TOKEN";
export const DEFAULTS = { maxOwners: 3, maxProjects: 50 };

export const TEAM_CHECKS = ["team_saml_enforced", "team_owners_limited", "activity_log_available"] as const;
export const PROJECT_CHECKS = ["deployment_protection", "git_fork_protection", "no_plain_secret_envs", "firewall_enabled"] as const;
type C = (typeof TEAM_CHECKS)[number] | (typeof PROJECT_CHECKS)[number];

/** Names that say the value is a credential. A plain variable is shown to anyone who can open the project's settings. */
export const SECRET_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API_?KEY|ACCESS_?KEY|SIGNING_?KEY|DATABASE_URL|_DSN$|WEBHOOK)/i;

export function vercelFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const token = env[VERCEL_TOKEN_ENV];
  if (!token) return `${VERCEL_TOKEN_ENV} is not set`;
  return fetchRest({ base: VERCEL_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${token}` }) });
}

export interface VercelOptions { team?: string; projects: string[]; maxOwners: number; maxProjects: number }

/** The query naming the team: teamId for an id (team_…), slug for anything else; nothing for a personal account. */
export const teamQuery = (team: string | undefined) => (!team ? "" : /^team_/.test(team) ? `teamId=${enc(team)}` : `slug=${enc(team)}`);
const withTeam = (path: string, tq: string) => (tq ? `${path}${path.includes("?") ? "&" : "?"}${tq}` : path);

async function teamChecks(api: RestApi, team: string, tq: string, o: VercelOptions, out: Emitter<C>): Promise<void> {
  const t = await api.get(withTeam(`/v2/teams/${enc(team)}`, tq));
  if (!ok(t) || !isObj(t.body)) out.skip("team_saml_enforced", t, "team");
  else {
    const saml = isObj(t.body.saml) ? t.body.saml : undefined;
    const enforced = saml?.enforced;
    const connected = !!saml && isObj(saml.connection);
    if (enforced === true) out.add("team_saml_enforced", "pass", "saml.enforced is true; every sign-in to the team goes through its SAML identity provider");
    else if (connected) out.add("team_saml_enforced", "fail", "a SAML connection is configured but saml.enforced is not true; members may still sign in without it");
    else out.add("team_saml_enforced", "skipped", "SAML SSO is not configured (available on Pro and Enterprise); Vercel's REST API does not show the team's two-factor enforcement, so sign-in strength is not judged here");
  }

  const members = await getAll(api, withTeam(`/v3/teams/${enc(team)}/members?limit=100`, tq),
    (b) => (isObj(b) && Array.isArray(b.members) ? b.members : undefined),
    (r) => {
      const p = isObj(r.body) && isObj(r.body.pagination) ? r.body.pagination : undefined;
      const next = p && p.hasNext === true && p.next !== undefined && p.next !== null ? String(p.next) : undefined;
      return next ? withTeam(`/v3/teams/${enc(team)}/members?limit=100&until=${enc(next)}`, tq) : undefined;
    }, 20);
  if ("error" in members) out.skip("team_owners_limited", members.error, "team members");
  else {
    const owners = members.items.filter(isObj).filter((m) => m.role === "OWNER").map((m) => String(m.uid ?? "?"));
    const over = owners.length > o.maxOwners;
    out.add("team_owners_limited", over ? "fail" : "pass",
      `${owners.length} owner(s) among ${members.items.length} member(s)${over ? `; user ids${firstIds(owners)}` : ""}; at most ${o.maxOwners} allowed (--vercel-max-owners)${members.truncated ? "; the member list was cut at 20 pages" : ""}`);
  }

  const ev = await api.get(withTeam("/v3/events?limit=1", tq));
  if (!ok(ev) || !isObj(ev.body) || !Array.isArray(ev.body.events)) out.skip("activity_log_available", ev, "team activity log");
  else {
    const e = ev.body.events[0];
    const at = isObj(e) && Number.isFinite(Number(e.createdAt)) ? new Date(Number(e.createdAt)).toISOString() : undefined;
    out.add("activity_log_available", e ? "pass" : "fail", e ? `team activity log readable; latest event at ${at ?? "?"}` : "team activity log readable but empty");
  }
}

const PROTECTED = new Set(["all", "all_except_custom_domains", "preview", "prod_deployment_urls_and_all_previews"]);
const scopeOf = (v: unknown) => (isObj(v) ? str(v.deploymentType) : undefined);

async function projectChecks(api: RestApi, id: string, tq: string, out: Emitter<C>): Promise<void> {
  const p = await api.get(withTeam(`/v9/projects/${enc(id)}`, tq));
  const res = `vercel project ${id}`;
  if (!ok(p) || !isObj(p.body)) { for (const c of PROJECT_CHECKS) out.skip(c, p, "project", res); return; }
  const b = p.body;
  const name = str(b.name) ?? id;
  const r = `vercel project ${name}`;

  const sso = scopeOf(b.ssoProtection), pw = scopeOf(b.passwordProtection);
  const on = [sso && `Vercel Authentication (${sso})`, pw && `Password Protection (${pw})`].filter(Boolean);
  const covers = [sso, pw].some((s) => !!s && PROTECTED.has(s));
  out.add("deployment_protection", covers ? "pass" : "fail",
    `${on.length ? on.join(", ") : "no Deployment Protection"}; a protection scope that covers preview deployments required`, r);

  const fork = b.gitForkProtection;
  if (typeof fork !== "boolean") out.add("git_fork_protection", "skipped", "gitForkProtection is not shown for this project (no Git repository connected?)", r);
  else out.add("git_fork_protection", fork ? "pass" : "fail", `gitForkProtection is ${fork}; true required, so a pull request from a fork needs a team member's authorization before it deploys`, r);

  const fw = isObj(b.security) ? b.security.firewallEnabled : undefined;
  if (typeof fw !== "boolean") out.add("firewall_enabled", "skipped", "security.firewallEnabled is not shown for this project", r);
  else out.add("firewall_enabled", fw ? "pass" : "fail", `security.firewallEnabled is ${fw}; true required`, r);

  const env = await api.get(withTeam(`/v10/projects/${enc(id)}/env`, tq));
  if (!ok(env) || !isObj(env.body) || !Array.isArray(env.body.envs)) { out.skip("no_plain_secret_envs", env, "environment variables", r); return; }
  const vars = env.body.envs.filter(isObj);
  const plain = vars.filter((v) => v.type === "plain" && SECRET_NAME.test(String(v.key ?? ""))).map((v) => String(v.key));
  out.add("no_plain_secret_envs", plain.length ? "fail" : "pass",
    `${vars.length} environment variable(s), ${vars.filter((v) => v.type === "plain").length} of type plain, ${plain.length} of them named like a credential${firstIds(plain)}; a credential stored as encrypted, sensitive or secret required (names only were read)`, r);
}

export async function vercelChecks(api: RestApi, o: VercelOptions, warn: (s: string) => void = () => {}): Promise<Result[]> {
  const tq = teamQuery(o.team);
  const out = new Emitter<C>("vercel", o.team ? `vercel team ${o.team}` : "vercel personal account");
  if (o.team) await teamChecks(api, o.team, tq, o, out);
  else out.skipAll(TEAM_CHECKS, "no --vercel-team given; a personal account has no team settings");

  let ids = o.projects;
  if (!ids.length) {
    const l = await getAll(api, withTeam("/v10/projects?limit=100", tq),
      (b) => (isObj(b) && Array.isArray(b.projects) ? b.projects : Array.isArray(b) ? b : undefined),
      (r) => {
        const p = isObj(r.body) && isObj(r.body.pagination) ? r.body.pagination : undefined;
        const next = p && p.next !== undefined && p.next !== null ? String(p.next) : undefined;
        return next ? withTeam(`/v10/projects?limit=100&from=${enc(next)}`, tq) : undefined;
      }, Math.ceil(o.maxProjects / 100) + 1);
    if ("error" in l) {
      for (const c of PROJECT_CHECKS) out.skip(c, l.error as HttpResponse, "the project list", "vercel project (list)");
      return out.results;
    }
    const all = l.items.filter(isObj).map((p) => String(p.id ?? p.name ?? "?"));
    if (all.length > o.maxProjects) warn(`vercel: ${all.length} projects; checking the first ${o.maxProjects} (--vercel-max-projects, or name them with --vercel-project)`);
    ids = all.slice(0, o.maxProjects);
    if (!ids.length) for (const c of PROJECT_CHECKS) out.add(c, "skipped", "no project the token can see", "vercel project (none)");
  }
  for (const id of ids) await projectChecks(api, id, tq, out);
  return out.results;
}

const listOpt = (v: unknown): string[] => (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => String(s).split(",")).map((s) => s.trim()).filter(Boolean);

export const vercel: Source = {
  name: "vercel",
  options: {
    "vercel-team": { type: "string", help: "Vercel team id (team_…) or slug; omit for a personal account (team checks are then skipped)" },
    "vercel-project": { type: "string", multiple: true, help: "project id or name; default: every project the token can see" },
    "vercel-max-projects": { type: "string", help: `projects checked when none is named (default ${DEFAULTS.maxProjects})` },
    "vercel-max-owners": { type: "string", help: `team owners allowed (default ${DEFAULTS.maxOwners})` },
  },
  emits: [...TEAM_CHECKS, ...PROJECT_CHECKS].map((c) => `vercel.${c}`),
  describe(opts) {
    const t = typeof opts["vercel-team"] === "string" ? `team ${opts["vercel-team"]}` : "personal account";
    const p = listOpt(opts["vercel-project"]);
    return `${t} / ${p.length ? `projects ${p.join(",")}` : "every project"}`;
  },
  async run(ctx: SourceContext) {
    const team = typeof ctx.opts["vercel-team"] === "string" && ctx.opts["vercel-team"].trim() ? ctx.opts["vercel-team"].trim() : undefined;
    const given = ctx.clients.vercel as RestApi | null | undefined;
    const built = given !== undefined ? given : vercelFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("vercel", team ? `vercel team ${team}` : "vercel personal account");
      const reason = typeof built === "string" ? built : "no Vercel client";
      out.skipAll(TEAM_CHECKS, reason);
      out.skipAll(PROJECT_CHECKS, reason, "vercel project (none)");
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o: VercelOptions = {
      team, projects: listOpt(ctx.opts["vercel-project"]),
      maxOwners: intOpt(ctx.opts["vercel-max-owners"], DEFAULTS.maxOwners),
      maxProjects: intOpt(ctx.opts["vercel-max-projects"], DEFAULTS.maxProjects),
    };
    return redact(await vercelChecks(api, o, ctx.warn), [ctx.env[VERCEL_TOKEN_ENV]]);
  },
};
