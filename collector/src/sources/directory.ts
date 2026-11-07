// The identity provider's side of the HR leaver check (hris.ts): given the work email of a person who left, is their
// account still active, and when was it disabled or deleted? It reuses the identity sources' own clients and the
// credentials the customer already gave them (okta.ts, entra.ts, google_workspace.ts, jumpcloud.ts), so it adds no
// permission and no check of its own: the identity sources keep their checks, and this answers one question per person.
// GET only. A person is looked up by email; the email goes to the customer's own identity provider and never into a result.
//
// Endpoints, fields and permissions (all read 2026-11-07):
//   Okta     GET /api/v1/users?search=profile.email eq "<email>"                         okta.users.read
//            "Returned users include those with the DEPROVISIONED status" (search); status is one of ACTIVE,
//            DEPROVISIONED, LOCKED_OUT, PASSWORD_EXPIRED, PROVISIONED, RECOVERY, STAGED, SUSPENDED; statusChanged is
//            "The timestamp when the status of the user last changed".
//            https://developer.okta.com/docs/api/openapi/okta-management/management/tags/user/other/listusers
//   Entra    GET /users?$filter=mail eq '<email>' or userPrincipalName eq '<email>'&$select=id,accountEnabled  User.Read.All
//            No user property records when accountEnabled became false, so the time comes from
//            GET /auditLogs/directoryAudits?$filter=activityDisplayName eq 'Disable account' and targetResources/any(t:t/id eq '<id>')
//            (AuditLog.Read.All; targetResources "Supports $filter (eq) for id and displayName"; kept 7 days on Entra ID
//            Free, 30 on P1 or P2). A user not found is looked for among deleted users,
//            GET /directory/deletedItems/microsoft.graph.user?$filter=mail eq '<email>'&$select=id,deletedDateTime (User.Read.All,
//            kept 30 days after deletion).
//            https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
//            https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0
//            https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0
//            https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention
//   Google   GET /admin/directory/v1/users/<email>                         admin.directory.user.readonly
//            suspended ("Indicates if user is suspended"), suspensionTime ("User's account suspension time"), archived.
//            A deleted user is not returned; its time comes from the Reports API, GET /admin/reports/v1/activity/users/all/
//            applications/admin?eventName=DELETE_USER&filters=USER_EMAIL==<email> (admin.reports.audit.readonly; id.time;
//            admin log events kept 6 months).
//            https://developers.google.com/workspace/admin/directory/reference/rest/v1/users
//            https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
//            https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-user-settings
//   JumpCloud GET /api/systemusers?filter=email:$eq:<email>&fields=_id suspended state      users.readonly
//            suspended, state (STAGED, ACTIVATED, SUSPENDED). No field dates a suspension, and Directory Insights, which
//            does, is POST only (https://docs.jumpcloud.com/api/insights/directory/1.0/index.html), so a JumpCloud answer
//            is the state alone. https://docs.jumpcloud.com/api/1.0/index.html

import type { SourceContext } from "../types.ts";
import { entraFromEnv } from "./entra.ts";
import { googleFromEnv } from "./google_workspace.ts";
import { jumpcloudFromEnv } from "./jumpcloud.ts";
import { oktaFromEnv } from "./okta.ts";
import { arr, enc, isObj, ok, realSleep, str, why, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep } from "./readonly_http.ts";

export const IDPS = ["okta", "entra", "google_workspace", "jumpcloud"] as const;
export type Idp = (typeof IDPS)[number];

/** What the identity provider says about one email. `at` is when the account was disabled or deleted, when known. */
export type Account =
  | { state: "active"; id: string }
  | { state: "disabled" | "deleted"; id?: string; at?: string; how: string }
  | { state: "absent" }
  | { state: "error"; why: string };

export interface Directory { idp: Idp; lookup(email: string): Promise<Account> }

const q = (s: string) => s.replace(/'/g, "''");          // OData string literal
const dq = (s: string) => s.replace(/["\\]/g, "");       // Okta search literal: an email has neither
const first = (b: unknown, key = "value"): Obj | undefined => {
  const xs = Array.isArray(b) ? b : isObj(b) ? arr(b[key]) : [];
  return xs.find(isObj);
};
const err = (r: HttpResponse, what: string): Account => ({ state: "error", why: `${what}: ${why(r)}` });

export function oktaDirectory(api: RestApi): Directory {
  return {
    idp: "okta",
    async lookup(email) {
      const r = await api.get(`/api/v1/users?search=${enc(`profile.email eq "${dq(email)}"`)}&limit=2`);
      if (!ok(r) || !Array.isArray(r.body)) return err(r, "Okta user search");
      const u = first(r.body);
      if (!u) return { state: "absent" };
      const id = String(u.id ?? "?"), status = str(u.status);
      if (status === "DEPROVISIONED" || status === "SUSPENDED") return { state: "disabled", id, at: str(u.statusChanged), how: `Okta status ${status}` };
      return { state: "active", id };
    },
  };
}

export function entraDirectory(api: RestApi): Directory {
  return {
    idp: "entra",
    async lookup(email) {
      const e = q(email);
      const r = await api.get(`/users?$filter=${enc(`mail eq '${e}' or userPrincipalName eq '${e}'`)}&$select=id,accountEnabled`);
      if (!ok(r)) return err(r, "Entra user lookup");
      const u = first(r.body);
      if (u) {
        const id = String(u.id ?? "?");
        if (u.accountEnabled !== false) return { state: "active", id };
        const a = await api.get(`/auditLogs/directoryAudits?$filter=${enc(`activityDisplayName eq 'Disable account' and targetResources/any(t:t/id eq '${q(id)}')`)}&$top=1`);
        const ev = ok(a) ? first(a.body) : undefined;
        return { state: "disabled", id, at: ev ? str(ev.activityDateTime) : undefined, how: "Entra accountEnabled false" };
      }
      const d = await api.get(`/directory/deletedItems/microsoft.graph.user?$filter=${enc(`mail eq '${e}'`)}&$select=id,deletedDateTime`);
      const du = ok(d) ? first(d.body) : undefined;
      if (du) return { state: "deleted", id: String(du.id ?? "?"), at: str(du.deletedDateTime), how: "Entra deleted user" };
      return { state: "absent" };
    },
  };
}

export function googleDirectory(api: RestApi): Directory {
  return {
    idp: "google_workspace",
    async lookup(email) {
      const r = await api.get(`/admin/directory/v1/users/${enc(email)}`);
      if (ok(r) && isObj(r.body)) {
        const id = String(r.body.id ?? "?");
        if (r.body.suspended === true) return { state: "disabled", id, at: str(r.body.suspensionTime), how: "Google suspended" };
        if (r.body.archived === true) return { state: "disabled", id, how: "Google archived" };
        return { state: "active", id };
      }
      if (r.status !== 404) return err(r, "Google user lookup");
      const a = await api.get(`/admin/reports/v1/activity/users/all/applications/admin?eventName=DELETE_USER&filters=${enc(`USER_EMAIL==${email}`)}&maxResults=1`);
      const ev = ok(a) ? first(a.body, "items") : undefined;
      if (ev) return { state: "deleted", at: isObj(ev.id) ? str(ev.id.time) : undefined, how: "Google DELETE_USER event" };
      return { state: "absent" };
    },
  };
}

export function jumpcloudDirectory(api: RestApi): Directory {
  return {
    idp: "jumpcloud",
    async lookup(email) {
      const r = await api.get(`/systemusers?filter=${enc(`email:$eq:${email}`)}&fields=${enc("_id suspended state")}&limit=2`);
      if (!ok(r) || !isObj(r.body)) return err(r, "JumpCloud user lookup");
      const u = first(r.body, "results");
      if (!u) return { state: "absent" };
      const id = String(u._id ?? "?");
      if (u.suspended === true || u.state === "SUSPENDED") return { state: "disabled", id, how: "JumpCloud suspended (no time recorded)" };
      return { state: "active", id };
    },
  };
}

/** The directory for an identity provider, built from the client a test injected or that provider's own variables; else why not. */
export function directoryFor(idp: string, ctx: SourceContext): Directory | string {
  const sleep = (ctx.clients.sleep as Sleep | undefined) ?? realSleep;
  const pick = (key: string, build: () => RestApi | string): RestApi | string => {
    const given = ctx.clients[key] as RestApi | null | undefined;
    const b = given !== undefined ? given : build();
    if (!b) return `no ${idp} client`;
    return typeof b === "string" ? b : withRetry(b, sleep);
  };
  const o = ctx.opts;
  let api: RestApi | string;
  switch (idp) {
    case "okta": api = pick("okta", () => oktaFromEnv(ctx.env)); return typeof api === "string" ? api : oktaDirectory(api);
    case "entra": api = pick("entra", () => entraFromEnv(ctx.env)); return typeof api === "string" ? api : entraDirectory(api);
    case "google_workspace": api = pick("google", () => googleFromEnv(ctx.env)); return typeof api === "string" ? api : googleDirectory(api);
    case "jumpcloud":
      api = pick("jumpcloud", () => jumpcloudFromEnv(ctx.env, { region: typeof o["jumpcloud-region"] === "string" ? o["jumpcloud-region"] : undefined,
        orgId: typeof o["jumpcloud-org-id"] === "string" ? o["jumpcloud-org-id"] : undefined }));
      return typeof api === "string" ? api : jumpcloudDirectory(api);
    default: return `unknown identity provider "${idp}"; one of ${IDPS.join(", ")}`;
  }
}

/** The secrets the identity providers' clients read, for scrubbing results. */
export const IDP_SECRETS = (env: NodeJS.ProcessEnv) => [env.OKTA_API_TOKEN, env.OKTA_ACCESS_TOKEN, env.ENTRA_CLIENT_SECRET, env.JUMPCLOUD_API_KEY];
