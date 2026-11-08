// `collector doctor`: a smoke test a customer runs before the first real run (2026-11-07). For each configured source it
// checks the credentials are there and makes ONE cheap read per permission the source needs, then prints pass or fail
// with the fix: the exact scope, role or permission named in that source's own header (its provider-docs citations).
// It collects nothing and sends nothing: no check-in, no push, no run report. File-based sources check their files are
// readable; engines check their executable is on PATH without running it; the host sources check the platform.
//
// Every read below is one the source itself makes (same path, with a page size of 1 where the API takes one), so a
// pass here means the same call will be allowed during a run. GET only, except GCP's :getIamPolicy, a read the GCP
// source makes as a POST.

import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import type { OptionValue, SourceContext } from "./types.ts";
import { codeForStatus, setPermissionLookup, type Code } from "./diagnostics.ts";
import { templatePath } from "./report.ts";
import { isObj, realSleep, why, withRetry, type HttpResponse, type RestApi, type Sleep } from "./sources/readonly_http.ts";
import { oktaFromEnv, OKTA_ENV } from "./sources/okta.ts";
import { entraFromEnv, ENTRA_ENV } from "./sources/entra.ts";
import { jumpcloudFromEnv, JUMPCLOUD_ENV } from "./sources/jumpcloud.ts";
import { GOOGLE_ENV, googleFromEnv } from "./sources/google_workspace.ts";
import { OAUTH_ENV } from "./sources/google_oauth.ts";
import { githubFromEnv, GITHUB_TOKEN_ENV } from "./sources/github.ts";
import { vercelFromEnv, VERCEL_TOKEN_ENV } from "./sources/vercel.ts";
import { pagerdutyFromEnv, PAGERDUTY_ENV } from "./sources/pagerduty.ts";
import { stripeFromEnv, STRIPE_ENV } from "./sources/stripe.ts";
import { resendFromEnv, RESEND_ENV } from "./sources/resend.ts";
import { fleetFromEnv, FLEET_ENV } from "./sources/fleet.ts";
import { intuneFromEnv, INTUNE_ENV } from "./sources/intune.ts";
import { jamfFromEnv, JAMF_ENV, inventoryPath, VERSIONS as JAMF_VERSIONS } from "./sources/jamf.ts";
import { kandjiFromEnv, KANDJI_ENV } from "./sources/kandji.ts";
import { defenderFromEnv, DEFENDER_ENV } from "./sources/defender_endpoint.ts";
import { ws1FromEnv, WS1_ENV } from "./sources/workspace_one.ts";
import { configmgrFromEnv, CONFIGMGR_ENV } from "./sources/configmgr.ts";
import { googleDevicesFromEnv } from "./sources/google_endpoints.ts";
import { ivantiMdmFromEnv, IVANTI_MDM_ENV, metadataPath } from "./sources/ivanti_mdm.ts";
import { ninjaoneFromEnv, NINJAONE_ENV } from "./sources/ninjaone.ts";
import { endpointCentralFromEnv, EC_ENV, SCAN_PATH } from "./sources/endpoint_central.ts";
import { bamboohrFromEnv, BAMBOOHR_ENV, employeesPath } from "./sources/bamboohr.ts";
import { ripplingFromEnv, RIPPLING_ENV } from "./sources/rippling.ts";
import { fetchCloudflareApi, TOKEN_ENV as CF_TOKEN_ENV, type CloudflareApi } from "./sources/cloudflare/api.ts";
import { Aws, callerAccount, envCredentials, fetchAwsTransport, queryReq, awsWhy, type AwsTransport } from "./sources/aws/api.ts";
import { API as AZURE_API, ARM, armGet, fetchAzure, tokenFromEnv as azureToken, type AzureTransport } from "./sources/azure/api.ts";
import { Gcp, GCP_KEY_ENV, GCP_TOKEN_ENV, fetchGcpTransport, gcpKeyToken, type GcpTransport } from "./sources/gcp/api.ts";
import { fetchJira, JIRA_ENV, type JiraTransport } from "./sources/jira.ts";

export type Verdict = "pass" | "fail" | "skip";
/** One line of the doctor's answer. `fix` says what to change when it is not a pass; `code` is the run's diagnostic
 *  code for the same answer (src/diagnostics.ts), so the doctor and sos-app name a fault the same way. */
export interface Check { what: string; verdict: Verdict; detail: string; fix?: string; code?: Code }
export type Probe = (ctx: SourceContext) => Promise<Check[]>;

const one = (v: OptionValue): string | undefined => (typeof v === "string" ? v : Array.isArray(v) ? v[0] : undefined);
const many = (v: OptionValue): string[] => (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);
const sleepOf = (ctx: SourceContext) => (ctx.clients.sleep as Sleep | undefined) ?? realSleep;

/** The verdict on one answer to `call`: the fix names `permission` on a 403, `creds` on a 401. `label` names the
 *  permission shortly for the pass line. */
export function judge(label: string, call: string, r: { status: number; message: string }, creds: string, permission: string): Check {
  const what = call;
  if (r.status >= 200 && r.status < 300) return { what, verdict: "pass", detail: `HTTP ${r.status} (needs ${label})` };
  const detail = r.message, code = codeForStatus(r.status);
  if (r.status === 401) return { what, verdict: "fail", detail, code, fix: `the credential was refused: check ${creds} (expired, revoked, or for another tenant)` };
  if (r.status === 403) return { what, verdict: "fail", detail, code, fix: `grant ${permission}` };
  if (r.status === 404) return { what, verdict: "fail", detail, code, fix: `not found: check the organization, team, project or URL given (or the feature is not on this plan); needs ${permission}` };
  if (r.status === 429) return { what, verdict: "fail", detail, code, fix: "rate limited even after retries: run the doctor again in a few minutes" };
  if (r.status === 0) return { what, verdict: "fail", detail, code, fix: "no answer: check the network path from this runner (proxy, firewall, DNS) and the URL in the credentials" };
  return { what, verdict: "fail", detail, code, fix: `the provider answered HTTP ${r.status}; try again later, then check its status page` };
}

const credsCheck = (ok: boolean, creds: string, why?: string): Check =>
  ok ? { what: "credentials", verdict: "pass", detail: `${creds}: present` }
    : { what: "credentials", verdict: "fail", detail: why ?? `${creds}: not set`, fix: `set ${creds} (in the vault, the CI secrets or the environment)` };

/** Each REST probe's [path, permission] list, for a run's PERMISSION_MISSING hint (permissionFor below). */
const CALLS = new Map<Probe, (ctx: SourceContext) => [string, string][]>();

/** A REST source: the client the source builds (or the one injected), then one GET per [path, permission]. */
function rest(o: { key: string; creds: string; build: (ctx: SourceContext) => RestApi | string; calls: (ctx: SourceContext) => [string, string][] }): Probe {
  const probe: Probe = async (ctx) => {
    const given = ctx.clients[o.key] as RestApi | null | undefined;
    const built = given !== undefined ? (given ?? "no client") : o.build(ctx);
    if (typeof built === "string") return [credsCheck(false, o.creds, built)];
    const api = withRetry(built, sleepOf(ctx));
    const out: Check[] = [credsCheck(true, o.creds)];
    for (const [path, permission] of o.calls(ctx)) {
      let r: HttpResponse;
      try { r = await api.get(path); } catch (e) { r = { status: 0, headers: {}, body: { message: String(e) } }; }
      out.push(judge(permission, `GET ${path.split("?")[0]}`, { status: r.status, message: why(r) }, o.creds, permission));
      // A refused credential refuses every call: one line says it.
      if (r.status === 401) break;
    }
    return out;
  };
  CALLS.set(probe, o.calls);
  return probe;
}

/** Each named file is there and readable. `need` lists options of which one must be given. */
function files(need: string[], optional: string[] = []): Probe {
  return async (ctx) => {
    const out: Check[] = [];
    const given = need.filter((k) => many(ctx.opts[k]).length);
    if (!given.length) out.push({ what: "input", verdict: "fail", detail: `no --${need.join(" or --")} given`, fix: `give --${need[0]} <file> (in the config file or on the command line)` });
    for (const k of [...given, ...optional.filter((x) => many(ctx.opts[x]).length)]) {
      for (const p of many(ctx.opts[k])) {
        try {
          accessSync(p, constants.R_OK);
          const st = statSync(p);
          out.push({ what: `--${k}`, verdict: "pass", detail: `${p}: readable, ${st.isDirectory() ? "a folder" : `${st.size} bytes`}, modified ${st.mtime.toISOString().slice(0, 10)}` });
        } catch (e) {
          out.push({ what: `--${k}`, verdict: "fail", detail: `${p}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`, fix: "produce the file before the collector runs (the engine's step in the workflow), or fix the path" });
        }
      }
    }
    return out;
  };
}

/** Whether an executable is on PATH (or at the path given), found without running it. */
export function onPath(bin: string, env: NodeJS.ProcessEnv, platform = process.platform): string | undefined {
  const exts = platform === "win32" ? (env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  const candidates = isAbsolute(bin) || bin.includes("/") ? [bin] : (env.PATH ?? "").split(delimiter).filter(Boolean).map((d) => join(d, bin));
  for (const c of candidates) for (const x of exts) {
    try { accessSync(c + x, constants.X_OK); if (statSync(c + x).isFile()) return c + x; } catch { /* next */ }
  }
  return undefined;
}

const binCheck = (bin: string, env: NodeJS.ProcessEnv, install: string): Check => {
  const at = onPath(bin, env);
  return at ? { what: "executable", verdict: "pass", detail: `${bin}: ${at}` } : { what: "executable", verdict: "fail", detail: `${bin}: not on PATH`, fix: install };
};

const graphCreds = (pre: { tenant: string; client: string; secret: string; cert: string }) => `${pre.tenant}, ${pre.client} and ${pre.secret} or ${pre.cert} (or their ENTRA_* twins)`;
const ENTRA_CREDS = `${ENTRA_ENV.tenant}, ${ENTRA_ENV.client} and ${ENTRA_ENV.secret} or ${ENTRA_ENV.cert}`;
const GOOGLE_CREDS = `${GOOGLE_ENV.keyFile} and ${GOOGLE_ENV.admin} (service account with domain-wide delegation), or ${OAUTH_ENV.clientFile} after \`collector google-login\``;
const googleCustomer = (env: NodeJS.ProcessEnv) => env[GOOGLE_ENV.customer] || "my_customer";

export const PROBES: Record<string, Probe> = {
  // ── Identity and code ────────────────────────────────────────────────────────────────────────────
  okta: rest({ key: "okta", creds: `${OKTA_ENV.domain} with ${OKTA_ENV.token} (a Read-Only Administrator's token) or ${OKTA_ENV.access}`, build: (c) => oktaFromEnv(c.env),
    calls: () => [["/api/v1/policies?type=PASSWORD", "okta.policies.read"], ["/api/v1/authenticators", "okta.authenticators.read (Identity Engine)"],
      ["/api/v1/iam/assignees/users?limit=1", "okta.roles.read"], ["/api/v1/users?limit=1", "okta.users.read"], ["/api/v1/logs?limit=1", "okta.logs.read"]] }),
  entra: rest({ key: "entra", creds: ENTRA_CREDS, build: (c) => entraFromEnv(c.env),
    calls: () => [["/policies/authorizationPolicy", "the application permission Policy.Read.All"],
      ["/identity/conditionalAccess/policies?$top=1", "the application permission Policy.Read.All (Conditional Access needs Entra ID P1)"],
      ["/roleManagement/directory/roleAssignments?$top=1", "the application permission RoleManagement.Read.Directory"],
      ["/users?$top=1&$select=id", "the application permission User.Read.All"],
      ["/auditLogs/directoryAudits?$top=1", "the application permission AuditLog.Read.All"],
      ["/reports/authenticationMethods/userRegistrationDetails?$top=1", "the application permission AuditLog.Read.All (the report needs Entra ID P1 or P2)"],
      ["/subscribedSkus", "the application permission LicenseAssignment.Read.All"]] }),
  jumpcloud: rest({ key: "jumpcloud", creds: `${JUMPCLOUD_ENV.key} (an administrator with the Read Only role)`,
    build: (c) => jumpcloudFromEnv(c.env, { region: one(c.opts["jumpcloud-region"]), orgId: one(c.opts["jumpcloud-org-id"]) }),
    calls: () => [["/organizations?limit=1", "the API key scope organizations.readonly"], ["/systemusers?limit=1&skip=0", "the API key scope users.readonly"],
      ["/v2/authn/policies?limit=1&skip=0", "the API key scope authn.readonly"], ["/systems?limit=1&skip=0", "the API key scope systems.readonly"]] }),
  google_workspace: rest({ key: "google", creds: GOOGLE_CREDS, build: (c) => googleFromEnv(c.env),
    calls: (c) => [[`/admin/directory/v1/users?customer=${encodeURIComponent(googleCustomer(c.env))}&maxResults=1&projection=basic`, "the scope https://www.googleapis.com/auth/admin.directory.user.readonly in domain-wide delegation"],
      ["/admin/reports/v1/activity/users/all/applications/admin?maxResults=1", "the scope https://www.googleapis.com/auth/admin.reports.audit.readonly in domain-wide delegation"]] }),
  github: rest({ key: "github", creds: `${GITHUB_TOKEN_ENV} (a fine-grained token, read-only)`, build: (c) => githubFromEnv(c.env),
    calls: (c) => {
      const org = one(c.opts["github-org"]);
      if (!org) return [["/rate_limit", "no permission (the token is only checked; give --github-org to check the organization's)"]];
      const o = encodeURIComponent(org);
      return [[`/orgs/${o}`, "membership of the organization"], [`/orgs/${o}/members?role=admin&per_page=1`, "the fine-grained permission Organization: Members (read)"],
        [`/orgs/${o}/actions/permissions`, "the fine-grained permission Organization: Administration (read)"],
        [`/orgs/${o}/repos?type=all&per_page=1`, "the fine-grained permission Repository: Metadata (read), on all repositories"]];
    } }),
  vercel: rest({ key: "vercel", creds: VERCEL_TOKEN_ENV, build: (c) => vercelFromEnv(c.env),
    calls: (c) => {
      const team = one(c.opts["vercel-team"]);
      const tq = team ? `teamId=${encodeURIComponent(team)}` : "";
      return [...(team ? [[`/v2/teams/${encodeURIComponent(team)}`, "a token scoped to the team, from a member who can read its settings"] as [string, string]] : []),
        [`/v10/projects?limit=1${tq ? `&${tq}` : ""}`, "a token scoped to the team (or account) that owns the projects"]];
    } }),
  pagerduty: rest({ key: "pagerduty", creds: `${PAGERDUTY_ENV.token} (a read-only API key)`, build: (c) => pagerdutyFromEnv(c.env),
    calls: () => [["/services?limit=1", "services.read"], ["/incidents?limit=1", "incidents.read"], ["/escalation_policies?limit=1", "escalation_policies.read"],
      ["/incident_workflows?limit=1", "incident_workflows.read"]] }),
  stripe: rest({ key: "stripe", creds: `${STRIPE_ENV.token} (a restricted key, rk_...)`, build: (c) => stripeFromEnv(c.env),
    calls: () => [["/v1/webhook_endpoints?limit=1", "the restricted key permission Webhook Endpoints: Read"]] }),
  resend: rest({ key: "resend", creds: RESEND_ENV.token, build: (c) => resendFromEnv(c.env),
    calls: () => [["/domains?limit=1", "a key with full_access (Resend has no read-only key)"], ["/api-keys?limit=1", "a key with full_access (Resend has no read-only key)"]] }),
  // ── HR ───────────────────────────────────────────────────────────────────────────────────────────
  bamboohr: rest({ key: "bamboohr", creds: `${BAMBOOHR_ENV.key} and --bamboohr-company`, build: (c) => bamboohrFromEnv(c.env, one(c.opts["bamboohr-company"])),
    calls: () => [[employeesPath("active", ["status"]).replace(/page%5Blimit%5D=\d+/, "page%5Blimit%5D=1"), "an API key of a user allowed to see employees' status (BambooHR access level)"]] }),
  rippling: rest({ key: "rippling", creds: RIPPLING_ENV.token, build: (c) => ripplingFromEnv(c.env),
    calls: () => [["/workers/?limit=1", "the token scope to read workers (workers:read)"]] }),
  // ── Devices ──────────────────────────────────────────────────────────────────────────────────────
  fleet: rest({ key: "fleet", creds: `${FLEET_ENV.url} and ${FLEET_ENV.token} (an API-only user with the global Observer role)`, build: (c) => fleetFromEnv(c.env),
    calls: () => [["/hosts?page=0&per_page=1&order_key=id&order_direction=asc&populate_policies=true", "the global Observer role"]] }),
  intune: rest({ key: "intune", creds: graphCreds(INTUNE_ENV), build: (c) => intuneFromEnv(c.env),
    calls: () => [["/deviceManagement/managedDevices?$top=1&$select=id", "the application permission DeviceManagementManagedDevices.Read.All"],
      ["/deviceManagement/deviceCompliancePolicies?$top=1", "the application permission DeviceManagementConfiguration.Read.All"]] }),
  jamf: rest({ key: "jamf", creds: `${JAMF_ENV.url}, ${JAMF_ENV.client} and ${JAMF_ENV.secret} (an API client)`, build: (c) => jamfFromEnv(c.env),
    calls: () => [[inventoryPath(JAMF_VERSIONS[0], 0).replace(/page-size=\d+/, "page-size=1"), "the API role privilege Read Computers"],
      ["/v2/mdm/commands?page=0&page-size=1", "the API role privilege View MDM command information in Jamf Pro API"]] }),
  kandji: rest({ key: "kandji", creds: `${KANDJI_ENV.url} and ${KANDJI_ENV.token}`, build: (c) => kandjiFromEnv(c.env),
    calls: () => [["/v1/devices?platform=Mac&limit=1&offset=0", "the token permission List Devices"],
      ["/v1/prism/application_firewall?device_families=Mac&limit=1&cursor=", "the token permission Prism: Application firewall"]] }),
  defender_endpoint: rest({ key: "defender_endpoint", creds: graphCreds(DEFENDER_ENV), build: (c) => defenderFromEnv(c.env),
    calls: () => [["/api/machines?$top=1", "the WindowsDefenderATP application permission Machine.Read.All"],
      ["/api/vulnerabilities/machinesVulnerabilities?$top=1", "the WindowsDefenderATP application permission Vulnerability.Read.All"],
      ["/api/recommendations?$top=1", "the WindowsDefenderATP application permission SecurityRecommendation.Read.All"]] }),
  workspace_one: async (ctx) => {
    const given = ctx.clients.workspace_one as RestApi | { v3: RestApi } | null | undefined;
    const b = given !== undefined ? (given === null ? "no client" : "get" in given ? given : given.v3) : ((w) => (typeof w === "string" ? w : w.v3))(ws1FromEnv(ctx.env));
    return rest({ key: "\0", creds: `${WS1_ENV.url}, ${WS1_ENV.tokenUrl}, ${WS1_ENV.client} and ${WS1_ENV.secret} (an OAuth client)`, build: () => b,
      calls: () => [["/mdm/devices/search?page=0&page_size=1", "the role permission REST > Devices > REST API Devices Read"]] })(ctx);
  },
  configmgr: rest({ key: "configmgr", creds: `${CONFIGMGR_ENV.provider} (run on a domain-joined Windows host as a Read-only Analyst)`, build: (c) => configmgrFromEnv(c.env),
    calls: () => [["/SMS_CombinedDeviceResources?$top=1", "the Configuration Manager security role Read-only Analyst"]] }),
  google_endpoints: rest({ key: "google_endpoints", creds: `${GOOGLE_ENV.keyFile} and ${GOOGLE_ENV.admin} (service account with domain-wide delegation)`, build: (c) => googleDevicesFromEnv(c.env),
    calls: (c) => [[`/v1/devices?customer=${encodeURIComponent(`customers/${googleCustomer(c.env)}`)}&pageSize=1&view=USER_ASSIGNED_DEVICES`, "the scope https://www.googleapis.com/auth/cloud-identity.devices.readonly in domain-wide delegation"]] }),
  ivanti_mdm: rest({ key: "ivanti_mdm", creds: `${IVANTI_MDM_ENV.url}, ${IVANTI_MDM_ENV.user} and ${IVANTI_MDM_ENV.password} (an admin with the Device Read Only role)`, build: (c) => ivantiMdmFromEnv(c.env),
    calls: () => [[metadataPath, "the admin role Device Read Only (API access enabled for the user)"]] }),
  ninjaone: rest({ key: "ninjaone", creds: `${NINJAONE_ENV.url}, ${NINJAONE_ENV.client} and ${NINJAONE_ENV.secret} (an API Services client app)`, build: (c) => ninjaoneFromEnv(c.env),
    calls: () => [["/v2/devices?pageSize=1", "the client app scope Monitoring"], ["/v2/queries/operating-systems?pageSize=1", "the client app scope Monitoring"]] }),
  endpoint_central: rest({ key: "endpoint_central", creds: `${EC_ENV.url}, ${EC_ENV.client}, ${EC_ENV.secret} and ${EC_ENV.refresh} (a Zoho self client)`, build: (c) => endpointCentralFromEnv(c.env),
    calls: () => [[SCAN_PATH, "the scope DesktopCentralCloud.Inventory.READ and a role with Inventory read access"],
      ["/dcapi/patch/reports/systemHealth?page=1&pageLimit=1", "the scope DesktopCentralCloud.PatchMgmt.READ and a role with Patch Management read access"]] }),
  // ── Clouds and ticketing ─────────────────────────────────────────────────────────────────────────
  cloudflare: async (ctx) => {
    const token = ctx.env[CF_TOKEN_ENV];
    const given = ctx.clients.cloudflare as CloudflareApi | null | undefined;
    const api = given !== undefined ? given : token ? fetchCloudflareApi(token, fetch, undefined, sleepOf(ctx)) : null;
    if (!api) return [credsCheck(false, CF_TOKEN_ENV)];
    const out: Check[] = [credsCheck(true, CF_TOKEN_ENV)];
    const get = async (path: string, permission: string) => {
      let r: { status: number; body: unknown };
      try { r = await api.get(path); } catch (e) { r = { status: 0, body: { errors: [{ message: String(e) }] } }; }
      const errs = isObj(r.body) && Array.isArray(r.body.errors) ? r.body.errors.map((e) => (isObj(e) ? String(e.message ?? "") : "")).filter(Boolean).join("; ") : "";
      out.push(judge(permission, `GET ${path.split("?")[0]}`, { status: r.status, message: `HTTP ${r.status}${errs ? `: ${errs.slice(0, 200)}` : ""}` }, CF_TOKEN_ENV, permission));
    };
    for (const z of many(ctx.opts.zone).slice(0, 1)) await get(`/zones/${encodeURIComponent(z)}`, "the token permission Zone: Zone Read");
    if (!many(ctx.opts.zone).length) await get("/zones?per_page=5&page=1", "the token permission Zone: Zone Read");
    for (const a of many(ctx.opts.account)) await get(`/accounts/${encodeURIComponent(a)}/members?per_page=5&page=1`, "the token permission Account: Account Settings Read");
    return out;
  },
  aws: async (ctx) => {
    const region = many(ctx.opts["aws-regions"])[0] || ctx.env.AWS_REGION || ctx.env.AWS_DEFAULT_REGION || "us-east-1";
    const creds = "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_ROLE_ARN with AWS_WEB_IDENTITY_TOKEN_FILE";
    let t = ctx.clients.aws as AwsTransport | null | undefined;
    if (t === null) return [credsCheck(false, creds)];
    if (t === undefined) {
      const c = await envCredentials(ctx.env, region);
      if (!c) return [credsCheck(false, creds)];
      if ("error" in c) return [credsCheck(false, creds, c.error)];
      t = fetchAwsTransport(c);
    }
    const api = new Aws(t);
    const out: Check[] = [];
    const who = await callerAccount(api, region);
    if ("error" in who) return [{ what: "credentials", verdict: "fail", detail: `sts:GetCallerIdentity: ${who.error}`, fix: `check ${creds} (expired session or wrong account)` }];
    out.push({ what: "credentials", verdict: "pass", detail: `sts:GetCallerIdentity: account ${who.account}` });
    const r = await api.send(queryReq("iam", "us-east-1", "GetAccountSummary", "2010-05-08"));
    out.push(judge("iam:GetAccountSummary", "iam GetAccountSummary", { status: r.status, message: awsWhy(r) }, creds, "the AWS managed policy SecurityAudit (or iam:GetAccountSummary) to the role"));
    return out;
  },
  azure: async (ctx) => {
    const creds = "AZURE_ACCESS_TOKEN, or AZURE_TENANT_ID and AZURE_CLIENT_ID with AZURE_FEDERATED_TOKEN_FILE or AZURE_CLIENT_SECRET";
    const given = ctx.clients.azure as AzureTransport | null | undefined;
    const t = given !== undefined ? given : ((tok) => (tok ? fetchAzure(tok) : null))(azureToken(ctx.env));
    if (!t) return [credsCheck(false, creds)];
    const out: Check[] = [credsCheck(true, creds)];
    const subs = many(ctx.opts["azure-subscription"]);
    for (const url of subs.length ? subs.map((s) => `${ARM}/subscriptions/${encodeURIComponent(s)}?api-version=${AZURE_API.subscriptions}`) : [`${ARM}/subscriptions?api-version=${AZURE_API.subscriptions}`]) {
      const r = await armGet(t, url);
      out.push(judge("Reader", `GET ${new URL(url).pathname}`, { status: r.status, message: `HTTP ${r.status}` }, creds, "the Reader role (and Security Reader) on the subscription to the app"));
    }
    return out;
  },
  gcp: async (ctx) => {
    const creds = `${GCP_TOKEN_ENV}, or ${GCP_KEY_ENV}`;
    const token = ctx.env[GCP_TOKEN_ENV];
    const keyed = token ? undefined : gcpKeyToken(ctx.env);
    const t = ctx.clients.gcp !== undefined ? (ctx.clients.gcp as GcpTransport | null) : token ? fetchGcpTransport(token) : typeof keyed === "function" ? fetchGcpTransport(keyed) : null;
    if (!t) return [credsCheck(false, creds, typeof keyed === "string" ? keyed : undefined)];
    const projects = many(ctx.opts["gcp-project"]);
    const out: Check[] = [credsCheck(true, creds)];
    if (!projects.length) out.push({ what: "input", verdict: "fail", detail: "no --gcp-project given", fix: "give --gcp-project <id>" });
    const api = new Gcp(t);
    for (const p of projects) {
      const r = await api.call("POST", `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(p)}:getIamPolicy`, { options: { requestedPolicyVersion: 3 } });
      out.push(judge("roles/iam.securityReviewer", `POST projects/${p}:getIamPolicy`, { status: r.status, message: `HTTP ${r.status}` }, creds,
        "roles/iam.securityReviewer and roles/viewer on the project to the service account"));
    }
    return out;
  },
  jira: async (ctx) => {
    const creds = `${JIRA_ENV.base}, ${JIRA_ENV.email} and ${JIRA_ENV.token}`;
    let t = ctx.clients.jira as JiraTransport | null | undefined;
    if (t === null) return [credsCheck(false, creds)];
    if (t === undefined) {
      const base = ctx.env[JIRA_ENV.base], email = ctx.env[JIRA_ENV.email], token = ctx.env[JIRA_ENV.token];
      if (!base || !email || !token) return [credsCheck(false, creds)];
      try { t = fetchJira(base, email, token); } catch (e) { return [credsCheck(false, creds, (e as Error).message)]; }
    }
    const out: Check[] = [credsCheck(true, creds)];
    const jql = Object.entries(ctx.opts).find(([k, v]) => k.startsWith("jira-") && k.endsWith("-jql") && typeof v === "string")?.[1] as string | undefined;
    const path = `/rest/api/3/search/jql?jql=${encodeURIComponent(jql ?? "order by created DESC")}&maxResults=1&fields=key`;
    const r = await t.get(path);
    out.push(judge("Browse projects", "GET /rest/api/3/search/jql", { status: r.status, message: `HTTP ${r.status}` }, creds, "the project permission Browse projects on the projects the JQL names"));
    return out;
  },
  // ── Files, engines and hosts ─────────────────────────────────────────────────────────────────────
  lms: files(["training-csv"], ["roster-csv"]),
  scubagoggles: files(["scubagoggles-results"]),
  scubagear: files(["scubagear-results"]),
  trivy: files(["trivy-report"]),
  grype: files(["grype-report"]),
  syft: files(["sbom-file"]),
  gitleaks: files(["gitleaks-report"]),
  scorecard: files(["scorecard-result"]),
  kubescape: files(["kubescape-report"]),
  checkov: files(["checkov-report"]),
  vulnscan: files(["vulnscan-report"], ["vulnscan-inventory"]),
  prowler: async (ctx) => {
    const providers = many(ctx.opts["prowler-provider"]);
    const out: Check[] = [providers.length ? { what: "input", verdict: "pass", detail: `providers ${providers.join(", ")}` }
      : { what: "input", verdict: "fail", detail: "no --prowler-provider given", fix: "give --prowler-provider aws (or azure, gcp, kubernetes, m365, github, googleworkspace, okta, cloudflare)" }];
    if (one(ctx.opts["prowler-output"])) return [...out, ...await files(["prowler-output"])(ctx)];
    if (ctx.clients.prowler) return [...out, { what: "executable", verdict: "pass", detail: "a test runner stands in for prowler" }];
    return [...out, binCheck(one(ctx.opts["prowler-bin"]) ?? "prowler", ctx.env, "install Prowler (pip install prowler, or the runner image) or pass --prowler-bin; the provider's own credentials are checked by Prowler itself")];
  },
  stig: async (ctx) => {
    if (one(ctx.opts["cinc-report"]) || one(ctx.opts["stig-input-file"])) return files(["cinc-report", "stig-input-file"])(ctx);
    const out: Check[] = [];
    if (!many(ctx.opts["stig-target"]).length) out.push({ what: "input", verdict: "fail", detail: "no --stig-target or --cinc-report given", fix: "give --stig-target ssh://user@host with --stig-profile, or --cinc-report <file>" });
    if (ctx.clients.cinc) out.push({ what: "executable", verdict: "pass", detail: "a test runner stands in for cinc-auditor" });
    else out.push(binCheck(one(ctx.opts["cinc-bin"]) ?? "cinc-auditor", ctx.env, "install Cinc Auditor (or use the runner image), or pass --cinc-bin"));
    return out;
  },
  macos: async (ctx) => [ctx.clients.macos || process.platform === "darwin"
    ? { what: "platform", verdict: "pass", detail: "macOS: this Mac's own settings are read with its own tools" }
    : { what: "platform", verdict: "fail", detail: `this computer runs ${process.platform}`, fix: "run the macos source on the Mac to check (a LaunchAgent from sos-app's setup)" }],
  windows: async (ctx) => [ctx.clients.windows || process.platform === "win32"
    ? { what: "platform", verdict: "pass", detail: "Windows: this PC's own settings are read with PowerShell" }
    : { what: "platform", verdict: "fail", detail: `this computer runs ${process.platform}`, fix: "run the windows source on the PC to check (a scheduled task from sos-app's setup)" }],
  web: async (ctx) => {
    const urls = many(ctx.opts["web-url"]), proofs = new Set(many(ctx.opts["web-proof"]).map((p) => p.split("=")[0].toLowerCase()));
    if (!urls.length && !many(ctx.opts["web-privacy-url"]).length) return [{ what: "input", verdict: "fail", detail: "no --web-url given", fix: "give --web-url https://<host>/ with --web-proof <host>=<token> from sos-app" }];
    return urls.map((u): Check => {
      let host = "";
      try { host = new URL(u).hostname.toLowerCase(); } catch { return { what: "--web-url", verdict: "fail", detail: `${u}: not a URL`, fix: "give an https URL" }; }
      if (proofs.has(host) || ctx.opts["web-skip-proof"] === true) return { what: "--web-url", verdict: "pass", detail: `${host}: proof token given (checked against DNS or the well-known file during the run)` };
      return { what: "--web-url", verdict: "fail", detail: `${host}: no --web-proof`, fix: `give --web-proof ${host}=<the token sos-app issued for this host>` };
    });
  },
};

/** The fix for a source's refused call, for the run's own messages (cli.ts): "check it with collector doctor". */
export const doctorHint = (source: string) => `run \`collector doctor --config <file> --source ${source}\` to see which permission is missing`;

/**
 * The permission the doctor names for a refused call of a run (a 403's hint, src/diagnostics.ts): the REST probe's entry
 * whose path, templated, is the call's. Probes that need the run's options to name their paths answer only for the
 * paths they name without them.
 */
export function permissionFor(source: string, path: string): string | undefined {
  const calls = CALLS.get(PROBES[source]);
  if (!calls) return undefined;
  let list: [string, string][];
  try { list = calls({ opts: {}, env: {}, clients: {}, now: new Date(0), warn: () => {} }); } catch { return undefined; }
  const want = templatePath(path);
  return list.find(([p]) => templatePath(new URL(p, "https://x.invalid").pathname) === want)?.[1];
}
setPermissionLookup(permissionFor);
