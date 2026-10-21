// The Entra ID source against a fake Microsoft Graph.
import { test } from "node:test";
import assert from "node:assert/strict";
import { GLOBAL_ADMIN_ROLE, GRAPH_BASE, entra, entraFromEnv } from "../src/sources/entra.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const TENANT = "11111111-2222-3333-4444-555555555555";
const page = (value: unknown[], next?: string) => res(200, { value, ...(next ? { "@odata.nextLink": next } : {}) });
const REG2 = `${GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails?$skiptoken=page2`;

const caMfa = { id: "ca1", displayName: "Require MFA", state: "enabled", conditions: { users: { includeUsers: ["All"], excludeUsers: ["bg1"] }, applications: { includeApplications: ["All"] } }, grantControls: { operator: "OR", builtInControls: ["mfa"] } };
const caLegacy = { id: "ca2", displayName: "Block legacy", state: "enabled", conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["exchangeActiveSync", "other"] }, grantControls: { builtInControls: ["block"] } };
const caRisk = { id: "ca3", displayName: "Risky sign-in", state: "enabled", conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, signInRiskLevels: ["high", "medium"] }, grantControls: { builtInControls: ["mfa"] } };
const MEMBERS = [
  { id: "u1", accountEnabled: true, userType: "Member", userPrincipalName: "admin@example.com" },
  { id: "u2", accountEnabled: true, userType: "Member", userPrincipalName: "user@example.com" },
  { id: "u3", accountEnabled: false, userType: "Member", userPrincipalName: "gone@example.com" },
  { id: "g1", accountEnabled: true, userType: "Guest", userPrincipalName: "guest_partner.example#EXT#@example.com" },
];
const sched = (id: string, principalId: string, type: string, expiration: string) => ({ id, principalId, roleDefinitionId: GLOBAL_ADMIN_ROLE, assignmentType: type, scheduleInfo: { expiration: { type: expiration } } });

function strong(): Routes {
  return {
    "/subscribedSkus": page([{ skuPartNumber: "AAD_PREMIUM_P2", capabilityStatus: "Enabled", servicePlans: [{ servicePlanName: "AAD_PREMIUM_P2" }, { servicePlanName: "AAD_PREMIUM" }] }]),
    "/reports/authenticationMethods/userRegistrationDetails": page([
      { id: "u1", userPrincipalName: "admin@example.com", userType: "member", isAdmin: true, isMfaRegistered: true, isMfaCapable: true, methodsRegistered: ["passKeyDeviceBound", "microsoftAuthenticatorPush"] },
    ], REG2),
    [REG2.slice(GRAPH_BASE.length)]: page([{ id: "u2", userType: "member", isAdmin: false, isMfaRegistered: true, isMfaCapable: true, methodsRegistered: ["microsoftAuthenticatorPush"] }]),
    "/identity/conditionalAccess/policies": page([caMfa, caLegacy, caRisk]),
    "/policies/identitySecurityDefaultsEnforcementPolicy": res(200, { id: "00000000-0000-0000-0000-000000000005", isEnabled: false }),
    "/roleManagement/directory/roleAssignments": page([{ id: "a1", principalId: "u1", roleDefinitionId: GLOBAL_ADMIN_ROLE }, { id: "a2", principalId: "bg1", roleDefinitionId: GLOBAL_ADMIN_ROLE }]),
    "/roleManagement/directory/roleAssignmentSchedules": page([sched("s1", "bg1", "Assigned", "noExpiration"), sched("s2", "u1", "Activated", "afterDateTime")]),
    "/roleManagement/directory/roleEligibilitySchedules": page([sched("e1", "u1", "Eligible", "noExpiration")]),
    "/policies/authorizationPolicy": res(200, { id: "authorizationPolicy", allowInvitesFrom: "adminsAndGuestInviters" }),
    "/users": (url) => url.includes("signInActivity") ? page([
        { id: "u1", accountEnabled: true, createdDateTime: daysAgo(400), signInActivity: { lastSignInDateTime: daysAgo(2) } },
        { id: "u2", accountEnabled: true, createdDateTime: daysAgo(10), signInActivity: { lastSignInDateTime: null } },
        { id: "u3", accountEnabled: false, createdDateTime: daysAgo(900), signInActivity: { lastSignInDateTime: daysAgo(800) } },
      ])
      : url.includes("$filter=") ? page([{ id: "g1" }])
      : page(MEMBERS),
    "/auditLogs/directoryAudits": page([{ id: "d1", activityDateTime: daysAgo(0) }]),
  };
}

const C: Contract = {
  source: entra, clientKey: "entra", base: GRAPH_BASE, prefix: "entra", strong,
  env: { ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: "app", ENTRA_CLIENT_SECRET: "x" },
  rateLimited: { path: "/policies/authorizationPolicy", check: "guest_invites_restricted" },
  fails: {
    mfa_registered: { [REG2.slice(GRAPH_BASE.length)]: page([{ id: "u2", isMfaRegistered: false, methodsRegistered: [] }]) },
    admins_phishing_resistant: { "/reports/authenticationMethods/userRegistrationDetails": page([{ id: "u1", isAdmin: true, isMfaRegistered: true, methodsRegistered: ["mobilePhone"] }]) },
    ca_mfa_all_users: { "/identity/conditionalAccess/policies": page([{ ...caMfa, state: "enabledForReportingButNotEnforced" }, caLegacy, caRisk]) },
    ca_blocks_legacy_auth: { "/identity/conditionalAccess/policies": page([caMfa, { ...caLegacy, conditions: { ...caLegacy.conditions, clientAppTypes: ["exchangeActiveSync"] } }, caRisk]) },
    security_defaults: { "/identity/conditionalAccess/policies": page([caLegacy]) },
    global_admins_limited: { "/roleManagement/directory/roleAssignments": page(["a", "b", "c", "d", "e"].map((p) => ({ principalId: p, roleDefinitionId: GLOBAL_ADMIN_ROLE }))) },
    pim_no_permanent_admins: { "/roleManagement/directory/roleAssignmentSchedules": page(["a", "b", "c"].map((p) => sched(p, p, "Assigned", "noExpiration"))) },
    guest_invites_restricted: { "/policies/authorizationPolicy": res(200, { allowInvitesFrom: "everyone" }) },
    stale_accounts: { "/users": (url) => (url.includes("signInActivity") ? page([{ id: "old", accountEnabled: true, createdDateTime: daysAgo(500), signInActivity: { lastSignInDateTime: daysAgo(200) } }]) : page([])) },
    audit_log_available: { "/auditLogs/directoryAudits": page([]) },
    risk_policies: { "/identity/conditionalAccess/policies": page([caMfa, caLegacy]) },
    users_mfa_covered: { [REG2.slice(GRAPH_BASE.length)]: page([{ id: "u2", userType: "member", isMfaRegistered: true, isMfaCapable: false, methodsRegistered: ["email"] }]) },
  },
};

contractSuite(C);

test("entra: the registration report is read across @odata.nextLink pages", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(GRAPH_BASE, strong(), calls));
  assert.ok(calls.some((u) => u.includes("$skiptoken=page2")));
  assert.match(of(rs, "entra.mfa_registered")[0].detail, /^2 of 2 enabled users/);
});

test("entra: failing details give object ids, never user principal names", async () => {
  const rs = await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), ...C.fails.mfa_registered,
    [REG2.slice(GRAPH_BASE.length)]: page([{ id: "u2", userPrincipalName: "alice@example.com", isMfaRegistered: false }]) }));
  const d = of(rs, "entra.mfa_registered")[0].detail;
  assert.match(d, /u2/);
  assert.doesNotMatch(JSON.stringify(rs), /alice@example\.com/);
});

test("entra: without P2, PIM and risk policies are skipped, not failed", async () => {
  const rs = await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), "/subscribedSkus": page([{ capabilityStatus: "Enabled", servicePlans: [{ servicePlanName: "AAD_PREMIUM" }] }]),
    "/identity/conditionalAccess/policies": page([caMfa, caLegacy]) }));
  assert.equal(of(rs, "entra.pim_no_permanent_admins")[0].result, "skipped");
  assert.equal(of(rs, "entra.risk_policies")[0].result, "skipped");
});

test("entra: security defaults on pass without Conditional Access", async () => {
  const rs = await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), "/policies/identitySecurityDefaultsEnforcementPolicy": res(200, { isEnabled: true }),
    "/identity/conditionalAccess/policies": res(403, { error: { code: "Forbidden", message: "requires premium" } }) }));
  assert.equal(of(rs, "entra.security_defaults")[0].result, "pass");
  assert.equal(of(rs, "entra.ca_mfa_all_users")[0].result, "skipped");
});

test("entra: the fetch client gets a token by client credentials, then only GETs Graph; the token never reaches a result", async () => {
  const seen: { url: string; method: string; body?: string; auth?: string }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    const h = init.headers as Record<string, string>;
    seen.push({ url, method: String(init.method), body: init.body as string | undefined, auth: h.authorization });
    if (url.startsWith("https://login.microsoftonline.com/")) return new Response(JSON.stringify({ access_token: "graph-access-token-XYZ123456", expires_in: 3599 }), { status: 200 });
    return new Response(JSON.stringify({ error: { code: "Authorization_RequestDenied", message: `denied for ${h.authorization}` } }), { status: 403 });
  }) as unknown as typeof fetch;
  const env = { ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: "app-id", ENTRA_CLIENT_SECRET: "client-secret-value-0001" };
  const api = entraFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string");
  const rs = await runWith(C, api, { env });
  const token = seen.filter((s) => s.url.includes("/oauth2/v2.0/token"));
  assert.equal(token.length, 1, "one token request, cached");
  assert.equal(token[0].method, "POST");
  assert.match(token[0].body!, /grant_type=client_credentials/);
  assert.match(token[0].body!, /scope=https%3A%2F%2Fgraph\.microsoft\.com%2F\.default/);
  for (const s of seen.filter((x) => !x.url.includes("/oauth2/"))) {
    assert.equal(s.method, "GET");
    assert.ok(s.url.startsWith(`${GRAPH_BASE}/`), s.url);
    assert.equal(s.auth, "Bearer graph-access-token-XYZ123456");
  }
  const text = JSON.stringify(rs);
  assert.ok(!text.includes("graph-access-token-XYZ123456") && !text.includes("client-secret-value-0001"));
  for (const r of rs) assert.equal(r.result, "skipped");
});

test("entra: a next link to another origin is refused without sending the token", async () => {
  const seen: string[] = [];
  const fetchFn = (async (url: string) => {
    seen.push(url);
    if (url.includes("/oauth2/")) return new Response(JSON.stringify({ access_token: "tok-abcdefgh-1234", expires_in: 3599 }), { status: 200 });
    return new Response(JSON.stringify({ value: [{ id: "u1", isMfaRegistered: true }], "@odata.nextLink": "https://evil.example/steal" }), { status: 200 });
  }) as unknown as typeof fetch;
  const api = entraFromEnv({ ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: "a", ENTRA_CLIENT_SECRET: "s" }, fetchFn) as Exclude<ReturnType<typeof entraFromEnv>, string>;
  const r = await api.get("/reports/authenticationMethods/userRegistrationDetails");
  assert.equal(r.status, 200);
  const r2 = await api.get("https://evil.example/steal");
  assert.equal(r2.status, 0);
  assert.ok(!seen.some((u) => u.startsWith("https://evil.example")));
});

test("entra: missing credentials skip every check with the variable names", async () => {
  const rs = await entra.run({ opts: {}, env: {}, clients: {}, now: new Date(), warn: () => {} });
  assert.equal(rs.length, entra.emits.length);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /ENTRA_TENANT_ID/); }
});

// ── users_mfa_covered ────────────────────────────────────────────────────────────────────────────────
const COV = "entra.users_mfa_covered";
const covered = async (over: Routes, opts: Record<string, string | string[]> = {}, calls: string[] = []) =>
  of(await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), ...over }, calls), { opts }), COV)[0];
const withPolicy = (users: Record<string, unknown>, grantControls: Record<string, unknown> = caMfa.grantControls) =>
  ({ "/identity/conditionalAccess/policies": page([{ ...caMfa, conditions: { ...caMfa.conditions, users }, grantControls }, caLegacy, caRisk]) });
const usersRoute = (members: unknown) => ({ "/users": (url: string) => (url.includes("signInActivity") || url.includes("$filter=") ? page([])
  : typeof members === "function" ? members(url) : page(members as unknown[])) });

test("entra.users_mfa_covered: passes with every enabled member capable and covered; guests and disabled accounts are counted, not judged", async () => {
  const r = await covered({});
  assert.equal(r.result, "pass", r.detail);
  assert.match(r.detail, /^2 enabled member account\(s\) judged; 2 have a strong method .*1 of them a phishing-resistant one; 2 are in scope of MFA/);
  assert.match(r.detail, /not judged: 1 guest\(s\), 1 disabled/);
});

test("entra.users_mfa_covered: a guest without MFA does not fail the check", async () => {
  const r = await covered({ [REG2.slice(GRAPH_BASE.length)]: page([
    { id: "u2", userType: "member", isMfaCapable: true, methodsRegistered: ["microsoftAuthenticatorPush"] },
    { id: "g1", userType: "guest", isMfaCapable: false, isMfaRegistered: false, methodsRegistered: [] },
  ]) });
  assert.equal(r.result, "pass", r.detail);
});

test("entra.users_mfa_covered: a member registered but not capable, or missing from the report, fails by object id", async () => {
  const r = await covered({ [REG2.slice(GRAPH_BASE.length)]: page([]) });
  assert.equal(r.result, "fail");
  assert.match(r.detail, /1 without a strong method \(1 missing from the registration report\) \(u2\)/);
  const notAllowed = await covered(C.fails.users_mfa_covered);
  assert.equal(notAllowed.result, "fail");
  assert.match(notAllowed.detail, /\(u2\)/);
  assert.doesNotMatch(JSON.stringify(notAllowed), /@example\.com/);
});

test("entra.users_mfa_covered: a passkey alone counts as strong and phishing-resistant when Microsoft reports it capable", async () => {
  const r = await covered({ [REG2.slice(GRAPH_BASE.length)]: page([{ id: "u2", userType: "member", isMfaRegistered: true, isMfaCapable: true, methodsRegistered: ["passKeyDeviceBound"] }]) });
  assert.equal(r.result, "pass", r.detail);
  assert.match(r.detail, /2 of them a phishing-resistant one/);
});

test("entra.users_mfa_covered: a policy that exists but excludes a member does not cover them", async () => {
  const r = await covered(withPolicy({ includeUsers: ["All"], excludeUsers: ["u2"] }));
  assert.equal(r.result, "fail");
  assert.match(r.detail, /1 not covered \(u2\)/);
});

test("entra.users_mfa_covered: group and role scopes are resolved to users, through nested groups and role-assignable groups", async () => {
  const user = (id: string) => ({ "@odata.type": "#microsoft.graph.user", id });
  const grp = withPolicy({ includeGroups: ["grp1"] });
  const calls: string[] = [];
  const only1 = await covered({ ...grp, "/groups/grp1/transitiveMembers": page([user("u1")]) }, {}, calls);
  assert.equal(only1.result, "fail");
  assert.match(only1.detail, /1 not covered \(u2\)/);
  assert.ok(calls.includes("/groups/grp1/transitiveMembers"));
  const both = await covered({ ...grp, "/groups/grp1/transitiveMembers": page([user("u1"), user("u2"), { "@odata.type": "#microsoft.graph.group", id: "nested" }]) });
  assert.equal(both.result, "pass", both.detail);
  const role = "b0f54661-2d74-4c50-afa3-1ec803f12efe";
  const byRole = await covered({ ...withPolicy({ includeUsers: ["All"], excludeRoles: [role] }),
    "/roleManagement/directory/roleAssignments": (url) => (url.includes(role) ? page([{ principalId: "rag1", roleDefinitionId: role }, { principalId: "sp1", roleDefinitionId: role }])
      : page([{ principalId: "u1", roleDefinitionId: GLOBAL_ADMIN_ROLE }])),
    "/groups/rag1/transitiveMembers": page([user("u2")]) });
  assert.equal(byRole.result, "fail", byRole.detail);
  assert.match(byRole.detail, /1 not covered \(u2\)/);
});

test("entra.users_mfa_covered: an exclusion group that cannot be read gives skipped, not pass", async () => {
  const r = await covered({ ...withPolicy({ includeUsers: ["All"], excludeGroups: ["grpX"] }),
    "/groups/grpX/transitiveMembers": res(403, { error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" } }) });
  assert.equal(r.result, "skipped", r.detail);
  assert.match(r.detail, /GroupMember\.Read\.All/);
  assert.match(r.detail, /not credited: "Require MFA" has exclusions that could not be resolved/);
});

test("entra.users_mfa_covered: MFA offered as one choice among others, or a B2B-member exclusion, is not credited", async () => {
  const or = await covered(withPolicy({ includeUsers: ["All"] }, { operator: "OR", builtInControls: ["mfa", "compliantDevice"] }));
  assert.equal(or.result, "fail");
  assert.match(or.detail, /: 0 enabled Conditional Access polic/);
  const and = await covered(withPolicy({ includeUsers: ["All"] }, { operator: "AND", builtInControls: ["mfa", "compliantDevice"] }));
  assert.equal(and.result, "pass", and.detail);
  const strength = await covered(withPolicy({ includeUsers: ["All"] }, { operator: "OR", builtInControls: [], authenticationStrength: { id: "00000000-0000-0000-0000-000000000004", requirementsSatisfied: "mfa" } }));
  assert.equal(strength.result, "pass", strength.detail);
  const none = await covered(withPolicy({ includeUsers: ["All"] }, { operator: "OR", builtInControls: [], authenticationStrength: { id: "custom", requirementsSatisfied: "none" } }));
  assert.equal(none.result, "fail");
  const b2b = await covered(withPolicy({ includeUsers: ["All"], excludeGuestsOrExternalUsers: { guestOrExternalUserTypes: "internalGuest,b2bCollaborationMember" } }));
  assert.equal(b2b.result, "fail");
  assert.match(b2b.detail, /B2B collaboration members/);
});

test("entra.users_mfa_covered: security defaults cover everyone; with Conditional Access unreadable and defaults off it is skipped", async () => {
  const ca403 = { "/identity/conditionalAccess/policies": res(403, { error: { code: "Forbidden", message: "requires premium" } }) };
  const sd = await covered({ ...ca403, "/policies/identitySecurityDefaultsEnforcementPolicy": res(200, { isEnabled: true }) });
  assert.equal(sd.result, "pass", sd.detail);
  assert.match(sd.detail, /security defaults are on/);
  const off = await covered(ca403);
  assert.equal(off.result, "skipped");
  assert.match(off.detail, /security defaults are off and Conditional Access is not readable/);
});

test("entra.users_mfa_covered: a 403 on the registration report (licence or permission) gives skipped with the reason", async () => {
  const r = await covered({ "/reports/authenticationMethods/userRegistrationDetails": res(403, { error: { code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", message: "Neither tenant is B2C or tenant doesn't have premium license" } }) });
  assert.equal(r.result, "skipped");
  assert.match(r.detail, /HTTP 403: Neither tenant is B2C .*AuditLog\.Read\.All and Entra ID P1 or P2/);
});

test("entra.users_mfa_covered: /users is read across @odata.nextLink pages", async () => {
  const next = `${GRAPH_BASE}/users?$skiptoken=members2`;
  const calls: string[] = [];
  const r = await covered(usersRoute((url: string) => (url.includes("members2") ? page([MEMBERS[1], { id: "u9", accountEnabled: true, userType: "Member" }]) : page([MEMBERS[0]], next))), {}, calls);
  assert.ok(calls.some((u) => u.includes("$skiptoken=members2")));
  assert.equal(r.result, "fail");
  assert.match(r.detail, /^3 enabled member account\(s\) judged/);
  assert.match(r.detail, /\(1 missing from the registration report\) \(u9\)/);
});

test("entra.users_mfa_covered: a break-glass account named by --entra-mfa-exempt is listed by id, not judged", async () => {
  const bg = usersRoute([...MEMBERS, { id: "bg1", accountEnabled: true, userType: "Member", userPrincipalName: "BreakGlass@example.com" }]);
  const without = await covered(bg);
  assert.equal(without.result, "fail");
  assert.match(without.detail, /\(bg1\).*1 not covered \(bg1\)/);
  const r = await covered(bg, { "entra-mfa-exempt": ["breakglass@EXAMPLE.com", "nobody@example.com"] });
  assert.equal(r.result, "pass", r.detail);
  assert.match(r.detail, /1 exempt by --entra-mfa-exempt \(bg1\), 0 of them with a strong method registered; 1 --entra-mfa-exempt value\(s\) matched no enabled member account/);
  assert.doesNotMatch(JSON.stringify(r), /example\.com/i);
  const byId = await covered(bg, { "entra-mfa-exempt": "bg1" });
  assert.equal(byId.result, "pass", byId.detail);
});

test("entra.users_mfa_covered: without /users the report itself gives the accounts", async () => {
  const r = await covered(usersRoute(() => res(403, { error: { message: "denied" } })));
  assert.equal(r.result, "pass", r.detail);
  assert.match(r.detail, /accounts taken from the registration report because \/users is not readable: HTTP 403/);
});
