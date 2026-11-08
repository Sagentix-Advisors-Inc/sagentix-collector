// Fixtures for the entra source, shared by test/entra.test.ts and the end-to-end run (test/e2e.test.ts).
import { GLOBAL_ADMIN_ROLE, GRAPH_BASE, entra, entraFromEnv } from "../../../src/sources/entra.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const TENANT = "11111111-2222-3333-4444-555555555555";
export const page = (value: unknown[], next?: string) => res(200, { value, ...(next ? { "@odata.nextLink": next } : {}) });
export const REG2 = `${GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails?$skiptoken=page2`;

export const caMfa = { id: "ca1", displayName: "Require MFA", state: "enabled", conditions: { users: { includeUsers: ["All"], excludeUsers: ["bg1"] }, applications: { includeApplications: ["All"] } }, grantControls: { operator: "OR", builtInControls: ["mfa"] } };
export const caLegacy = { id: "ca2", displayName: "Block legacy", state: "enabled", conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["exchangeActiveSync", "other"] }, grantControls: { builtInControls: ["block"] } };
export const caRisk = { id: "ca3", displayName: "Risky sign-in", state: "enabled", conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, signInRiskLevels: ["high", "medium"] }, grantControls: { builtInControls: ["mfa"] } };
export const MEMBERS = [
  { id: "u1", accountEnabled: true, userType: "Member", userPrincipalName: "admin@example.com" },
  { id: "u2", accountEnabled: true, userType: "Member", userPrincipalName: "user@example.com" },
  { id: "u3", accountEnabled: false, userType: "Member", userPrincipalName: "gone@example.com" },
  { id: "g1", accountEnabled: true, userType: "Guest", userPrincipalName: "guest_partner.example#EXT#@example.com" },
];
export const sched = (id: string, principalId: string, type: string, expiration: string) => ({ id, principalId, roleDefinitionId: GLOBAL_ADMIN_ROLE, assignmentType: type, scheduleInfo: { expiration: { type: expiration } } });

export function strong(): Routes {
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
        { id: "u1", accountEnabled: true, createdDateTime: daysAgo(400), signInActivity: { lastSignInDateTime: daysAgo(2), lastSuccessfulSignInDateTime: daysAgo(2) } },
        { id: "u2", accountEnabled: true, createdDateTime: daysAgo(10), signInActivity: { lastSignInDateTime: null } },
        { id: "u3", accountEnabled: false, createdDateTime: daysAgo(900), signInActivity: { lastSignInDateTime: daysAgo(800) } },
      ])
      : url.includes("$filter=") ? page([{ id: "g1" }])
      : page(MEMBERS),
    "/auditLogs/directoryAudits": page([{ id: "d1", activityDateTime: daysAgo(0) }]),
  };
}

export const C: Contract = {
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
