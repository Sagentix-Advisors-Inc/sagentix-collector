// Fixtures for the google_workspace source, shared by test/google_workspace.test.ts and the end-to-end run (test/e2e.test.ts).
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ADMIN_BASE, GOOGLE_SCOPES, POLICY_BASE, POLICY_SCOPE, driveSharingCheck, googleFromEnv, googlePolicyFromEnv, googleWorkspace, isGoogleTokenUri } from "../../../src/sources/google_workspace.ts";
import { googleAssertion } from "../../../src/sources/oauth.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const USERS = "/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic";
export const REPORT = "/admin/reports/v1/activity/users/all/applications/admin";
export const ok = (b: unknown) => res(200, b);
export const POLICIES = `${POLICY_BASE}/v1/policies?pageSize=100&filter=${encodeURIComponent("setting.type.matches('drive_and_docs.external_sharing$')")}`;
export const sharing = (orgUnit: string, value: Record<string, unknown>, type = "ADMIN") =>
  ({ name: `policies/${orgUnit}`, customer: "customers/C0123", type, policyQuery: { orgUnit: `orgUnits/${orgUnit}`, sortOrder: 1 }, setting: { type: "settings/drive_and_docs.external_sharing", value } });
export const user = (id: string, o: Record<string, unknown> = {}) => ({ id, primaryEmail: `${id}@example.com`, isEnrolledIn2Sv: true, isEnforcedIn2Sv: true, isAdmin: false, suspended: false, archived: false, creationTime: daysAgo(400), lastLoginTime: daysAgo(3), ...o });

export function users(page1: unknown[], page2: unknown[]): Routes {
  return {
    [USERS]: ok({ kind: "admin#directory#users", users: page1, nextPageToken: "tok2" }),
    [`${USERS}&pageToken=tok2`]: ok({ kind: "admin#directory#users", users: page2 }),
  };
}

export function strong(): Routes {
  return {
    ...users([user("1", { isAdmin: true }), user("2")], [user("3", { isDelegatedAdmin: true }), user("4", { suspended: true, isEnrolledIn2Sv: false, lastLoginTime: "1970-01-01T00:00:00.000Z" })]),
    [REPORT]: ok({ kind: "admin#reports#activities", items: [{ id: { time: daysAgo(0), applicationName: "admin" } }] }),
    [POLICIES]: ok({ policies: [sharing("root", { externalSharingMode: "ALLOWLISTED_DOMAINS" }), sharing("sales", { externalSharingMode: "ALLOWED", allowPublishingFiles: false })] }),
  };
}

export const C: Contract = {
  source: googleWorkspace, clientKey: "google", base: ADMIN_BASE, prefix: "google_workspace", strong,
  rateLimited: { path: REPORT, check: "audit_reports_available" },
  fails: {
    two_step_enrolled: users([user("1", { isAdmin: true }), user("2", { isEnrolledIn2Sv: false })], []),
    two_step_enforced: users([user("1", { isAdmin: true }), user("2", { isEnforcedIn2Sv: false })], []),
    admins_two_step: users([user("1", { isAdmin: true, isEnrolledIn2Sv: false })], []),
    super_admins_limited: users(["1", "2", "3", "4", "5"].map((i) => user(i, { isAdmin: true })), []),
    inactive_users: users([user("1", { isAdmin: true }), user("2", { lastLoginTime: daysAgo(200) })], [user("3", { lastLoginTime: "1970-01-01T00:00:00.000Z", creationTime: daysAgo(300) })]),
    audit_reports_available: { [REPORT]: ok({ kind: "admin#reports#activities" }) },
    drive_external_sharing_restricted: { [POLICIES]: ok({ policies: [sharing("root", { externalSharingMode: "DISALLOWED" }), sharing("eng", { externalSharingMode: "ALLOWED" })] }) },
  },
};
