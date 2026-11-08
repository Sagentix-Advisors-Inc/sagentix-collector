// Fixtures for the okta source, shared by test/okta.test.ts and the end-to-end run (test/e2e.test.ts).
import { okta, oktaFromEnv } from "../../../src/sources/okta.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://acme.okta.com";
export const USERS1 = `/api/v1/users?limit=200&filter=${encodeURIComponent('status eq "ACTIVE"')}`;
export const USERS2 = "/api/v1/users?after=00u2&limit=200";
export const ok = (b: unknown, h: Record<string, string> = {}) => res(200, b, h);

export const enroll = { id: "pe1", name: "Default", type: "MFA_ENROLL", status: "ACTIVE", settings: { type: "AUTHENTICATORS", authenticators: [
  { key: "okta_password", enroll: { self: "REQUIRED" } }, { key: "okta_verify", enroll: { self: "REQUIRED" } }, { key: "phone_number", enroll: { self: "NOT_ALLOWED" } },
] } };
export const gsp = { id: "pg1", name: "Default Policy", type: "OKTA_SIGN_ON", status: "ACTIVE" };
export const asp = { id: "pa1", name: "Any two factors", type: "ACCESS_POLICY", status: "ACTIVE" };
export const pwd = { id: "pp1", name: "Default Policy", type: "PASSWORD", status: "ACTIVE", settings: { password: {
  complexity: { minLength: 14 }, age: { historyCount: 4, maxAgeDays: 0 }, lockout: { maxAttempts: 5, autoUnlockMinutes: 30 },
} } };
export const gspRule = (requireFactor: boolean) => [{ id: "r1", name: "Default Rule", status: "ACTIVE", actions: { signon: { access: "ALLOW", requireFactor } } }];
export const aspRule = (factorMode: string) => [{ id: "r2", name: "Catch-all", status: "ACTIVE", actions: { appSignOn: { access: "ALLOW", verificationMethod: { type: "ASSURANCE", factorMode } } } }];

export function strong(): Routes {
  return {
    "/api/v1/policies?type=MFA_ENROLL": ok([enroll]),
    "/api/v1/policies?type=OKTA_SIGN_ON": ok([gsp]),
    "/api/v1/policies?type=ACCESS_POLICY": ok([asp]),
    "/api/v1/policies?type=PASSWORD": ok([pwd]),
    "/api/v1/policies/pg1/rules": ok(gspRule(true)),
    "/api/v1/policies/pa1/rules": ok(aspRule("2FA")),
    "/api/v1/authenticators": ok([{ id: "a1", key: "okta_password", status: "ACTIVE" }, { id: "a2", key: "webauthn", status: "ACTIVE" }, { id: "a3", key: "okta_verify", status: "ACTIVE" }]),
    "/api/v1/authenticators/a3/methods": ok([{ type: "push", status: "ACTIVE" }, { type: "signed_nonce", status: "ACTIVE" }]),
    "/api/v1/iam/assignees/users": ok({ value: [{ id: "00u1" }, { id: "00u2" }], _links: {} }),
    "/api/v1/users/00u1/roles": ok([{ id: "ra1", type: "SUPER_ADMIN" }]),
    "/api/v1/users/00u2/roles": ok([{ id: "ra2", type: "READ_ONLY_ADMIN" }]),
    [USERS1]: ok([{ id: "00u1", status: "ACTIVE", created: daysAgo(400), lastLogin: daysAgo(1) }], { link: `<${BASE}${USERS1}>; rel="self", <${BASE}${USERS2}>; rel="next"` }),
    [USERS2]: ok([{ id: "00u2", status: "ACTIVE", created: daysAgo(5), lastLogin: null }]),
    "/api/v1/logs": ok([{ uuid: "e1", published: daysAgo(0) }]),
  };
}

export const C: Contract = {
  source: okta, clientKey: "okta", base: BASE, prefix: "okta", strong,
  env: { OKTA_DOMAIN: "acme.okta.com", OKTA_API_TOKEN: "x" },
  rateLimited: { path: "/api/v1/logs", check: "system_log_available" },
  fails: {
    mfa_enroll_required: { "/api/v1/policies?type=MFA_ENROLL": ok([{ ...enroll, settings: { authenticators: [{ key: "okta_password", enroll: { self: "REQUIRED" } }, { key: "okta_verify", enroll: { self: "OPTIONAL" } }] } }]) },
    phishing_resistant_authenticator: {
      "/api/v1/authenticators": ok([{ id: "a3", key: "okta_verify", status: "ACTIVE" }, { id: "a2", key: "webauthn", status: "INACTIVE" }]),
      "/api/v1/authenticators/a3/methods": ok([{ type: "push", status: "ACTIVE" }, { type: "signed_nonce", status: "INACTIVE" }]),
    },
    global_session_requires_mfa: { "/api/v1/policies/pg1/rules": ok(gspRule(false)) },
    app_policies_require_2fa: { "/api/v1/policies/pa1/rules": ok(aspRule("1FA")) },
    password_policy: { "/api/v1/policies?type=PASSWORD": ok([{ ...pwd, settings: { password: { ...pwd.settings.password, complexity: { minLength: 8 } } } }]) },
    account_lockout: { "/api/v1/policies?type=PASSWORD": ok([{ ...pwd, settings: { password: { ...pwd.settings.password, lockout: { maxAttempts: 0 } } } }]) },
    super_admins_limited: { "/api/v1/users/00u2/roles": ok([{ type: "SUPER_ADMIN" }]) },
    inactive_users: { [USERS2]: ok([{ id: "00u9", status: "ACTIVE", created: daysAgo(400), lastLogin: daysAgo(120) }]) },
    system_log_available: { "/api/v1/logs": ok([]) },
  },
  opts: { "okta-max-super-admins": "1" },
};
