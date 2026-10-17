// The Okta source against a fake management API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { okta, oktaFromEnv } from "../src/sources/okta.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const BASE = "https://acme.okta.com";
const USERS1 = `/api/v1/users?limit=200&filter=${encodeURIComponent('status eq "ACTIVE"')}`;
const USERS2 = "/api/v1/users?after=00u2&limit=200";
const ok = (b: unknown, h: Record<string, string> = {}) => res(200, b, h);

const enroll = { id: "pe1", name: "Default", type: "MFA_ENROLL", status: "ACTIVE", settings: { type: "AUTHENTICATORS", authenticators: [
  { key: "okta_password", enroll: { self: "REQUIRED" } }, { key: "okta_verify", enroll: { self: "REQUIRED" } }, { key: "phone_number", enroll: { self: "NOT_ALLOWED" } },
] } };
const gsp = { id: "pg1", name: "Default Policy", type: "OKTA_SIGN_ON", status: "ACTIVE" };
const asp = { id: "pa1", name: "Any two factors", type: "ACCESS_POLICY", status: "ACTIVE" };
const pwd = { id: "pp1", name: "Default Policy", type: "PASSWORD", status: "ACTIVE", settings: { password: {
  complexity: { minLength: 14 }, age: { historyCount: 4, maxAgeDays: 0 }, lockout: { maxAttempts: 5, autoUnlockMinutes: 30 },
} } };
const gspRule = (requireFactor: boolean) => [{ id: "r1", name: "Default Rule", status: "ACTIVE", actions: { signon: { access: "ALLOW", requireFactor } } }];
const aspRule = (factorMode: string) => [{ id: "r2", name: "Catch-all", status: "ACTIVE", actions: { appSignOn: { access: "ALLOW", verificationMethod: { type: "ASSURANCE", factorMode } } } }];

function strong(): Routes {
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

const C: Contract = {
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

contractSuite(C);

test("okta: users are read across Link rel=next pages", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.ok(calls.includes(USERS2), calls.join("\n"));
  assert.match(of(rs, "okta.inactive_users")[0].detail, /^0 of 2 ACTIVE/);
});

test("okta: role assignees follow _links.next.href", async () => {
  const calls: string[] = [];
  await runWith(C, fakeRest(BASE, { ...strong(),
    "/api/v1/iam/assignees/users": (url) => url.includes("after=x")
      ? ok({ value: [{ id: "00u2" }] })
      : ok({ value: [{ id: "00u1" }], _links: { next: { href: `${BASE}/api/v1/iam/assignees/users?after=x&limit=100` } } }),
  }, calls));
  assert.ok(calls.includes("/api/v1/iam/assignees/users?after=x&limit=100"));
  assert.ok(calls.includes("/api/v1/users/00u2/roles"));
});

test("okta: Classic Engine (no authenticators API, no app sign-in policies) is skipped for those checks", async () => {
  const rs = await runWith(C, fakeRest(BASE, { ...strong(),
    "/api/v1/authenticators": res(401, { errorCode: "E0000015", errorSummary: "You do not have permission to access the feature you are requesting" }),
    "/api/v1/policies?type=ACCESS_POLICY": res(400, { errorCode: "E0000001", errorSummary: "Api validation failed: type" }),
  }));
  assert.equal(of(rs, "okta.phishing_resistant_authenticator")[0].result, "skipped");
  assert.match(of(rs, "okta.phishing_resistant_authenticator")[0].detail, /do not have permission/);
  assert.equal(of(rs, "okta.app_policies_require_2fa")[0].result, "skipped");
});

test("okta: Okta's X-Rate-Limit-Reset sets the wait", async () => {
  const waits: number[] = [];
  const reset = String(Math.floor(Date.now() / 1000) + 5);
  await runWith(C, fakeRest(BASE, { ...strong(), "/api/v1/logs": (u, n) => (n === 1 ? res(429, { errorSummary: "rate" }, { "x-rate-limit-reset": reset }) : ok([{ published: daysAgo(0) }])) }), { waits });
  assert.equal(waits.length, 1);
  assert.ok(waits[0] >= 1000 && waits[0] <= 60_000, String(waits[0]));
});

test("okta: the fetch client sends SSWS and GET only; the token never reaches a result", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    const h = init.headers as Record<string, string>;
    return new Response(JSON.stringify({ errorCode: "E0000006", errorSummary: `You do not have permission (${h.authorization})` }), { status: 403 });
  }) as unknown as typeof fetch;
  const env = { OKTA_DOMAIN: "acme.okta.com", OKTA_API_TOKEN: "00okta-api-token-value-777" };
  const api = oktaFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string");
  const rs = await runWith(C, api, { env });
  assert.ok(seen.length > 5);
  for (const s of seen) {
    assert.equal(s.init.method, "GET");
    assert.ok(s.url.startsWith(`${BASE}/api/v1/`), s.url);
    assert.equal((s.init.headers as Record<string, string>).authorization, "SSWS 00okta-api-token-value-777");
  }
  assert.ok(!JSON.stringify(rs).includes("00okta-api-token-value-777"));
  for (const r of rs) assert.equal(r.result, "skipped");
});
