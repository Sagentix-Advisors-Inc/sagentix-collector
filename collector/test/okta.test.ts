// The Okta source against a fake management API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { okta, oktaFromEnv } from "../src/sources/okta.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { BASE, USERS1, USERS2, ok, enroll, gsp, asp, pwd, gspRule, aspRule, strong, C } from "./fixtures/rest/okta.ts";

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

test("okta.global_session_requires_mfa: a rule that hands the session to app sign-in policies (PASSWORD_IDP_ANY_FACTOR) passes only when they all require 2FA", async () => {
  const handed = { "/api/v1/policies/pg1/rules": ok([{ id: "r1", name: "Default Rule", status: "ACTIVE", actions: { signon: { access: "ALLOW", requireFactor: false, primaryFactor: "PASSWORD_IDP_ANY_FACTOR" } } }]) };
  const pass = of(await runWith(C, fakeRest(BASE, { ...strong(), ...handed })), "okta.global_session_requires_mfa")[0];
  assert.equal(pass.result, "pass", pass.detail);
  assert.match(pass.detail, /PASSWORD_IDP_ANY_FACTOR/);
  const weakApps = of(await runWith(C, fakeRest(BASE, { ...strong(), ...handed, "/api/v1/policies/pa1/rules": ok(aspRule("1FA")) })), "okta.global_session_requires_mfa")[0];
  assert.equal(weakApps.result, "fail", weakApps.detail);
  const classic = of(await runWith(C, fakeRest(BASE, { ...strong(), ...handed, "/api/v1/policies?type=ACCESS_POLICY": res(400, { errorCode: "E0000001", errorSummary: "Api validation failed: type" }) })), "okta.global_session_requires_mfa")[0];
  assert.equal(classic.result, "skipped", classic.detail);
  // A password-only session rule without requireFactor still fails, whatever the app policies say.
  const pwdOnly = { "/api/v1/policies/pg1/rules": ok([{ id: "r1", name: "Default Rule", status: "ACTIVE", actions: { signon: { access: "ALLOW", requireFactor: false, primaryFactor: "PASSWORD_IDP" } } }]) };
  assert.equal(of(await runWith(C, fakeRest(BASE, { ...strong(), ...pwdOnly })), "okta.global_session_requires_mfa")[0].result, "fail");
});
