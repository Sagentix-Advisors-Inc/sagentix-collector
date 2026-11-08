// Fixtures for the jumpcloud source, shared by test/jumpcloud.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGE, SYSTEM_FIELDS, USER_FIELDS, jumpcloud, jumpcloudFromEnv, systemsPath, usersPath } from "../../../src/sources/jumpcloud.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://console.jumpcloud.com/api";
export const ORG = "6230a0d26a4e4bc86c6b36f1";
export const ok = (b: unknown, h: Record<string, string> = {}) => res(200, b, h);
export const v1 = (results: unknown[], total = results.length) => ok({ totalCount: total, results });

export const settings = (pw: Record<string, unknown> = {}, adminMfa = true) => ({
  _id: ORG, displayName: "Acme", contactEmail: "it@acme.example",
  settings: { requireAdminMFA: adminMfa, passwordPolicy: { enableMinLength: true, minLength: 14, enableMaxLoginAttempts: true, maxLoginAttempts: 5, lockoutTimeInSeconds: 900, ...pw } },
});
export type U = { state?: string; suspended?: boolean; required?: boolean; overall?: string; totp?: string; push?: string; webauthn?: string };
export function user(id: string, o: U = {}): Record<string, unknown> {
  return {
    _id: id, username: "achao", email: "anna.chao@acme.example", firstname: "Anna", state: o.state ?? "ACTIVATED", suspended: o.suspended ?? false,
    enable_user_portal_multifactor: o.required ?? true, totp_enabled: (o.totp ?? "ENROLLED") === "ENROLLED",
    mfaEnrollment: { overallStatus: o.overall ?? "ENROLLED", totpStatus: o.totp ?? "ENROLLED", pushStatus: o.push ?? "NOT_ENROLLED", webAuthnStatus: o.webauthn ?? "NOT_ENROLLED" },
  };
}
export const policy = (id: string, o: { mfa?: boolean; type?: string; disabled?: boolean; action?: string } = {}) => ({
  id, name: `Policy ${id} (owner anna.chao@acme.example)`, disabled: o.disabled ?? false, monitorOnly: false, type: o.type ?? "user_portal",
  effect: { action: o.action ?? "allow", obligations: { mfa: { required: o.mfa ?? true } } }, targets: { resources: [{ type: o.type ?? "user_portal" }] },
});
export type S = { fde?: boolean; version?: string; os?: string; family?: string; contact?: string | null };
export function system(id: string, serial: string, o: S = {}): Record<string, unknown> {
  return {
    _id: id, serialNumber: serial, hostname: "annas-macbook-air", displayName: "Anna's MacBook Air",
    os: o.os ?? "Mac OS X", osFamily: o.family ?? "darwin", version: o.version ?? "15.1",
    osVersionDetail: { osName: o.os ?? "Mac OS X", version: o.version ?? "15.1" },
    fde: { active: o.fde ?? true, keyPresent: true }, lastContact: o.contact === undefined ? daysAgo(1) : o.contact,
  };
}

export const strong = (): Routes => ({
  "/organizations": v1([{ _id: ORG, displayName: "Acme" }]),
  [`/organizations/${ORG}`]: ok(settings()),
  [`/v2/organizations/${ORG}/administratorlinks`]: ok([{ administrator: "a1", organization: ORG }, { administrator: "a2", organization: ORG }]),
  "/v2/authn/policies": ok([policy("p1"), policy("p2", { type: "application" }), policy("p3", { mfa: false, disabled: true })]),
  "/systemusers": v1([user("u1"), user("u2", { totp: "NOT_ENROLLED", overall: "ENROLLED", webauthn: "ENROLLED" }), user("u3", { state: "SUSPENDED", suspended: true, required: false, overall: "NOT_ENROLLED", totp: "NOT_ENROLLED" })]),
  "/systems": v1([system("s1", "C02TEST0001"), system("s2", "PF3TEST2", { os: "Windows", family: "windows", version: "10.0.22631" })]),
});
export const withUser = (o: U): Routes => ({ "/systemusers": v1([user("u1"), user("u9", o)]) });
export const withSystem = (o: S): Routes => ({ "/systems": v1([system("s1", "C02TEST0001"), system("s9", "C02TEST0009", o)]) });
export const withPw = (pw: Record<string, unknown>): Routes => ({ [`/organizations/${ORG}`]: ok(settings(pw)) });

export const C: Contract = {
  source: jumpcloud, clientKey: "jumpcloud", base: BASE, prefix: "jumpcloud", strong,
  opts: { "jumpcloud-min-os": ["macos=14.0", "windows=10.0.22631"] },
  env: { JUMPCLOUD_API_KEY: "jca_x" },
  rateLimited: { path: "/systems", check: "device_encrypted" },
  fails: {
    users_mfa_enrolled: withUser({ overall: "NOT_ENROLLED", totp: "IN_ENROLLMENT" }),
    users_mfa_required: { ...withUser({ required: false }), "/v2/authn/policies": ok([policy("p2", { type: "application" })]) },
    policies_require_mfa: { "/v2/authn/policies": ok([policy("p1"), policy("p4", { mfa: false })]) },
    admin_mfa_required: { [`/organizations/${ORG}`]: ok(settings({}, false)) },
    admins_limited: { [`/v2/organizations/${ORG}/administratorlinks`]: ok(["a1", "a2", "a3", "a4", "a5", "a6"].map((a) => ({ administrator: a, organization: ORG }))) },
    password_policy: withPw({ minLength: 8 }),
    account_lockout: withPw({ enableMaxLoginAttempts: false }),
    device_encrypted: withSystem({ fde: false }),
    device_os_minimum: withSystem({ version: "13.6.9" }),
    device_last_contact: withSystem({ contact: daysAgo(30) }),
  },
};
