// The Google Workspace source against a fake Admin SDK.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ADMIN_BASE, GOOGLE_SCOPES, googleFromEnv, googleWorkspace, isGoogleTokenUri } from "../src/sources/google_workspace.ts";
import { googleAssertion } from "../src/sources/oauth.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const USERS = "/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic";
const REPORT = "/admin/reports/v1/activity/users/all/applications/admin";
const ok = (b: unknown) => res(200, b);
const user = (id: string, o: Record<string, unknown> = {}) => ({ id, primaryEmail: `${id}@example.com`, isEnrolledIn2Sv: true, isEnforcedIn2Sv: true, isAdmin: false, suspended: false, archived: false, creationTime: daysAgo(400), lastLoginTime: daysAgo(3), ...o });

function users(page1: unknown[], page2: unknown[]): Routes {
  return {
    [USERS]: ok({ kind: "admin#directory#users", users: page1, nextPageToken: "tok2" }),
    [`${USERS}&pageToken=tok2`]: ok({ kind: "admin#directory#users", users: page2 }),
  };
}

function strong(): Routes {
  return {
    ...users([user("1", { isAdmin: true }), user("2")], [user("3", { isDelegatedAdmin: true }), user("4", { suspended: true, isEnrolledIn2Sv: false, lastLoginTime: "1970-01-01T00:00:00.000Z" })]),
    [REPORT]: ok({ kind: "admin#reports#activities", items: [{ id: { time: daysAgo(0), applicationName: "admin" } }] }),
  };
}

const C: Contract = {
  source: googleWorkspace, clientKey: "google", base: ADMIN_BASE, prefix: "google_workspace", strong,
  rateLimited: { path: REPORT, check: "audit_reports_available" },
  fails: {
    two_step_enrolled: users([user("1", { isAdmin: true }), user("2", { isEnrolledIn2Sv: false })], []),
    two_step_enforced: users([user("1", { isAdmin: true }), user("2", { isEnforcedIn2Sv: false })], []),
    admins_two_step: users([user("1", { isAdmin: true, isEnrolledIn2Sv: false })], []),
    super_admins_limited: users(["1", "2", "3", "4", "5"].map((i) => user(i, { isAdmin: true })), []),
    inactive_users: users([user("1", { isAdmin: true }), user("2", { lastLoginTime: daysAgo(200) })], [user("3", { lastLoginTime: "1970-01-01T00:00:00.000Z", creationTime: daysAgo(300) })]),
    audit_reports_available: { [REPORT]: ok({ kind: "admin#reports#activities" }) },
  },
};

contractSuite(C);

test("google_workspace: users are read across nextPageToken pages; suspended users are not judged", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(ADMIN_BASE, strong(), calls));
  assert.ok(calls.includes(`${USERS}&pageToken=tok2`));
  assert.match(of(rs, "google_workspace.two_step_enrolled")[0].detail, /^3 of 3 active/);
  assert.match(of(rs, "google_workspace.inactive_users")[0].detail, /1 suspended or archived not counted/);
});

test("google_workspace: failing details carry Google user ids, never addresses", async () => {
  const rs = await runWith(C, fakeRest(ADMIN_BASE, { ...strong(), ...C.fails.two_step_enrolled }));
  assert.match(of(rs, "google_workspace.two_step_enrolled")[0].detail, /\(2\)/);
  assert.doesNotMatch(JSON.stringify(rs), /@example\.com/);
});

test("google_workspace: a 403 rateLimitExceeded is retried, a plain 403 is not", async () => {
  const waits: number[] = [];
  const rs = await runWith(C, fakeRest(ADMIN_BASE, { ...strong(),
    [REPORT]: (u, n) => (n === 1 ? res(403, { error: { code: 403, message: "Quota exceeded", errors: [{ reason: "rateLimitExceeded" }] } }) : strong()[REPORT] as ReturnType<typeof res>) }), { waits });
  assert.equal(waits.length, 1);
  assert.equal(of(rs, "google_workspace.audit_reports_available")[0].result, "pass");
  const w2: number[] = [];
  const rs2 = await runWith(C, fakeRest(ADMIN_BASE, { ...strong(), [REPORT]: res(403, { error: { code: 403, message: "Not Authorized to access this resource/api" } }) }), { waits: w2 });
  assert.equal(w2.length, 0);
  assert.equal(of(rs2, "google_workspace.audit_reports_available")[0].result, "skipped");
});

test("google_workspace: the service-account assertion is signed RS256 and acts as the admin with read-only scopes", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const a = googleAssertion({ client_email: "collector@p.iam.gserviceaccount.com", private_key: pem }, "reader@example.com", GOOGLE_SCOPES, 1_760_000_000);
  const [h, c, s] = a.split(".");
  assert.ok(verify("sha256", Buffer.from(`${h}.${c}`), publicKey, Buffer.from(s, "base64url")));
  const claims = JSON.parse(Buffer.from(c, "base64url").toString());
  assert.equal(JSON.parse(Buffer.from(h, "base64url").toString()).alg, "RS256");
  assert.equal(claims.sub, "reader@example.com");
  assert.equal(claims.aud, "https://oauth2.googleapis.com/token");
  for (const sc of claims.scope.split(" ")) assert.match(sc, /\.readonly$/);
  assert.equal(claims.exp - claims.iat, 3600);
});

test("google_workspace: the fetch client exchanges the assertion once, then only GETs; the token never reaches a result", async () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dir = mkdtempSync(join(tmpdir(), "collector-gws-"));
  const keyFile = join(dir, "sa.json");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  writeFileSync(keyFile, JSON.stringify({ type: "service_account", client_email: "c@p.iam.gserviceaccount.com", private_key: pem, token_uri: "https://oauth2.googleapis.com/token" }));
  const seen: { url: string; method: string; auth?: string; body?: string }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    const h = init.headers as Record<string, string>;
    seen.push({ url, method: String(init.method), auth: h.authorization, body: init.body as string | undefined });
    if (url === "https://oauth2.googleapis.com/token") return new Response(JSON.stringify({ access_token: "ya29.google-access-token-0042", expires_in: 3599 }), { status: 200 });
    return new Response(JSON.stringify({ error: { code: 403, message: `Not Authorized (${h.authorization})` } }), { status: 403 });
  }) as unknown as typeof fetch;
  const env = { GOOGLE_SA_KEY_FILE: keyFile, GOOGLE_ADMIN_EMAIL: "reader@example.com" };
  const api = googleFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string", String(api));
  const rs = await runWith(C, api, { env });
  const tok = seen.filter((s) => s.url.endsWith("/token"));
  assert.equal(tok.length, 1);
  assert.equal(tok[0].method, "POST");
  assert.match(tok[0].body!, /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer/);
  for (const s of seen.filter((x) => !x.url.endsWith("/token"))) {
    assert.equal(s.method, "GET");
    assert.ok(s.url.startsWith(`${ADMIN_BASE}/admin/`), s.url);
  }
  assert.ok(!JSON.stringify(rs).includes("ya29.google-access-token-0042"));
  assert.ok(!JSON.stringify(rs).includes(pem.split("\n")[1]), "no part of the private key");
  for (const r of rs) assert.equal(r.result, "skipped");
});

test("a key file whose token_uri leaves googleapis.com over HTTPS is refused before any request", () => {
  for (const bad of ["https://evil.example/token", "http://oauth2.googleapis.com/token", "https://oauth2.googleapis.com.evil.example/token"]) assert.equal(isGoogleTokenUri(bad), false, bad);
  assert.equal(isGoogleTokenUri("https://oauth2.googleapis.com/token"), true);
});
