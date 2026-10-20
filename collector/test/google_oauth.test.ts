// The Google Workspace browser sign-in (google-login) and the token-file path, against a fake Google token
// endpoint. The loopback listener is real; Google's consent page is played by the test's `open`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Deps } from "../src/cli.ts";
import { main } from "../src/cli.ts";
import { googleLogin, type LoginIo } from "../src/google_login.ts";
import { GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL, authUrl, pkce, readClient, readTokenFile, writeTokenFile } from "../src/sources/google_oauth.ts";
import { ADMIN_BASE, GOOGLE_SCOPES, googleFromEnv, googleWorkspace } from "../src/sources/google_workspace.ts";
import { NOW } from "./helpers.ts";

const CLIENT_ID = "123-abc.apps.googleusercontent.com";
const CLIENT_SECRET = "GOCSPX-client-secret-0042";
const REFRESH = "1//refresh-token-must-never-print-0042";
const ACCESS = "ya29.access-token-must-never-print-0042";

function dir() { return mkdtempSync(join(tmpdir(), "collector-goauth-")); }
function clientFile(d: string, doc: unknown = { installed: { client_id: CLIENT_ID, project_id: "p", auth_uri: "https://evil.example/auth", token_uri: "https://evil.example/token", client_secret: CLIENT_SECRET, redirect_uris: ["http://localhost"] } }) {
  const p = join(d, "client.json"); writeFileSync(p, JSON.stringify(doc)); return p;
}
function deps(env: Record<string, string> = {}) {
  const lines: string[] = [];
  const d: Deps = { fetch: (() => { throw new Error("no sos-app call expected"); }) as unknown as typeof fetch, clients: {}, sources: [], env, now: () => NOW,
    out: (s) => lines.push(s), err: (s) => lines.push(s) };
  return { d, lines };
}

/** Plays Google: on `open`, redirects the browser to the loopback URI with a code (or what `redirect` says). */
function google(o: { redirect?: (u: URL) => string[]; scope?: string; tokenStatus?: number } = {}) {
  const posts: URLSearchParams[] = [];
  let auth: URL | undefined;
  const statuses: number[] = [];
  const io: LoginIo = {
    timeoutMs: 5_000,
    open: (url) => {
      auth = new URL(url);
      const back = auth.searchParams.get("redirect_uri")!, state = auth.searchParams.get("state")!;
      const queries = o.redirect ? o.redirect(auth) : [`code=4/auth-code&state=${state}&scope=${encodeURIComponent(GOOGLE_SCOPES.join(" "))}`];
      void (async () => { for (const q of queries) statuses.push((await fetch(`${back}/?${q}`)).status); })();
    },
    fetchFn: (async (url: string, init: RequestInit) => {
      assert.equal(url, GOOGLE_TOKEN_URL);
      assert.equal(init.method, "POST");
      posts.push(new URLSearchParams(String(init.body)));
      return new Response(JSON.stringify({ access_token: ACCESS, expires_in: 3599, refresh_token: REFRESH, scope: o.scope ?? GOOGLE_SCOPES.join(" "), token_type: "Bearer" }), { status: o.tokenStatus ?? 200 });
    }) as unknown as typeof fetch,
  };
  return { io, posts, statuses, auth: () => auth! };
}

test("google-login: loopback + PKCE sign-in writes the refresh token 0600 and prints no token or secret", async () => {
  const d = dir(), token = join(d, "tok.json");
  const g = google();
  const { d: dp, lines } = deps();
  assert.equal(await googleLogin(["--client", clientFile(d), "--token", token], dp, g.io), 0, lines.join("\n"));
  const a = g.auth();
  assert.equal(`${a.origin}${a.pathname}`, GOOGLE_AUTH_URL);
  assert.match(a.searchParams.get("redirect_uri")!, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(a.searchParams.get("code_challenge_method"), "S256");
  assert.equal(a.searchParams.get("response_type"), "code");
  assert.deepEqual(a.searchParams.get("scope")!.split(" "), GOOGLE_SCOPES);
  for (const s of GOOGLE_SCOPES) assert.match(s, /\.readonly$/);
  assert.equal(g.posts.length, 1);
  const p = g.posts[0];
  assert.equal(p.get("grant_type"), "authorization_code");
  assert.equal(p.get("code"), "4/auth-code");
  assert.equal(p.get("redirect_uri"), a.searchParams.get("redirect_uri"));
  assert.equal(createHash("sha256").update(p.get("code_verifier")!).digest("base64url"), a.searchParams.get("code_challenge"));
  assert.equal(p.get("client_secret"), CLIENT_SECRET);
  assert.equal(statSync(token).mode & 0o777, 0o600);
  const saved = JSON.parse(readFileSync(token, "utf8"));
  assert.equal(saved.refresh_token, REFRESH);
  assert.equal(saved.client_id, CLIENT_ID);
  assert.equal(saved.access_token, undefined, "the access token is never stored");
  const said = lines.join("\n");
  for (const secret of [REFRESH, ACCESS, CLIENT_SECRET, "4/auth-code"]) assert.ok(!said.includes(secret), `printed ${secret}`);
});

test("google-login: a redirect with the wrong state is refused and the right one still completes", async () => {
  const d = dir(), token = join(d, "tok.json");
  const g = google({ redirect: (u) => [`code=4/forged&state=0000`, `code=4/auth-code&state=${u.searchParams.get("state")}`] });
  const { d: dp } = deps();
  assert.equal(await googleLogin(["--client", clientFile(d), "--token", token], dp, g.io), 0);
  assert.equal(g.statuses[0], 404);
  assert.equal(g.posts[0].get("code"), "4/auth-code");
});

test("google-login: a scope left unticked, a declined consent or a refused exchange writes nothing", async () => {
  for (const g of [
    google({ scope: GOOGLE_SCOPES[0] }),
    google({ redirect: (u) => [`error=access_denied&state=${u.searchParams.get("state")}`] }),
    google({ tokenStatus: 400 }),
  ]) {
    const d = dir(), token = join(d, "tok.json");
    const { d: dp, lines } = deps();
    assert.equal(await googleLogin(["--client", clientFile(d), "--token", token], dp, g.io), 1);
    assert.equal(existsSync(token), false, lines.join("\n"));
    assert.ok(!lines.join("\n").includes(REFRESH));
  }
});

test("google-login: only a Desktop app client file is taken; usage errors exit 2", async () => {
  const d = dir();
  assert.match(String(readClient(clientFile(d, { web: { client_id: CLIENT_ID } }))), /Desktop app/);
  assert.match(String(readClient(clientFile(d, { installed: { client_id: "x" } }))), /no Desktop app client/);
  assert.deepEqual(readClient(clientFile(d, { installed: { client_id: CLIENT_ID } })), { clientId: CLIENT_ID });
  const { d: dp } = deps();
  assert.equal(await main(["google-login"], dp), 2);
  assert.equal(await main(["google-login", "--bogus"], dp), 2);
});

test("pkce and the consent URL: a 43-character verifier, its S256 challenge, a fresh refresh token each sign-in", () => {
  const { verifier, challenge } = pkce();
  assert.equal(verifier.length, 43);
  assert.equal(challenge, createHash("sha256").update(verifier).digest("base64url"));
  const u = new URL(authUrl({ clientId: CLIENT_ID, redirectUri: "http://127.0.0.1:1234", scopes: GOOGLE_SCOPES, challenge, state: "s", loginHint: "admin@example.com" }));
  assert.equal(u.searchParams.get("prompt"), "consent");
  assert.equal(u.searchParams.get("login_hint"), "admin@example.com");
  assert.equal(u.searchParams.get("code_verifier"), null, "the verifier never leaves the machine before the exchange");
});

function oauthEnv(d: string, scopes = GOOGLE_SCOPES) {
  const token = join(d, "tok.json");
  writeTokenFile(token, { type: "sagentix_google_oauth", client_id: CLIENT_ID, refresh_token: REFRESH, scopes, created: NOW.toISOString() });
  return { GOOGLE_OAUTH_CLIENT_FILE: clientFile(d), GOOGLE_OAUTH_TOKEN_FILE: token };
}

test("google_workspace with the token file: one refresh grant to Google, then only GETs; no token reaches a result", async () => {
  const env = oauthEnv(dir());
  const seen: { url: string; method: string; body?: string }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    seen.push({ url, method: String(init.method), body: init.body as string | undefined });
    if (url === GOOGLE_TOKEN_URL) return new Response(JSON.stringify({ access_token: ACCESS, expires_in: 3599 }), { status: 200 });
    return new Response(JSON.stringify({ error: { code: 403, message: `Not Authorized (${(init.headers as Record<string, string>).authorization})` } }), { status: 403 });
  }) as unknown as typeof fetch;
  const api = googleFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string", String(api));
  const rs = await googleWorkspace.run({ opts: {}, env, clients: { google: api, sleep: async () => {} }, now: NOW, warn: () => {} });
  const tok = seen.filter((s) => s.url === GOOGLE_TOKEN_URL);
  assert.equal(tok.length, 1);
  const form = new URLSearchParams(tok[0].body);
  assert.equal(form.get("grant_type"), "refresh_token");
  assert.equal(form.get("refresh_token"), REFRESH);
  assert.equal(form.get("client_id"), CLIENT_ID);
  for (const s of seen.filter((x) => x.url !== GOOGLE_TOKEN_URL)) { assert.equal(s.method, "GET"); assert.ok(s.url.startsWith(`${ADMIN_BASE}/admin/`), s.url); }
  const text = JSON.stringify(rs);
  for (const secret of [REFRESH, ACCESS, CLIENT_SECRET]) assert.ok(!text.includes(secret));
  assert.ok(!seen.some((s) => s.url.includes("evil.example")), "the client file's endpoints are ignored");
});

test("google_workspace: the service-account key wins when both are set", () => {
  const env = { ...oauthEnv(dir()), GOOGLE_SA_KEY_FILE: "/nonexistent/sa.json", GOOGLE_ADMIN_EMAIL: "a@example.com" };
  assert.match(String(googleFromEnv(env)), /GOOGLE_SA_KEY_FILE is not a readable service account key/);
  assert.match(String(googleFromEnv({})), /GOOGLE_OAUTH_CLIENT_FILE after `collector google-login`/);
});

test("the token file is refused when others can read it, when it belongs to another client or lacks a scope", () => {
  const d = dir(), env = oauthEnv(d);
  const client = readClient(env.GOOGLE_OAUTH_CLIENT_FILE);
  assert.ok(typeof client !== "string");
  assert.equal(readTokenFile(env.GOOGLE_OAUTH_TOKEN_FILE, client, GOOGLE_SCOPES), REFRESH);
  if (process.platform !== "win32") {
    chmodSync(env.GOOGLE_OAUTH_TOKEN_FILE, 0o644);
    assert.match(String(googleFromEnv(env)), /readable by other users \(mode 644\)/);
    chmodSync(env.GOOGLE_OAUTH_TOKEN_FILE, 0o600);
  }
  assert.deepEqual(readTokenFile(env.GOOGLE_OAUTH_TOKEN_FILE, { clientId: "other.apps.googleusercontent.com" }, GOOGLE_SCOPES), { error: `${env.GOOGLE_OAUTH_TOKEN_FILE} was made with another OAuth client; run \`collector google-login\` again` });
  const narrow = oauthEnv(dir(), GOOGLE_SCOPES.slice(0, 1));
  assert.match(String(googleFromEnv(narrow)), /lacks .*admin\.reports\.audit\.readonly.*google-login/);
  assert.match(String(googleFromEnv({ GOOGLE_OAUTH_CLIENT_FILE: env.GOOGLE_OAUTH_CLIENT_FILE, GOOGLE_OAUTH_TOKEN_FILE: join(d, "missing.json") })), /run `collector google-login` first/);
});

test("a revoked sign-in (invalid_grant) skips every check with the way to mend it", async () => {
  const env = oauthEnv(dir());
  const fetchFn = (async () => new Response(JSON.stringify({ error: "invalid_grant", error_description: "Token has been expired or revoked." }), { status: 400 })) as unknown as typeof fetch;
  const api = googleFromEnv(env, fetchFn);
  assert.ok(typeof api !== "string");
  const rs = await googleWorkspace.run({ opts: {}, env, clients: { google: api, sleep: async () => {} }, now: NOW, warn: () => {} });
  assert.ok(rs.length > 0);
  for (const r of rs) {
    assert.equal(r.result, "skipped");
    // Drive sharing reads the Policy API, which the sign-in never asks for (2026-10-20): it says so instead.
    assert.match(r.detail, r.check.endsWith("drive_external_sharing_restricted") ? /browser sign-in does not ask for/ : /invalid_grant: the sign-in was revoked or has expired; run `collector google-login` again/);
  }
});

test("google-login --port listens on that loopback port, for an SSH tunnel; a bad or busy port is refused", async () => {
  const free = await new Promise<number>((r) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = (s.address() as AddressInfo).port; s.close(() => r(p)); }); });
  const d = dir(), g = google();
  const { d: dp, lines } = deps();
  assert.equal(await googleLogin(["--client", clientFile(d), "--token", join(d, "tok.json"), "--port", String(free)], dp, g.io), 0, lines.join("\n"));
  assert.equal(g.auth().searchParams.get("redirect_uri"), `http://127.0.0.1:${free}`);
  assert.match(lines.join("\n"), new RegExp(`SSH tunnel to port ${free}`));
  for (const bad of ["80", "70000", "x"]) assert.equal(await googleLogin(["--client", clientFile(d), "--port", bad], deps().d, g.io), 2);
  const busy = createServer().listen(free, "127.0.0.1");
  await new Promise((r) => busy.once("listening", r));
  const b = deps();
  assert.equal(await googleLogin(["--client", clientFile(d), "--token", join(d, "t2.json"), "--port", String(free)], b.d, g.io), 1);
  assert.match(b.lines.join("\n"), /cannot listen on 127\.0\.0\.1:\d+: EADDRINUSE/);
  busy.close();
});

test("the Drive sharing check says the browser sign-in cannot read the Policy API, instead of asking for a key", async () => {
  const { googlePolicyFromEnv } = await import("../src/sources/google_workspace.ts");
  const got = googlePolicyFromEnv({ GOOGLE_OAUTH_CLIENT_FILE: "google-oauth-client.json" } as NodeJS.ProcessEnv);
  assert.equal(typeof got, "string");
  assert.match(got as string, /browser sign-in does not ask for https:\/\/www\.googleapis\.com\/auth\/cloud-identity\.policies\.readonly/);
  assert.match(googlePolicyFromEnv({} as NodeJS.ProcessEnv) as string, /GOOGLE_SA_KEY_FILE and GOOGLE_ADMIN_EMAIL are not both set/);
});
