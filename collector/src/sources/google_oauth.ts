// Google Workspace without a service-account key: a Workspace admin signs in once through the browser
// (`collector google-login`), and the collector keeps the refresh token in a 0600 file. Google Cloud
// organizations created since 2024 refuse service-account key creation by default
// (constraints/iam.disableServiceAccountKeyCreation), which is what this path avoids.
//
// The OAuth client is the customer's own: a "Desktop app" client in their Google Cloud project, with the
// consent screen's audience set to Internal. Google's pages, read 2026-10-20:
//   developers.google.com/identity/protocols/oauth2/native-app (updated 2026-10-16): loopback redirect
//     http://127.0.0.1:<port>, PKCE with S256, endpoints accounts.google.com/o/oauth2/v2/auth and
//     oauth2.googleapis.com/token, "Desktop apps are public clients and cannot keep secrets confidential",
//     client_secret optional in the code exchange, refresh tokens always returned for installed apps.
//   developers.google.com/identity/protocols/oauth2 (updated 2026-10-16): the 7-day refresh-token expiry is
//     for an External user type in "Testing"; a token also stops after six months unused, on revocation, or
//     past 100 refresh tokens per account per client.
//   support.google.com/cloud/answer/13464323: an Internal app needs no verification.
//
// Both endpoints are fixed here; the client file's auth_uri and token_uri are not read, so a tampered file
// cannot send the code or the refresh token elsewhere. Nothing here prints or logs a token.

import { randomBytes, createHash } from "node:crypto";
import { closeSync, fstatSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { cachedToken, tokenRequest } from "./oauth.ts";

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const OAUTH_ENV = { clientFile: "GOOGLE_OAUTH_CLIENT_FILE", tokenFile: "GOOGLE_OAUTH_TOKEN_FILE" } as const;
/** The token file when GOOGLE_OAUTH_TOKEN_FILE is unset: in the folder the collector runs from, beside its config. */
export const DEFAULT_TOKEN_FILE = "sagentix-google-token.json";
const TOKEN_TYPE = "sagentix_google_oauth";

export interface OAuthClient { clientId: string; clientSecret?: string }
export interface TokenFile { type: typeof TOKEN_TYPE; client_id: string; refresh_token: string; scopes: string[]; created: string }

export const tokenPath = (env: NodeJS.ProcessEnv) => env[OAUTH_ENV.tokenFile] || DEFAULT_TOKEN_FILE;

/** The client JSON downloaded from the Google Cloud console's Clients page; only a Desktop app client ("installed") is taken. */
export function readClient(path: string): OAuthClient | string {
  let doc: Record<string, unknown>;
  try { doc = JSON.parse(readFileSync(path, "utf8")); } catch (e) { return `${path} is not a readable OAuth client file (${(e as NodeJS.ErrnoException).code ?? "bad JSON"})`; }
  if (doc && typeof doc === "object" && "web" in doc) return `${path} is a "Web application" client; create a "Desktop app" client instead`;
  const c = (doc as { installed?: Record<string, unknown> }).installed;
  if (!c || typeof c.client_id !== "string" || !c.client_id.endsWith(".apps.googleusercontent.com")) return `${path} holds no Desktop app client (installed.client_id)`;
  return { clientId: c.client_id, ...(typeof c.client_secret === "string" && c.client_secret ? { clientSecret: c.client_secret } : {}) };
}

/** A PKCE pair: a 43-character verifier and its S256 challenge. */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export function authUrl(o: { clientId: string; redirectUri: string; scopes: string[]; challenge: string; state: string; loginHint?: string }): string {
  const q = new URLSearchParams({
    client_id: o.clientId, redirect_uri: o.redirectUri, response_type: "code", scope: o.scopes.join(" "),
    code_challenge: o.challenge, code_challenge_method: "S256", state: o.state,
    // A new refresh token on every sign-in, so running google-login again replaces a revoked one.
    prompt: "consent",
    ...(o.loginHint ? { login_hint: o.loginHint } : {}),
  });
  return `${GOOGLE_AUTH_URL}?${q}`;
}

/** Writes the token file with mode 0600, replacing any earlier one in one rename. */
export function writeTokenFile(path: string, t: TokenFile): void {
  const tmp = join(dirname(path), `.${TOKEN_TYPE}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  writeFileSync(tmp, JSON.stringify(t, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  renameSync(tmp, path);
}

/** The refresh token, or why it cannot be used. */
export function readTokenFile(path: string, client: OAuthClient, scopes: string[]): string | { error: string } {
  // One open, then the mode and the bytes from that same descriptor: a file swapped between a stat and a read by
  // path (CodeQL js/file-system-race) cannot pass the mode check and hand over other contents.
  let fd: number;
  try { fd = openSync(path, "r"); } catch (e) { return { error: `${path} cannot be read (${(e as NodeJS.ErrnoException).code}); run \`collector google-login\` first` }; }
  let raw: string;
  try {
    const st = fstatSync(fd);
    // The file holds a refresh token, so, like an SSH key, it is refused when other users can read it.
    if (process.platform !== "win32" && (st.mode & 0o077) !== 0) return { error: `${path} is readable by other users (mode ${(st.mode & 0o777).toString(8)}); run chmod 600 on it` };
    raw = readFileSync(fd, "utf8");
  } finally { closeSync(fd); }
  let t: Partial<TokenFile>;
  try { t = JSON.parse(raw); } catch { return { error: `${path} is not JSON` }; }
  if (t.type !== TOKEN_TYPE || typeof t.refresh_token !== "string" || !t.refresh_token) return { error: `${path} is not a token file written by \`collector google-login\`` };
  if (t.client_id !== client.clientId) return { error: `${path} was made with another OAuth client; run \`collector google-login\` again` };
  const missing = scopes.filter((s) => !(t.scopes ?? []).includes(s));
  if (missing.length) return { error: `${path} lacks ${missing.join(", ")}; run \`collector google-login\` again to grant it` };
  return t.refresh_token;
}

/** An access-token function for the Admin SDK client: refreshes in memory, never writes the access token anywhere. */
export function googleOAuthFromEnv(env: NodeJS.ProcessEnv, scopes: string[], fetchFn: typeof fetch = fetch): (() => Promise<string>) | string {
  const clientFile = env[OAUTH_ENV.clientFile];
  if (!clientFile) return `${OAUTH_ENV.clientFile} is not set`;
  const client = readClient(clientFile);
  if (typeof client === "string") return client;
  const refresh = readTokenFile(tokenPath(env), client, scopes);
  if (typeof refresh !== "string") return refresh.error;
  return cachedToken(async () => {
    try {
      return await tokenRequest(GOOGLE_TOKEN_URL, {
        grant_type: "refresh_token", refresh_token: refresh, client_id: client.clientId,
        ...(client.clientSecret ? { client_secret: client.clientSecret } : {}),
      }, fetchFn);
    } catch (e) {
      const m = (e as Error).message;
      // invalid_grant: revoked, unused for six months, or pushed out by newer tokens; only a new sign-in mends it.
      throw new Error(/invalid_grant/.test(m) ? `${m}: the sign-in was revoked or has expired; run \`collector google-login\` again` : m);
    }
  });
}
