// `collector google-login`: a Workspace admin signs in once, in the browser, and the collector stores the
// refresh token it gets (mode 0600). OAuth 2.0 for installed apps with a loopback redirect and PKCE
// (developers.google.com/identity/protocols/oauth2/native-app, read 2026-10-20):
//
//   1 listen on 127.0.0.1 at a port the system picks (or --port, for an SSH tunnel to a server without a
//     browser: ssh -L <port>:127.0.0.1:<port> <server>); the redirect URI is http://127.0.0.1:<port>
//   2 open Google's consent page with a fresh S256 challenge and a random state
//   3 take the one redirect whose state matches, then stop listening
//   4 exchange the code with the verifier, check every read-only scope was granted, write the token file
//
// The listener answers only that redirect and only on the loopback address. The authorization URL holds no
// secret and is printed so it can be pasted into a browser on the same machine. No token is ever printed.

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Deps } from "./cli.ts";
import { GOOGLE_SCOPES } from "./sources/google_workspace.ts";
import { GOOGLE_TOKEN_URL, OAUTH_ENV, authUrl, pkce, readClient, tokenPath, writeTokenFile } from "./sources/google_oauth.ts";
import { tokenGrant } from "./sources/oauth.ts";

export interface LoginIo {
  /** Opens the URL in the person's browser; the default calls the system's opener without a shell. */
  open: (url: string) => void;
  /** For the code exchange only. */
  fetchFn: typeof fetch;
  timeoutMs: number;
}

export function openBrowser(url: string): void {
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]]
    : process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
    : ["xdg-open", [url]];
  try { spawn(cmd, args, { stdio: "ignore", detached: true }).on("error", () => { /* the URL is printed too */ }).unref(); } catch { /* idem */ }
}

const PAGE = (msg: string) => `<!doctype html><meta charset="utf-8"><title>Sagentix collector</title><p>${msg}</p>`;
const same = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** Waits for Google's redirect to the loopback listener: the code, or the error Google sent. */
function awaitRedirect(state: string, timeoutMs: number, port: number): Promise<{ port: number; result: Promise<{ code: string } | { error: string }> }> {
  return new Promise((ready, fail) => {
    let settle: (r: { code: string } | { error: string }) => void;
    const result = new Promise<{ code: string } | { error: string }>((r) => { settle = r; });
    const server = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      const got = u.searchParams.get("state");
      if (req.method !== "GET" || u.pathname !== "/" || !got || !same(got, state)) {
        res.writeHead(404, { "content-type": "text/plain" }).end("not found");
        return;
      }
      const code = u.searchParams.get("code"), error = u.searchParams.get("error");
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" })
        .end(PAGE(code ? "Signed in. You can close this tab and return to the terminal." : "Sign-in did not complete. Return to the terminal."));
      done(code ? { code } : { error: error ?? "no code in the redirect" });
    });
    const timer = setTimeout(() => done({ error: `no sign-in within ${Math.round(timeoutMs / 1000)} s` }), timeoutMs);
    const done = (r: { code: string } | { error: string }) => { clearTimeout(timer); server.close(); server.closeAllConnections(); settle(r); };
    server.on("error", (e) => { clearTimeout(timer); fail(e); });
    server.listen(port, "127.0.0.1", () => ready({ port: (server.address() as AddressInfo).port, result }));
  });
}

export async function googleLogin(argv: string[], deps: Deps, io: LoginIo = { open: openBrowser, fetchFn: globalThis.fetch, timeoutMs: 300_000 }): Promise<number> {
  let values: { client?: string; token?: string; port?: string; "login-hint"?: string; "no-browser"?: boolean };
  try {
    ({ values } = parseArgs({ args: argv, strict: true, options: {
      client: { type: "string" }, token: { type: "string" }, port: { type: "string" }, "login-hint": { type: "string" }, "no-browser": { type: "boolean" },
    } }));
  } catch (e) {
    deps.err(`${(e as Error).message}\nusage: collector google-login --client <client JSON> [--token <file>] [--port <n>] [--login-hint <admin email>] [--no-browser]`);
    return 2;
  }
  const port = values.port === undefined ? 0 : Number(values.port);
  if (values.port !== undefined && (!Number.isInteger(port) || port < 1024 || port > 65535)) { deps.err("--port must be a whole number from 1024 to 65535."); return 2; }
  const clientFile = values.client ?? deps.env[OAUTH_ENV.clientFile];
  if (!clientFile) { deps.err(`--client (or ${OAUTH_ENV.clientFile}) is required: the Desktop app client JSON from your Google Cloud project.`); return 2; }
  const client = readClient(clientFile);
  if (typeof client === "string") { deps.err(client); return 1; }
  const out = resolve(values.token ?? tokenPath(deps.env));

  const { verifier, challenge } = pkce();
  const state = randomBytes(16).toString("hex");
  let listening: Awaited<ReturnType<typeof awaitRedirect>>;
  try { listening = await awaitRedirect(state, io.timeoutMs, port); } catch (e) { deps.err(`google-login: cannot listen on 127.0.0.1:${port}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); return 1; }
  const { result } = listening;
  const redirectUri = `http://127.0.0.1:${listening.port}`;
  const url = authUrl({ clientId: client.clientId, redirectUri, scopes: GOOGLE_SCOPES, challenge, state, loginHint: values["login-hint"] });
  deps.err("Sign in as a Google Workspace admin who can read users and the admin audit log. Read-only scopes requested:");
  for (const s of GOOGLE_SCOPES) deps.err(`  ${s}`);
  deps.err(`If no browser opens, paste this address into a browser on this machine${port ? ` (or on the computer holding the SSH tunnel to port ${port})` : ""}:\n${url}`);
  if (!values["no-browser"]) io.open(url);

  const got = await result;
  if ("error" in got) { deps.err(`google-login: ${got.error === "access_denied" ? "the sign-in was declined" : got.error}.`); return 1; }
  let body: Record<string, unknown>;
  try {
    body = await tokenGrant(GOOGLE_TOKEN_URL, {
      grant_type: "authorization_code", code: got.code, code_verifier: verifier, redirect_uri: redirectUri, client_id: client.clientId,
      ...(client.clientSecret ? { client_secret: client.clientSecret } : {}),
    }, io.fetchFn);
  } catch (e) { deps.err(`google-login: ${(e as Error).message}`); return 1; }
  if (typeof body.refresh_token !== "string" || !body.refresh_token) { deps.err("google-login: Google returned no refresh token; run the command again."); return 1; }
  const granted = typeof body.scope === "string" ? body.scope.split(" ") : [];
  const missing = GOOGLE_SCOPES.filter((s) => !granted.includes(s));
  if (missing.length) { deps.err(`google-login: not granted: ${missing.join(", ")}. Run the command again and allow every box; nothing was written.`); return 1; }
  try {
    writeTokenFile(out, { type: "sagentix_google_oauth", client_id: client.clientId, refresh_token: body.refresh_token, scopes: GOOGLE_SCOPES, created: deps.now().toISOString() });
  } catch (e) { deps.err(`google-login: cannot write ${out}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); return 1; }
  deps.err(`Refresh token written to ${out} (mode 0600). Set ${OAUTH_ENV.clientFile}=${resolve(clientFile)} and ${OAUTH_ENV.tokenFile}=${out} for \`collector run\`; keep both files off any shared drive.`);
  return 0;
}
