// OAuth token requests for the identity sources. These are the only POSTs the collector's sources
// make, and they go to the identity provider's token endpoint, never to a resource API.
//
//   Entra ID: client-credentials grant, with a client secret or a certificate-signed client assertion
//     (PS256, x5t#S256; learn.microsoft.com/entra/identity-platform/certificate-credentials).
//   Google:   service-account JWT bearer grant with domain-wide delegation (RS256, `sub` = the admin
//     the account acts as; developers.google.com/identity/protocols/oauth2/service-account).
//
// A failed token request throws an Error whose message names the HTTP status and the provider's
// error code, never the secret.

import { X509Certificate, constants, createHash, createPrivateKey, randomUUID, sign } from "node:crypto";

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");

function jwt(header: object, claims: object, key: string, pss: boolean): string {
  const data = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const k = createPrivateKey(key);
  const sig = pss
    ? sign("sha256", Buffer.from(data), { key: k, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST })
    : sign("sha256", Buffer.from(data), k);
  return `${data}.${b64url(sig)}`;
}

/** A client assertion for Entra ID from a PEM that holds the certificate and its private key. */
export function entraClientAssertion(pem: string, tenant: string, clientId: string, nowSec: number): string {
  const certPem = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0];
  if (!certPem) throw new Error("the certificate file holds no PEM certificate");
  const thumb = createHash("sha256").update(new X509Certificate(certPem).raw).digest("base64url");
  return jwt(
    { alg: "PS256", typ: "JWT", "x5t#S256": thumb },
    { aud: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, iss: clientId, sub: clientId, jti: randomUUID(), nbf: nowSec, iat: nowSec, exp: nowSec + 600 },
    pem, true,
  );
}

/** The signed assertion a Google service account exchanges for an access token as `subject`. */
export function googleAssertion(key: { client_email: string; private_key: string; token_uri?: string }, subject: string, scopes: string[], nowSec: number): string {
  return jwt(
    { alg: "RS256", typ: "JWT" },
    { iss: key.client_email, sub: subject, scope: scopes.join(" "), aud: key.token_uri ?? "https://oauth2.googleapis.com/token", iat: nowSec, exp: nowSec + 3600 },
    key.private_key, false,
  );
}

/** Posts a form to a token endpoint and returns the access token. */
export async function tokenRequest(url: string, form: Record<string, string>, fetchFn: typeof fetch = fetch): Promise<{ token: string; expiresAt: number }> {
  // A secret or a signed assertion goes in the body, so never over plain HTTP.
  if (new URL(url).protocol !== "https:") throw new Error(`token request to ${new URL(url).host} refused: not HTTPS`);
  const res = await fetchFn(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: new URLSearchParams(form).toString() });
  let body: Record<string, unknown> = {};
  try { body = (await res.json()) as Record<string, unknown>; } catch { /* empty */ }
  if (!res.ok || typeof body.access_token !== "string") {
    const code = typeof body.error === "string" ? body.error : "no access_token";
    throw new Error(`token request to ${new URL(url).host} failed: HTTP ${res.status} ${code}`);
  }
  const ttl = Number(body.expires_in);
  return { token: body.access_token, expiresAt: Date.now() + (Number.isFinite(ttl) ? ttl : 3000) * 1000 };
}

/** Caches a token until a minute before it expires. */
export function cachedToken(fetchToken: () => Promise<{ token: string; expiresAt: number }>): () => Promise<string> {
  let cur: { token: string; expiresAt: number } | undefined;
  let pending: Promise<{ token: string; expiresAt: number }> | undefined;
  return async () => {
    if (cur && cur.expiresAt - 60_000 > Date.now()) return cur.token;
    pending ??= fetchToken().finally(() => { pending = undefined; });
    cur = await pending;
    return cur.token;
  };
}
