// AWS Signature Version 4, written against the steps in AWS's IAM user guide ("Create a signed AWS
// API request") with node:crypto and nothing else. test/aws.test.ts holds it against AWS's published
// test vectors (get-vanilla from the SigV4 test suite, and the IAM ListUsers example).

import { createHash, createHmac } from "node:crypto";

export interface Credentials { accessKeyId: string; secretAccessKey: string; sessionToken?: string }

export interface SignInput {
  method: string;
  host: string;
  /** The decoded path, e.g. "/" or "/detector/abc". */
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: string;
  service: string;
  region: string;
  /** Signing time; the x-amz-date header is set from it. */
  date: Date;
}

export const sha256Hex = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const hmac = (key: string | Buffer, s: string) => createHmac("sha256", key).update(s, "utf8").digest();

/** RFC 3986 encoding as SigV4 wants it: everything but A-Z a-z 0-9 - _ . ~ is %XX (upper case). */
export const rfc3986 = (s: string) =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** 20150830T123600Z */
export const amzDate = (d: Date) => d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");

/** The path as sent on the wire: each segment encoded once. */
export const wirePath = (path: string) => path.split("/").map(rfc3986).join("/");

/** S3 encodes the path once in the canonical request; every other service encodes the wire path again. */
export const canonicalPath = (path: string, service: string) =>
  service === "s3" ? wirePath(path) : wirePath(path).split("/").map(rfc3986).join("/");

export const canonicalQuery = (q: Record<string, string>) =>
  Object.entries(q).map(([k, v]) => [rfc3986(k), rfc3986(v)] as const)
    .sort(([a, x], [b, y]) => (a < b ? -1 : a > b ? 1 : x < y ? -1 : x > y ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`).join("&");

export function signingKey(secret: string, ymd: string, region: string, service: string): Buffer {
  return hmac(hmac(hmac(hmac(`AWS4${secret}`, ymd), region), service), "aws4_request");
}

export interface Signed {
  /** Every header to send, including host, x-amz-date, x-amz-security-token and authorization. */
  headers: Record<string, string>;
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
}

export function sign(req: SignInput, creds: Credentials): Signed {
  const t = amzDate(req.date), ymd = t.slice(0, 8);
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
  headers.host = req.host;
  headers["x-amz-date"] = t;
  if (creds.sessionToken) headers["x-amz-security-token"] = creds.sessionToken;
  const payloadHash = headers["x-amz-content-sha256"] ?? sha256Hex(req.body);
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((n) => `${n}:${headers[n].trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalRequest = [req.method, canonicalPath(req.path, req.service), canonicalQuery(req.query), canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${ymd}/${req.region}/${req.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", t, scope, sha256Hex(canonicalRequest)].join("\n");
  const signature = createHmac("sha256", signingKey(creds.secretAccessKey, ymd, req.region, req.service)).update(stringToSign, "utf8").digest("hex");
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers, canonicalRequest, stringToSign, signature };
}
