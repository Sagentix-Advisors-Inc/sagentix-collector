// AWS client for the collector: SigV4-signed HTTPS calls with Node's fetch, no SDK. Three wire
// protocols are used, each a read action only:
//   query  (IAM, EC2, RDS, STS)               GET  ?Action=<Get|List|Describe…>&Version=…   XML reply
//   json   (CloudTrail, Config, KMS)          POST x-amz-target: <Service>.<Get|List|Describe…>  JSON reply
//   rest   (GuardDuty, Security Hub, Backup,  GET  <path>                                  JSON or XML reply
//           Access Analyzer, S3, S3 Control)
// The client refuses any action whose name does not start with Get, List or Describe, apart from
// GenerateCredentialReport (it makes IAM build the credential report the collector then reads) and
// the two STS calls that obtain the read-only role's session.

import { readFileSync } from "node:fs";
import type { HttpReply, RetryOptions } from "../shared-cloud.ts";
import { isObj, str, withRetry } from "../shared-cloud.ts";
import { sha256Hex, sign, wirePath, type Credentials } from "./sigv4.ts";
import { deepText, kidText, parseXml, path, type XNode } from "./xml.ts";

export interface AwsRequest {
  service: string;
  region: string;
  method: "GET" | "POST";
  host: string;
  /** Decoded path, "/" for query and json calls. */
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: string;
  /** The API action, for the read-only guard and for fakes: "ListUsers", "DescribeTrails", "GET /detector". */
  action: string;
}

/** What the source talks to. Tests pass a fake; the real one signs and fetches. */
export interface AwsTransport {
  send(req: AwsRequest): Promise<HttpReply>;
  sleep?: (ms: number) => Promise<void>;
}

export const READ_ACTION = /^(Get|List|Describe)[A-Za-z]+$/;
const ALLOWED_OTHER = new Set(["GenerateCredentialReport", "AssumeRole", "AssumeRoleWithWebIdentity"]);

/** True for an action the collector may send: a read, or one of the three named exceptions. */
export function isReadAction(action: string): boolean {
  if (action.startsWith("GET ")) return true;
  return READ_ACTION.test(action) || ALLOWED_OTHER.has(action);
}

export function fetchAwsTransport(creds: Credentials, fetchFn: typeof fetch = fetch, now: () => Date = () => new Date()): AwsTransport {
  return {
    async send(req) {
      if (!isReadAction(req.action)) throw new Error(`refused: ${req.action} is not a read action`);
      if (req.method !== "GET" && !(req.method === "POST" && req.headers["x-amz-target"])) throw new Error(`refused: ${req.method} without x-amz-target`);
      const headers = req.service === "s3" ? { ...req.headers, "x-amz-content-sha256": sha256Hex(req.body) } : req.headers;
      const s = sign({ ...req, headers, date: now() }, creds);
      const qs = Object.entries(req.query).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
      const url = `https://${req.host}${wirePath(req.path)}${qs ? `?${qs}` : ""}`;
      const { host: _h, ...send } = s.headers;
      const res = await fetchFn(url, { method: req.method, headers: send, body: req.method === "POST" ? req.body : undefined });
      const out: Record<string, string> = {};
      res.headers.forEach((v, k) => { out[k.toLowerCase()] = v; });
      return { status: res.status, headers: out, body: await res.text() };
    },
  };
}

// ── Credentials ─────────────────────────────────────────────────────────────────────────────────

export const AWS_SECRET_ENVS = ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID"] as const;

/**
 * Credentials from the environment, in this order:
 *   1. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN): what
 *      aws-actions/configure-aws-credentials exports after assuming the role through GitHub OIDC.
 *   2. AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE: STS AssumeRoleWithWebIdentity (unsigned).
 * Shared config profiles, SSO and the EC2/ECS metadata endpoints are not read.
 */
export async function envCredentials(env: NodeJS.ProcessEnv, region: string, fetchFn: typeof fetch = fetch): Promise<Credentials | { error: string } | null> {
  if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) {
    return { accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY, sessionToken: env.AWS_SESSION_TOKEN || undefined };
  }
  if (env.AWS_ROLE_ARN && env.AWS_WEB_IDENTITY_TOKEN_FILE) {
    let token: string;
    try { token = readFileSync(env.AWS_WEB_IDENTITY_TOKEN_FILE, "utf8").trim(); } catch (e) { return { error: `cannot read AWS_WEB_IDENTITY_TOKEN_FILE (${(e as NodeJS.ErrnoException).code ?? "error"})` }; }
    const q = new URLSearchParams({ Action: "AssumeRoleWithWebIdentity", Version: "2011-06-15", RoleArn: env.AWS_ROLE_ARN, RoleSessionName: "sagentix-collector", WebIdentityToken: token, DurationSeconds: "3600" });
    const res = await fetchFn(`https://sts.${region}.amazonaws.com/?${q}`, { method: "GET" });
    const body = await res.text();
    return credsFromSts(res.status, body) ?? { error: `AssumeRoleWithWebIdentity failed: HTTP ${res.status} ${errorOf({ status: res.status, headers: {}, body }).code}` };
  }
  return null;
}

function credsFromSts(status: number, body: string): Credentials | undefined {
  if (status !== 200) return undefined;
  try {
    const c = parseXml(body);
    const id = deepText(c, "AccessKeyId"), secret = deepText(c, "SecretAccessKey"), tok = deepText(c, "SessionToken");
    return id && secret ? { accessKeyId: id, secretAccessKey: secret, sessionToken: tok } : undefined;
  } catch { return undefined; }
}

/** Assumes a role (--aws-role-arn, optional --aws-external-id) with the base credentials. */
export async function assumeRole(t: AwsTransport, region: string, roleArn: string, externalId?: string): Promise<Credentials | { error: string }> {
  const r = await t.send(queryReq("sts", region, "AssumeRole", "2011-06-15", {
    RoleArn: roleArn, RoleSessionName: "sagentix-collector", DurationSeconds: "3600", ...(externalId ? { ExternalId: externalId } : {}),
  }));
  return credsFromSts(r.status, r.body) ?? { error: `AssumeRole ${roleArn} failed: HTTP ${r.status} ${errorOf(r).code}` };
}

// ── Requests ────────────────────────────────────────────────────────────────────────────────────

const GLOBAL_HOST: Record<string, string> = { iam: "iam.amazonaws.com" };

export function queryReq(service: string, region: string, action: string, version: string, params: Record<string, string> = {}): AwsRequest {
  const host = GLOBAL_HOST[service] ?? `${service}.${region}.amazonaws.com`;
  return { service, region: service === "iam" ? "us-east-1" : region, method: "GET", host, path: "/", query: { Action: action, Version: version, ...params }, headers: {}, body: "", action };
}

const JSON_TARGET: Record<string, string> = {
  cloudtrail: "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101",
  config: "StarlingDoveService",
  kms: "TrentService",
};

export function jsonReq(service: keyof typeof JSON_TARGET | string, region: string, action: string, payload: unknown): AwsRequest {
  return {
    service, region, method: "POST", host: `${service}.${region}.amazonaws.com`, path: "/", query: {}, body: JSON.stringify(payload ?? {}), action,
    headers: { "content-type": "application/x-amz-json-1.1", "x-amz-target": `${JSON_TARGET[service]}.${action}` },
  };
}

export function restReq(service: string, region: string, host: string, p: string, query: Record<string, string> = {}, headers: Record<string, string> = {}): AwsRequest {
  return { service, region, method: "GET", host, path: p, query, headers, body: "", action: `GET ${p}` };
}

// ── Replies ─────────────────────────────────────────────────────────────────────────────────────

export interface AwsError { code: string; message: string }

/** The error code and message of a reply, from an XML or JSON body or the x-amzn-errortype header. */
export function errorOf(r: HttpReply): AwsError {
  const b = r.body.trim();
  if (b.startsWith("<")) {
    try {
      const x = parseXml(b);
      return { code: deepText(x, "Code") ?? "", message: deepText(x, "Message") ?? "" };
    } catch { /* fall through */ }
  }
  let code = (r.headers["x-amzn-errortype"] ?? "").split(":")[0];
  let message = "";
  try {
    const o = JSON.parse(b) as unknown;
    if (isObj(o)) {
      code = str(o.__type) ?? str(o.code) ?? str(o.Code) ?? code;
      message = str(o.message) ?? str(o.Message) ?? "";
    }
  } catch { /* not JSON */ }
  return { code: code.split("#").pop() ?? code, message };
}

export const THROTTLE_CODES = new Set(["Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException", "SlowDown", "RequestThrottled", "RequestThrottledException", "ProvisionedThroughputExceededException"]);

export function isThrottled(r: HttpReply): boolean {
  if (r.status === 429 || r.status === 503) return true;
  if (r.status !== 400) return false;
  return THROTTLE_CODES.has(errorOf(r).code);
}

export const okStatus = (r: HttpReply) => r.status >= 200 && r.status < 300;

/** Why a call gave no usable answer, for a "skipped" detail. */
export function awsWhy(r: HttpReply): string {
  const e = errorOf(r);
  const hint = r.status === 401 || r.status === 403 || /AccessDenied|UnauthorizedOperation|AuthorizationError/.test(e.code)
    ? " (the role may lack the read permission for this call)" : "";
  return `HTTP ${r.status}${e.code ? ` ${e.code}` : ""}${e.message ? `: ${e.message.replace(/\s+/g, " ").slice(0, 250)}` : ""}${hint}`;
}

/** A transport wrapped with retry on throttling; every source call goes through this. */
export class Aws {
  readonly t: AwsTransport;
  readonly retry: RetryOptions;
  constructor(t: AwsTransport, retry: RetryOptions = {}) {
    this.t = t;
    this.retry = { sleep: t.sleep, throttled: isThrottled, ...retry };
  }
  send(req: AwsRequest): Promise<HttpReply> { return withRetry(() => this.t.send(req), this.retry); }

  async xml(req: AwsRequest): Promise<{ ok: true; x: XNode } | { ok: false; r: HttpReply }> {
    const r = await this.send(req);
    if (!okStatus(r)) return { ok: false, r };
    try { return { ok: true, x: parseXml(r.body) }; } catch { return { ok: false, r: { ...r, status: r.status, body: "<Error><Code>BadXml</Code><Message>reply is not XML</Message></Error>" } }; }
  }

  async json(req: AwsRequest): Promise<{ ok: true; o: Record<string, unknown> } | { ok: false; r: HttpReply }> {
    const r = await this.send(req);
    if (!okStatus(r)) return { ok: false, r };
    try {
      const o = JSON.parse(r.body || "{}") as unknown;
      return isObj(o) ? { ok: true, o } : { ok: false, r: { ...r, body: '{"__type":"BadJson","message":"reply is not a JSON object"}' } };
    } catch { return { ok: false, r: { ...r, body: '{"__type":"BadJson","message":"reply is not JSON"}' } }; }
  }
}

/** Account id of the credentials (sts:GetCallerIdentity needs no permission). */
export async function callerAccount(aws: Aws, region: string): Promise<{ account: string } | { error: string }> {
  const r = await aws.xml(queryReq("sts", region, "GetCallerIdentity", "2011-06-15"));
  if (!r.ok) return { error: awsWhy(r.r) };
  const a = kidText(path(r.x, "GetCallerIdentityResponse", "GetCallerIdentityResult"), "Account");
  return a ? { account: a } : { error: "GetCallerIdentity returned no Account" };
}
