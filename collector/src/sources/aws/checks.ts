// AWS checks for one account, over the regions given. Every call is a read (see api.ts).
//
// Calls, and the IAM action each needs (all in the SecurityAudit managed policy):
//   sts   GetCallerIdentity                                   none
//   iam   GetAccountSummary                                   iam:GetAccountSummary
//   iam   GenerateCredentialReport, GetCredentialReport       iam:GenerateCredentialReport, iam:GetCredentialReport
//   iam   ListUsers                                           iam:ListUsers
//   iam   GetAccountPasswordPolicy                            iam:GetAccountPasswordPolicy
//   cloudtrail DescribeTrails, GetTrailStatus                 cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus
//   guardduty  GET /detector, GET /detector/{id}              guardduty:ListDetectors, guardduty:GetDetector
//   securityhub GET /accounts (DescribeHub, Security Hub CSPM) securityhub:DescribeHub
//   securityhub GET /hubv2 (DescribeSecurityHubV2, AWS Security Hub) securityhub:DescribeSecurityHubV2
//   config DescribeConfigurationRecorderStatus                config:DescribeConfigurationRecorderStatus
//   s3control GET /v20180820/configuration/publicAccessBlock  s3:GetAccountPublicAccessBlock
//   s3    ListBuckets, GetBucketEncryption                    s3:ListAllMyBuckets, s3:GetEncryptionConfiguration
//   ec2   GetEbsEncryptionByDefault, DescribeSecurityGroups,  ec2:GetEbsEncryptionByDefault, ec2:DescribeSecurityGroups,
//         DescribeVpcs, DescribeFlowLogs                      ec2:DescribeVpcs, ec2:DescribeFlowLogs
//   rds   DescribeDBInstances                                 rds:DescribeDBInstances
//   kms   ListKeys, DescribeKey, GetKeyRotationStatus         kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus
//   backup GET /backup/plans/ (ListBackupPlans)               backup:ListBackupPlans
//   access-analyzer GET /analyzer (ListAnalyzers)             access-analyzer:ListAnalyzers

import type { Result } from "../../types.ts";
import { ADMIN_PORTS, Results, ageDays, arr, isObj, j, rangeHits, str } from "../shared-cloud.ts";
import { Aws, awsWhy, errorOf, jsonReq, queryReq, restReq, type AwsRequest } from "./api.ts";
import { deep, deepText, items, kidText, kids, path, type XNode } from "./xml.ts";

export const AWS_CHECKS = [
  "root_mfa", "root_no_access_keys", "iam_users_mfa", "access_keys_rotated", "password_policy",
  "cloudtrail_multi_region", "cloudtrail_kms_encrypted", "guardduty_enabled", "securityhub_enabled",
  "config_recorder_on", "s3_account_public_access_block", "s3_bucket_encryption", "ebs_encryption_default",
  "rds_encrypted", "rds_not_public", "rds_automated_backups", "sg_no_open_admin_ports", "kms_rotation",
  "backup_plans_exist", "vpc_flow_logs", "access_analyzer_enabled",
] as const;
export type AwsCheck = (typeof AWS_CHECKS)[number];

export const DEFAULT_KEY_MAX_AGE_DAYS = 90;
export const MIN_PASSWORD_LENGTH = 14;

export interface AwsOptions { regions: string[]; keyMaxAgeDays: number; now: Date }

const IAM_V = "2010-05-08", EC2_V = "2016-11-15", RDS_V = "2014-10-31";
const MAX_PAGES = 50;

type Out = Results<AwsCheck>;

export async function accountChecks(aws: Aws, account: string, o: AwsOptions): Promise<Result[]> {
  const out = new Results<AwsCheck>("aws");
  const acct = `aws account ${account}`;
  const home = o.regions[0];
  await rootChecks(aws, out, acct);
  await userChecks(aws, out, acct, o);
  await passwordPolicy(aws, out, acct);
  await cloudtrail(aws, out, acct, home);
  await s3AccountBlock(aws, out, acct, account, home);
  await s3Buckets(aws, out, acct);
  let rdsSeen = 0, kmsSeen = 0;
  for (const region of o.regions) {
    const rr = `${acct} region ${region}`;
    await guardduty(aws, out, rr, region);
    await securityhub(aws, out, rr, region);
    await configRecorder(aws, out, rr, region);
    await ebsDefault(aws, out, rr, region);
    rdsSeen += await rds(aws, out, rr, region);
    await securityGroups(aws, out, rr, region);
    kmsSeen += await kms(aws, out, rr, region);
    await backupPlans(aws, out, rr, region);
    await flowLogs(aws, out, rr, region);
    await accessAnalyzer(aws, out, rr, region);
  }
  if (rdsSeen === 0) for (const c of ["rds_encrypted", "rds_not_public", "rds_automated_backups"] as const) {
    if (!out.results.some((r) => r.check === `aws.${c}`)) out.skip(c, acct, `no RDS DB instance in ${o.regions.join(", ")}`);
  }
  if (kmsSeen === 0 && !out.results.some((r) => r.check === "aws.kms_rotation")) out.skip("kms_rotation", acct, `no enabled symmetric customer-managed KMS key in ${o.regions.join(", ")}`);
  return out.results;
}

// ── IAM ─────────────────────────────────────────────────────────────────────────────────────────

async function rootChecks(aws: Aws, out: Out, acct: string) {
  const r = await aws.xml(queryReq("iam", "us-east-1", "GetAccountSummary", IAM_V));
  if (!r.ok) {
    out.skip("root_mfa", acct, `account summary not readable: ${awsWhy(r.r)}`);
    out.skip("root_no_access_keys", acct, `account summary not readable: ${awsWhy(r.r)}`);
    return;
  }
  const map = new Map(items(deep(r.x, "SummaryMap")).concat(kids(deep(r.x, "SummaryMap"), "entry")).map((e) => [kidText(e, "key") ?? "", kidText(e, "value") ?? ""]));
  const mfa = map.get("AccountMFAEnabled"), keys = map.get("AccountAccessKeysPresent");
  if (mfa === undefined) out.skip("root_mfa", acct, "GetAccountSummary returned no AccountMFAEnabled");
  else out.add("root_mfa", acct, mfa === "1" ? "pass" : "fail", `AccountMFAEnabled is ${mfa}; 1 required`);
  if (keys === undefined) out.skip("root_no_access_keys", acct, "GetAccountSummary returned no AccountAccessKeysPresent");
  else out.add("root_no_access_keys", acct, keys === "0" ? "pass" : "fail", `AccountAccessKeysPresent is ${keys}; 0 required`);
}

/** Splits one CSV line; quoted fields allowed (IAM does not quote, but user names may hold commas). */
export function csvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
    else if (c === '"') q = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

export async function credentialReport(aws: Aws): Promise<{ rows: Record<string, string>[] } | { error: string }> {
  const get = () => aws.xml(queryReq("iam", "us-east-1", "GetCredentialReport", IAM_V));
  let r = await get();
  for (let i = 0; !r.ok && i < 6 && /ReportNotPresent|ReportExpired|ReportInProgress/.test(errorOf(r.r).code); i++) {
    if (i === 0 || errorOf(r.r).code !== "ReportInProgress") {
      const g = await aws.xml(queryReq("iam", "us-east-1", "GenerateCredentialReport", IAM_V));
      if (!g.ok) return { error: `credential report cannot be generated: ${awsWhy(g.r)}` };
    }
    await (aws.t.sleep ?? ((ms: number) => new Promise<void>((res) => setTimeout(res, ms))))(2000);
    r = await get();
  }
  if (!r.ok) return { error: `credential report not readable: ${awsWhy(r.r)}` };
  const b64 = deepText(r.x, "Content");
  if (!b64) return { error: "GetCredentialReport returned no Content" };
  const lines = Buffer.from(b64, "base64").toString("utf8").split(/\r?\n/).filter(Boolean);
  const head = csvLine(lines[0] ?? "");
  return { rows: lines.slice(1).map((l) => { const v = csvLine(l); return Object.fromEntries(head.map((h, i) => [h, v[i] ?? ""])); }) };
}

/** IAM user name → UserId (AIDA…). Results name users by id, never by name: names are often people's names. */
async function userIds(aws: Aws): Promise<Map<string, string> | { error: string }> {
  const ids = new Map<string, string>();
  let marker: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.xml(queryReq("iam", "us-east-1", "ListUsers", IAM_V, { MaxItems: "1000", ...(marker ? { Marker: marker } : {}) }));
    if (!r.ok) return { error: `IAM users not listable: ${awsWhy(r.r)}` };
    const res = deep(r.x, "ListUsersResult");
    for (const u of items(path(res, "Users"))) ids.set(kidText(u, "UserName") ?? "", kidText(u, "UserId") ?? "");
    marker = kidText(res, "IsTruncated") === "true" ? kidText(res, "Marker") : undefined;
    if (!marker) break;
  }
  return ids;
}

async function userChecks(aws: Aws, out: Out, acct: string, o: AwsOptions) {
  const rep = await credentialReport(aws);
  if ("error" in rep) { out.skipAll(["iam_users_mfa", "access_keys_rotated"], acct, rep.error); return; }
  const ids = await userIds(aws);
  if ("error" in ids) { out.skipAll(["iam_users_mfa", "access_keys_rotated"], acct, ids.error); return; }
  const users = rep.rows.filter((r) => r.user !== "<root_account>");
  const idOf = (name: string) => `iam user ${ids.get(name) || "(id not listed)"}`;
  const console = users.filter((u) => u.password_enabled === "true");
  if (!console.length) out.skip("iam_users_mfa", acct, `${users.length} IAM user(s), none with console access`);
  for (const u of console) out.add("iam_users_mfa", idOf(u.user), u.mfa_active === "true" ? "pass" : "fail", `console password enabled; mfa_active is ${u.mfa_active}; true required`);

  let withKeys = 0;
  for (const u of users) {
    const ages: number[] = [];
    for (const n of ["1", "2"]) {
      if (u[`access_key_${n}_active`] !== "true") continue;
      const a = ageDays(u[`access_key_${n}_last_rotated`], o.now);
      ages.push(a === undefined ? Infinity : Math.floor(a));
    }
    if (!ages.length) continue;
    withKeys++;
    const old = ages.filter((a) => a > o.keyMaxAgeDays);
    out.add("access_keys_rotated", idOf(u.user), old.length ? "fail" : "pass",
      `${ages.length} active access key(s), last rotated ${ages.map((a) => (Number.isFinite(a) ? `${a} days` : "at an unknown date")).join(" and ")} ago; ${o.keyMaxAgeDays} days or less required (--aws-key-max-age-days)`);
  }
  if (!withKeys) out.skip("access_keys_rotated", acct, `${users.length} IAM user(s), none with an active access key`);
}

async function passwordPolicy(aws: Aws, out: Out, acct: string) {
  const r = await aws.xml(queryReq("iam", "us-east-1", "GetAccountPasswordPolicy", IAM_V));
  if (!r.ok) {
    if (errorOf(r.r).code === "NoSuchEntity") return out.add("password_policy", acct, "fail", "no account password policy is set; minimum length 14 and reuse prevention required");
    return out.skip("password_policy", acct, `password policy not readable: ${awsWhy(r.r)}`);
  }
  const p = deep(r.x, "PasswordPolicy");
  const len = Number(kidText(p, "MinimumPasswordLength") ?? 0), reuse = Number(kidText(p, "PasswordReusePrevention") ?? 0);
  out.add("password_policy", acct, len >= MIN_PASSWORD_LENGTH && reuse >= 1 ? "pass" : "fail",
    `MinimumPasswordLength ${len}, PasswordReusePrevention ${reuse || "not set"}; length ${MIN_PASSWORD_LENGTH} or more and reuse prevention required`);
}

// ── Logging and detection ───────────────────────────────────────────────────────────────────────

async function cloudtrail(aws: Aws, out: Out, acct: string, home: string) {
  const r = await aws.json(jsonReq("cloudtrail", home, "DescribeTrails", { includeShadowTrails: true }));
  if (!r.ok) { out.skipAll(["cloudtrail_multi_region", "cloudtrail_kms_encrypted"], acct, `trails not readable: ${awsWhy(r.r)}`); return; }
  const trails = new Map<string, Record<string, unknown>>();
  for (const t of arr(r.o.trailList).filter(isObj)) trails.set(String(t.TrailARN ?? t.Name), t);
  if (!trails.size) {
    out.add("cloudtrail_multi_region", acct, "fail", "no CloudTrail trail; a multi-region trail that is logging, with log file validation, required");
    out.skip("cloudtrail_kms_encrypted", acct, "no CloudTrail trail");
    return;
  }
  const good: string[] = [], seen: string[] = [];
  for (const [arn, t] of trails) {
    if (t.IsMultiRegionTrail !== true) { seen.push(`${j(t.Name)} single-region`); continue; }
    const s = await aws.json(jsonReq("cloudtrail", str(t.HomeRegion) ?? home, "GetTrailStatus", { Name: arn }));
    const logging = s.ok ? s.o.IsLogging === true : undefined;
    seen.push(`${j(t.Name)} multi-region, logging ${logging ?? "unknown"}, validation ${t.LogFileValidationEnabled === true}`);
    if (logging && t.LogFileValidationEnabled === true) good.push(String(t.Name));
  }
  out.add("cloudtrail_multi_region", acct, good.length ? "pass" : "fail",
    `${trails.size} trail(s): ${seen.join("; ")}; one multi-region trail that is logging, with log file validation, required`);
  for (const [arn, t] of trails) {
    const kmsKey = str(t.KmsKeyId);
    out.add("cloudtrail_kms_encrypted", `cloudtrail trail ${arn}`, kmsKey ? "pass" : "fail",
      kmsKey ? `log files encrypted with KMS key ${kmsKey}` : "KmsKeyId not set: log files use the bucket's default encryption (SSE-S3), not a KMS key; SSE-KMS required");
  }
}

async function guardduty(aws: Aws, out: Out, rr: string, region: string) {
  const host = `guardduty.${region}.amazonaws.com`;
  const ids: string[] = [];
  let next: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.json(restReq("guardduty", region, host, "/detector", { maxResults: "50", ...(next ? { nextToken: next } : {}) }));
    if (!r.ok) return out.skip("guardduty_enabled", rr, `detectors not readable: ${awsWhy(r.r)}`);
    ids.push(...arr(r.o.detectorIds).map(String));
    next = str(r.o.nextToken) || undefined;
    if (!next) break;
  }
  if (!ids.length) return out.add("guardduty_enabled", rr, "fail", "no GuardDuty detector in the region; an enabled detector required");
  const states: string[] = [];
  for (const id of ids) {
    const d = await aws.json(restReq("guardduty", region, host, `/detector/${id}`));
    states.push(d.ok ? String(d.o.status) : `unreadable (${awsWhy(d.r)})`);
  }
  out.add("guardduty_enabled", rr, states.includes("ENABLED") ? "pass" : "fail", `detector status ${states.join(", ")}; ENABLED required`);
}

// AWS sells two products behind the one `securityhub` endpoint and IAM prefix (AWS docs, read 2026-10-20:
// docs.aws.amazon.com/securityhub/latest/userguide/what-are-securityhub-services.html). Security Hub CSPM
// (the former Security Hub) runs the standards and control checks; DescribeHub, GET /accounts, answers for
// it. The newer "AWS Security Hub" correlates findings into exposures; DescribeSecurityHubV2, GET /hubv2,
// answers for it. This check is about posture checks, so CSPM decides the result. AWS: "if you enable
// Security Hub without enabling Security Hub CSPM, Security Hub cannot use Security Hub CSPM findings".
// The detail always says which product was read and whether the other one is on, so a client running
// only the newer Security Hub sees why the posture check fails instead of a bare "not enabled".
async function securityhubV2(aws: Aws, region: string): Promise<{ on: boolean; text: string }> {
  const r = await aws.json(restReq("securityhub", region, `securityhub.${region}.amazonaws.com`, "/hubv2"));
  if (r.ok) {
    const arn = str(r.o.HubV2Arn);
    return arn ? { on: true, text: `AWS Security Hub is on (DescribeSecurityHubV2: ${arn})` } : { on: false, text: "AWS Security Hub: DescribeSecurityHubV2 returned no HubV2Arn" };
  }
  const code = errorOf(r.r).code;
  // [Unverified] AWS lists ResourceNotFoundException for DescribeSecurityHubV2 without saying it means "not enabled".
  if (code === "ResourceNotFoundException") return { on: false, text: "AWS Security Hub is not enabled (DescribeSecurityHubV2: ResourceNotFoundException)" };
  return { on: false, text: `AWS Security Hub not readable (DescribeSecurityHubV2: ${awsWhy(r.r)})` };
}

async function securityhub(aws: Aws, out: Out, rr: string, region: string) {
  const r = await aws.json(restReq("securityhub", region, `securityhub.${region}.amazonaws.com`, "/accounts"));
  const v2 = await securityhubV2(aws, region);
  if (r.ok) return out.add("securityhub_enabled", rr, str(r.o.HubArn) ? "pass" : "fail", str(r.o.HubArn)
    ? `Security Hub CSPM enabled (DescribeHub: ${r.o.HubArn}), subscribed ${String(r.o.SubscribedAt ?? "?")}; ${v2.text}`
    : `Security Hub CSPM: DescribeHub returned no HubArn; ${v2.text}`);
  const code = errorOf(r.r).code;
  // DescribeHub answers InvalidAccessException when the account is not subscribed to Security Hub CSPM.
  if (code === "InvalidAccessException" || code === "ResourceNotFoundException") {
    return out.add("securityhub_enabled", rr, "fail", v2.on
      ? `Security Hub CSPM is not enabled in the region (DescribeHub: ${code}); ${v2.text}, but without CSPM it has no standards or control checks to use, so turn on Security Hub CSPM too`
      : `Security Hub CSPM is not enabled in the region (DescribeHub: ${code}); ${v2.text}`);
  }
  out.skip("securityhub_enabled", rr, `Security Hub CSPM not readable (DescribeHub: ${awsWhy(r.r)}); ${v2.text}`);
}

async function configRecorder(aws: Aws, out: Out, rr: string, region: string) {
  const r = await aws.json(jsonReq("config", region, "DescribeConfigurationRecorderStatus", {}));
  if (!r.ok) return out.skip("config_recorder_on", rr, `recorder status not readable: ${awsWhy(r.r)}`);
  const st = arr(r.o.ConfigurationRecordersStatus).filter(isObj);
  const on = st.filter((s) => s.recording === true);
  out.add("config_recorder_on", rr, on.length ? "pass" : "fail",
    st.length ? `${st.length} recorder(s): ${st.map((s) => `${j(s.name)} recording ${s.recording === true}`).join(", ")}; one recording required` : "no AWS Config recorder; one recording required");
}

async function flowLogs(aws: Aws, out: Out, rr: string, region: string) {
  const vpcs = await ec2List(aws, region, "DescribeVpcs", "vpcSet");
  if ("error" in vpcs) return out.skip("vpc_flow_logs", rr, `VPCs not listable: ${vpcs.error}`);
  if (!vpcs.items.length) return out.skip("vpc_flow_logs", rr, "no VPC in the region");
  const fl = await ec2List(aws, region, "DescribeFlowLogs", "flowLogSet");
  if ("error" in fl) return out.skip("vpc_flow_logs", rr, `flow logs not listable: ${fl.error}`);
  const active = new Map<string, number>();
  for (const f of fl.items) if (kidText(f, "flowLogStatus") === "ACTIVE") active.set(kidText(f, "resourceId") ?? "", (active.get(kidText(f, "resourceId") ?? "") ?? 0) + 1);
  for (const v of vpcs.items) {
    const id = kidText(v, "vpcId") ?? "?", n = active.get(id) ?? 0;
    out.add("vpc_flow_logs", `vpc ${region}/${id}`, n ? "pass" : "fail", `${n} active flow log(s) on the VPC; at least one required`);
  }
}

async function accessAnalyzer(aws: Aws, out: Out, rr: string, region: string) {
  const host = `access-analyzer.${region}.amazonaws.com`;
  const all: Record<string, unknown>[] = [];
  let next: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.json(restReq("access-analyzer", region, host, "/analyzer", { maxResults: "100", ...(next ? { nextToken: next } : {}) }));
    if (!r.ok) return out.skip("access_analyzer_enabled", rr, `analyzers not readable: ${awsWhy(r.r)}`);
    all.push(...arr(r.o.analyzers).filter(isObj));
    next = str(r.o.nextToken) || undefined;
    if (!next) break;
  }
  const active = all.filter((a) => a.status === "ACTIVE");
  out.add("access_analyzer_enabled", rr, active.length ? "pass" : "fail",
    `${all.length} analyzer(s), ${active.length} ACTIVE${active.length ? ` (types ${[...new Set(active.map((a) => String(a.type)))].join(", ")})` : ""}; one active analyzer required`);
}

// ── Storage and encryption ──────────────────────────────────────────────────────────────────────

async function s3AccountBlock(aws: Aws, out: Out, acct: string, account: string, region: string) {
  const r = await aws.xml(restReq("s3", region, `${account}.s3-control.${region}.amazonaws.com`, "/v20180820/configuration/publicAccessBlock", {}, { "x-amz-account-id": account }));
  if (!r.ok) {
    if (errorOf(r.r).code === "NoSuchPublicAccessBlockConfiguration") return out.add("s3_account_public_access_block", acct, "fail", "no account-level S3 Block Public Access configuration; all four settings true required");
    return out.skip("s3_account_public_access_block", acct, `account public access block not readable: ${awsWhy(r.r)}`);
  }
  const c = deep(r.x, "PublicAccessBlockConfiguration") ?? r.x;
  const names = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"];
  const vals = names.map((n) => `${n} ${kidText(c, n) ?? "unset"}`);
  out.add("s3_account_public_access_block", acct, names.every((n) => kidText(c, n) === "true") ? "pass" : "fail", `${vals.join(", ")}; all true required`);
}

async function s3Buckets(aws: Aws, out: Out, acct: string) {
  const buckets: { name: string; region: string }[] = [];
  let token: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.xml(restReq("s3", "us-east-1", "s3.us-east-1.amazonaws.com", "/", { "max-buckets": "1000", ...(token ? { "continuation-token": token } : {}) }));
    if (!r.ok) return out.skip("s3_bucket_encryption", acct, `buckets not listable: ${awsWhy(r.r)}`);
    const res = deep(r.x, "ListAllMyBucketsResult") ?? r.x;
    for (const b of kids(path(res, "Buckets"), "Bucket")) buckets.push({ name: kidText(b, "Name") ?? "?", region: kidText(b, "BucketRegion") || "us-east-1" });
    token = kidText(res, "ContinuationToken") || undefined;
    if (!token) break;
  }
  if (!buckets.length) return out.skip("s3_bucket_encryption", acct, "the account has no S3 bucket");
  for (const b of buckets) {
    const res = `s3 bucket ${b.name}`;
    const r = await aws.xml(restReq("s3", b.region, `s3.${b.region}.amazonaws.com`, `/${b.name}`, { encryption: "" }));
    if (!r.ok) {
      if (errorOf(r.r).code === "ServerSideEncryptionConfigurationNotFoundError") { out.add("s3_bucket_encryption", res, "fail", "no default encryption configuration on the bucket"); continue; }
      out.skip("s3_bucket_encryption", res, `bucket encryption not readable: ${awsWhy(r.r)}`);
      continue;
    }
    const algs = kids(deep(r.x, "ServerSideEncryptionConfiguration") ?? r.x, "Rule").map((rule) => deepText(rule, "SSEAlgorithm")).filter((x): x is string => !!x);
    out.add("s3_bucket_encryption", res, algs.length ? "pass" : "fail", algs.length ? `default encryption ${algs.join(", ")}` : "no SSEAlgorithm in the bucket's encryption rules");
  }
}

async function ebsDefault(aws: Aws, out: Out, rr: string, region: string) {
  const r = await aws.xml(queryReq("ec2", region, "GetEbsEncryptionByDefault", EC2_V));
  if (!r.ok) return out.skip("ebs_encryption_default", rr, `EBS default encryption not readable: ${awsWhy(r.r)}`);
  const v = deepText(r.x, "ebsEncryptionByDefault");
  out.add("ebs_encryption_default", rr, v === "true" ? "pass" : "fail", `ebsEncryptionByDefault is ${v ?? "absent"}; true required`);
}

async function rds(aws: Aws, out: Out, rr: string, region: string): Promise<number> {
  const all: XNode[] = [];
  let marker: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.xml(queryReq("rds", region, "DescribeDBInstances", RDS_V, { MaxRecords: "100", ...(marker ? { Marker: marker } : {}) }));
    if (!r.ok) {
      out.skipAll(["rds_encrypted", "rds_not_public", "rds_automated_backups"], rr, `DB instances not readable: ${awsWhy(r.r)}`);
      return 0;
    }
    const res = deep(r.x, "DescribeDBInstancesResult");
    all.push(...kids(path(res, "DBInstances"), "DBInstance"));
    marker = kidText(res, "Marker") || undefined;
    if (!marker) break;
  }
  for (const d of all) {
    const res = `rds instance ${region}/${kidText(d, "DBInstanceIdentifier") ?? "?"}`;
    const enc = kidText(d, "StorageEncrypted"), pub = kidText(d, "PubliclyAccessible"), keep = Number(kidText(d, "BackupRetentionPeriod") ?? 0);
    out.add("rds_encrypted", res, enc === "true" ? "pass" : "fail", `StorageEncrypted is ${enc ?? "absent"}; true required`);
    out.add("rds_not_public", res, pub === "false" ? "pass" : "fail", `PubliclyAccessible is ${pub ?? "absent"}; false required`);
    out.add("rds_automated_backups", res, keep > 0 ? "pass" : "fail", `BackupRetentionPeriod is ${keep} day(s); 1 or more required`);
  }
  return all.length;
}

async function kms(aws: Aws, out: Out, rr: string, region: string): Promise<number> {
  const keys: Record<string, unknown>[] = [];
  let marker: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.json(jsonReq("kms", region, "ListKeys", { Limit: 1000, ...(marker ? { Marker: marker } : {}) }));
    if (!r.ok) { out.skip("kms_rotation", rr, `KMS keys not listable: ${awsWhy(r.r)}`); return 0; }
    keys.push(...arr(r.o.Keys).filter(isObj));
    marker = r.o.Truncated === true ? str(r.o.NextMarker) : undefined;
    if (!marker) break;
  }
  let n = 0;
  for (const k of keys) {
    const id = String(k.KeyId), res = `kms key ${str(k.KeyArn) ?? `${region}/${id}`}`;
    const d = await aws.json(jsonReq("kms", region, "DescribeKey", { KeyId: id }));
    if (!d.ok) { out.skip("kms_rotation", res, `key not readable: ${awsWhy(d.r)}`); continue; }
    const m = isObj(d.o.KeyMetadata) ? d.o.KeyMetadata : {};
    const spec = str(m.KeySpec) ?? str(m.CustomerMasterKeySpec);
    // Automatic rotation exists only for enabled, symmetric, customer-managed keys with AWS_KMS key material.
    if (m.KeyManager !== "CUSTOMER" || spec !== "SYMMETRIC_DEFAULT" || m.KeyState !== "Enabled" || m.Origin !== "AWS_KMS") continue;
    n++;
    const s = await aws.json(jsonReq("kms", region, "GetKeyRotationStatus", { KeyId: id }));
    if (!s.ok) { out.skip("kms_rotation", res, `rotation status not readable: ${awsWhy(s.r)}`); continue; }
    const on = s.o.KeyRotationEnabled === true;
    out.add("kms_rotation", res, on ? "pass" : "fail", `KeyRotationEnabled is ${on}${s.o.RotationPeriodInDays ? `, period ${s.o.RotationPeriodInDays} days` : ""}; true required`);
  }
  return n;
}

async function backupPlans(aws: Aws, out: Out, rr: string, region: string) {
  const plans: Record<string, unknown>[] = [];
  let next: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const r = await aws.json(restReq("backup", region, `backup.${region}.amazonaws.com`, "/backup/plans/", { maxResults: "100", ...(next ? { nextToken: next } : {}) }));
    if (!r.ok) return out.skip("backup_plans_exist", rr, `backup plans not readable: ${awsWhy(r.r)}`);
    plans.push(...arr(r.o.BackupPlansList).filter(isObj));
    next = str(r.o.NextToken) || undefined;
    if (!next) break;
  }
  out.add("backup_plans_exist", rr, plans.length ? "pass" : "fail",
    `${plans.length} AWS Backup plan(s)${plans.length ? ` (${plans.slice(0, 10).map((x) => j(x.BackupPlanName)).join(", ")})` : ""}; at least one required`);
}

// ── Network ─────────────────────────────────────────────────────────────────────────────────────

/** Every item of an EC2 Describe call that pages with NextToken. */
async function ec2List(aws: Aws, region: string, action: string, set: string, params: Record<string, string> = {}): Promise<{ items: XNode[] } | { error: string }> {
  const all: XNode[] = [];
  let next: string | undefined;
  for (let p = 0; p < MAX_PAGES; p++) {
    const req: AwsRequest = queryReq("ec2", region, action, EC2_V, { MaxResults: "1000", ...params, ...(next ? { NextToken: next } : {}) });
    const r = await aws.xml(req);
    if (!r.ok) return { error: awsWhy(r.r) };
    const top = r.x.kids[0];
    all.push(...items(path(top, set)));
    next = kidText(top, "nextToken") || undefined;
    if (!next) break;
  }
  return { items: all };
}

const OPEN = new Set(["0.0.0.0/0", "::/0"]);

/** Admin ports (22, 3389) an ingress permission opens to the whole internet. */
export function openAdminPorts(perm: XNode): number[] {
  const proto = kidText(perm, "ipProtocol") ?? "";
  if (proto !== "-1" && proto !== "tcp" && proto !== "6") return [];
  const cidrs = [...items(path(perm, "ipRanges")).map((r) => kidText(r, "cidrIp")), ...items(path(perm, "ipv6Ranges")).map((r) => kidText(r, "cidrIpv6"))];
  if (!cidrs.some((c) => c && OPEN.has(c))) return [];
  if (proto === "-1") return [...ADMIN_PORTS];
  const from = Number(kidText(perm, "fromPort") ?? 0), to = Number(kidText(perm, "toPort") ?? 65535);
  return rangeHits(from, to, ADMIN_PORTS);
}

async function securityGroups(aws: Aws, out: Out, rr: string, region: string) {
  const sgs = await ec2List(aws, region, "DescribeSecurityGroups", "securityGroupInfo");
  if ("error" in sgs) return out.skip("sg_no_open_admin_ports", rr, `security groups not listable: ${sgs.error}`);
  if (!sgs.items.length) return out.skip("sg_no_open_admin_ports", rr, "no security group in the region");
  for (const g of sgs.items) {
    const open = [...new Set(items(path(g, "ipPermissions")).flatMap(openAdminPorts))].sort((a, b) => a - b);
    out.add("sg_no_open_admin_ports", `security group ${region}/${kidText(g, "groupId") ?? "?"}`, open.length ? "fail" : "pass",
      open.length ? `ingress from 0.0.0.0/0 or ::/0 allows port(s) ${open.join(", ")}` : "no ingress rule opens 22 or 3389 to 0.0.0.0/0 or ::/0");
  }
}
