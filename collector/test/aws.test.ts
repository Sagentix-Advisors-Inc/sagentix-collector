// The AWS source against a fake transport: pass and fail per check, denied → skipped, pagination,
// throttling retry, secrets kept out of results, and SigV4 against AWS's published test vectors.
import { test } from "node:test";
import assert from "node:assert/strict";
import { aws } from "../src/sources/aws.ts";
import { fetchAwsTransport, isReadAction, type AwsRequest, type AwsTransport } from "../src/sources/aws/api.ts";
import { AWS_CHECKS } from "../src/sources/aws/checks.ts";
import { sign, signingKey } from "../src/sources/aws/sigv4.ts";
import { parseXml, deepText } from "../src/sources/aws/xml.ts";
import type { HttpReply } from "../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../src/types.ts";
import { NOW, inDays } from "./helpers.ts";

const ACCT = "111122223333";
const xml = (body: string, status = 200): HttpReply => ({ status, headers: { "content-type": "text/xml" }, body: `<?xml version="1.0" encoding="UTF-8"?>${body}` });
const json = (o: unknown, status = 200): HttpReply => ({ status, headers: { "content-type": "application/json" }, body: JSON.stringify(o) });
const xmlErr = (status: number, code: string, message = "denied") => xml(`<ErrorResponse><Error><Type>Sender</Type><Code>${code}</Code><Message>${message}</Message></Error><RequestId>r</RequestId></ErrorResponse>`, status);
const ec2Err = (status: number, code: string) => xml(`<Response><Errors><Error><Code>${code}</Code><Message>You are not authorized to perform this operation.</Message></Error></Errors><RequestID>r</RequestID></Response>`, status);
const jsonErr = (status: number, type: string, message = "denied") => json({ __type: type, message }, status);

const report = (rows: string[]) => Buffer.from([
  "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated",
  ...rows,
].join("\n")).toString("base64");
const ROOT_ROW = `<root_account>,arn:aws:iam::${ACCT}:root,2020-01-01T00:00:00+00:00,not_supported,2026-10-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A`;
const userRow = (name: string, console: boolean, mfa: boolean, keyRotated?: string, lastUsed = inDays(-5)) =>
  `${name},arn:aws:iam::${ACCT}:user/${name},2024-01-01T00:00:00+00:00,${console},${console ? lastUsed : "N/A"},N/A,N/A,${mfa},${keyRotated ? "true" : "false"},${keyRotated ?? "N/A"},${keyRotated ? lastUsed : "N/A"},N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A`;

const sgXml = (perms: string) => xml(`<DescribeSecurityGroupsResponse><requestId>r</requestId><securityGroupInfo><item><ownerId>${ACCT}</ownerId><groupId>sg-1</groupId><groupName>web</groupName><ipPermissions>${perms}</ipPermissions><ipPermissionsEgress><item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissionsEgress></item></securityGroupInfo></DescribeSecurityGroupsResponse>`);
const perm = (proto: string, from: number, to: number, cidr: string) => `<item><ipProtocol>${proto}</ipProtocol><fromPort>${from}</fromPort><toPort>${to}</toPort><ipRanges><item><cidrIp>${cidr}</cidrIp></item></ipRanges><ipv6Ranges/></item>`;
const rdsXml = (enc: boolean, pub: boolean, keep: number) => xml(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>db1</DBInstanceIdentifier><StorageEncrypted>${enc}</StorageEncrypted><PubliclyAccessible>${pub}</PubliclyAccessible><BackupRetentionPeriod>${keep}</BackupRetentionPeriod></DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`);
const pab = (v: boolean) => xml(`<PublicAccessBlockConfiguration xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>${v}</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`);

type Route = HttpReply | ((req: AwsRequest) => HttpReply);

const SSE = xml(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>`);
const ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers";
const aclXml = (grantees: string[]) => xml(`<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList><Grant><Grantee><ID>o</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>${grantees.map((u) => `<Grant><Grantee><URI>${u}</URI></Grantee><Permission>READ</Permission></Grant>`).join("")}</AccessControlList></AccessControlPolicy>`);
/** One bucket's sub-resources, by query: ?encryption, ?publicAccessBlock, ?policyStatus, ?acl. */
const bucket = (o: { pab?: HttpReply; policyPublic?: boolean; acl?: string[] } = {}): Route => (req) => {
  if ("encryption" in req.query) return SSE;
  if ("publicAccessBlock" in req.query) return o.pab ?? xmlErr(404, "NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found");
  if ("policyStatus" in req.query) return o.policyPublic === undefined ? xmlErr(404, "NoSuchBucketPolicy", "The bucket policy does not exist") : xml(`<PolicyStatus><IsPublic>${o.policyPublic}</IsPublic></PolicyStatus>`);
  if ("acl" in req.query) return aclXml(o.acl ?? []);
  return jsonErr(404, "NotFound", "no such sub-resource in the fake");
};
const instancesXml = (...ids: string[]) => xml(`<DescribeInstancesResponse><requestId>r</requestId><reservationSet><item><reservationId>r-1</reservationId><instancesSet>${ids.map((id) => `<item><instanceId>${id}</instanceId><instanceState><code>16</code><name>running</name></instanceState></item>`).join("")}</instancesSet></item></reservationSet></DescribeInstancesResponse>`);
const patchItem = (id: string, status: string, missing = 0) => ({ ComplianceType: "Patch", ResourceId: id, ResourceType: "ManagedInstance", Status: status, OverallSeverity: "UNSPECIFIED",
  NonCompliantSummary: { NonCompliantCount: missing }, ExecutionSummary: { ExecutionTime: 1760000000 } });

/** A well-configured account in one region: every check passes. Keyed "<service> <action>". */
function strong(): Record<string, Route> {
  return {
    "sts GetCallerIdentity": xml(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::${ACCT}:assumed-role/collector/s</Arn><UserId>AROA:s</UserId><Account>${ACCT}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`),
    "iam GetAccountSummary": xml(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>AccountMFAEnabled</key><value>1</value></entry><entry><key>AccountAccessKeysPresent</key><value>0</value></entry><entry><key>Users</key><value>2</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`),
    "iam GetCredentialReport": xml(`<GetCredentialReportResponse><GetCredentialReportResult><Content>${report([ROOT_ROW, userRow("alice.smith", true, true, inDays(-10)), userRow("ci-deployer", false, false, inDays(-30))])}</Content><ReportFormat>text/csv</ReportFormat><GeneratedTime>2026-10-15T11:00:00Z</GeneratedTime></GetCredentialReportResult></GetCredentialReportResponse>`),
    "iam ListUsers": xml(`<ListUsersResponse><ListUsersResult><IsTruncated>false</IsTruncated><Users><member><UserName>alice.smith</UserName><UserId>AIDAALICE0000000001</UserId></member><member><UserName>ci-deployer</UserName><UserId>AIDACIDEP0000000002</UserId></member></Users></ListUsersResult></ListUsersResponse>`),
    "iam GetAccountPasswordPolicy": xml(`<GetAccountPasswordPolicyResponse><GetAccountPasswordPolicyResult><PasswordPolicy><MinimumPasswordLength>14</MinimumPasswordLength><PasswordReusePrevention>24</PasswordReusePrevention></PasswordPolicy></GetAccountPasswordPolicyResult></GetAccountPasswordPolicyResponse>`),
    "cloudtrail DescribeTrails": json({ trailList: [{ Name: "org", TrailARN: `arn:aws:cloudtrail:us-east-1:${ACCT}:trail/org`, HomeRegion: "us-east-1", IsMultiRegionTrail: true, LogFileValidationEnabled: true, KmsKeyId: `arn:aws:kms:us-east-1:${ACCT}:key/k1`, S3BucketName: "trail-logs" }] }),
    "cloudtrail GetTrailStatus": json({ IsLogging: true }),
    "guardduty GET /detector": json({ detectorIds: ["d1"] }),
    "guardduty GET /detector/d1": json({ status: "ENABLED", findingPublishingFrequency: "SIX_HOURS", features: [{ name: "CLOUD_TRAIL", status: "ENABLED" }, { name: "EBS_MALWARE_PROTECTION", status: "ENABLED" }] }),
    "securityhub GET /accounts": json({ HubArn: `arn:aws:securityhub:us-east-1:${ACCT}:hub/default`, SubscribedAt: "2025-01-01T00:00:00Z" }),
    "securityhub GET /hubv2": json({ HubV2Arn: `arn:aws:securityhub:us-east-1:${ACCT}:hubv2/default`, SubscribedAt: "2026-01-01T00:00:00Z", Features: {} }),
    "config DescribeConfigurationRecorderStatus": json({ ConfigurationRecordersStatus: [{ name: "default", recording: true, lastStatus: "SUCCESS" }] }),
    "s3 GET /v20180820/configuration/publicAccessBlock": pab(true),
    "s3 GET /": xml(`<ListAllMyBucketsResult><Owner><ID>o</ID></Owner><Buckets><Bucket><Name>logs</Name><CreationDate>2025-01-01T00:00:00Z</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>`),
    "s3 GET /logs": bucket(),
    "ec2 GetEbsEncryptionByDefault": xml(`<GetEbsEncryptionByDefaultResponse><requestId>r</requestId><ebsEncryptionByDefault>true</ebsEncryptionByDefault></GetEbsEncryptionByDefaultResponse>`),
    "rds DescribeDBInstances": rdsXml(true, false, 7),
    "ec2 DescribeSecurityGroups": sgXml(perm("tcp", 443, 443, "0.0.0.0/0") + perm("tcp", 22, 22, "10.0.0.0/8")),
    "kms ListKeys": json({ Keys: [{ KeyId: "k1", KeyArn: `arn:aws:kms:us-east-1:${ACCT}:key/k1` }, { KeyId: "aws1", KeyArn: `arn:aws:kms:us-east-1:${ACCT}:key/aws1` }], Truncated: false }),
    "kms DescribeKey": (req) => json({ KeyMetadata: JSON.parse(req.body).KeyId === "k1"
      ? { KeyId: "k1", KeyManager: "CUSTOMER", KeySpec: "SYMMETRIC_DEFAULT", KeyState: "Enabled", Origin: "AWS_KMS" }
      : { KeyId: "aws1", KeyManager: "AWS", KeySpec: "SYMMETRIC_DEFAULT", KeyState: "Enabled", Origin: "AWS_KMS" } }),
    "kms GetKeyRotationStatus": json({ KeyRotationEnabled: true, RotationPeriodInDays: 365 }),
    "backup GET /backup/plans/": json({ BackupPlansList: [{ BackupPlanName: "daily", BackupPlanId: "p1" }] }),
    "ec2 DescribeVpcs": xml(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet></DescribeVpcsResponse>`),
    "ec2 DescribeFlowLogs": xml(`<DescribeFlowLogsResponse><flowLogSet><item><flowLogId>fl-1</flowLogId><resourceId>vpc-1</resourceId><flowLogStatus>ACTIVE</flowLogStatus></item></flowLogSet></DescribeFlowLogsResponse>`),
    "access-analyzer GET /analyzer": json({ analyzers: [{ name: "account", status: "ACTIVE", type: "ACCOUNT" }] }),
    "ec2 DescribeInstances": instancesXml("i-0abc"),
    "ssm ListResourceComplianceSummaries": json({ ResourceComplianceSummaryItems: [patchItem("i-0abc", "COMPLIANT")] }),
  };
}

const keyOf = (r: AwsRequest) => `${r.service} ${r.action}`;

function fakeAws(over: Record<string, Route> = {}, calls: AwsRequest[] = [], sleeps: number[] = []): AwsTransport {
  const routes = { ...strong(), ...over };
  return {
    async send(req) {
      calls.push(req);
      const r = routes[keyOf(req)];
      if (r === undefined) return jsonErr(404, "NotFound", `no fake for ${keyOf(req)}`);
      return typeof r === "function" ? r(req) : r;
    },
    async sleep(ms) { sleeps.push(ms); },
  };
}

async function run(t: AwsTransport | null, opts: Record<string, OptionValue> = {}, env: NodeJS.ProcessEnv = {}): Promise<Result[]> {
  return aws.run({ opts, env, clients: { aws: t }, now: NOW, warn: () => {} });
}
const of = (rs: Result[], check: string) => rs.filter((r) => r.check === `aws.${check}`);

const FAILS: Record<string, Record<string, Route>> = {
  root_mfa: { "iam GetAccountSummary": xml(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>AccountMFAEnabled</key><value>0</value></entry><entry><key>AccountAccessKeysPresent</key><value>0</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`) },
  root_no_access_keys: { "iam GetAccountSummary": xml(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>AccountMFAEnabled</key><value>1</value></entry><entry><key>AccountAccessKeysPresent</key><value>1</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`) },
  iam_users_mfa: { "iam GetCredentialReport": xml(`<GetCredentialReportResponse><GetCredentialReportResult><Content>${report([ROOT_ROW, userRow("alice.smith", true, false)])}</Content></GetCredentialReportResult></GetCredentialReportResponse>`) },
  access_keys_rotated: { "iam GetCredentialReport": xml(`<GetCredentialReportResponse><GetCredentialReportResult><Content>${report([ROOT_ROW, userRow("alice.smith", true, true), userRow("ci-deployer", false, false, inDays(-200))])}</Content></GetCredentialReportResult></GetCredentialReportResponse>`) },
  password_policy: { "iam GetAccountPasswordPolicy": xmlErr(404, "NoSuchEntity", "The Password Policy with domain name 111122223333 cannot be found.") },
  cloudtrail_multi_region: { "cloudtrail DescribeTrails": json({ trailList: [{ Name: "one", TrailARN: "arn:t/one", HomeRegion: "us-east-1", IsMultiRegionTrail: true, LogFileValidationEnabled: false, KmsKeyId: "k" }] }) },
  cloudtrail_kms_encrypted: { "cloudtrail DescribeTrails": json({ trailList: [{ Name: "org", TrailARN: "arn:t/org", HomeRegion: "us-east-1", IsMultiRegionTrail: true, LogFileValidationEnabled: true }] }) },
  guardduty_enabled: { "guardduty GET /detector": json({ detectorIds: [] }) },
  securityhub_enabled: { "securityhub GET /accounts": jsonErr(401, "InvalidAccessException", "Account 111122223333 is not subscribed to AWS Security Hub") },
  config_recorder_on: { "config DescribeConfigurationRecorderStatus": json({ ConfigurationRecordersStatus: [{ name: "default", recording: false }] }) },
  s3_account_public_access_block: { "s3 GET /v20180820/configuration/publicAccessBlock": pab(false) },
  s3_bucket_encryption: { "s3 GET /logs": xmlErr(404, "ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found") },
  ebs_encryption_default: { "ec2 GetEbsEncryptionByDefault": xml(`<GetEbsEncryptionByDefaultResponse><ebsEncryptionByDefault>false</ebsEncryptionByDefault></GetEbsEncryptionByDefaultResponse>`) },
  rds_encrypted: { "rds DescribeDBInstances": rdsXml(false, false, 7) },
  rds_not_public: { "rds DescribeDBInstances": rdsXml(true, true, 7) },
  rds_automated_backups: { "rds DescribeDBInstances": rdsXml(true, false, 0) },
  sg_no_open_admin_ports: { "ec2 DescribeSecurityGroups": sgXml(perm("tcp", 3000, 4000, "0.0.0.0/0")) },
  kms_rotation: { "kms GetKeyRotationStatus": json({ KeyRotationEnabled: false }) },
  backup_plans_exist: { "backup GET /backup/plans/": json({ BackupPlansList: [] }) },
  vpc_flow_logs: { "ec2 DescribeFlowLogs": xml(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`) },
  access_analyzer_enabled: { "access-analyzer GET /analyzer": json({ analyzers: [{ name: "old", status: "DISABLED", type: "ACCOUNT" }] }) },
  iam_users_inactive: { "iam GetCredentialReport": xml(`<GetCredentialReportResponse><GetCredentialReportResult><Content>${report([ROOT_ROW, userRow("alice.smith", true, true, undefined, inDays(-200))])}</Content></GetCredentialReportResult></GetCredentialReportResponse>`) },
  s3_bucket_not_public: { "s3 GET /v20180820/configuration/publicAccessBlock": xmlErr(404, "NoSuchPublicAccessBlockConfiguration", "none"), "s3 GET /logs": bucket({ policyPublic: true }) },
  guardduty_malware_protection: { "guardduty GET /detector/d1": json({ status: "ENABLED", features: [{ name: "EBS_MALWARE_PROTECTION", status: "DISABLED" }] }) },
  ssm_patch_compliance: { "ssm ListResourceComplianceSummaries": json({ ResourceComplianceSummaryItems: [patchItem("i-0abc", "NON_COMPLIANT", 3)] }) },
};

test("every check the AWS source declares has a pass and a fail case here", () => {
  assert.deepEqual(Object.keys(FAILS).sort(), [...AWS_CHECKS].sort());
  assert.deepEqual(aws.emits, AWS_CHECKS.map((c) => `aws.${c}`));
});

test("a well-configured account passes every check", async () => {
  const rs = await run(fakeAws());
  for (const c of AWS_CHECKS) {
    const mine = of(rs, c);
    assert.ok(mine.length >= 1, `${c}: no result`);
    for (const r of mine) assert.equal(r.result, "pass", `${c} [${r.resource}]: ${r.detail}`);
  }
});

for (const [check, over] of Object.entries(FAILS)) {
  test(`aws ${check}: fails with the observed value when weakened`, async () => {
    const fail = of(await run(fakeAws(over)), check);
    assert.ok(fail.some((r) => r.result === "fail"), `${check}: ${JSON.stringify(fail)}`);
    for (const r of fail) assert.ok(r.detail.length > 0 && r.detail.length <= 1000);
  });
}

test("security group rules: protocol -1 and ::/0 count as open; egress is ignored", async () => {
  const all = of(await run(fakeAws({ "ec2 DescribeSecurityGroups": sgXml(`<item><ipProtocol>-1</ipProtocol><ipRanges/><ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges></item>`) })), "sg_no_open_admin_ports");
  assert.equal(all[0].result, "fail");
  assert.match(all[0].detail, /22, 3389/);
  // The strong fixture has 0.0.0.0/0 in egress only (and 22 from 10/8): pass.
  assert.equal(of(await run(fakeAws()), "sg_no_open_admin_ports")[0].result, "pass");
});

test("AccessDenied on every call gives skipped, never pass", async () => {
  const denied: AwsTransport = {
    async send(req) {
      if (req.action === "GetCallerIdentity") return strong()["sts GetCallerIdentity"] as HttpReply;
      if (req.service === "ec2") return ec2Err(403, "UnauthorizedOperation");
      if (["iam", "rds", "sts"].includes(req.service)) return xmlErr(403, "AccessDenied", "User is not authorized");
      if (req.service === "s3") return xml(`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`, 403);
      return jsonErr(403, "AccessDeniedException", "not authorized");
    },
  };
  const rs = await run(denied);
  assert.ok(rs.length >= AWS_CHECKS.length);
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  for (const c of AWS_CHECKS) assert.ok(of(rs, c).length >= 1, `${c} has no result`);
  assert.ok(rs.every((r) => /403|AccessDenied|UnauthorizedOperation/.test(r.detail)), "the detail names the refusal");
});

test("no credentials: every check is skipped", async () => {
  const rs = await run(null);
  assert.equal(rs.length, AWS_CHECKS.length);
  for (const r of rs) assert.equal(r.result, "skipped");
  const env = await aws.run({ opts: {}, env: {}, clients: {}, now: NOW, warn: () => {} });
  assert.ok(env.every((r) => r.result === "skipped" && /no AWS credentials/.test(r.detail)));
});

test("unknown account (GetCallerIdentity refused): every check skipped", async () => {
  const rs = await run(fakeAws({ "sts GetCallerIdentity": xmlErr(403, "InvalidClientTokenId", "The security token included in the request is invalid") }));
  assert.equal(rs.length, AWS_CHECKS.length);
  assert.ok(rs.every((r) => r.result === "skipped"));
});

test("pagination: IAM Marker, EC2 NextToken, KMS NextMarker, S3 ContinuationToken, GuardDuty nextToken", async () => {
  const calls: AwsRequest[] = [];
  const t = fakeAws({
    "iam ListUsers": (req) => req.query.Marker
      ? xml(`<ListUsersResponse><ListUsersResult><IsTruncated>false</IsTruncated><Users><member><UserName>ci-deployer</UserName><UserId>AIDACIDEP0000000002</UserId></member></Users></ListUsersResult></ListUsersResponse>`)
      : xml(`<ListUsersResponse><ListUsersResult><IsTruncated>true</IsTruncated><Marker>m2</Marker><Users><member><UserName>alice.smith</UserName><UserId>AIDAALICE0000000001</UserId></member></Users></ListUsersResult></ListUsersResponse>`),
    "ec2 DescribeSecurityGroups": (req) => req.query.NextToken
      ? xml(`<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-2</groupId><ipPermissions>${perm("tcp", 22, 22, "0.0.0.0/0")}</ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>`)
      : xml(`<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-1</groupId><ipPermissions/></item></securityGroupInfo><nextToken>t2</nextToken></DescribeSecurityGroupsResponse>`),
    "kms ListKeys": (req) => JSON.parse(req.body).Marker
      ? json({ Keys: [{ KeyId: "k1", KeyArn: "arn:k1b" }], Truncated: false })
      : json({ Keys: [{ KeyId: "k1", KeyArn: "arn:k1a" }], Truncated: true, NextMarker: "n2" }),
    "s3 GET /": (req) => req.query["continuation-token"]
      ? xml(`<ListAllMyBucketsResult><Buckets><Bucket><Name>logs</Name><BucketRegion>us-east-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>`)
      : xml(`<ListAllMyBucketsResult><Buckets><Bucket><Name>logs</Name><BucketRegion>us-east-1</BucketRegion></Bucket></Buckets><ContinuationToken>c2</ContinuationToken></ListAllMyBucketsResult>`),
    "guardduty GET /detector": (req) => req.query.nextToken ? json({ detectorIds: ["d1"] }) : json({ detectorIds: [], nextToken: "g2" }),
  }, calls);
  const rs = await run(t);
  assert.deepEqual(of(rs, "sg_no_open_admin_ports").map((r) => [r.resource, r.result]), [["security group us-east-1/sg-1", "pass"], ["security group us-east-1/sg-2", "fail"]]);
  assert.deepEqual(of(rs, "kms_rotation").map((r) => r.resource), ["kms key arn:k1a", "kms key arn:k1b"]);
  assert.equal(of(rs, "s3_bucket_encryption").length, 2);
  assert.equal(of(rs, "guardduty_enabled")[0].result, "pass");
  assert.ok(of(rs, "access_keys_rotated").some((r) => r.resource === "iam user AIDACIDEP0000000002"), "second ListUsers page used");
  assert.ok(calls.some((c) => c.action === "ListUsers" && c.query.Marker === "m2"));
  assert.ok(calls.some((c) => c.action === "DescribeSecurityGroups" && c.query.NextToken === "t2"));
});

test("throttling: a 400 Throttling and a 429 are retried with backoff, then the answer is used", async () => {
  const sleeps: number[] = [];
  let n = 0, m = 0;
  const t = fakeAws({
    "iam GetAccountSummary": (_req) => (++n <= 2 ? xmlErr(400, "Throttling", "Rate exceeded") : (strong()["iam GetAccountSummary"] as HttpReply)),
    "guardduty GET /detector": () => (++m === 1 ? { ...jsonErr(429, "TooManyRequestsException", "slow down"), headers: { "retry-after": "3" } } : json({ detectorIds: ["d1"] })),
  }, [], sleeps);
  const rs = await run(t);
  assert.equal(of(rs, "root_mfa")[0].result, "pass");
  assert.equal(of(rs, "guardduty_enabled")[0].result, "pass");
  assert.deepEqual(sleeps.slice(0, 3), [500, 1000, 3000]);
});

test("throttled on every attempt: skipped, never pass", async () => {
  const rs = await run(fakeAws({ "ec2 GetEbsEncryptionByDefault": ec2Err(503, "RequestLimitExceeded") }));
  const e = of(rs, "ebs_encryption_default");
  assert.equal(e[0].result, "skipped");
  assert.match(e[0].detail, /RequestLimitExceeded/);
});

test("the credential report is generated when missing", async () => {
  const calls: AwsRequest[] = [];
  let made = false;
  const t = fakeAws({
    "iam GenerateCredentialReport": () => { made = true; return xml(`<GenerateCredentialReportResponse><GenerateCredentialReportResult><State>STARTED</State></GenerateCredentialReportResult></GenerateCredentialReportResponse>`); },
    "iam GetCredentialReport": () => (made ? (strong()["iam GetCredentialReport"] as HttpReply) : xmlErr(410, "ReportNotPresent", "Credential report not present")),
  }, calls);
  const rs = await run(t);
  assert.ok(made);
  assert.equal(of(rs, "iam_users_mfa")[0].result, "pass");
});

test("users are named by IAM user id, never by user name", async () => {
  const rs = await run(fakeAws());
  const users = rs.filter((r) => r.resource.startsWith("iam user"));
  assert.ok(users.length >= 2);
  for (const r of rs) assert.ok(!/alice|ci-deployer/.test(r.resource + r.detail), `${r.check}: ${r.resource} ${r.detail}`);
});

test("no secret from the environment appears in any result, even when an error echoes it", async () => {
  const env = { AWS_ACCESS_KEY_ID: "AKIAEXAMPLEACCESS01", AWS_SECRET_ACCESS_KEY: "wJalrSECRETvalueEXAMPLEKEY0000", AWS_SESSION_TOKEN: "FwoGZXIvYXdzSESSIONTOKENexample" };
  const t = fakeAws({ "iam GetAccountPasswordPolicy": xmlErr(403, "AccessDenied", `denied for ${env.AWS_ACCESS_KEY_ID} token ${env.AWS_SESSION_TOKEN} secret ${env.AWS_SECRET_ACCESS_KEY}`) });
  const rs = await run(t, {}, env);
  const text = JSON.stringify(rs);
  for (const v of Object.values(env)) assert.ok(!text.includes(v), `leaked ${v.slice(0, 6)}…`);
  assert.match(of(rs, "password_policy")[0].detail, /\[redacted\]/);
});

test("--aws-regions runs the regional checks once per region", async () => {
  const calls: AwsRequest[] = [];
  const rs = await run(fakeAws({}, calls), { "aws-regions": ["us-east-1,ca-central-1"] });
  assert.deepEqual(of(rs, "guardduty_enabled").map((r) => r.resource), [`aws account ${ACCT} region us-east-1`, `aws account ${ACCT} region ca-central-1`]);
  assert.ok(calls.some((c) => c.service === "ec2" && c.region === "ca-central-1"));
});

test("(check, resource) is unique and every result names its resource", async () => {
  const rs = await run(fakeAws());
  const keys = rs.map((r) => `${r.check}|${r.resource}`);
  assert.equal(new Set(keys).size, keys.length);
});

test("only read actions are sent", async () => {
  const calls: AwsRequest[] = [];
  await run(fakeAws({}, calls));
  assert.ok(calls.length > 20);
  for (const c of calls) {
    assert.ok(isReadAction(c.action), c.action);
    assert.ok(c.method === "GET" || (c.method === "POST" && /\.(Get|List|Describe)/.test(c.headers["x-amz-target"] ?? "")), `${c.method} ${c.action}`);
  }
  assert.equal(isReadAction("DeleteTrail"), false);
  assert.equal(isReadAction("PutBucketPolicy"), false);
});

test("the fetch transport signs, sends GET, and refuses a write action", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const t = fetchAwsTransport({ accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", sessionToken: "tok" },
    (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("<ok/>", { status: 200 }); }) as unknown as typeof fetch,
    () => new Date("2015-08-30T12:36:00Z"));
  await t.send({ service: "iam", region: "us-east-1", method: "GET", host: "iam.amazonaws.com", path: "/", query: { Action: "ListUsers", Version: "2010-05-08" }, headers: {}, body: "", action: "ListUsers" });
  assert.equal(seen[0].url, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08");
  assert.equal(seen[0].init.method, "GET");
  const h = seen[0].init.headers as Record<string, string>;
  assert.match(h.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/us-east-1\/iam\/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$/);
  assert.equal(h["x-amz-security-token"], "tok");
  await assert.rejects(t.send({ service: "iam", region: "us-east-1", method: "GET", host: "iam.amazonaws.com", path: "/", query: { Action: "DeleteUser" }, headers: {}, body: "", action: "DeleteUser" }), /not a read action/);
  await assert.rejects(t.send({ service: "kms", region: "us-east-1", method: "POST", host: "kms.us-east-1.amazonaws.com", path: "/", query: {}, headers: {}, body: "{}", action: "ListKeys" }), /without x-amz-target/);
});

// ── SigV4 against AWS's published vectors ─────────────────────────────────────────────────────────
// Credentials, date and expected values from the AWS SigV4 test suite (get-vanilla,
// get-vanilla-query-order-key-case, get-vanilla-query-unreserved) and the IAM user guide's
// ListUsers example.

const EX = { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" };
const T = new Date("2015-08-30T12:36:00Z");
const vanilla = (query: Record<string, string>) => sign({ method: "GET", host: "example.amazonaws.com", path: "/", query, headers: {}, body: "", service: "service", region: "us-east-1", date: T }, EX);

test("SigV4 get-vanilla", () => {
  assert.equal(vanilla({}).headers.authorization,
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
});

test("SigV4 get-vanilla-query-order-key-case and get-vanilla-query-unreserved", () => {
  assert.equal(vanilla({ Param2: "value2", Param1: "value1" }).signature, "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
  const u = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  assert.equal(vanilla({ [u]: u }).signature, "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197");
});

test("SigV4 IAM ListUsers example: signing key and signature", () => {
  assert.equal(signingKey(EX.secretAccessKey, "20150830", "us-east-1", "iam").toString("hex"), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
  const s = sign({ method: "GET", host: "iam.amazonaws.com", path: "/", query: { Action: "ListUsers", Version: "2010-05-08" }, headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" }, body: "", service: "iam", region: "us-east-1", date: T }, EX);
  assert.equal(s.signature, "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
});

test("the XML reader handles namespaces, entities, CDATA and self-closing tags", () => {
  const x = parseXml(`<?xml version="1.0"?><a:R xmlns:a="u"><a:M>x &amp; y &#x41;</a:M><E/><C><![CDATA[<raw>]]></C></a:R>`);
  assert.equal(deepText(x, "M"), "x & y A");
  assert.equal(deepText(x, "C"), "<raw>");
  assert.throws(() => parseXml("<a><b></a>"));
});

// Security Hub CSPM (DescribeHub) and the newer AWS Security Hub (DescribeSecurityHubV2) share one endpoint
// and IAM prefix; the check reads both, decides on CSPM, and says which product each part of the detail is.
test("aws securityhub_enabled: names Security Hub CSPM and AWS Security Hub separately", async () => {
  const notCspm = { "securityhub GET /accounts": jsonErr(401, "InvalidAccessException", "Account 111122223333 is not subscribed to AWS Security Hub") };
  const v2Only = of(await run(fakeAws(notCspm)), "securityhub_enabled");
  assert.equal(v2Only.length, 1);
  assert.equal(v2Only[0].result, "fail");
  assert.match(v2Only[0].detail, /Security Hub CSPM is not enabled/);
  assert.match(v2Only[0].detail, /AWS Security Hub is on \(DescribeSecurityHubV2/);
  assert.match(v2Only[0].detail, /turn on Security Hub CSPM too/);

  const neither = of(await run(fakeAws({ ...notCspm, "securityhub GET /hubv2": jsonErr(404, "ResourceNotFoundException", "not found") })), "securityhub_enabled");
  assert.equal(neither[0].result, "fail");
  assert.match(neither[0].detail, /AWS Security Hub is not enabled/);

  const cspmOnly = of(await run(fakeAws({ "securityhub GET /hubv2": jsonErr(404, "ResourceNotFoundException", "not found") })), "securityhub_enabled");
  assert.equal(cspmOnly[0].result, "pass", cspmOnly[0].detail);
  assert.match(cspmOnly[0].detail, /Security Hub CSPM enabled \(DescribeHub/);

  const v2Denied = of(await run(fakeAws({ "securityhub GET /hubv2": jsonErr(403, "AccessDeniedException", "not authorized to perform: securityhub:DescribeSecurityHubV2") })), "securityhub_enabled");
  assert.equal(v2Denied[0].result, "pass", "a policy without DescribeSecurityHubV2 must not turn a CSPM pass into anything else");
  assert.match(v2Denied[0].detail, /AWS Security Hub not readable/);
});

test("root_mfa: a root user with no password, access key or signing certificate passes without MFA (Security Hub IAM.9)", async () => {
  const summary = (entries: Record<string, string>) => ({ "iam GetAccountSummary": xml(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap>${Object.entries(entries).map(([k, v]) => `<entry><key>${k}</key><value>${v}</value></entry>`).join("")}</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`) });
  const none = of(await run(fakeAws(summary({ AccountMFAEnabled: "0", AccountPasswordPresent: "0", AccountAccessKeysPresent: "0", AccountSigningCertificatesPresent: "0" }))), "root_mfa")[0];
  assert.equal(none.result, "pass", none.detail);
  assert.match(none.detail, /no password, access key or signing certificate/);
  // A password left, or a key not reported, keeps the fail.
  assert.equal(of(await run(fakeAws(summary({ AccountMFAEnabled: "0", AccountPasswordPresent: "1", AccountAccessKeysPresent: "0", AccountSigningCertificatesPresent: "0" }))), "root_mfa")[0].result, "fail");
  assert.equal(of(await run(fakeAws(summary({ AccountMFAEnabled: "0", AccountPasswordPresent: "0", AccountAccessKeysPresent: "0" }))), "root_mfa")[0].result, "fail");
});

test("iam_users_inactive: a never-used password counts from the user's creation; a recent key use keeps the user active", async () => {
  const never = of(await run(fakeAws({ "iam GetCredentialReport": xml(`<GetCredentialReportResponse><GetCredentialReportResult><Content>${report([ROOT_ROW, userRow("bob", true, true, undefined, "no_information")])}</Content></GetCredentialReportResult></GetCredentialReportResponse>`) })), "iam_users_inactive");
  assert.equal(never[0].result, "fail");
  assert.match(never[0].detail, /console password active; last used \d+ day\(s\) ago/);
  assert.ok(!/bob/.test(never[0].resource + never[0].detail));
  const keyOnly = of(await run(fakeAws()), "iam_users_inactive").find((r) => /AIDACIDEP/.test(r.resource));
  assert.equal(keyOnly?.result, "pass");
});

test("s3_bucket_not_public: account RestrictPublicBuckets and IgnorePublicAcls pass without reading the bucket; a public ACL grant fails", async () => {
  const calls: AwsRequest[] = [];
  assert.equal(of(await run(fakeAws({}, calls)), "s3_bucket_not_public")[0].result, "pass");
  assert.ok(!calls.some((c) => "policyStatus" in c.query || "acl" in c.query), "no bucket policy or ACL read when the account blocks both");
  const acl = of(await run(fakeAws({ "s3 GET /v20180820/configuration/publicAccessBlock": xmlErr(404, "NoSuchPublicAccessBlockConfiguration", "none"), "s3 GET /logs": bucket({ acl: [ALL_USERS] }) })), "s3_bucket_not_public");
  assert.equal(acl[0].result, "fail");
  assert.match(acl[0].detail, /AllUsers READ/);
  const none = of(await run(fakeAws({ "s3 GET /v20180820/configuration/publicAccessBlock": xmlErr(404, "NoSuchPublicAccessBlockConfiguration", "none") })), "s3_bucket_not_public");
  assert.equal(none[0].result, "pass", "no policy (NoSuchBucketPolicy) and no public grant");
  const bucketBlock = pab(true);
  const own = of(await run(fakeAws({ "s3 GET /v20180820/configuration/publicAccessBlock": xmlErr(404, "NoSuchPublicAccessBlockConfiguration", "none"), "s3 GET /logs": bucket({ pab: bucketBlock, policyPublic: true, acl: [ALL_USERS] }) })), "s3_bucket_not_public");
  assert.equal(own[0].result, "pass", "the bucket's own Block Public Access restricts the public policy and ignores the ACL");
});

test("guardduty_malware_protection: read from the older dataSources shape too; no detector fails", async () => {
  const old = of(await run(fakeAws({ "guardduty GET /detector/d1": json({ status: "ENABLED", dataSources: { malwareProtection: { scanEc2InstanceWithFindings: { ebsVolumes: { status: "ENABLED" } } } } }) })), "guardduty_malware_protection");
  assert.equal(old[0].result, "pass");
  const none = of(await run(fakeAws({ "guardduty GET /detector": json({ detectorIds: [] }) })), "guardduty_malware_protection");
  assert.equal(none[0].result, "fail");
});

test("ssm_patch_compliance: an instance Patch Manager never scanned fails; no running instance is skipped; the filter asks for Patch", async () => {
  const calls: AwsRequest[] = [];
  const unscanned = of(await run(fakeAws({ "ec2 DescribeInstances": instancesXml("i-0abc", "i-0new") }, calls)), "ssm_patch_compliance");
  assert.deepEqual(unscanned.map((r) => [r.resource, r.result]), [["ec2 instance us-east-1/i-0abc", "pass"], ["ec2 instance us-east-1/i-0new", "fail"]]);
  const ssm = calls.find((c) => c.action === "ListResourceComplianceSummaries")!;
  assert.equal(ssm.headers["x-amz-target"], "AmazonSSM.ListResourceComplianceSummaries");
  assert.deepEqual(JSON.parse(ssm.body).Filters, [{ Key: "ComplianceType", Values: ["Patch"], Type: "EQUAL" }]);
  const di = calls.find((c) => c.action === "DescribeInstances")!;
  assert.equal(di.query["Filter.1.Name"], "instance-state-name");
  const idle = of(await run(fakeAws({ "ec2 DescribeInstances": instancesXml() })), "ssm_patch_compliance");
  assert.equal(idle[0].result, "skipped");
});
