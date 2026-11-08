// Fixtures for the aws source, shared by test/aws.test.ts and the end-to-end run (test/e2e.test.ts).
import { aws } from "../../../src/sources/aws.ts";
import { fetchAwsTransport, isReadAction, type AwsRequest, type AwsTransport } from "../../../src/sources/aws/api.ts";
import { AWS_CHECKS } from "../../../src/sources/aws/checks.ts";
import { sign, signingKey } from "../../../src/sources/aws/sigv4.ts";
import { parseXml, deepText } from "../../../src/sources/aws/xml.ts";
import type { HttpReply } from "../../../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../../../src/types.ts";
import { NOW, inDays } from "../../helpers.ts";

export const ACCT = "111122223333";
export const xml = (body: string, status = 200): HttpReply => ({ status, headers: { "content-type": "text/xml" }, body: `<?xml version="1.0" encoding="UTF-8"?>${body}` });
export const json = (o: unknown, status = 200): HttpReply => ({ status, headers: { "content-type": "application/json" }, body: JSON.stringify(o) });
export const xmlErr = (status: number, code: string, message = "denied") => xml(`<ErrorResponse><Error><Type>Sender</Type><Code>${code}</Code><Message>${message}</Message></Error><RequestId>r</RequestId></ErrorResponse>`, status);
export const ec2Err = (status: number, code: string) => xml(`<Response><Errors><Error><Code>${code}</Code><Message>You are not authorized to perform this operation.</Message></Error></Errors><RequestID>r</RequestID></Response>`, status);
export const jsonErr = (status: number, type: string, message = "denied") => json({ __type: type, message }, status);

export const report = (rows: string[]) => Buffer.from([
  "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated",
  ...rows,
].join("\n")).toString("base64");
export const ROOT_ROW = `<root_account>,arn:aws:iam::${ACCT}:root,2020-01-01T00:00:00+00:00,not_supported,2026-10-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A`;
export const userRow = (name: string, console: boolean, mfa: boolean, keyRotated?: string, lastUsed = inDays(-5)) =>
  `${name},arn:aws:iam::${ACCT}:user/${name},2024-01-01T00:00:00+00:00,${console},${console ? lastUsed : "N/A"},N/A,N/A,${mfa},${keyRotated ? "true" : "false"},${keyRotated ?? "N/A"},${keyRotated ? lastUsed : "N/A"},N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A`;

export const sgXml = (perms: string) => xml(`<DescribeSecurityGroupsResponse><requestId>r</requestId><securityGroupInfo><item><ownerId>${ACCT}</ownerId><groupId>sg-1</groupId><groupName>web</groupName><ipPermissions>${perms}</ipPermissions><ipPermissionsEgress><item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissionsEgress></item></securityGroupInfo></DescribeSecurityGroupsResponse>`);
export const perm = (proto: string, from: number, to: number, cidr: string) => `<item><ipProtocol>${proto}</ipProtocol><fromPort>${from}</fromPort><toPort>${to}</toPort><ipRanges><item><cidrIp>${cidr}</cidrIp></item></ipRanges><ipv6Ranges/></item>`;
export const rdsXml = (enc: boolean, pub: boolean, keep: number) => xml(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>db1</DBInstanceIdentifier><StorageEncrypted>${enc}</StorageEncrypted><PubliclyAccessible>${pub}</PubliclyAccessible><BackupRetentionPeriod>${keep}</BackupRetentionPeriod></DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`);
export const pab = (v: boolean) => xml(`<PublicAccessBlockConfiguration xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>${v}</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`);

export type Route = HttpReply | ((req: AwsRequest) => HttpReply);

export const SSE = xml(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>`);
export const ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers";
export const aclXml = (grantees: string[]) => xml(`<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList><Grant><Grantee><ID>o</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>${grantees.map((u) => `<Grant><Grantee><URI>${u}</URI></Grantee><Permission>READ</Permission></Grant>`).join("")}</AccessControlList></AccessControlPolicy>`);
/** One bucket's sub-resources, by query: ?encryption, ?publicAccessBlock, ?policyStatus, ?acl. */
export const bucket = (o: { pab?: HttpReply; policyPublic?: boolean; acl?: string[] } = {}): Route => (req) => {
  if ("encryption" in req.query) return SSE;
  if ("publicAccessBlock" in req.query) return o.pab ?? xmlErr(404, "NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found");
  if ("policyStatus" in req.query) return o.policyPublic === undefined ? xmlErr(404, "NoSuchBucketPolicy", "The bucket policy does not exist") : xml(`<PolicyStatus><IsPublic>${o.policyPublic}</IsPublic></PolicyStatus>`);
  if ("acl" in req.query) return aclXml(o.acl ?? []);
  return jsonErr(404, "NotFound", "no such sub-resource in the fake");
};
export const instancesXml = (...ids: string[]) => xml(`<DescribeInstancesResponse><requestId>r</requestId><reservationSet><item><reservationId>r-1</reservationId><instancesSet>${ids.map((id) => `<item><instanceId>${id}</instanceId><instanceState><code>16</code><name>running</name></instanceState></item>`).join("")}</instancesSet></item></reservationSet></DescribeInstancesResponse>`);
export const patchItem = (id: string, status: string, missing = 0) => ({ ComplianceType: "Patch", ResourceId: id, ResourceType: "ManagedInstance", Status: status, OverallSeverity: "UNSPECIFIED",
  NonCompliantSummary: { NonCompliantCount: missing }, ExecutionSummary: { ExecutionTime: 1760000000 } });

/** A well-configured account in one region: every check passes. Keyed "<service> <action>". */
export function strong(): Record<string, Route> {
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
    "backup GET /backup-jobs/": json({ BackupJobs: [
      { BackupJobId: "j1", ResourceArn: `arn:aws:rds:us-east-1:${ACCT}:db:db1`, ResourceType: "RDS", State: "FAILED", CreationDate: NOW.getTime() / 1000 - 2 * 86400 },
      { BackupJobId: "j2", ResourceArn: `arn:aws:rds:us-east-1:${ACCT}:db:db1`, ResourceType: "RDS", State: "COMPLETED", CreationDate: NOW.getTime() / 1000 - 86400 },
      { BackupJobId: "j3", ResourceArn: `arn:aws:ec2:us-east-1:${ACCT}:volume/vol-1`, ResourceType: "EBS", State: "RUNNING", CreationDate: NOW.getTime() / 1000 - 3600 }] }),
    "backup GET /restore-jobs/": json({ RestoreJobs: [{ RestoreJobId: "r1", Status: "COMPLETED", ResourceType: "RDS", CreationDate: NOW.getTime() / 1000 - 40 * 86400, CompletionDate: NOW.getTime() / 1000 - 40 * 86400 }] }),
    "ec2 DescribeVpcs": xml(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet></DescribeVpcsResponse>`),
    "ec2 DescribeFlowLogs": xml(`<DescribeFlowLogsResponse><flowLogSet><item><flowLogId>fl-1</flowLogId><resourceId>vpc-1</resourceId><flowLogStatus>ACTIVE</flowLogStatus></item></flowLogSet></DescribeFlowLogsResponse>`),
    "access-analyzer GET /analyzer": json({ analyzers: [{ name: "account", status: "ACTIVE", type: "ACCOUNT" }] }),
    "ec2 DescribeInstances": instancesXml("i-0abc"),
    "ssm ListResourceComplianceSummaries": json({ ResourceComplianceSummaryItems: [patchItem("i-0abc", "COMPLIANT")] }),
  };
}

export const keyOf = (r: AwsRequest) => `${r.service} ${r.action}`;

export function fakeAws(over: Record<string, Route> = {}, calls: AwsRequest[] = [], sleeps: number[] = []): AwsTransport {
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
