// AWS: one account per run (the credentials' account), the regions in --aws-regions. Credentials come
// from the environment (see aws/api.ts envCredentials) and may assume --aws-role-arn first. Every call
// is a signed read; no SDK.

import type { OptionValue, Result, Source } from "../types.ts";
import { AWS_SECRET_ENVS, Aws, assumeRole, callerAccount, envCredentials, fetchAwsTransport, type AwsTransport } from "./aws/api.ts";
import { AWS_CHECKS, DEFAULT_INACTIVE_DAYS, DEFAULT_KEY_MAX_AGE_DAYS, accountChecks } from "./aws/checks.ts";
import { allSkipped, list, scrub } from "./shared-cloud.ts";

export const DEFAULT_AWS_REGION = "us-east-1";

const regionsOf = (opts: Record<string, OptionValue>, env: NodeJS.ProcessEnv) => {
  const r = list(opts["aws-regions"]);
  return r.length ? r : [env.AWS_REGION || env.AWS_DEFAULT_REGION || DEFAULT_AWS_REGION];
};

export const aws: Source = {
  name: "aws",
  options: {
    "aws-regions": { type: "string", multiple: true, help: "AWS regions to check, comma-separated (default AWS_REGION, else us-east-1); the first is the home region" },
    "aws-role-arn": { type: "string", help: "IAM role to assume with the environment's credentials before reading (read-only role)" },
    "aws-external-id": { type: "string", help: "external id for --aws-role-arn" },
    "aws-key-max-age-days": { type: "string", help: `oldest an active IAM access key may be (default ${DEFAULT_KEY_MAX_AGE_DAYS})` },
    "aws-inactive-days": { type: "string", help: `days an IAM user's password and active keys may go unused (default ${DEFAULT_INACTIVE_DAYS})` },
  },
  emits: AWS_CHECKS.map((c) => `aws.${c}`),
  describe(opts) {
    const r = list(opts["aws-regions"]);
    return `the credentials' AWS account / regions ${r.length ? r.join(",") : "default"}${typeof opts["aws-role-arn"] === "string" ? ` / role ${opts["aws-role-arn"]}` : ""}`;
  },
  async run(ctx) {
    const regions = regionsOf(ctx.opts, ctx.env);
    const skipAll = (reason: string): Result[] => allSkipped("aws", AWS_CHECKS, "aws account (unknown)", reason);
    const injected = ctx.clients.aws as AwsTransport | null | undefined;
    let transport: AwsTransport;
    const secrets: (string | undefined)[] = AWS_SECRET_ENVS.map((n) => ctx.env[n]);
    if (injected === null) return skipAll("no AWS credentials");
    if (injected) transport = injected;
    else {
      const c = await envCredentials(ctx.env, regions[0]);
      if (!c) return skipAll("no AWS credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (aws-actions/configure-aws-credentials does) or AWS_ROLE_ARN with AWS_WEB_IDENTITY_TOKEN_FILE");
      if ("error" in c) return skipAll(c.error);
      secrets.push(c.secretAccessKey, c.sessionToken);
      transport = fetchAwsTransport(c);
    }
    const roleArn = typeof ctx.opts["aws-role-arn"] === "string" ? ctx.opts["aws-role-arn"] : undefined;
    if (roleArn) {
      const extId = typeof ctx.opts["aws-external-id"] === "string" ? ctx.opts["aws-external-id"] : undefined;
      const c = await assumeRole(new Aws(transport).t, regions[0], roleArn, extId);
      if ("error" in c) return scrub(skipAll(c.error), secrets);
      secrets.push(c.secretAccessKey, c.sessionToken, extId);
      if (!injected) transport = fetchAwsTransport(c);
    }
    const api = new Aws(transport);
    const who = await callerAccount(api, regions[0]);
    if ("error" in who) return scrub(skipAll(`the credentials' account is unknown (sts:GetCallerIdentity: ${who.error})`), secrets);
    const days = Number(ctx.opts["aws-key-max-age-days"] ?? DEFAULT_KEY_MAX_AGE_DAYS);
    const idle = Number(ctx.opts["aws-inactive-days"] ?? DEFAULT_INACTIVE_DAYS);
    const results = await accountChecks(api, who.account, {
      regions, keyMaxAgeDays: Number.isFinite(days) && days > 0 ? days : DEFAULT_KEY_MAX_AGE_DAYS,
      inactiveDays: Number.isFinite(idle) && idle > 0 ? idle : DEFAULT_INACTIVE_DAYS, now: ctx.now,
    });
    return scrub(results, secrets);
  },
};
