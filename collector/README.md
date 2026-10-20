# Sagentix evidence collector

The collector runs in the customer's own CI. It reads the customer's systems with read-only credentials, runs checks, signs what it saw with an Ed25519 key and pushes the result to sos-app at `POST /api/collect`. sos-app maps each check to NIST SP 800-53 Rev. 5 controls and FedRAMP 20x KSIs itself. The collector reads the check list in `apps/sos-app/src/data/checks/<source>.json`, so it sends only check ids sos-app knows.

Version 0.2.0 has 27 sources and 2,731 checks in its catalogue (counted from `src/sources/index.ts` on 2026-10-20). Most of them come from engines the customer already runs (Prowler 824, DISA STIG profiles 1,347, ScubaGoggles and ScubaGear 267); the rest are the collector's own reads of Cloudflare, the clouds, identity providers, GitHub, device managers, the Mac it runs on and, since 2026-10-18, websites by URL. The first ten sources' 134 checks alone name 80 of the 610 SP 800-53 Rev. 5 controls and enhancements sos-app tracks (58 distinct base controls, counted 2026-10-20); policies cover 20 more, and the rest are procedures a person describes.

## Data flow

```
customer's CI (GitHub Actions, cron)
  │  reads with CLOUDFLARE_API_TOKEN_READONLY (GET only)     ──►  api.cloudflare.com
  │  optional: opa eval over `tofu show -json`                     (local, no network)
  │  signs the body with SAGENTIX_COLLECTOR_KEY (Ed25519)
  │  writes its own copy with --out
  ▼
HTTPS POST /api/collect  ──►  sos-app (stores the body in R2, results in D1)
```

Every connection starts in the customer's CI and goes out. The collector opens no port and sos-app never calls back. sos-app holds the public key and nothing else: no Cloudflare token, no state file, no private key. With `--out`, the customer keeps the exact bytes sent and the signature, so either side can prove later what was pushed.

## The short way: sos-app's "Connect your environment" screen

A customer does not need to read the rest of this file to start. sos-app's **Connect your environment** screen (the command centre's "Set up the collector" button; `apps/sos-app/docs/CONNECT.md`) asks what to look at, shows which requirements each asset helps prove, and writes the two files a runner needs: `sagentix-collector.config.json` (see [Config file](#config-file)) and either `.github/workflows/sagentix-collector.yml` or a `sagentix-collector.sh` for a server, Docker or a Mac. It lists the least-privilege access per source with the provider's pages, registers the public key and waits for the first signed push. The sections below are what those files do, source by source.

## Install

Node 24 or later. The source is TypeScript run by Node's type stripping, so there is no build step; `tsc` is a dev dependency used only by `npm run typecheck`.

```sh
cd collector
npm ci            # ajv 8.20.0 and ajv-formats 3.0.1 (v1 SDR validation); typescript 5.9.3, @types/node 24.13.6
npm test          # node:test, fakes only, no network
```

The OPA sub-source needs `opa` on PATH (`brew install opa`, or the `open-policy-agent/setup-opa` action) and OpenTofu 1.8 or later to produce the state.

## 1. Make a key

```sh
node src/cli.ts keygen --out sagentix-collector.pem
```

This writes an Ed25519 private key (PKCS8 PEM, mode 0600; it refuses to overwrite a file) and prints the raw 32-byte public key in base64.

## 2. Register the key in sos-app

In sos-app, open **Evidence**, then **Collector keys**, and paste the public key. An owner or admin does this; the call behind it is `POST /api/evidence/keys {publicKey, label}`. The key belongs to the organization, not to one FedRAMP target. sos-app answers with a key id, which the collector sends as `x-sagentix-key-id`. Revoking the key in sos-app makes every later push signed with it fail with 401.

Store the private key as the CI secret `SAGENTIX_COLLECTOR_KEY` (the PEM text) and delete the local file.

## 3. Create the read-only Cloudflare token

Either apply `iac/cloudflare/evidence-role` in your own account (it creates an account-owned token from read groups only, and refuses any group whose name does not end in " Read"), or create a token by hand with these permission groups:

| Scope | Permission group | Used by |
| --- | --- | --- |
| Zone | Zone Read | zone list and details |
| Zone | Zone Settings Read | TLS, HSTS, security level, browser check, Page Shield, security.txt |
| Zone | DNS Read | DNSSEC |
| Zone | Zone WAF Read | managed, custom and rate limiting rules; leaked credential detection |
| Zone | Bot Management Read | Bot Fight Mode |
| Zone | SSL and Certificates Read | edge certificate packs, custom hostnames |
| Account | Account Settings Read | 2FA enforcement, members and roles, audit log |
| Account | Account API Tokens Read | expiry of account-owned tokens |
| Account | Notifications Read | notification policies |
| Account | Access: Apps and Policies Read | Access applications and their policies |
| Account | Access: Organizations, Identity Providers, and Groups Read | organisation-wide independent MFA (without it, MFA set on the application or policy still counts) |
| Account | Zero Trust Read | Gateway rules, device posture rules |
| Account | Workers R2 Storage Read | r2.dev public access per bucket |

The names are Cloudflare's API names, matched per endpoint against `x-api-token-group` in Cloudflare's OpenAPI document (github.com/cloudflare/api-schemas). Two are not fully confirmed. Zero Trust Read: the OpenAPI names no group for `GET /accounts/{id}/gateway/rules` or `/devices/posture`. Account API Tokens Read: the OpenAPI names it, but the permissions reference page does not list it. If a group is missing, its checks come back `skipped`, never `pass`.

Store the token as the CI secret `CLOUDFLARE_API_TOKEN_READONLY`.

## 4. Run

```sh
node src/cli.ts run --source cloudflare \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem \
  --dry-run
```

`--dry-run` prints the payload, the headers and a pass/fail/skipped count, and posts nothing; it works without a key. Drop it to push. Options:

- `--zone <id>` (repeatable): zones to check. Default: every zone the token can list.
- `--account <id>` (repeatable): accounts to check. Default: the accounts of the zones read.
- `--max-super-admins <n>`: members allowed to hold Super Administrator (default 3).
- `--tofu-state <file>` and `--policy <dir>`: evaluate the Rego in `iac/policy/cloudflare` over `tofu show -json`.
- `--out <file>`: also write `{endpoint, keyId, publicKey, signature, body}` to a file. `body` is the exact string sent.
- `--catalog <dir>`: the check catalogue (default `../apps/sos-app/src/data/checks`). A check id not in it is dropped with a warning, because sos-app would refuse the whole push.

Exit codes: 0 sent (or dry run); 1 error (unreadable key, network failure, a failed engine run); 2 usage; 3 nothing to send, because every check was skipped; 4 sos-app refused the push, with its message printed (401 bad signature or revoked key, 409 replay, 400 unknown check or stale `issuedAt`).

### Config file

Instead of a long command line, put the sources and their options in `collector.config.json` and run one command:

```sh
node src/cli.ts run --config collector.config.json
```

```json
{
  "$schema": "https://github.com/Sagentix-Advisors-Inc/sagentix-collector/collector.config.schema.json",
  "endpoint": "https://<sos-app host>",
  "keyId": "<key id>",
  "keyFile": "sagentix-collector.pem",
  "out": "sagentix-push.json",
  "sources": {
    "web": { "web-url": ["https://www.example.ca/"], "web-proof": ["www.example.ca=<token from sos-app>"] },
    "macos": {},
    "trivy": { "trivy-report": "trivy.json" }
  }
}
```

Top-level keys are `endpoint` (required), `keyId`, `keyFile`, `out`, `dryRun` and `catalog`, the same as `--endpoint`, `--key-id`, `--key`, `--out`, `--dry-run` and `--catalog`. Under `sources`, each key is a source name and each option is that source's command-line option without the leading `--`: a string, `true`/`false` for a flag, or a list for a repeatable option. The file is checked against `collector.config.schema.json` (JSON Schema 2020-12, printed by `node src/cli.ts config-schema`), then every source name and option is checked against the sources themselves; a problem exits 2 with the path of the bad key.

The file holds no secret. The private key comes from the `keyFile` path or from `SAGENTIX_COLLECTOR_KEY`, and each source reads its credentials from the environment as before; a value that looks like a PEM block or a well-known token prefix (`ghp_`, `github_pat_`, `AKIA`, `xoxb-` …) is refused. Paths are relative to the directory the command runs in. Options given on the command line override the file's, and `--source` on the command line adds to the file's sources.

### The older v1 push

`--fedramp-target <id> [--class A|B|C|D]` sends the v1 format (`sagentix-fedramp-collect/1`) to `/api/fedramp/collect` instead. It carries the original 11 checks grouped into five KSIs with a Security Decision Record, validated locally against FedRAMP's schema. New installs should use the default v2 push; v1 stays for targets already wired to it.

## Run on a schedule from GitHub Actions

```yaml
name: sagentix-collector
on:
  schedule:
    - cron: "17 6 * * *"   # daily, 06:17 UTC
  workflow_dispatch: {}
permissions:
  contents: read
jobs:
  collect:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - name: Collect, sign and push
        working-directory: collector
        env:
          CLOUDFLARE_API_TOKEN_READONLY: ${{ secrets.CLOUDFLARE_API_TOKEN_READONLY }}
          SAGENTIX_COLLECTOR_KEY: ${{ secrets.SAGENTIX_COLLECTOR_KEY }}
        run: |
          npm ci
          node src/cli.ts run --source cloudflare \
            --endpoint "${{ vars.SAGENTIX_ENDPOINT }}" --key-id "${{ vars.SAGENTIX_KEY_ID }}" \
            --out "$RUNNER_TEMP/sagentix-push.json"
      - uses: actions/upload-artifact@v4
        with:
          name: sagentix-push
          path: ${{ runner.temp }}/sagentix-push.json
          retention-days: 400
```

The uploaded artifact is the customer's copy of each push. To add the OPA checks, install `opa` and `tofu` in the job, write the state with `tofu show -json > "$RUNNER_TEMP/state.json"` (the state backend's read credentials stay in your secrets), and add `--tofu-state "$RUNNER_TEMP/state.json"`. Pin each action to a commit SHA in your own repository; the tags above are for readability.

## Checks

Each check reports one result per resource: a zone, an account, a certificate pack, a custom hostname, an Access application, an API token or an R2 bucket. `detail` states the value observed. A call refused for lack of permission, or for a feature the plan lacks, gives `skipped`; so does a check with nothing to judge (no Access application, no R2 bucket, no custom hostname). A check that looks for something configured (Gateway rules, notification policies, rate limiting rules) fails when it finds none.

| Check (`cloudflare.`…) | What passes |
| --- | --- |
| `min_tls_version` | Zone minimum TLS is 1.2 or 1.3 |
| `tls_1_3` | TLS 1.3 is on at the edge |
| `always_use_https` | HTTP is redirected to HTTPS |
| `automatic_https_rewrites` | Automatic HTTPS rewrites are on |
| `ssl_mode` | Origin connections use Full (strict) |
| `hsts` | HSTS on, max-age ≥ 31536000 s, includeSubDomains |
| `dnssec` | DNSSEC status is `active` |
| `waf_managed_ruleset` | An enabled `execute` rule in `http_request_firewall_managed` |
| `account_enforces_2fa` | The account enforces 2FA |
| `members_have_2fa` | Every accepted member has 2FA on |
| `audit_log_available` | The account audit log is readable and not empty |
| `security_level` | Security level above `essentially_off` |
| `browser_integrity_check` | Browser Integrity Check is on |
| `waf_custom_rules` | An enabled custom rule that blocks or challenges |
| `rate_limiting_rules` | An enabled rule in `http_ratelimit` |
| `bot_protection` | Bot Fight Mode on, or Super Bot Fight Mode blocking or challenging definitely automated traffic |
| `leaked_credential_checks` | Leaked credential detection is on |
| `edge_certificates_valid` | Each certificate pack active, with > 30 days left (uploaded) or > 14 days (Cloudflare-managed) |
| `custom_hostname_min_tls` | Each custom hostname requires TLS 1.2 or higher |
| `page_shield` | Client-side security (Page Shield) is enabled; Pro plan or higher |
| `security_txt` | Cloudflare serves a security.txt with a contact |
| `super_admins_limited` | At most `--max-super-admins` members hold Super Administrator |
| `account_tokens_expire` | Each active account-owned API token has an expiry |
| `security_notifications` | An enabled notification policy for a DDoS, WAF anomaly, bot, BGP hijack, security insight or client-side security alert |
| `access_apps_have_policies` | Each Access application has an allow policy that names who may enter, and no bypass for everyone |
| `access_mfa_required` | Each allow policy of an Access application requires MFA: an `auth_method: mfa` rule, or Access independent MFA set on the policy, the application or the organisation (policy over application over organisation) |
| `access_session_duration` | Each Access application's session is 24 h or less (unset means Access's 24 h default) |
| `gateway_dns_filtering` | An enabled Gateway DNS rule with action `block`, and at least one DNS location or enrolled device sending queries to Gateway (without one, the rule filters nothing) |
| `device_posture_rules` | At least one device posture rule |
| `r2_public_access_off` | Each R2 bucket's r2.dev public access is off |

The OPA policies test 8 of these (the six TLS checks, `dnssec` and `waf_managed_ruleset`) against the OpenTofu state. Their results carry the same check ids, with resource `tofu <resource address>`, so sos-app shows the deployed value and the declared value side by side.

Left out on purpose: Logpush jobs (listing them requires Logs Write, `#logs:edit`, so a read-only token cannot), user-owned API tokens (an account token cannot read them), and Workers behind Access (routes do not map reliably to Access applications). HTTP/2, HTTP/3 and email obfuscation were judged too thin to count as evidence.

## Cloud, ticketing and training sources

Five more sources sit beside Cloudflare: `aws`, `azure`, `gcp`, `jira` and `lms`. Each follows the same rules: read-only credentials taken from the CI environment, one result per resource with the observed value in `detail`, `skipped` (never `pass`) when a call is refused or the feature is off, pagination followed to the end, retry with exponential backoff on throttling (429 and 503, AWS's `Throttling` family too, honouring `Retry-After`), and every credential value scrubbed from resources and details before anything is signed. No result carries a person's name or email: IAM users go out as user ids (`AIDA…`), Jira as issue keys, training records as the person ids the customer's export uses.

None of the five adds an npm dependency. AWS requests are signed with SigV4 in `src/sources/aws/sigv4.ts` (about 70 lines of `node:crypto`, tested against AWS's published vectors), XML replies are read by a 60-line reader in `src/sources/aws/xml.ts`, and Azure, GCP and Jira are plain REST over Node's `fetch`. An SDK would have added a dozen packages per cloud to read about 25 endpoints.

### AWS

**Create:** apply `iac/aws/evidence-role` (an IAM role with the AWS managed **SecurityAudit** policy, `arn:aws:iam::aws:policy/SecurityAudit`, trusted by GitHub Actions OIDC for one repository). ViewOnlyAccess is not enough: it lacks the credential report, KMS rotation status and bucket encryption, and those checks come back `skipped`.

**Credentials:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, which `aws-actions/configure-aws-credentials` exports after assuming the role; or `AWS_ROLE_ARN` with `AWS_WEB_IDENTITY_TOKEN_FILE` (the collector calls `AssumeRoleWithWebIdentity`). Shared config profiles, SSO and the EC2/ECS metadata endpoints are not read. `--aws-role-arn` with `--aws-external-id` assumes a second role first, for the cross-account path.

**Options:** `--aws-regions us-east-1,ca-central-1` (default `AWS_REGION`, else us-east-1; the first is the home region for CloudTrail and S3 Control), `--aws-key-max-age-days` (default 90).

The client sends only actions named `Get*`, `List*` or `Describe*`, plus `iam:GenerateCredentialReport` (it makes IAM build the report the collector then reads) and the two STS calls that open the session; anything else throws before it is signed. One run covers the credentials' account.

```sh
node src/cli.ts run --source aws --aws-regions us-east-1,ca-central-1 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`aws.`…) | What passes |
| --- | --- |
| `root_mfa` | The root user has MFA enabled |
| `root_no_access_keys` | The root user has no access keys |
| `iam_users_mfa` | Each IAM user with a console password has MFA |
| `access_keys_rotated` | Each active IAM access key was rotated within 90 days |
| `password_policy` | The account password policy requires 14 characters and prevents reuse |
| `cloudtrail_multi_region` | A multi-region CloudTrail trail is logging, with log file validation |
| `cloudtrail_kms_encrypted` | Each CloudTrail trail encrypts its log files with a KMS key |
| `guardduty_enabled` | GuardDuty has an enabled detector in the region |
| `securityhub_enabled` | Security Hub is enabled in the region |
| `config_recorder_on` | An AWS Config recorder is recording in the region |
| `s3_account_public_access_block` | S3 Block Public Access is on at the account level (all four settings) |
| `s3_bucket_encryption` | Each S3 bucket has default encryption |
| `ebs_encryption_default` | EBS encryption by default is on in the region |
| `rds_encrypted` | Each RDS DB instance has encrypted storage |
| `rds_not_public` | Each RDS DB instance is not publicly accessible |
| `rds_automated_backups` | Each RDS DB instance keeps automated backups (retention of 1 day or more) |
| `sg_no_open_admin_ports` | No security group allows SSH (22) or RDP (3389) from 0.0.0.0/0 or ::/0 |
| `kms_rotation` | Each enabled symmetric customer-managed KMS key has automatic rotation on |
| `backup_plans_exist` | At least one AWS Backup plan exists in the region |
| `vpc_flow_logs` | Each VPC has an active flow log |
| `access_analyzer_enabled` | IAM Access Analyzer has an active analyzer in the region |

### Azure

**Create:** apply `iac/azure/evidence-role` (an Entra application and service principal with a federated credential for one GitHub Actions workflow, and the built-in roles **Reader** and **Security Reader** at subscription scope). It creates no client secret. Entra ID itself (users, conditional access) belongs to the `entra` source; this one reads Azure Resource Manager only.

**Credentials,** first match wins: `AZURE_ACCESS_TOKEN` (for example from `az account get-access-token --resource https://management.azure.com/` after `azure/login`); `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_FEDERATED_TOKEN_FILE`; `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`. The token request is the only POST; every other call is a GET to `https://management.azure.com/`, and the client refuses any other host.

**Options:** `--azure-subscription <id>` (repeatable; default every enabled subscription the identity can list), `--azure-min-secure-score <percent>` (default 0, so a readable score passes).

```sh
node src/cli.ts run --source azure --azure-subscription 00000000-0000-0000-0000-000000000000 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`azure.`…) | What passes |
| --- | --- |
| `defender_plans` | Each Microsoft Defender for Cloud plan is on (Standard tier) |
| `secure_score` | The Defender for Cloud secure score is readable and at or above the set threshold |
| `activity_log_export` | The subscription's activity log is exported, Administrative events included |
| `keyvault_recoverable` | Each key vault has soft delete and purge protection on |
| `storage_secure_transfer` | Each storage account accepts HTTPS only |
| `storage_no_public_blob` | Each storage account disallows anonymous blob access |
| `storage_min_tls` | Each storage account requires TLS 1.2 or higher |
| `sql_tde` | Each Azure SQL database has transparent data encryption enabled |
| `nsg_no_open_admin_ports` | No network security group allows SSH (22) or RDP (3389) in from the Internet |
| `policy_assignments` | At least one Azure Policy assignment applies to the subscription |
| `disk_encryption` | Each managed disk is encrypted at rest (platform key, customer key, both, or Azure Disk Encryption) |
| `backup_protected_items` | Each Recovery Services vault protects at least one item, and the subscription has a vault |

### GCP

**Create:** apply `iac/gcp/evidence-role` (a service account with **roles/viewer**, **roles/iam.securityReviewer** and **roles/cloudasset.viewer**, and Workload Identity Federation for one GitHub repository). No check uses `roles/cloudasset.viewer` yet; it is granted so the identity matches the other clouds' inventory reach.

**Credentials:** `GOOGLE_OAUTH_ACCESS_TOKEN`, which `google-github-actions/auth` produces with `token_format: access_token`. Every call is a GET except `POST …:getIamPolicy`, which is a read; the client refuses any other POST. IAM bindings are read for the audit config and bucket checks and never reported.

**Options:** `--gcp-project <id>` (repeatable; required, or every check is skipped), `--gcp-org-constraints` (default `iam.disableServiceAccountKeyCreation,storage.publicAccessPrevention`), `--gcp-key-max-age-days` (default 90).

```sh
node src/cli.ts run --source gcp --gcp-project acme-prod \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`gcp.`…) | What passes |
| --- | --- |
| `data_access_audit_logs` | Data Access audit logs (DATA_READ and DATA_WRITE) are on for allServices |
| `org_policy_enforced` | Each listed boolean organization policy constraint is enforced on the project |
| `sa_keys_rotated` | No enabled user-managed service account key is older than the limit (default 90 days) |
| `bucket_not_public` | No Cloud Storage bucket grants a role to allUsers or allAuthenticatedUsers |
| `cloudsql_no_public_ip` | Each Cloud SQL instance has no public IPv4 address |
| `cloudsql_ssl_required` | Each Cloud SQL instance accepts only encrypted connections |
| `firewall_no_open_admin_ports` | No enabled ingress firewall rule allows TCP 22 or 3389 from 0.0.0.0/0 or ::/0 |
| `scc_api_enabled` | The Security Command Center API is enabled on the project |
| `kms_rotation` | Each symmetric Cloud KMS key rotates automatically every 365 days or less |
| `vpc_flow_logs` | Each private subnetwork has VPC flow logs on |

### Jira

**Create:** a Jira Cloud account that holds only the **Browse projects** project permission on the projects the queries name, and an API token for it.

**Credentials:** `JIRA_BASE_URL` (https only), `JIRA_EMAIL`, `JIRA_API_TOKEN`. The collector calls one endpoint, `GET /rest/api/3/search/jql`, paging with `nextPageToken`, and asks only for `created`, `resolutiondate` and the approval field: never a summary or description.

**Options:** `--jira-change-jql` with `--jira-approval-field <field id>`, `--jira-incident-jql` with `--jira-incident-sla-hours` (default 72), `--jira-security-jql` with `--jira-security-max-age-days` (default 30), `--jira-lookback-days` (default 90). A check whose query is not given is skipped. Each check gives one result per query, with counts and up to 50 failing issue keys.

```sh
node src/cli.ts run --source jira \
  --jira-change-jql 'project = CHG' --jira-approval-field customfield_10050 \
  --jira-incident-jql 'project = INC' --jira-security-jql 'labels = security' \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

These show that change, incident and security-issue records exist and how they are handled. They do not show that the process behind them is sound.

| Check (`jira.`…) | What passes |
| --- | --- |
| `change_approval` | Change records from the last 90 days carry an approval or reviewer |
| `incident_sla` | Incidents from the last 90 days were resolved within the SLA |
| `security_issue_age` | No security issue stays open longer than the allowed age |

### Training records (LMS)

No LMS shares an API worth targeting, so this source reads two CSV files the customer exports: `--training-csv` with columns `person_id`, `course`, `completed_on` (ISO date), and `--roster-csv` with columns `person_id`, `role`. Nothing is called over the network and no credential is needed.

**Options:** `--lms-awareness-course` (case-insensitive text a course name must contain; default "security awareness"), `--lms-role-course` (default "role-based"), `--lms-privileged-roles` (default `admin,administrator,privileged`), `--lms-max-age-days` (default 365). Each check gives one result for the roster, with counts and up to 50 person ids; no other column and no other course name leaves the machine.

```sh
node src/cli.ts run --source lms --training-csv lms-export.csv --roster-csv roster.csv \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`lms.`…) | What passes |
| --- | --- |
| `security_awareness_current` | Everyone on the roster completed security awareness training within 12 months |
| `role_based_training_current` | People in privileged roles completed role-based training within 12 months |
| `training_records_complete` | Every person on the roster has a training record |

## Identity and code sources

Five sources read who can sign in and how code changes: `entra`, `okta`, `jumpcloud`, `google_workspace` and `github`. They share `src/sources/readonly_http.ts`, a client with a GET method and nothing else. It refuses a next-page link that points at another origin, so a token never leaves the API it was made for. A 429 is retried up to four times, and so are GitHub's 403 with `x-ratelimit-remaining: 0` and Google's 403 `rateLimitExceeded`; the wait comes from `Retry-After`, Okta's `X-Rate-Limit-Reset` or GitHub's `x-ratelimit-reset` (capped at 60 s). Should an API ever echo the credential, the client cuts it out of the response before parsing, and every source scrubs its secret variables from results as well. The only POSTs are the OAuth token requests for Entra ID and Google, in `src/sources/oauth.ts`; neither adds an npm dependency. `collector google-login` adds the one listener the collector ever opens: on 127.0.0.1, for a single sign-in redirect, never during `run`.

Personal data stays out. A result carries counts and the vendor's opaque ids (Entra object id, Okta user id, JumpCloud user id, Google user id, GitHub numeric user id), at most ten per failing detail. No result holds a user principal name, email address, login or display name, even in a failing detail. An assessor who needs the person looks the id up in the tenant.

An identity tenant or a GitHub organization is one part of a system's boundary, so none of these checks shows a whole control alone.

### Microsoft Entra ID

**Create:** an app registration in the tenant with a client secret or, better, a certificate. Under **API permissions**, add these Microsoft Graph *application* permissions and grant admin consent: `AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `LicenseAssignment.Read.All`. Each is the least-privileged one named on its endpoint's reference page.

**Env:** `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, and either `ENTRA_CLIENT_SECRET` or `ENTRA_CLIENT_CERT_FILE` (a PEM holding the certificate and its private key; the collector signs a PS256 client assertion with `x5t#S256`).

**Options:** `--entra-max-global-admins` (default 4), `--entra-max-permanent-admins` (default 2, for break-glass accounts), `--entra-stale-days` (default 90).

Licences matter. The registration report, Conditional Access and `signInActivity` need Entra ID P1; PIM schedules and risk-based policies need P2. The collector reads `/subscribedSkus`, and a P2 check on a tenant without `AAD_PREMIUM_P2` comes back `skipped`.

```sh
node src/cli.ts run --source entra --entra-stale-days 60 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`entra.`…) | What passes |
| --- | --- |
| `mfa_registered` | Every enabled user is registered for MFA (`isMfaRegistered`) |
| `admins_phishing_resistant` | Every user flagged `isAdmin` has FIDO2 or a passkey, Windows Hello for Business, or a certificate registered |
| `ca_mfa_all_users` | An enabled Conditional Access policy requires MFA or an authentication strength for all users and all apps, with no risk, location, platform or client-app condition |
| `ca_blocks_legacy_auth` | An enabled policy blocks client app types `exchangeActiveSync` and `other` for all users |
| `security_defaults` | Security defaults on, or off with `ca_mfa_all_users` met |
| `global_admins_limited` | At most `--entra-max-global-admins` principals hold Global Administrator |
| `pim_no_permanent_admins` | At most `--entra-max-permanent-admins` permanent Global Administrator assignments (P2) |
| `guest_invites_restricted` | `allowInvitesFrom` is `none` or `adminsAndGuestInviters`; the guest count goes in the detail |
| `stale_accounts` | No enabled account without a sign-in for `--entra-stale-days` days (P1) |
| `audit_log_available` | The directory audit log is readable and not empty |
| `risk_policies` | An enabled policy acts on sign-in or user risk (P2) |

Left out: audit log retention (Graph does not expose it), password expiry and smart lockout (the directory setting template behind them is not in the v1.0 reference, so the field names could not be confirmed).

### Okta

**Create:** either an API token made by an admin who holds only the **Read-Only Administrator** role (an SSWS token carries its maker's permissions), or an OAuth service app granted `okta.policies.read`, `okta.authenticators.read`, `okta.roles.read`, `okta.users.read` and `okta.logs.read`. The scopes come from Okta's management OpenAPI, endpoint by endpoint. The collector does not mint the OAuth token itself: pass one you obtained with the service app's private key.

**Env:** `OKTA_DOMAIN` (e.g. `acme.okta.com`) and `OKTA_API_TOKEN`, or `OKTA_ACCESS_TOKEN` for an OAuth token.

**Options:** `--okta-max-super-admins` (default 3), `--okta-stale-days` (default 90), `--okta-min-password-length` (default 12).

Authenticators and app sign-in policies exist on Identity Engine only. On Classic Engine those two checks come back `skipped`.

```sh
node src/cli.ts run --source okta --okta-max-super-admins 2 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`okta.`…) | What passes |
| --- | --- |
| `mfa_enroll_required` | Each active enrollment policy requires an authenticator besides the password (one result per policy) |
| `phishing_resistant_authenticator` | WebAuthn, smart card or Okta Verify FastPass (`signed_nonce`) is active |
| `global_session_requires_mfa` | Every active ALLOW rule of each global session policy has `requireFactor: true` |
| `app_policies_require_2fa` | Every active ALLOW rule of each app sign-in policy has `factorMode: 2FA`; method chains are not judged |
| `password_policy` | Each active password policy sets `minLength` ≥ `--okta-min-password-length` |
| `account_lockout` | Each active password policy locks after 1 to 10 failed attempts |
| `super_admins_limited` | At most `--okta-max-super-admins` users hold `SUPER_ADMIN` |
| `inactive_users` | No ACTIVE user without a sign-in for `--okta-stale-days` days |
| `system_log_available` | The System Log is readable and not empty |

A global session policy that leaves MFA to the app sign-in policies fails `global_session_requires_mfa` while passing `app_policies_require_2fa`; the assessor reads the two together.

### JumpCloud

**Create:** an administrator who holds only the **Read Only** role. JumpCloud turns API access off for every new administrator, and only an **Administrator with Billing** can turn it on (Settings > Administrators > the admin > **Enable API access**). That administrator then opens **My API Key** and generates a key (prefix `jca_`). The key carries its administrator's role, and Read Only can view users, devices, organization settings, authentication policies, administrators and System Insights (JumpCloud's Admin Portal Roles table). Set an expiry on the key; JumpCloud defaults new keys to 90 days.

**Env:** `JUMPCLOUD_API_KEY`, sent as `x-api-key`. `JUMPCLOUD_ORG_ID` (or `--jumpcloud-org-id`) is sent as `x-org-id`; without it the collector uses the only organization the key can see, and a multi-tenant key that sees several gets its organization checks skipped.

**Options:** `--jumpcloud-org-id`, `--jumpcloud-region` (`us`, `eu` or `in`; default `us`, which picks `console.jumpcloud.com`, `console.eu.jumpcloud.com` or `console.in.jumpcloud.com`), `--jumpcloud-min-password-length` (default 12), `--jumpcloud-max-admins` (default 5), `--jumpcloud-min-os` (e.g. `macos=15.0`, `windows=10.0.22631`; repeatable; without it `device_os_minimum` is skipped), `--jumpcloud-contact-days` (default 14), `--jumpcloud-max-devices` (default 5000).

Every call is a GET: `/api/organizations` and `/api/organizations/{id}`, `/api/v2/organizations/{id}/administratorlinks`, `/api/systemusers`, `/api/v2/authn/policies` and `/api/systems`. Lists page with `limit=100` and `skip`, sorted by `_id` as JumpCloud's API best-practices article asks. The user and device lists name the fields they need (`fields=`), so usernames, email addresses and hostnames never leave JumpCloud. Endpoints and fields come from the JumpCloud API 1.0 and 2.0 references (OpenAPI files last modified 2026-10-19), read on 2026-10-20.

```sh
node src/cli.ts run --source jumpcloud --jumpcloud-min-os macos=15.0 --jumpcloud-min-os windows=10.0.22631 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`jumpcloud.`…) | What passes |
| --- | --- |
| `users_mfa_enrolled` | Every ACTIVATED, unsuspended user has `mfaEnrollment` ENROLLED (overall, TOTP, Push or WebAuthn), or `totp_enabled` |
| `users_mfa_required` | Every active user has `enable_user_portal_multifactor`; a gap is skipped when an enabled User Portal policy requires MFA |
| `policies_require_mfa` | Every enabled, enforced `allow` authentication policy sets `obligations.mfa.required` |
| `admin_mfa_required` | The organization setting `requireAdminMFA` is true |
| `admins_limited` | At most `--jumpcloud-max-admins` administrators are linked to the organization, every role counted |
| `password_policy` | The default password policy sets `minLength` ≥ `--jumpcloud-min-password-length` |
| `account_lockout` | The default password policy locks after 1 to 10 failed attempts (`maxLoginAttempts`) |
| `device_encrypted` | Each device reports `fde.active` true (FileVault or BitLocker) |
| `device_os_minimum` | Each device's OS version is at or above its platform's `--jumpcloud-min-os` |
| `device_last_contact` | Each device's `lastContact` is within `--jumpcloud-contact-days` |

Left out, because no documented GET shows them: inactive users (a system user has no last sign-in field, and sign-in events come from the Directory Insights API, which takes POST), each administrator's role and MFA (no `GET /administrators` outside the MSP routes), and a screen-lock policy (policy template names and their settings are not in the reference). Staged and suspended users are counted in the user checks' details, not judged. Two readings rest on a field's name, since the reference does not describe them: `requireAdminMFA` as the Global MFA Requirement for admins, and the Windows build numbers in `osVersionDetail`.

### Google Workspace

Two ways in, both with the same two read-only scopes, `https://www.googleapis.com/auth/admin.directory.user.readonly` and `https://www.googleapis.com/auth/admin.reports.audit.readonly`. On a server, in Docker or on a Mac, use the browser sign-in: it needs no service-account key. Google Cloud organizations created since 2024 refuse key creation by default (`constraints/iam.disableServiceAccountKeyCreation`), so the key path there needs an org-policy exception first. GitHub Actions cannot open a browser and stays on the key.

**Browser sign-in (no key).** A Workspace admin signs in once; the collector keeps the refresh token in a file of mode 0600 and gets each access token from it in memory. The OAuth client is yours, in your own Google Cloud project, so no Sagentix app ever holds access to your tenant. The console pages below were checked on 2026-10-20 against the Google guides that link them (each asks you to sign in first).

1. Create a project in your organization, or pick one: <https://console.cloud.google.com/projectcreate>. Its location must be your organization, because only a project inside a Google Cloud organization can have an Internal consent screen.
2. Enable the Admin SDK API in it: <https://console.cloud.google.com/apis/enableflow;apiid=admin.googleapis.com>.
3. Set up the consent screen: <https://console.cloud.google.com/auth/branding>, then **Get started**. Give an app name and a support email, choose **Internal** under Audience, give a contact email, accept the user data policy, then **Create**. No test users and no scopes to add here.
4. Create the client: <https://console.cloud.google.com/auth/clients>, **Create client**, application type **Desktop app**, any name, **Create**, then download the JSON. Save it as `google-oauth-client.json` beside the collector's config and run `chmod 600` on it. Google calls a desktop client's secret non-confidential; the file still stays off shared drives.
5. Choose who signs in: a super admin, or better a user holding a custom admin role with read-only Users and Reports privileges (<https://admin.google.com/ac/roles>).
6. If your Admin console restricts which apps reach Google data (Security → Access and data control → API controls, <https://admin.google.com/ac/owl>), mark this client **Trusted**, or tick **Trust internal apps** under Settings.
7. Sign in once, from the collector's folder: `node src/cli.ts google-login --client google-oauth-client.json --token sagentix-google-token.json`. The browser opens Google's consent page; sign in as the admin from step 5 and allow both scopes. The command prints where it wrote the token, never the token. If a box was left unticked it writes nothing and says which scope is missing.
8. Run as usual, with `GOOGLE_OAUTH_CLIENT_FILE=google-oauth-client.json` and, if you moved it, `GOOGLE_OAUTH_TOKEN_FILE` (default `sagentix-google-token.json` in the folder the collector runs from). Leave `GOOGLE_SA_KEY_FILE` unset; when it is set, the service account wins.

A server with no browser: from your computer, `ssh -L 8765:127.0.0.1:8765 <server>`, then on the server `google-login … --port 8765 --no-browser`, and open the address it prints in your computer's browser. The listener answers only on 127.0.0.1, only the one redirect whose `state` matches, and stops after it (or after five minutes).

How long the sign-in lasts. Google states the 7-day refresh-token expiry for a consent screen of user type External in Testing status ("Refresh token expiration", <https://developers.google.com/identity/protocols/oauth2>, updated 2026-10-16); Google's consent-screen guide asks for test users only when the user type is External (<https://developers.google.com/workspace/guides/configure-oauth-consent>), and an Internal app needs no verification and sees no 100-user cap ("Internal Use apps", <https://support.google.com/cloud/answer/13464323>). No Google page read on 2026-10-20 states a fixed lifetime for an Internal app's token, so this is read from what the 7-day rule names, not from a promise. A token still stops when the admin revokes it (<https://myaccount.google.com/connections>), after six months unused (a daily run keeps it alive), when the account passes 100 refresh tokens for the client (each `google-login` makes one), or when an admin restricts the service. Each case then answers `invalid_grant`, every Google check reports `skipped` with "run `collector google-login` again", and running it again mends it. The token file is refused if group or other can read it, if it was made with another client, or if it lacks a scope the collector now asks for.

The flow is OAuth 2.0 for installed apps (<https://developers.google.com/identity/protocols/oauth2/native-app>, updated 2026-10-16): loopback redirect `http://127.0.0.1:<port>`, PKCE with S256, `prompt=consent` so each sign-in returns a new refresh token. The endpoints are fixed in `src/sources/google_oauth.ts`; the client file's own `auth_uri` and `token_uri` are not read.

**Service account (GitHub Actions, or a key you already have).** Create a Google Cloud service account with a JSON key, enable the Admin SDK API in its project, then in the Admin console (Security → API controls → Domain-wide delegation) authorize its client id for exactly the two scopes above. The account acts as `GOOGLE_ADMIN_EMAIL`; give that user a custom admin role with read-only Users and Reports privileges, not super admin.

**Optional, Drive sharing:** `drive_external_sharing_restricted` reads the Cloud Identity Policy API, the only read-only API that shows Drive's sharing settings. Google states that "only a super administrator can use the Cloud Identity Policy API" (docs.cloud.google.com/identity/docs/concepts/overview-policies, read 2026-10-20). To run it with the service account, enable the Cloud Identity API in its project, add `https://www.googleapis.com/auth/cloud-identity.policies.readonly` to the same domain-wide delegation entry, and set `GOOGLE_POLICY_ADMIN_EMAIL` to a super administrator (default: `GOOGLE_ADMIN_EMAIL`). The collector asks for that scope in a token of its own, which holds no other scope, so an install without it keeps the six checks above and gets this one `skipped`, with the reason. The browser sign-in does not ask for that scope (2026-10-20), so with it this check reports `skipped`.

**Env:** browser sign-in: `GOOGLE_OAUTH_CLIENT_FILE`, `GOOGLE_OAUTH_TOKEN_FILE` (optional). Service account: `GOOGLE_SA_KEY_FILE` (the JSON key), `GOOGLE_ADMIN_EMAIL`. Both: `GOOGLE_CUSTOMER_ID` (default `my_customer`), `GOOGLE_POLICY_ADMIN_EMAIL` (optional, service account only).

**Options:** `--google-max-super-admins` (default 4), `--google-stale-days` (default 90).

```sh
node src/cli.ts run --source google_workspace \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`google_workspace.`…) | What passes |
| --- | --- |
| `two_step_enrolled` | Every active user has `isEnrolledIn2Sv` |
| `two_step_enforced` | Every active user has `isEnforcedIn2Sv` |
| `admins_two_step` | Every super or delegated admin is enrolled in 2-Step Verification |
| `super_admins_limited` | At most `--google-max-super-admins` active super admins |
| `inactive_users` | No active user without a sign-in for `--google-stale-days` days; suspended and archived users are counted, not judged |
| `audit_reports_available` | The Admin console audit (Reports API, `admin` application) is readable and not empty |
| `drive_external_sharing_restricted` | Every `drive_and_docs.external_sharing` policy sets `external_sharing_mode` to `DISALLOWED` or `ALLOWLISTED_DOMAINS`, or `allow_publishing_files` to false; an absent field is Google's default (`ALLOWED`, true), and no policy at all fails |

Left out: enforcement of security keys as the only second factor. The Directory and Reports APIs do not expose it.

### GitHub

**Create:** a fine-grained personal access token owned by an organization owner, scoped to the organization and all its repositories, with *read* on Organization **Administration** and **Members**, and Repository **Metadata**, **Administration**, **Contents**, **Dependabot alerts** and **Code scanning alerts**. A GitHub App installation token with the same read permissions works too. Some fields show only to privileged callers: `two_factor_requirement_enabled`, `default_repository_permission`, `members_can_create_public_repositories` and `members_can_change_repo_visibility` to organization owners ("To see the full details about an organization, the authenticated user must be an organization owner", docs.github.com/rest/orgs/orgs#get-an-organization, read 2026-10-20), `security_and_analysis` to repository admins. A token whose owner lacks the role gets `skipped` for those checks.

**Env:** `GITHUB_TOKEN`.

**Options:** `--github-org` (required), `--github-repo <name>` (repeatable; default every active repository), `--github-max-repos` (default 200), `--github-max-owners` (default 3), `--github-max-outside-collaborators` (default 0), `--github-alert-days` (default 30).

Branch protection is read two ways: classic protection (needs Administration) and the active ruleset rules on the default branch (needs only Metadata). A setting passes when either shows it, and fails only when both were readable and neither does.

```sh
node src/cli.ts run --source github --github-org acme \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

| Check (`github.`…) | What passes |
| --- | --- |
| `org_requires_2fa` | `two_factor_requirement_enabled` is true |
| `actions_token_read_only` | Default workflow permissions `read`, and workflows cannot approve pull requests |
| `actions_allowed_restricted` | `allowed_actions` is `local_only` or `selected`, or Actions are off |
| `org_owners_limited` | At most `--github-max-owners` organization owners |
| `outside_collaborators` | At most `--github-max-outside-collaborators` outside collaborators |
| `audit_log_available` | The organization audit log is readable and not empty (Enterprise Cloud) |
| `org_base_permission_read` | `default_repository_permission` is `read` or `none` |
| `org_public_repos_restricted` | Members can neither create a public repository nor change a repository's visibility (`members_can_create_public_repositories` false, or creation off; `members_can_change_repo_visibility` false) |
| `default_branch_reviews` | A pull request with ≥ 1 approving review is required |
| `default_branch_dismiss_stale` | Stale approvals are dismissed on push |
| `default_branch_status_checks` | At least one required status check |
| `default_branch_no_force_push` | Force pushes are blocked |
| `default_branch_signed_commits` | Signed commits are required (advisory for most baselines) |
| `codeowners` | A CODEOWNERS file in `.github/`, the root or `docs/` |
| `secret_scanning` | Secret scanning is enabled |
| `push_protection` | Secret scanning push protection is enabled |
| `dependabot_alerts_enabled` | Dependabot alerts are on (`vulnerability-alerts` answers 204) |
| `dependabot_aged_critical_high` | No open critical or high alert older than `--github-alert-days` days |
| `code_scanning_enabled` | Code scanning has at least one analysis; skipped when Advanced Security is not licensed |

The eight organization checks report once per organization (resource `github org <org>`); the others once per repository (`repo <owner>/<name>`, or `… branch <name>` for the branch rules). With 200 repositories that is about 2,200 results and 2,000 API calls, well under the 5,000-result push limit and GitHub's 5,000 requests an hour. Left out: SAML SSO enforcement and audit log streaming, which no REST field shows for an organization.

## Device sources

Four sources read what laptops look like: `fleet` (the open-source Fleet server in front of fleetd and osquery), `intune`, `jamf` and `kandji` (Iru Endpoint Management, formerly Kandji). Sagentix approved this on 2026-10-15, with Fleet as the device agent and Intune and Jamf Pro as the second path for customers who already run one of them; `kandji` joined on 2026-10-20 for small Mac-based firms. They use the same GET-only client as the identity sources (`src/sources/readonly_http.ts`), and their shared helpers live in `src/sources/device_common.ts`. A fifth, `defender_endpoint` (2026-10-20), reads the EDR and antivirus side of the same laptops from Microsoft Defender for Endpoint.

Each device check reports once per device. A device is named by the vendor's id and its hardware serial (`fleet host 12 serial C02…`, `intune device <id> serial …`, `jamf computer 7 serial …`); Defender's machine entity has no serial, so its devices are `defender device <machine id>`. Hostnames, computer names, display names, user principal names, email addresses and usernames are never put in a result; the Intune device list asks Graph for seven fields with `$select`, and the Jamf call never requests the `USER_AND_LOCATION` section. When a device has not reported a value, the result is `skipped`. A 401 or 403 also gives `skipped` with the HTTP status in the detail, so an expired token shows as a collector error rather than a fleet of failing laptops.

### Fleet

Fleet's MIT-licensed core only. The collector calls one endpoint, `GET /api/v1/fleet/hosts?populate_policies=true`, which Fleet Free serves; it uses no Fleet Premium parameter and no code from Fleet's `ee/` directory, which carries a commercial licence.

**Create:** an API-only user with the global **Observer** role, which is read-only and part of Fleet Free:

```sh
fleetctl user create --name 'Sagentix collector' --api-only --global-role observer
```

**Env:** `FLEET_URL` (https only, e.g. `https://fleet.example.com`) and `FLEET_API_TOKEN` (the API-only user's token).

**Options:** `--fleet-seen-days` (default 14), `--fleet-max-hosts` (default 5000), `--fleet-policy <check>=<id>[,<id>]` (repeatable), `--fleet-min-os <platform>=<version>` (repeatable, e.g. `darwin=15.0`, `windows=10.0.22631`).

Screen lock, OS currency, firewall and EDR come from the customer's own Fleet policies, the osquery queries that answer pass or fail on each host. A policy counts when `--fleet-policy` names its id; without that, when its name matches the check's pattern in `src/sources/fleet.ts` (for example `firewall`, or `crowdstrike|sentinelone|defender|xprotect|antivirus|edr`). If no host has a matching policy, the check gives one `skipped` result for the whole server, naming the flag to set. The collector cannot see what a customer's SQL tests, so a screen-lock policy that allows a 60-minute idle time still passes here.

| Check (`fleet.`…) | What passes |
| --- | --- |
| `disk_encryption` | `disk_encryption_enabled` is true (Fleet omits it when it does not know) |
| `screen_lock` | Every matching policy answers pass on the host |
| `os_up_to_date` | Matching policies pass, and `os_version` meets the `--fleet-min-os` floor when one is given |
| `firewall` | Every matching policy answers pass |
| `edr_present` | Every matching policy answers pass |
| `mdm_enrolled` | `mdm.enrollment_status` starts with "On" (any MDM Fleet detects); Linux hosts are skipped |
| `last_seen` | `seen_time` within `--fleet-seen-days` |

### Microsoft Intune

**Create:** an Entra app registration with these Microsoft Graph *application* permissions, admin consent granted: `DeviceManagementManagedDevices.Read.All` (for `GET /deviceManagement/managedDevices`) and `DeviceManagementConfiguration.Read.All` (for `GET /deviceManagement/deviceCompliancePolicies` and each policy's `/assignments`). The tenant needs an active Intune licence. The same app registration as `entra` can carry them.

**Env:** `INTUNE_TENANT_ID`, `INTUNE_CLIENT_ID`, and `INTUNE_CLIENT_SECRET` or `INTUNE_CLIENT_CERT_FILE`. Each falls back to its `ENTRA_*` twin, and the token request is the one `entra` makes.

**Options:** `--intune-sync-days` (default 14), `--intune-max-lock-minutes` (default 15), `--intune-min-os <operatingSystem>=<version>` (repeatable, e.g. `Windows=10.0.22631`, `macOS=14.0`).

| Check (`intune.`…) | What passes |
| --- | --- |
| `policy_requires_encryption` | For Windows and macOS (where a device is managed), an assigned compliance policy sets `storageRequireEncryption` (or `bitLockerEnabled` on Windows) |
| `policy_requires_screen_lock` | An assigned policy sets `passwordRequired` and `passwordMinutesOfInactivityBeforeLock` from 1 to `--intune-max-lock-minutes` |
| `policy_min_os` | An assigned policy sets `osMinimumVersion` (at or above `--intune-min-os` when given) |
| `device_compliant` | `complianceState` is `compliant`; `unknown` and `configManager` are skipped |
| `device_encrypted` | `isEncrypted` is true |
| `device_os_minimum` | `osVersion` meets `--intune-min-os`, or else the highest `osMinimumVersion` among the platform's assigned policies |
| `device_last_sync` | `lastSyncDateTime` within `--intune-sync-days` |

Policy results report once per platform (`intune tenant <id> Windows`). Settings pushed by configuration profiles instead of compliance policies are not read.

### Jamf Pro

**Create:** in Jamf Pro, an API role holding the single privilege **Read Computers**, and an API client with only that role. The collector exchanges its id and secret at `POST /api/v1/oauth/token` (then `/api/oauth/token` on a server that answers 404) and reads `GET /api/v4/computers-inventory` with the `GENERAL`, `DISK_ENCRYPTION`, `OPERATING_SYSTEM` and `HARDWARE` sections. Jamf marks v1, v2 and v3 of that endpoint deprecated; a server without v4 answers on the next older one.

**Env:** `JAMF_URL` (https only, e.g. `https://acme.jamfcloud.com`), `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`.

**Options:** `--jamf-min-os` (e.g. `15.0`; without it `os_minimum` is skipped), `--jamf-inventory-days` (default 14), `--jamf-max-computers` (default 5000).

| Check (`jamf.`…) | What passes |
| --- | --- |
| `filevault` | `partitionFileVault2State` is `ENCRYPTED`, or `fileVault2Enabled` when the state is unknown |
| `os_minimum` | `operatingSystem.version` at or above `--jamf-min-os` |
| `last_inventory` | `general.reportDate` within `--jamf-inventory-days` |
| `managed` | `general.remoteManagement.managed` is true |

### Iru Endpoint Management (formerly Kandji)

Kandji renamed itself Iru; the API reference is now titled "Iru Endpoint Management API" (https://api-docs.kandji.io/ redirects to https://api-docs.iru.com/), while tenant API hosts stay on kandji.io. Endpoints and fields below were read in that reference on 2026-10-20, Prism category meanings in https://support.kandji.io/kb/prism and token creation in https://support.kandji.io/kb/kandji-api, same date.

**Create:** under Settings → Access, an API token (Add API Token) whose permissions are these five GET endpoints and nothing else: `GET /api/v1/devices` (List Devices), `GET /api/v1/devices/{device_id}/status` (Get Device Status), and the Prism categories `GET /api/v1/prism/application_firewall`, `/gatekeeper_and_xprotect` and `/startup_settings`. Token permissions are granted per endpoint and method. A permission left off skips only the checks that read it: without `startup_settings`, `sip` reports one `skipped` result naming HTTP 403. The token belongs to the admin who made it and is removed with that admin.

**Env:** `KANDJI_API_URL`, the tenant's API URL from the same page (https only: `https://<subdomain>.api.kandji.io` in the US, `https://<subdomain>.api.eu.kandji.io` in the EU), and `KANDJI_API_TOKEN`.

**Options:** `--kandji-min-os` (e.g. `15.0`; without it `os_minimum` is skipped), `--kandji-checkin-days` (default 14), `--kandji-max-devices` (default 1000).

Only Macs are read (`platform=Mac`, Prism `device_families=Mac`). List Devices pages by `limit=300` and `offset`, ordered by `device_id`; Prism pages by its opaque `cursor`, starting from an empty one and stopping when the answer's cursor is null. The tenant may make 10,000 requests an hour, and each Mac costs one Get Device Status call, so 1,000 Macs take about 1,010 requests. The screen saver and lock settings are left out: Prism's Desktop and Screensaver category documents no idle-time or password field. Device names, assigned users, Prism's `device__user_*` fields and library item logs are never read into a result.

| Check (`kandji.`…) | What passes |
| --- | --- |
| `filevault` | The Mac is listed under `filevault_enabled=true`; under `false` it fails, in neither it is skipped |
| `os_minimum` | `os_version` at or above `--kandji-min-os` |
| `last_checkin` | `last_check_in` (the agent check-in) within `--kandji-checkin-days` |
| `managed` | `mdm_enabled` is true |
| `library_items` | No library item is `ERROR` or `failed`, and at least one is `PASS` or `success` |
| `parameters` | No parameter is `ERROR` or `WARNING` (a muted alert), and at least one is `PASS` or `REMEDIATED` |
| `firewall` | Prism Application firewall `status` is true |
| `gatekeeper` | Prism Gatekeeper and XProtect `gatekeeper_status` is true |
| `sip` | Prism Startup settings `sip` is true |

```sh
node src/cli.ts run --source fleet --fleet-min-os darwin=15.0 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

### Microsoft Defender for Endpoint

The collector reads Defender's own API at `https://api.security.microsoft.com/api` (version V1.0), not Microsoft Graph. Graph took over advanced hunting (the old `/api/advancedhunting/run` stops returning data on 2027-02-01) and alerts, but its security API overview (graph-rest-1.0, ms.date 2026-01-21) has no device or antivirus health resource. Every endpoint, permission, limit and field below was read on learn.microsoft.com/defender-endpoint/api on 2026-10-20; the page dates are in the header of `src/sources/defender_endpoint.ts`.

**Create:** an Entra app registration with these **WindowsDefenderATP** *application* permissions (API permissions → APIs my organization uses → WindowsDefenderATP), admin consent granted: `Machine.Read.All` (`GET /api/machines`, `GET /api/deviceavinfo`), `Vulnerability.Read.All` (`GET /api/vulnerabilities/machinesVulnerabilities`) and `SecurityRecommendation.Read.All` (`GET /api/recommendations`, `GET /api/recommendations/{id}/machineReferences`). The token is requested for `https://api.securitycenter.microsoft.com/.default`: Microsoft's app-context page (ms.date 2026-07-28) warns that some of these APIs answer 403 to any other audience. The tenant needs Defender for Endpoint Plan 1 or 2, or Defender for Business; exposure levels, vulnerabilities and recommendations come from Defender Vulnerability Management, and without it those three checks report `skipped`. The same app registration as `entra` can carry the permissions. US Government clouds use other hosts and are not supported.

**Env:** `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, and `DEFENDER_CLIENT_SECRET` or `DEFENDER_CLIENT_CERT_FILE`. Each falls back to its `ENTRA_*` twin.

**Options:** `--defender-seen-days` (default 14), `--defender-max-exposure` (default 0), `--defender-max-devices` (default 10000), `--defender-allow-passive`.

Lists are read 10,000 rows at a time (the documented `$top` ceiling), following `@odata.nextLink` when the API gives one and `$skip` otherwise. At that size a 10,000-device tenant takes about five calls, far inside the documented limits (machines 100 a minute, antivirus health 30 a minute); a 429 is retried after its `Retry-After`. The machine and antivirus APIs take no `$select`, so computer names and IP addresses reach the collector, and no result carries them.

| Check (`defender_endpoint.`…) | What passes |
| --- | --- |
| `device_onboarded` | `onboardingStatus` is `onboarded`; `CanBeOnboarded` (discovered, never onboarded) fails; `Unsupported` and `InsufficientInfo` are skipped |
| `sensor_healthy` | `healthStatus` is `Active` and `lastSeen` (the last full device report) within `--defender-seen-days` |
| `av_active_mode` | `avMode` is `0` (Active); `2` (Disabled) fails; `1`, `4` and `5` (Passive, EDRBlocked, PassiveAudit) fail unless `--defender-allow-passive` |
| `av_signatures_current` | `avIsSignatureUpToDate` and `avIsEngineUpToDate` are both `True` |
| `high_exposure_devices` | At most `--defender-max-exposure` onboarded machines at `exposureLevel` High (one tenant result) |
| `critical_vulnerability_devices` | At most `--defender-max-exposure` machines with a `Critical` vulnerability; the detail counts those a missing Microsoft update fixes (`fixingKbId`) |
| `tamper_protection` | The "Turn on Tamper Protection" security recommendation lists 0 exposed machines; skipped when the recommendation is not listed |

Real-time protection has no check. No documented field of these APIs reports it (`avMode` is the antivirus mode, not the real-time setting), and the collector does not guess from undocumented columns. The antivirus checks report once per machine in the health export, which covers Windows, macOS and Linux (`osKind`).

### This Windows PC (`windows`)

For a firm with no device management, which for a small Canadian defence supplier usually means Windows laptops without Intune. The source reads the Windows 10 or 11 PC the collector runs on, through Windows PowerShell 5.1 (`powershell.exe -NoProfile -NonInteractive -EncodedCommand`) and `whoami.exe`. It is the Windows counterpart of `macos`: no credential, no network call, nothing written to the PC, and it runs as the signed-in user. Off Windows, every check is skipped.

Every command, field and value was written on 2026-10-20 from Microsoft Learn, each page cited with its last-updated date in the header of `src/sources/windows.ts` and in the catalogue's `notes`. Sagentix ran it on 2026-10-20 on a Windows 11 Pro 25H2 PC (build 26200, a Parallels VM), as a standard user and elevated, and checked each result against the same cmdlets run by hand; `test/windows.test.ts` uses outputs shaped from those pages' examples.

Two checks need an administrator, and Microsoft says so: `Get-BitLockerVolume` reads `Win32_EncryptableVolume` ("You must have administrator privileges"), and `Confirm-SecureBootUEFI` "requires that Windows PowerShell be run in administrator mode". No documented read works without elevation. On a standard user's run both are `skipped` with that reason; running the collector once from PowerShell opened as administrator fills them. The daily scheduled run stays unelevated.

**Options:** `--windows-max-lock-seconds` (default 900), `--windows-signature-days` (default 7), `--windows-update-days` (default 35), `--windows-min-build` (default 26200: Windows 11 25H2, the oldest version Microsoft still updated for Home and Pro on 2026-10-20; an Enterprise or Education firm on 24H2 sets 26100).

| Check (`windows.`…) | What passes |
| --- | --- |
| `disk_encryption` | `Get-BitLockerVolume` on the system drive: `FullyEncrypted`, protection `On` (administrator only) |
| `os_updates_installed` | The Windows Update Agent's `LastInstallationSuccessDate` and the newest `Get-HotFix` `InstalledOn` both within `--windows-update-days` |
| `automatic_updates` | Policy `NoAutoUpdate` is not 1, `AUOptions` is not 1 or 2, `wuauserv` is not Disabled, Automatic Updates' `ServiceEnabled` is true |
| `os_supported` | `Win32_OperatingSystem.BuildNumber` at or above `--windows-min-build` |
| `malware_protection` | `Get-MpComputerStatus`: `AMRunningMode` Normal, antimalware service, antivirus and real-time protection on |
| `malware_definitions_current` | Defender's `AntivirusSignatureLastUpdated` within `--windows-signature-days` |
| `firewall` | `Get-NetFirewallProfile -PolicyStore ActiveStore`: Domain, Private and Public all enabled |
| `screen_lock` | The machine inactivity limit, or a password-protected screen saver, locks within `--windows-max-lock-seconds` |
| `auto_login_off` | Winlogon `AutoAdminLogon` is not 1 |
| `user_not_admin` | The signed-in account's token holds no S-1-5-32-544 (`whoami /groups`) |
| `secure_boot` | `Confirm-SecureBootUEFI` answers True (administrator only) |

The PC is named by its BIOS serial (`pc serial <serial> Windows 10.0.26200`), never by its computer name or a user name. `AutoAdminLogon` is read alone, never the `DefaultUserName` or `DefaultPassword` values beside it; the Administrators group is counted, never listed. Error messages are cut to 160 characters, with any `C:\Users\<name>` path and email address removed.

```powershell
node src/cli.ts run --source windows --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

sos-app's "Connect your environment" screen generates `sagentix-collector.ps1` and a scheduled task for the signed-in user (`Register-ScheduledTask`, daily at 06:17 with `-StartWhenAvailable`), run with `-ExecutionPolicy Bypass` for that one process, since Restricted is the Windows client default. The application scanners are not offered on Windows: their steps are bash.

## Websites and APIs by URL (`web`)

The `web` source looks at a site the way a browser does, for URLs the organization declared and proved it controls. It reads only the exact URLs it is given: no crawling, no link or redirect followed, no form, no POST, no vulnerability probe. Each URL gets two TLS handshakes to port 443, one GET of the URL and one GET of its `http://` form; each mail domain gets DNS lookups and one DNS-over-HTTPS query. Requests to one host are at least a second apart by default, each times out after 15 s, and each carries the User-Agent `sagentix-evidence-collector/<version> (+https://github.com/Sagentix-Advisors-Inc/sagentix-collector)`.

**Prove control first.** sos-app issues a token per host when the URL is declared. Publish it one of two ways:

```
_sagentix-collector.www.example.ca.  TXT  "sagentix-collector-verification=<token>"
```

or serve `https://www.example.ca/.well-known/sagentix-collector.txt` with the line `sagentix-collector-verification=<token>`. Then pass `--web-proof www.example.ca=<token>`. The collector checks the proof itself before anything else goes to the host. A host with no `--web-proof` gets no request at all, and all nine URL checks come back `skipped` with the record to publish; a wrong token costs one TXT lookup and one GET of the well-known file (redirect not followed, first 4 KB read). `--web-skip-proof` runs the checks without proof, every detail then starts "control not proven (dry run only)", and the CLI accepts it only with `--dry-run`, which sends nothing.

**Accepted URLs:** https only, the default port, no user name or password, a host name rather than an IP address (an IP cannot be proven by DNS).

**Options:** `--web-url <https URL>` (repeatable), `--web-proof <host>=<token>` (repeatable), `--web-mail-domain <domain>` (repeatable; default the last two labels of each host, which is wrong under a two-label public suffix such as `gc.ca`, so give it there), `--web-delay-ms` (default 1000, at least 200), `--web-cert-min-days` (default 14), `--web-skip-proof` (dry run only).

The mail domain's checks run only beside a proven host: the same domain, a parent, or a sibling under the same two labels.

```sh
node src/cli.ts run --source web --web-url https://www.example.ca/ --web-proof www.example.ca=<token> \
  --web-mail-domain example.ca --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

Each check was written against a page read on 2026-10-18: CCCS ITSP.40.062 v3 (January 2025), section 3, for TLS versions; the Government of Canada's "Web Sites and Services Management Configuration Requirements" (canada.ca, page details 2024-10-25) for HTTPS only, the HTTP redirect, HSTS and TLS 1.2 or later; RFC 6797 (HSTS), RFC 7208 (SPF), RFC 7489 (DMARC) and RFC 8659 (CAA); the OWASP HTTP Headers Cheat Sheet for the response headers; Cloudflare's DNS-over-HTTPS JSON API for the DS lookup. The citations sit in `src/sources/web.ts`.

| Check (`web.`…) | What passes |
| --- | --- |
| `tls_min_version` | A handshake offering only TLS 1.0 and 1.1 fails, and a default one lands on TLS 1.2 or 1.3 |
| `certificate_valid` | The chain verifies for the host name, with more than `--web-cert-min-days` days left |
| `https_redirect` | `http://` answers 301, 302, 307 or 308 to `https://` on the same host, or port 80 refuses connections |
| `hsts` | Strict-Transport-Security on the HTTPS answer with max-age ≥ 31536000 |
| `csp` | An enforced Content-Security-Policy with script-src or default-src that allows neither `*` nor `'unsafe-inline'` without a nonce or hash; Report-Only alone fails |
| `content_type_options` | `X-Content-Type-Options: nosniff` |
| `frame_protection` | CSP `frame-ancestors`, or X-Frame-Options DENY or SAMEORIGIN |
| `referrer_policy` | A Referrer-Policy whose effective value is not `unsafe-url` or `no-referrer-when-downgrade` |
| `no_version_banner` | No digit in Server; no X-Powered-By, X-AspNet-Version or X-AspNetMvc-Version |
| `spf` | Exactly one `v=spf1` record, ending in `-all` or `~all` |
| `dmarc` | `_dmarc` of the domain, or else of its parents down to two labels, has `p=quarantine` or `p=reject` and pct 100 |
| `dnssec` | A DS record exists for the domain (recommended) |
| `caa` | A CAA record set at the domain or its nearest parent (recommended) |

A TLS 1.1 probe that this machine's OpenSSL cannot make, or a network failure, gives `skipped`, never a pass. The certificate handshake reads the certificate without trusting it (`rejectUnauthorized: false`) and judges the verification result itself; nothing is sent on that connection. The DMARC walk approximates RFC 7489's Organizational Domain without the Public Suffix List. A result names the URL or the domain, header values, protocol versions and dates; never page content, a cookie or a person.

## Layout

- `src/cli.ts`: `keygen`, `run` and `config-schema`; exit codes.
- `src/config.ts` and `collector.config.schema.json`: the config file and its schema (a test holds the two equal).
- `src/sources/web.ts`: websites by URL, with proof of control; tests in `test/web.test.ts` over a fake network.
- `src/payload.ts`: the v2 body, catalogue vetting, the 5,000-result limit.
- `src/catalog.ts`: reads `apps/sos-app/src/data/checks/*.json`.
- `src/sources/index.ts`: the list of sources. A new source is a file in `src/sources/` that exports `{ name, options, emits, describe, run }`, plus one line in this list, plus its catalogue JSON in sos-app.
- `src/sources/cloudflare.ts` and `src/sources/cloudflare/`: the API client (GET only), zone and account checks, and the OPA sub-source.
- `src/sources/entra.ts`, `okta.ts`, `jumpcloud.ts`, `google_workspace.ts`, `github.ts`: the identity and code sources (JumpCloud also reads devices, with `device_common.ts`); `readonly_http.ts` (GET-only client, retry, pagination, redaction) serves all five and `oauth.ts` (token requests) serves Entra ID and Google; `google_oauth.ts` and `src/google_login.ts` are Google's browser sign-in and its token file (`test/google_oauth.test.ts`). Their tests are `test/{entra,okta,jumpcloud,google_workspace,github}.test.ts` over the fakes and shared contract suite in `test/rest_fakes.ts`.
- `src/sources/fleet.ts`, `intune.ts`, `jamf.ts`, `kandji.ts`, `defender_endpoint.ts`: the device sources, listed through `device_sources.ts`, with helpers in `device_common.ts`; tests in `test/{fleet,intune,jamf,kandji,defender_endpoint}.test.ts`.
- `src/sources/macos.ts` and `windows.ts`: the Mac or Windows PC the collector runs on, read with the operating system's own tools through an injectable command runner; also listed through `device_sources.ts`, tested in `test/{macos,windows}.test.ts` with fake runners.
- `src/v1/`: the v1 FedRAMP push behind `--fedramp-target`.
- `src/sources/prowler.ts` and `runner/`: Prowler as an engine (`--source prowler`) and the container that runs it; see `runner/README.md`. More than 5,000 results (or 4 MB) go out as several signed pushes, each with its own nonce.
- `src/sources/stig.ts`, `kubescape.ts`, `checkov.ts`: Cinc Auditor with MITRE's DISA STIG profiles (`--source stig`, which runs `cinc-auditor` over SSH or WinRM, or reads an InSpec report), and the Kubescape and Checkov report readers; listed through `engines.ts`, documented in `runner/README.md`, tested in `test/host_iac_engines.test.ts` with hand-built reports. Their catalogues (`stig_<profile>.json`, `kubescape.json`, `checkov.json`) come from `apps/sos-app/scripts/build_{stig,kubescape,checkov}_catalog.py`.
- `test/`: node:test suites with a fake Cloudflare API, a fake `opa` and a fake sos-app; one suite runs the real `opa` when it is installed.
