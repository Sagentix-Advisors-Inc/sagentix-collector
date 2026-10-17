# Sagentix evidence collector

The collector runs in the customer's own CI. It reads the customer's systems with read-only credentials, runs checks, signs what it saw with an Ed25519 key and pushes the result to sos-app at `POST /api/collect`. sos-app maps each check to NIST SP 800-53 Rev. 5 controls and FedRAMP 20x KSIs itself. The collector reads the check list in `apps/sos-app/src/data/checks/<source>.json`, so it sends only check ids sos-app knows.

Version 0.2.0 has ten sources and 122 read-only checks: Cloudflare (30), AWS (21), GitHub (17), Azure (12), Entra ID (11), GCP (10), Okta (9), Google Workspace (6), Jira (3) and training records from an LMS export (3). Together they give evidence for 62 of the 585 SP 800-53 Rev. 5 controls sos-app tracks; policies cover 20 more, and the rest are procedures a person describes.

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

Four sources read who can sign in and how code changes: `entra`, `okta`, `google_workspace` and `github`. They share `src/sources/readonly_http.ts`, a client with a GET method and nothing else. It refuses a next-page link that points at another origin, so a token never leaves the API it was made for. A 429 is retried up to four times, and so are GitHub's 403 with `x-ratelimit-remaining: 0` and Google's 403 `rateLimitExceeded`; the wait comes from `Retry-After`, Okta's `X-Rate-Limit-Reset` or GitHub's `x-ratelimit-reset` (capped at 60 s). Should an API ever echo the credential, the client cuts it out of the response before parsing, and every source scrubs its secret variables from results as well. The only POSTs are the OAuth token requests for Entra ID and Google, in `src/sources/oauth.ts`; neither adds an npm dependency.

Personal data stays out. A result carries counts and the vendor's opaque ids (Entra object id, Okta user id, Google user id, GitHub numeric user id), at most ten per failing detail. No result holds a user principal name, email address, login or display name, even in a failing detail. An assessor who needs the person looks the id up in the tenant.

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

### Google Workspace

**Create:** a Google Cloud service account with a JSON key, enable the Admin SDK API in its project, then in the Admin console (Security → API controls → Domain-wide delegation) authorize its client id for exactly `https://www.googleapis.com/auth/admin.directory.user.readonly` and `https://www.googleapis.com/auth/admin.reports.audit.readonly`. The account acts as `GOOGLE_ADMIN_EMAIL`; give that user a custom admin role with read-only Users and Reports privileges, not super admin.

**Env:** `GOOGLE_SA_KEY_FILE` (the JSON key), `GOOGLE_ADMIN_EMAIL`, `GOOGLE_CUSTOMER_ID` (default `my_customer`).

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

Left out: enforcement of security keys as the only second factor. The Directory and Reports APIs do not expose it.

### GitHub

**Create:** a fine-grained personal access token owned by an organization owner, scoped to the organization and all its repositories, with *read* on Organization **Administration** and **Members**, and Repository **Metadata**, **Administration**, **Contents**, **Dependabot alerts** and **Code scanning alerts**. A GitHub App installation token with the same read permissions works too. Two fields show only to privileged callers: `two_factor_requirement_enabled` to organization owners, `security_and_analysis` to repository admins. A token whose owner lacks the role gets `skipped` for those checks.

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

The six organization checks report once per organization (resource `github org <org>`); the others once per repository (`repo <owner>/<name>`, or `… branch <name>` for the branch rules). With 200 repositories that is about 2,200 results and 2,000 API calls, well under the 5,000-result push limit and GitHub's 5,000 requests an hour. Left out: SAML SSO enforcement and audit log streaming, which no REST field shows for an organization.

## Device sources

Three sources read what laptops look like: `fleet` (the open-source Fleet server in front of fleetd and osquery), `intune` and `jamf`. Sagentix approved this on 2026-10-15, with Fleet as the device agent and Intune and Jamf Pro as the second path for customers who already run one of them. They use the same GET-only client as the identity sources (`src/sources/readonly_http.ts`), and their shared helpers live in `src/sources/device_common.ts`.

Each device check reports once per device. A device is named by the vendor's id and its hardware serial (`fleet host 12 serial C02…`, `intune device <id> serial …`, `jamf computer 7 serial …`). Hostnames, computer names, display names, user principal names, email addresses and usernames are never put in a result; the Intune device list asks Graph for seven fields with `$select`, and the Jamf call never requests the `USER_AND_LOCATION` section. When a device has not reported a value, the result is `skipped`. A 401 or 403 also gives `skipped` with the HTTP status in the detail, so an expired token shows as a collector error rather than a fleet of failing laptops.

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

```sh
node src/cli.ts run --source fleet --fleet-min-os darwin=15.0 \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

## Layout

- `src/cli.ts`: `keygen` and `run`; exit codes.
- `src/payload.ts`: the v2 body, catalogue vetting, the 5,000-result limit.
- `src/catalog.ts`: reads `apps/sos-app/src/data/checks/*.json`.
- `src/sources/index.ts`: the list of sources. A new source is a file in `src/sources/` that exports `{ name, options, emits, describe, run }`, plus one line in this list, plus its catalogue JSON in sos-app.
- `src/sources/cloudflare.ts` and `src/sources/cloudflare/`: the API client (GET only), zone and account checks, and the OPA sub-source.
- `src/sources/entra.ts`, `okta.ts`, `google_workspace.ts`, `github.ts`: the identity and code sources; `readonly_http.ts` (GET-only client, retry, pagination, redaction) and `oauth.ts` (token requests) serve all four. Their tests are `test/{entra,okta,google_workspace,github}.test.ts` over the fakes and shared contract suite in `test/rest_fakes.ts`.
- `src/sources/fleet.ts`, `intune.ts`, `jamf.ts`: the device sources, listed through `device_sources.ts`, with helpers in `device_common.ts`; tests in `test/{fleet,intune,jamf}.test.ts`.
- `src/v1/`: the v1 FedRAMP push behind `--fedramp-target`.
- `src/sources/prowler.ts` and `runner/`: Prowler as an engine (`--source prowler`) and the container that runs it; see `runner/README.md`. More than 5,000 results (or 4 MB) go out as several signed pushes, each with its own nonce.
- `src/sources/stig.ts`, `kubescape.ts`, `checkov.ts`: Cinc Auditor with MITRE's DISA STIG profiles (`--source stig`, which runs `cinc-auditor` over SSH or WinRM, or reads an InSpec report), and the Kubescape and Checkov report readers; listed through `engines.ts`, documented in `runner/README.md`, tested in `test/host_iac_engines.test.ts` with hand-built reports. Their catalogues (`stig_<profile>.json`, `kubescape.json`, `checkov.json`) come from `apps/sos-app/scripts/build_{stig,kubescape,checkov}_catalog.py`.
- `test/`: node:test suites with a fake Cloudflare API, a fake `opa` and a fake sos-app; one suite runs the real `opa` when it is installed.
