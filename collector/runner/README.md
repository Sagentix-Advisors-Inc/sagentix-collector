# Collector runner image (Prowler and the bundled engines)

The runner is one container image: Node 24 runs the collector, Python 3.13 runs Prowler 5.45.0 (Apache-2.0), ScubaGoggles 1.0.1 and Checkov 3.3.27, Cinc Auditor 7.2.1 runs five MITRE DISA STIG profiles, five more engines, built from source with Go, sit in `/usr/local/bin` (see [Bundled engines](#bundled-engines)), and a non-root user (uid 10001) runs all of them. It holds no secret. The cloud credentials and the collector's signing key reach it as environment variables when it starts, and the collector sends one thing out: the signed push to sos-app's `POST /api/collect`. The engines reach only what they scan and their own vulnerability databases.

## The `prowler` source

```sh
node src/cli.ts run --source prowler --prowler-provider aws \
  --prowler-args="--region us-east-1 ca-central-1" \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

The collector runs `prowler <provider> --output-formats json-ocsf --output-directory <temp> --output-filename sagentix --no-banner --ignore-exit-code-3`, adds the provider's authentication flag, then reads the OCSF file. Options:

- `--prowler-provider`: `aws`, `azure`, `gcp`, `kubernetes`, `m365`, `github`, `googleworkspace`, `okta` or `cloudflare`.
- `--prowler-bin`: the executable (default `prowler` on PATH).
- `--prowler-args="…"`: more Prowler options. Write it with `=`, because the value starts with a dash. The collector refuses any option that makes Prowler write, fix or send somewhere (`--push-to-cloud`, `--security-hub`, `--output-bucket`, `--slack`, `--shodan`, `--fixer`, `--scan-secrets-validate`), and any that changes the output it reads (`--output-formats`, `--output-directory`, `--output-filename`, `--status`).
- `--prowler-output <file>`: read a json-ocsf file instead of running Prowler, for a customer who runs Prowler their own way.

Each finding becomes one result, `prowler.<provider>.<CheckID>`. PASS goes as `pass` and FAIL as `fail`. MANUAL and muted findings (OCSF status `Suppressed`) go as `skipped`. A check that sos-app's catalogue does not list is dropped, and stderr says how many findings went and from which checks. When Prowler reports one check on one resource several times, the results merge: fail if any failed, and the details are joined. Email addresses in a resource or detail become `[email]`; an IAM ARN still carries the user or role name, as AWS writes it. A non-zero exit from Prowler stops the run with exit 1, so a failed scan never reads as an empty one.

More than 5,000 results, or about 4 MB, go out as several pushes. Each push is signed alone and has its own nonce. With `--out`, the file then holds `pushes: [{signature, body}]`.

Authentication comes from the environment:

| Provider | What Prowler reads | Flag the collector adds |
| --- | --- | --- |
| aws | `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`, or `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (boto3's chain) | none |
| azure, m365 | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` | `--sp-env-auth` when a secret is set, else `--az-cli-auth` |
| gcp | `GOOGLE_APPLICATION_CREDENTIALS` (a key or a Workload Identity Federation config) | none |
| kubernetes | `KUBECONFIG` | `--kubeconfig-file $KUBECONFIG` |
| github | `GITHUB_PERSONAL_ACCESS_TOKEN`, or `GITHUB_APP_ID` + `GITHUB_APP_KEY` | none |
| googleworkspace | `GOOGLEWORKSPACE_CREDENTIALS_FILE`, `GOOGLEWORKSPACE_DELEGATED_USER` | none |
| okta | `OKTA_ORG_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY` | none |
| cloudflare | `CLOUDFLARE_API_TOKEN` | none |

The image has no Azure CLI and no PowerShell. Azure and Microsoft 365 with `--az-cli-auth` need a derived image with `az`; Prowler's Microsoft 365 PowerShell checks need `pwsh`.

### What sos-app counts

Every Prowler catalogue has source `prowler`. sos-app counts automated methods by distinct source, so Prowler counts once for FRC-CSX-VVK however many providers run.

### Permissions

Prowler's documentation asks for more than the collector's own sources do. Read `readScopes` and `notes` in `apps/sos-app/src/data/checks/prowler_<provider>.json` before granting anything. Five grants go beyond reading configuration:

- AWS: `prowler-additions-policy.json` includes `securityhub:BatchImportFindings`, a write. Remove that line; the collector never passes `--security-hub`. The same policy reads function code links and environment variables (`lambda:GetFunction*`), image layers and log events.
- Azure: Prowler's custom `ProwlerRole` holds `listkeys` and `config/list` actions on App Service, which return keys and app settings. Leave it out; the few checks that need it then fail to read.
- Microsoft 365: `Exchange.ManageAsApp`, held back to reading by the Global Reader role.
- GitHub: a classic token needs `admin:org` for two checks. Use a fine-grained token or a GitHub App with read permissions.
- Kubernetes: `get` on configmaps reads their content.

The AWS role from `iac/aws/evidence-role` carries SecurityAudit only. Prowler runs with it; checks that need ViewOnlyAccess or the additions policy log an access error and report nothing for those resources. Attach `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` to the role if you want them.

## The `stig` source (Cinc Auditor and MITRE's DISA STIG profiles)

```sh
node src/cli.ts run --source stig --stig-profile rhel9 --stig-target ssh://ec2-user@10.0.1.5 \
  --stig-key-file /keys/scan_ed25519 --stig-sudo \
  --endpoint https://<sos-app host> --key-id <key id> --key sagentix-collector.pem --dry-run
```

The collector runs `cinc-auditor exec /opt/sagentix/stig/<profile>.tar.gz -t <target> --reporter json:<temp file>` and reads the report. Cinc Auditor is the Apache-2.0 community build of Chef InSpec; Chef's own binary needs Chef's EULA and is not used. Options:

- `--stig-profile`: `rhel9`, `rhel8`, `ubuntu2204`, `ubuntu2404` or `al2023`. These are MITRE's maintained STIG profiles for the hosts customers run most (each released in September 2026). MITRE publishes no maintained Windows Server 2022 profile, and its Windows Server 2019 profile's last release is from 2023-06-28, so Windows hosts have no profile here.
- `--stig-target`: `ssh://user@host[:port]`, `winrm://user@host[:port]` or `local://`; repeatable, one result set per host. Any other scheme, a password in the URI, or a host name with shell characters is refused.
- `--stig-key-file` for SSH; a WinRM password goes in `STIG_TARGET_PASSWORD` (it is passed to `cinc-auditor --password` and scrubbed from errors and results). `--stig-sudo` reads root-only files through sudo; without it those rules fail to read and come back failed or skipped, never passed.
- `--stig-input-file <yml>`: InSpec inputs the profile reads (the site's banner text, allowed services and the like); repeatable.
- `--cinc-report <file>`: read an InSpec JSON report the customer produced instead of scanning (the profile is found by name; `--stig-profile` maps an overlay profile onto a pinned one).

The collector offers no way to run anything but the bundled profiles: no custom profile path, no `--command`, `--shell-command` or `--sudo-command`. The profiles only read (`stat`, `grep`, package and `sysctl` queries). Each control becomes one result, `stig.<profile>.<v-id>`: pass when every test InSpec ran passed, fail when one failed, skipped when InSpec skipped, waived or could not run it. Details carry test counts and severity only, never InSpec's messages, which can name users and paths, and the resource is `stig <profile> host <host>` with no user name. A report older than `--stig-max-age-days` (default 30) is skipped. A `cinc-auditor` exit other than 0, 100 (a test skipped) or 101 (a test failed) stops the run.

The profiles are archived at build time with their one dependency (`mitre/inspec-profile-resources` at the commit each `inspec.yml` pins), so a scan fetches nothing.

## Bundled engines

Every engine the collector reads runs inside this image, except ScubaGear (it needs Windows) and Grype and Syft, which left the image on 2026-10-26. The collector never calls the engines itself: a job step runs the engine, the engine writes JSON, then `run --source <engine>` reads that file and sends results only. Each version is the newest stable release at least 14 days old when it was pinned.

The five Go engines (Trivy, Gitleaks, OpenSSF Scorecard, OPA, Kubescape) are built from source in the image's `gobuild` stage, with Go 1.27.3 from go.dev. Their release binaries were compiled with older Go and older modules: Trivy's scan of the image on 2026-10-26 found 304 advisories of medium severity or worse in the seven Go engines then bundled, 170 of them in Go's standard library. Stéphane asked on 2026-10-26 for fewer tools and fewer weaknesses, so `collector/runner/build_go_engine.sh` fetches each release tag, fails if the tag no longer points at the pinned commit, raises modules to the floors in `go-module-fixes.txt`, and builds with the project's own release flags. The other engines are downloads pinned by SHA-256 from the project's checksum file or PyPI's digest; a mismatch stops the build. Python packages in the image's three environments rise to the floors in `python-fixes.txt`, and `pip check` must pass after.

Grype and Syft left because Trivy does both of their jobs here: `trivy image|fs --format cyclonedx` writes the SBOM that the `syft` source reads (it reads any CycloneDX or SPDX file), and Trivy's own vulnerability report covers the image and the dependencies. One check goes with Grype: `grype.no_aged_fixable_critical_high` (a fix left unapplied past N days) needs the fix date that only Grype's report carries. A customer who runs Grype in their own pipeline still gets it; the `grype` and `syft` readers stay.

| Engine | Version (tag) | Licence | In the image | Collector reads it with |
| --- | --- | --- | --- | --- |
| Trivy | 0.75.0 (`v0.75.0`, built from source) | Apache-2.0 | `trivy image\ | fs\ | config --format json --output /out/trivy.json <target>`; the SBOM with `--format cyclonedx --output /out/sbom.json` | `--source trivy --trivy-report /out/trivy.json`; `--source syft --sbom-file /out/sbom.json` |
| Gitleaks | 8.30.1 (`v8.30.1`, built from source) | MIT | `gitleaks git --report-format json --report-path /out/gitleaks.json <repo>` | `--source gitleaks --gitleaks-report /out/gitleaks.json` |
| OpenSSF Scorecard | 5.6.0 (`v5.6.0`, built from source) | Apache-2.0 | `scorecard --repo=<repo> --format=json > /out/scorecard.json` | `--source scorecard --scorecard-result /out/scorecard.json` |
| ScubaGoggles | 1.0.1 (PyPI; tag `v1.0.1`) | CC0 1.0 | `scubagoggles gws --credentials <file> -o /out/scuba` | `--source scubagoggles --scubagoggles-results /out/scuba` |
| OPA | 1.21.1 (`v1.21.1`, built from source) | Apache-2.0 | evaluates ScubaGoggles' Rego, and the `cloudflare` source's `--tofu-state` policies | no source of its own |
| Cinc Auditor | 7.2.1 (Debian 12 package; InSpec tag `v7.2.1`) | Apache-2.0 | runs the STIG profiles; `/opt/cinc-auditor` | `--source stig --stig-profile <p> --stig-target ssh://…` (the collector runs it) |
| MITRE STIG profiles | five tags, see `THIRD_PARTY_NOTICES.md` | Apache-2.0 with MITRE's notice | `/opt/sagentix/stig/<profile>.tar.gz` | as above, or `--source stig --cinc-report <file>` |
| Kubescape | 4.0.15 (`v4.0.15`, built from source) | Apache-2.0 | `kubescape scan framework nsa,mitre [<dir>] --use-artifacts-from /opt/kubescape/artifacts --format json --output /out/kubescape.json` | `--source kubescape --kubescape-report /out/kubescape.json` |
| Kubescape regolibrary | 2.0.38 (`v2.0.38`) | Apache-2.0 | the NSA and MITRE frameworks in `/opt/kubescape/artifacts` | no source of its own |
| Go | 1.27.3 (go.dev; tag `go1.27.3`) | BSD-3-Clause | compiles the five Go engines; not in the image | none |
| Checkov | 3.3.27 (PyPI; tag `3.3.27`) | Apache-2.0 | `checkov -d <dir> -o json > /out/checkov.json`, or `checkov -f plan.json -o json` | `--source checkov --checkov-report /out/checkov.json` |

Trivy fetches its vulnerability database into `~/.cache` on first use; a database baked into the image would go stale within a day. Scorecard reads the GitHub API and wants `GITHUB_AUTH_TOKEN`. ScubaGoggles finds OPA through `~/.scubagoggles/userdefaults.yaml` (`opa_dir: /usr/local/bin`), so `scubagoggles setup` and `getopa` never download it, though each `gws` run still asks PyPI whether a newer ScubaGoggles exists and only logs the answer. The image sets `TRIVY_SKIP_VERSION_CHECK=true` and `TRIVY_DISABLE_TELEMETRY=true` (since 0.74.0 Trivy sends anonymous usage data to Aqua unless told not to). ScubaGoggles lives in its own virtual environment, `/opt/scubagoggles`, so its Google client libraries cannot shift Prowler's; Checkov has its own too, `/opt/checkov`. Kubescape's version check posts the scan context to `version-check.ks-services.co`, so the image sets `KS_SKIP_UPDATE_CHECK=true`, and Kubescape reads its NSA and MITRE frameworks from `/opt/kubescape/artifacts` when given `--use-artifacts-from`; without that flag it downloads the latest regolibrary release at scan time. Checkov runs with `BC_SKIP_MAPPING=TRUE` and `CKV_SKIP_PACKAGE_UPDATE_CHECK=true`, so it fetches neither Prisma Cloud's mapping nor PyPI's version list.

The readers were checked against each project's main branch on 2026-10-15 (the commits named in `notes` of `apps/sos-app/src/data/checks/<engine>.json`), which is newer than these releases. The format files did not change between each tag and that commit, except Trivy's `pkg/types/report.go`, where main adds a `crypto` result class and an optional `CryptoAssets` field that the reader ignores. Scorecard's `pkg/scorecard/json.go` and Gitleaks' `report/json.go` and `report/finding.go` are byte-identical.

ScubaGear is not in the image. It is a PowerShell module that needs Windows PowerShell 5.1 and Microsoft's Windows-only modules, so the customer runs it in a Windows job (`Invoke-SCuBA -ProductNames * -OutPath <dir>`), keeps the `ScubaResults*.json` it writes, and passes that file or folder to this image with `--source scubagear --scubagear-results <file or dir>`. The reader was checked against ScubaGear 1.8.0 (tag `v1.8.0`).

Each engine's licence and copyright line are in `collector/THIRD_PARTY_NOTICES.md` — the LICENSE files shipped inside the release archives also go to `/usr/share/doc/sagentix-engines/<engine>/` in the image. No engine is under the GPL or AGPL; the Cinc Auditor package carries two build scripts (`config.guess`, `config.sub`) under GPL-3.0 with the Autoconf exception, which lets them ship with the build's output.

## Keeping engines current

`.github/workflows/engine-updates.yml` runs every day at 07:17 UTC (and by hand, for one engine if you choose). It asks GitHub's API for each pinned engine's releases through `collector/runner/update_engines.py check`. Prowler moves the day a release comes out, once PyPI has it, because Sagentix decided on 2026-10-15 for the newest Prowler as soon as it ships. Go moves the day a stable release is on go.dev, because Go's point releases are its security releases. Trivy, Gitleaks, Scorecard, OPA, ScubaGoggles, ScubaGear, Kubescape, its regolibrary, Checkov, Cinc Auditor and the five MITRE STIG profiles (engines `stigrhel9`, `stigrhel8`, `stigubuntu2204`, `stigubuntu2404`, `stigal2023`) move once a release is 14 days old, the rule this image was first built on. Cinc Auditor's versions and package digests come from Cinc's omnitruck rather than GitHub; a STIG profile's pin is the SHA-256 of GitHub's tarball of the new tag, since MITRE publishes no checksum, and its catalogue is rebuilt from the same bytes.

For each newer release, one job runs `update_engines.py apply <engine> <version>`. It moves every pin of that engine (Dockerfile `ARG`s, `THIRD_PARTY_NOTICES.md`, the table above, and for Prowler `build_prowler_catalog.py` and `src/sources/prowler.ts`; for SCuBA the `PINS` of `build_scuba_catalog.py`), taking a Go engine's new tag commit from GitHub, Go's archive digests from go.dev, and each download's SHA-256 from the project's checksum file, refusing with no PR if GitHub's asset digest disagrees. It then regenerates the Prowler or SCuBA catalogues (and Prowler's remediation texts, then the per-control guides when `build_control_guides.py` exists), runs that engine's tests and an amd64 build of this image, and opens a PR to `rnd` titled `engine update: <name> <old> → <new>` whose body carries the generator's checks added and removed per provider. A draft PR means a person must look: the generator's drop guard refused, a LICENSE or NOTICE file changed between the two tags, or a test failed. The body also lists lines that still name the old version, prose about what the old release did, which the script never rewrites.

The workflow holds only `GITHUB_TOKEN` (contents and pull-requests write), pushes only `engine-update/*` branches and never deploys; merging is what ships. While the repository setting "Allow GitHub Actions to create and approve pull requests" is off (as it was on 2026-10-15), the branch is pushed, the run fails, and its summary carries the compare link. To try it locally: `python3 collector/runner/update_engines.py check`.

A version bump does not move a module the release still pins low, so a second job closes that gap. `.github/workflows/engine-module-fixes.yml` runs every Monday at 08:23 UTC: it builds this image, scans it with Trivy (`--severity MEDIUM,HIGH,CRITICAL --ignore-unfixed`, as the release gate does), and runs `collector/runner/go_fixes.py`, which raises a floor in `go-module-fixes.txt` or `python-fixes.txt` for every finding with a fixed version. A floor only moves up, and `build_go_engine.sh` skips one the release has caught up with. When a floor changes, the job rebuilds and rescans the image with it, pushes `engine-update/module-fixes-<date>` and opens a PR, a draft when the rebuild broke or findings remain. A fix a floor cannot reach (the build breaks, or the fix needs a new major version) goes in `trivyignore.yaml` by hand, with the reason and an expiry no more than 30 days out, and the release gate reads that file.

## Build

From the repository root (BuildKit reads `collector/runner/Dockerfile.dockerignore`, an allowlist, instead of the root `.dockerignore`):

```sh
docker build -f collector/runner/Dockerfile -t sagentix-collector-runner .
docker run --rm sagentix-collector-runner --help
```

The build ends by running every engine's version command as uid 10001, `opa test` over `iac/policy/cloudflare`, and a check that ScubaGoggles resolves `/usr/local/bin/opa` and that each STIG archive holds its vendored dependency; any failure stops it. On 2026-10-15 the image built for linux/amd64 in 4 minutes on an Apple-silicon Mac under emulation and came to 2.87 GB, of which Prowler is 1.92 GB and the bundled engines about 690 MB. Adding Cinc Auditor (243 MB), the five archived STIG profiles (3.6 MB), Kubescape (293 MB) and Checkov's virtual environment (232 MB) took it to 3.64 GB the same day; a scan by each of the three, run as uid 10001 with `--network none`, worked from the image alone.

A linux/arm64 build stops at the Prowler step, which this change did not touch: one of Prowler 5.45.0's dependencies, `zstd`, publishes no aarch64 wheel for Python 3.13, and the slim image has no C compiler to build it. The engine downloads and their arm64 checksums do verify. Build with `--platform linux/amd64` on an arm64 machine, or add `build-essential` before the Prowler step in a derived image.

## Weekly from GitHub Actions, with an OIDC-assumed AWS role

```yaml
name: sagentix-prowler
on:
  schedule:
    - cron: "41 5 * * 1"   # Mondays, 05:41 UTC
  workflow_dispatch: {}
permissions:
  contents: read
  id-token: write          # for the OIDC token the AWS role trusts
jobs:
  prowler:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.SAGENTIX_AWS_ROLE_ARN }}   # output role_arn of iac/aws/evidence-role
          aws-region: ca-central-1
      - name: Build the runner
        run: docker build -f collector/runner/Dockerfile -t sagentix-collector-runner .
      - name: Scan, sign and push
        env:
          SAGENTIX_COLLECTOR_KEY: ${{ secrets.SAGENTIX_COLLECTOR_KEY }}
        run: |
          mkdir -m 0777 "$RUNNER_TEMP/sagentix"   # the container writes as uid 10001
          docker run --rm \
            -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION \
            -e SAGENTIX_COLLECTOR_KEY \
            -v "$RUNNER_TEMP/sagentix:/out" \
            sagentix-collector-runner run --source prowler --prowler-provider aws \
              --prowler-args="--region ca-central-1 us-east-1" \
              --endpoint "${{ vars.SAGENTIX_ENDPOINT }}" --key-id "${{ vars.SAGENTIX_KEY_ID }}" \
              --out /out/sagentix-prowler-push.json
      - uses: actions/upload-artifact@v4
        with:
          name: sagentix-prowler-push
          path: ${{ runner.temp }}/sagentix/sagentix-prowler-push.json
          retention-days: 400
```

The role's trust policy names the repository and branch (`github_repository`, `github_subjects` in `iac/aws/evidence-role`), so a pull request cannot assume it. The session credentials live for the job only and pass into the container as environment variables; nothing is written to the image. Pin each action to a commit SHA in your own repository.

A full AWS scan takes Prowler tens of minutes on a large account [Unverified: no run against a real account was made for this integration]. Narrow it with `--prowler-args="--region …"` or `--services …` when it does not fit the job's time limit.
