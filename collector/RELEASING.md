# Releasing the collector

`.github/workflows/collector-release.yml` runs by hand only (Actions → collector-release → Run workflow). Until the steps below are done it publishes nothing: the npm job stops at `npm publish --dry-run`, and the runner job builds the image without pushing it. Both still leave the tarball, its CycloneDX SBOM and `SHA256SUMS` as a workflow artifact, kept 400 days.

Releases come from the public mirror `Sagentix-Advisors-Inc/sagentix-collector`, because npm refuses provenance for a package built from a private repository, and GitHub artifact attestations in a private repository need GitHub Enterprise Cloud. Sagentix decided on 2026-10-17: public mirror, Apache License 2.0 (`LICENSE`, `NOTICE`), npm scope `@sagentix-inc` (the name `sagentix` was taken on npm).

## Release order for a new push format

A collector that sends a new format waits for sos-app to accept it everywhere it pushes. Format `sagentix-collect/3` (2026-10-23) is taken by sos-app from the release that carries migration 0040; dev and demo get it on the push to `rnd`, staging and prod through `scripts/release.py`. sos-app keeps taking format 2, so older collectors go on working.

## Release order for 0.5.0 (signature v2, signed answers)

sos-app goes first, with its channel key set as a Worker secret in every environment (`COLLECTOR_CHANNEL_SIGNING_KEY`, `apps/sos-app/docs/COLLECTOR_CHANNEL.md` section 10.2): a 0.5.0 collector takes no update and no vault delivery from an unsigned answer. The key's public half is pinned in `src/channel_keys.ts`; changing the channel key means pinning the new public key in a collector release first, then switching the secret, then dropping the old key in a later release. sos-app keeps accepting signature v1 until `COLLECTOR_SIG_V1=refuse` is set, which waits until every collector checks in at 0.5.0 or later (`GET /api/internal/collector/errors` lists check-ins per version).

## The security gate

Every change to the collector is scanned, and nothing ships without a pass (Sagentix, 2026-10-17). `.github/workflows/collector-security.yml` runs on each push and pull request that touches `collector/` or the catalogues, every Monday, and inside each release:

| Job | What fails it |
| --- | --- |
| `dependencies` | `npm audit`: a moderate or worse advisory in a shipped dependency, a high one in a build tool; `npm audit signatures`: a package whose registry signature or provenance does not verify |
| `trivy` | a MEDIUM or worse known vulnerability in the lockfile, a secret in the code, a MEDIUM or worse Dockerfile misconfiguration |
| `codeql` | any CodeQL `security-extended` result in `collector/src` or `collector/scripts`, unless `collector/security/accepted-findings.json` lists its rule and file with a reason |

Beside the gate, `.github/workflows/collector-qa.yml` (2026-11-07) runs on the same pushes: the typecheck, every suite with coverage floors (`npm run coverage`: 98% of lines, 82% of branches, 94% of functions, never lowered), the end-to-end run of every source against recorded replies with its golden results, `collector doctor` and a `--dry-run` as processes, and the timing of a full dry run in the job summary. `collector-release.yml` calls it as its `qa` job, and the npm and runner jobs need both `security` and `qa`: no release without a green QA run on that commit. The mirror gets it with the other two workflows.

`collector-release.yml` calls the gate first and its jobs `need` it; the runner job also scans the built image with Trivy before it can push. `collector/scripts/sync-public-repo.sh` refuses uncommitted collector changes and any commit the gate has not passed on GitHub.

## The mirror

The mirror holds `collector/`, the check catalogues without Sagentix's control mappings (`scripts/public-catalogue.mjs`), `apps/sos-app/src/data/fedramp_rules.json`, the release and security workflows, and the root files in `collector/public-repo/` (README, SECURITY.md, CI). The collector's READMEs go through `scripts/public-docs.mjs`, which drops the mapping columns and paragraphs. The OPA policies (`iac/policy/cloudflare/`) stay private; without them the `--tofu-state` checks report `skipped`. The npm package and the runner image carry the same cut-down catalogues and no policies. The paths match the private tree, since the collector finds its data by relative path. To refresh it, from the private repository's root:

```bash
git clone https://github.com/Sagentix-Advisors-Inc/sagentix-collector.git /tmp/sagentix-collector
bash collector/scripts/sync-public-repo.sh /tmp/sagentix-collector
cd /tmp/sagentix-collector && git diff --stat   # review, then commit and push
```

The script refuses to finish if the gate has not passed, or if it finds a control mapping, a policy, a name of the private tree or a key body. Pull requests to the mirror are not merged there; a fix goes into the private tree and reaches the mirror with the next sync.

## npm trusted publishing

1. Create the npm organization `sagentix-inc` (done 2026-10-17) and turn on two-factor authentication for publishing.
2. Publish the first version by hand, because a trusted publisher is attached to an existing package [Unverified: npm's behaviour for a package that does not exist yet was not tested]. From a checkout of the release repository: `cd collector && npm ci && node scripts/stage-package.mjs && cd build && npm publish --access public --provenance=false` (npm signs provenance only from CI, so the package's `publishConfig.provenance` must be switched off for this one). Done 2026-10-27 for 0.2.0, from npm's web sign-in in a real terminal: a command without one hides the two-factor link and fails with EOTP.
3. On npmjs.com, package settings → Trusted publishing → GitHub Actions: the owner and repository of the release repo, workflow file `collector-release.yml`, environment `npm`. Done 2026-10-27 on the website, with the permission "npm stage publish"; `npm trust github` answered 400 twice for a well-formed request. npm marks the entry "Pending validation" until the workflow publishes once, within 48 hours.
4. In that package's settings, set "Require two-factor authentication and disallow tokens", so only the workflow can publish.
5. In the release repository: Settings → Environments → `npm`, add a Sagentix maintainer as required reviewer; Settings → Variables → `NPM_TRUSTED_PUBLISHER` = `configured`.
6. Run the workflow with `publish` ticked. The job runs the tests, builds `collector/build/` with `scripts/stage-package.mjs`, installs the packed tarball in an empty folder and runs `npx collector --help`, writes the SBOM, then `npm stage publish --provenance --access public`. The version is staged, not live: a maintainer runs `npm stage list @sagentix-inc/evidence-collector` and `npm stage approve <id>` in a real terminal (two-factor prompt), or approves it on npmjs.com. npm then shows the provenance statement on the package page. A direct `npm publish` from the workflow answers 403 "OIDC permission denied for this action" under this permission (run 40439484580, 2026-10-27).

Bump `version` in `collector/package.json` before each release; npm refuses a version twice.

## Signing the channel target in CI (2026-11-08)

The workflow's third job, `channel`, ends the release: it signs the release target with a second release key and posts it to each sos-app environment, which makes it the candidate for Sagentix's own organizations; the canary analysis then promotes it (10%, 50%, stable) or halts it (`apps/sos-app/docs/COLLECTOR_CHANNEL.md`, section 14). It runs only when `post_channel` and `publish` are ticked, after the `npm` and `runner` jobs, in the protected environment `release`. No model and no AI key take part. Until the steps below are done it says so in a notice and ends green, and the release Mac's Keychain path (`apps/sos-app/scripts/collector-channel.mjs`, section 6 of the channel contract) remains; it stays the backup afterwards.

Set up once, by Stéphane:

1. Make the second key on the release Mac: `node apps/sos-app/scripts/collector-release-key.mjs`. It writes the private key to `~/.sagentix/collector-release-signing-key.b64` (mode 0600, never overwritten, never inside the repository) and prints only the public key.
2. Pin that public key in both lists, `collector/src/release_keys.ts` and `apps/sos-app/src/collector/release-keys.ts` (a test fails when they differ), and ship it in a collector release signed the old way: a collector verifies an update only against the keys it already carries, and `scripts/post-release-target.mjs` refuses to sign with a key that is not pinned.
3. In the release repository: Settings → Environments → New environment `release`, required reviewer Stéphane, deployment branches limited to the default branch. Its secrets: `COLLECTOR_RELEASE_SIGNING_KEY` (`gh secret set COLLECTOR_RELEASE_SIGNING_KEY --env release --repo Sagentix-Advisors-Inc/sagentix-collector < ~/.sagentix/collector-release-signing-key.b64`) and `COLLECTOR_RELEASE_POST_TOKEN` (a random value, for example `openssl rand -base64 32`). Its variable: `SOS_APP_RELEASE_ENDPOINTS`, the sos-app origins to post to, space separated (each environment keeps its own channel).
4. Give each of those sos-app environments the same token as a Worker secret, from `apps/sos-app`: `npx wrangler versions secret put COLLECTOR_RELEASE_POST_TOKEN -c wrangler.sos-app.jsonc --env <env>` (staged with the next release; `secret put` deploys at once). Optionally set the Worker variable `COLLECTOR_CANARY_ORGS` (organization ids); unset, the canaries are Sagentix's staff organizations.
5. Then delete the key file, or keep it offline only.

Each release: tick `post_channel`, and put in `fixes` the error signature ids this release fixes (the fix brief's release steps give them). The job also reads the head commit's `Fixes-Signature:` trailers, so carry the trailer from the private commit into the mirror commit message. Approve the `release` environment when GitHub asks; the job prints each environment's answer. A `409 already published` from an environment is not an error.

## Runner image on GHCR

Run the workflow with `push_image` ticked. It builds `collector/runner/Dockerfile` for `linux/amd64` only (on arm64 the Prowler install needs a compiler the slim base lacks; `runner/README.md`, Build) and pushes `ghcr.io/<owner>/sagentix-collector-runner:<version>` and `:sha-<commit>`. BuildKit attaches SLSA provenance (`mode=max`) and an SBOM to the image index in every case; check them with `docker buildx imagetools inspect ghcr.io/<owner>/sagentix-collector-runner:<version> --format '{{json .Provenance}}'`. The GitHub attestation step (`actions/attest-build-provenance`) runs only from a public repository; verify it with `gh attestation verify oci://ghcr.io/<owner>/sagentix-collector-runner:<version> --owner <owner>`.

A package pushed from a private repository is private on GHCR. Make it public under the package's settings if customers pull it without a token.
