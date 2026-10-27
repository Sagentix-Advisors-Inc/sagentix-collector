# Releasing the collector

`.github/workflows/collector-release.yml` runs by hand only (Actions → collector-release → Run workflow). Until the steps below are done it publishes nothing: the npm job stops at `npm publish --dry-run`, and the runner job builds the image without pushing it. Both still leave the tarball, its CycloneDX SBOM and `SHA256SUMS` as a workflow artifact, kept 400 days.

Releases come from the public mirror `Sagentix-Advisors-Inc/sagentix-collector`, because npm refuses provenance for a package built from a private repository, and GitHub artifact attestations in a private repository need GitHub Enterprise Cloud. Sagentix decided on 2026-10-17: public mirror, Apache License 2.0 (`LICENSE`, `NOTICE`), npm scope `@sagentix-inc` (the name `sagentix` was taken on npm).

## Release order for a new push format

A collector that sends a new format waits for sos-app to accept it everywhere it pushes. Format `sagentix-collect/3` (2026-10-23) is taken by sos-app from the release that carries migration 0040; dev and demo get it on the push to `rnd`, staging and prod through `scripts/release.py`. sos-app keeps taking format 2, so older collectors go on working.

## The security gate

Every change to the collector is scanned, and nothing ships without a pass (Sagentix, 2026-10-17). `.github/workflows/collector-security.yml` runs on each push and pull request that touches `collector/` or the catalogues, every Monday, and inside each release:

| Job | What fails it |
| --- | --- |
| `dependencies` | `npm audit`: a moderate or worse advisory in a shipped dependency, a high one in a build tool; `npm audit signatures`: a package whose registry signature or provenance does not verify |
| `trivy` | a MEDIUM or worse known vulnerability in the lockfile, a secret in the code, a MEDIUM or worse Dockerfile misconfiguration |
| `codeql` | any CodeQL `security-extended` result in `collector/src` or `collector/scripts`, unless `collector/security/accepted-findings.json` lists its rule and file with a reason |

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

## Runner image on GHCR

Run the workflow with `push_image` ticked. It builds `collector/runner/Dockerfile` for `linux/amd64` only (on arm64 the Prowler install needs a compiler the slim base lacks; `runner/README.md`, Build) and pushes `ghcr.io/<owner>/sagentix-collector-runner:<version>` and `:sha-<commit>`. BuildKit attaches SLSA provenance (`mode=max`) and an SBOM to the image index in every case; check them with `docker buildx imagetools inspect ghcr.io/<owner>/sagentix-collector-runner:<version> --format '{{json .Provenance}}'`. The GitHub attestation step (`actions/attest-build-provenance`) runs only from a public repository; verify it with `gh attestation verify oci://ghcr.io/<owner>/sagentix-collector-runner:<version> --owner <owner>`.

A package pushed from a private repository is private on GHCR. Make it public under the package's settings if customers pull it without a token.
