# Sagentix evidence collector

The collector runs in your own CI. It reads your systems with read-only credentials, runs checks, signs what it saw with an Ed25519 key and pushes the result to Sagentix Cyber & AI. It never writes to the systems it reads.

This repository is a mirror. Sagentix develops the collector in a private repository and copies each release here, so the code you can read is the code that is published.

| Path | What it holds |
| --- | --- |
| `collector/` | the collector itself; start with [`collector/README.md`](collector/README.md) |
| `apps/sos-app/src/data/checks/` | the check list the collector reads: id, title, scope and evidence type of each check, one file per source |
| `apps/sos-app/src/data/fedramp_rules.json` | the FedRAMP 20x rules file the collector validates against |

Sagentix maps each check to controls inside its platform; those mappings, and the OPA policies the `cloudflare` source can evaluate with `--tofu-state --policy <dir>`, are not part of this repository.

The paths match the private repository's layout, because the collector finds its data by relative path.

The npm package is `@sagentix-inc/evidence-collector`. Releases carry npm provenance, and the runner image on GHCR carries a GitHub build attestation; [`collector/RELEASING.md`](collector/RELEASING.md) says how to check both.

Licence: Apache License 2.0 ([`LICENSE`](LICENSE), [`NOTICE`](NOTICE)). Third-party programs the collector runs are listed in [`collector/THIRD_PARTY_NOTICES.md`](collector/THIRD_PARTY_NOTICES.md).

Every change passes a security gate before it is published here: npm audit, Trivy and CodeQL (`.github/workflows/collector-security.yml`). Pull requests are read but not merged here, since the next release overwrites this tree. Report a security problem as [`SECURITY.md`](SECURITY.md) describes.
