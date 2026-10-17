#!/usr/bin/env bash
# Copies the collector and the files it reads into a checkout of the public mirror (Sagentix, 2026-10-17;
# collector/RELEASING.md). Usage, from the repository root:
#   bash collector/scripts/sync-public-repo.sh <path to a checkout of Sagentix-Advisors-Inc/sagentix-collector>
# It changes files only; review the diff, then commit and push in the mirror yourself.
set -euo pipefail
src="$(cd "$(dirname "$0")/../.." && pwd)"
dst="${1:?path to the public mirror checkout}"
[ -d "$dst/.git" ] || { echo "$dst is not a git checkout" >&2; exit 1; }

# The security gate first (collector-security.yml, Sagentix 2026-10-17): only a committed, pushed collector
# that passed the gate on GitHub may reach the mirror.
shipped=(collector apps/sos-app/src/data/checks apps/sos-app/src/data/fedramp_rules.json .github/workflows/collector-security.yml .github/workflows/collector-release.yml)
if [ -n "$(git -C "$src" status --porcelain -- "${shipped[@]}")" ]; then
  echo "refusing: uncommitted changes in the collector; commit and push them so the security gate can scan them" >&2; exit 1
fi
last="$(git -C "$src" log -1 --format=%H -- "${shipped[@]}")"
passed="$(cd "$src" && gh run list --workflow collector-security.yml --commit "$last" --status success --limit 1 --json databaseId --jq 'length')"
if [ "$passed" != "1" ]; then
  echo "refusing: collector-security has not passed on ${last:0:8}, the last commit that changed the collector (push it, wait for the run)" >&2; exit 1
fi
echo "security gate passed on ${last:0:8}"

sync() { mkdir -p "$dst/$(dirname "$1")"; rsync -a --delete --exclude node_modules --exclude __pycache__ --exclude build --exclude public-repo "$src/$1" "$dst/$(dirname "$1")/"; }
sync collector
# The catalogues without Sagentix's control mappings; the OPA policies stay private (2026-10-17).
rm -rf "$dst/apps/sos-app/src/data/checks" "$dst/iac"
node "$src/collector/scripts/public-catalogue.mjs" "$src/apps/sos-app/src/data/checks" "$dst/apps/sos-app/src/data/checks"
mkdir -p "$dst/apps/sos-app/src/data" "$dst/.github/workflows"
cp "$src/apps/sos-app/src/data/fedramp_rules.json" "$dst/apps/sos-app/src/data/"
cp "$src/.github/workflows/collector-release.yml" "$src/.github/workflows/collector-security.yml" "$dst/.github/workflows/"
rsync -a "$src/collector/public-repo/" "$dst/"
cp "$src/collector/LICENSE" "$src/collector/NOTICE" "$dst/"
for doc in collector/README.md collector/runner/README.md; do node "$src/collector/scripts/public-docs.mjs" "$src/$doc" "$dst/$doc"; done

# Nothing private may leave: stop on any name of the private tree, a key, a mapping or a policy.
if grep -rlE '"(hub|ksis|coverage|hubBasis|ksiBasis)":' "$dst/apps/sos-app/src/data/checks" || [ -e "$dst/iac" ]; then
  echo "refusing: control mappings or policies in the mirror" >&2; exit 1
fi
if grep -rnE "Sagentix-KB|ENGAGEMENTS/|MAS_CONTROLLER|^MII[A-Za-z0-9+/]{60,}" "$dst" --exclude-dir=.git --exclude-dir=node_modules --exclude=sync-public-repo.sh; then
  echo "refusing: private references above" >&2; exit 1
fi
git -C "$dst" status --short | tail -n 20
