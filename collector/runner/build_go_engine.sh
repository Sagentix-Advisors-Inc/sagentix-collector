#!/usr/bin/env bash
# Build one Go engine from its release tag with the pinned Go toolchain (Stéphane, 2026-10-26: "build those tools
# yourself with a current go version ... less weaknesses the better"). Run inside the runner Dockerfile's gobuild stage.
#
#   build_go_engine.sh NAME REPO COMMIT TAG PKG TAGS LDFLAGS
#
# NAME     the binary's name, and the first column of go-module-fixes.txt
# REPO     owner/name on GitHub
# COMMIT   the full commit the release tag points at (update_engines.py moves it with the version); a tag that
#          now points elsewhere fails the build
# PKG      the main package (./cmd/trivy, .)
# TAGS     go build -tags, or "" for none
# LDFLAGS  the project's own release ldflags (version stamps), as its goreleaser config or Makefile writes them
#
# Each go-module-fixes.txt line for NAME raises one module to at least the version that fixes a published advisory.
# A line is skipped when the release already requires that version or newer, so a stale line does nothing. Go's
# checksum database verifies every module fetched (GOFLAGS=-mod=mod, GONOSUMDB unset).
set -euo pipefail
name="$1" repo="$2" commit="$3" tag="$4" pkg="$5" tags="$6" ldflags="$7"
src="/src/$name"
mkdir -p "$src" && cd "$src"
git init -q && git remote add origin "https://github.com/$repo.git"
git fetch -q --depth 1 origin "refs/tags/$tag:refs/tags/$tag"
got="$(git rev-parse "refs/tags/$tag^{commit}")"
[ "$got" = "$commit" ] || { echo "$name: tag $tag is $got, the Dockerfile pins $commit" >&2; exit 1; }
git checkout -q "$commit"

applied=0
while read -r tool mod min _; do
  [ "$tool" = "$name" ] || continue
  have="$(go list -m -f '{{.Version}}' "$mod" 2>/dev/null || true)"
  if [ -z "$have" ]; then echo "$name: $mod is not in the build list; skipped"; continue; fi
  if [ "$(printf '%s\n%s\n' "$have" "$min" | sort -V | head -1)" = "$min" ]; then
    echo "$name: $mod $have already >= $min; skipped"; continue
  fi
  echo "$name: $mod $have -> $min"
  go get "$mod@$min"
  applied=$((applied + 1))
done < <(grep -vE '^\s*(#|$)' /fixes/go-module-fixes.txt)
if [ "$applied" -gt 0 ]; then go mod tidy; fi

mkdir -p /out/bin "/out/licenses/$name"
CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
  go build -trimpath ${tags:+-tags "$tags"} -ldflags "-s -w $ldflags" -o "/out/bin/$name" "$pkg"
for f in LICENSE LICENSE.md NOTICE; do [ -f "$f" ] && cp "$f" "/out/licenses/$name/"; done
echo "$name $tag ($commit) built with $(go version | cut -d' ' -f3), $applied module fixes"
