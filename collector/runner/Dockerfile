# Sagentix collector runner: Node 24 for the collector, Python 3.13 for Prowler, ScubaGoggles and Checkov, Cinc
# Auditor with MITRE's DISA STIG profiles, and the Go engines whose JSON the collector reads (Trivy, Gitleaks,
# OpenSSF Scorecard, OPA, Kubescape), built here from their release tags with a current Go toolchain.
#
#   docker build -f collector/runner/Dockerfile -t sagentix-collector-runner .     (from the repository root)
#
# The build context is the repository root, cut down by Dockerfile.dockerignore beside this file (BuildKit
# reads it instead of the root .dockerignore). No secret is baked in: credentials and the signing key
# arrive as environment variables at `docker run` time. Pin all three base images by digest in your registry.
# Builds for linux/amd64 and linux/arm64 (TARGETARCH); any other architecture stops the build.

ARG NODE_IMAGE=node:24-bookworm-slim
ARG PYTHON_IMAGE=python:3.13-slim-bookworm
ARG FETCH_IMAGE=debian:bookworm-slim
ARG PROWLER_VERSION=5.45.0

# Go and the engines built from source (Stéphane, 2026-10-26: "build those tools yourself with a current go version -
# and of course find a way to keep everything up to date - less tools the better and less weaknesses the better").
# The projects' release binaries were built with older Go and older modules: Trivy's scan of the 2026-10-26 image
# found 304 medium-or-worse advisories in them, 170 in Go's standard library. Each engine is fetched at the commit its
# release tag points at (the build fails if the tag has moved), built with the Go below, and its modules raised to the
# floors in go-module-fixes.txt. update_engines.py moves a version and its commit together; Go moves the day a new
# patch release is out, since Go's point releases are its security releases.
# Go: https://go.dev/dl/?mode=json (the sha256 of each linux archive), checked 2026-10-26.
ARG GO_VERSION=1.27.3
ARG GO_SHA256_AMD64=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_SHA256_ARM64=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
# https://github.com/aquasecurity/trivy/releases/tag/v0.75.0
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_COMMIT=591e9799316a602e703f0b484f6c6d7b234ec8f3
# https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
# https://github.com/ossf/scorecard/releases/tag/v5.6.0
ARG SCORECARD_VERSION=5.6.0
ARG SCORECARD_COMMIT=61e84743356275f6ffca23b1b2f2cb945e19eb96
# https://github.com/open-policy-agent/opa/releases/tag/v1.21.1
# ScubaGoggles 1.0.1 asks for OPA v1.18.2 or later (docs/installation/OPA.md at tag v1.0.1).
ARG OPA_VERSION=1.21.1
ARG OPA_COMMIT=2a109e54103370d2ef288782ef3cb4c8a37902b2
# https://github.com/kubescape/kubescape/releases/tag/v4.0.15
ARG KUBESCAPE_VERSION=4.0.15
ARG KUBESCAPE_COMMIT=16cfe102f11551a6455fe9bf8e37d7083da90484
# ScubaGoggles from PyPI; the SHA-256 is the wheel digest in https://pypi.org/pypi/scubagoggles/1.0.1/json
ARG SCUBAGOGGLES_VERSION=1.0.1
ARG SCUBAGOGGLES_WHEEL_URL=https://files.pythonhosted.org/packages/6e/23/9cacc45e30c1253e235f372468505330aaef16c0cc5d1559b0d34e5606c2/scubagoggles-1.0.1-py3-none-any.whl
ARG SCUBAGOGGLES_WHEEL_SHA256=0fcbbc73f2c646fb6b01ec8a1a068954684a6022d0a7a32b3b21bba9f408bdc9
# Kubescape's controls, read offline (--use-artifacts-from /opt/kubescape/artifacts), never fetched at scan time.
# https://github.com/kubescape/regolibrary/releases/download/v2.0.38/checksums.txt
ARG REGOLIBRARY_VERSION=2.0.38
ARG REGOLIBRARY_NSA_SHA256=80e23ca99be3e5bb0f80d968b32ae27b7dada39f9b12b9e3abffea8680ac7737
ARG REGOLIBRARY_MITRE_SHA256=66ede046cacd778b80b1afd6432288b7cb5ba44f10b6dd39f99c31f5093315f9
ARG REGOLIBRARY_ATTACK_TRACKS_SHA256=80f3db3161aee990a8bab7fa0261576123fb7acf9654c595e7a47bdab339a6bb
ARG REGOLIBRARY_CONFIG_INPUTS_SHA256=6b78fae941db97d00780898da40581168303985e6dae0c74799f2c0a6ff5a8b6
ARG REGOLIBRARY_EXCEPTIONS_SHA256=d0b662af82db3fd6b2d8a242e1c7a46f47941ac7c298c2525481f817d928ddc3
# Checkov from PyPI; the SHA-256 is the wheel digest in https://pypi.org/pypi/checkov/3.3.27/json
ARG CHECKOV_VERSION=3.3.27
ARG CHECKOV_WHEEL_URL=https://files.pythonhosted.org/packages/26/ec/0042c3eecc84f394867554efdb25425b0b84f690997de512924850009c71/checkov-3.3.27-py3-none-any.whl
ARG CHECKOV_WHEEL_SHA256=f162b1fee91e204cc5891baa7e3dc1775fe9843dd11a0809986b9bce806528a2
# Cinc Auditor (Apache-2.0 community build of Chef InSpec; never Chef's EULA binary), Debian 12 package. Each SHA-256
# is the one Cinc's omnitruck lists: https://omnitruck.cinc.sh/stable/cinc-auditor/metadata?p=debian&pv=12&m=x86_64&v=7.2.1
# (and m=aarch64), matched on 2026-10-15 against the downloaded package.
ARG CINC_AUDITOR_VERSION=7.2.1
ARG CINC_AUDITOR_SHA256_AMD64=7bdb16945ddbd5781ce8367a4eb5072af3f4fcc0c5c7a1639dad1c3831bcb9d4
ARG CINC_AUDITOR_SHA256_ARM64=d23e46096cd5c9208d79b805e46cf7077d01d39f79f456b0cacdd37746c37ed4
# MITRE SAF DISA STIG profiles: GitHub's tarball of each release tag (https://codeload.github.com/mitre/<repo>/tar.gz/refs/tags/<tag>).
# MITRE publishes no checksum, so the SHA-256 is of that tarball, pinned with the tag's commit in
# apps/sos-app/scripts/build_stig_catalog.py, which builds the catalogues from the same bytes.
ARG STIG_RHEL9_TAG=v2.7.2
ARG STIG_RHEL9_SHA256=99742c20780a4fa267ff7e4827647a3877509d2a7bda19db7d3aa925ddb676a2
ARG STIG_RHEL8_TAG=v2.7.1
ARG STIG_RHEL8_SHA256=e4c63c518087e2241fbdc26b3af69340f4376eb50879ef02a65afe0633924032
ARG STIG_UBUNTU2204_TAG=v2.7.2
ARG STIG_UBUNTU2204_SHA256=7697c7a66fd2ce72fdbc83a75430de9641d157151de2a7ee7cfb87552292637f
ARG STIG_UBUNTU2404_TAG=v1.4.2
ARG STIG_UBUNTU2404_SHA256=3de5186a59b33b27d5e0422a9e5255cb6c88f86be3eb3d7497c20803bbdae873
ARG STIG_AL2023_TAG=v1.3.2
ARG STIG_AL2023_SHA256=d01638c133c93de1e4e55d15b810f94ff9c30aa2c14760467748846e1d37aff0

FROM ${NODE_IMAGE} AS node
WORKDIR /opt/sagentix/collector
COPY collector/package.json collector/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
# The image is public: its catalogues carry no control mappings, and the OPA policies stay out (Sagentix, 2026-10-17).
COPY collector/scripts/public-catalogue.mjs /tmp/public-catalogue.mjs
COPY apps/sos-app/src/data/checks /tmp/checks
RUN node /tmp/public-catalogue.mjs /tmp/checks /opt/sagentix/catalogue

# The Go engines, built on the build machine's own architecture for TARGETARCH (Go cross-compiles; CGO is off).
FROM --platform=$BUILDPLATFORM ${FETCH_IMAGE} AS gobuild
ARG BUILDARCH TARGETARCH
ARG GO_VERSION GO_SHA256_AMD64 GO_SHA256_ARM64
SHELL ["/bin/bash", "-o", "pipefail", "-euc"]
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH}" in amd64|arm64) ;; *) echo "unsupported TARGETARCH '${TARGETARCH}'" >&2; exit 1 ;; esac \
    && if [ "${BUILDARCH}" = amd64 ]; then s="${GO_SHA256_AMD64}"; else s="${GO_SHA256_ARM64}"; fi \
    && f="go${GO_VERSION}.linux-${BUILDARCH}.tar.gz" \
    && curl -fsSL --proto =https --tlsv1.2 --retry 3 -o "/tmp/$f" "https://go.dev/dl/$f" \
    && echo "$s  /tmp/$f" | sha256sum -c - && tar -xzf "/tmp/$f" -C /usr/local && rm "/tmp/$f"
# GOTOOLCHAIN=local: a go.mod asking for a newer Go fails the build instead of downloading one.
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-mod=mod TARGETARCH=${TARGETARCH}
COPY collector/runner/build_go_engine.sh /usr/local/bin/build_go_engine.sh
COPY collector/runner/go-module-fixes.txt /fixes/go-module-fixes.txt
# Each project's own release flags: goreleaser.yml (Trivy, Gitleaks, Scorecard, Kubescape) or the Makefile (OPA).
ARG TRIVY_VERSION TRIVY_COMMIT
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    build_go_engine.sh trivy aquasecurity/trivy "${TRIVY_COMMIT}" "v${TRIVY_VERSION}" ./cmd/trivy "" \
      "-X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}"
ARG GITLEAKS_VERSION GITLEAKS_COMMIT
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    build_go_engine.sh gitleaks gitleaks/gitleaks "${GITLEAKS_COMMIT}" "v${GITLEAKS_VERSION}" . gore2regex \
      "-X=github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}"
ARG SCORECARD_VERSION SCORECARD_COMMIT
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    build_go_engine.sh scorecard ossf/scorecard "${SCORECARD_COMMIT}" "v${SCORECARD_VERSION}" . netgo \
      "-X sigs.k8s.io/release-utils/version.gitVersion=v${SCORECARD_VERSION} -X sigs.k8s.io/release-utils/version.gitCommit=${SCORECARD_COMMIT} -X sigs.k8s.io/release-utils/version.gitTreeState=clean"
ARG OPA_VERSION OPA_COMMIT
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    build_go_engine.sh opa open-policy-agent/opa "${OPA_COMMIT}" "v${OPA_VERSION}" . opa_wasm ""
ARG KUBESCAPE_VERSION KUBESCAPE_COMMIT
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    build_go_engine.sh kubescape kubescape/kubescape "${KUBESCAPE_COMMIT}" "v${KUBESCAPE_VERSION}" . "" \
      "-X main.version=v${KUBESCAPE_VERSION} -X main.commit=${KUBESCAPE_COMMIT}"

# Fetch each pinned asset, check its SHA-256 (a mismatch fails the build).
FROM ${FETCH_IMAGE} AS engines
ARG SCUBAGOGGLES_VERSION SCUBAGOGGLES_WHEEL_URL SCUBAGOGGLES_WHEEL_SHA256
ARG REGOLIBRARY_VERSION REGOLIBRARY_NSA_SHA256 REGOLIBRARY_MITRE_SHA256 REGOLIBRARY_ATTACK_TRACKS_SHA256
ARG REGOLIBRARY_CONFIG_INPUTS_SHA256 REGOLIBRARY_EXCEPTIONS_SHA256
ARG CHECKOV_VERSION CHECKOV_WHEEL_URL CHECKOV_WHEEL_SHA256
SHELL ["/bin/bash", "-o", "pipefail", "-euc"]
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN mkdir -p /out/wheels
ENV CURL="curl -fsSL --proto =https --tlsv1.2 --retry 3"
# ScubaGoggles wheel (pure Python, same file for both architectures)
RUN f="scubagoggles-${SCUBAGOGGLES_VERSION}-py3-none-any.whl" \
    && ${CURL} -o "/out/wheels/$f" "${SCUBAGOGGLES_WHEEL_URL}" \
    && echo "${SCUBAGOGGLES_WHEEL_SHA256}  /out/wheels/$f" | sha256sum -c -
# regolibrary: the NSA and MITRE frameworks, attack tracks, default control inputs and exceptions (same for both architectures)
RUN mkdir -p /out/kubescape \
    && for a in "nsa:${REGOLIBRARY_NSA_SHA256}" "mitre:${REGOLIBRARY_MITRE_SHA256}" "attack_tracks:${REGOLIBRARY_ATTACK_TRACKS_SHA256}" \
                "default_config_inputs:${REGOLIBRARY_CONFIG_INPUTS_SHA256}" "exceptions:${REGOLIBRARY_EXCEPTIONS_SHA256}"; do \
         n="${a%%:*}"; ${CURL} -o "/out/kubescape/$n" "https://github.com/kubescape/regolibrary/releases/download/v${REGOLIBRARY_VERSION}/$n"; \
         echo "${a#*:}  /out/kubescape/$n" | sha256sum -c -; \
       done
# Checkov wheel (pure Python; its dependencies come from PyPI at install time, unpinned, as Prowler's do)
RUN f="checkov-${CHECKOV_VERSION}-py3-none-any.whl" \
    && ${CURL} -o "/out/wheels/$f" "${CHECKOV_WHEEL_URL}" \
    && echo "${CHECKOV_WHEEL_SHA256}  /out/wheels/$f" | sha256sum -c -

# Cinc Auditor and the STIG profiles. Each profile is archived here with its one dependency (MITRE's
# inspec-profile-resources, fetched by git at the commit its inspec.yml pins), so a scan never fetches anything.
FROM ${FETCH_IMAGE} AS stig
ARG TARGETARCH
ARG CINC_AUDITOR_VERSION CINC_AUDITOR_SHA256_AMD64 CINC_AUDITOR_SHA256_ARM64
ARG STIG_RHEL9_TAG STIG_RHEL9_SHA256 STIG_RHEL8_TAG STIG_RHEL8_SHA256 STIG_UBUNTU2204_TAG STIG_UBUNTU2204_SHA256
ARG STIG_UBUNTU2404_TAG STIG_UBUNTU2404_SHA256 STIG_AL2023_TAG STIG_AL2023_SHA256
SHELL ["/bin/bash", "-o", "pipefail", "-euc"]
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
ENV CURL="curl -fsSL --proto =https --tlsv1.2 --retry 3"
RUN if [ "${TARGETARCH}" = amd64 ]; then s="${CINC_AUDITOR_SHA256_AMD64}"; else s="${CINC_AUDITOR_SHA256_ARM64}"; fi \
    && f="cinc-auditor_${CINC_AUDITOR_VERSION}-1_${TARGETARCH}.deb" && mkdir -p /out/stig /out/licenses \
    && ${CURL} -o "/out/$f" "https://packages.cinc.sh/files/stable/cinc-auditor/${CINC_AUDITOR_VERSION}/debian/12/$f" \
    && echo "$s  /out/$f" | sha256sum -c - && mv "/out/$f" /out/cinc-auditor.deb && dpkg -i /out/cinc-auditor.deb
WORKDIR /p
RUN for p in "rhel9:redhat-enterprise-linux-9-stig-baseline:${STIG_RHEL9_TAG}:${STIG_RHEL9_SHA256}" \
             "rhel8:redhat-enterprise-linux-8-stig-baseline:${STIG_RHEL8_TAG}:${STIG_RHEL8_SHA256}" \
             "ubuntu2204:canonical-ubuntu-22.04-lts-stig-baseline:${STIG_UBUNTU2204_TAG}:${STIG_UBUNTU2204_SHA256}" \
             "ubuntu2404:canonical-ubuntu-24.04-lts-stig-baseline:${STIG_UBUNTU2404_TAG}:${STIG_UBUNTU2404_SHA256}" \
             "al2023:amazon-linux-2023-stig-baseline:${STIG_AL2023_TAG}:${STIG_AL2023_SHA256}"; do \
         IFS=: read -r key repo tag sha <<< "$p"; \
         ${CURL} -o "$key.tar.gz" "https://codeload.github.com/mitre/$repo/tar.gz/refs/tags/$tag"; \
         echo "$sha  $key.tar.gz" | sha256sum -c -; \
         mkdir "$key" && tar -xzf "$key.tar.gz" -C "$key" --strip-components 1; \
         cinc-auditor archive "$key" --output "/out/stig/$key.tar.gz" --overwrite; \
         mkdir "/out/licenses/mitre-stig-$key" && cp "$key/LICENSE.md" "$key/NOTICE.md" "/out/licenses/mitre-stig-$key/"; \
       done \
    && cp /opt/cinc-auditor/LICENSE /out/licenses/cinc-auditor.LICENSE

FROM ${PYTHON_IMAGE}
# Debian security fixes published after the base image was built: Trivy found OpenSSL 3.0.22-1~deb12u1 in it on
# 2026-10-26, with deb12u2 already out. An upgrade within bookworm only; nothing new is installed.
# hadolint ignore=DL3005
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
ARG PROWLER_VERSION
ARG SCUBAGOGGLES_VERSION
# Prowler, at the version the sos-app catalogues were built from (apps/sos-app/scripts/build_prowler_catalog.py).
RUN pip install --no-cache-dir "prowler==${PROWLER_VERSION}" && prowler --version
# ScubaGoggles in its own virtual environment, so its Google client libraries never move Prowler's.
RUN --mount=type=bind,from=engines,source=/out/wheels,target=/wheels \
    python -m venv /opt/scubagoggles \
    && /opt/scubagoggles/bin/pip install --no-cache-dir "/wheels/scubagoggles-${SCUBAGOGGLES_VERSION}-py3-none-any.whl" \
    && ln -s /opt/scubagoggles/bin/scubagoggles /usr/local/bin/scubagoggles
# Checkov in its own virtual environment too, for the same reason.
ARG CHECKOV_VERSION
RUN --mount=type=bind,from=engines,source=/out/wheels,target=/wheels \
    python -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir "/wheels/checkov-${CHECKOV_VERSION}-py3-none-any.whl" \
    && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov
# Cinc Auditor (into /opt/cinc-auditor) and the archived STIG profiles.
RUN --mount=type=bind,from=stig,source=/out,target=/stig dpkg -i /stig/cinc-auditor.deb
COPY --from=stig /out/stig/ /opt/sagentix/stig/
COPY --from=stig /out/licenses/ /usr/share/doc/sagentix-engines/
COPY --from=gobuild /out/bin/ /usr/local/bin/
COPY --from=gobuild /out/licenses/ /usr/share/doc/sagentix-engines/
# Python package floors (python-fixes.txt), raised in each environment that has the package. A raise that breaks an
# engine's own pin is rolled back and logged as held; pip check must pass in every environment.
COPY collector/runner/python-fixes.txt collector/runner/apply_python_fixes.py /tmp/pyfix/
RUN for py in /usr/local/bin/python /opt/scubagoggles/bin/python /opt/checkov/bin/python; do \
      "$py" /tmp/pyfix/apply_python_fixes.py /tmp/pyfix/python-fixes.txt || exit 1; done \
    && rm -rf /tmp/pyfix /root/.cache/pip
# pip leaves the image once everything is installed: nothing runs it at scan time, and it carries its own vendored
# copies of urllib3, msgpack and setuptools, older than the environments' (pip 26.2.2's vendor.txt; Trivy, 2026-10-26).
RUN for py in /usr/local/bin/python /opt/scubagoggles/bin/python /opt/checkov/bin/python; do \
      "$py" -m pip uninstall --yes --quiet pip || exit 1; done \
    && rm -rf /usr/local/lib/python3.13/ensurepip/_bundled /usr/local/bin/pip /usr/local/bin/pip3*
# Kubescape reads its framework files from here; controls-inputs.json is the release's postureControlInputs.
RUN --mount=type=bind,from=engines,source=/out/kubescape,target=/rego \
    mkdir -p /opt/kubescape/artifacts \
    && cp /rego/nsa /opt/kubescape/artifacts/nsa.json && cp /rego/mitre /opt/kubescape/artifacts/mitre.json \
    && cp /rego/attack_tracks /opt/kubescape/artifacts/attack-tracks.json && cp /rego/exceptions /opt/kubescape/artifacts/exceptions.json \
    && python -c "import json,sys; json.dump(json.load(open('/rego/default_config_inputs'))['settings']['postureControlInputs'], open('/opt/kubescape/artifacts/controls-inputs.json','w'))"
# Node 24: the binary only (no npm at run time). Bookworm on both sides, so glibc and libstdc++ match.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
WORKDIR /opt/sagentix
COPY --from=node /opt/sagentix/collector/node_modules collector/node_modules
COPY collector/package.json collector/package-lock.json collector/
COPY collector/src collector/src
# What the collector reads beside itself: the check catalogues (without mappings) and the FedRAMP rules (v1 push).
COPY --from=node /opt/sagentix/catalogue apps/sos-app/src/data/checks
COPY apps/sos-app/src/data/fedramp_rules.json apps/sos-app/src/data/fedramp_rules.json
COPY collector/THIRD_PARTY_NOTICES.md collector/THIRD_PARTY_NOTICES.md

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin sagentix
USER 10001:10001
# Trivy skips its version notice and sends no usage data to Aqua (on by default since 0.74.0). ScubaGoggles' defaults file points at the bundled OPA, so neither
# `scubagoggles setup` nor `getopa` has to download it. Kubescape skips its version check, which posts the scan
# context to version-check.ks-services.co; Checkov fetches no Prisma Cloud mapping and skips its PyPI check.
ENV HOME=/home/sagentix NODE_ENV=production PYTHONDONTWRITEBYTECODE=1 \
    TRIVY_DISABLE_TELEMETRY=true TRIVY_SKIP_VERSION_CHECK=true \
    KS_SKIP_UPDATE_CHECK=true BC_SKIP_MAPPING=TRUE CKV_SKIP_PACKAGE_UPDATE_CHECK=true
# The image has no .git: the run report and the check-in read the collector's commit from here (2026-10-28,
# apps/sos-app/docs/COLLECTOR_CHANNEL.md). The release workflow passes the mirror commit it builds.
ARG COLLECTOR_COMMIT=unknown
ENV SAGENTIX_COLLECTOR_COMMIT=${COLLECTOR_COMMIT} SAGENTIX_RUNNER=docker
RUN mkdir -p /home/sagentix/.scubagoggles \
    && printf 'scubagoggles:\n  opa_dir: /usr/local/bin\n  output_dir: ./\n  credentials: null\n' \
       > /home/sagentix/.scubagoggles/userdefaults.yaml
# Every engine answers as the runtime user, and the build fails if one does not.
RUN trivy --version && gitleaks version && scorecard version \
    && opa version \
    && scubagoggles version && kubescape version && checkov --version && cinc-auditor version \
    && for a in /opt/sagentix/stig/*.tar.gz; do tar -tzf "$a" inspec.lock >/dev/null; done \
    && /opt/scubagoggles/bin/python -c "from scubagoggles.config import UserConfig; from scubagoggles.run_rego import find_opa; print('scubagoggles uses', find_opa(UserConfig().opa_dir))"
WORKDIR /opt/sagentix/collector
# An absolute path: `docker run -w /work` (the Docker google-login line sos-app generates) moves the working directory.
ENTRYPOINT ["node", "/opt/sagentix/collector/src/cli.ts"]
CMD ["--help"]
