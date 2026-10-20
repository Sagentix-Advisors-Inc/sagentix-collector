# Sagentix collector runner: Node 24 for the collector, Python 3.13 for Prowler, ScubaGoggles and Checkov, Cinc
# Auditor with MITRE's DISA STIG profiles, and the engines whose JSON the collector reads (Trivy, Syft, Grype,
# Gitleaks, OpenSSF Scorecard, OPA, Kubescape).
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

# Engines from their GitHub releases. Each SHA-256 is copied from the checksum file the project publishes
# with the release (URL above each group) and was matched on 2026-10-15 against the asset digest that
# GitHub's release API reports. Versions are the newest stable release at least 14 days old on 2026-10-15.
# https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256_AMD64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
# https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_checksums.txt
ARG SYFT_VERSION=1.52.0
ARG SYFT_SHA256_AMD64=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d
ARG SYFT_SHA256_ARM64=c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706
# https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_checksums.txt
ARG GRYPE_VERSION=0.119.0
ARG GRYPE_SHA256_AMD64=3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b
ARG GRYPE_SHA256_ARM64=29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8
# https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
# https://github.com/ossf/scorecard/releases/download/v5.5.0/scorecard_checksums.txt
ARG SCORECARD_VERSION=5.5.0
ARG SCORECARD_SHA256_AMD64=83b90a05c1540ef1390db1cd5711e5fd04be9c1d8537fb84d39d02092d6a8dff
ARG SCORECARD_SHA256_ARM64=3ce59d20c1d53e540c4a14e0da1e0d96b3b294e8ddc96a3c5a7b8a637b32991e
# https://github.com/open-policy-agent/opa/releases/download/v1.21.1/opa_linux_amd64_static.sha256
# https://github.com/open-policy-agent/opa/releases/download/v1.21.1/opa_linux_arm64_static.sha256
# ScubaGoggles 1.0.1 asks for OPA v1.18.2 or later (docs/installation/OPA.md at tag v1.0.1).
ARG OPA_VERSION=1.21.1
ARG OPA_SHA256_AMD64=668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031
ARG OPA_SHA256_ARM64=9a1f3625529c6f01240fe68286dde06aa0b23c5253da700ac48f4d943ff8a4de
# ScubaGoggles from PyPI; the SHA-256 is the wheel digest in https://pypi.org/pypi/scubagoggles/1.0.1/json
ARG SCUBAGOGGLES_VERSION=1.0.1
ARG SCUBAGOGGLES_WHEEL_URL=https://files.pythonhosted.org/packages/6e/23/9cacc45e30c1253e235f372468505330aaef16c0cc5d1559b0d34e5606c2/scubagoggles-1.0.1-py3-none-any.whl
ARG SCUBAGOGGLES_WHEEL_SHA256=0fcbbc73f2c646fb6b01ec8a1a068954684a6022d0a7a32b3b21bba9f408bdc9
# https://github.com/kubescape/kubescape/releases/download/v4.0.15/checksums.sha256
ARG KUBESCAPE_VERSION=4.0.15
ARG KUBESCAPE_SHA256_AMD64=6c9fd51bcdcd1093d19383ef20e1c58c2bf83c9026073f8dcc786680ed2a0093
ARG KUBESCAPE_SHA256_ARM64=416326e66c5d6cd5a542fceb912072e7c5dc2bb313d6c35d5dd13ff8fc26d31d
# Kubescape's controls, read offline (--use-artifacts-from /opt/kubescape/artifacts), never fetched at scan time.
# https://github.com/kubescape/regolibrary/releases/download/v2.0.38/checksums.txt
ARG REGOLIBRARY_VERSION=2.0.38
ARG REGOLIBRARY_NSA_SHA256=80e23ca99be3e5bb0f80d968b32ae27b7dada39f9b12b9e3abffea8680ac7737
ARG REGOLIBRARY_MITRE_SHA256=66ede046cacd778b80b1afd6432288b7cb5ba44f10b6dd39f99c31f5093315f9
ARG REGOLIBRARY_ATTACK_TRACKS_SHA256=80f3db3161aee990a8bab7fa0261576123fb7acf9654c595e7a47bdab339a6bb
ARG REGOLIBRARY_CONFIG_INPUTS_SHA256=6b78fae941db97d00780898da40581168303985e6dae0c74799f2c0a6ff5a8b6
ARG REGOLIBRARY_EXCEPTIONS_SHA256=d0b662af82db3fd6b2d8a242e1c7a46f47941ac7c298c2525481f817d928ddc3
# Checkov from PyPI; the SHA-256 is the wheel digest in https://pypi.org/pypi/checkov/3.3.21/json
ARG CHECKOV_VERSION=3.3.21
ARG CHECKOV_WHEEL_URL=https://files.pythonhosted.org/packages/86/7b/fd0d8803b773a82fdef37b795b738b0b673732139853931ebc8557276c03/checkov-3.3.21-py3-none-any.whl
ARG CHECKOV_WHEEL_SHA256=735cda1e6059fc9ec37735dddef1d30e3f05ae1ef74d4c291dbf23348d0b914c
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

# Fetch each pinned asset, check its SHA-256 (a mismatch fails the build), keep the binary and its LICENSE.
FROM ${FETCH_IMAGE} AS engines
ARG TARGETARCH
ARG TRIVY_VERSION TRIVY_SHA256_AMD64 TRIVY_SHA256_ARM64
ARG SYFT_VERSION SYFT_SHA256_AMD64 SYFT_SHA256_ARM64
ARG GRYPE_VERSION GRYPE_SHA256_AMD64 GRYPE_SHA256_ARM64
ARG GITLEAKS_VERSION GITLEAKS_SHA256_AMD64 GITLEAKS_SHA256_ARM64
ARG SCORECARD_VERSION SCORECARD_SHA256_AMD64 SCORECARD_SHA256_ARM64
ARG OPA_VERSION OPA_SHA256_AMD64 OPA_SHA256_ARM64
ARG SCUBAGOGGLES_VERSION SCUBAGOGGLES_WHEEL_URL SCUBAGOGGLES_WHEEL_SHA256
ARG KUBESCAPE_VERSION KUBESCAPE_SHA256_AMD64 KUBESCAPE_SHA256_ARM64
ARG REGOLIBRARY_VERSION REGOLIBRARY_NSA_SHA256 REGOLIBRARY_MITRE_SHA256 REGOLIBRARY_ATTACK_TRACKS_SHA256
ARG REGOLIBRARY_CONFIG_INPUTS_SHA256 REGOLIBRARY_EXCEPTIONS_SHA256
ARG CHECKOV_VERSION CHECKOV_WHEEL_URL CHECKOV_WHEEL_SHA256
SHELL ["/bin/bash", "-o", "pipefail", "-euc"]
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN case "${TARGETARCH}" in amd64|arm64) ;; *) echo "unsupported TARGETARCH '${TARGETARCH}'" >&2; exit 1 ;; esac \
    && mkdir -p /out/bin /out/licenses /out/wheels
ENV CURL="curl -fsSL --proto =https --tlsv1.2 --retry 3"
# Trivy (names its archives Linux-64bit and Linux-ARM64)
RUN if [ "${TARGETARCH}" = amd64 ]; then a=64bit s="${TRIVY_SHA256_AMD64}"; else a=ARM64 s="${TRIVY_SHA256_ARM64}"; fi \
    && f="trivy_${TRIVY_VERSION}_Linux-${a}.tar.gz" \
    && ${CURL} -o "$f" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && tar -xzf "$f" -C /out/bin trivy && mkdir /out/licenses/trivy && tar -xzf "$f" -C /out/licenses/trivy LICENSE && rm "$f"
# Syft
RUN if [ "${TARGETARCH}" = amd64 ]; then s="${SYFT_SHA256_AMD64}"; else s="${SYFT_SHA256_ARM64}"; fi \
    && f="syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && ${CURL} -o "$f" "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && tar -xzf "$f" -C /out/bin syft && mkdir /out/licenses/syft && tar -xzf "$f" -C /out/licenses/syft LICENSE && rm "$f"
# Grype
RUN if [ "${TARGETARCH}" = amd64 ]; then s="${GRYPE_SHA256_AMD64}"; else s="${GRYPE_SHA256_ARM64}"; fi \
    && f="grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && ${CURL} -o "$f" "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && tar -xzf "$f" -C /out/bin grype && mkdir /out/licenses/grype && tar -xzf "$f" -C /out/licenses/grype LICENSE && rm "$f"
# Gitleaks (names its amd64 archive x64)
RUN if [ "${TARGETARCH}" = amd64 ]; then a=x64 s="${GITLEAKS_SHA256_AMD64}"; else a=arm64 s="${GITLEAKS_SHA256_ARM64}"; fi \
    && f="gitleaks_${GITLEAKS_VERSION}_linux_${a}.tar.gz" \
    && ${CURL} -o "$f" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && tar -xzf "$f" -C /out/bin gitleaks && mkdir /out/licenses/gitleaks && tar -xzf "$f" -C /out/licenses/gitleaks LICENSE && rm "$f"
# OpenSSF Scorecard
RUN if [ "${TARGETARCH}" = amd64 ]; then s="${SCORECARD_SHA256_AMD64}"; else s="${SCORECARD_SHA256_ARM64}"; fi \
    && f="scorecard_${SCORECARD_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && ${CURL} -o "$f" "https://github.com/ossf/scorecard/releases/download/v${SCORECARD_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && tar -xzf "$f" -C /out/bin scorecard && mkdir /out/licenses/scorecard && tar -xzf "$f" -C /out/licenses/scorecard LICENSE && rm "$f"
# OPA: a bare static binary, no archive and no LICENSE beside it (THIRD_PARTY_NOTICES.md carries it)
RUN if [ "${TARGETARCH}" = amd64 ]; then s="${OPA_SHA256_AMD64}"; else s="${OPA_SHA256_ARM64}"; fi \
    && f="opa_linux_${TARGETARCH}_static" \
    && ${CURL} -o "$f" "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && install -m 0755 "$f" /out/bin/opa && rm "$f"
# ScubaGoggles wheel (pure Python, same file for both architectures)
RUN f="scubagoggles-${SCUBAGOGGLES_VERSION}-py3-none-any.whl" \
    && ${CURL} -o "/out/wheels/$f" "${SCUBAGOGGLES_WHEEL_URL}" \
    && echo "${SCUBAGOGGLES_WHEEL_SHA256}  /out/wheels/$f" | sha256sum -c -
# Kubescape
RUN if [ "${TARGETARCH}" = amd64 ]; then s="${KUBESCAPE_SHA256_AMD64}"; else s="${KUBESCAPE_SHA256_ARM64}"; fi \
    && f="kubescape_${KUBESCAPE_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && ${CURL} -o "$f" "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/$f" \
    && echo "$s  $f" | sha256sum -c - \
    && tar -xzf "$f" -C /out/bin kubescape && mkdir /out/licenses/kubescape && tar -xzf "$f" -C /out/licenses/kubescape LICENSE && rm "$f"
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
    && echo "${CHECKOV_WHEEL_SHA256}  /out/wheels/$f" | sha256sum -c - \
    && chmod 0755 /out/bin/*

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
COPY --from=engines /out/bin/ /usr/local/bin/
COPY --from=engines /out/licenses/ /usr/share/doc/sagentix-engines/
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
# Syft and Grype skip their check for a newer release; Trivy skips its version notice and sends no usage
# data to Aqua (on by default in 0.74.0). ScubaGoggles' defaults file points at the bundled OPA, so neither
# `scubagoggles setup` nor `getopa` has to download it. Kubescape skips its version check, which posts the scan
# context to version-check.ks-services.co; Checkov fetches no Prisma Cloud mapping and skips its PyPI check.
ENV HOME=/home/sagentix NODE_ENV=production PYTHONDONTWRITEBYTECODE=1 \
    SYFT_CHECK_FOR_APP_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false \
    TRIVY_DISABLE_TELEMETRY=true TRIVY_SKIP_VERSION_CHECK=true \
    KS_SKIP_UPDATE_CHECK=true BC_SKIP_MAPPING=TRUE CKV_SKIP_PACKAGE_UPDATE_CHECK=true
RUN mkdir -p /home/sagentix/.scubagoggles \
    && printf 'scubagoggles:\n  opa_dir: /usr/local/bin\n  output_dir: ./\n  credentials: null\n' \
       > /home/sagentix/.scubagoggles/userdefaults.yaml
# Every engine answers as the runtime user, and the build fails if one does not.
RUN trivy --version && syft version && grype version && gitleaks version && scorecard version \
    && opa version \
    && scubagoggles version && kubescape version && checkov --version && cinc-auditor version \
    && for a in /opt/sagentix/stig/*.tar.gz; do tar -tzf "$a" inspec.lock >/dev/null; done \
    && /opt/scubagoggles/bin/python -c "from scubagoggles.config import UserConfig; from scubagoggles.run_rego import find_opa; print('scubagoggles uses', find_opa(UserConfig().opa_dir))"
WORKDIR /opt/sagentix/collector
# An absolute path: `docker run -w /work` (the Docker google-login line sos-app generates) moves the working directory.
ENTRYPOINT ["node", "/opt/sagentix/collector/src/cli.ts"]
CMD ["--help"]
