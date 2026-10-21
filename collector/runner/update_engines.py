#!/usr/bin/env python3
"""Find newer releases of the engines the collector runner pins, and move one pin to its new release.

Run by .github/workflows/engine-updates.yml (daily). Sagentix, 2026-10-15: "ensure that you are running the
most up to date version of Prowler (and keep it up to date as soon as a new version comes up)".

  check                list the engines with a newer eligible release, as JSON (and a matrix for Actions)
  apply NAME VERSION   move NAME's pins to VERSION, regenerate its catalogues, write the PR body

Pins live in collector/runner/Dockerfile (Prowler, Trivy, Syft, Grype, Gitleaks, Scorecard, OPA, ScubaGoggles,
Kubescape and its regolibrary, Checkov, Cinc Auditor, the five MITRE STIG profiles),
apps/sos-app/scripts/build_prowler_catalog.py, collector/src/sources/prowler.ts,
apps/sos-app/scripts/build_scuba_catalog.py (ScubaGoggles, ScubaGear), build_stig_catalog.py (STIG profiles),
build_kubescape_catalog.py (regolibrary, Kubescape's version), build_checkov_catalog.py (Checkov) and
collector/src/sources/stig.ts (Cinc Auditor's and the profiles' versions). collector/THIRD_PARTY_NOTICES.md and the
README's engine table carry the same versions and digests, so they move too. Prose that describes what an old
release did (check counts, a missing wheel) is never rewritten: the PR body lists those lines for a person.

Eligible: a published, non-prerelease GitHub release whose tag is a plain X.Y.Z (with or without "v"), at least
MIN_AGE_DAYS old. Prowler's age is 0 (Sagentix's decision); the others keep the README's rule of 14 days.
A binary's SHA-256 comes from the checksum file its project publishes with the release, and must agree with
the digest GitHub's release API reports when it reports one; a disagreement stops with exit 2 and no PR.
Cinc Auditor is not on GitHub: its versions, package digests and dates come from Cinc's omnitruck and package
server, and its source tag and licence from InSpec's repository at the same version. MITRE publishes no checksum for
a STIG profile, so its pin is the SHA-256 of GitHub's tarball of the release tag, taken when the pin moves.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "collector" / "runner" / "Dockerfile"
README = ROOT / "collector" / "runner" / "README.md"
NOTICES = ROOT / "collector" / "THIRD_PARTY_NOTICES.md"
PROWLER_GEN = ROOT / "apps" / "sos-app" / "scripts" / "build_prowler_catalog.py"
PROWLER_TS = ROOT / "collector" / "src" / "sources" / "prowler.ts"
SCUBA_GEN = ROOT / "apps" / "sos-app" / "scripts" / "build_scuba_catalog.py"
STIG_GEN = ROOT / "apps" / "sos-app" / "scripts" / "build_stig_catalog.py"
KUBESCAPE_GEN = ROOT / "apps" / "sos-app" / "scripts" / "build_kubescape_catalog.py"
CHECKOV_GEN = ROOT / "apps" / "sos-app" / "scripts" / "build_checkov_catalog.py"
STIG_TS = ROOT / "collector" / "src" / "sources" / "stig.ts"
GUIDES_GEN = ROOT / "apps" / "sos-app" / "scripts" / "build_control_guides.py"
CHECKS = ROOT / "apps" / "sos-app" / "src" / "data" / "checks"

ENGINES: dict[str, dict] = {
    "prowler": {"label": "Prowler", "repo": "prowler-cloud/prowler", "tag": "{v}", "kind": "prowler", "arg": "PROWLER",
                "pypi": "prowler", "notices": "Prowler", "min_age_days": 0,
                "tests": ["prowler-catalogue", "collector", "sos-app", "docker"]},
    "trivy": {"label": "Trivy", "repo": "aquasecurity/trivy", "tag": "v{v}", "kind": "binary", "arg": "TRIVY",
              "checksums": "trivy_{v}_checksums.txt",
              "assets": {"amd64": "trivy_{v}_Linux-64bit.tar.gz", "arm64": "trivy_{v}_Linux-ARM64.tar.gz"},
              "notices": "Trivy", "readme": "Trivy", "tests": ["collector", "docker"]},
    "syft": {"label": "Syft", "repo": "anchore/syft", "tag": "v{v}", "kind": "binary", "arg": "SYFT",
             "checksums": "syft_{v}_checksums.txt",
             "assets": {"amd64": "syft_{v}_linux_amd64.tar.gz", "arm64": "syft_{v}_linux_arm64.tar.gz"},
             "notices": "Syft", "readme": "Syft", "tests": ["collector", "docker"]},
    "grype": {"label": "Grype", "repo": "anchore/grype", "tag": "v{v}", "kind": "binary", "arg": "GRYPE",
              "checksums": "grype_{v}_checksums.txt",
              "assets": {"amd64": "grype_{v}_linux_amd64.tar.gz", "arm64": "grype_{v}_linux_arm64.tar.gz"},
              "notices": "Grype", "readme": "Grype", "tests": ["collector", "docker"]},
    "gitleaks": {"label": "Gitleaks", "repo": "gitleaks/gitleaks", "tag": "v{v}", "kind": "binary", "arg": "GITLEAKS",
                 "checksums": "gitleaks_{v}_checksums.txt",
                 "assets": {"amd64": "gitleaks_{v}_linux_x64.tar.gz", "arm64": "gitleaks_{v}_linux_arm64.tar.gz"},
                 "notices": "Gitleaks", "readme": "Gitleaks", "tests": ["collector", "docker"]},
    "scorecard": {"label": "OpenSSF Scorecard", "repo": "ossf/scorecard", "tag": "v{v}", "kind": "binary", "arg": "SCORECARD",
                  "checksums": "scorecard_checksums.txt",
                  "assets": {"amd64": "scorecard_{v}_linux_amd64.tar.gz", "arm64": "scorecard_{v}_linux_arm64.tar.gz"},
                  "notices": "OpenSSF Scorecard", "readme": "OpenSSF Scorecard", "tests": ["collector", "docker"]},
    "opa": {"label": "OPA", "repo": "open-policy-agent/opa", "tag": "v{v}", "kind": "binary", "arg": "OPA",
            "checksums": "{asset}.sha256",  # one file per asset
            "assets": {"amd64": "opa_linux_amd64_static", "arm64": "opa_linux_arm64_static"},
            "notices": "Open Policy Agent (OPA)", "readme": "OPA", "tests": ["collector", "docker"]},
    "scubagoggles": {"label": "ScubaGoggles", "repo": "cisagov/ScubaGoggles", "tag": "v{v}", "kind": "scubagoggles",
                     "arg": "SCUBAGOGGLES", "pypi": "scubagoggles", "notices": "ScubaGoggles", "readme": "ScubaGoggles",
                     "tests": ["scuba-catalogue", "collector", "sos-app", "docker"]},
    "scubagear": {"label": "ScubaGear", "repo": "cisagov/ScubaGear", "tag": "v{v}", "kind": "scubagear",
                  "tests": ["scuba-catalogue", "collector", "sos-app"]},
    "kubescape": {"label": "Kubescape", "repo": "kubescape/kubescape", "tag": "v{v}", "kind": "binary", "arg": "KUBESCAPE",
                  "checksums": "checksums.sha256",
                  "assets": {"amd64": "kubescape_{v}_linux_amd64.tar.gz", "arm64": "kubescape_{v}_linux_arm64.tar.gz"},
                  "notices": "Kubescape", "readme": "Kubescape", "tests": ["engine-catalogue", "collector", "sos-app", "docker"]},
    "regolibrary": {"label": "Kubescape regolibrary", "repo": "kubescape/regolibrary", "tag": "v{v}", "kind": "regolibrary",
                    "arg": "REGOLIBRARY", "checksums": "checksums.txt",
                    "assets": {"nsa": "NSA", "mitre": "MITRE", "attack_tracks": "ATTACK_TRACKS",
                               "default_config_inputs": "CONFIG_INPUTS", "exceptions": "EXCEPTIONS"},
                    "notices": "Kubescape regolibrary", "readme": "Kubescape regolibrary",
                    "tests": ["engine-catalogue", "collector", "sos-app", "docker"]},
    "checkov": {"label": "Checkov", "repo": "bridgecrewio/checkov", "tag": "{v}", "kind": "wheel", "arg": "CHECKOV",
                "pypi": "checkov", "notices": "Checkov", "readme": "Checkov",
                "tests": ["engine-catalogue", "collector", "sos-app", "docker"]},
    "cinc": {"label": "Cinc Auditor", "repo": "inspec/inspec", "tag": "v{v}", "kind": "cinc", "arg": "CINC_AUDITOR",
             "notices": "Cinc Auditor", "readme": "Cinc Auditor", "tests": ["collector", "docker"]},
}
# The MITRE SAF STIG profiles, one engine each (names are [a-z0-9]+ for the workflow's branch names).
STIG_PROFILES = {"rhel9": "redhat-enterprise-linux-9-stig-baseline", "rhel8": "redhat-enterprise-linux-8-stig-baseline",
                 "ubuntu2204": "canonical-ubuntu-22.04-lts-stig-baseline", "ubuntu2404": "canonical-ubuntu-24.04-lts-stig-baseline",
                 "al2023": "amazon-linux-2023-stig-baseline"}
for _key, _repo in STIG_PROFILES.items():
    ENGINES[f"stig{_key}"] = {"label": f"MITRE STIG profile {_key}", "repo": f"mitre/{_repo}", "tag": "v{v}", "kind": "stig",
                              "profile": _key, "arg": f"STIG_{_key.upper()}", "notices": "MITRE SAF STIG profiles",
                              "tests": ["engine-catalogue", "collector", "sos-app", "docker"]}
OMNITRUCK = "https://omnitruck.cinc.sh/stable/cinc-auditor"
CINC_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
DEFAULT_MIN_AGE_DAYS = 14
VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


# ── Pure helpers (unit-tested) ───────────────────────────────────────────────────────────────────────

def vkey(v: str) -> tuple[int, int, int]:
    m = VERSION.match(v)
    if not m:
        raise ValueError(f"not a plain X.Y.Z version: {v!r}")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def pick_release(releases: list[dict], current: str, min_age_days: int, now: dt.datetime) -> dict | None:
    """The newest eligible release newer than `current`, or None."""
    best = None
    for r in releases:
        if r.get("draft") or r.get("prerelease") or not r.get("published_at"):
            continue
        tag = str(r.get("tag_name", ""))
        if not VERSION.match(tag):
            continue
        published = dt.datetime.fromisoformat(r["published_at"].replace("Z", "+00:00"))
        if now - published < dt.timedelta(days=min_age_days):
            continue
        if vkey(tag) <= vkey(current):
            continue
        if best is None or vkey(tag) > vkey(best["tag_name"]):
            best = r
    if best is None:
        return None
    return {"tag": best["tag_name"], "version": best["tag_name"].lstrip("v"), "published": best["published_at"],
            "url": best.get("html_url")}


def parse_checksums(text: str) -> dict[str, str]:
    """'<sha256>  <file>' lines (also '*file' and a bare hash for a one-asset .sha256 file under key '')."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            continue
        out[parts[1].lstrip("*") if len(parts) > 1 else ""] = parts[0]
    return out


def ver_rx(v: str) -> re.Pattern:
    """A version as a whole token: 5.5.0 matches in 'v5.5.0' and 'x_5.5.0_y', never in '15.5.0' or '5.5.01'."""
    return re.compile(rf"(?<![\d.]){re.escape(v)}(?!\d|\.\d)")


def substitute(text: str, subs: list[tuple[str, str]]) -> str:
    """Replace each old value with its new one; versions as whole tokens, everything else literally."""
    for old, new in subs:
        if not old or old == new:
            continue
        text = ver_rx(old).sub(new, text) if VERSION.match(old) else text.replace(old, new)
    return text


def section(text: str, heading: str) -> tuple[int, int]:
    """Start and end offsets of '## heading' up to the next '## ' heading (or the end)."""
    m = re.search(rf"^## {re.escape(heading)}\n", text, re.M)
    if not m:
        raise ValueError(f"no '## {heading}' section")
    n = re.search(r"^## ", text[m.end():], re.M)
    return m.start(), (m.end() + n.start()) if n else len(text)


def edit_section(text: str, heading: str, subs: list[tuple[str, str]]) -> str:
    a, b = section(text, heading)
    return text[:a] + substitute(text[a:b], subs) + text[b:]


def edit_dockerfile(text: str, arg: str, repo_hint: str | None, subs: list[tuple[str, str]]) -> str:
    """Substitute only on `ARG <arg>_…` lines and on comment lines that name the engine's download location."""
    out = []
    for line in text.splitlines(keepends=True):
        if line.startswith(f"ARG {arg}_") or (repo_hint and line.startswith("#") and repo_hint in line):
            line = substitute(line, subs)
        out.append(line)
    return "".join(out)


def edit_readme_row(text: str, label: str, subs: list[tuple[str, str]]) -> str:
    """The engine's row in the README's 'Bundled engines' table."""
    out = []
    for line in text.splitlines(keepends=True):
        if line.startswith(f"| {label} |"):
            line = substitute(line, subs)
        out.append(line)
    return "".join(out)


def edit_scuba_pin(text: str, name: str, subs: list[tuple[str, str]]) -> str:
    """One tool's block of PINS in build_scuba_catalog.py."""
    m = re.search(rf'^    "{re.escape(name)}": \{{\n.*?^    \}},\n', text, re.M | re.S)
    if not m:
        raise ValueError(f"no PINS block for {name}")
    return text[:m.start()] + substitute(m.group(0), subs) + text[m.end():]


def edit_stig_pin(text: str, key: str, subs: list[tuple[str, str]]) -> str:
    """One profile's block of PINS in build_stig_catalog.py."""
    m = re.search(rf'^    "{re.escape(key)}": \{{.*?^\s+"tarSha256": "[0-9a-f]{{64}}"\}},\n', text, re.M | re.S)
    if not m:
        raise ValueError(f"no PINS block for {key}")
    # The pin moves to a tag read today, so its "read" date (cited in the catalogue's notes) moves too.
    block = re.sub(r'"read": "\d{4}-\d{2}-\d{2}"', f'"read": "{dt.date.today().isoformat()}"', substitute(m.group(0), subs))
    return text[:m.start()] + block + text[m.end():]


def edit_lines(text: str, marker: str, subs: list[tuple[str, str]]) -> str:
    """Substitute only on lines that contain `marker` (one STIG profile's line in a shared section or table)."""
    return "".join(substitute(l, subs) if marker in l else l for l in text.splitlines(keepends=True))


def omnitruck_versions(listing: list[str]) -> list[str]:
    """Plain X.Y.Z versions from omnitruck's versions/all, oldest first."""
    return sorted((v for v in listing if VERSION.match(v)), key=vkey)


def catalogue_diff(before: dict[str, list[str]], after: dict[str, list[str]]) -> str:
    """Check ids added and removed, per catalogue file."""
    lines = []
    for name in sorted(set(before) | set(after)):
        a, b = set(before.get(name, [])), set(after.get(name, []))
        added, removed = sorted(b - a), sorted(a - b)
        lines.append(f"{name}: {len(a)} -> {len(b)} checks (+{len(added)} -{len(removed)})")
        if removed:
            lines.append("  removed: " + ", ".join(removed[:40]) + (" …" if len(removed) > 40 else ""))
        if added:
            lines.append("  added: " + ", ".join(added[:40]) + (" …" if len(added) > 40 else ""))
    return "\n".join(lines)


def current_version(name: str, dockerfile: str, scuba_src: str) -> str:
    e = ENGINES[name]
    if e["kind"] == "scubagear":
        m = re.search(r'"scubagear": \{\n\s+"tool": "ScubaGear", "repo": "[^"]+", "tag": "[^"]+", "version": "([^"]+)"', scuba_src)
    elif e["kind"] == "stig":
        m = re.search(rf"^ARG {e['arg']}_TAG=v?(\S+)$", dockerfile, re.M)
    else:
        m = re.search(rf"^ARG {e['arg']}_VERSION=(\S+)$", dockerfile, re.M)
    if not m:
        raise ValueError(f"cannot find the pinned version of {name}")
    return m.group(1)


# ── Network ──────────────────────────────────────────────────────────────────────────────────────────

def http(url: str, accept: str = "application/vnd.github+json", api: bool = False) -> bytes:
    headers = {"User-Agent": "sagentix-engine-updates", "Accept": accept}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and api:
        headers["Authorization"] = f"Bearer {tok}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (fixed https hosts)
        return r.read()


def gh(path: str):
    return json.loads(http(f"https://api.github.com/{path}", api=True))


def tag_commit(repo: str, tag: str) -> str:
    return gh(f"repos/{repo}/commits/{tag}")["sha"]


def licence_files(repo: str, ref: str) -> dict[str, str]:
    """LICENSE (as GitHub detects it) and NOTICE at a ref; a missing file is ''."""
    out = {}
    try:
        lic = gh(f"repos/{repo}/license?ref={ref}")
        out["licence"] = base64.b64decode(lic["content"]).decode("utf-8", "replace")
    except urllib.error.HTTPError:
        out["licence"] = ""
    try:
        out["notice"] = http(f"https://raw.githubusercontent.com/{repo}/{ref}/NOTICE", accept="*/*").decode("utf-8", "replace")
    except urllib.error.HTTPError:
        out["notice"] = ""
    return out


def pypi_has(name: str, version: str) -> dict | None:
    try:
        return json.loads(http(f"https://pypi.org/pypi/{name}/{version}/json", accept="application/json"))
    except urllib.error.HTTPError:
        return None


def cinc_releases(newest: int = 5) -> list[dict]:
    """The newest Cinc Auditor versions as release-like dicts; the date is the Debian 12 package's Last-Modified."""
    out = []
    for v in omnitruck_versions(json.loads(http(f"{OMNITRUCK}/versions/all", accept="application/json")))[-newest:]:
        meta = cinc_metadata(v, "x86_64")
        req = urllib.request.Request(meta["url"], method="HEAD", headers={"User-Agent": "sagentix-engine-updates"})
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (Cinc's https package server)
            modified = r.headers.get("Last-Modified")
        when = dt.datetime.strptime(modified, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=dt.timezone.utc) if modified else None
        out.append({"tag_name": v, "published_at": when.isoformat().replace("+00:00", "Z") if when else None,
                    "draft": False, "prerelease": False, "html_url": f"https://downloads.cinc.sh/files/stable/cinc-auditor/{v}/"})
    return out


def cinc_metadata(version: str, machine: str) -> dict:
    """omnitruck's tab-separated metadata (url, sha256, …) for the Debian 12 package."""
    text = http(f"{OMNITRUCK}/metadata?p=debian&pv=12&m={machine}&v={version}", accept="text/plain").decode()
    return dict(line.split("\t", 1) for line in text.splitlines() if "\t" in line)


def tarball_sha(repo: str, tag: str) -> str:
    """SHA-256 of GitHub's tarball of a tag (MITRE publishes no checksum for its profiles)."""
    return hashlib.sha256(http(f"https://codeload.github.com/{repo}/tar.gz/refs/tags/{tag}", accept="*/*")).hexdigest()


# ── check ────────────────────────────────────────────────────────────────────────────────────────────

def check(only: str | None, min_age_override: int | None, now: dt.datetime | None = None) -> tuple[list[dict], list[str]]:
    now = now or dt.datetime.now(dt.timezone.utc)
    dockerfile, scuba_src = DOCKERFILE.read_text(), SCUBA_GEN.read_text()
    updates, notes = [], []
    for name, e in ENGINES.items():
        if only and name != only:
            continue
        cur = current_version(name, dockerfile, scuba_src)
        age = min_age_override if min_age_override is not None else e.get("min_age_days", DEFAULT_MIN_AGE_DAYS)
        releases = cinc_releases() if e["kind"] == "cinc" else gh(f"repos/{e['repo']}/releases?per_page=30")
        rel = pick_release(releases, cur, age, now)
        if rel is None:
            notes.append(f"{name}: {cur} is current (eligible: releases at least {age} days old)")
            continue
        if e.get("pypi") and pypi_has(e["pypi"], rel["version"]) is None:
            notes.append(f"{name}: {rel['tag']} is on GitHub but not yet on PyPI; waiting")
            continue
        updates.append({"name": name, "old": cur, "new": rel["version"], "tag": rel["tag"], "published": rel["published"],
                        "branch": f"engine-update/{name}-{rel['version']}"})
        notes.append(f"{name}: {cur} -> {rel['version']} (published {rel['published']})")
    return updates, notes


# ── apply ────────────────────────────────────────────────────────────────────────────────────────────

class Refused(Exception):
    """A supply-chain check failed: no PR."""


def binary_pins(e: dict, old: str, new: str) -> list[tuple[str, str]]:
    """Old -> new substitutions for a binary engine, each new SHA-256 from the published checksum file."""
    old_tag, new_tag = e["tag"].format(v=old), e["tag"].format(v=new)
    rel = gh(f"repos/{e['repo']}/releases/tags/{new_tag}")
    api_digest = {a["name"]: str(a.get("digest") or "").removeprefix("sha256:") for a in rel.get("assets", [])}
    base = f"https://github.com/{e['repo']}/releases/download/{new_tag}/"
    dockerfile = DOCKERFILE.read_text()
    subs = [(old, new), (old_tag, new_tag)]
    for arch, pattern in e["assets"].items():
        asset = pattern.format(v=new)
        cfile = e["checksums"].format(v=new, asset=asset)
        sums = parse_checksums(http(base + cfile, accept="*/*").decode())
        sha = sums.get(asset) or (sums.get("") if cfile.endswith(".sha256") else None)
        if not sha:
            raise Refused(f"{e['label']} {new}: {asset} is not in {cfile}")
        if api_digest.get(asset) and api_digest[asset] != sha:
            raise Refused(f"{e['label']} {new}: {cfile} says {sha} for {asset}, GitHub's release API says {api_digest[asset]}")
        if asset not in api_digest:
            raise Refused(f"{e['label']} {new}: the release has no asset {asset}")
        m = re.search(rf"^ARG {e['arg']}_SHA256_{arch.upper()}=([0-9a-f]{{64}})$", dockerfile, re.M)
        if not m:
            raise Refused(f"no ARG {e['arg']}_SHA256_{arch.upper()} in the Dockerfile")
        subs.append((m.group(1), sha))
    return subs


def scubagoggles_wheel(old: str, new: str, package: str = "scubagoggles", arg: str = "SCUBAGOGGLES") -> list[tuple[str, str]]:
    meta = pypi_has(package, new)
    if meta is None:
        raise Refused(f"{package} {new} is not on PyPI")
    wheels = [u for u in meta["urls"] if u["packagetype"] == "bdist_wheel" and u["filename"].endswith("-py3-none-any.whl")]
    if len(wheels) != 1:
        raise Refused(f"{package} {new}: expected one py3-none-any wheel on PyPI, found {len(wheels)}")
    dockerfile = DOCKERFILE.read_text()
    old_url = re.search(rf"^ARG {arg}_WHEEL_URL=(\S+)$", dockerfile, re.M).group(1)
    old_sha = re.search(rf"^ARG {arg}_WHEEL_SHA256=(\S+)$", dockerfile, re.M).group(1)
    return [(old_url, wheels[0]["url"]), (old_sha, wheels[0]["digests"]["sha256"])]


def regolibrary_pins(e: dict, new_tag: str) -> list[tuple[str, str]]:
    """Each regolibrary asset's new SHA-256 from checksums.txt, held against GitHub's asset digest."""
    rel = gh(f"repos/{e['repo']}/releases/tags/{new_tag}")
    api_digest = {a["name"]: str(a.get("digest") or "").removeprefix("sha256:") for a in rel.get("assets", [])}
    sums = parse_checksums(http(f"https://github.com/{e['repo']}/releases/download/{new_tag}/{e['checksums']}", accept="*/*").decode())
    dockerfile, subs = DOCKERFILE.read_text(), []
    for asset, arg in e["assets"].items():
        sha = sums.get(asset)
        if not sha or asset not in api_digest:
            raise Refused(f"regolibrary {new_tag}: {asset} is not in the release or its {e['checksums']}")
        if api_digest[asset] and api_digest[asset] != sha:
            raise Refused(f"regolibrary {new_tag}: {e['checksums']} says {sha} for {asset}, GitHub says {api_digest[asset]}")
        subs.append((re.search(rf"^ARG REGOLIBRARY_{arg}_SHA256=([0-9a-f]{{64}})$", dockerfile, re.M).group(1), sha))
    return subs


def cinc_pins(old: str, new: str) -> list[tuple[str, str]]:
    """The new Debian 12 package digests from omnitruck, for both architectures."""
    dockerfile, subs = DOCKERFILE.read_text(), [(old, new)]
    for arch, machine in CINC_ARCH.items():
        meta = cinc_metadata(new, machine)
        if meta.get("version") != new or not re.fullmatch(r"[0-9a-f]{64}", meta.get("sha256", "")):
            raise Refused(f"Cinc Auditor {new}: omnitruck has no Debian 12 {machine} package")
        subs.append((re.search(rf"^ARG CINC_AUDITOR_SHA256_{arch.upper()}=([0-9a-f]{{64}})$", dockerfile, re.M).group(1), meta["sha256"]))
    return subs


def scuba_pin_subs(name: str, new_tag: str) -> list[tuple[str, str]]:
    """New commit and mapping-CSV digest for one PINS entry of build_scuba_catalog.py."""
    spec = importlib.util.spec_from_file_location("build_scuba_catalog", SCUBA_GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pin = mod.PINS[name]
    commit = tag_commit(pin["repo"], new_tag)
    try:
        csv = http(f"https://raw.githubusercontent.com/{pin['repo']}/{commit}/{pin['csv']}", accept="*/*")
    except urllib.error.HTTPError as err:
        raise Refused(f"{name} {new_tag}: the mapping {pin['csv']} is not at that tag ({err.code}); the generator needs a person")
    return [(pin["commit"], commit), (pin["csvSha256"], hashlib.sha256(csv).hexdigest())]


def catalogue_ids(names: list[str]) -> dict[str, list[str]]:
    out = {}
    for n in names:
        f = CHECKS / n
        if f.is_file():
            out[n] = [c["id"] for c in json.loads(f.read_text())["checks"]]
    return out


def stale_mentions(label: str, old: str) -> list[str]:
    """Tracked lines that still name `label` with the old version: prose about the old release, for a person."""
    rx = ver_rx(old)
    try:
        files = subprocess.run(["git", "-C", str(ROOT), "grep", "-l", "-F", old, "--", "collector", "apps/sos-app/scripts",
                                "apps/sos-app/CLAUDE.md", ".github/workflows", ":!*package-lock.json"],
                               capture_output=True, text=True).stdout.split()
    except OSError:
        return []
    out = []
    key = label.split(" (")[0].split()[-1].lower()
    for f in files:
        for i, line in enumerate((ROOT / f).read_text(errors="replace").splitlines(), 1):
            if rx.search(line) and key in line.lower():
                out.append(f"{f}:{i}: {line.strip()[:160]}")
    return out[:40]


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


def apply(name: str, new: str, out_dir: Path) -> dict:
    e = ENGINES[name]
    vkey(new)
    dockerfile, scuba_src = DOCKERFILE.read_text(), SCUBA_GEN.read_text()
    old = current_version(name, dockerfile, scuba_src)
    if vkey(new) <= vkey(old):
        raise SystemExit(f"{name}: {new} is not newer than the pinned {old}")
    old_tag, new_tag = e["tag"].format(v=old), e["tag"].format(v=new)
    old_commit = None
    flags: list[str] = []
    changed: list[str] = []
    gen_report, refusal = "", None

    def write(path: Path, text: str) -> None:
        if path.read_text() != text:
            path.write_text(text)
            changed.append(str(path.relative_to(ROOT)))

    new_commit = tag_commit(e["repo"], new_tag)
    try:
        old_commit = tag_commit(e["repo"], old_tag)
    except urllib.error.HTTPError:
        pass
    subs = [(old, new), (old_tag, new_tag)] + ([(old_commit, new_commit)] if old_commit else [])
    if e["kind"] == "binary":
        subs = binary_pins(e, old, new) + ([(old_commit, new_commit)] if old_commit else [])
    elif e["kind"] == "scubagoggles":
        subs += scubagoggles_wheel(old, new)
        subs.append((f"pypi/scubagoggles/{old}/json", f"pypi/scubagoggles/{new}/json"))
    elif e["kind"] == "wheel":
        subs += scubagoggles_wheel(old, new, e["pypi"], e["arg"])
        subs.append((f"pypi/{e['pypi']}/{old}/json", f"pypi/{e['pypi']}/{new}/json"))
    elif e["kind"] == "regolibrary":
        subs += regolibrary_pins(e, new_tag)
    elif e["kind"] == "cinc":
        subs = cinc_pins(old, new) + [(old_tag, new_tag)] + ([(old_commit, new_commit)] if old_commit else [])
    elif e["kind"] == "stig":
        old_sha = re.search(rf"^ARG {e['arg']}_SHA256=([0-9a-f]{{64}})$", dockerfile, re.M).group(1)
        subs.append((old_sha, tarball_sha(e["repo"], new_tag)))
    if e["kind"] in ("scubagoggles", "scubagear"):
        subs += scuba_pin_subs(name, new_tag)

    # Licence and NOTICE at both tags: a change needs a person to update THIRD_PARTY_NOTICES by hand.
    try:
        a, b = licence_files(e["repo"], old_tag), licence_files(e["repo"], new_tag)
        for k in ("licence", "notice"):
            if a[k] != b[k]:
                flags.append(f"The {k.upper() if k == 'notice' else 'LICENSE'} file differs between {old_tag} and {new_tag}: "
                             "update collector/THIRD_PARTY_NOTICES.md by hand before merging.")
    except urllib.error.URLError as err:
        flags.append(f"Could not compare the licence files ({err}); check them by hand.")

    # Pins.
    if e["kind"] != "scubagear":
        hint = {"prowler": None, "binary": f"github.com/{e['repo']}/", "regolibrary": f"github.com/{e['repo']}/",
                "scubagoggles": "pypi.org/pypi/scubagoggles/", "wheel": f"pypi.org/pypi/{e.get('pypi')}/",
                "cinc": "omnitruck.cinc.sh", "stig": None}[e["kind"]]
        write(DOCKERFILE, edit_dockerfile(DOCKERFILE.read_text(), e["arg"], hint, subs))
    if e.get("notices") and e["kind"] == "stig":
        # One section holds all five profiles, which share version numbers: edit only this profile's line.
        a_, b_ = section(NOTICES.read_text(), e["notices"])
        t_ = NOTICES.read_text()
        write(NOTICES, t_[:a_] + edit_lines(t_[a_:b_], f"`{e['profile']}`", subs) + t_[b_:])
    elif e.get("notices"):
        write(NOTICES, edit_section(NOTICES.read_text(), e["notices"], subs))
    if e.get("readme"):
        write(README, edit_readme_row(README.read_text(), e["readme"], subs))
    if e["kind"] in ("scubagoggles", "scubagear"):
        write(SCUBA_GEN, edit_scuba_pin(SCUBA_GEN.read_text(), name, subs))
    if e["kind"] == "stig":
        write(STIG_GEN, edit_stig_pin(STIG_GEN.read_text(), e["profile"], subs + [(old_commit or "", new_commit)]))
        write(STIG_TS, edit_lines(STIG_TS.read_text(), f"  {e['profile']}: {{", subs))
    if e["kind"] == "regolibrary":
        write(KUBESCAPE_GEN, substitute(KUBESCAPE_GEN.read_text(), subs + [(old_commit or "", new_commit)]))
    if e["kind"] == "binary" and name == "kubescape":
        write(KUBESCAPE_GEN, edit_lines(KUBESCAPE_GEN.read_text(), "KUBESCAPE_VERSION = ", subs))
    if e["kind"] == "wheel" and name == "checkov":
        tar_old = re.search(r'"tarSha256": "([0-9a-f]{64})"', CHECKOV_GEN.read_text()).group(1)
        write(CHECKOV_GEN, substitute(CHECKOV_GEN.read_text(), subs + [(old_commit or "", new_commit), (tar_old, tarball_sha(e["repo"], new_tag))]))
    if e["kind"] == "cinc":
        write(STIG_TS, edit_lines(STIG_TS.read_text(), "export const CINC_VERSION = ", subs))
    if e["kind"] == "prowler":
        today = dt.date.today().isoformat()
        g = PROWLER_GEN.read_text()
        g = re.sub(r'^PROWLER_VERSION = "[^"]+".*$', f'PROWLER_VERSION = "{new}"  # release tag {new_tag}, pinned {today} by update_engines.py',
                   g, count=1, flags=re.M)
        g = re.sub(r'^PROWLER_COMMIT = "[0-9a-f]+"', f'PROWLER_COMMIT = "{new_commit}"', g, count=1, flags=re.M)
        write(PROWLER_GEN, g)
        write(PROWLER_TS, re.sub(r'^export const PROWLER_VERSION = "[^"]+";', f'export const PROWLER_VERSION = "{new}";',
                                 PROWLER_TS.read_text(), count=1, flags=re.M))

    # Regenerate.
    if e["kind"] == "prowler":
        rc, log = run([sys.executable, str(PROWLER_GEN)])
        gen_report = "\n".join(l for l in log.splitlines() if not l.startswith(("warning:", "fetching ")))
        if rc != 0:
            refusal = log[log.find("refusing"):] if "refusing" in log else log[-3000:]
        elif GUIDES_GEN.is_file():  # the per-control guides read the remediation files just written
            rc, log = run([sys.executable, str(GUIDES_GEN)])
            if rc != 0:
                flags.append("scripts/build_control_guides.py failed on the new remediation files:\n\n```\n" + log[-2000:] + "\n```")
    elif e["kind"] in ("scubagoggles", "scubagear"):
        before = catalogue_ids([f"{name}.json"])
        rc, log = run([sys.executable, str(SCUBA_GEN), "--only", name])
        gen_report = log.strip() + "\n" + catalogue_diff(before, catalogue_ids([f"{name}.json"]))
        if rc != 0:
            refusal = log[-3000:]
    elif e["kind"] in ("stig", "regolibrary", "wheel") or name == "kubescape":
        gen, files = {"stig": (STIG_GEN, [f"stig_{e.get('profile')}.json"]), "regolibrary": (KUBESCAPE_GEN, ["kubescape.json"]),
                      "wheel": (CHECKOV_GEN, ["checkov.json"]), "binary": (KUBESCAPE_GEN, ["kubescape.json"])}[e["kind"]]
        before = catalogue_ids(files)
        rc, log = run([sys.executable, str(gen)] + (["--only", e["profile"]] if e["kind"] == "stig" else []))
        gen_report = log.strip() + "\n" + catalogue_diff(before, catalogue_ids(files))
        if rc != 0:
            refusal = log[-3000:]
    _, status = run(["git", "status", "--porcelain", "--", "apps/sos-app/src/data"])
    changed += [l[3:] for l in status.splitlines() if l[3:] not in changed]

    stale = stale_mentions(e["label"], old)
    meta = {"name": name, "label": e["label"], "old": old, "new": new, "tag": new_tag, "commit": new_commit,
            "branch": f"engine-update/{name}-{new}", "title": f"engine update: {e['label']} {old} → {new}",
            "refused": refusal is not None, "flags": flags, "tests": e["tests"], "changed": changed}
    body = [f"{e['label']} {old} → {new} (tag `{new_tag}`, commit `{new_commit}`), found by `.github/workflows/engine-updates.yml`.",
            f"Release notes: https://github.com/{e['repo']}/releases/tag/{new_tag}", ""]
    if refusal:
        body += ["**The generator refused to write.** The pins moved but the catalogues did not, so tests that hold the "
                 "catalogues to the pinned version fail. A person reads the change before this goes anywhere:", "",
                 "```", refusal.strip()[-3000:], "```", ""]
    if flags:
        body += ["**Needs a person:**", ""] + [f"- {f}" for f in flags] + [""]
    if gen_report.strip():
        body += ["Generator report (checks added and removed per provider):", "", "```", gen_report.strip()[-6000:], "```", ""]
    body += ["Files changed: " + ", ".join(f"`{c}`" for c in changed), ""]
    if e["kind"] in ("binary", "regolibrary"):
        body += ["Each SHA-256 is from the project's checksum file for this release and matches the digest GitHub's "
                 "release API reports for the asset.", ""]
    elif e["kind"] == "cinc":
        body += ["Each SHA-256 is the one Cinc's omnitruck lists for the Debian 12 package; the build checks it.", ""]
    elif e["kind"] == "stig":
        body += ["MITRE publishes no checksum: the SHA-256 is of GitHub's tarball of the tag, fetched by this job, and the "
                 "generator rebuilt the catalogue from the same bytes. Read the profile's release notes for renamed or "
                 "removed controls.", ""]
    if stale:
        body += ["Lines that still name the old version. They describe what the old release did (counts, a missing wheel, "
                 "a date it was checked) and were not rewritten; read each against the new release:", "", "```", *stale, "```", ""]
    body += ["The collector's readers were checked against the old release's output format. Read the release notes for a "
             "change to the JSON the collector reads before merging. Merging deploys sos-app's `dev` when a file under "
             "`apps/sos-app/` changed, as any sos-app change does; this workflow never pushes to `rnd` and never deploys."]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    (out_dir / "body.md").write_text("\n".join(body) + "\n")
    return meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--only", choices=sorted(ENGINES))
    c.add_argument("--min-age-days", type=int, help="override every engine's minimum release age")
    c.add_argument("--github-output", type=Path, help="append updates=<json> to this file (GITHUB_OUTPUT)")
    p = sub.add_parser("apply")
    p.add_argument("name", choices=sorted(ENGINES))
    p.add_argument("version")
    p.add_argument("--out-dir", type=Path, default=Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "engine-update")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        updates, notes = check(a.only, a.min_age_days)
        print("\n".join(notes), file=sys.stderr)
        print(json.dumps(updates, indent=2))
        if a.github_output:
            with a.github_output.open("a") as f:
                f.write(f"updates={json.dumps(updates)}\n")
        return 0
    try:
        meta = apply(a.name, a.version, a.out_dir)
    except Refused as err:
        print(f"refused: {err}", file=sys.stderr)
        return 2
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
