#!/usr/bin/env python3
"""Turn a Trivy JSON scan of the runner image into the module floors and Python floors the next build applies.

    trivy image --format json --scanners vuln --severity MEDIUM,HIGH,CRITICAL --ignore-unfixed -o scan.json <image>
    collector/runner/go_fixes.py scan.json            rewrite go-module-fixes.txt and python-fixes.txt in place
    collector/runner/go_fixes.py scan.json --check    exit 1 if either file would change (the weekly job's test)

Run by .github/workflows/engine-updates.yml (weekly job `module-fixes`), and by hand after a failed image scan.

Go: each finding in a binary built from source (/usr/local/bin/<name>, Trivy type gobinary) whose package is a module,
not `stdlib`, becomes one line `<name> <module> <version>`: the smallest fixed version Trivy names that is newer than
the one installed, raised to the largest such version when several advisories hit the same module. Lines already in
the file stay (build_go_engine.sh skips a line the release has caught up with); a line only ever moves up. A `stdlib`
finding is the Go toolchain's: it is reported and left to the `go` engine in update_engines.py.

Python: the same for packages in the image's Python environments, one line `<package> <version>`, applied by the
Dockerfile to each environment that has the package (pip check must still pass).

Anything Trivy calls fixed that a floor cannot reach (a module whose fix needs a major version, a build that breaks)
goes in trivyignore.yaml by hand, with a statement and an expiry no more than 30 days out.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GO_FIXES = HERE / "go-module-fixes.txt"
PY_FIXES = HERE / "python-fixes.txt"
GO_HEADER = """# Go module floors for the engines built from source (collector/runner/build_go_engine.sh).
# <binary> <module> <minimum version> [advisories]. Written by go_fixes.py from a Trivy scan; a line only moves up.
# A line whose last word is companion-of-<module> was added by hand: that module's floor breaks the build without it.
"""
PY_HEADER = """# Python package floors for the runner image's environments (collector/runner/Dockerfile).
# <package> <minimum version> [advisories]. Written by go_fixes.py from a Trivy scan; a line only moves up.
"""


def vkey(v: str) -> tuple:
    """Order Go (v1.2.3, v28.5.2+incompatible, v0.0.0-2024...) and Python (1.2.3, 2.0.0rc1) versions."""
    v = v.strip().lstrip("v").split("+")[0]
    out = []
    for part in re.split(r"[.\-]", v):
        m = re.match(r"(\d+)(.*)", part)
        out.append((int(m.group(1)), m.group(2)) if m else (-1, part))
    return tuple(out)


def smallest_fix(installed: str, fixed: str) -> str | None:
    """Trivy writes `1.2.4, 1.3.1` when several lines carry a fix: the smallest one newer than what is installed."""
    cands = [f.strip() for f in fixed.split(",") if f.strip()]
    newer = sorted((c for c in cands if vkey(c) > vkey(installed)), key=vkey)
    return newer[0] if newer else None


def read(path: Path, width: int) -> dict[tuple, tuple[str, set[str]]]:
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split()
            key, ver, ids = tuple(parts[:width]), parts[width], set(parts[width + 1:])
            out[key] = (ver, ids)
    return out


def raise_floor(table: dict, key: tuple, ver: str, vid: str) -> None:
    cur = table.get(key)
    if cur is None or vkey(ver) > vkey(cur[0]):
        table[key] = (ver, ({vid} | (cur[1] if cur and vkey(ver) == vkey(cur[0]) else set())))
    elif vkey(ver) == vkey(cur[0]):
        cur[1].add(vid)


def plan(scan: dict, go: dict, py: dict) -> list[str]:
    notes = []
    for res in scan.get("Results") or []:
        target, typ = res.get("Target", ""), res.get("Type", "")
        for v in res.get("Vulnerabilities") or []:
            fix = smallest_fix(v.get("InstalledVersion", ""), v.get("FixedVersion", ""))
            if not fix:
                continue
            pkg, vid = v["PkgName"], v["VulnerabilityID"]
            if typ == "gobinary":
                name = Path(target).name
                if pkg == "stdlib":
                    notes.append(f"{name}: stdlib {v['InstalledVersion']} -> {fix} ({vid}) is the Go toolchain's")
                    continue
                raise_floor(go, (name, pkg), "v" + fix.lstrip("v"), vid)
            elif typ == "python-pkg":
                raise_floor(py, (pkg.lower(),), fix, vid)
    return notes


def render(header: str, table: dict) -> str:
    rows = [" ".join([*k, v, *sorted(ids)]) for k, (v, ids) in sorted(table.items())]
    return header + "\n".join(rows) + ("\n" if rows else "")


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 2
    scan = json.loads(Path(argv[0]).read_text())
    go, py = read(GO_FIXES, 2), read(PY_FIXES, 1)
    for n in plan(scan, go, py):
        print(n, file=sys.stderr)
    new_go, new_py = render(GO_HEADER, go), render(PY_HEADER, py)
    changed = [p.name for p, t in ((GO_FIXES, new_go), (PY_FIXES, new_py)) if not p.exists() or p.read_text() != t]
    if "--check" in argv:
        if changed:
            print("would change: " + ", ".join(changed), file=sys.stderr)
        return 1 if changed else 0
    GO_FIXES.write_text(new_go)
    PY_FIXES.write_text(new_py)
    print("changed: " + (", ".join(changed) or "nothing"), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
