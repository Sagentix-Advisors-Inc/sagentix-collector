"""Raise packages in this Python environment to the floors in python-fixes.txt (collector/runner/go_fixes.py writes
it from a Trivy scan). Only packages the environment already has move, one at a time: when a raise breaks the
engine's own pins (pip check fails), that package goes back to the version it had and the line says "held", so the
image scan still reports it and a person decides (collector/runner/trivyignore.yaml). Run as `<env>/bin/python <this> <file>`.
"""
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version


def key(v):
    out = []
    for p in v.replace("-", ".").split("."):
        d = "".join(c for c in p if c.isdigit())
        out.append(int(d) if d else -1)
    return out


def pip(*args, check=True):
    return subprocess.run([sys.executable, "-m", "pip", *args], check=check, capture_output=True, text=True)


if pip("check", check=False).returncode != 0:
    sys.exit(f"{sys.executable}: pip check fails before any floor is applied")
for line in open(sys.argv[1]):
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    pkg, floor = line.split()[:2]
    try:
        have = version(pkg)
    except PackageNotFoundError:
        continue
    if key(have) >= key(floor):
        continue
    pip("install", "--no-cache-dir", "--upgrade", f"{pkg}>={floor}")
    broken = pip("check", check=False)
    if broken.returncode == 0:
        print(f"{sys.executable}: {pkg} {have} -> {version(pkg)}")
    else:
        pip("install", "--no-cache-dir", f"{pkg}=={have}")
        held = " ".join(l.split()[0] for l in broken.stdout.splitlines() if f"requires {pkg}" in l.lower() or f"requirement {pkg}" in l.lower())
        print(f"{sys.executable}: {pkg} {have} held (floor {floor}; pinned by {held or 'another package'})")
pip("check")
