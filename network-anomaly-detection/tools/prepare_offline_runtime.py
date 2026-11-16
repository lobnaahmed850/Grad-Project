"""Prepare a Docker context from an existing trusted CPython 3.11 environment."""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def prepare(destination):
    if sys.version_info[:2] != (3, 11):
        raise ValueError("Use the tested Python 3.11 environment")
    if destination.exists():
        raise ValueError("Choose a new context directory")
    destination.mkdir(parents=True)
    base = Path(sys.base_prefix)
    shutil.copytree(base, destination / "python", symlinks=True)
    libraries = Path(sys.prefix) / "lib/python3.11/site-packages"
    shutil.copytree(libraries, destination / "packages", symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("libstdc++.so.6", "libgcc_s.so.1", "libz.so.1", "libbz2.so.1.0", "liblzma.so.5", "libuuid.so.1"):
        path = Path("/usr/lib/x86_64-linux-gnu") / name
        if path.exists():
            (destination / "libraries").mkdir(exist_ok=True)
            shutil.copy2(path.resolve(), destination / "libraries" / name)
    shutil.copytree(ROOT / "netguard", destination / "app/netguard", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(ROOT / "logic.py", destination / "app/logic.py")
    shutil.copytree(ROOT / "network-anomaly-detection/src", destination / "app/network-anomaly-detection/src",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "network-anomaly-detection/models/releases", destination / "app/network-anomaly-detection/models/releases")
    shutil.copy2(ROOT / "Dockerfile.offline", destination / "Dockerfile")
    metadata = {"python": sys.version, "base_prefix": str(base),
                "packages": subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
                if (libraries / "pip").exists() else sorted(path.name for path in libraries.glob("*.dist-info"))}
    (destination / "environment.json").write_text(json.dumps(metadata, indent=2))
    print(destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    prepare(parser.parse_args().destination)
