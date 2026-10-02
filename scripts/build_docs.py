#!/usr/bin/env python3
"""Build the documentation site exactly as CI does.

    pip install -e ".[api,engines,docs]"
    python scripts/build_docs.py            # -> site/

Copies the committed result figures into ``docs/figures``, pre-renders the static
investigation console into ``docs/demo`` (both git-ignored build outputs) and runs
``mkdocs build --strict``.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    figs = ROOT / "docs" / "figures"
    shutil.rmtree(figs, ignore_errors=True)
    shutil.copytree(ROOT / "results" / "figures", figs)
    demo = ROOT / "docs" / "demo"
    shutil.rmtree(demo, ignore_errors=True)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_static_demo.py"), str(demo)], check=True, cwd=ROOT)
    return subprocess.run([sys.executable, "-m", "mkdocs", "build", "--strict"], cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
