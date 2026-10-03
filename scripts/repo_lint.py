#!/usr/bin/env python3
"""Repository hygiene checks run in CI and before a release.

* no tracked file is larger than 1,000,000 bytes (the size of the committed blob, so a
  Windows checkout with CRLF conversion is judged like the Linux one);
* every YAML file under ``.github`` parses (a broken workflow does not fail the push that
  breaks it);
* no tracked text file contains Unicode bidirectional control characters (U+202A-U+202E,
  U+2066-U+2069). They reorder how text is *displayed* (a filename such as
  ``<U+202E>cod.3aka3.scr`` renders as ``rcs.3aka3.doc``), so docs must show them as
  escapes, never raw.

    python scripts/repo_lint.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 1_000_000
BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
TEXT = {".md", ".py", ".yml", ".yaml", ".toml", ".html", ".js", ".css", ".txt", ".cff", ".cfg", ".json",
        ".sha256", ""}


def tracked() -> list[tuple[str, str]]:
    """(path, blob sha) of every file in the index."""
    out = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    rows = []
    for entry in out.decode("utf-8", "replace").split("\0"):
        if entry:
            meta, path = entry.split("\t", 1)
            rows.append((path, meta.split()[1]))
    return rows


def blob_sizes(shas: list[str]) -> dict[str, int]:
    out = subprocess.run(["git", "cat-file", "--batch-check=%(objectname) %(objectsize)"], cwd=ROOT,
                         input="\n".join(shas).encode(), capture_output=True, check=True).stdout
    sizes = {}
    for line in out.decode().splitlines():
        sha, size = line.split()
        sizes[sha] = int(size)
    return sizes


def yaml_problems(paths: list[str]) -> list[str]:
    """Every YAML file under .github must parse, and every workflow must have ``on`` and ``jobs``
    (an unparsable workflow does not fail a push; GitHub only shows a failed, nameless run)."""
    import yaml

    out = []
    for p in paths:
        if not p.startswith(".github/") or not p.endswith((".yml", ".yaml")):
            continue
        try:
            d = yaml.safe_load((ROOT / p).read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            out.append(f"{p}: invalid YAML ({str(e).splitlines()[0]})")
            continue
        if p.startswith(".github/workflows/") and not (isinstance(d, dict) and "jobs" in d and True in d):
            out.append(f"{p}: not a workflow (needs `on` and `jobs`)")
    return out


def main() -> int:
    files = tracked()
    sizes = blob_sizes([sha for _, sha in files])
    problems = [f"{p}: {sizes[sha]:,} bytes > {MAX_BYTES:,}" for p, sha in files if sizes.get(sha, 0) > MAX_BYTES]
    for p, _ in files:
        if Path(p).suffix.lower() not in TEXT:
            continue
        try:
            text = (ROOT / p).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            bad = sorted({f"U+{ord(c):04X}" for c in line if c in BIDI})
            if bad:
                problems.append(f"{p}:{n}: bidi control character(s) {', '.join(bad)}")
    problems += yaml_problems([p for p, _ in files])
    for msg in problems:
        print(msg)
    if problems:
        return 1
    print(f"ok: {len(files)} tracked files, none over {MAX_BYTES:,} bytes, no bidi controls, GitHub YAML parses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
