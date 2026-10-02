#!/usr/bin/env python3
"""Print the CHANGELOG section of one version (the GitHub Release body).

    python scripts/release_notes.py 1.1.0 > notes.md

Exits non-zero when CHANGELOG.md has no ``## [<version>]`` heading or the section is
empty, so a release can never be published with a placeholder body. (The release
workflow used an awk regex whose escaped ``\\[`` gawk read as a bracket expression,
which silently produced the fallback text "See CHANGELOG.md" for v1.0.0.)
"""
from __future__ import annotations

import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def section(text: str, version: str) -> str:
    """Body of the ``## [version]`` section (without its heading), stripped."""
    head = f"## [{version}]"
    out: list[str] = []
    inside = False
    for line in text.splitlines():
        if line.startswith("## ["):
            if inside:
                break
            inside = line.startswith(head) and line[len(head):len(head) + 1] in ("", " ")
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: release_notes.py <version>", file=sys.stderr)
        return 2
    version = args[0].removeprefix("v")
    body = section(CHANGELOG.read_text(encoding="utf-8"), version)
    if not body:
        print(f"CHANGELOG.md has no non-empty section '## [{version}]'", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
