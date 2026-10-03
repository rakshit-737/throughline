#!/usr/bin/env python3
"""Check (and optionally update) the sibling-engine pins against their newest releases.

Run it immediately before tagging a THROUGHLINE release; the release workflow runs it
again as its first job.

    python scripts/check_sibling_tags.py                # exit 1 if any pin is stale or a tag moved
    python scripts/check_sibling_tags.py --write        # move stale pins to the newest release
    python scripts/check_sibling_tags.py --json out.json

For each of the 13 siblings it

* lists the repository's tags with ``git ls-remote`` (no API quota) and checks that the
  pinned tag still points at the commit recorded in ``throughline.engines.SIBLINGS``
  (a moved tag is an error, never silently accepted);
* finds the newest *published* release (not draft, not pre-release) with one GraphQL
  call through ``gh`` when it is available (falls back to the newest ``vX.Y.Z`` tag);
* reads that release's ``pyproject.toml`` from raw.githubusercontent.com, so a renamed
  distribution or a higher ``requires-python`` is caught before ``pip install`` breaks.

``--write`` rewrites the ``engines``/``network`` extras in ``pyproject.toml`` and the
matching ``SIBLINGS`` rows (dist, tag, commit). Re-run the engines CI job afterwards.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from throughline.engines import REPO_NAMES, SIBLINGS, Sibling  # noqa: E402

OWNER = "rakshit-737"
SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
PYPROJECT = ROOT / "pyproject.toml"
REGISTRY = ROOT / "throughline" / "engines" / "__init__.py"


def semver(tag: str) -> tuple[int, int, int] | None:
    m = SEMVER.match(tag)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def remote_tags(repo: str) -> dict[str, str]:
    """``vX.Y.Z`` -> peeled commit SHA, from ``git ls-remote --tags``."""
    out = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{OWNER}/{repo}"],
                         capture_output=True, text=True, timeout=120, check=True).stdout
    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in out.splitlines():
        sha, ref = line.split("\t", 1)
        name = ref.removeprefix("refs/tags/")
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            direct[name] = sha
    return {t: peeled.get(t, sha) for t, sha in direct.items() if semver(t)}


def published_releases(repos: list[str]) -> dict[str, list[str]] | None:
    """repo -> tags of its published (non-draft, non-pre-release) releases; one GraphQL call.
    ``None`` when ``gh`` is unavailable or unauthenticated."""
    if not shutil.which("gh"):
        return None
    fields = "\n".join(
        f'r{i}: repository(owner:"{OWNER}", name:"{r}") {{ name releases(first:20, '
        'orderBy:{field:CREATED_AT, direction:DESC}) { nodes { tagName isDraft isPrerelease } } }'
        for i, r in enumerate(repos))
    try:
        out = subprocess.run(["gh", "api", "graphql", "-f", f"query=query {{ {fields} }}"],
                             capture_output=True, text=True, timeout=120, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    data = json.loads(out)["data"]
    return {v["name"]: [n["tagName"] for n in v["releases"]["nodes"] if not n["isDraft"] and not n["isPrerelease"]]
            for v in data.values() if v}


def release_metadata(repo: str, tag: str) -> dict:
    """Distribution name and requires-python declared in a release's pyproject.toml."""
    url = f"https://raw.githubusercontent.com/{OWNER}/{repo}/{tag}/pyproject.toml"
    req = urllib.request.Request(url, headers={"User-Agent": "throughline-pin-check"})
    with urllib.request.urlopen(req, timeout=60) as r:
        proj = tomllib.loads(r.read().decode("utf-8")).get("project", {})
    return {"dist": proj.get("name"), "requires_python": proj.get("requires-python")}


def check(siblings: tuple[Sibling, ...] = SIBLINGS) -> list[dict]:
    repos = [s.repo_name for s in siblings]
    releases = published_releases(repos)
    rows = []
    for s in siblings:
        repo = s.repo_name
        tags = remote_tags(repo)
        cands = releases.get(repo, []) if releases is not None else list(tags)
        cands = [t for t in cands if semver(t) and t in tags]
        newest = max(cands, key=semver) if cands else None
        row = {"project": s.project, "pinned": s.tag, "pinned_sha": s.sha, "dist": s.dist, "newest": newest,
               "source": "releases" if releases is not None else "tags", "problems": []}
        if s.tag not in tags:
            row["problems"].append(f"pinned tag {s.tag} no longer exists")
        elif tags[s.tag] != s.sha:
            row["problems"].append(f"tag {s.tag} moved: {s.sha[:7]} -> {tags[s.tag][:7]}")
        if newest and semver(newest) > semver(s.tag):
            meta = release_metadata(repo, newest)
            row.update(newest_sha=tags[newest], newest_dist=meta["dist"],
                       newest_requires_python=meta["requires_python"])
            row["problems"].append(f"newer release {newest} (dist {meta['dist']}, "
                                   f"requires-python {meta['requires_python']})")
        rows.append(row)
    return rows


def write(rows: list[dict]) -> list[str]:
    """Move every stale pin to its newest release in pyproject.toml and SIBLINGS."""
    py, reg = PYPROJECT.read_text(encoding="utf-8"), REGISTRY.read_text(encoding="utf-8")
    changed = []
    for r in rows:
        if not r.get("newest_sha"):
            continue
        repo, dist, tag, sha = REPO_NAMES[r["project"]], r["newest_dist"], r["newest"], r["newest_sha"]
        py, n1 = re.subn(rf'"[A-Za-z0-9_.\-]+ @ git\+https://github\.com/{OWNER}/{repo}@v[0-9.]+"',
                         f'"{dist} @ git+https://github.com/{OWNER}/{repo}@{tag}"', py)
        reg, n2 = re.subn(rf'(Sibling\("{r["project"]}",\s*"[^"]*",\s*"[^"]*",\s*)"[^"]*",\s*"v[0-9.]+",\s*'
                          r'"[0-9a-f]{40}"', rf'\1"{dist}", "{tag}", "{sha}"', reg)
        if n1 != 1 or n2 != 1:
            raise SystemExit(f"could not rewrite the pin for {r['project']} (pyproject {n1}, registry {n2})")
        changed.append(f"{r['project']} {r['pinned']} -> {tag} ({dist} @ {sha[:7]})")
    if changed:
        PYPROJECT.write_text(py, encoding="utf-8")
        REGISTRY.write_text(reg, encoding="utf-8")
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="move stale pins to the newest release")
    ap.add_argument("--json", default=None, help="also write the report as JSON")
    a = ap.parse_args(argv)
    try:
        rows = check()
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        print(f"cannot reach the sibling repositories: {e}", file=sys.stderr)
        return 2
    for r in rows:
        state = "; ".join(r["problems"]) or "ok"
        print(f"{r['project']:10} pinned {r['pinned']:7} newest {r['newest'] or '-':7} [{r['source']}] {state}")
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    moved = [r for r in rows if any("moved" in p or "no longer exists" in p for p in r["problems"])]
    if moved:
        print("pinned tags were moved or deleted: investigate before releasing", file=sys.stderr)
        return 1
    stale = [r for r in rows if r.get("newest_sha")]
    if stale and a.write:
        for line in write(stale):
            print("updated", line)
        print("pins updated: re-run the engines CI job before tagging")
        return 0
    if stale:
        print(f"{len(stale)} sibling pin(s) are behind their newest release: run with --write, "
              "then re-run the engines job", file=sys.stderr)
        return 1
    print("all sibling pins are at their newest published release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
