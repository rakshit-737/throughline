#!/usr/bin/env python3
"""Download the public datasets THROUGHLINE's demo and benchmarks run on.

Every source is pinned (git commit or release tag) and every file is checked
against ``scripts/checksums.sha256``; a file without a pinned checksum is an
error (fail closed). OTRF files are additionally checked against the git blob
id that the pinned OTRF commit's tree lists for them, so a newly added capture
is verified before its sha256 is recorded. The rolling OSV feed is the only
unpinned source (its date and digest are recorded instead). Nothing here is
executable content: the sources are YAML rules, JSON/EVTX *log records*, ATT&CK
STIX bundles and an emulation-plan YAML.

    python scripts/download_data.py all              # ~310 MB download (everything but `baseline`)
    python scripts/download_data.py attack otrf      # just some sources
    python scripts/download_data.py all --record     # (maintainers) pin checksums of new files

Data goes to $THROUGHLINE_DATA (default: ../../datasets/throughline next to the
repo checkout if that folder exists, else ./data inside the checkout - git-ignored
either way; set THROUGHLINE_DATA to keep it outside).

Sources and licences
--------------------
attack    MITRE ATT&CK Enterprise STIX 2.1 v19.2 + v10.1     ATT&CK Terms of Use (royalty-free)
sigma     SigmaHQ/sigma rules @ pinned commit                Detection Rule License 1.1
otrf      OTRF Security-Datasets (Mordor) Windows host logs  MIT
          (96 atomic captures + compound: APT29 evals day 1/2,
          APT3 Empire + CALDERA round 1, LSASS campaigns 01-07)
baseline  NextronSystems/evtx-baseline win10-client (benign)  public (repository README); optional,
          not part of `all` (the loop's false-positive gate uses unrelated OTRF captures)
apt29plan CTID adversary emulation plan for APT29 (YAML)     Apache-2.0
          (per-step ATT&CK techniques: ground truth for the APT29 evaluation captures)
cis       CIS Controls v8 -> ATT&CK v8.2 master mapping (xlsx)  CC BY-NC-ND 4.0 (CIS Controls licence)
misp      MISP galaxy threat-actor cluster (sponsor country)  CC0-1.0 / BSD-2-Clause
osv       OSV.dev PyPI advisory dump (rolling; date + sha256 recorded in osv/MANIFEST.json)  CC-BY 4.0
repos     healthchecks/healthchecks git history @ pinned commit (supply-chain demo)  BSD-3-Clause
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import functools
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKSUMS = ROOT / "scripts" / "checksums.sha256"

ATTACK_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
ATTACK_VERSIONS = ("19.2", "10.1")      # current + temporal hold-out knowledge base
SIGMA_COMMIT = "07ec293a51695cb1131a2e05260247872b31e1e1"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
BASELINE_TAG = "v0.8.5"
BASELINE_ASSETS = ["win10-client.tgz"]
OTRF_COMPOUND = [
    "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
    "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip",
    # 1.1.0: further multi-host / multi-stage compound captures (host logs only, no pcaps)
    "datasets/compound/windows/apt3/empire_apt3.tar.gz",
    "datasets/compound/windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz",
    *[f"datasets/compound/LSASS_campaign_0{i}/metasploit_{n}_lsass_memory_dump.zip" for i, n in enumerate(
        ("logonpasswords", "procdump", "comsvcs", "out-minidump", "sharpdump", "outflank-dumpert", "nanodump"), 1)],
    *[f"datasets/compound/_metadata/LSASS_campaign_0{i}.yaml" for i in range(1, 8)],
]
UA = {"User-Agent": "throughline-downloader"}


def data_dir() -> Path:
    env = os.environ.get("THROUGHLINE_DATA")
    if env:
        return Path(env).resolve()
    sibling = ROOT.parents[1] / "datasets" / "throughline"
    return sibling.resolve() if sibling.parent.exists() else (ROOT / "data").resolve()


def load_checksums() -> dict[str, str]:
    out: dict[str, str] = {}
    if CHECKSUMS.exists():
        for line in CHECKSUMS.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                digest, name = line.split(maxsplit=1)
                out[name.strip()] = digest
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ShortRead(OSError):
    """The server closed the connection before the advertised length arrived."""


def _expected_total(r, have: int) -> int | None:
    cr = r.headers.get("Content-Range")  # "bytes 100-199/2000"
    if r.status == 206 and cr and "/" in cr and not cr.endswith("/*"):
        return int(cr.rsplit("/", 1)[1])
    cl = r.headers.get("Content-Length")
    return int(cl) if cl and r.status == 200 else (have + int(cl) if cl else None)


def _request(url: str, headers: dict) -> urllib.request.Request:
    """A request whose Authorization header is *not* copied onto redirects (urllib forwards
    ordinary headers to whatever host a redirect points at)."""
    plain = {k: v for k, v in headers.items() if k.lower() != "authorization"}
    req = urllib.request.Request(url, headers=plain)
    for k, v in headers.items():
        if k.lower() == "authorization":
            req.add_unredirected_header(k, v)
    return req


def _download(url: str, dest: Path, attempts: int = 8, headers: dict | None = None) -> None:
    """Stream ``url`` to ``dest`` via a ``.part`` file, resuming with HTTP Range on retry.

    Connection resets on large GitHub downloads can end a response early without an
    exception, so the received size is checked against Content-Length/Content-Range.
    """
    print(f"  GET {url}", flush=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, attempts + 1):
        have = tmp.stat().st_size if tmp.exists() else 0
        hdrs = {**UA, **(headers or {})}
        if have:
            hdrs["Range"] = f"bytes={have}-"
        try:
            req = _request(url, hdrs)
            with urllib.request.urlopen(req, timeout=120) as r:
                resume = bool(have) and r.status == 206
                total = _expected_total(r, have if resume else 0)
                with open(tmp, "ab" if resume else "wb") as fh:
                    shutil.copyfileobj(r, fh, 1 << 20)
            size = tmp.stat().st_size
            if total is not None and size < total:
                raise ShortRead(f"short read {size}/{total}")
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 416 and tmp.exists():  # already complete
                break
            if attempt == attempts or exc.code in (401, 403, 404):
                raise
            print(f"  retry {attempt}/{attempts} ({dest.name}) after {exc}", flush=True)
            time.sleep(2 * attempt)
        except OSError as exc:
            if attempt == attempts:
                raise
            print(f"  retry {attempt}/{attempts} ({dest.name}) after {exc}", flush=True)
            time.sleep(2 * attempt)
    tmp.replace(dest)


def gh_raw(repo: str, commit: str, path: str) -> list[tuple[str, dict]]:
    """Candidate URLs for one file of a GitHub repo at a pinned commit.

    raw.githubusercontent.com first; the authenticated contents API (raw media
    type, files up to 100 MB) as a fallback for networks that reset raw.* hosts.
    """
    out: list[tuple[str, dict]] = [(f"https://raw.githubusercontent.com/{repo}/{commit}/{path}", {})]
    tok = _github_token()
    api_headers = {"Accept": "application/vnd.github.raw"}
    if tok:
        api_headers["Authorization"] = f"Bearer {tok}"
    out.append((f"https://api.github.com/repos/{repo}/contents/{path}?ref={commit}", api_headers))
    return out


USE_GH_CLI = False  # --use-gh-token: fall back to `gh auth token` (a broad CLI token) when no env token


@functools.lru_cache(maxsize=1)
def _github_token() -> str | None:
    """GITHUB_TOKEN / GH_TOKEN (a read-only token is enough); ``gh auth token`` only when asked."""
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok or not USE_GH_CLI:
        return tok or None
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def git_blob_sha(path: Path) -> str:
    """Git's object id of a file's content (sha1 over ``blob <size>\\0`` + content)."""
    h = hashlib.sha1(f"blob {path.stat().st_size}\0".encode())
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Unverified(SystemExit):
    """A downloaded file has no pinned checksum (and no pinned git blob id) to check it against."""


class Fetcher:
    def __init__(self, record: bool, force: bool, allow_unpinned: bool = False):
        self.record, self.force, self.allow_unpinned = record, force, allow_unpinned
        self.sums = load_checksums()
        self.dirty = False
        self.blocked_hosts: set[str] = set()
        self.unpinned: list[str] = []

    def _fetch(self, url, dest: Path) -> None:
        candidates = [(url, {})] if isinstance(url, str) else url
        candidates = [c for c in candidates if c[0].split("/")[2] not in self.blocked_hosts] or candidates[-1:]
        for i, (u, h) in enumerate(candidates):
            try:
                _download(u, dest, attempts=3 if i < len(candidates) - 1 else 8, headers=h)
                return
            except OSError:
                if i == len(candidates) - 1:
                    raise
                host = u.split("/")[2]
                self.blocked_hosts.add(host)  # don't pay the retry cost again for every file
                print(f"  falling back from {host} for the rest of this run", flush=True)

    def get(self, url: str | list[tuple[str, dict]], dest: Path, key: str, blob: str | None = None) -> Path:
        """Download ``url`` to ``dest`` unless present, then verify it: against the pinned sha256
        for ``key`` if there is one, else against ``blob`` (the git blob id a pinned commit's tree
        lists for it). A file with neither is refused unless ``--record`` (pin it now) or
        ``--allow-unpinned`` was given."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        if self.force or not dest.exists():
            self._fetch(url, dest)
        digest = sha256(dest)
        expected = self.sums.get(key)
        if expected is not None and expected != digest:
            print(f"  checksum mismatch for {key}; re-downloading once", flush=True)
            dest.unlink()
            self._fetch(url, dest)
            digest = sha256(dest)
            if expected != digest:
                raise SystemExit(f"checksum mismatch for {key}: expected {expected}, got {digest}")
        if expected is None:
            if blob is not None:
                got = git_blob_sha(dest)
                if got != blob:
                    dest.unlink()
                    raise SystemExit(f"git blob mismatch for {key}: pinned tree says {blob}, got {got}")
            if self.record:
                self.sums[key] = digest
                self.dirty = True
                print(f"  pinned {key} ({digest[:12]}...)" + (" after git-blob check" if blob else ""), flush=True)
            elif blob is not None:
                self.unpinned.append(key)  # verified against the pinned tree; sha256 not recorded yet
            elif self.allow_unpinned:
                print(f"  WARN no pinned checksum for {key} ({digest[:12]}...)", flush=True)
                self.unpinned.append(key)
            else:
                raise Unverified(f"no pinned checksum for {key}: run with --record to pin it (maintainers) "
                                 "or --allow-unpinned to accept it unverified")
        return dest

    def save(self) -> None:
        if self.dirty:
            self.sums = {**load_checksums(), **self.sums}
            lines = ["# sha256  source-key  (generated by scripts/download_data.py --record)"]
            lines += [f"{v}  {k}" for k, v in sorted(self.sums.items())]
            CHECKSUMS.write_text("\n".join(lines) + "\n")
            print(f"recorded {len(self.sums)} checksums in {CHECKSUMS.relative_to(ROOT)}")


def fetch_attack(f: Fetcher, d: Path) -> None:
    for v in ATTACK_VERSIONS:
        name = f"enterprise-attack-{v}.json"
        print(f"[attack] ATT&CK Enterprise STIX v{v}")
        f.get(gh_raw("mitre-attack/attack-stix-data", ATTACK_COMMIT, f"enterprise-attack/{name}"),
              d / "attack" / name, name)


def fetch_sigma(f: Fetcher, d: Path) -> None:
    print("[sigma] SigmaHQ rules @", SIGMA_COMMIT[:10])
    z = f.get(f"https://codeload.github.com/SigmaHQ/sigma/zip/{SIGMA_COMMIT}",
              d / "raw" / f"sigma-{SIGMA_COMMIT[:10]}.zip", f"sigma-{SIGMA_COMMIT}.zip")
    out = d / "sigma"
    if not (out / "rules").exists():
        prefix = f"sigma-{SIGMA_COMMIT}/"
        keep = ("rules/", "rules-threat-hunting/", "rules-emerging-threats/", "LICENSE")
        base = out.resolve()
        with zipfile.ZipFile(z) as zf:
            for m in zf.infolist():
                if m.is_dir() or not m.filename.startswith(prefix):
                    continue
                rel = m.filename[len(prefix):]
                if not rel.startswith(keep):
                    continue
                target = out / rel
                if not target.resolve().is_relative_to(base):  # "rules/../../x": never write outside
                    print(f"  SKIP {m.filename}: outside the extraction directory")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(m))
    print(f"  -> {out}")


def _otrf_tree() -> list[dict]:
    url = f"https://api.github.com/repos/OTRF/Security-Datasets/git/trees/{OTRF_COMMIT}?recursive=1"
    headers = dict(UA)
    if tok := _github_token():
        headers["Authorization"] = f"Bearer {tok}"
    with urllib.request.urlopen(_request(url, headers), timeout=120) as r:
        return json.load(r)["tree"]


def fetch_otrf(f: Fetcher, d: Path) -> None:
    print("[otrf] Security-Datasets (Mordor) Windows host datasets @", OTRF_COMMIT[:10])
    tree = _otrf_tree()
    blobs = {i["path"]: i["sha"] for i in tree if i["type"] == "blob" and (
        (i["path"].startswith("datasets/atomic/windows/") and "/host/" in i["path"]
         and i["path"].endswith((".zip", ".tar.gz")))
        or i["path"].startswith("datasets/atomic/_metadata/SDWIN")
        or i["path"] in OTRF_COMPOUND)}
    missing = sorted(set(OTRF_COMPOUND) - set(blobs))
    if missing:
        raise SystemExit(f"not in the OTRF tree at {OTRF_COMMIT[:10]}: {missing}")
    wanted = sorted(blobs)
    blocked = []
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(f.get, gh_raw("OTRF/Security-Datasets", OTRF_COMMIT, p),
                            d / "otrf" / p.removeprefix("datasets/"), "otrf/" + p, blobs[p]): p
                for p in wanted}
        for fut in cf.as_completed(futs):
            try:
                fut.result()
            except OSError as exc:
                # Endpoint AV sometimes quarantines attack *logs* (they contain tool names
                # and command lines). The file is data, not malware; skip and report.
                blocked.append((futs[fut], str(exc)))
    for p, err in blocked:
        print(f"  SKIP {p}: unreadable ({err[:80]}) - likely blocked by local antivirus")
    print(f"  -> {len(wanted)} files under {d / 'otrf'}")


def fetch_baseline(f: Fetcher, d: Path) -> None:
    print("[baseline] evtx-baseline clean Windows install", BASELINE_TAG)
    base = f"https://github.com/NextronSystems/evtx-baseline/releases/download/{BASELINE_TAG}/"
    for asset in BASELINE_ASSETS:
        tgz = f.get(base + asset, d / "raw" / f"evtx-baseline-{asset}",
                    f"evtx-baseline/{BASELINE_TAG}/{asset}")
        out = d / "evtx-baseline" / asset.removesuffix(".tgz")
        if not out.exists():
            out.mkdir(parents=True)
            with tarfile.open(tgz) as tf:
                for m in tf.getmembers():
                    if not (m.isfile() and m.name.lower().endswith(".evtx")):
                        continue
                    src = tf.extractfile(m)
                    if src is not None:
                        (out / Path(m.name).name).write_bytes(src.read())
        print(f"  -> {out}")


CIS_URL = "https://learn.cisecurity.org/CIS-Controls-v8-Master-Mapping-to-MITRE-Enterprise-Attck-v8.2"
CIS_FILE = "cis_v8_attack_v82_master_mapping.xlsx"


def fetch_cis(f: Fetcher, d: Path) -> None:
    print("[cis] CIS Controls v8 -> ATT&CK master mapping")
    f.get(CIS_URL, d / "cis" / CIS_FILE, CIS_FILE)


MISP_COMMIT = "e9e867fe5a5e94be813540af9e227ac84c8d60ad"


def fetch_misp(f: Fetcher, d: Path) -> None:
    print("[misp] MISP galaxy threat-actor cluster @", MISP_COMMIT[:10])
    f.get(gh_raw("MISP/misp-galaxy", MISP_COMMIT, "clusters/threat-actor.json"),
          d / "misp" / "misp-threat-actor.json", "misp-threat-actor.json")


OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
REPOS = {"healthchecks": ("https://github.com/healthchecks/healthchecks", "3731fc452b0ddca253e48d8ff7968b12539df125")}


def fetch_osv(f: Fetcher, d: Path) -> None:
    """Rolling feed: not pinned; the download date and digest are recorded instead."""
    print("[osv] OSV.dev PyPI advisories (rolling snapshot)")
    dest = d / "osv" / "PyPI-all.zip"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if f.force or not dest.exists():
        _download(OSV_URL, dest)
    manifest = {"source": OSV_URL, "downloaded": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(dest.stat().st_mtime)),
                "sha256": sha256(dest), "bytes": dest.stat().st_size}
    (d / "osv" / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    print(f"  -> {dest} ({manifest['downloaded']})")


def fetch_repos(f: Fetcher, d: Path) -> None:
    for name, (url, commit) in REPOS.items():
        print(f"[repos] {name} @ {commit[:10]}")
        dest = d / "repos" / name
        if not (dest / ".git").exists():
            subprocess.run(["git", "clone", "-q", "--filter=blob:none", url, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", commit], check=True)
        print(f"  -> {dest}")


CTID_REPO = "center-for-threat-informed-defense/adversary_emulation_library"
CTID_COMMIT = "4467a6eed6e67d25009704130e1d27d1a8007f57"
APT29_PLAN = "apt29/Emulation_Plan/yaml/APT29.yaml"


def fetch_apt29plan(f: Fetcher, d: Path) -> None:
    """The CTID APT29 emulation plan: 79 procedures with step ids and ATT&CK technique ids, the
    ground truth the APT29 evaluation benchmark scores against (never vendored)."""
    print("[apt29plan] CTID adversary emulation plan APT29 @", CTID_COMMIT[:10])
    f.get(gh_raw(CTID_REPO, CTID_COMMIT, APT29_PLAN), d / "apt29plan" / "APT29.yaml", "apt29plan/APT29.yaml")


SOURCES = {"attack": fetch_attack, "sigma": fetch_sigma, "otrf": fetch_otrf, "apt29plan": fetch_apt29plan,
           "baseline": fetch_baseline, "cis": fetch_cis, "misp": fetch_misp, "osv": fetch_osv,
           "repos": fetch_repos}


def main(argv: list[str] | None = None) -> int:
    global USE_GH_CLI
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="+", choices=[*SOURCES, "all"])
    ap.add_argument("--record", action="store_true",
                    help="pin checksums of files not yet in the manifest (never overrides a pinned one)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="accept files that have no pinned checksum (warns instead of failing)")
    ap.add_argument("--use-gh-token", action="store_true",
                    help="use `gh auth token` for GitHub API fallbacks when GITHUB_TOKEN/GH_TOKEN is unset")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    a = ap.parse_args(argv)
    USE_GH_CLI = a.use_gh_token
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    f = Fetcher(a.record, a.force, a.allow_unpinned)
    failed: dict[str, str] = {}
    names = [n for n in SOURCES if n != "baseline"] if "all" in a.sources else a.sources
    try:
        for n in names:
            try:
                SOURCES[n](f, d)
            except (OSError, subprocess.CalledProcessError) as exc:  # keep going: one blocked host must not cost the other sources
                failed[n] = str(exc)[:200]
                print(f"  FAILED {n}: {failed[n]}", flush=True)
    finally:
        f.save()
    if f.unpinned:
        print(f"note: {len(f.unpinned)} file(s) verified against the pinned git tree only (no sha256 pinned yet; "
              "maintainers: --record)")
    print(f"done. THROUGHLINE_DATA={d}" + (f"; failed: {sorted(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
