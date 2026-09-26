"""OTRF Security-Datasets (Mordor) loader: labelled Windows attack captures.

Each atomic dataset has a metadata YAML (``atomic/_metadata/SDWIN-*.yaml``)
listing the emulated ATT&CK technique(s) and a zipped JSON-lines host capture
recorded while the technique ran in a lab. THROUGHLINE uses the captures as
real endpoint telemetry and the metadata as ground truth. Data only: nothing
is executed.
"""
from __future__ import annotations

import io
import json
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Capture:
    id: str
    title: str
    techniques: list[str]
    files: list[Path]
    tags: list[str] = field(default_factory=list)
    description: str = ""

    @property
    def available(self) -> bool:
        return any(p.exists() for p in self.files)

    def records(self) -> Iterator[dict[str, Any]]:
        for p in self.files:
            if p.exists():
                try:
                    yield from iter_records(p)
                except (OSError, zipfile.BadZipFile, tarfile.TarError):
                    continue  # AV-quarantined / truncated capture: skip, caller reports


def _lines(fh: io.TextIOBase) -> Iterator[dict[str, Any]]:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def iter_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """JSON-lines records from a ``.json``/``.jsonl`` file, a ``.zip`` or a ``.tar.gz``."""
    p = Path(path)
    name = p.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(p) as zf:
            for m in zf.infolist():
                if m.is_dir() or "__MACOSX" in m.filename or not m.filename.endswith((".json", ".jsonl")):
                    continue
                with zf.open(m) as raw:
                    yield from _lines(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
    elif name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(p) as tf:
            for m in tf.getmembers():
                if not m.isfile() or not m.name.endswith((".json", ".jsonl")):
                    continue
                raw = tf.extractfile(m)
                if raw is not None:
                    yield from _lines(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
    else:
        with open(p, encoding="utf-8", errors="replace") as fh:
            yield from _lines(fh)


def _techniques(meta: dict[str, Any]) -> list[str]:
    out = []
    for m in meta.get("attack_mappings") or []:
        t = str(m.get("technique") or "").strip().upper()
        if not t or t == "T0000":  # T0000 = OTRF's "unmapped" placeholder
            continue
        sub = m.get("sub-technique")
        out.append(f"{t}.{int(sub):03d}" if sub not in (None, "", "null") and str(sub).isdigit() else t)
    return sorted(set(out))


def load_catalog(root: str | Path) -> list[Capture]:
    """Atomic Windows captures under ``<root>/atomic`` (layout of scripts/download_data.py)."""
    import yaml  # core dependency, imported lazily to keep `import throughline` light

    root = Path(root)
    out: list[Capture] = []
    for f in sorted((root / "atomic" / "_metadata").glob("SDWIN-*.yaml")):
        try:
            meta = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        files = []
        for fl in meta.get("files") or []:
            if str(fl.get("type", "")).lower() != "host":
                continue
            link = str(fl.get("link", ""))
            if "/datasets/" in link:
                files.append(root / link.split("/datasets/", 1)[1])
        if files:
            out.append(Capture(str(meta.get("id", f.stem)), str(meta.get("title", "")), _techniques(meta),
                               files, [str(t) for t in meta.get("tags") or []],
                               str(meta.get("description", ""))))
    return out


APT29_DAY1 = "compound/apt29/day1/apt29_evals_day1_manual.zip"
APT29_DAY2 = "compound/apt29/day2/apt29_evals_day2_manual.zip"
