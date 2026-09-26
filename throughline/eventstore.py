"""Append-only raw event store with a hash-chained custody ledger.

Raw connector records are the evidence every claim points back to
(``raw_ref``). They are written once, never rewritten:

* ``events-<n>.jsonl`` shards hold ``{"seq", "connector", "sha256", "raw"}``
  lines; ``sha256`` is the canonical hash the normalizer puts in the event.
* ``ledger.jsonl`` holds one record per append batch: the batch's first/last
  sequence numbers, a digest over the batch's hashes, and the previous ledger
  record's hash, so editing any stored event or any ledger line breaks
  :meth:`EventStore.verify`.

File-based on purpose (ADR-0002 spirit): zero infrastructure, greppable, and
the same format ships to object storage unchanged.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from .contracts import canonical_hash

GENESIS = "0" * 64


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class EventStore:
    def __init__(self, root: str | Path, shard_size: int = 100_000):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.shard_size = shard_size
        self.ledger = self.root / "ledger.jsonl"
        self._seq = self._count()
        self._head = self._last_ledger_hash()

    def _count(self) -> int:
        n = 0
        for p in sorted(self.root.glob("events-*.jsonl")):
            with open(p, encoding="utf-8") as fh:
                n += sum(1 for _ in fh)
        return n

    def _last_ledger_hash(self) -> str:
        if not self.ledger.exists():
            return GENESIS
        last = GENESIS
        with open(self.ledger, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["record_hash"]
        return last

    def _shard(self, seq: int) -> Path:
        return self.root / f"events-{seq // self.shard_size:05d}.jsonl"

    def append(self, records: Iterable[tuple[str, dict]], note: str = "") -> list[str]:
        """Store ``(connector, raw)`` records; return their ``raw_ref``s."""
        refs, hashes = [], []
        first = self._seq
        for connector, raw in records:
            digest = canonical_hash(raw)
            line = json.dumps({"seq": self._seq, "connector": connector, "sha256": digest, "raw": raw},
                              sort_keys=True, default=str)
            with open(self._shard(self._seq), "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            refs.append(f"store://{self._seq}#{digest}")
            hashes.append(digest)
            self._seq += 1
        if hashes:
            body = {"first": first, "last": self._seq - 1, "batch_digest": _h("\n".join(hashes)),
                    "prev": self._head, "note": note[:200]}
            body["record_hash"] = _h(json.dumps(body, sort_keys=True))
            with open(self.ledger, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, sort_keys=True) + "\n")
            self._head = body["record_hash"]
        return refs

    def __len__(self) -> int:
        return self._seq

    def iter(self) -> Iterator[dict]:
        for p in sorted(self.root.glob("events-*.jsonl")):
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)

    def get(self, ref: str) -> dict:
        seq = int(ref.removeprefix("store://").split("#", 1)[0])
        with open(self._shard(seq), encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                if rec["seq"] == seq:
                    return rec
        raise KeyError(ref)

    def verify(self) -> dict:
        """Re-hash every stored record and replay the ledger chain."""
        hashes: dict[int, str] = {}
        bad_records = []
        for rec in self.iter():
            h = canonical_hash(rec["raw"])
            if h != rec["sha256"]:
                bad_records.append(rec["seq"])
            hashes[rec["seq"]] = h
        prev, bad_ledger, n = GENESIS, [], 0
        if self.ledger.exists():
            with open(self.ledger, encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if not line.strip():
                        continue
                    n += 1
                    body = json.loads(line)
                    rh = body.pop("record_hash")
                    ok = body["prev"] == prev and _h(json.dumps(body, sort_keys=True)) == rh
                    digest = _h("\n".join(hashes.get(s, "") for s in range(body["first"], body["last"] + 1)))
                    if not ok or digest != body["batch_digest"]:
                        bad_ledger.append(i)
                    prev = rh
        return {"records": len(hashes), "ledger_entries": n, "tampered_records": bad_records,
                "broken_ledger_entries": bad_ledger, "ok": not bad_records and not bad_ledger}
