"""Append-only raw event store with a hash-chained custody ledger.

Raw connector records are the evidence every claim points back to
(``raw_ref``). They are written once, never rewritten:

* ``events-<n>.jsonl`` shards hold ``{"seq", "connector", "sha256", "raw"}``
  lines; ``sha256`` is the canonical hash the normalizer puts in the event.
* ``ledger.jsonl`` holds one record per append batch: the batch's first/last
  sequence numbers, a digest over the batch's hashes, and the previous ledger
  record's hash, so editing any stored event or any ledger line breaks
  :meth:`EventStore.verify`.

What the chain alone cannot prove: that nobody *appended* a well-formed batch, or cut
the tail off, since anyone with write access can extend an unkeyed chain. Two
anchors close that gap: export :attr:`EventStore.head` off-host after each append and
pass it back as ``expect_head``, and/or set ``THROUGHLINE_LEDGER_KEY`` so every ledger
record carries an HMAC that only the key holder can produce.

File-based on purpose (ADR-0002 spirit): zero infrastructure, greppable, and
the same format ships to object storage unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Iterable, Iterator
from pathlib import Path

from .contracts import canonical_hash

GENESIS = "0" * 64


class StoreError(OSError):
    """The store directory or its ledger is missing or unreadable."""


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _mac(key: bytes, record_hash: str) -> str:
    return hmac.new(key, record_hash.encode("ascii"), hashlib.sha256).hexdigest()


class EventStore:
    """Append-only JSONL shards plus a hash-chained ledger.

    Args:
        root: store directory.
        shard_size: records per ``events-<n>.jsonl`` shard.
        create: create ``root`` if it does not exist (``False`` for read-only use such as
            ``verify``; a missing directory then raises :class:`StoreError`).
        key: HMAC key for ledger records (default ``$THROUGHLINE_LEDGER_KEY``).
    """

    def __init__(self, root: str | Path, shard_size: int = 100_000, create: bool = True,
                 key: bytes | str | None = None):
        self.root = Path(root)
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        elif not self.root.is_dir():
            raise StoreError(f"no event store at {self.root}")
        self.shard_size = shard_size
        self.ledger = self.root / "ledger.jsonl"
        k = key if key is not None else os.environ.get("THROUGHLINE_LEDGER_KEY")
        self.key = k.encode("utf-8") if isinstance(k, str) else k
        self._seq = self._count()
        self._head = self._last_ledger_hash()

    def _count(self) -> int:
        n = 0
        for p in sorted(self.root.glob("events-*.jsonl")):
            with open(p, encoding="utf-8") as fh:
                n += sum(1 for line in fh if line.strip())
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

    @property
    def head(self) -> str:
        """Hash of the newest ledger record; record it off-host to detect tail changes later."""
        return self._head

    def _shard(self, seq: int) -> Path:
        return self.root / f"events-{seq // self.shard_size:05d}.jsonl"

    def append(self, records: Iterable[tuple[str, dict]], note: str = "") -> list[str]:
        """Store ``(connector, raw)`` records; return their ``raw_ref``s (``store://<seq>#<sha256>``)."""
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
            if self.key:
                body["mac"] = _mac(self.key, body["record_hash"])
            with open(self.ledger, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, sort_keys=True) + "\n")
            self._head = body["record_hash"]
        return refs

    def __len__(self) -> int:
        return self._seq

    def iter(self) -> Iterator[dict]:
        """Every stored record, shard by shard."""
        for p in sorted(self.root.glob("events-*.jsonl")):
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)

    def get(self, ref: str) -> dict:
        """The stored record a ``raw_ref`` points at; ``KeyError`` if absent or its digest differs."""
        seq_s, _, digest = ref.removeprefix("store://").partition("#")
        seq = int(seq_s)
        shard = self._shard(seq)
        if shard.exists():
            with open(shard, encoding="utf-8") as fh:
                for line in fh:
                    rec = json.loads(line)
                    if rec["seq"] == seq:
                        if digest and (rec["sha256"] != digest or canonical_hash(rec["raw"]) != digest):
                            raise KeyError(f"{ref}: stored record does not match the reference digest")
                        return rec
        raise KeyError(ref)

    def verify(self, allow_empty: bool = False, expect_head: str | None = None) -> dict:
        """Re-hash every record, replay the ledger chain and check its coverage.

        ``ok`` requires: every record's hash matches its content, every ledger record chains
        to the previous one and digests exactly its batch, the batches cover sequence numbers
        ``0..n-1`` contiguously with no duplicates and no unledgered record, HMACs verify when
        a key is configured, the head equals ``expect_head`` when given, and (unless
        ``allow_empty``) the store holds at least one record."""
        hashes: dict[int, str] = {}
        bad_records, duplicates = [], []
        for rec in self.iter():
            h = canonical_hash(rec["raw"])
            if h != rec["sha256"]:
                bad_records.append(rec["seq"])
            if rec["seq"] in hashes:
                duplicates.append(rec["seq"])
            hashes[rec["seq"]] = h
        prev, bad_ledger, n, covered, gaps, bad_mac = GENESIS, [], 0, set(), [], []
        expected_first = 0
        if not self.ledger.exists() and hashes:
            gaps.append("ledger.jsonl missing")
        if self.ledger.exists():
            with open(self.ledger, encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if not line.strip():
                        continue
                    n += 1
                    body = json.loads(line)
                    rh = body.pop("record_hash")
                    mac = body.pop("mac", None)
                    ok = body["prev"] == prev and _h(json.dumps(body, sort_keys=True)) == rh
                    digest = _h("\n".join(hashes.get(s, "") for s in range(body["first"], body["last"] + 1)))
                    if not ok or digest != body["batch_digest"]:
                        bad_ledger.append(i)
                    if self.key and (mac is None or not hmac.compare_digest(mac, _mac(self.key, rh))):
                        bad_mac.append(i)
                    if body["first"] != expected_first:
                        gaps.append(f"ledger entry {i} starts at {body['first']}, expected {expected_first}")
                    expected_first = body["last"] + 1
                    covered.update(range(body["first"], body["last"] + 1))
                    prev = rh
        unledgered = sorted(set(hashes) - covered)
        missing = sorted(covered - set(hashes))
        head_ok = expect_head is None or expect_head == prev
        rep = {"records": len(hashes), "ledger_entries": n, "head": prev, "tampered_records": bad_records,
               "broken_ledger_entries": bad_ledger, "unledgered_records": unledgered[:100],
               "missing_records": missing[:100], "duplicate_records": duplicates[:100], "ledger_gaps": gaps[:100],
               "bad_macs": bad_mac, "keyed": bool(self.key), "head_matches": head_ok}
        rep["ok"] = (not bad_records and not bad_ledger and not unledgered and not missing and not duplicates
                     and not gaps and not bad_mac and head_ok and (allow_empty or bool(hashes)))
        return rep
