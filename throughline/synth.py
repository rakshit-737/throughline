"""Synthetic-enterprise generator (data only; nothing is executed).

Produces raw connector records for a small fictional enterprise plus a
labeled supply-chain intrusion: malicious dependency -> image -> pod ->
process beacons out. Ground truth is returned for benchmarking.
All IPs are from RFC 5737 documentation ranges; nothing is contacted.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
C2_IP = "203.0.113.66"          # TEST-NET-3, documentation-only
BENIGN_IPS = ["198.51.100.10", "198.51.100.11"]  # TEST-NET-2


def _ts(minutes: int) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate(seed: int = 7, services: int = 4, false_flag: bool = False) -> dict:
    rnd = random.Random(seed)
    records: list[tuple[str, dict, str]] = []  # (connector, raw, reliability)
    truth = {"malicious_nodes": set(), "techniques": set(), "attacker": "Actor:APT-Example"}
    authors = ["alice", "bob", "carol"]

    for i in range(services):
        svc = ["checkout", "cart", "search", "auth", "billing", "inventory"][i % 6]
        sha = f"{rnd.getrandbits(40):010x}"
        img = f"registry.local/{svc}:1.{i}"
        pod = f"{svc}-{i}"
        host = f"node-{i % 2}"
        pid = 1000 + i * 10
        m = i * 3
        records += [
            ("cicd", {"kind": "commit", "author": rnd.choice(authors), "sha": sha, "ts": _ts(m)}, "A"),
            ("cicd", {"kind": "dependency_added", "sha": sha, "package": "requests==2.32.0",
                      "ts": _ts(m + 1)}, "A"),
            ("cicd", {"kind": "build", "package": "requests==2.32.0", "image": img, "ts": _ts(m + 2)}, "A"),
            ("cicd", {"kind": "deploy", "image": img, "pod": pod, "ts": _ts(m + 3)}, "A"),
            ("cicd", {"kind": "pod_process", "pod": pod, "pid_key": f"{host}/{pid}", "ts": _ts(m + 4)}, "B"),
            ("endpoint", {"kind": "network_connect", "host": host, "pid": pid,
                          "dst_ip": rnd.choice(BENIGN_IPS), "dst_port": 443, "ts": _ts(m + 5)}, "B"),
        ]

    # --- the intrusion (checkout service) ---
    evil_sha, evil_pkg = "deadbeef01", "colorama-utils==0.0.9"
    img, pod, host, pid, child = "registry.local/checkout:1.0-evil", "checkout-7", "node-0", 4242, 4243
    records += [
        ("cicd", {"kind": "commit", "author": "mallory", "sha": evil_sha, "ts": _ts(60)}, "A"),
        ("cicd", {"kind": "dependency_added", "sha": evil_sha, "package": evil_pkg,
                  "untrusted": True, "ts": _ts(61)}, "A"),
        ("cicd", {"kind": "build", "package": evil_pkg, "image": img, "ts": _ts(62)}, "A"),
        ("cicd", {"kind": "deploy", "image": img, "pod": pod, "ts": _ts(63)}, "A"),
        ("cicd", {"kind": "pod_process", "pod": pod, "pid_key": f"{host}/{pid}", "ts": _ts(64)}, "B"),
        ("endpoint", {"kind": "process_create", "host": host, "ppid": pid, "pid": child,
                      "image": "/bin/sh", "ts": _ts(65)}, "B"),
        ("endpoint", {"kind": "file_write", "host": host, "pid": child, "path": "/tmp/.x",
                      "ts": _ts(66)}, "B"),
        ("endpoint", {"kind": "network_connect", "host": host, "pid": child, "dst_ip": C2_IP,
                      "dst_port": 443, "external": True, "ts": _ts(67)}, "B"),
        ("cti", {"subject_type": "IPAddress", "subject": f"{C2_IP}:443", "object": "APT-Example",
                 "source": "feed-alpha", "ts": _ts(70)}, "B"),
        ("cti", {"subject_type": "IPAddress", "subject": f"{C2_IP}:443", "object": "APT-Example",
                 "source": "vendor-report-7", "ts": _ts(71)}, "C"),
    ]
    if false_flag:
        records.append(("cti", {"subject_type": "IPAddress", "subject": f"{C2_IP}:443", "object": "APT-Decoy",
                                "source": "paste-site", "ts": _ts(72)}, "B"))
    truth["malicious_nodes"] = {f"Commit:{evil_sha}", f"Dependency:{evil_pkg}", f"ImageLayer:{img}",
                                f"Pod:{pod}", f"Process:{host}/{pid}", f"Process:{host}/{child}",
                                "File:/tmp/.x", f"IPAddress:{C2_IP}:443"}
    truth["techniques"] = {"T1195.001", "T1059", "T1105", "T1071.001"}
    return {"records": records, "truth": truth}
