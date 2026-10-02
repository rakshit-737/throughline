"""Supply-chain engines: TRACEGATE (git manifest lineage) and STRATUM (code-to-runtime).

TRACEGATE walks the first-parent history of a pinned dependency manifest in
a real git repository and says which commit introduced which pinned version.
THROUGHLINE records that as

    Author AUTHORED Commit    and    Commit INTRODUCED Dependency:<name>==<version>

(observed, reliability A: it is read from the repository itself), and, when
OSV results are supplied, ``Vulnerability AFFECTS Dependency``. Root cause of
a vulnerable pin is then an ordinary graph walk:
Vulnerability -> Dependency <- Commit <- Author.

STRATUM models the Kubernetes lifecycle (commit -> build -> image -> workload
-> pod -> runtime) and raises Zero-Trust findings and runtime incidents;
:func:`stratum_claims` maps its analysis onto the same graph vocabulary.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require


def _iso(ts: int | float) -> str:
    return datetime.fromtimestamp(float(ts), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def lineage_claims(kg: KnowledgeGraph, history, repo: str = "", source: str = "tracegate") -> list[Claim]:
    """Claims from TRACEGATE ``ManifestCommit`` objects (duck-typed: sha, author, timestamp,
    subject, added, removed)."""
    out: list[Claim] = []
    for mc in history:
        ts = _iso(mc.timestamp)
        sha = mc.sha[:12]
        out.append(kg.add_claim("Author", mc.author, "AUTHORED", "Commit", sha, source=source,
                                method="observed", reliability="A", timestamp=ts))
        kg.set_attrs(f"Commit:{sha}", {"subject": mc.subject[:200], "repo": repo, "pr": getattr(mc, "pr", None) or ""})
        for name, ver in sorted(mc.added.items()):
            out.append(kg.add_claim("Commit", sha, "INTRODUCED", "Dependency", f"{name}=={ver}", source=source,
                                    method="observed", reliability="A", timestamp=ts))
            kg.set_attrs(f"Dependency:{name}=={ver}", {"package": name, "version": ver, "ecosystem": "pypi"})
        for name, ver in sorted(mc.removed.items()):
            kg.set_attrs(f"Dependency:{name}=={ver}", {"removed_by": sha})
    return out


def osv_claims(kg: KnowledgeGraph, results: dict[str, list[str]], ts: str, source: str = "osv") -> list[Claim]:
    """``results`` maps ``name==version`` to OSV advisory ids (e.g. from TRACEGATE's OsvApiClient)."""
    out = []
    for dep, vulns in sorted(results.items()):
        for v in vulns:
            out.append(kg.add_claim("Vulnerability", v, "AFFECTS", "Dependency", dep, source=source,
                                    method="stated", reliability="B", timestamp=ts))
    return out


class TracegateSupplyChainEngine:
    name = "supply-chain:tracegate"
    project = "TRACEGATE"
    reads = ("git",)
    writes = ("AUTHORED", "INTRODUCED", "AFFECTS")

    def __init__(self, repo: str | Path, manifest: str = "requirements.txt", osv_cache: str | Path | None = None,
                 online: bool = False, limit: int | None = None, osv_zip: str | Path | None = None):
        self.repo, self.manifest, self.limit = Path(repo), manifest, limit
        self.osv_cache = Path(osv_cache) if osv_cache else None
        self.osv_zip = Path(osv_zip) if osv_zip else None
        self.online = online
        self.history: list = []
        self.severity: dict[str, str] = {}

    def osv(self, deps: list[str]) -> dict[str, list[str]]:
        """Advisory ids per ``name==version``: from an offline OSV dump (preferred), else the
        cache / online API."""
        if self.osv_zip and self.osv_zip.exists():
            from tracegate.osv import OsvIndex
            idx = OsvIndex.from_zip(self.osv_zip, "pypi")
            out: dict[str, list[str]] = {}
            for d in deps:
                name, ver = d.split("==", 1)
                vs = idx.vulns(name, ver)
                if vs:
                    out[d] = [v.id for v in vs]
                    for v in vs:
                        self.severity[v.id] = v.severity or "UNKNOWN"
            return out
        cache: dict[str, list[str]] = {}
        if self.osv_cache and self.osv_cache.exists():
            cache = json.loads(self.osv_cache.read_text(encoding="utf-8"))
        todo = [d for d in deps if d not in cache]
        if todo and self.online:
            from tracegate.osv import OsvApiClient
            client = OsvApiClient()
            for i in range(0, len(todo), 500):
                chunk = todo[i:i + 500]
                res = client.query([(d.split("==")[0], d.split("==")[1], "pypi") for d in chunk])
                cache.update(dict(zip(chunk, res)))
            if self.osv_cache:
                self.osv_cache.parent.mkdir(parents=True, exist_ok=True)
                self.osv_cache.write_text(json.dumps(cache, indent=0, sort_keys=True), encoding="utf-8")
        return {d: cache[d] for d in deps if cache.get(d)}

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        require("TRACEGATE")
        from tracegate.gitlineage import manifest_history

        self.history = manifest_history(self.repo, self.manifest, limit=self.limit)
        out = lineage_claims(kg, self.history, repo=self.repo.name)
        deps = sorted({f"{n}=={v}" for mc in self.history for n, v in mc.added.items()})
        if self.history:
            out += osv_claims(kg, self.osv(deps), _iso(self.history[-1].timestamp))
            for vid, sev in self.severity.items():
                kg.set_attrs(f"Vulnerability:{vid}", {"severity": sev})
        return out


# ------------------------------------------------------------------ STRATUM
_STRATUM_TYPES = {"commit": "Commit", "build": "Build", "image": "ImageLayer", "base_image": "ImageLayer",
                  "workload": "CloudResource", "pod": "Pod", "namespace": "NetworkSegment",
                  "service_account": "ServiceAccount", "netpol": "Policy"}
_STRATUM_EDGES = {"builds": "BUILT_INTO", "produces": "BUILT_INTO", "base_of": "BUILT_INTO",
                  "deploys": "DEPLOYED_AS", "deploys_sidecar": "DEPLOYED_AS", "runs": "RUNS",
                  "identity_of": "USES", "guards": "MITIGATES", "contains": "RUNS"}


def _snode(nid: str, attrs: dict) -> tuple[str, str] | None:
    kind, _, rest = nid.partition(":")
    t = _STRATUM_TYPES.get(attrs.get("type", kind))
    return (t, rest[:120] if kind != "commit" else rest[:12]) if t else None


def stratum_claims(kg: KnowledgeGraph, analysis, ts: str = "1970-01-01T00:00:00Z",
                   source: str = "stratum") -> list[Claim]:
    """Map a STRATUM ``incident.Analysis`` (lifecycle graph, findings, incidents) into claims."""
    g = analysis.graph
    out: list[Claim] = []
    for src, edges in g.out.items():
        s = _snode(src, g.nodes.get(src, {}))
        if not s:
            continue
        for dst, rel in edges:
            d = _snode(dst, g.nodes.get(dst, {}))
            pred = _STRATUM_EDGES.get(rel)
            if not d or not pred:
                continue
            if pred == "USES":  # identity_of: service account -> workload; store as workload USES SA
                s2, d2 = d, s
            else:
                s2, d2 = s, d
            out.append(kg.add_claim(s2[0], s2[1], pred, d2[0], d2[1], source=source, method="observed",
                                    reliability="A", timestamp=ts))
    for nid, attrs in g.nodes.items():
        if attrs.get("type") == "commit" and attrs.get("author"):
            out.append(kg.add_claim("Author", str(attrs["author"]), "AUTHORED", "Commit", nid.split(":", 1)[1][:12],
                                    source=source, method="observed", reliability="A", timestamp=ts))
    for f in analysis.findings:
        n = _snode(f.subject, g.nodes.get(f.subject, {}))
        if n:
            key = f"{n[0]}:{n[1]}"
            if key in kg.g:
                prev = kg.g.nodes[key]["attrs"].get("failed_controls", "")
                kg.set_attrs(key, {"failed_controls": ",".join(x for x in (prev, f.control_id) if x)[:500]})
    for inc in analysis.incidents:
        members = [c for c in inc.chain] + ([inc.workload] if inc.workload else [])
        for m in dict.fromkeys(members):
            n = _snode(m, g.nodes.get(m, {}))
            if n:
                out.append(kg.add_claim(n[0], n[1], "PART_OF", "Incident", f"stratum-{inc.id}", source=source,
                                        method="inferred", reliability="B", timestamp=ts))
        kg.set_attrs(f"Incident:stratum-{inc.id}", {
            "engine": "STRATUM", "commit": inc.root_commit or "", "author": inc.author or "",
            "failed_controls": ",".join(f.control_id for f in inc.failed_controls)[:500],
            "recommendations": " | ".join(inc.recommendations)[:1000],
            "blast_radius": ",".join(inc.blast_radius)[:1000]})
    return out


class StratumEngine:
    name = "cnapp:stratum"
    project = "STRATUM"
    reads = ("k8s",)
    writes = ("BUILT_INTO", "DEPLOYED_AS", "RUNS", "PART_OF")

    def __init__(self, dataset=None, seed: int = 7):
        self.dataset, self.seed = dataset, seed
        self.analysis = None

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        require("STRATUM")
        from stratum.incident import analyze
        from stratum.synth import generate

        ds = self.dataset or context.get("stratum_dataset") or generate(seed=self.seed)
        self.analysis = analyze(ds)
        return stratum_claims(kg, self.analysis)
