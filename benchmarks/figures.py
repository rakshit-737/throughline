"""Figures for the README and docs from the committed result JSON (matplotlib, small PNGs).

Every bar carries its 95% interval: bootstrap over captures for B1, Wilson for the
attribution rates, case-clustered bootstrap over culprit groups for the drift curve.

    python benchmarks/figures.py
"""
from __future__ import annotations

import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from common import RESULTS  # noqa: E402

FIG = RESULTS / "figures"
COLORS = {"sigma": "#8c8c8c", "revenant": "#b5a27a", "max": "#6f8fa8", "fused": "#2f5d8a", "fused+cal": "#1b8a5a",
          "similarity": "#8c8c8c", "dragnet": "#b5a27a", "occam": "#6f8fa8", "noisy_or_all": "#c07b5a",
          "per_process": "#8a6fa8", "fused_no_grade": "#5a9ac0", "rba": "#a85a6f"}
LABEL = {"sigma": "Sigma alone (ANVIL)", "revenant": "provenance alone (REVENANT)", "max": "both, unfused (max)",
         "fused": "THROUGHLINE fused", "similarity": "TTP similarity", "dragnet": "DRAGNET", "occam": "OCCAM",
         "noisy_or_all": "A2 noisy-OR, no independence", "per_process": "A3 per process, no incidents",
         "fused_no_grade": "A5 fused, no reliability grades", "rba": "A6 risk-based alerting (risk sum)"}


def _err(v: float, ci) -> tuple[float, float]:
    if not ci or ci[0] is None or ci[1] is None:
        return (0.0, 0.0)
    return (max(0.0, v - ci[0]), max(0.0, ci[1] - v))


def _bars(ax, groups: list[str], series: list[tuple[str, list[float], list]], width: float = 0.2) -> None:
    n = len(series)
    for i, (m, vals, cis) in enumerate(series):
        errs = [_err(v, c) for v, c in zip(vals, cis, strict=True)]
        xs = [x + (i - (n - 1) / 2) * width for x in range(len(groups))]
        ax.bar(xs, vals, width, label=LABEL.get(m, m), color=COLORS.get(m, "#777"),
               yerr=[[e[0] for e in errs], [e[1] for e in errs]], capsize=2, error_kw={"lw": 0.8, "ecolor": "#333"})
    ax.set_xticks(range(len(groups)), groups, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)


def otrf() -> None:
    r = json.loads((RESULTS / "otrf_core.json").read_text())
    ms = ["sigma", "revenant", "max", "fused"]
    metrics = [("recall", "recall_ci", "technique claimed"), ("hit@1", "hit@1_ci", "top claim correct"),
               ("mrr", "mrr_ci", "MRR")]
    fig, ax = plt.subplots(figsize=(7, 3.4), dpi=110)
    _bars(ax, [lbl for _, _, lbl in metrics],
          [(m, [r["methods"][m][k] for k, _, _ in metrics], [r["methods"][m][c] for _, c, _ in metrics]) for m in ms])
    ax.set_ylim(0, 1)
    ax.set_title(f"Emulated technique identification, {r['captures']} real OTRF captures (ties in expectation)",
                 fontsize=9)
    ax.legend(fontsize=7, frameon=False, ncol=2)
    fig.tight_layout()
    fig.savefig(FIG / "otrf_methods.png")
    plt.close(fig)

    # ablation: paired difference fused - each alternative, with bootstrap CIs over captures
    alts = ["sigma", "revenant", "max", "noisy_or_all", "per_process", "fused_no_grade", "rba"]
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.3), dpi=110, sharey=True)
    for ax, key, title in ((axes[0], "hit@1", "hit@1"), (axes[1], "mrr", "MRR")):
        for y, m in enumerate(alts):
            d = r["methods"][m]["fused_minus_this"][key]
            lo, hi = d["ci"]
            ax.errorbar(d["diff"], y, xerr=[[d["diff"] - lo], [hi - d["diff"]]], fmt="o", color=COLORS[m],
                        capsize=3, ms=4)
        ax.axvline(0, color="#999", lw=0.8, ls=":")
        ax.set_title(f"THROUGHLINE fused minus alternative: {title}", fontsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_yticks(range(len(alts)), [LABEL[m] for m in alts], fontsize=7)
    axes[0].invert_yaxis()
    fig.tight_layout()
    fig.savefig(FIG / "otrf_ablation.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.4, 4), dpi=110)
    ax.plot([0, 1], [0, 1], ls=":", color="#999")
    cal = r["calibration"]["methods"]
    curves = [("fused", cal["fused"]["own_claims"]["reliability_raw"], "THROUGHLINE fused, raw",
               cal["fused"]["own_claims"]["raw"]["ece"], "#b0b0b0"),
              ("sigma", cal["sigma"]["shared_universe"]["reliability"], "Sigma alone + Platt (CV)",
               cal["sigma"]["shared_universe"]["platt_cv"]["ece"], COLORS["sigma"]),
              ("fused", cal["fused"]["shared_universe"]["reliability"], "fused + Platt (CV)",
               cal["fused"]["shared_universe"]["platt_cv"]["ece"], COLORS["fused+cal"])]
    for _m, rel, lbl, ece, color in curves:
        xs, ys = [b["mean_conf"] for b in rel], [b["accuracy"] for b in rel]
        ax.plot(xs, ys, lw=1, color=color, label=f"{lbl} (ECE {ece:.2f})")
        ax.scatter(xs, ys, s=[6 + b["n"] / 4 for b in rel], color=color, alpha=0.8)
    ax.set_xlabel("stated confidence")
    ax.set_ylabel("fraction correct")
    ax.set_title(f"Reliability on one shared claim set ({r['calibration']['universe_claims']} claims)", fontsize=9)
    ax.legend(fontsize=7, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "otrf_reliability.png")
    plt.close(fig)


def attribution() -> None:
    d = json.loads((RESULTS / "attribution.json").read_text())
    r = d["temporal_all"]
    ms = ["similarity", "dragnet", "occam", "fused"]
    settings = [("clean", "clean"), ("false_flag_l1", "false flag L1"), ("false_flag_l2", "false flag L2")]
    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.3), dpi=110, sharey=True)
    for ax, key, title in ((axes[0], "confident_correct", "confident and right"),
                           (axes[1], "confident_wrong", "confident and WRONG")):
        _bars(ax, [lbl for _, lbl in settings],
              [(m, [r[s]["methods"][m][key] for s, _ in settings],
                [r[s]["methods"][m][f"{key}_wilson"] for s, _ in settings]) for m in ms])
        ax.set_title(title, fontsize=10)
    axes[0].set_ylim(0, 1)
    axes[0].legend(fontsize=7, frameon=False)
    fig.suptitle(f"Attribution, temporal hold-out: {r['cases']} cases (campaigns + new malware families), "
                 f"v{r['kg_version']} profiles; Wilson 95% CIs", fontsize=9)
    fig.tight_layout()
    fig.savefig(FIG / "attribution.png")
    plt.close(fig)

    dd = d["drift_dose"]
    doses = sorted(dd["doses"], key=float)
    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.2), dpi=110, sharey=True)
    for ax, key, title in ((axes[0], "top1", "named the right group (top-1)"),
                           (axes[1], "confident_correct", "confident and right")):
        for m in ms:
            ys = [dd["doses"][x]["methods"][m][key] for x in doses]
            cis = [dd["doses"][x]["methods"][m].get(f"{key}_ci_group_clustered") or
                   dd["doses"][x]["methods"][m][f"{key}_wilson"] for x in doses]
            xs = [float(x) for x in doses]
            ax.errorbar(xs, ys, yerr=[[y - c[0] for y, c in zip(ys, cis, strict=True)],
                                      [c[1] - y for y, c in zip(ys, cis, strict=True)]],
                        label=LABEL[m], color=COLORS[m], capsize=2, lw=1.2, marker="o", ms=3)
        ax.set_xlabel("share of evidence learned after the profile (v10.1)")
        ax.set_title(title, fontsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylim(0, 1)
    axes[0].legend(fontsize=7, frameon=False)
    fig.suptitle(f"Behaviour drift: {dd['groups']} ATT&CK groups x {len(dd['seeds'])} seeds, "
                 f"{dd['signals']} signals per case", fontsize=9)
    fig.tight_layout()
    fig.savefig(FIG / "attribution_drift.png")
    plt.close(fig)


if __name__ == "__main__":
    FIG.mkdir(parents=True, exist_ok=True)
    otrf()
    attribution()
    print("wrote", sorted(p.name for p in FIG.glob("*.png")))
