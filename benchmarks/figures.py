"""Figures for the README from the committed result JSON (matplotlib, small PNGs)."""
from __future__ import annotations

import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from common import RESULTS  # noqa: E402

FIG = RESULTS / "figures"
COLORS = {"sigma": "#8c8c8c", "revenant": "#b5a27a", "max": "#6f8fa8", "fused": "#2f5d8a", "fused+cal": "#1b8a5a",
          "similarity": "#8c8c8c", "dragnet": "#b5a27a", "occam": "#6f8fa8"}
LABEL = {"sigma": "Sigma alone (ANVIL)", "revenant": "provenance alone (REVENANT)", "max": "both, unfused",
         "fused": "THROUGHLINE fused", "fused+cal": "fused + Platt (CV)", "similarity": "TTP similarity",
         "dragnet": "DRAGNET", "occam": "OCCAM"}


def otrf() -> None:
    r = json.loads((RESULTS / "otrf_core.json").read_text())
    ms = ["sigma", "revenant", "max", "fused"]
    metrics = [("recall", "technique found"), ("hit@1", "top claim correct"), ("mrr", "MRR")]
    fig, ax = plt.subplots(figsize=(7, 3.4), dpi=110)
    w = 0.2
    for i, m in enumerate(ms):
        vals = [r["methods"][m][k] for k, _ in metrics]
        ax.bar([x + (i - 1.5) * w for x in range(len(metrics))], vals, w, label=LABEL[m], color=COLORS[m])
    ax.set_xticks(range(len(metrics)), [lbl for _, lbl in metrics])
    ax.set_ylim(0, 1)
    ax.set_title(f"Emulated technique identification, {r['captures']} real OTRF captures")
    ax.legend(fontsize=7, frameon=False, ncol=2)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "otrf_methods.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.2, 4), dpi=110)
    ax.plot([0, 1], [0, 1], ls=":", color="#999")
    for m in ("sigma", "fused", "fused+cal"):
        rel = r["methods"][m]["reliability"]
        xs, ys = [b["mean_conf"] for b in rel], [b["accuracy"] for b in rel]
        ax.plot(xs, ys, lw=1, color=COLORS[m],
                label=f"{LABEL[m]} (ECE {r['methods'][m]['calibration']['ece']:.2f})")
        ax.scatter(xs, ys, s=[6 + b["n"] / 2 for b in rel], color=COLORS[m], alpha=0.8)
    ax.set_xlabel("stated confidence")
    ax.set_ylabel("fraction correct")
    ax.set_title("Reliability of technique claims (marker area ~ claims per bin)", fontsize=9)
    ax.legend(fontsize=7, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "otrf_reliability.png")
    plt.close(fig)


def attribution() -> None:
    r = json.loads((RESULTS / "attribution.json").read_text())["temporal"]
    ms = ["similarity", "dragnet", "occam", "fused"]
    settings = [("clean", "clean"), ("false_flag_l1", "false flag L1"), ("false_flag_l2", "false flag L2")]
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2), dpi=110, sharey=True)
    for ax, key, title in ((axes[0], "confident_correct", "confident and right"),
                           (axes[1], "confident_wrong", "confident and WRONG")):
        w = 0.2
        for i, m in enumerate(ms):
            vals = [r[s]["methods"][m][key] for s, _ in settings]
            ax.bar([x + (i - 1.5) * w for x in range(len(settings))], vals, w, label=LABEL[m], color=COLORS[m])
        ax.set_xticks(range(len(settings)), [lbl for _, lbl in settings], fontsize=8)
        ax.set_title(title, fontsize=10)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylim(0, 1)
    axes[0].legend(fontsize=7, frameon=False)
    fig.suptitle(f"Attribution, temporal hold-out ({r['cases']} ATT&CK campaigns, v{r['kg_version']} profiles)",
                 fontsize=10)
    fig.tight_layout()
    fig.savefig(FIG / "attribution.png")
    plt.close(fig)


if __name__ == "__main__":
    FIG.mkdir(parents=True, exist_ok=True)
    otrf()
    attribution()
    print("wrote", sorted(p.name for p in FIG.glob("*.png")))
