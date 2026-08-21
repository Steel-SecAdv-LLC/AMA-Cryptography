#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Generate the multi-panel performance dashboard for AMA Cryptography.

Outputs:
  assets/performance_dashboard.png  - 12-panel performance overview (3x4)
  assets/defense_layers.png         - 4-layer defense-in-depth diagram

Merged on 2026-07-29
--------------------
This module used to emit a second image, `assets/benchmark_report.png`,
and the two overlapped on most of what they showed. Panel for panel:

  * Crypto Operations Throughput (one log axis, every operation) covered
    what the report split across "Top 8 Operations", "Baseline Operations
    (Lowest Throughput)" and "Performance by Category" — a single axis
    ranks them without cutting the list in half.
  * Signature Latency with +/- sigma error bars covered the report's
    "Sign vs Verify Latency" scatter, and carries variance the scatter
    could not.
  * "Regression: Measured vs Baseline" plots both values; the report's
    "Regression Improvement (%)" plotted only the derived percentage,
    which cannot be checked against a floor.
  * The report's "Operation Latency Distribution" was a histogram of
    roughly sixteen samples, which is not a distribution.

Three report panels were genuinely unique and are now merged in here:
**Performance by Category** (an aggregate altitude the per-operation
panel cannot show), **Ethical Integration Overhead**, and **NIST FIPS
Standard Compliance**. The grid went 3x3 -> 3x4 to hold them, all twelve
cells filled — an empty cell was one of the defects fixed earlier in this
branch and is not being reintroduced.

Restoring a second image means restoring the generator function AND
adding the document reference that justifies a reader needing both.
"""

import json
import os
import platform
import re
from pathlib import Path
from typing import Any, NamedTuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# ── Paths ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
ASSETS_DIR = ROOT / "assets"
ASSETS_DIR.mkdir(exist_ok=True)
BENCH_FILE = ROOT / "benchmark_results.json"
REGRESSION_FILE = ROOT / "benchmarks" / "regression_results.json"
VALIDATION_FILE = ROOT / "benchmarks" / "validation_results.json"
COMPARATIVE_FILE = ROOT / "benchmarks" / "comparative_benchmark_results.json"


# ── Host / package facts, derived rather than hardcoded ────────────────
# These were literals ("v3.0.0", "v2.0", "Python: 3.11.14",
# "Linux x86_64, 4 cores"), so every regenerated image asserted the version
# and host of whoever last edited this file. A dashboard that misstates the
# version it describes is worse than one with no version on it.
def _read_package_version() -> str:
    """The version declared by the package, or a hard failure.

    Not `.group(1)` on an unchecked `re.search`: if the declaration ever moves,
    that spelling raises `AttributeError: 'NoneType' object has no attribute
    'group'` at import time, which reads as a broken tool rather than as the
    one thing that actually went wrong.
    """
    source = (ROOT / "ama_cryptography" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', source)
    if match is None:
        raise RuntimeError(
            "ama_cryptography/__init__.py declares no __version__; refusing to "
            "label a dashboard with a version that was not read from the package"
        )
    return match.group(1)


_PKG_VERSION = _read_package_version()
_PY_VERSION = platform.python_version()
_PLATFORM = f"{platform.system()} {platform.machine()}, {os.cpu_count()} cores"


# ── Load benchmark data ────────────────────────────────────────────────
def load_json(path: Path) -> Any:
    with open(path) as f:
        return json.load(f)


def load_json_safe(path: Path, default: Any = None) -> Any:
    """Load JSON file, returning default if the file does not exist."""
    if not path.exists():
        return default
    with open(path) as f:
        return json.load(f)


bench = load_json(BENCH_FILE)
regression = load_json_safe(REGRESSION_FILE)
validation = load_json_safe(VALIDATION_FILE)
comparative = load_json_safe(COMPARATIVE_FILE)

# No synthetic fallbacks for the measurement artefacts, deliberately.
#
# `benchmarks/regression_results.json`, `benchmarks/validation_results.json`
# and `benchmarks/comparative_benchmark_results.json` are all gitignored
# transients. This module used to substitute hardcoded literals whenever one
# was missing -- which, on a clean checkout, was always. The consequences were
# not cosmetic:
#
#   * The regression fallback carried an `_baseline_ops` dict of floors that
#     no longer matched `benchmarks/baseline.json`, so the "Measured vs
#     Baseline" panel drew a margin against a floor the gate does not use.
#   * The validation fallback set `documented_value == measured_value` on
#     every claim, so "Claimed vs Measured Latency" rendered a flawless
#     diagonal *by construction*. A validation chart that cannot show a
#     discrepancy is not validating anything.
#   * The comparative fallback supplied stale AMA-only rows under a panel
#     titled as a cross-library comparison, and lacked the `implementation`
#     field the real runner emits.
#
# Each panel now renders an instruction to produce its artefact instead. A
# missing measurement is a legible gap; a fabricated one is a false claim.
#
# Produce all three with:
#     python benchmarks/benchmark_runner.py --output benchmarks/regression_results.json
#     python benchmarks/validation_suite.py
#     python benchmarks/comparative_benchmark.py

# ── Dark theme setup ───────────────────────────────────────────────────
DARK_BG = "#1a1a2e"
PANEL_BG = "#16213e"
TEXT_COLOR = "#e0e0e0"
GRID_COLOR = "#2a2a4a"
ACCENT_COLORS = [
    "#00d2ff",
    "#7b2ff7",
    "#ff6b6b",
    "#ffd93d",
    "#6bcb77",
    "#4d96ff",
    "#ff922b",
    "#845ef7",
]

plt.rcParams.update(
    {
        "figure.facecolor": DARK_BG,
        "axes.facecolor": PANEL_BG,
        "axes.edgecolor": GRID_COLOR,
        "axes.labelcolor": TEXT_COLOR,
        "axes.grid": True,
        "grid.color": GRID_COLOR,
        "grid.alpha": 0.4,
        "text.color": TEXT_COLOR,
        "xtick.color": TEXT_COLOR,
        "ytick.color": TEXT_COLOR,
        "font.family": "DejaVu Sans",
        "font.size": 9,
    }
)


# Display names for the two panels that read artefact keys directly.
#
# Both used to derive their labels mechanically -- the regression panel via
# `name.replace("_", "\n")`, the validation panel via `name.split("_")[0]`.
# The first turns `ama_sha3_256_hash` into a four-line tower that collides
# with its neighbour at fontsize 6; the second maps `ed25519_sign` and
# `ed25519_verify` both to "ed25519", so two distinct points carried the same
# label. Explicit names, with a mechanical fallback for keys added later.
SHORT_BENCH = {
    "ama_sha3_256_hash": "SHA3-256",
    "hmac_sha3_256": "HMAC-SHA3",
    "ed25519_keygen": "Ed25519\nkeygen",
    "ed25519_sign": "Ed25519\nsign",
    "ed25519_verify": "Ed25519\nverify",
    "hkdf_derive": "HKDF",
    "full_package_create": "package\ncreate",
    "full_package_verify": "package\nverify",
}

SHORT_CLAIM = {
    "master_secret_gen": "master secret",
    "hkdf_derivation": "HKDF",
    "ed25519_keygen": "Ed25519 keygen",
    "dilithium_keygen": "ML-DSA keygen",
    "sha3_256_hash": "SHA3-256",
    "hmac_sha3_auth": "HMAC-SHA3",
    "ed25519_sign": "Ed25519 sign",
    "ed25519_verify": "Ed25519 verify",
}


def _wrap_key(name: str, limit: int = 11) -> str:
    """Fallback label: split an unmapped snake_case key over at most 2 lines."""
    head, sep, tail = name.partition("_")
    if not sep or len(name) <= limit:
        return name
    return f"{head}\n{tail}"


def _summary_line(artefact: Any) -> str:
    """`passed/total passed`, or `not run` when the artefact is absent.

    Never `0/0 passed` and never a fabricated tally: an unrun suite and a suite
    that passed everything must not read the same on the summary panel.
    """
    if artefact is None:
        return "not run"
    s = artefact["summary"]
    return f"{s['passed']}/{s['total']} passed"


def missing_artefact(ax: Any, title: str, produce_cmd: str) -> None:
    """Render a panel whose measurement artefact is absent.

    The alternative -- substituting plausible literals -- is what this module
    used to do, and it turned three panels into assertions no measurement
    backed.  Naming the command that produces the data keeps the gap legible
    and actionable in the image itself.
    """
    ax.axis("off")
    ax.text(
        0.5,
        0.5,
        f"{title.split(' (')[0]} unavailable\n\nRun:  {produce_cmd}",
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=8.5,
        color=TEXT_COLOR,
    )
    ax.set_title(title, fontsize=10, fontweight="bold", pad=8)


# ═══════════════════════════════════════════════════════════════════════
#  DASHBOARD 1: Performance Dashboard
# ═══════════════════════════════════════════════════════════════════════
def create_performance_dashboard() -> None:
    # 3 rows x 4 columns = 12 cells, all filled. Was 3x3 across two separate
    # images (performance_dashboard + benchmark_report) whose panels overlapped
    # on throughput, signature latency and regression; see the merge note in
    # the module docstring.
    fig, axes = plt.subplots(3, 4, figsize=(24, 13))
    fig.suptitle(
        f"AMA Cryptography v{_PKG_VERSION} \u2014 Performance Dashboard",
        fontsize=18,
        fontweight="bold",
        color="#ffffff",
        y=0.98,
    )

    # ── Panel 1: Crypto Throughput (top-left) ──────────────────────────
    ax = axes[0, 0]
    ops = bench["cryptographic_operations"]
    names = [
        "SHA3-256",
        "HMAC Auth",
        "HMAC Verify",
        "Ed25519\nSign",
        "Ed25519\nVerify",
        "ML-DSA-65\nSign",
        "ML-DSA-65\nVerify",
    ]
    vals = [
        ops["sha3_256"]["ops_per_sec"],
        ops["hmac_auth"]["ops_per_sec"],
        ops["hmac_verify"]["ops_per_sec"],
        ops["ed25519_sign"]["ops_per_sec"],
        ops["ed25519_verify"]["ops_per_sec"],
        ops["dilithium_sign"]["ops_per_sec"],
        ops["dilithium_verify"]["ops_per_sec"],
    ]
    colors = ["#00d2ff", "#00d2ff", "#00d2ff", "#7b2ff7", "#7b2ff7", "#ff6b6b", "#ff6b6b"]
    bars = ax.bar(names, vals, color=colors, edgecolor="none", width=0.7)
    ax.set_yscale("log")
    ax.set_title("Crypto Operations Throughput", fontsize=10, fontweight="bold", pad=8)
    ax.set_ylabel("ops/sec (log)")
    ax.tick_params(axis="x", labelsize=7, rotation=0)
    for bar, v in zip(bars, vals):
        label = f"{v:,.0f}" if v < 10000 else f"{v/1000:.0f}K"
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.3,
            label,
            ha="center",
            va="bottom",
            fontsize=6.5,
            color=TEXT_COLOR,
        )

    # ── Panel 2: Signature Latency (top-center) ───────────────────────
    ax = axes[0, 2]
    sig_names = ["Ed25519\nSign", "Ed25519\nVerify", "ML-DSA-65\nSign", "ML-DSA-65\nVerify"]
    sig_means = [
        ops["ed25519_sign"]["mean_ms"],
        ops["ed25519_verify"]["mean_ms"],
        ops["dilithium_sign"]["mean_ms"],
        ops["dilithium_verify"]["mean_ms"],
    ]
    sig_stds = [
        ops["ed25519_sign"]["std_dev_ms"],
        ops["ed25519_verify"]["std_dev_ms"],
        ops["dilithium_sign"]["std_dev_ms"],
        ops["dilithium_verify"]["std_dev_ms"],
    ]
    sig_colors = ["#7b2ff7", "#845ef7", "#ff6b6b", "#ff922b"]
    bars = ax.bar(
        sig_names,
        sig_means,
        yerr=sig_stds,
        color=sig_colors,
        edgecolor="none",
        capsize=3,
        error_kw={"ecolor": "#888", "linewidth": 1},
    )
    ax.set_title("Signature Latency (\u00b1\u03c3)", fontsize=10, fontweight="bold", pad=8)
    ax.set_ylabel("Latency (ms)")
    ax.tick_params(axis="x", labelsize=7.5)
    for bar, v in zip(bars, sig_means):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(sig_stds) * 1.2,
            f"{v:.3f}",
            ha="center",
            va="bottom",
            fontsize=7,
            color=TEXT_COLOR,
        )

    # ── Panel 3: Scalability (top-right) ──────────────────────────────
    ax = axes[0, 3]
    scale = bench["scalability"]
    scale_x = [1, 10, 100, 1000]
    scale_y = [scale[f"dna_size_{s}"]["mean_ms"] for s in scale_x]
    scale_ops = [scale[f"dna_size_{s}"]["ops_per_sec"] for s in scale_x]
    ax.plot(
        scale_x,
        scale_y,
        "o-",
        color="#ffd93d",
        linewidth=2,
        markersize=7,
        markerfacecolor="#ffd93d",
        markeredgecolor="#fff",
        markeredgewidth=1,
    )
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_title("Package Scalability", fontsize=10, fontweight="bold", pad=8)
    ax.set_xlabel("Input Scale (codes)")
    ax.set_ylabel("Latency (ms, log)")
    for x, y, o in zip(scale_x, scale_y, scale_ops):
        ax.annotate(
            f"{y:.1f}ms\n({o:,.0f} ops/s)",
            (x, y),
            textcoords="offset points",
            xytext=(12, -5),
            fontsize=6.5,
            color="#ffd93d",
        )

    # ── Panel 4: Key Generation (mid-left) ────────────────────────────
    ax = axes[1, 0]
    keygen = bench["key_generation"]
    kg_names = [
        "Master\nSecret",
        "HKDF\nDerivation",
        "Ed25519\nKeygen",
        "ML-DSA-65\nKeygen",
        "Full KMS\nGeneration",
    ]
    kg_vals = [
        keygen["master_secret"]["ops_per_sec"],
        keygen["hkdf_derivation"]["ops_per_sec"],
        keygen["ed25519_keygen"]["ops_per_sec"],
        keygen["dilithium_keygen"]["ops_per_sec"],
        keygen["kms_generation"]["ops_per_sec"],
    ]
    kg_colors = ["#6bcb77", "#6bcb77", "#4d96ff", "#ff6b6b", "#ffd93d"]
    bars = ax.barh(kg_names, kg_vals, color=kg_colors, edgecolor="none", height=0.6)
    ax.set_xscale("log")
    ax.set_title("Key Generation Speed", fontsize=10, fontweight="bold", pad=8)
    ax.set_xlabel("ops/sec (log)")
    ax.tick_params(axis="y", labelsize=7.5)
    for bar, v in zip(bars, kg_vals):
        label = f"{v:,.0f}" if v < 10000 else f"{v/1000:.0f}K"
        ax.text(
            bar.get_width() * 1.15,
            bar.get_y() + bar.get_height() / 2,
            label,
            va="center",
            fontsize=7,
            color=TEXT_COLOR,
        )

    # ── Panel 5: 4-Layer Breakdown (mid-center) ───────────────────────
    ax = axes[1, 1]
    layer_names = ["SHA3-256 Hash", "HMAC-SHA3", "Ed25519 Sign", "ML-DSA-65 Sign", "HKDF Derive"]
    layer_ms = [
        ops["sha3_256"]["mean_ms"],
        ops["hmac_auth"]["mean_ms"],
        ops["ed25519_sign"]["mean_ms"],
        ops["dilithium_sign"]["mean_ms"],
        keygen["hkdf_derivation"]["mean_ms"],
    ]
    # A horizontal bar on a log axis, not a pie. One layer takes ~95% of the
    # time, so as a pie the other four collapse into slivers whose leader
    # labels land on top of each other — which is exactly what this panel used
    # to render. Bars keep every layer readable and let the share be stated as
    # a number instead of estimated from an angle.
    layer_colors = ["#00d2ff", "#4d96ff", "#7b2ff7", "#ff6b6b", "#6bcb77"]
    total_ms = sum(layer_ms)
    order = sorted(range(len(layer_ms)), key=lambda i: layer_ms[i])
    o_names = [layer_names[i] for i in order]
    o_ms = [layer_ms[i] for i in order]
    o_colors = [layer_colors[i] for i in order]
    bars = ax.barh(o_names, o_ms, color=o_colors, edgecolor="none", height=0.62)
    ax.set_xscale("log")
    ax.set_xlabel("Mean time per operation (ms, log)", fontsize=8)
    ax.set_xlim(min(o_ms) * 0.5, max(o_ms) * 6.0)
    ax.tick_params(axis="y", labelsize=7.5)
    ax.tick_params(axis="x", labelsize=7)
    for bar, val in zip(bars, o_ms):
        ax.text(
            bar.get_width() * 1.12,
            bar.get_y() + bar.get_height() / 2,
            f"{val:.3f} ms  ({val / total_ms * 100:.1f}%)",
            va="center",
            fontsize=6.8,
            color=TEXT_COLOR,
        )
    ax.set_title("4-Layer Package Time Breakdown", fontsize=10, fontweight="bold", pad=8)

    # ── Panel 6: Regression vs Baseline (mid-right) ───────────────────
    ax = axes[1, 2]
    if regression is None:
        missing_artefact(
            ax,
            "Regression: Measured vs Baseline",
            "python benchmarks/benchmark_runner.py\n         --output benchmarks/regression_results.json",
        )
    else:
        reg = regression["results"]
        reg_names = [SHORT_BENCH.get(r["name"], _wrap_key(r["name"])) for r in reg[:8]]
        reg_actual = [r["ops_per_second"] for r in reg[:8]]
        reg_base = [r["baseline_value"] for r in reg[:8]]
        x_pos = np.arange(len(reg_names))
        w = 0.35
        ax.barh(x_pos - w / 2, reg_base, w, color="#555555", label="Baseline", edgecolor="none")
        ax.barh(x_pos + w / 2, reg_actual, w, color="#6bcb77", label="Measured", edgecolor="none")
        ax.set_yticks(x_pos)
        ax.set_yticklabels(reg_names, fontsize=6.5)
        ax.set_xscale("log")
        ax.set_title("Regression: Measured vs Baseline", fontsize=10, fontweight="bold", pad=8)
        ax.set_xlabel("ops/sec (log)")
        ax.legend(
            fontsize=7,
            loc="lower right",
            facecolor=PANEL_BG,
            edgecolor=GRID_COLOR,
            labelcolor=TEXT_COLOR,
        )

    # ── Panel 7: Validation Claims (bottom-left) ─────────────────────
    ax = axes[1, 3]
    if validation is None:
        missing_artefact(ax, "Claimed vs Measured Latency", "python benchmarks/validation_suite.py")
    else:
        # Log-log, not linear. The claims span three decades (0.005 ms for
        # master-secret generation to 0.85 ms for ML-DSA-65 keygen), so on a
        # linear axis seven of the eight points collapse into the origin and
        # only the slowest is legible. In log space the ratio each point sits
        # at relative to its claim -- which is the quantity being validated --
        # is a constant vertical distance regardless of absolute latency.
        val_results = validation["results"][:8]
        val_claimed = [r["documented_value"] for r in val_results]
        val_measured = [r["measured_value"] for r in val_results]
        lo = min(min(val_claimed), min(val_measured)) * 0.45
        hi = max(max(val_claimed), max(val_measured)) * 2.2
        # Everything under the diagonal met its documented claim; shade it so
        # the pass condition is readable without decoding the axes.
        ax.fill_between([lo, hi], [lo, hi], lo, color="#6bcb77", alpha=0.12, zorder=0)
        ax.plot(
            [lo, hi],
            [lo, hi],
            "--",
            color="#ff6b6b",
            alpha=0.6,
            linewidth=1,
            label="Claimed = Measured",
            zorder=1,
        )
        ax.scatter(
            val_claimed,
            val_measured,
            c="#00d2ff",
            s=55,
            zorder=5,
            edgecolors="#ffffff",
            linewidths=0.5,
        )
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlim(lo, hi)
        ax.set_ylim(lo, hi)
        ax.set_title("Claimed vs Measured Latency", fontsize=10, fontweight="bold", pad=8)
        ax.set_xlabel("Documented (ms, log)")
        ax.set_ylabel("Measured (ms, log)")
        ax.legend(
            fontsize=6.5,
            loc="upper left",
            facecolor=PANEL_BG,
            edgecolor=GRID_COLOR,
            labelcolor=TEXT_COLOR,
        )
        # Place labels in four alternating slots, cycling by *rank along the
        # x axis* rather than by list position. Neighbouring points are the
        # ones that collide, and a fixed offset stacks the three Ed25519
        # claims -- which sit within a factor of two of each other -- into an
        # unreadable pile.
        slots = ((6, 7, "left"), (-6, -11, "right"), (6, -11, "left"), (-6, 7, "right"))
        by_x = sorted(range(len(val_results)), key=lambda i: val_claimed[i])
        for rank, i in enumerate(by_x):
            dx, dy, ha = slots[rank % len(slots)]
            ax.annotate(
                SHORT_CLAIM.get(val_results[i]["claim_name"], val_results[i]["claim_name"]),
                (val_claimed[i], val_measured[i]),
                textcoords="offset points",
                xytext=(dx, dy),
                ha=ha,
                fontsize=5.8,
                color="#aaaaaa",
            )

    # ── Panel 8: Hybrid Performance (bottom-center) ──────────────────
    ax = axes[2, 0]
    # Cross-library Ed25519, the one family AMA / libsodium / OpenSSL all expose.
    #
    # This panel previously plotted *every* available row of
    # comparative_benchmark_results.json under the title "Hybrid Crypto
    # Performance". That was survivable while the file held six rows; once the
    # comparative runner grew an AES-GCM size sweep it emitted thirty-one, and
    # thirty-one category labels in one cell overlap into an unreadable band —
    # with a six-entry colour list cycling underneath them. Bounded to a named
    # operation set so the panel cannot silently grow past what its cell can
    # render.
    ed_ops = ("Ed25519 KeyGen", "Ed25519 Sign", "Ed25519 Verify")
    impls = (
        ("AMA Cryptography", "#7b2ff7"),
        ("libsodium (PyNaCl)", "#ff922b"),
        ("cryptography (OpenSSL)", "#6bcb77"),
    )
    comp_rows = (comparative or {}).get("results", [])
    have = {
        (r["implementation"], r["operation"]): r["ops_per_sec"]
        for r in comp_rows
        if r.get("available") and r.get("operation") in ed_ops
    }
    if have:
        width = 0.26
        idx = np.arange(len(ed_ops))
        for k, (impl, colour) in enumerate(impls):
            vals = [have.get((impl, op), 0.0) for op in ed_ops]
            if not any(vals):
                continue
            bars = ax.bar(
                idx + (k - 1) * width,
                vals,
                width=width,
                color=colour,
                edgecolor="none",
                label=impl.split(" (")[0],
            )
            for bar, v in zip(bars, vals):
                if v <= 0:
                    continue
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() * 1.03,
                    f"{v:,.0f}",
                    ha="center",
                    va="bottom",
                    fontsize=6,
                    color=TEXT_COLOR,
                )
        ax.set_xticks(idx)
        ax.set_xticklabels([o.replace("Ed25519 ", "") for o in ed_ops], fontsize=8)
        ax.set_yscale("log")
        ax.set_ylabel("ops/sec (log)")
        ax.legend(fontsize=6.5, facecolor=PANEL_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)
        ax.set_title("Ed25519 vs Peer Libraries", fontsize=10, fontweight="bold", pad=8)
    else:
        # comparative_benchmark_results.json is gitignored, so a clean checkout
        # has no cross-library data. Say so in the cell rather than crashing on
        # a None subscript the way this panel used to.
        missing_artefact(
            ax, "Ed25519 vs Peer Libraries", "python benchmarks/comparative_benchmark.py"
        )

    # ── Panel: Performance by Category (merged from benchmark_report) ──
    # An aggregate altitude the per-operation panel above cannot show: which
    # *family* of primitive costs what, averaged across its operations.
    ax = axes[0, 1]
    dna = bench["dna_operations"]
    categories = {
        "Hashing": [ops["sha3_256"]["ops_per_sec"]],
        "MAC": [ops["hmac_auth"]["ops_per_sec"], ops["hmac_verify"]["ops_per_sec"]],
        "Classical Sig": [ops["ed25519_sign"]["ops_per_sec"], ops["ed25519_verify"]["ops_per_sec"]],
        "PQC Sig": [ops["dilithium_sign"]["ops_per_sec"], ops["dilithium_verify"]["ops_per_sec"]],
        "Key Derivation": [keygen["hkdf_derivation"]["ops_per_sec"]],
        "Key Generation": [
            keygen["ed25519_keygen"]["ops_per_sec"],
            keygen["dilithium_keygen"]["ops_per_sec"],
        ],
        "Code Package": [
            dna["package_creation"]["ops_per_sec"],
            dna["package_verification"]["ops_per_sec"],
        ],
    }
    cat_names = list(categories.keys())
    cat_means = [float(np.mean(v)) for v in categories.values()]
    cat_colors = ["#00d2ff", "#4d96ff", "#7b2ff7", "#ff6b6b", "#6bcb77", "#ffd93d", "#ff922b"]
    bars = ax.barh(cat_names, cat_means, color=cat_colors, edgecolor="none", height=0.6)
    ax.set_xscale("log")
    ax.set_xlim(min(cat_means) * 0.4, max(cat_means) * 6.0)
    ax.set_title("Performance by Category", fontsize=10, fontweight="bold", pad=8)
    ax.set_xlabel("Mean ops/sec (log)")
    ax.tick_params(axis="y", labelsize=7.5)
    for bar, v in zip(bars, cat_means):
        ax.text(
            bar.get_width() * 1.15,
            bar.get_y() + bar.get_height() / 2,
            f"{v:,.0f}",
            va="center",
            fontsize=6.8,
            color=TEXT_COLOR,
        )

    # ── Panel: Ethical Integration Overhead (merged from benchmark_report) ──
    ax = axes[2, 1]
    eth = bench["ethical_integration"]
    eth_names = ["Standard\nHKDF", "Ethical\nHKDF", "Ethical\nContext"]
    eth_vals = [
        eth["hkdf_standard"]["ops_per_sec"],
        eth["hkdf_ethical"]["ops_per_sec"],
        eth["ethical_context"]["ops_per_sec"],
    ]
    bars = ax.bar(
        eth_names, eth_vals, color=["#6bcb77", "#ff6b6b", "#7b2ff7"], edgecolor="none", width=0.5
    )
    ax.set_title("Ethical Integration Overhead", fontsize=10, fontweight="bold", pad=8)
    ax.set_ylabel("ops/sec")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x/1000:.0f}K"))
    ax.tick_params(axis="x", labelsize=7.5)
    for bar, v in zip(bars, eth_vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.02,
            f"{v:,.0f}",
            ha="center",
            fontsize=7,
            color=TEXT_COLOR,
        )
    ax.text(
        0.5,
        0.90,
        f"Overhead: {eth['ethical_overhead']['overhead_pct']:.1f}%",
        transform=ax.transAxes,
        ha="center",
        fontsize=8,
        color="#ff6b6b",
        fontweight="bold",
    )

    # ── Panel: NIST FIPS Compliance (merged from benchmark_report) ────
    ax = axes[2, 2]
    fips_standards = [
        "FIPS 180-4\n(SHA-2)",
        "FIPS 202\n(SHA-3)",
        "FIPS 186-5\n(Ed25519)",
        "FIPS 203\n(ML-KEM)",
        "FIPS 204\n(ML-DSA)",
        "FIPS 205\n(SLH-DSA)",
    ]
    bars = ax.bar(fips_standards, [1] * 6, color="#6bcb77", edgecolor="none", width=0.5)
    ax.set_ylim(0, 1.3)
    ax.set_title("NIST FIPS Standard Compliance", fontsize=10, fontweight="bold", pad=8)
    ax.set_yticks([0, 0.5, 1])
    ax.set_yticklabels(["None", "Partial", "Full"])
    ax.tick_params(axis="x", labelsize=6.5)
    for bar in bars:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.03,
            "\u2713",
            ha="center",
            fontsize=13,
            color="#6bcb77",
            fontweight="bold",
        )

    # ── Panel: Key Metrics Summary (bottom-right) ─────────────────────
    ax = axes[2, 3]
    ax.axis("off")
    # Draw summary box
    metrics_text = (
        "AMA CRYPTOGRAPHY  BENCHMARK RESULTS\n"
        # The `+` is load-bearing: without it the adjacent string literals
        # concatenate at compile time and `* 42` repeats the whole title
        # forty-two times instead of drawing a 42-character rule.
        + "=" * 42 + "\n\n"
        f"  Platform:        {_PLATFORM}\n"
        f"  Python:          {_PY_VERSION}\n"
        f"  PQC Backend:     Native C (ML-DSA-65)\n"
        f"  Duration:        {bench['benchmark_duration_sec']:.2f}s\n\n"
        f"  SHA3-256:        {ops['sha3_256']['ops_per_sec']:>12,.0f} ops/s\n"
        f"  Ed25519 Sign:    {ops['ed25519_sign']['ops_per_sec']:>12,.0f} ops/s\n"
        f"  ML-DSA-65 Sign:  {ops['dilithium_sign']['ops_per_sec']:>12,.0f} ops/s\n"
        f"  Package Create:  {bench['dna_operations']['package_creation']['ops_per_sec']:>12,.0f} ops/s\n"
        f"  Package Verify:  {bench['dna_operations']['package_verification']['ops_per_sec']:>12,.0f} ops/s\n\n"
        f"  Regression:      {_summary_line(regression)}\n"
        f"  Validation:      {_summary_line(validation)}\n"
        f"  Ethical Overhead: {bench['ethical_integration']['ethical_overhead']['overhead_pct']:.1f}%\n\n"
        f"  All timings measured on benchmark run\n"
        f"  {bench['benchmark_start'][:10]}"
    )
    ax.text(
        0.05,
        0.95,
        metrics_text,
        transform=ax.transAxes,
        fontsize=7.5,
        fontfamily="monospace",
        color="#00d2ff",
        verticalalignment="top",
        bbox=dict(
            boxstyle="round,pad=0.6", facecolor="#0d1117", edgecolor="#00d2ff", linewidth=1.5
        ),
    )

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    out = ASSETS_DIR / "performance_dashboard.png"
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    print(f"  Created {out}")


# ═══════════════════════════════════════════════════════════════════════
#  DASHBOARD 2: Defense Layers
# ═══════════════════════════════════════════════════════════════════════
class _DefenseLayer(NamedTuple):
    """One band of the defense-architecture figure.

    A NamedTuple rather than a dict literal: the dict mixed str and float
    values, so it inferred as ``dict[str, object]`` and every ``layer["y"] -
    0.6`` in the drawing code was arithmetic on ``object``. The field names are
    also checked now, which a string key never was.
    """

    name: str
    color: str
    desc: str
    detail: str
    y: float


def create_defense_layers() -> None:
    fig, ax = plt.subplots(figsize=(14, 10))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 10)
    ax.axis("off")

    # Title
    ax.text(
        7,
        9.6,
        "AMA Cryptography — 4-Layer Defense Architecture",
        ha="center",
        fontsize=20,
        fontweight="bold",
        color="#ffffff",
    )
    ax.text(
        7,
        9.15,
        "Quantum-Resistant Integrity Protection Pipeline",
        ha="center",
        fontsize=11,
        color="#aaaaaa",
        style="italic",
    )

    layers = [
        _DefenseLayer(
            name="Layer 1: SHA3-256 Content Hash",
            color="#00d2ff",
            desc="Quantum-resistant 256-bit hash of canonical data",
            detail="FIPS 202 • Keccak sponge • AVX2/NEON accelerated",
            y=7.8,
        ),
        _DefenseLayer(
            name="Layer 2: HMAC-SHA3-256 Authentication",
            color="#7b2ff7",
            desc="Keyed hash for tamper detection & origin auth",
            detail="RFC 2104 • Ethical context binding • Side-channel safe",
            y=6.0,
        ),
        _DefenseLayer(
            name="Layer 3: Ed25519 + ML-DSA-65 Dual Signatures",
            color="#ff6b6b",
            desc="Classical + post-quantum hybrid signature scheme",
            detail="FIPS 186-5 + FIPS 204 • 128-bit classical + 192-bit PQ security",
            y=4.2,
        ),
        _DefenseLayer(
            name="Layer 4: HKDF-SHA3-256 Key Derivation",
            color="#6bcb77",
            desc="Deterministic key re-derivation for verification",
            detail="RFC 5869 • Ethical pillar binding • Empty-key guard (S1 fix)",
            y=2.4,
        ),
    ]

    for i, layer in enumerate(layers):
        y = layer.y
        c = layer.color
        # Layer box
        rect = plt.Rectangle(
            (1.5, y - 0.6),
            11,
            1.4,
            linewidth=2,
            edgecolor=c,
            facecolor=c + "18",
            clip_on=False,
            zorder=2,
        )
        ax.add_patch(rect)
        # Layer number badge
        badge = plt.Circle((2.3, y + 0.1), 0.35, color=c, zorder=3)
        ax.add_patch(badge)
        ax.text(
            2.3,
            y + 0.1,
            str(i + 1),
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold",
            color="#000000",
            zorder=4,
        )
        # Layer title
        ax.text(3.2, y + 0.35, layer.name, fontsize=13, fontweight="bold", color=c, zorder=3)
        # Description
        ax.text(3.2, y - 0.05, layer.desc, fontsize=9.5, color="#cccccc", zorder=3)
        # Technical detail
        ax.text(3.2, y - 0.38, layer.detail, fontsize=8, color="#888888", style="italic", zorder=3)
        # Arrow between layers
        if i < len(layers) - 1:
            ax.annotate(
                "",
                xy=(7, layer.y - 0.65),
                xytext=(7, layers[i + 1].y + 0.85),
                arrowprops=dict(
                    arrowstyle="->",
                    color="#ffffff",
                    lw=1.5,
                    connectionstyle="arc3,rad=0",
                ),
            )

    # Optional timestamp layer (dashed)
    ax.plot([1.5, 12.5], [1.2, 1.2], "--", color="#ffd93d", alpha=0.5, lw=1)
    ax.text(
        7,
        0.85,
        "Optional: RFC 3161 Timestamp (TSA integration)",
        ha="center",
        fontsize=9,
        color="#ffd93d",
        alpha=0.7,
        style="italic",
    )

    # Footer
    ax.text(
        7,
        0.25,
        "v3.0.0  •  "
        "SIMD Acceleration: AVX2 (x86-64) | NEON (AArch64) | SVE2 (ARMv9)"
        "  •  Zero external dependencies  •  FIPS 202/203/204/205 compliant",
        ha="center",
        fontsize=8,
        color="#666666",
    )

    out = ASSETS_DIR / "defense_layers.png"
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    print(f"  Created {out}")


# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("Generating AMA Cryptography dashboard images...")
    create_performance_dashboard()
    create_defense_layers()
    print("\nDone. Dashboard images saved to assets/")
