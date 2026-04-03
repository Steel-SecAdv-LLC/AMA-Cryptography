#!/usr/bin/env python3
"""
Generate benchmark visualization charts for AMA Cryptography.

Outputs SVG charts to benchmarks/charts/ for inclusion in documentation.
Reads live benchmark data from JSON files when available, falls back to
measured baseline data.

Requires matplotlib: pip install matplotlib

Usage:
    python benchmarks/generate_charts.py
    python benchmarks/generate_charts.py --output-dir docs/images

Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0
"""

import argparse
import json
import os
from pathlib import Path

# -- Paths -------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
BENCH_FILE = ROOT / "benchmark_results.json"

# -- Baseline data (measured 2026-04-03, Linux 6.18.5, native C backend) ------
# Raw C numbers from benchmark_c_raw; Python numbers from phase0_baseline.py.
CRYPTO_OPS = {
    "SHA3-256 (C, 32B)": {"ops_sec": 136_593, "category": "hash"},
    "SHA3-256 (C, 1KB)": {"ops_sec": 18_840, "category": "hash"},
    "SHA3-256 (Py, 1KB)": {"ops_sec": 19_159, "category": "hash"},
    "HMAC-SHA3-256 (C)": {"ops_sec": 13_160, "category": "mac"},
    "HKDF-SHA3-256 (C)": {"ops_sec": 8_464, "category": "kdf"},
}

SIGNATURE_OPS = {
    "Ed25519 Sign": {"ops_sec": 5_211, "latency_ms": 0.192},
    "Ed25519 Verify": {"ops_sec": 2_715, "latency_ms": 0.368},
    "ML-DSA-65 Sign": {"ops_sec": 463, "latency_ms": 2.162},
    "ML-DSA-65 Verify": {"ops_sec": 706, "latency_ms": 1.416},
    "SLH-DSA Sign": {"ops_sec": 1, "latency_ms": 741.0},
    "SLH-DSA Verify": {"ops_sec": 53, "latency_ms": 19.0},
}

KEM_OPS = {
    "ML-KEM KeyGen": {"ops_sec": 1_463, "latency_ms": 0.683},
    "ML-KEM Encap": {"ops_sec": 1_408, "latency_ms": 0.710},
    "ML-KEM Decap": {"ops_sec": 1_372, "latency_ms": 0.729},
}

C_VS_PYTHON = {
    "SHA3-256 (1KB)": {"c": 18_840, "python": 19_159, "speedup": 1.0},
    "HKDF (96B)": {"c": 8_464, "python": 8_013, "speedup": 1.1},
    "Ed25519 Sign": {"c": 5_211, "python": 5_335, "speedup": 1.0},
    "ML-DSA-65 Sign": {"c": 463, "python": 373, "speedup": 1.2},
    "ML-KEM Encap": {"c": 1_408, "python": 580, "speedup": 2.4},
}

SCALING = {
    7: {"ms": 2.04, "ops_sec": 491},
    70: {"ms": 4.10, "ops_sec": 244},
    700: {"ms": 5.50, "ops_sec": 182},
    7000: {"ms": 120.00, "ops_sec": 8},
}

FOUR_LAYER_BREAKDOWN = [
    ("SHA3-256 Hash", 0.052),
    ("HMAC-SHA3-256", 0.078),
    ("Ed25519 + ML-DSA-65 Sign", 2.354),
    ("HKDF Derivation", 0.125),
]


def load_live_data():
    """Load live benchmark data if available."""
    if BENCH_FILE.exists():
        try:
            with open(BENCH_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, KeyError):
            pass
    return None


# -- Professional dark theme -------------------------------------------------
DARK_BG = "#1a1a2e"
PANEL_BG = "#16213e"
TEXT_COLOR = "#e0e0e0"
GRID_COLOR = "#2a2a4a"


def apply_theme(plt):
    """Apply professional dark theme to all charts."""
    plt.rcParams.update(
        {
            "figure.facecolor": DARK_BG,
            "axes.facecolor": PANEL_BG,
            "axes.edgecolor": GRID_COLOR,
            "axes.labelcolor": TEXT_COLOR,
            "axes.grid": True,
            "grid.color": GRID_COLOR,
            "grid.alpha": 0.3,
            "text.color": TEXT_COLOR,
            "xtick.color": TEXT_COLOR,
            "ytick.color": TEXT_COLOR,
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "legend.facecolor": PANEL_BG,
            "legend.edgecolor": GRID_COLOR,
            "legend.labelcolor": TEXT_COLOR,
        }
    )


def generate_charts(output_dir: str) -> None:
    """Generate benchmark chart as a single combined SVG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
    except ImportError:
        print("matplotlib not installed. Install with: pip install matplotlib")
        print("Generating text-only summary instead.\n")
        generate_text_summary()
        return

    import numpy as np

    apply_theme(plt)
    os.makedirs(output_dir, exist_ok=True)

    sig_ops = dict(SIGNATURE_OPS)
    kem_ops = dict(KEM_OPS)
    c_vs_py = dict(C_VS_PYTHON)

    # -- Combined 3-panel chart: algorithm_performance.svg -------------------
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle(
        "Algorithm Performance Detail — v2.1.0",
        fontsize=14, fontweight="bold", color="#00d2ff", y=0.98,
    )

    # Panel 1: Signature throughput (horizontal bar)
    names = list(sig_ops.keys())
    ops_vals = [sig_ops[n]["ops_sec"] for n in names]
    latencies = [sig_ops[n]["latency_ms"] for n in names]
    colors = ["#00d2ff", "#4d96ff", "#ff6b6b", "#ff922b", "#6bcb77", "#845ef7"]
    bars = ax1.barh(names, ops_vals, color=colors[: len(names)], edgecolor="none", height=0.6)
    ax1.set_xlabel("Operations/sec", fontsize=10)
    ax1.set_title("Signature Throughput", fontsize=12, fontweight="bold", pad=10)
    ax1.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val, lat in zip(bars, ops_vals, latencies):
        label = f"{val:,} ops/s  ({lat:.3f}ms)" if val > 10 else f"{val} ops/s  ({lat:.1f}ms)"
        ax1.text(
            bar.get_width() + max(ops_vals) * 0.02,
            bar.get_y() + bar.get_height() / 2,
            label, va="center", fontsize=8, color=TEXT_COLOR,
        )

    # Panel 2: ML-KEM-1024 (vertical bar)
    kem_names = list(kem_ops.keys())
    kem_vals = [kem_ops[n]["ops_sec"] for n in kem_names]
    kem_lats = [kem_ops[n]["latency_ms"] for n in kem_names]
    kem_colors = ["#7b2ff7", "#845ef7", "#ff6b6b"]
    bars2 = ax2.bar(kem_names, kem_vals, color=kem_colors, edgecolor="none", width=0.5)
    ax2.set_ylabel("Operations/sec", fontsize=10)
    ax2.set_title("ML-KEM-1024 (FIPS 203)", fontsize=12, fontweight="bold", pad=10)
    ax2.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val, lat in zip(bars2, kem_vals, kem_lats):
        ax2.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height() + 20,
            f"{val:,}\n{lat:.3f}ms", ha="center", fontsize=9, color=TEXT_COLOR,
        )
    ax2.text(
        0.5, 0.02, "AVX2 NTT dispatch active",
        transform=ax2.transAxes, ha="center", fontsize=8, color="#666666", style="italic",
    )

    # Panel 3: C vs Python (grouped bar)
    ops_names = list(c_vs_py.keys())
    c_vals = [c_vs_py[n]["c"] for n in ops_names]
    py_vals = [c_vs_py[n]["python"] for n in ops_names]
    x = np.arange(len(ops_names))
    w = 0.32
    ax3.bar(x - w / 2, c_vals, w, label="Raw C", color="#00d2ff", edgecolor="none")
    ax3.bar(x + w / 2, py_vals, w, label="Python ctypes", color="#ff6b6b", edgecolor="none")
    ax3.set_ylabel("Operations/sec", fontsize=10)
    ax3.set_title("Raw C vs Python API", fontsize=12, fontweight="bold", pad=10)
    ax3.set_xticks(list(x))
    ax3.set_xticklabels(ops_names, fontsize=9)
    ax3.legend(fontsize=9, loc="upper right")
    ax3.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    plt.savefig(os.path.join(output_dir, "algorithm_performance.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/algorithm_performance.svg")

    print(f"\nAll charts generated in {output_dir}/")


def generate_text_summary() -> None:
    """Print text-only benchmark summary when matplotlib is unavailable."""
    print("=" * 60)
    print("AMA Cryptography Benchmark Summary")
    print("=" * 60)

    print("\nSignature Operations:")
    for name, data in SIGNATURE_OPS.items():
        bar = "#" * min(50, data["ops_sec"] // 400)
        print(f"  {name:20s} {bar} {data['ops_sec']:>8,} ops/sec")

    print("\nC vs Python:")
    for name, data in C_VS_PYTHON.items():
        print(
            f"  {name:20s} C: {data['c']:>10,}  "
            f"Python: {data['python']:>10,}  ({data['speedup']}x)"
        )

    print("\nML-KEM-1024:")
    for name, data in KEM_OPS.items():
        print(f"  {name:20s} {data['ops_sec']:>8,} ops/sec" f" ({data['latency_ms']} ms)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate AMA Cryptography benchmark charts")
    parser.add_argument(
        "--output-dir",
        default="benchmarks/charts",
        help="Output directory for SVG charts (default: benchmarks/charts)",
    )
    args = parser.parse_args()
    print("Generating AMA Cryptography benchmark charts...")
    generate_charts(args.output_dir)
