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

# -- Baseline data (measured 2026-03-19, Linux 6.18.5, native C backend) -----
CRYPTO_OPS = {
    "SHA3-256 (C)": {"ops_sec": 591_593, "category": "hash"},
    "HMAC-SHA3-256": {"ops_sec": 64_402, "category": "mac"},
    "HKDF-SHA3-256 (C)": {"ops_sec": 12_839, "category": "kdf"},
    "HKDF-SHA3-256 (ethical)": {"ops_sec": 11_514, "category": "kdf"},
}

SIGNATURE_OPS = {
    "Ed25519 Sign": {"ops_sec": 2_652, "latency_ms": 0.377},
    "Ed25519 Verify": {"ops_sec": 1_472, "latency_ms": 0.680},
    "ML-DSA-65 Sign": {"ops_sec": 429, "latency_ms": 2.333},
    "ML-DSA-65 Verify": {"ops_sec": 536, "latency_ms": 1.864},
    "SLH-DSA Sign": {"ops_sec": 1, "latency_ms": 741.0},
    "SLH-DSA Verify": {"ops_sec": 53, "latency_ms": 19.0},
}

KEM_OPS = {
    "ML-KEM KeyGen": {"ops_sec": 4_289, "latency_ms": 0.233},
    "ML-KEM Encap": {"ops_sec": 6_384, "latency_ms": 0.157},
    "ML-KEM Decap": {"ops_sec": 9_464, "latency_ms": 0.106},
}

C_VS_PYTHON = {
    "SHA3-256 (short)": {"c": 591_593, "python": 75_505, "speedup": 7.8},
    "HKDF (32B)": {"c": 12_839, "python": 3_850, "speedup": 3.3},
    "Ed25519 Sign": {"c": 2_652, "python": 2_652, "speedup": 1.0},
}

SCALING = {
    7: {"ms": 3.41, "ops_sec": 293},
    70: {"ms": 6.82, "ops_sec": 147},
    700: {"ms": 4.70, "ops_sec": 213},
    7000: {"ms": 187.29, "ops_sec": 5.34},
}

FOUR_LAYER_BREAKDOWN = [
    ("SHA3-256 Hash", 0.002),
    ("HMAC-SHA3-256", 0.016),
    ("Ed25519 + ML-DSA-65 Sign", 2.710),
    ("HKDF Derivation", 0.260),
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
    """Generate all benchmark charts as SVG files."""
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

    apply_theme(plt)
    os.makedirs(output_dir, exist_ok=True)
    bench = load_live_data()

    # Update data from live benchmarks if available
    sig_ops = dict(SIGNATURE_OPS)
    kem_ops = dict(KEM_OPS)
    c_vs_py = dict(C_VS_PYTHON)
    scaling = dict(SCALING)

    if bench:
        ops = bench.get("cryptographic_operations", {})
        if "ed25519_sign" in ops:
            sig_ops["Ed25519 Sign"]["ops_sec"] = ops["ed25519_sign"]["ops_per_sec"]
            sig_ops["Ed25519 Sign"]["latency_ms"] = ops["ed25519_sign"]["mean_ms"]
        if "ed25519_verify" in ops:
            sig_ops["Ed25519 Verify"]["ops_sec"] = ops["ed25519_verify"]["ops_per_sec"]
            sig_ops["Ed25519 Verify"]["latency_ms"] = ops["ed25519_verify"]["mean_ms"]
        if "dilithium_sign" in ops:
            sig_ops["ML-DSA-65 Sign"]["ops_sec"] = ops["dilithium_sign"]["ops_per_sec"]
            sig_ops["ML-DSA-65 Sign"]["latency_ms"] = ops["dilithium_sign"]["mean_ms"]
        if "dilithium_verify" in ops:
            sig_ops["ML-DSA-65 Verify"]["ops_sec"] = ops["dilithium_verify"][
                "ops_per_sec"
            ]
            sig_ops["ML-DSA-65 Verify"]["latency_ms"] = ops["dilithium_verify"][
                "mean_ms"
            ]
        if "sha3_256" in ops:
            c_vs_py["SHA3-256 (short)"]["c"] = ops["sha3_256"]["ops_per_sec"]

    # -- Chart 1: Signature Performance --------------------------------------
    fig, ax = plt.subplots(figsize=(10, 6))
    names = list(sig_ops.keys())
    ops_vals = [sig_ops[n]["ops_sec"] for n in names]
    latencies = [sig_ops[n]["latency_ms"] for n in names]
    colors = ["#00d2ff", "#4d96ff", "#ff6b6b", "#ff922b", "#6bcb77", "#845ef7"]
    bars = ax.barh(
        names, ops_vals, color=colors[: len(names)], edgecolor="none", height=0.6
    )
    ax.set_xlabel("Operations/sec", fontsize=11)
    ax.set_title(
        "Signature Algorithm Performance",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax.xaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f"{x:,.0f}")
    )
    for bar, val, lat in zip(bars, ops_vals, latencies):
        label = (
            f"{val:,} ops/s ({lat:.3f} ms)"
            if val > 10
            else f"{val} ops/s ({lat:.1f} ms)"
        )
        ax.text(
            bar.get_width() + max(ops_vals) * 0.01,
            bar.get_y() + bar.get_height() / 2,
            label,
            va="center",
            fontsize=8,
            color=TEXT_COLOR,
        )
    plt.tight_layout()
    plt.savefig(
        os.path.join(output_dir, "signature_performance.svg"), format="svg"
    )
    plt.close()
    print(f"  Created {output_dir}/signature_performance.svg")

    # -- Chart 2: C vs Python Performance ------------------------------------
    fig, ax = plt.subplots(figsize=(10, 5))
    ops_names = list(c_vs_py.keys())
    c_vals = [c_vs_py[n]["c"] for n in ops_names]
    py_vals = [c_vs_py[n]["python"] for n in ops_names]
    x = range(len(ops_names))
    w = 0.35
    ax.bar(
        [i - w / 2 for i in x],
        c_vals,
        w,
        label="Native C Library",
        color="#00d2ff",
        edgecolor="none",
    )
    ax.bar(
        [i + w / 2 for i in x],
        py_vals,
        w,
        label="Python API",
        color="#ff6b6b",
        edgecolor="none",
    )
    ax.set_ylabel("Operations/sec", fontsize=11)
    ax.set_title(
        "C Library vs Python API Performance",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax.set_xticks(list(x))
    ax.set_xticklabels(ops_names, fontsize=10)
    ax.legend(fontsize=10)
    ax.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f"{x:,.0f}")
    )
    for i, (c, p) in enumerate(zip(c_vals, py_vals)):
        speedup = c_vs_py[ops_names[i]]["speedup"]
        ax.text(
            i,
            max(c, p) + max(c_vals) * 0.03,
            f"{speedup}x",
            ha="center",
            fontsize=12,
            fontweight="bold",
            color="#ffd93d",
        )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "c_vs_python.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/c_vs_python.svg")

    # -- Chart 3: 4-Layer Package Breakdown ----------------------------------
    fig, ax = plt.subplots(figsize=(9, 6))
    labels = [name for name, ms in FOUR_LAYER_BREAKDOWN if ms > 0]
    sizes = [ms for _, ms in FOUR_LAYER_BREAKDOWN if ms > 0]
    colors_pie = ["#00d2ff", "#7b2ff7", "#ff6b6b", "#6bcb77"]
    explode = [0, 0, 0.05, 0]
    wedges, texts, autotexts = ax.pie(
        sizes,
        explode=explode,
        labels=labels,
        colors=colors_pie,
        autopct=lambda pct: f"{pct:.1f}%\n({pct * sum(sizes) / 100:.3f}ms)",
        shadow=False,
        startangle=140,
        textprops={"fontsize": 9, "color": TEXT_COLOR},
        pctdistance=0.72,
    )
    for t in autotexts:
        t.set_fontsize(8)
        t.set_color("#ffffff")
    ax.set_title(
        "4-Layer Package Creation Time Breakdown",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    total_ms = sum(sizes)
    ax.text(
        0,
        -1.35,
        f"Total package creation: {total_ms:.3f} ms  |  "
        f"Layers: SHA3 + HMAC + Signatures + HKDF",
        ha="center",
        fontsize=9,
        color="#888888",
        style="italic",
    )
    plt.tight_layout()
    plt.savefig(
        os.path.join(output_dir, "layer_breakdown.svg"), format="svg"
    )
    plt.close()
    print(f"  Created {output_dir}/layer_breakdown.svg")

    # -- Chart 4: ML-KEM-1024 Performance ------------------------------------
    fig, ax = plt.subplots(figsize=(9, 5))
    kem_names = list(kem_ops.keys())
    kem_vals = [kem_ops[n]["ops_sec"] for n in kem_names]
    kem_lats = [kem_ops[n]["latency_ms"] for n in kem_names]
    kem_colors = ["#7b2ff7", "#845ef7", "#ff6b6b"]
    bars = ax.bar(
        kem_names,
        kem_vals,
        color=kem_colors,
        edgecolor="none",
        width=0.5,
    )
    ax.set_ylabel("Operations/sec", fontsize=11)
    ax.set_title(
        "ML-KEM-1024 (FIPS 203) Performance",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f"{x:,.0f}")
    )
    for bar, val, lat in zip(bars, kem_vals, kem_lats):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(kem_vals) * 0.02,
            f"{val:,} ops/s\n({lat:.3f} ms)",
            ha="center",
            fontsize=9,
            color=TEXT_COLOR,
        )
    ax.text(
        0.98,
        0.02,
        "FIPS 203 compliant | Native C implementation",
        transform=ax.transAxes,
        ha="right",
        fontsize=8,
        color="#666666",
        style="italic",
    )
    plt.tight_layout()
    plt.savefig(
        os.path.join(output_dir, "kem_performance.svg"), format="svg"
    )
    plt.close()
    print(f"  Created {output_dir}/kem_performance.svg")

    # -- Chart 5: Scalability ------------------------------------------------
    fig, ax = plt.subplots(figsize=(9, 5))
    codes = list(scaling.keys())
    times = [scaling[c]["ms"] for c in codes]
    ops_sec = [scaling[c]["ops_sec"] for c in codes]
    ax.plot(
        codes,
        times,
        "o-",
        color="#ffd93d",
        linewidth=2.5,
        markersize=10,
        markerfacecolor="#ffd93d",
        markeredgecolor="#ffffff",
        markeredgewidth=1.5,
    )
    ax.set_xlabel("Omni-Code Count", fontsize=11)
    ax.set_ylabel("Latency (ms)", fontsize=11)
    ax.set_title(
        "Package Creation Scalability",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax.set_xscale("log")
    ax.set_yscale("log")
    for c, t, o in zip(codes, times, ops_sec):
        ax.annotate(
            f"{t:.1f} ms\n({o:,.0f} ops/s)",
            (c, t),
            textcoords="offset points",
            xytext=(12, -5),
            fontsize=9,
            color="#ffd93d",
        )
    ax.text(
        0.98,
        0.02,
        "Log-log scale | 4-layer defense pipeline",
        transform=ax.transAxes,
        ha="right",
        fontsize=8,
        color="#666666",
        style="italic",
    )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "scalability.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/scalability.svg")

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
        print(
            f"  {name:20s} {data['ops_sec']:>8,} ops/sec"
            f" ({data['latency_ms']} ms)"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate AMA Cryptography benchmark charts"
    )
    parser.add_argument(
        "--output-dir",
        default="benchmarks/charts",
        help="Output directory for SVG charts (default: benchmarks/charts)",
    )
    args = parser.parse_args()
    print("Generating AMA Cryptography benchmark charts...")
    generate_charts(args.output_dir)
