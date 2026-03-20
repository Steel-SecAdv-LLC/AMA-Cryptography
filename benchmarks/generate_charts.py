#!/usr/bin/env python3
"""
Generate benchmark visualization charts for AMA Cryptography.

Outputs SVG charts to benchmarks/charts/ for inclusion in documentation.
Requires matplotlib: pip install matplotlib

Usage:
    python benchmarks/generate_charts.py
    python benchmarks/generate_charts.py --output-dir docs/images

Copyright 2025-2026 Steel Security Advisors LLC
Licensed under the Apache License, Version 2.0
"""

import argparse
import os

# Benchmark data (measured 2026-03-20, Linux 6.18.5, native C backend)
# Sources: docs/performance_investigation_report.md,
#          docs/ed25519_field_investigation_report.md
CRYPTO_OPS = {
    "SHA3-256 (C, 1KB)": {"ops_sec": 278_203, "category": "hash"},
    "SHA3-256 (Python API, 1KB)": {"ops_sec": 317_965, "category": "hash"},
    "HMAC-SHA3-256 (1KB)": {"ops_sec": 185_874, "category": "mac"},
    "HKDF-SHA3-256 (96B)": {"ops_sec": 123_047, "category": "kdf"},
}

SIGNATURE_OPS = {
    "Ed25519 Sign": {"ops_sec": 21_177, "latency_ms": 0.047},
    "Ed25519 Verify": {"ops_sec": 9_979, "latency_ms": 0.100},
    "ML-DSA-65 Sign": {"ops_sec": 4_315, "latency_ms": 0.232},
    "ML-DSA-65 Verify": {"ops_sec": 1_174_398, "latency_ms": 0.001},
    "SLH-DSA Sign": {"ops_sec": 1, "latency_ms": 741.0},
    "SLH-DSA Verify": {"ops_sec": 53, "latency_ms": 19.0},
}

KEM_OPS = {
    "ML-KEM KeyGen": {"ops_sec": 4_289, "latency_ms": 0.233},
    "ML-KEM Encap": {"ops_sec": 6_384, "latency_ms": 0.157},
    "ML-KEM Decap": {"ops_sec": 9_464, "latency_ms": 0.106},
}

C_VS_PYTHON = {
    "SHA3-256 (1KB)": {"c": 278_203, "python": 317_965, "speedup": 1.1},
    "HKDF-SHA3-256": {"c": 123_047, "python": 69_221, "speedup": 1.8},
    "Ed25519 Sign": {"c": 21_177, "python": 21_177, "speedup": 1.0},
}

SCALING = {
    7: {"ms": 3.41, "ops_sec": 293},
    70: {"ms": 6.82, "ops_sec": 147},
    700: {"ms": 4.70, "ops_sec": 213},
    7000: {"ms": 187.29, "ops_sec": 5.34},
}

SIX_LAYER_BREAKDOWN = [
    ("SHA3-256 Hash", 0.004),
    ("HMAC-SHA3-256", 0.005),
    ("Ed25519 Sign", 0.047),
    ("ML-DSA-65 Sign", 0.232),
    ("HKDF Derivation", 0.008),
    ("RFC 3161 Timestamp", 0.0),  # optional
]

# ── Consistent color palette ─────────────────────────────────────────
PALETTE = {
    "blue": "#1565C0",
    "blue_light": "#42A5F5",
    "purple": "#7B1FA2",
    "purple_light": "#AB47BC",
    "green": "#2E7D32",
    "green_light": "#66BB6A",
    "orange": "#E65100",
    "amber": "#FF8F00",
    "grey": "#616161",
}


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

    os.makedirs(output_dir, exist_ok=True)

    # Shared style
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "grid.linewidth": 0.5,
        }
    )

    # ── Chart 1: Signature Operations Comparison ─────────────────────
    fig, ax = plt.subplots(figsize=(10, 6))
    names = list(SIGNATURE_OPS.keys())
    ops = [SIGNATURE_OPS[n]["ops_sec"] for n in names]
    colors = [
        PALETTE["blue"],
        PALETTE["blue_light"],
        PALETTE["purple"],
        PALETTE["purple_light"],
        PALETTE["green"],
        PALETTE["green_light"],
    ]
    bars = ax.barh(names, ops, color=colors, edgecolor="white", linewidth=0.5, height=0.6)
    ax.set_xlabel("Operations / sec", fontsize=11)
    ax.set_title(
        "Signature Performance Comparison",
        fontsize=13,
        fontweight="bold",
        pad=12,
    )
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val in zip(bars, ops):
        label = f"{val:,}" if val < 100_000 else f"{val/1000:.0f}K"
        ax.text(
            bar.get_width() * 1.15,
            bar.get_y() + bar.get_height() / 2,
            label,
            va="center",
            fontsize=9,
            fontweight="bold",
        )
    fig.text(
        0.5,
        -0.02,
        "Platform: Intel Xeon @ 2.10GHz · GCC 13.3 · -O3 -march=native",
        ha="center",
        fontsize=8,
        color=PALETTE["grey"],
    )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "signature_performance.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/signature_performance.svg")

    # ── Chart 2: C vs Python Performance ─────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 5))
    ops_names = list(C_VS_PYTHON.keys())
    c_vals = [C_VS_PYTHON[n]["c"] for n in ops_names]
    py_vals = [C_VS_PYTHON[n]["python"] for n in ops_names]
    x = range(len(ops_names))
    w = 0.32
    ax.bar(
        [i - w / 2 for i in x],
        c_vals,
        w,
        label="C Library (ctypes)",
        color=PALETTE["blue"],
        edgecolor="white",
        linewidth=0.5,
    )
    ax.bar(
        [i + w / 2 for i in x],
        py_vals,
        w,
        label="Python API (Cython)",
        color=PALETTE["amber"],
        edgecolor="white",
        linewidth=0.5,
    )
    ax.set_ylabel("Operations / sec", fontsize=11)
    ax.set_title(
        "C Library vs Python API Throughput",
        fontsize=13,
        fontweight="bold",
        pad=12,
    )
    ax.set_xticks(list(x))
    ax.set_xticklabels(ops_names, fontsize=10)
    ax.legend(fontsize=9, framealpha=0.9)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x/1000:.0f}K"))
    for i, (c, p) in enumerate(zip(c_vals, py_vals)):
        speedup = C_VS_PYTHON[ops_names[i]]["speedup"]
        ax.text(
            i,
            max(c, p) + max(max(c_vals), max(py_vals)) * 0.03,
            f"{speedup:.1f}x",
            ha="center",
            fontsize=10,
            fontweight="bold",
            color=PALETTE["green"],
        )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "c_vs_python.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/c_vs_python.svg")

    # ── Chart 3: 6-Layer Package Breakdown ───────────────────────────
    fig, ax = plt.subplots(figsize=(8, 6))
    labels = [name for name, ms in SIX_LAYER_BREAKDOWN if ms > 0]
    sizes = [ms for _, ms in SIX_LAYER_BREAKDOWN if ms > 0]
    colors_pie = [
        PALETTE["green_light"],
        PALETTE["blue_light"],
        PALETTE["blue"],
        PALETTE["purple"],
        PALETTE["amber"],
    ]
    explode = [0, 0, 0.03, 0.06, 0]
    wedges, texts, autotexts = ax.pie(
        sizes,
        explode=explode,
        labels=labels,
        colors=colors_pie,
        autopct="%1.1f%%",
        shadow=False,
        startangle=140,
        textprops={"fontsize": 10},
        pctdistance=0.75,
    )
    for t in autotexts:
        t.set_fontsize(9)
        t.set_fontweight("bold")
    ax.set_title(
        "6-Layer Package Creation — Latency Breakdown",
        fontsize=13,
        fontweight="bold",
        pad=12,
    )
    fig.text(
        0.5,
        0.02,
        "Total ~0.30 ms per package (all layers). RFC 3161 timestamp is optional.",
        ha="center",
        fontsize=8,
        color=PALETTE["grey"],
    )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "layer_breakdown.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/layer_breakdown.svg")

    # ── Chart 4: ML-KEM-1024 Operations ──────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    kem_names = list(KEM_OPS.keys())
    kem_ops = [KEM_OPS[n]["ops_sec"] for n in kem_names]
    kem_colors = [PALETTE["purple"], PALETTE["purple_light"], PALETTE["blue_light"]]
    bars = ax.bar(kem_names, kem_ops, color=kem_colors, edgecolor="white", linewidth=0.5, width=0.5)
    ax.set_ylabel("Operations / sec", fontsize=11)
    ax.set_title(
        "ML-KEM-1024 (FIPS 203) Performance",
        fontsize=13,
        fontweight="bold",
        pad=12,
    )
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val in zip(bars, kem_ops):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(kem_ops) * 0.02,
            f"{val:,}",
            ha="center",
            fontsize=10,
            fontweight="bold",
        )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "kem_performance.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/kem_performance.svg")

    # ── Chart 5: Scalability ─────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    codes = list(SCALING.keys())
    times = [SCALING[c]["ms"] for c in codes]
    ax.plot(
        codes,
        times,
        "o-",
        color=PALETTE["blue"],
        linewidth=2.5,
        markersize=8,
        markerfacecolor=PALETTE["blue"],
        markeredgecolor="white",
        markeredgewidth=1.5,
    )
    ax.set_xlabel("Omni-Code Count", fontsize=11)
    ax.set_ylabel("Latency (ms)", fontsize=11)
    ax.set_title(
        "Package Creation Scalability",
        fontsize=13,
        fontweight="bold",
        pad=12,
    )
    ax.set_xscale("log")
    ax.set_yscale("log")
    for c, t in zip(codes, times):
        ax.annotate(
            f"{t:.1f} ms",
            (c, t),
            textcoords="offset points",
            xytext=(12, 5),
            fontsize=9,
            fontweight="bold",
            color=PALETTE["blue"],
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
            f"  {name:20s} C: {data['c']:>10,}  Python: {data['python']:>10,}  ({data['speedup']}x)"
        )

    print("\nML-KEM-1024:")
    for name, data in KEM_OPS.items():
        print(f"  {name:20s} {data['ops_sec']:>8,} ops/sec ({data['latency_ms']} ms)")


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
