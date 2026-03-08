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
import sys

# Benchmark data (measured values from CI and dedicated test systems)
CRYPTO_OPS = {
    "SHA3-256 (C)": {"ops_sec": 1_264_198, "category": "hash"},
    "SHA3-256 (Python)": {"ops_sec": 280_000, "category": "hash"},
    "HMAC-SHA3-256": {"ops_sec": 160_000, "category": "mac"},
    "HKDF-SHA3-256 (C)": {"ops_sec": 165_419, "category": "kdf"},
    "HKDF-SHA3-256 (Python)": {"ops_sec": 19_000, "category": "kdf"},
}

SIGNATURE_OPS = {
    "Ed25519 Sign": {"ops_sec": 20_000, "latency_ms": 0.05},
    "Ed25519 Verify": {"ops_sec": 8_000, "latency_ms": 0.12},
    "ML-DSA-65 Sign": {"ops_sec": 2_115, "latency_ms": 0.473},
    "ML-DSA-65 Verify": {"ops_sec": 6_398, "latency_ms": 0.156},
    "SLH-DSA Sign": {"ops_sec": 22, "latency_ms": 45.757},
    "SLH-DSA Verify": {"ops_sec": 818, "latency_ms": 1.222},
}

KEM_OPS = {
    "ML-KEM KeyGen": {"ops_sec": 4_289, "latency_ms": 0.233},
    "ML-KEM Encap": {"ops_sec": 6_384, "latency_ms": 0.157},
    "ML-KEM Decap": {"ops_sec": 9_464, "latency_ms": 0.106},
}

C_VS_PYTHON = {
    "SHA3-256 (short)": {"c": 1_264_198, "python": 292_790, "speedup": 4.3},
    "HKDF (32B)": {"c": 165_419, "python": 21_443, "speedup": 7.7},
    "Ed25519 Sign": {"c": 9_182, "python": 10_453, "speedup": 0.88},
}

SCALING = {
    7: {"ms": 0.30, "ops_sec": 3_300},
    70: {"ms": 0.43, "ops_sec": 2_300},
    700: {"ms": 1.90, "ops_sec": 526},
    7000: {"ms": 180, "ops_sec": 5.5},
}

SIX_LAYER_BREAKDOWN = [
    ("SHA3-256 Hash", 0.001),
    ("HMAC-SHA3-256", 0.006),
    ("Ed25519 Sign", 0.100),
    ("ML-DSA-65 Sign", 0.473),
    ("HKDF Derivation", 0.006),
    ("RFC 3161 Timestamp", 0.0),  # optional
]


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

    # Chart 1: Signature Operations Comparison
    fig, ax = plt.subplots(figsize=(10, 6))
    names = list(SIGNATURE_OPS.keys())
    ops = [SIGNATURE_OPS[n]["ops_sec"] for n in names]
    colors = ["#2196F3", "#2196F3", "#9C27B0", "#9C27B0", "#4CAF50", "#4CAF50"]
    bars = ax.barh(names, ops, color=colors)
    ax.set_xlabel("Operations/sec")
    ax.set_title("Signature Performance (Higher = Better)")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val in zip(bars, ops):
        ax.text(bar.get_width() + max(ops) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "signature_performance.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/signature_performance.svg")

    # Chart 2: C vs Python Performance
    fig, ax = plt.subplots(figsize=(10, 5))
    ops_names = list(C_VS_PYTHON.keys())
    c_vals = [C_VS_PYTHON[n]["c"] for n in ops_names]
    py_vals = [C_VS_PYTHON[n]["python"] for n in ops_names]
    x = range(len(ops_names))
    w = 0.35
    ax.bar([i - w / 2 for i in x], c_vals, w, label="C Library", color="#1565C0")
    ax.bar([i + w / 2 for i in x], py_vals, w, label="Python API", color="#FF8F00")
    ax.set_ylabel("Operations/sec")
    ax.set_title("C Library vs Python API Performance")
    ax.set_xticks(list(x))
    ax.set_xticklabels(ops_names)
    ax.legend()
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for i, (c, p) in enumerate(zip(c_vals, py_vals)):
        speedup = C_VS_PYTHON[ops_names[i]]["speedup"]
        ax.text(i, max(c, p) + max(c_vals) * 0.02, f"{speedup}x", ha="center", fontsize=10,
                fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "c_vs_python.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/c_vs_python.svg")

    # Chart 3: 6-Layer Package Breakdown
    fig, ax = plt.subplots(figsize=(8, 6))
    labels = [name for name, ms in SIX_LAYER_BREAKDOWN if ms > 0]
    sizes = [ms for _, ms in SIX_LAYER_BREAKDOWN if ms > 0]
    colors_pie = ["#E3F2FD", "#BBDEFB", "#64B5F6", "#1565C0", "#0D47A1"]
    explode = [0, 0, 0.05, 0.1, 0]
    ax.pie(sizes, explode=explode, labels=labels, colors=colors_pie, autopct="%1.1f%%",
           shadow=False, startangle=140)
    ax.set_title("6-Layer Package Creation Time Breakdown")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "layer_breakdown.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/layer_breakdown.svg")

    # Chart 4: ML-KEM-1024 Operations
    fig, ax = plt.subplots(figsize=(8, 5))
    kem_names = list(KEM_OPS.keys())
    kem_ops = [KEM_OPS[n]["ops_sec"] for n in kem_names]
    bars = ax.bar(kem_names, kem_ops, color=["#7B1FA2", "#9C27B0", "#CE93D8"])
    ax.set_ylabel("Operations/sec")
    ax.set_title("ML-KEM-1024 (FIPS 203) Performance")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val in zip(bars, kem_ops):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 100,
                f"{val:,}", ha="center", fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "kem_performance.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/kem_performance.svg")

    # Chart 5: Scalability
    fig, ax = plt.subplots(figsize=(8, 5))
    codes = list(SCALING.keys())
    times = [SCALING[c]["ms"] for c in codes]
    ax.plot(codes, times, "o-", color="#1565C0", linewidth=2, markersize=8)
    ax.set_xlabel("Omni-Code Count")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Package Creation Scalability")
    ax.set_xscale("log")
    ax.set_yscale("log")
    for c, t in zip(codes, times):
        ax.annotate(f"{t} ms", (c, t), textcoords="offset points", xytext=(10, 5), fontsize=9)
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
        print(f"  {name:20s} C: {data['c']:>10,}  Python: {data['python']:>10,}  ({data['speedup']}x)")

    print("\nML-KEM-1024:")
    for name, data in KEM_OPS.items():
        print(f"  {name:20s} {data['ops_sec']:>8,} ops/sec ({data['latency_ms']} ms)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate AMA Cryptography benchmark charts")
    parser.add_argument("--output-dir", default="benchmarks/charts",
                        help="Output directory for SVG charts (default: benchmarks/charts)")
    args = parser.parse_args()
    print("Generating AMA Cryptography benchmark charts...")
    generate_charts(args.output_dir)
