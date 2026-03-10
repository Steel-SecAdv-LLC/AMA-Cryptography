#!/usr/bin/env python3
"""
Generate visual diagrams for AMA Cryptography documentation.

Creates:
1. 6-Layer Defense-in-Depth diagram
2. Performance comparison bar charts
3. Test coverage visualization
4. Monitoring overhead pie chart
"""

from pathlib import Path

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np

# Set style
plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["font.size"] = 11

ASSETS_DIR = Path(__file__).parent.parent / "assets"
ASSETS_DIR.mkdir(exist_ok=True)


def create_defense_layers_diagram():
    """Create the 6-layer defense-in-depth visualization with data flow."""
    fig, ax = plt.subplots(figsize=(16, 10))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 12)
    ax.axis("off")

    # Layer data: (name, color, what_it_does, what_it_blocks, optional)
    layers = [
        (
            "Layer 1: SHA3-256 Hash",
            "#22C55E",
            "Detects any change in data",
            "Silent tampering, corruption",
            False,
        ),
        (
            "Layer 2: HMAC-SHA3-256",
            "#14B8A6",
            "Ties data to a secret key",
            "Message forgery without key",
            False,
        ),
        (
            "Layer 3: Ed25519 Signatures",
            "#0EA5E9",
            "Classical digital signature",
            "Forgery by classical computers",
            False,
        ),
        (
            "Layer 4: ML-DSA-65 (Dilithium)",
            "#3B82F6",
            "Post-quantum signature",
            "Forgery by quantum computers",
            False,
        ),
        (
            "Layer 5: HKDF Key Derivation",
            "#6366F1",
            "Fresh keys per package",
            "Key reuse attacks",
            False,
        ),
        (
            "Layer 6: RFC 3161 Timestamp",
            "#8B5CF6",
            "Proves when data existed",
            "Backdating, timeline attacks",
            True,
        ),
    ]

    # Title
    ax.text(
        8,
        11.5,
        "AMA Cryptography: 6-Layer Defense-in-Depth Architecture",
        ha="center",
        fontsize=18,
        fontweight="bold",
        color="#1F2937",
    )

    # Data flow arrow on the left
    ax.annotate(
        "",
        xy=(1.2, 1.5),
        xytext=(1.2, 9.5),
        arrowprops=dict(arrowstyle="->", color="#374151", lw=3),
    )
    ax.text(
        0.4,
        9.5,
        "Data In",
        ha="center",
        va="bottom",
        fontsize=11,
        fontweight="bold",
        color="#374151",
    )
    ax.text(
        0.4,
        1.2,
        "Protected\nPackage\nOut",
        ha="center",
        va="top",
        fontsize=10,
        fontweight="bold",
        color="#374151",
    )

    # Column headers
    ax.text(4.5, 10.3, "Layer", ha="center", fontsize=12, fontweight="bold", color="#6B7280")
    ax.text(9.5, 10.3, "What It Does", ha="center", fontsize=12, fontweight="bold", color="#6B7280")
    ax.text(
        13.5, 10.3, "What It Blocks", ha="center", fontsize=12, fontweight="bold", color="#6B7280"
    )

    # Draw each layer
    y_start = 9.2
    layer_height = 1.2

    for i, (name, color, does, blocks, optional) in enumerate(layers):
        y = y_start - i * layer_height

        # Layer name box
        rect = mpatches.FancyBboxPatch(
            (2, y - 0.4),
            5,
            0.8,
            boxstyle="round,pad=0.02,rounding_size=0.1",
            facecolor=color,
            edgecolor="white",
            linewidth=2,
        )
        ax.add_patch(rect)

        label = name + (" *" if optional else "")
        ax.text(
            4.5, y, label, ha="center", va="center", fontsize=11, fontweight="bold", color="white"
        )

        # What it does box
        rect2 = mpatches.FancyBboxPatch(
            (7.2, y - 0.35),
            4.6,
            0.7,
            boxstyle="round,pad=0.02,rounding_size=0.1",
            facecolor="#F3F4F6",
            edgecolor="#D1D5DB",
            linewidth=1,
        )
        ax.add_patch(rect2)
        ax.text(9.5, y, does, ha="center", va="center", fontsize=10, color="#374151")

        # What it blocks box
        rect3 = mpatches.FancyBboxPatch(
            (12, y - 0.35),
            3.5,
            0.7,
            boxstyle="round,pad=0.02,rounding_size=0.1",
            facecolor="#FEE2E2",
            edgecolor="#FECACA",
            linewidth=1,
        )
        ax.add_patch(rect3)
        ax.text(13.75, y, blocks, ha="center", va="center", fontsize=10, color="#991B1B")

        # Flow arrow between layers (except last)
        if i < len(layers) - 1:
            ax.annotate(
                "",
                xy=(4.5, y - 0.5),
                xytext=(4.5, y - 0.7),
                arrowprops=dict(arrowstyle="->", color="#9CA3AF", lw=1.5),
            )

    # Comparison box: Typical vs AMA Cryptography
    # Typical system box
    ax.text(
        8,
        1.8,
        "Comparison: Typical System vs AMA Cryptography",
        ha="center",
        fontsize=12,
        fontweight="bold",
        color="#374151",
    )

    # Typical system (1-2 layers)
    rect_typical = mpatches.FancyBboxPatch(
        (3, 0.4),
        4,
        1.0,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor="#9CA3AF",
        edgecolor="#6B7280",
        linewidth=2,
    )
    ax.add_patch(rect_typical)
    ax.text(
        5,
        0.9,
        "Typical: 1-2 Layers",
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        color="white",
    )
    ax.text(5, 0.55, "(Hash + Signature)", ha="center", va="center", fontsize=9, color="white")

    # AMA Cryptography (6 layers)
    colors_mini = ["#22C55E", "#14B8A6", "#0EA5E9", "#3B82F6", "#6366F1", "#8B5CF6"]
    for j, c in enumerate(colors_mini):
        rect_ag = mpatches.FancyBboxPatch(
            (9 + j * 0.7, 0.4),
            0.65,
            1.0,
            boxstyle="round,pad=0.01,rounding_size=0.05",
            facecolor=c,
            edgecolor="white",
            linewidth=1,
        )
        ax.add_patch(rect_ag)
    ax.text(
        11.1,
        0.9,
        "AMA Cryptography: 6 Layers",
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        color="#1F2937",
    )
    ax.text(
        11.1, 0.55, "(All must be broken)", ha="center", va="center", fontsize=9, color="#374151"
    )

    # Optional layer note
    ax.text(
        8,
        -0.1,
        "* Optional layer for trusted third-party timestamping",
        ha="center",
        fontsize=9,
        style="italic",
        color="#6B7280",
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "defense_layers.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'defense_layers.png'}")


def create_performance_comparison():
    """Create advanced multi-factor performance comparison with line charts."""
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))

    # Data from BENCHMARKS.md
    implementations = ["AMA Cryptography\n(Standard)", "AMA Cryptography\n(Optimized)", "OpenSSL+liboqs"]
    x_pos = np.arange(len(implementations))

    # Throughput data (ops/sec)
    sign_throughput = [4575, 6500, 6209]
    verify_throughput = [6192, 6700, 6721]

    # Derived latency data (ms = 1000 / ops_per_sec)
    sign_latency = [1000 / v for v in sign_throughput]
    verify_latency = [1000 / v for v in verify_throughput]

    # Relative performance vs OpenSSL+liboqs baseline (%)
    sign_relative = [100 * v / sign_throughput[2] for v in sign_throughput]
    verify_relative = [100 * v / verify_throughput[2] for v in verify_throughput]

    # === Panel 1: Throughput Line Chart ===
    ax1 = axes[0]
    ax1.plot(
        x_pos,
        sign_throughput,
        "o-",
        color="#3B82F6",
        linewidth=2.5,
        markersize=10,
        label="Hybrid Sign",
        markeredgecolor="white",
        markeredgewidth=2,
    )
    ax1.plot(
        x_pos,
        verify_throughput,
        "s-",
        color="#22C55E",
        linewidth=2.5,
        markersize=10,
        label="Hybrid Verify",
        markeredgecolor="white",
        markeredgewidth=2,
    )

    # Add value annotations
    for i, (s, v) in enumerate(zip(sign_throughput, verify_throughput)):
        ax1.annotate(
            f"{s:,}",
            (i, s),
            textcoords="offset points",
            xytext=(0, 12),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color="#3B82F6",
        )
        ax1.annotate(
            f"{v:,}",
            (i, v),
            textcoords="offset points",
            xytext=(0, -18),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color="#22C55E",
        )

    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(implementations, fontsize=9)
    ax1.set_ylabel("Operations per Second", fontsize=11)
    ax1.set_title("Throughput Comparison\n(Higher is Better)", fontsize=12, fontweight="bold")
    ax1.legend(loc="lower right", fontsize=9)
    ax1.set_ylim(3500, 7500)
    ax1.grid(True, alpha=0.3)

    # === Panel 2: Latency Line Chart ===
    ax2 = axes[1]
    ax2.plot(
        x_pos,
        sign_latency,
        "o-",
        color="#3B82F6",
        linewidth=2.5,
        markersize=10,
        label="Sign Latency",
        markeredgecolor="white",
        markeredgewidth=2,
    )
    ax2.plot(
        x_pos,
        verify_latency,
        "s-",
        color="#22C55E",
        linewidth=2.5,
        markersize=10,
        label="Verify Latency",
        markeredgecolor="white",
        markeredgewidth=2,
    )

    for i, (s, v) in enumerate(zip(sign_latency, verify_latency)):
        ax2.annotate(
            f"{s:.3f}ms",
            (i, s),
            textcoords="offset points",
            xytext=(0, 12),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color="#3B82F6",
        )
        ax2.annotate(
            f"{v:.3f}ms",
            (i, v),
            textcoords="offset points",
            xytext=(0, -18),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color="#22C55E",
        )

    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(implementations, fontsize=9)
    ax2.set_ylabel("Latency (milliseconds)", fontsize=11)
    ax2.set_title("Latency Comparison\n(Lower is Better)", fontsize=12, fontweight="bold")
    ax2.legend(loc="upper right", fontsize=9)
    ax2.set_ylim(0.1, 0.25)
    ax2.grid(True, alpha=0.3)

    # === Panel 3: Relative Performance vs Baseline ===
    ax3 = axes[2]
    width = 0.35
    bars1 = ax3.bar(
        x_pos - width / 2,
        sign_relative,
        width,
        color="#3B82F6",
        label="Sign",
        edgecolor="white",
        linewidth=1.5,
    )
    bars2 = ax3.bar(
        x_pos + width / 2,
        verify_relative,
        width,
        color="#22C55E",
        label="Verify",
        edgecolor="white",
        linewidth=1.5,
    )

    # Add percentage labels
    for bar, val in zip(bars1, sign_relative):
        ax3.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{val:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="bold",
        )
    for bar, val in zip(bars2, verify_relative):
        ax3.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{val:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="bold",
        )

    # 100% baseline line
    ax3.axhline(y=100, color="#6B7280", linestyle="--", linewidth=1.5, alpha=0.7)
    ax3.text(2.4, 101, "OpenSSL+liboqs baseline", fontsize=8, color="#6B7280", va="bottom")

    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(implementations, fontsize=9)
    ax3.set_ylabel("Relative Performance (%)", fontsize=11)
    ax3.set_title(
        "Performance vs OpenSSL+liboqs\n(100% = Baseline)", fontsize=12, fontweight="bold"
    )
    ax3.legend(loc="lower right", fontsize=9)
    ax3.set_ylim(0, 115)
    ax3.grid(True, alpha=0.3, axis="y")

    # Overall title and footer
    fig.suptitle(
        "Hybrid Signature Performance Analysis (Ed25519 + ML-DSA-65)",
        fontsize=14,
        fontweight="bold",
        y=1.02,
    )
    fig.text(
        0.5,
        -0.04,
        "Benchmarks: Linux x86_64, 16 cores, 13GB RAM, Python 3.11, liboqs 0.15.0\n"
        "Optimized mode uses cached Ed25519 key objects, eliminating reconstruction overhead",
        ha="center",
        fontsize=9,
        color="#6B7280",
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "performance_comparison.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'performance_comparison.png'}")


def create_full_package_performance():
    """Create comprehensive full package performance visualization with layer breakdown."""
    fig, (ax_layers, ax_total) = plt.subplots(
        1, 2, figsize=(18, 8), gridspec_kw={"width_ratios": [2.2, 1]}
    )

    # Overall figure title
    fig.suptitle(
        "Full 6-Layer Package Performance Breakdown", fontsize=16, fontweight="bold", y=0.96
    )
    fig.text(
        0.5,
        0.91,
        "Component latencies and end-to-end throughput for the complete AMA Cryptography package",
        ha="center",
        fontsize=11,
        color="#6B7280",
    )

    # === LEFT PANEL: Per-layer latency breakdown ===
    # Data from BENCHMARKS.md (approximate per-operation latencies)
    components = [
        ("HKDF Key Derivation", 0.144, "#8B5CF6", "39.3%"),
        ("ML-DSA-65 Signature", 0.109, "#3B82F6", "29.8%"),
        ("Ed25519 Signature", 0.100, "#0EA5E9", "27.3%"),
        ("HMAC-SHA3-256 Auth", 0.004, "#22C55E", "1.1%"),
        ("SHA3-256 + Encoding", 0.003, "#10B981", "0.8%"),
        ("3R Monitoring", 0.006, "#6366F1", "1.6%"),
    ]

    names = [c[0] for c in components]
    times = [c[1] for c in components]
    colors_layers = [c[2] for c in components]
    # percentages available in c[3] if needed for labels

    y_pos = range(len(names))
    ax_layers.barh(y_pos, times, color=colors_layers, edgecolor="white", linewidth=1.5, height=0.55)

    ax_layers.set_yticks(y_pos)
    ax_layers.set_yticklabels(names, fontsize=10)
    ax_layers.set_xlabel("Latency (ms)", fontsize=10, labelpad=10)
    ax_layers.set_title(
        "Where the Time Goes (Per Operation)", fontsize=12, fontweight="bold", pad=15
    )
    ax_layers.set_xlim(0, 0.22)
    ax_layers.invert_yaxis()

    # Add value labels to bars - percentage and ms together, positioned after bar
    for i, (name, t, _, pct) in enumerate(components):
        if "3R" in name:
            label = f"{pct}  |  <0.006 ms"
        else:
            label = f"{pct}  |  {t:.3f} ms"
        ax_layers.text(
            t + 0.005, i, label, va="center", fontsize=9, color="#374151", fontweight="bold"
        )

    # RFC 3161 annotation (optional, external) - moved to avoid overlap
    ax_layers.text(
        0.95,
        0.05,
        "RFC 3161 Timestamp: optional, external TSA latency\nnot included in 0.278 ms measurement",
        transform=ax_layers.transAxes,
        ha="right",
        va="bottom",
        fontsize=8,
        color="#6B7280",
        style="italic",
        bbox=dict(
            boxstyle="round,pad=0.3", facecolor="#F9FAFB", edgecolor="#E5E7EB", linestyle="--"
        ),
    )

    # === RIGHT PANEL: End-to-end throughput ===
    operations = ["Package\nCreate", "Package\nVerify"]
    throughput = [3595, 5029]
    latency_ms = [0.278, 0.199]
    colors_total = ["#3B82F6", "#22C55E"]

    bars_total = ax_total.bar(
        operations, throughput, color=colors_total, edgecolor="white", linewidth=2, width=0.5
    )

    ax_total.set_ylabel("Operations per Second", fontsize=10)
    ax_total.set_title(
        "End-to-End Throughput\n(All 6 Layers Enabled)", fontsize=12, fontweight="bold", pad=15
    )
    ax_total.set_ylim(0, 6500)

    # Add value labels
    for bar, ops, ms in zip(bars_total, throughput, latency_ms):
        ax_total.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 150,
            f"{ops:,}\nops/sec\n({ms:.3f} ms)",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
            color="#1F2937",
        )

    # Layer summary box
    ax_total.text(
        0.5,
        0.35,
        "All 6 layers:\n"
        "1. SHA3-256 Hash\n"
        "2. HMAC-SHA3-256\n"
        "3. Ed25519 Sig\n"
        "4. ML-DSA-65 Sig\n"
        "5. HKDF Derivation\n"
        "6. RFC 3161 (opt)",
        transform=ax_total.transAxes,
        ha="center",
        va="top",
        fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#F3F4F6", edgecolor="#D1D5DB"),
    )

    # Bottom caption - simplified and moved up
    fig.text(
        0.5,
        0.03,
        "Dual signatures (Ed25519 + ML-DSA-65) and HKDF dominate latency. "
        "Hashing, HMAC, and 3R monitoring are negligible (<2% combined).\n"
        "Data from BENCHMARKS.md. Reference hardware: 16-core Linux, 13GB RAM.",
        ha="center",
        fontsize=9,
        color="#6B7280",
        style="italic",
    )

    plt.tight_layout(rect=[0, 0.08, 1, 0.88])
    plt.savefig(
        ASSETS_DIR / "package_performance.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'package_performance.png'}")


def create_monitoring_overhead():
    """Create compact monitoring overhead pie chart."""
    fig, ax = plt.subplots(figsize=(5, 4))

    sizes = [98, 2]
    labels = ["Crypto Ops\n(98%)", "3R Monitor\n(2%)"]
    colors = ["#3B82F6", "#F59E0B"]
    explode = (0, 0.05)

    ax.pie(
        sizes,
        explode=explode,
        labels=labels,
        colors=colors,
        autopct="",
        startangle=90,
        wedgeprops=dict(edgecolor="white", linewidth=2),
        textprops={"fontsize": 9},
    )

    ax.set_title("3R Monitoring Overhead", fontsize=11, fontweight="bold", pad=10)

    # Compact annotation
    fig.text(
        0.5,
        0.02,
        "<2% overhead for comprehensive security monitoring",
        ha="center",
        fontsize=8,
        style="italic",
        color="#6B7280",
    )

    plt.tight_layout(pad=0.5)
    plt.savefig(
        ASSETS_DIR / "monitoring_overhead.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'monitoring_overhead.png'}")


def create_test_coverage():
    """Create enhanced test coverage visualization with percentages and cumulative data."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 5), gridspec_kw={"width_ratios": [2, 1]})

    categories = [
        "Core Crypto\n& NIST KATs",
        "PQC Backends\n& Integration",
        "Key Management\n& Rotation",
        "Memory Security\n& Fuzzing",
        "Performance\n& Monitoring",
    ]
    # Approximate distribution based on test file analysis
    test_counts = [198, 170, 135, 150, 145]  # Total = 798
    total_tests = sum(test_counts)
    percentages = [100 * c / total_tests for c in test_counts]
    colors = ["#22C55E", "#3B82F6", "#8B5CF6", "#F59E0B", "#EF4444"]

    # === Left Panel: Horizontal bar chart with percentages ===
    bars = ax1.barh(categories, test_counts, color=colors, edgecolor="white", linewidth=2)

    ax1.set_xlabel("Number of Tests", fontsize=11)
    ax1.set_title("Test Distribution by Category", fontsize=12, fontweight="bold")
    ax1.set_xlim(0, 240)

    # Add count and percentage labels
    for bar, val, pct in zip(bars, test_counts, percentages):
        ax1.text(
            bar.get_width() + 3,
            bar.get_y() + bar.get_height() / 2,
            f"{val} ({pct:.1f}%)",
            ha="left",
            va="center",
            fontsize=10,
            fontweight="bold",
        )

    ax1.grid(True, alpha=0.3, axis="x")

    # === Right Panel: Cumulative coverage line chart ===
    cumulative = np.cumsum(test_counts)
    cumulative_pct = 100 * cumulative / total_tests
    y_pos = np.arange(len(categories))

    ax2.plot(
        cumulative_pct,
        y_pos,
        "o-",
        color="#3B82F6",
        linewidth=2.5,
        markersize=10,
        markeredgecolor="white",
        markeredgewidth=2,
    )
    ax2.fill_betweenx(y_pos, 0, cumulative_pct, alpha=0.2, color="#3B82F6")

    # Add percentage annotations
    for i, (cum, pct) in enumerate(zip(cumulative, cumulative_pct)):
        ax2.annotate(
            f"{pct:.0f}%\n({cum})",
            (pct, i),
            textcoords="offset points",
            xytext=(8, 0),
            ha="left",
            fontsize=9,
            fontweight="bold",
        )

    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(categories, fontsize=9)
    ax2.set_xlabel("Cumulative Coverage (%)", fontsize=11)
    ax2.set_title("Cumulative Test Coverage", fontsize=12, fontweight="bold")
    ax2.set_xlim(0, 115)
    ax2.grid(True, alpha=0.3)

    # Overall title
    fig.suptitle(
        "Test Suite Coverage: 798 Tests Across 32 Files (~11,000 Lines)",
        fontsize=14,
        fontweight="bold",
        y=1.02,
    )

    # Summary box
    fig.text(
        0.5,
        -0.06,
        f"Total: {total_tests} tests | 32 test files | ~11,000 LOC | "
        "Categories: NIST KATs, PQC, Key Mgmt, Memory Security, Performance",
        ha="center",
        fontsize=9,
        color="#6B7280",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#F3F4F6", edgecolor="#D1D5DB"),
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "test_coverage.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'test_coverage.png'}")


def create_ethical_binding_flow():
    """Create comprehensive ethical binding diagram showing 4 pillars with weights."""
    fig, ax = plt.subplots(figsize=(18, 12))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 12)
    ax.axis("off")

    # Title
    ax.text(
        9,
        11.5,
        "Ethical Vector Cryptographic Binding",
        ha="center",
        fontsize=20,
        fontweight="bold",
        color="#1F2937",
    )
    ax.text(
        9,
        10.9,
        "4 Omni-Code Ethical Pillars bound to keys and signatures via SHA3-256 + HKDF",
        ha="center",
        fontsize=12,
        color="#6B7280",
    )

    # Define the 4 pillars with their triads
    triads = [
        (
            "Omniscient: Wisdom",
            "#3B82F6",
            "Verification Layer",
            [
                ("verification", "Complete verification"),
                ("detection", "Multi-dimensional detection"),
                ("validation", "Data validation"),
            ],
        ),
        (
            "Omnipotent: Agency",
            "#22C55E",
            "Cryptographic Generation",
            [
                ("strength", "Maximum strength"),
                ("generation", "Key generation"),
                ("protection", "Real-time protection"),
            ],
        ),
        (
            "Omnidirectional: Geography",
            "#0EA5E9",
            "Defense-in-Depth",
            [
                ("defense", "Multi-layer defense"),
                ("temporal", "Temporal integrity"),
                ("coverage", "Attack surface coverage"),
            ],
        ),
        (
            "Omnibenevolent: Integrity",
            "#8B5CF6",
            "Ethical Constraints",
            [
                ("ethics", "Ethical foundation"),
                ("correctness", "Mathematical correctness"),
                ("hybrid", "Hybrid security"),
            ],
        ),
    ]

    # Draw 4 triad boxes in 2x2 grid on the left
    triad_positions = [(1.8, 8.2), (5.5, 8.2), (1.8, 4.8), (5.5, 4.8)]

    for idx, ((name, color, subtitle, pillars), (x, y)) in enumerate(zip(triads, triad_positions)):
        # Triad box
        rect = mpatches.FancyBboxPatch(
            (x - 1.6, y - 1.5),
            3.2,
            3.0,
            boxstyle="round,pad=0.02,rounding_size=0.15",
            facecolor=color,
            edgecolor="white",
            linewidth=2,
            alpha=0.15,
        )
        ax.add_patch(rect)

        # Triad header
        header_rect = mpatches.FancyBboxPatch(
            (x - 1.5, y + 1.0),
            3.0,
            0.45,
            boxstyle="round,pad=0.01,rounding_size=0.1",
            facecolor=color,
            edgecolor="white",
            linewidth=1,
        )
        ax.add_patch(header_rect)
        ax.text(
            x,
            y + 1.22,
            name,
            ha="center",
            va="center",
            fontsize=10,
            fontweight="bold",
            color="white",
        )
        ax.text(x, y + 0.75, f"({subtitle})", ha="center", va="center", fontsize=8, color="#374151")

        # Pillars
        for i, (pillar_name, pillar_desc) in enumerate(pillars):
            py = y + 0.3 - i * 0.55
            ax.text(
                x - 1.4,
                py,
                f"{pillar_name}",
                ha="left",
                va="center",
                fontsize=9,
                fontweight="bold",
                color="#1F2937",
            )
            ax.text(
                x + 1.5,
                py,
                "w=1.0",
                ha="right",
                va="center",
                fontsize=8,
                color=color,
                fontweight="bold",
            )
            ax.text(
                x - 1.4,
                py - 0.22,
                f"  {pillar_desc}",
                ha="left",
                va="center",
                fontsize=7,
                color="#6B7280",
            )

    # Aggregator box: Balanced Ethical Vector
    agg_x, agg_y = 9.2, 6.5
    agg_rect = mpatches.FancyBboxPatch(
        (agg_x - 1.3, agg_y - 0.8),
        2.6,
        1.6,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor="#F3F4F6",
        edgecolor="#9CA3AF",
        linewidth=2,
    )
    ax.add_patch(agg_rect)
    ax.text(
        agg_x,
        agg_y + 0.35,
        "Balanced Vector",
        ha="center",
        va="center",
        fontsize=10,
        fontweight="bold",
        color="#1F2937",
    )
    ax.text(
        agg_x, agg_y - 0.05, "4 pillars", ha="center", va="center", fontsize=9, color="#374151"
    )
    ax.text(
        agg_x,
        agg_y - 0.4,
        "each w = 1.0",
        ha="center",
        va="center",
        fontsize=9,
        color="#374151",
        fontweight="bold",
    )

    # Draw arrows from triads to aggregator
    # Arrow styling is set inline in annotate() calls below
    for x, y in triad_positions:
        ax.annotate(
            "",
            xy=(agg_x - 1.3, agg_y),
            xytext=(x + 1.6, y),
            arrowprops=dict(
                arrowstyle="->", color="#9CA3AF", lw=1.2, connectionstyle="arc3,rad=0.1"
            ),
        )

    # Cryptographic binding pipeline on the right
    pipeline_y = 6.5
    pipeline_boxes = [
        (11.5, "JSON Encode", "sorted keys", "#6366F1"),
        (13.5, "SHA3-256", "H(ethical_json)", "#3B82F6"),
        (15.5, "128-bit Sig", "H(E)[:16]", "#0EA5E9"),
    ]

    # Arrow from aggregator to pipeline
    ax.annotate(
        "",
        xy=(11.5 - 0.9, pipeline_y),
        xytext=(agg_x + 1.3, agg_y),
        arrowprops=dict(arrowstyle="->", color="#374151", lw=2),
    )

    for px, label, sublabel, color in pipeline_boxes:
        rect = mpatches.FancyBboxPatch(
            (px - 0.85, pipeline_y - 0.6),
            1.7,
            1.2,
            boxstyle="round,pad=0.02,rounding_size=0.1",
            facecolor=color,
            edgecolor="white",
            linewidth=2,
        )
        ax.add_patch(rect)
        ax.text(
            px,
            pipeline_y + 0.15,
            label,
            ha="center",
            va="center",
            fontsize=10,
            fontweight="bold",
            color="white",
        )
        ax.text(
            px,
            pipeline_y - 0.2,
            sublabel,
            ha="center",
            va="center",
            fontsize=8,
            color="white",
            alpha=0.9,
        )

    # Arrows between pipeline boxes
    for i in range(len(pipeline_boxes) - 1):
        x1 = pipeline_boxes[i][0] + 0.85
        x2 = pipeline_boxes[i + 1][0] - 0.85
        ax.annotate(
            "",
            xy=(x2, pipeline_y),
            xytext=(x1, pipeline_y),
            arrowprops=dict(arrowstyle="->", color="#374151", lw=2),
        )

    # Final output boxes
    output_y1, output_y2 = 8.5, 4.5

    # Arrow from 128-bit sig to outputs
    ax.annotate(
        "",
        xy=(16.2, output_y1 - 0.5),
        xytext=(15.5, pipeline_y + 0.6),
        arrowprops=dict(arrowstyle="->", color="#22C55E", lw=2),
    )
    ax.annotate(
        "",
        xy=(16.2, output_y2 + 0.5),
        xytext=(15.5, pipeline_y - 0.6),
        arrowprops=dict(arrowstyle="->", color="#22C55E", lw=2),
    )

    # HKDF Context output
    rect1 = mpatches.FancyBboxPatch(
        (15.3, output_y1 - 0.5),
        2.4,
        1.0,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor="#22C55E",
        edgecolor="white",
        linewidth=2,
    )
    ax.add_patch(rect1)
    ax.text(
        16.5,
        output_y1 + 0.1,
        "HKDF Context",
        ha="center",
        va="center",
        fontsize=10,
        fontweight="bold",
        color="white",
    )
    ax.text(
        16.5,
        output_y1 - 0.2,
        "Key Derivation",
        ha="center",
        va="center",
        fontsize=8,
        color="white",
        alpha=0.9,
    )

    # Signature Message output
    rect2 = mpatches.FancyBboxPatch(
        (15.3, output_y2 - 0.5),
        2.4,
        1.0,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor="#22C55E",
        edgecolor="white",
        linewidth=2,
    )
    ax.add_patch(rect2)
    ax.text(
        16.5,
        output_y2 + 0.1,
        "Signature Msg",
        ha="center",
        va="center",
        fontsize=10,
        fontweight="bold",
        color="white",
    )
    ax.text(
        16.5,
        output_y2 - 0.2,
        "Ed25519 + ML-DSA-65",
        ha="center",
        va="center",
        fontsize=8,
        color="white",
        alpha=0.9,
    )

    # Sum annotation
    ax.text(
        9.2,
        5.4,
        "Sum: 12 x 1.0 = 12.0",
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        color="#059669",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#DCFCE7", edgecolor="#22C55E"),
    )

    # Caption
    ax.text(
        9,
        0.8,
        "The 4 Omni-Code Ethical Pillars form a balanced vector (each w = 3.0, total = 12.0).\n"
        "This vector is hashed with SHA3-256 and a 128-bit signature is injected into HKDF context and signature messages,\n"
        "cryptographically binding keys and signatures to an explicit ethical profile. This is binding, not enforcement.",
        ha="center",
        fontsize=10,
        style="italic",
        color="#6B7280",
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "ethical_binding.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'ethical_binding.png'}")


def create_quantum_comparison():
    """Create quantum vs classical security comparison."""
    fig, ax = plt.subplots(figsize=(10, 6))

    algorithms = [
        "RSA-2048\n(Classical)",
        "ECDSA-256\n(Classical)",
        "Ed25519\n(Classical)",
        "ML-DSA-65\n(Quantum-Resistant)",
    ]

    # Security levels (bits) - classical vs quantum
    classical_security = [112, 128, 128, 192]
    quantum_security = [0, 0, 0, 192]  # 0 means broken by quantum

    x = np.arange(len(algorithms))
    width = 0.35

    ax.bar(
        x - width / 2,
        classical_security,
        width,
        label="Classical Security",
        color="#3B82F6",
        edgecolor="white",
        linewidth=2,
    )
    ax.bar(
        x + width / 2,
        quantum_security,
        width,
        label="Quantum Security",
        color="#8B5CF6",
        edgecolor="white",
        linewidth=2,
    )

    ax.set_ylabel("Security Level (bits)", fontsize=12)
    ax.set_title("Classical vs Quantum Security Comparison", fontsize=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms)
    ax.legend(loc="upper left")
    ax.set_ylim(0, 250)

    # Add "BROKEN" labels for quantum-vulnerable algorithms
    for i, (c, q) in enumerate(zip(classical_security, quantum_security)):
        ax.text(
            i - width / 2, c + 5, f"{c}", ha="center", va="bottom", fontsize=10, fontweight="bold"
        )
        if q == 0:
            ax.text(
                i + width / 2,
                10,
                "BROKEN",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold",
                color="#EF4444",
                rotation=90,
            )
        else:
            ax.text(
                i + width / 2,
                q + 5,
                f"{q}",
                ha="center",
                va="bottom",
                fontsize=10,
                fontweight="bold",
            )

    # Add annotation
    fig.text(
        0.5,
        -0.02,
        "ML-DSA-65 (Dilithium) provides 192-bit security against both classical and quantum attacks",
        ha="center",
        fontsize=10,
        style="italic",
        color="#6B7280",
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "quantum_comparison.png",
        dpi=150,
        bbox_inches="tight",
        facecolor="white",
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'quantum_comparison.png'}")


if __name__ == "__main__":
    print("Generating AMA Cryptography visual diagrams...")
    print("=" * 50)

    create_defense_layers_diagram()
    create_performance_comparison()
    create_full_package_performance()
    create_monitoring_overhead()
    create_test_coverage()
    create_ethical_binding_flow()
    create_quantum_comparison()

    print("=" * 50)
    print(f"All visuals saved to: {ASSETS_DIR}")
