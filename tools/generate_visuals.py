#!/usr/bin/env python3
"""
Generate visual diagrams for AMA Cryptography documentation.

Creates professional STEM/cryptography-aligned visualizations with a
consistent dark theme matching benchmark_report.png and performance_dashboard.png.

Creates:
1. 4-Layer Defense-in-Depth diagram
2. Performance comparison charts
3. Full package performance breakdown
4. Monitoring overhead gauge
5. Test coverage visualization
6. Ethical vector binding flow
7. Quantum security comparison
"""

from pathlib import Path

import matplotlib
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np

matplotlib.use("Agg")

# -- Professional dark theme (matching benchmark_report.png) -----------------
DARK_BG = "#1a1a2e"
PANEL_BG = "#16213e"
TEXT_COLOR = "#e0e0e0"
GRID_COLOR = "#2a2a4a"
MUTED_TEXT = "#8899aa"
ACCENT_CYAN = "#00d2ff"
ACCENT_PURPLE = "#7b2ff7"
ACCENT_BLUE = "#4d96ff"
ACCENT_GREEN = "#6bcb77"
ACCENT_YELLOW = "#ffd93d"
ACCENT_RED = "#ff6b6b"
ACCENT_ORANGE = "#ff922b"
ACCENT_TEAL = "#14b8a6"
ACCENT_INDIGO = "#845ef7"

LAYER_COLORS = [
    ACCENT_CYAN,
    ACCENT_TEAL,
    ACCENT_BLUE,
    ACCENT_PURPLE,
    ACCENT_INDIGO,
    "#b845ef",
]


def apply_dark_theme() -> None:
    """Apply the professional dark STEM theme globally."""
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


apply_dark_theme()

ASSETS_DIR = Path(__file__).parent.parent / "assets"
ASSETS_DIR.mkdir(exist_ok=True)


def create_defense_layers_diagram() -> None:
    """Create the 4-layer defense-in-depth visualization with dark theme."""
    fig, ax = plt.subplots(figsize=(16, 10))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 12)
    ax.axis("off")

    layers = [
        (
            "Layer 1: SHA3-256 Content Hash",
            ACCENT_CYAN,
            "Quantum-resistant 256-bit hash of canonical data",
            "FIPS 202 \u2022 Keccak sponge \u2022 AVX2/NEON accelerated",
        ),
        (
            "Layer 2: HMAC-SHA3-256 Authentication",
            ACCENT_TEAL,
            "Keyed hash for tamper detection & origin auth",
            "RFC 2104 \u2022 Ethical context binding \u2022 Side-channel safe",
        ),
        (
            "Layer 3: Ed25519 + ML-DSA-65 Dual Signatures",
            ACCENT_RED,
            "Classical + post-quantum hybrid signature scheme",
            "FIPS 186-5 + FIPS 204 \u2022 128-bit classical + 192-bit PQ security",
        ),
        (
            "Layer 4: HKDF-SHA3-256 Key Derivation",
            ACCENT_GREEN,
            "Deterministic key re-derivation for verification",
            "RFC 5869 \u2022 Ethical pillar binding \u2022 Empty-key guard (S1 fix)",
        ),
    ]

    ax.text(
        8,
        11.5,
        "AMA Cryptography \u2014 4-Layer Defense Architecture",
        ha="center",
        fontsize=20,
        fontweight="bold",
        color=TEXT_COLOR,
    )
    ax.text(
        8,
        10.8,
        "Quantum-Resistant Integrity Protection Pipeline",
        ha="center",
        fontsize=12,
        style="italic",
        color=MUTED_TEXT,
    )

    y_start = 9.5
    layer_height = 1.8

    for i, (name, color, desc, standards) in enumerate(layers):
        y = y_start - i * layer_height

        glow = mpatches.FancyBboxPatch(
            (2.2, y - 0.65),
            11.6,
            1.3,
            boxstyle="round,pad=0.02,rounding_size=0.15",
            facecolor=color,
            edgecolor=color,
            linewidth=2,
            alpha=0.15,
        )
        ax.add_patch(glow)

        border = mpatches.FancyBboxPatch(
            (2.2, y - 0.65),
            11.6,
            1.3,
            boxstyle="round,pad=0.02,rounding_size=0.15",
            facecolor="none",
            edgecolor=color,
            linewidth=2,
        )
        ax.add_patch(border)

        circle = plt.Circle((3.2, y), 0.4, color=color, alpha=0.8)
        ax.add_patch(circle)
        ax.text(
            3.2,
            y,
            str(i + 1),
            ha="center",
            va="center",
            fontsize=16,
            fontweight="bold",
            color="white",
        )

        ax.text(
            4.2,
            y + 0.2,
            name,
            ha="left",
            va="center",
            fontsize=13,
            fontweight="bold",
            color=color,
        )
        ax.text(4.2, y - 0.15, desc, ha="left", va="center", fontsize=10, color=TEXT_COLOR)
        ax.text(
            4.2,
            y - 0.45,
            standards,
            ha="left",
            va="center",
            fontsize=9,
            style="italic",
            color=MUTED_TEXT,
        )

        if i < len(layers) - 1:
            ax.annotate(
                "",
                xy=(8, y - 0.75),
                xytext=(8, y - 1.05),
                arrowprops=dict(arrowstyle="->", color=MUTED_TEXT, lw=2),
            )

    y_opt = y_start - len(layers) * layer_height + 0.2
    ax.plot([3, 13], [y_opt, y_opt], "--", color=MUTED_TEXT, alpha=0.5, linewidth=1)
    ax.text(
        8,
        y_opt - 0.4,
        "Optional: RFC 3161 Timestamp (TSA integration)",
        ha="center",
        fontsize=10,
        style="italic",
        color=ACCENT_YELLOW,
    )

    ax.text(
        8,
        0.3,
        "SIMD Acceleration: AVX2 (x86-64) | NEON (AArch64) | SVE2 (ARMv9)  \u2022  "
        "Zero external dependencies  \u2022  FIPS 202/203/204/205 compliant",
        ha="center",
        fontsize=9,
        color=MUTED_TEXT,
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "defense_layers.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'defense_layers.png'}")


def create_performance_comparison() -> None:
    """Create advanced multi-factor performance comparison with dark theme."""
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.patch.set_facecolor(DARK_BG)

    implementations = [
        "AMA Crypto\n(Standard)",
        "AMA Crypto\n(Optimized)",
        "OpenSSL+liboqs",
    ]
    x_pos = np.arange(len(implementations))

    sign_throughput = [4575, 6500, 6209]
    verify_throughput = [6192, 6700, 6721]
    sign_latency = [1000 / v for v in sign_throughput]
    verify_latency = [1000 / v for v in verify_throughput]
    sign_relative = [100 * v / sign_throughput[2] for v in sign_throughput]
    verify_relative = [100 * v / verify_throughput[2] for v in verify_throughput]

    # Panel 1: Throughput
    ax1 = axes[0]
    ax1.plot(
        x_pos,
        sign_throughput,
        "o-",
        color=ACCENT_CYAN,
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
        color=ACCENT_GREEN,
        linewidth=2.5,
        markersize=10,
        label="Hybrid Verify",
        markeredgecolor="white",
        markeredgewidth=2,
    )
    for i, (s, v) in enumerate(zip(sign_throughput, verify_throughput)):
        ax1.annotate(
            f"{s:,}",
            (i, s),
            textcoords="offset points",
            xytext=(0, 12),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color=ACCENT_CYAN,
        )
        ax1.annotate(
            f"{v:,}",
            (i, v),
            textcoords="offset points",
            xytext=(0, -18),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color=ACCENT_GREEN,
        )
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(implementations, fontsize=9)
    ax1.set_ylabel("Operations per Second", fontsize=11)
    ax1.set_title(
        "Throughput Comparison\n(Higher is Better)",
        fontsize=12,
        fontweight="bold",
    )
    ax1.legend(loc="lower right", fontsize=9)
    ax1.set_ylim(3500, 7500)

    # Panel 2: Latency
    ax2 = axes[1]
    ax2.plot(
        x_pos,
        sign_latency,
        "o-",
        color=ACCENT_CYAN,
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
        color=ACCENT_GREEN,
        linewidth=2.5,
        markersize=10,
        label="Verify Latency",
        markeredgecolor="white",
        markeredgewidth=2,
    )
    for j, (sl, vl) in enumerate(zip(sign_latency, verify_latency)):
        ax2.annotate(
            f"{sl:.3f}ms",
            (j, sl),
            textcoords="offset points",
            xytext=(0, 12),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color=ACCENT_CYAN,
        )
        ax2.annotate(
            f"{vl:.3f}ms",
            (j, vl),
            textcoords="offset points",
            xytext=(0, -18),
            ha="center",
            fontsize=9,
            fontweight="bold",
            color=ACCENT_GREEN,
        )
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(implementations, fontsize=9)
    ax2.set_ylabel("Latency (milliseconds)", fontsize=11)
    ax2.set_title("Latency Comparison\n(Lower is Better)", fontsize=12, fontweight="bold")
    ax2.legend(loc="upper right", fontsize=9)
    ax2.set_ylim(0.1, 0.25)

    # Panel 3: Relative performance
    ax3 = axes[2]
    width = 0.35
    bars1 = ax3.bar(
        x_pos - width / 2,
        sign_relative,
        width,
        color=ACCENT_CYAN,
        label="Sign",
        edgecolor="none",
    )
    bars2 = ax3.bar(
        x_pos + width / 2,
        verify_relative,
        width,
        color=ACCENT_GREEN,
        label="Verify",
        edgecolor="none",
    )
    for bar, val in zip(bars1, sign_relative):
        ax3.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{val:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="bold",
            color=ACCENT_CYAN,
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
            color=ACCENT_GREEN,
        )
    ax3.axhline(y=100, color=ACCENT_YELLOW, linestyle="--", linewidth=1.5, alpha=0.7)
    ax3.text(
        2.4,
        101,
        "OpenSSL+liboqs baseline",
        fontsize=8,
        color=ACCENT_YELLOW,
        va="bottom",
    )
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(implementations, fontsize=9)
    ax3.set_ylabel("Relative Performance (%)", fontsize=11)
    ax3.set_title(
        "Performance vs OpenSSL+liboqs\n(100% = Baseline)",
        fontsize=12,
        fontweight="bold",
    )
    ax3.legend(loc="lower right", fontsize=9)
    ax3.set_ylim(0, 115)

    fig.suptitle(
        "Hybrid Signature Performance Analysis (Ed25519 + ML-DSA-65)",
        fontsize=14,
        fontweight="bold",
        y=1.02,
        color=TEXT_COLOR,
    )
    fig.text(
        0.5,
        -0.04,
        "Benchmarks: Linux x86_64, 16 cores, 13GB RAM, Python 3.11, liboqs 0.15.0\n"
        "Optimized mode uses cached Ed25519 key objects, eliminating "
        "reconstruction overhead",
        ha="center",
        fontsize=9,
        color=MUTED_TEXT,
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "performance_comparison.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'performance_comparison.png'}")


def create_full_package_performance() -> None:
    """Create comprehensive package performance visualization with dark theme."""
    fig, (ax_layers, ax_total) = plt.subplots(
        1,
        2,
        figsize=(18, 8),
        gridspec_kw={"width_ratios": [2.2, 1]},
    )
    fig.patch.set_facecolor(DARK_BG)

    fig.suptitle(
        "Full 4-Layer Package Performance Breakdown",
        fontsize=16,
        fontweight="bold",
        y=0.96,
        color=TEXT_COLOR,
    )
    fig.text(
        0.5,
        0.91,
        "Component latencies and end-to-end throughput for the complete "
        "AMA Cryptography package",
        ha="center",
        fontsize=11,
        color=MUTED_TEXT,
    )

    components = [
        ("HKDF Key Derivation", 0.144, ACCENT_PURPLE, "39.3%"),
        ("ML-DSA-65 Signature", 0.109, ACCENT_BLUE, "29.8%"),
        ("Ed25519 Signature", 0.100, ACCENT_CYAN, "27.3%"),
        ("HMAC-SHA3-256 Auth", 0.004, ACCENT_GREEN, "1.1%"),
        ("SHA3-256 + Encoding", 0.003, ACCENT_TEAL, "0.8%"),
        ("3R Monitoring", 0.006, ACCENT_INDIGO, "1.6%"),
    ]

    names = [c[0] for c in components]
    times = [c[1] for c in components]
    colors_layers = [c[2] for c in components]

    y_pos = range(len(names))
    ax_layers.barh(y_pos, times, color=colors_layers, edgecolor="none", height=0.55)
    ax_layers.set_yticks(y_pos)
    ax_layers.set_yticklabels(names, fontsize=10)
    ax_layers.set_xlabel("Latency (ms)", fontsize=10, labelpad=10)
    ax_layers.set_title(
        "Where the Time Goes (Per Operation)",
        fontsize=12,
        fontweight="bold",
        pad=15,
    )
    ax_layers.set_xlim(0, 0.22)
    ax_layers.invert_yaxis()

    for i, (name, t, _, pct) in enumerate(components):
        if "3R" in name:
            label = f"{pct}  |  <0.006 ms"
        else:
            label = f"{pct}  |  {t:.3f} ms"
        ax_layers.text(
            t + 0.005,
            i,
            label,
            va="center",
            fontsize=9,
            color=TEXT_COLOR,
            fontweight="bold",
        )

    ax_layers.text(
        0.95,
        0.05,
        "RFC 3161 Timestamp: optional, external TSA latency\n"
        "not included in 0.278 ms measurement",
        transform=ax_layers.transAxes,
        ha="right",
        va="bottom",
        fontsize=8,
        color=MUTED_TEXT,
        style="italic",
        bbox=dict(
            boxstyle="round,pad=0.3",
            facecolor=PANEL_BG,
            edgecolor=GRID_COLOR,
            linestyle="--",
        ),
    )

    operations = ["Package\nCreate", "Package\nVerify"]
    throughput = [3595, 5029]
    latency_ms = [0.278, 0.199]
    colors_total = [ACCENT_BLUE, ACCENT_GREEN]

    bars_total = ax_total.bar(
        operations, throughput, color=colors_total, edgecolor="none", width=0.5
    )
    ax_total.set_ylabel("Operations per Second", fontsize=10)
    ax_total.set_title(
        "End-to-End Throughput\n(All 4 Layers Enabled)",
        fontsize=12,
        fontweight="bold",
        pad=15,
    )
    ax_total.set_ylim(0, 6500)

    for bar, ops, ms in zip(bars_total, throughput, latency_ms):
        ax_total.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 150,
            f"{ops:,}\nops/sec\n({ms:.3f} ms)",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
            color=TEXT_COLOR,
        )

    ax_total.text(
        0.5,
        0.35,
        "All 4 layers:\n1. SHA3-256 Hash\n2. HMAC-SHA3-256\n"
        "3. Ed25519 Sig\n4. ML-DSA-65 Sig\n5. HKDF Derivation\n"
        "6. RFC 3161 (opt)",
        transform=ax_total.transAxes,
        ha="center",
        va="top",
        fontsize=9,
        bbox=dict(
            boxstyle="round,pad=0.4",
            facecolor=PANEL_BG,
            edgecolor=GRID_COLOR,
        ),
    )

    fig.text(
        0.5,
        0.03,
        "Dual signatures (Ed25519 + ML-DSA-65) and HKDF dominate latency. "
        "Hashing, HMAC, and 3R monitoring are negligible (<2% combined).\n"
        "Data from BENCHMARKS.md. Reference hardware: 16-core Linux, 13GB RAM.",
        ha="center",
        fontsize=9,
        color=MUTED_TEXT,
        style="italic",
    )

    plt.tight_layout(rect=[0, 0.08, 1, 0.88])
    plt.savefig(
        ASSETS_DIR / "package_performance.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'package_performance.png'}")


def create_monitoring_overhead() -> None:
    """Create monitoring overhead donut chart with dark theme."""
    fig, ax = plt.subplots(figsize=(6, 5))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)

    sizes = [98, 2]
    labels = ["Crypto Ops\n(98%)", "3R Monitor\n(2%)"]
    colors = [ACCENT_BLUE, ACCENT_ORANGE]
    explode = (0, 0.08)

    wedges, texts = ax.pie(
        sizes,
        explode=explode,
        labels=labels,
        colors=colors,
        startangle=90,
        wedgeprops=dict(edgecolor=DARK_BG, linewidth=3, width=0.55),
        textprops={"fontsize": 10, "color": TEXT_COLOR, "fontweight": "bold"},
    )

    ax.text(
        0,
        0,
        "<2%\nOverhead",
        ha="center",
        va="center",
        fontsize=14,
        fontweight="bold",
        color=ACCENT_YELLOW,
    )

    ax.set_title(
        "3R Monitoring Overhead",
        fontsize=13,
        fontweight="bold",
        pad=15,
        color=TEXT_COLOR,
    )

    fig.text(
        0.5,
        0.02,
        "Comprehensive security monitoring with negligible performance impact",
        ha="center",
        fontsize=9,
        style="italic",
        color=MUTED_TEXT,
    )

    plt.tight_layout(pad=0.5)
    plt.savefig(
        ASSETS_DIR / "monitoring_overhead.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'monitoring_overhead.png'}")


def create_test_coverage() -> None:
    """Create test coverage visualization with dark theme."""
    fig, (ax1, ax2) = plt.subplots(
        1,
        2,
        figsize=(16, 5),
        gridspec_kw={"width_ratios": [2, 1]},
    )
    fig.patch.set_facecolor(DARK_BG)

    categories = [
        "Core Crypto\n& NIST KATs",
        "PQC Backends\n& Integration",
        "Key Management\n& Rotation",
        "Memory Security\n& Fuzzing",
        "Performance\n& Monitoring",
    ]
    test_counts = [225, 186, 148, 166, 141]
    total_tests = sum(test_counts)
    percentages = [100 * c / total_tests for c in test_counts]
    cat_colors = [
        ACCENT_GREEN,
        ACCENT_BLUE,
        ACCENT_PURPLE,
        ACCENT_ORANGE,
        ACCENT_RED,
    ]

    bars = ax1.barh(categories, test_counts, color=cat_colors, edgecolor="none")
    ax1.set_xlabel("Number of Tests", fontsize=11)
    ax1.set_title("Test Distribution by Category", fontsize=12, fontweight="bold")
    ax1.set_xlim(0, 280)

    for bar, val, pct in zip(bars, test_counts, percentages):
        ax1.text(
            bar.get_width() + 3,
            bar.get_y() + bar.get_height() / 2,
            f"{val} ({pct:.1f}%)",
            ha="left",
            va="center",
            fontsize=10,
            fontweight="bold",
            color=TEXT_COLOR,
        )

    cumulative = np.cumsum(test_counts)
    cumulative_pct = 100 * cumulative / total_tests
    y_pos = np.arange(len(categories))

    ax2.plot(
        cumulative_pct,
        y_pos,
        "o-",
        color=ACCENT_CYAN,
        linewidth=2.5,
        markersize=10,
        markeredgecolor="white",
        markeredgewidth=2,
    )
    ax2.fill_betweenx(y_pos, 0, cumulative_pct, alpha=0.15, color=ACCENT_CYAN)

    for i, (cum, pct) in enumerate(zip(cumulative, cumulative_pct)):
        ax2.annotate(
            f"{pct:.0f}%\n({cum})",
            (pct, i),
            textcoords="offset points",
            xytext=(8, 0),
            ha="left",
            fontsize=9,
            fontweight="bold",
            color=ACCENT_CYAN,
        )

    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(categories, fontsize=9)
    ax2.set_xlabel("Cumulative Coverage (%)", fontsize=11)
    ax2.set_title("Cumulative Test Coverage", fontsize=12, fontweight="bold")
    ax2.set_xlim(0, 115)

    fig.suptitle(
        f"Test Suite Coverage: {total_tests} Tests Across 32 Files " "(~11,000 Lines)",
        fontsize=14,
        fontweight="bold",
        y=1.02,
        color=TEXT_COLOR,
    )

    fig.text(
        0.5,
        -0.06,
        f"Total: {total_tests} tests | 32 test files | ~11,000 LOC | "
        "Categories: NIST KATs, PQC, Key Mgmt, Memory Security, Performance",
        ha="center",
        fontsize=9,
        color=MUTED_TEXT,
        bbox=dict(
            boxstyle="round,pad=0.4",
            facecolor=PANEL_BG,
            edgecolor=GRID_COLOR,
        ),
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "test_coverage.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'test_coverage.png'}")


def create_ethical_binding_flow() -> None:
    """Create ethical binding diagram with dark theme."""
    fig, ax = plt.subplots(figsize=(18, 12))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 12)
    ax.axis("off")

    ax.text(
        9,
        11.5,
        "Ethical Vector Cryptographic Binding",
        ha="center",
        fontsize=20,
        fontweight="bold",
        color=TEXT_COLOR,
    )
    ax.text(
        9,
        10.9,
        "4 Omni-Code Ethical Pillars bound to keys and signatures " "via SHA3-256 + HKDF",
        ha="center",
        fontsize=12,
        color=MUTED_TEXT,
    )

    triads = [
        (
            "Omniscient: Wisdom",
            ACCENT_BLUE,
            "Verification Layer",
            [
                ("verification", "Complete verification"),
                ("detection", "Multi-dimensional detection"),
                ("validation", "Data validation"),
            ],
        ),
        (
            "Omnipotent: Agency",
            ACCENT_GREEN,
            "Cryptographic Generation",
            [
                ("strength", "Maximum strength"),
                ("generation", "Key generation"),
                ("protection", "Real-time protection"),
            ],
        ),
        (
            "Omnidirectional: Geography",
            ACCENT_CYAN,
            "Defense-in-Depth",
            [
                ("defense", "Multi-layer defense"),
                ("temporal", "Temporal integrity"),
                ("coverage", "Attack surface coverage"),
            ],
        ),
        (
            "Omnibenevolent: Integrity",
            ACCENT_PURPLE,
            "Ethical Constraints",
            [
                ("ethics", "Ethical foundation"),
                ("correctness", "Mathematical correctness"),
                ("hybrid", "Hybrid security"),
            ],
        ),
    ]

    triad_positions = [(1.8, 8.2), (5.5, 8.2), (1.8, 4.8), (5.5, 4.8)]

    for idx, ((name, color, subtitle, pillars), (tx, ty)) in enumerate(
        zip(triads, triad_positions)
    ):
        rect = mpatches.FancyBboxPatch(
            (tx - 1.6, ty - 1.5),
            3.2,
            3.0,
            boxstyle="round,pad=0.02,rounding_size=0.15",
            facecolor=color,
            edgecolor=color,
            linewidth=1,
            alpha=0.1,
        )
        ax.add_patch(rect)

        bdr = mpatches.FancyBboxPatch(
            (tx - 1.6, ty - 1.5),
            3.2,
            3.0,
            boxstyle="round,pad=0.02,rounding_size=0.15",
            facecolor="none",
            edgecolor=color,
            linewidth=1.5,
            alpha=0.6,
        )
        ax.add_patch(bdr)

        header_rect = mpatches.FancyBboxPatch(
            (tx - 1.5, ty + 1.0),
            3.0,
            0.45,
            boxstyle="round,pad=0.01,rounding_size=0.1",
            facecolor=color,
            edgecolor="none",
            linewidth=1,
            alpha=0.85,
        )
        ax.add_patch(header_rect)
        ax.text(
            tx,
            ty + 1.22,
            name,
            ha="center",
            va="center",
            fontsize=10,
            fontweight="bold",
            color="white",
        )
        ax.text(
            tx,
            ty + 0.75,
            f"({subtitle})",
            ha="center",
            va="center",
            fontsize=8,
            color=MUTED_TEXT,
        )

        for i, (pillar_name, pillar_desc) in enumerate(pillars):
            py = ty + 0.3 - i * 0.55
            ax.text(
                tx - 1.4,
                py,
                pillar_name,
                ha="left",
                va="center",
                fontsize=9,
                fontweight="bold",
                color=TEXT_COLOR,
            )
            ax.text(
                tx + 1.5,
                py,
                "w=1.0",
                ha="right",
                va="center",
                fontsize=8,
                color=color,
                fontweight="bold",
            )
            ax.text(
                tx - 1.4,
                py - 0.22,
                f"  {pillar_desc}",
                ha="left",
                va="center",
                fontsize=7,
                color=MUTED_TEXT,
            )

    # Aggregation box
    agg_x, agg_y = 9.2, 6.5
    agg_rect = mpatches.FancyBboxPatch(
        (agg_x - 1.3, agg_y - 0.8),
        2.6,
        1.6,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor=PANEL_BG,
        edgecolor=MUTED_TEXT,
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
        color=TEXT_COLOR,
    )
    ax.text(
        agg_x,
        agg_y - 0.05,
        "4 pillars",
        ha="center",
        va="center",
        fontsize=9,
        color=MUTED_TEXT,
    )
    ax.text(
        agg_x,
        agg_y - 0.4,
        "each w = 1.0",
        ha="center",
        va="center",
        fontsize=9,
        color=TEXT_COLOR,
        fontweight="bold",
    )

    for tx, ty in triad_positions:
        ax.annotate(
            "",
            xy=(agg_x - 1.3, agg_y),
            xytext=(tx + 1.6, ty),
            arrowprops=dict(
                arrowstyle="->",
                color=MUTED_TEXT,
                lw=1.2,
                connectionstyle="arc3,rad=0.1",
            ),
        )

    # Processing pipeline
    pipeline_y = 6.5
    pipeline_boxes = [
        (11.5, "JSON Encode", "sorted keys", ACCENT_INDIGO),
        (13.5, "SHA3-256", "H(ethical_json)", ACCENT_BLUE),
        (15.5, "128-bit Sig", "H(E)[:16]", ACCENT_CYAN),
    ]

    ax.annotate(
        "",
        xy=(11.5 - 0.9, pipeline_y),
        xytext=(agg_x + 1.3, agg_y),
        arrowprops=dict(arrowstyle="->", color=TEXT_COLOR, lw=2),
    )

    for px, label, sublabel, pcolor in pipeline_boxes:
        prect = mpatches.FancyBboxPatch(
            (px - 0.85, pipeline_y - 0.6),
            1.7,
            1.2,
            boxstyle="round,pad=0.02,rounding_size=0.1",
            facecolor=pcolor,
            edgecolor="none",
            linewidth=2,
            alpha=0.85,
        )
        ax.add_patch(prect)
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

    for i in range(len(pipeline_boxes) - 1):
        x1 = pipeline_boxes[i][0] + 0.85
        x2 = pipeline_boxes[i + 1][0] - 0.85
        ax.annotate(
            "",
            xy=(x2, pipeline_y),
            xytext=(x1, pipeline_y),
            arrowprops=dict(arrowstyle="->", color=TEXT_COLOR, lw=2),
        )

    output_y1, output_y2 = 8.5, 4.5

    ax.annotate(
        "",
        xy=(16.2, output_y1 - 0.5),
        xytext=(15.5, pipeline_y + 0.6),
        arrowprops=dict(arrowstyle="->", color=ACCENT_GREEN, lw=2),
    )
    ax.annotate(
        "",
        xy=(16.2, output_y2 + 0.5),
        xytext=(15.5, pipeline_y - 0.6),
        arrowprops=dict(arrowstyle="->", color=ACCENT_GREEN, lw=2),
    )

    rect1 = mpatches.FancyBboxPatch(
        (15.3, output_y1 - 0.5),
        2.4,
        1.0,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor=ACCENT_GREEN,
        edgecolor="none",
        linewidth=2,
        alpha=0.85,
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

    rect2 = mpatches.FancyBboxPatch(
        (15.3, output_y2 - 0.5),
        2.4,
        1.0,
        boxstyle="round,pad=0.02,rounding_size=0.1",
        facecolor=ACCENT_TEAL,
        edgecolor="none",
        linewidth=2,
        alpha=0.85,
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

    ax.text(
        9.2,
        5.4,
        "Sum: 12 x 1.0 = 12.0",
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        color=ACCENT_GREEN,
        bbox=dict(
            boxstyle="round,pad=0.3",
            facecolor=PANEL_BG,
            edgecolor=ACCENT_GREEN,
        ),
    )

    ax.text(
        9,
        0.8,
        "The 4 Omni-Code Ethical Pillars form a balanced vector "
        "(each w = 3.0, total = 12.0).\n"
        "This vector is hashed with SHA3-256 and a 128-bit signature "
        "is injected into HKDF context and signature messages,\n"
        "cryptographically binding keys and signatures to an explicit "
        "ethical profile. This is binding, not enforcement.",
        ha="center",
        fontsize=10,
        style="italic",
        color=MUTED_TEXT,
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "ethical_binding.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'ethical_binding.png'}")


def create_quantum_comparison() -> None:
    """Create quantum vs classical security comparison with dark theme."""
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor(DARK_BG)

    algorithms = [
        "RSA-2048\n(Classical)",
        "ECDSA-256\n(Classical)",
        "Ed25519\n(Classical)",
        "ML-DSA-65\n(Quantum-Resistant)",
    ]

    classical_security = [112, 128, 128, 192]
    quantum_security = [0, 0, 0, 192]

    x = np.arange(len(algorithms))
    width = 0.35

    ax.bar(
        x - width / 2,
        classical_security,
        width,
        label="Classical Security",
        color=ACCENT_BLUE,
        edgecolor="none",
    )
    ax.bar(
        x + width / 2,
        quantum_security,
        width,
        label="Quantum Security",
        color=ACCENT_PURPLE,
        edgecolor="none",
    )

    ax.set_ylabel("Security Level (bits)", fontsize=12)
    ax.set_title(
        "Classical vs Quantum Security Comparison",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms)
    ax.legend(loc="upper left")
    ax.set_ylim(0, 250)

    for i, (c, q) in enumerate(zip(classical_security, quantum_security)):
        ax.text(
            i - width / 2,
            c + 5,
            f"{c}",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
            color=ACCENT_CYAN,
        )
        if q == 0:
            ax.text(
                i + width / 2,
                10,
                "BROKEN",
                ha="center",
                va="bottom",
                fontsize=10,
                fontweight="bold",
                color=ACCENT_RED,
                rotation=90,
            )
        else:
            ax.text(
                i + width / 2,
                q + 5,
                f"{q}",
                ha="center",
                va="bottom",
                fontsize=11,
                fontweight="bold",
                color=ACCENT_PURPLE,
            )

    ax.annotate(
        "192-bit security\nagainst quantum attacks",
        xy=(3 + width / 2, 192),
        xytext=(3 + 0.6, 230),
        fontsize=9,
        fontweight="bold",
        color=ACCENT_YELLOW,
        arrowprops=dict(arrowstyle="->", color=ACCENT_YELLOW, lw=1.5),
        ha="center",
    )

    fig.text(
        0.5,
        -0.02,
        "ML-DSA-65 (Dilithium) provides 192-bit security against "
        "both classical and quantum attacks",
        ha="center",
        fontsize=10,
        style="italic",
        color=ACCENT_YELLOW,
    )

    plt.tight_layout()
    plt.savefig(
        ASSETS_DIR / "quantum_comparison.png",
        dpi=150,
        bbox_inches="tight",
        facecolor=DARK_BG,
        edgecolor="none",
    )
    plt.close()
    print(f"Created: {ASSETS_DIR / 'quantum_comparison.png'}")


if __name__ == "__main__":
    print("Generating AMA Cryptography visual diagrams (dark STEM theme)...")
    print("=" * 60)

    create_defense_layers_diagram()
    create_performance_comparison()
    create_full_package_performance()
    create_monitoring_overhead()
    create_test_coverage()
    create_ethical_binding_flow()
    create_quantum_comparison()

    print("=" * 60)
    print(f"All visuals saved to: {ASSETS_DIR}")
