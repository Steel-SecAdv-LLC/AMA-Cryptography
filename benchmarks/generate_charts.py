#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Generate benchmark visualization charts for AMA Cryptography.

Outputs SVG charts to benchmarks/charts/ for inclusion in documentation.
Reads live benchmark data from JSON files when available, falls back to
measured baseline data.

Requires matplotlib: pip install matplotlib

Usage:
    python benchmarks/generate_charts.py
    python benchmarks/generate_charts.py --output-dir docs/images

"""

import argparse
import copy
import json
import os
from pathlib import Path
from typing import Any

# -- Paths -------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
# Where the documented producer writes: benchmarks/README.md gives
# `python benchmarks/benchmark_suite.py --json benchmarks/benchmark_results.json`,
# the path tools/generate_dashboards.py reads too.  This read the repository
# ROOT, so the live-data branch below never saw the output of the documented
# command and the charts kept drawing the anchored tables.
BENCH_FILE = ROOT / "benchmarks" / "benchmark_results.json"

# -- Anchored baselines ------------------------------------------------------
# Used when no live benchmark JSON is available, which is the normal case:
# the live files are run products that git ignores.  Every table below was
# re-derived on 2026-09-22 from runs on one host, back to back, each pinned
# to one core (`taskset -c 0`), so the charts describe one machine and one
# build rather than a collage of hosts:
#
#   host    : Linux 6.18.44, a Docker container on a hypervisor; Intel Xeon
#             @ 2.80GHz, 4 vCPU; AVX-512F/BW/DQ/VL present, VBMI/VAES/
#             VPCLMULQDQ absent.  The dispatcher's auto-tune demoted the
#             four-way Keccak kernel on this host (keccak_x4 regressed,
#             reverted to the scalar path) — the same verdict the committed
#             benchmark-report.md records in its Dispatch row.
#   build   : cmake Release, -DAMA_USE_NATIVE_PQC=ON, GCC 13.3.0; the raw-C
#             and ctypes runs at tree 1e79cd1, the Python-API rows at
#             219d3fa (a docs, tests and harness-provenance delta; no
#             measured path differs).  Native library digest b9179064a813c9a1…,
#             the object CI measured on 2026-09-21.
#   raw C   : `build/bin/benchmark_c_raw --json`, medians (a run product,
#             not checked in — see benchmarks/README.md)
#   ctypes  : benchmarks/phase0_baseline_results.json (checked in): the
#             hash, MAC, KDF and signature rows call the library through
#             ctypes directly; the package rows go through the Python API.
#   Python  : benchmarks/benchmark_results.json from
#             `python benchmarks/benchmark_suite.py` (the scalability sweep)
#             and the committed benchmarks/benchmark-results.json from
#             `benchmark_runner.py` (kyber_encapsulate).  Both records say
#             so themselves: no Cython binding was built, so every
#             Python-side row is the ctypes path.
#
#   SIGNATURE_OPS         : ctypes rows (phase0), raw C for SLH-DSA verify and
#                           secp256k1 pubkey (phase0 has neither)
#   PQC_SIGN_LATENCY, X25519_MULX, DILITHIUM_NTT, FROST_OPS, KEM_OPS : raw C
#   C_VS_PYTHON           : raw C against the ctypes / Python-API rows
#   SCALING               : benchmark_suite.py scalability sweep (mean ms)
#   FOUR_LAYER_BREAKDOWN  : ctypes medians (phase0), serial add
#
# The constants these replace were April-2026 measurements of 4.x-era code
# (one secp256k1 row from 2026-07-29).  The in-house Ed25519 backend, the
# INVARIANT-51 signer check and the FIPS 204 external interface all landed
# after them, so the old signature and C-vs-Python charts described code this
# tree no longer contains.  Re-derive whenever a source artefact changes; the
# live-data branch below overrides individual entries when
# benchmark_results.json exists.  (A CRYPTO_OPS table once listed here was
# read by nothing and was removed rather than wired to a chart nobody asked
# for.)
SIGNATURE_OPS = {
    "Ed25519 Sign": {"ops_sec": 39_539, "latency_ms": 0.0253},
    "Ed25519 Verify": {"ops_sec": 28_732, "latency_ms": 0.0348},
    "ML-DSA-65 Sign": {"ops_sec": 5_301, "latency_ms": 0.1886},
    "ML-DSA-65 Verify": {"ops_sec": 10_164, "latency_ms": 0.0984},
    # SLH-DSA-SHAKE-128s Verify fits within an order of magnitude of the
    # rest of the signature chart; Sign is sub-second-to-second and gets its
    # own log-scale chart (PQC_SIGN_LATENCY below) so it does not flatten
    # this one. Anchor: `benchmark_c_raw --json` row, 2026-09-22.
    "SLH-DSA-SHAKE-128s Verify": {"ops_sec": 1_133, "latency_ms": 0.882},
    # secp256k1 pubkey-from-privkey through the constant-time fixed-base comb
    # (since 2026-07-29; the generic Montgomery ladder it replaced measured
    # 3,038 ops/s on the same host class — see docs/BENCHMARK_HISTORY.md
    # "2026-07-29").  Anchor: `benchmark_c_raw --json` row, 2026-09-22.
    "secp256k1 pubkey": {"ops_sec": 12_161, "latency_ms": 0.0822},
}

# Sign-latency comparison for the hash-based + lattice families.
# Plotted on a log scale so the four orders of magnitude between
# Ed25519 Sign and SLH-DSA-SHAKE-128s Sign do not collapse to a
# single visible bar. Anchored to `benchmark_c_raw` medians, 2026-09-22
# (the SLH-DSA sign row is 5 iterations by design of the harness).
PQC_SIGN_LATENCY = {
    "Ed25519 Sign": {"latency_ms": 0.0227},
    # The pooled row (a whole pass over 256 messages per sample, see
    # bench_dilithium_sign): median of five rounds on the canonical bench
    # host, 2026-09-24 at 352fb916.  The 0.2376 ms it replaces timed one fixed
    # (key, message) pair, so it was that pair's rejection count.
    "ML-DSA-65 Sign": {"latency_ms": 0.2976},
    "SLH-DSA-SHAKE-128s Sign": {"latency_ms": 934.67},
}

# X25519 fe64 MULX/ADX kernel on-vs-off (BMI2+ADX gate). Anchor:
# `benchmark_c_raw` rows `X25519 DH (MULX off)` / `(MULX on)`, 2026-09-22.
# Live-data override below picks these up by name when present in
# `benchmarks/benchmark_c_raw_results.json` (the same path the override
# block actually reads — see the `bench_raw = ROOT / "benchmarks" /
# "benchmark_c_raw_results.json"` line below).
X25519_MULX = {
    "MULX off (pure-C fe64)": {"ops_sec": 11_090, "latency_us": 90.18},
    "MULX on (BMI2+ADX kernel)": {"ops_sec": 18_571, "latency_us": 53.85},
}

# Dilithium NTT / invNTT scalar vs dispatched (FIPS 204 §6.5).
# Anchor: `benchmark_c_raw` rows, 2026-09-22 (AVX2 dispatch on this host).
DILITHIUM_NTT = {
    "NTT (scalar)": {"ops_sec": 499_141, "latency_us": 2.00},
    "NTT (dispatch)": {"ops_sec": 628_986, "latency_us": 1.59},
    "invNTT (scalar)": {"ops_sec": 464_692, "latency_us": 2.15},
    "invNTT (dispatch)": {"ops_sec": 597_080, "latency_us": 1.68},
}

# FROST 2-of-3 (RFC 9591-style) per-row per-signer cost. Anchor:
# `benchmark_c_raw` rows, 2026-09-22.
FROST_OPS = {
    "round1 commit": {"ops_sec": 44_635, "latency_us": 22.40},
    "round2 sign": {"ops_sec": 6_106, "latency_us": 163.77},
    "aggregate": {"ops_sec": 2_130, "latency_us": 469.50},
}

# Raw C medians from `build/bin/benchmark_c_raw --json`, 2026-09-22. Latency
# = median_us / 1000. (phase0_baseline_results.json does not exercise ML-KEM,
# so the raw C harness is the correct anchor for KEM numbers.)
KEM_OPS = {
    "ML-KEM-1024 KeyGen": {"ops_sec": 17_277, "latency_ms": 0.0579},
    "ML-KEM-1024 Encap": {"ops_sec": 17_998, "latency_ms": 0.0556},
    "ML-KEM-1024 Decap": {"ops_sec": 14_885, "latency_ms": 0.0672},
}

# Raw C values: build/bin/benchmark_c_raw (AVX2 on x86_64), 2026-09-22.
# Python values: benchmarks/phase0_baseline_results.json ctypes rows for the
# first four, benchmarks/benchmark-results.json (`benchmark_runner.py`,
# kyber_encapsulate, ctypes path) for ML-KEM.  Speedup = raw_C_ops_sec /
# python_ops_sec, rounded to 1 decimal place.  The ratios are what the FFI
# costs on this host: about 1.2 µs per call, which is 30% of a 1 KB SHA3-256
# and noise on a 300 µs ML-DSA-65 sign.  The ML-DSA-65 row has its own
# source: both figures are canonical-bench-host medians of five rounds from
# 2026-09-24 (raw C: the pooled row, 256 messages per sample, at 352fb916;
# Python: the README's canonical Sign figure).  Its earlier pair, 4,208 raw C
# against 5,301 ctypes, read below 1.0 because the raw-C row then timed one
# fixed (key, message) pair and the Python runner a 256-message pool: two
# estimators, not an FFI cost.
C_VS_PYTHON = {
    "SHA3-256 (1KB)": {"c": 413_223, "python": 315_259, "speedup": 1.3},
    "HKDF (96B)": {"c": 189_000, "python": 145_433, "speedup": 1.3},
    "Ed25519 Sign": {"c": 44_150, "python": 39_539, "speedup": 1.1},
    "ML-DSA-65 Sign": {"c": 3_360, "python": 3_171, "speedup": 1.1},
    "ML-KEM Encap": {"c": 17_998, "python": 16_227, "speedup": 1.1},
}

# Omni-code scaling: package_create latency grows near-linearly with N codes.
# All four points from `benchmark_suite.py`'s scalability sweep (mean ms and
# ops/sec over 50 iterations, dna_size_1 .. dna_size_1000), 2026-09-22.
SCALING = {
    1: {"ms": 0.565, "ops_sec": 1_769},
    10: {"ms": 0.691, "ops_sec": 1_446},
    100: {"ms": 2.625, "ops_sec": 381},
    1000: {"ms": 65.755, "ops_sec": 15},
}

# 4-layer breakdown: per-layer ctypes-path median latency (ms) along the
# package creation pipeline, from phase0_baseline_results.json, 2026-09-22.
# Layer 3 (dual signature) is Ed25519 + ML-DSA-65 combined (25.29 + 188.65 µs).
FOUR_LAYER_BREAKDOWN = [
    ("SHA3-256 Hash", 0.0032),
    ("HMAC-SHA3-256", 0.0045),
    ("Ed25519 + ML-DSA-65 Sign", 0.2139),
    ("HKDF Derivation", 0.0069),
]

# The whole the layers are a breakdown OF: phase0_baseline_results.json's
# "Package create" median (446.033 µs), from the same run as the rows above.
# The chart once labelled the SUM of the four layer medians "Total package
# creation" -- 0.229 ms, half the measured call, beside a scalability chart
# showing 0.565 ms at N=1.  The four layers leave out the canonical encoding,
# the KMS/HKDF context and the packaging the real call performs; that
# remainder is now its own slice, so the pie adds up to what was measured.
PACKAGE_CREATE_MS = 0.4460


def layer_breakdown_slices() -> "tuple[list[tuple[str, float]], float, float]":
    """``(slices, measured_total_ms, layer_sum_ms)`` for the breakdown chart.

    ``slices`` are the four primitive layers plus the rest of package
    creation, so they sum to the measured total.  A layer sum above the
    measured total would mean the tables describe different runs, and is
    refused rather than drawn as a negative slice.
    """
    layers = [(name, ms) for name, ms in FOUR_LAYER_BREAKDOWN if ms > 0]
    layer_sum = sum(ms for _, ms in layers)
    remainder = PACKAGE_CREATE_MS - layer_sum
    if remainder < 0:
        raise ValueError(
            f"the four layers sum to {layer_sum:.4f} ms, more than the "
            f"{PACKAGE_CREATE_MS:.4f} ms package creation they break down; "
            f"FOUR_LAYER_BREAKDOWN and PACKAGE_CREATE_MS describe different runs"
        )
    slices = [*layers, ("Rest of package creation", remainder)]
    return slices, PACKAGE_CREATE_MS, layer_sum


def load_live_data() -> Any:
    """Live benchmark measurements, or ``None`` when none have been produced.

    An *absent* ``benchmark_results.json`` means no benchmark has run, and the
    caller legitimately charts the hardcoded baseline tables instead.  A file
    that exists but cannot be read or parsed is a different state entirely,
    and returning ``None`` for it made the two indistinguishable: a damaged
    results file drew every chart from the baselines and published them as
    though they had been measured.  Nothing in the output says which source
    was used, so that substitution is invisible — it fails loudly instead.

    The handler was also wrong in both directions.  ``json.load`` cannot raise
    ``KeyError``, so that arm was unreachable; ``OSError`` — the failure that
    genuinely occurs between ``exists()`` and ``open()``, and on a path that
    is not a regular file — was not caught at all.  ``json.JSONDecodeError``
    and ``UnicodeDecodeError`` are both ``ValueError``, which is why the read
    is now pinned to UTF-8 rather than decoded against the host locale.
    """
    if not BENCH_FILE.exists():
        return None
    try:
        with open(BENCH_FILE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            f"{BENCH_FILE} exists but could not be read as JSON ({exc}). "
            f"Charting would fall back to the hardcoded baseline constants "
            f"and present them as measurements. Re-run the benchmarks to "
            f"regenerate it, or remove the file to chart the baselines "
            f"deliberately."
        ) from exc


# -- Professional dark theme -------------------------------------------------
DARK_BG = "#1a1a2e"
PANEL_BG = "#16213e"
TEXT_COLOR = "#e0e0e0"
GRID_COLOR = "#2a2a4a"


def apply_theme(plt: Any) -> None:
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

    # Update data from live benchmarks if available.  deepcopy, not dict():
    # a shallow copy shares the nested per-row dicts, so the live-data
    # override below wrote through into the module-level anchored tables —
    # the exact aliasing hazard the deepcopy at the bottom of this file
    # already guards against for the same tables.
    sig_ops = copy.deepcopy(SIGNATURE_OPS)
    kem_ops = copy.deepcopy(KEM_OPS)
    c_vs_py = copy.deepcopy(C_VS_PYTHON)
    scaling = copy.deepcopy(SCALING)

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
            sig_ops["ML-DSA-65 Verify"]["ops_sec"] = ops["dilithium_verify"]["ops_per_sec"]
            sig_ops["ML-DSA-65 Verify"]["latency_ms"] = ops["dilithium_verify"]["mean_ms"]
        if "sha3_256" in ops:
            c_vs_py["SHA3-256 (1KB)"]["python"] = ops["sha3_256"]["ops_per_sec"]

    # -- Chart 1: Signature Performance --------------------------------------
    fig, ax = plt.subplots(figsize=(10, 6))
    names = list(sig_ops.keys())
    ops_vals = [sig_ops[n]["ops_sec"] for n in names]
    latencies = [sig_ops[n]["latency_ms"] for n in names]
    colors = ["#00d2ff", "#4d96ff", "#ff6b6b", "#ff922b", "#6bcb77", "#845ef7"]
    bars = ax.barh(names, ops_vals, color=colors[: len(names)], edgecolor="none", height=0.6)
    # Log scale, for the same reason PQC_SIGN_LATENCY uses one: this family
    # spans 1,133 ops/s (SLH-DSA-SHAKE-128s Verify) to 39,539 (Ed25519 Sign),
    # a 35x range. On a linear axis the slowest bars collapse into an
    # unreadable stub against the fastest — which is exactly what happened
    # when the secp256k1 fixed-base comb moved that bar from 3,038 to 11,997.
    ax.set_xscale("log")
    ax.set_xlabel("Operations/sec (log scale)", fontsize=11)
    ax.set_title(
        "Signature Algorithm Performance",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    # Headroom on the right so the widest label is not clipped by the axis.
    ax.set_xlim(min(ops_vals) * 0.55, max(ops_vals) * 3.2)
    for bar, val, lat in zip(bars, ops_vals, latencies):
        label = f"{val:,} ops/s ({lat:.3f} ms)" if val > 10 else f"{val} ops/s ({lat:.1f} ms)"
        ax.text(
            bar.get_width() * 1.06,  # multiplicative offset: a log axis has no fixed gap
            bar.get_y() + bar.get_height() / 2,
            label,
            va="center",
            fontsize=8,
            color=TEXT_COLOR,
        )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "signature_performance.svg"), format="svg")
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
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
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
    # Name the two harnesses and the host, because the ratio is the FFI cost
    # on one machine and nothing else; and say why one bar can read below
    # 1.0 rather than leave a reader to infer that C lost.
    ax.text(
        0.99,
        0.02,
        "Raw C: build/bin/benchmark_c_raw --json  |  Python: ctypes path, same host and build "
        "(2026-09-22)\nML-DSA-65 sign is rejection-sampled: the harnesses' medians differ "
        "by more than the ~1.2 µs FFI cost",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=7,
        color="#888888",
        style="italic",
    )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "c_vs_python.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/c_vs_python.svg")

    # -- Chart 3: 4-Layer Package Breakdown ----------------------------------
    fig, ax = plt.subplots(figsize=(9, 6))
    slices, package_total_ms, layer_sum_ms = layer_breakdown_slices()
    labels = [name for name, _ in slices]
    sizes = [ms for _, ms in slices]
    colors_pie = ["#00d2ff", "#7b2ff7", "#ff6b6b", "#6bcb77", "#888888"]
    explode = [0, 0, 0.05, 0, 0]
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
    ax.text(
        0,
        -1.35,
        f"Measured package creation: {package_total_ms:.3f} ms  |  "
        f"Sum of the four primitive layers: {layer_sum_ms:.3f} ms",
        ha="center",
        fontsize=9,
        color="#888888",
        style="italic",
    )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "layer_breakdown.svg"), format="svg")
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
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
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
        "FIPS 203 | Raw C harness (build/bin/benchmark_c_raw --json)",
        transform=ax.transAxes,
        ha="right",
        fontsize=8,
        color="#666666",
        style="italic",
    )
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "kem_performance.svg"), format="svg")
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

    # -- Chart 6: PQC + kernel benchmark overview collage (2x2) ---------------
    # Single combined figure replacing what used to be four standalone SVGs
    # (x25519_mulx_kernel, dilithium_ntt_kernel, pqc_sign_latency,
    # frost_2of3). One artifact = one piece of truth; the underlying
    # numbers are not duplicated across multiple checked-in SVGs.

    # Live-data override: pick up `X25519 DH (MULX off)` / `(MULX on)` rows
    # from `benchmarks/benchmark_c_raw_results.json` when it is present.
    #
    # `copy.deepcopy(X25519_MULX)` (not `dict(X25519_MULX)`) so the per-row
    # `{"ops_sec": ..., "latency_us": ...}` nested dicts are *independent*
    # of the module-level anchored constants. If the live-data block
    # below mutates one row and then raises on the next entry (or if
    # `generate_charts()` is invoked twice in the same process), the
    # anchored fallback values in `X25519_MULX` must remain pristine —
    # otherwise the second call would mix half-stale live data with the
    # anchored constants, producing a chart that silently misrepresents
    # both.
    mulx_rows = copy.deepcopy(X25519_MULX)
    bench_raw = ROOT / "benchmarks" / "benchmark_c_raw_results.json"
    if bench_raw.exists():
        # Transactional override: collect BOTH live rows into local
        # temporaries before mutating `mulx_rows`. A malformed or
        # partial file that yields a valid `MULX off` entry and then
        # raises (KeyError / TypeError) while parsing `MULX on` MUST
        # NOT leave the chart in a mixed live+fallback state — both
        # bars come from the same source, or neither does. The fall-
        # back is the anchored constants in `X25519_MULX` already
        # deep-copied into `mulx_rows`.
        try:
            with open(bench_raw, encoding="utf-8") as f:
                raw = json.load(f)
            live_off = None
            live_on = None
            for entry in raw.get("results", []):
                # Use median_us (not mean_us) so the live numbers match
                # the "Raw C medians" anchor convention used everywhere
                # else in this file — see KEM_OPS, the panel headers,
                # and the X25519_MULX docstring above.
                if entry.get("operation") == "X25519 DH (MULX off)":
                    live_off = {
                        "ops_sec": entry["ops_per_sec"],
                        "latency_us": entry["median_us"],
                    }
                elif entry.get("operation") == "X25519 DH (MULX on)":
                    live_on = {
                        "ops_sec": entry["ops_per_sec"],
                        "latency_us": entry["median_us"],
                    }
            # Atomic swap: both rows or neither. Either both temporaries
            # are populated, or the file did not contain the paired
            # rows we expect and the anchored constants stand unchanged.
            if live_off is not None and live_on is not None:
                mulx_rows["MULX off (pure-C fe64)"].update(live_off)
                mulx_rows["MULX on (BMI2+ADX kernel)"].update(live_on)
        except (json.JSONDecodeError, KeyError, TypeError):
            # Live-data override is best-effort: a malformed or partial
            # benchmark_c_raw_results.json file should not break chart
            # generation. Fall back to the anchored sandbox numbers in
            # X25519_MULX (already loaded into `mulx_rows` above).
            # Because the per-row mutation is gated on both temporaries
            # being populated, no partial state can leak past this
            # except-block.
            pass

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle(
        "PQC + Kernel Benchmark Overview — 2026-05 coverage expansion",
        fontsize=15,
        fontweight="bold",
        color=TEXT_COLOR,
        y=0.995,
    )

    # Panel (0,0): X25519 fe64 MULX/ADX kernel on-vs-off
    ax = axes[0, 0]
    mulx_names = list(mulx_rows.keys())
    mulx_vals = [mulx_rows[n]["ops_sec"] for n in mulx_names]
    mulx_lats = [mulx_rows[n]["latency_us"] for n in mulx_names]
    bars = ax.bar(mulx_names, mulx_vals, color=["#ff6b6b", "#00d2ff"], edgecolor="none", width=0.5)
    ax.set_ylabel("Operations/sec", fontsize=10)
    ax.set_title("X25519 fe64 MULX/ADX Kernel — On vs Off", fontsize=12, fontweight="bold", pad=8)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val, lat in zip(bars, mulx_vals, mulx_lats):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(mulx_vals) * 0.02,
            f"{val:,.0f} ops/s\n({lat:.2f} µs)",
            ha="center",
            fontsize=8,
            color=TEXT_COLOR,
        )
    if mulx_vals[0] > 0:
        speedup = mulx_vals[1] / mulx_vals[0]
        ax.text(
            0.98,
            0.02,
            f"Kernel speedup: {speedup:.2f}×",
            transform=ax.transAxes,
            ha="right",
            fontsize=8,
            color="#888888",
            style="italic",
        )

    # Panel (0,1): Dilithium NTT / invNTT scalar vs dispatched
    ax = axes[0, 1]
    ntt_names = list(DILITHIUM_NTT.keys())
    ntt_vals = [DILITHIUM_NTT[n]["ops_sec"] for n in ntt_names]
    ntt_colors = ["#ff6b6b", "#00d2ff", "#ff922b", "#6bcb77"]
    bars = ax.bar(ntt_names, ntt_vals, color=ntt_colors, edgecolor="none", width=0.55)
    ax.set_ylabel("Operations/sec", fontsize=10)
    ax.set_title(
        "ML-DSA-65 NTT / invNTT — Scalar vs Dispatched", fontsize=12, fontweight="bold", pad=8
    )
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    ax.tick_params(axis="x", labelsize=8)
    for bar, val in zip(bars, ntt_vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(ntt_vals) * 0.02,
            f"{val:,.0f}",
            ha="center",
            fontsize=8,
            color=TEXT_COLOR,
        )
    ax.text(
        0.98,
        0.02,
        "Isolated via ama_dilithium_{ntt,invntt}_bench()",
        transform=ax.transAxes,
        ha="right",
        fontsize=8,
        color="#888888",
        style="italic",
    )

    # Panel (1,0): PQC Sign Latency (log scale)
    ax = axes[1, 0]
    pqc_names = list(PQC_SIGN_LATENCY.keys())
    pqc_lats = [PQC_SIGN_LATENCY[n]["latency_ms"] for n in pqc_names]
    bars = ax.barh(
        pqc_names, pqc_lats, color=["#00d2ff", "#7b2ff7", "#ff6b6b"], edgecolor="none", height=0.5
    )
    ax.set_xlabel("Sign latency (ms, log scale)", fontsize=10)
    ax.set_xscale("log")
    ax.set_title("Signature Family — Sign Latency (log)", fontsize=12, fontweight="bold", pad=8)
    for bar, lat in zip(bars, pqc_lats):
        ax.text(
            bar.get_width() * 1.05,
            bar.get_y() + bar.get_height() / 2,
            f"{lat:,.3f} ms" if lat < 100 else f"{lat:,.1f} ms",
            va="center",
            fontsize=8,
            color=TEXT_COLOR,
        )
    ax.text(
        0.98,
        0.02,
        "Ed25519: RFC 8032 | ML-DSA-65: FIPS 204 | SLH-DSA: FIPS 205 L1",
        transform=ax.transAxes,
        ha="right",
        fontsize=8,
        color="#888888",
        style="italic",
    )

    # Panel (1,1): FROST 2-of-3 (RFC 9591-style) per-role cost
    ax = axes[1, 1]
    frost_names = list(FROST_OPS.keys())
    frost_vals = [FROST_OPS[n]["ops_sec"] for n in frost_names]
    frost_lats = [FROST_OPS[n]["latency_us"] for n in frost_names]
    bars = ax.bar(
        frost_names,
        frost_vals,
        color=["#6bcb77", "#ffd93d", "#7b2ff7"],
        edgecolor="none",
        width=0.5,
    )
    ax.set_ylabel("Operations/sec", fontsize=10)
    ax.set_title(
        "FROST 2-of-3 (RFC 9591-style) — Per-Role Cost", fontsize=12, fontweight="bold", pad=8
    )
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    for bar, val, lat in zip(bars, frost_vals, frost_lats):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(frost_vals) * 0.02,
            f"{val:,.0f} ops/s\n({lat:.1f} µs)",
            ha="center",
            fontsize=8,
            color=TEXT_COLOR,
        )
    ax.text(
        0.98,
        0.02,
        "Round1 commit | Round2 sign | Aggregate (Ed25519-compatible)",
        transform=ax.transAxes,
        ha="right",
        fontsize=8,
        color="#888888",
        style="italic",
    )

    plt.tight_layout(rect=(0, 0, 1, 0.97))
    plt.savefig(os.path.join(output_dir, "pqc_benchmark_overview.svg"), format="svg")
    plt.close()
    print(f"  Created {output_dir}/pqc_benchmark_overview.svg (2x2 collage)")

    print(f"\nAll charts generated in {output_dir}/")


def generate_text_summary() -> None:
    """Print text-only benchmark summary when matplotlib is unavailable."""
    print("=" * 60)
    print("AMA Cryptography Benchmark Summary")
    print("=" * 60)

    print("\nSignature Operations:")
    for name, data in SIGNATURE_OPS.items():
        # int(): the row values are int and float together, so the mapping
        # infers as float and `"#" * <float>` is not a repetition.
        bar = "#" * int(min(50, data["ops_sec"] // 400))
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
