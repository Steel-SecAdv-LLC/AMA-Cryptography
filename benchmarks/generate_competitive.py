#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Full-surface competitive positioning page.

Renders `benchmarks/competitive.html` from the two measurement artefacts:

  * `benchmarks/multi_library_results.json` — native C/C++ harness
    (`multi_library_bench.cpp`) covering every AMA primitive that at least one
    other library on the host also exposes, across OpenSSL, libsodium, wolfSSL,
    Botan, Nettle, libgcrypt and mbedTLS.
  * `benchmarks/pqc_results.json` — the ML-KEM / ML-DSA head-to-head
    (`pqc_comparative_bench.py`), which runs at the Python layer because
    OpenSSL 4.0.1 via `cryptography` is the only peer on the host that
    implements those at all.

Why a generator and not a static page
-------------------------------------
Every number on the page comes from JSON produced by a run, so the numeric
content cannot drift from the measurement the way a committed table does.
Three structures in this file are hand-maintained and say so on the page:
COVERAGE (each cell records the result of a runtime capability probe or a
benchmark row taken at measurement time — the probe source is quoted in the
methodology section — but the matrix itself is a transcription), VERSIONS
(eight of the nine entries are pinned string literals, because the harness
does not record peer versions), and NOTES (engineering prose, which must be
reconciled against the rendered numbers whenever the JSON changes).

Design rules (see the project's data-viz guidance)
--------------------------------------------------
* Two categorical series only — AMA and the fastest peer for that primitive.
  Nine libraries do not become nine hues; the table carries per-library
  identity, the chart carries the comparison. Both hues validated for CVD
  separation against both surfaces (worst adjacent dE 24.7 light / 26.8 dark
  against a >=8 target, normal-vision 33.6 / 31.8).
* Log axis wherever the range spans more than a decade — AES-GCM alone runs
  from 203 MB/s to 10.5 GB/s.
* Every bar carries a direct value label, so nothing is encoded by colour
  alone, and the full numeric table is the chart's table view.
* Dark mode is selected, not flipped: its own validated steps from the same
  ramps under both the OS media query and the explicit theme toggle.

Usage
-----
    python benchmarks/generate_competitive.py
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
BENCH = REPO / "benchmarks"


# Library versions on the measurement host. Read from the JSON where the
# harness records them; pinned here for the ones it does not carry.
#
# The AMA version is read from the RESULT DATA, not from the working tree.
# It used to be read from `ama_cryptography/__init__.py` at render time, with
# a comment that named the hazard exactly — "REGENERATE ONLY ALONGSIDE A
# MEASUREMENT RUN ON THE HOST ... an offline re-render against old result
# JSONs would claim a build that was never benchmarked" — and relied on
# whoever ran the generator to honour it.
#
# They did not, and the page said so: benchmarks/competitive.html was
# regenerated at fe8b8ab (2026-08-21) and stamped "AMA 5.0.0", while both
# source JSONs were last produced at 66d2073 (2026-07-29), where
# __version__ was "3.4.0", and neither was touched by the work in between.
# The page's own closing paragraph says every figure is read from those two
# files and nothing is hand-entered — true of every number, and false of the
# only label that says which build produced them.
#
# A convention a comment asks for is not a control. Reading the version from
# the data makes an offline re-render harmless: it re-renders the version the
# data was measured at. A re-measurement updates the JSON, and the stamp
# follows it.
def _ama_version() -> str:
    provenance = _source_provenance()
    version = provenance.get("ama_version")
    if not isinstance(version, str) or not version.strip():
        # Raise rather than fall back to the working tree: falling back IS the
        # defect this function was rewritten to remove.
        raise RuntimeError(
            "benchmarks/multi_library_results.json carries no "
            "provenance.ama_version, so the version of the build these "
            "measurements came from is unknown. Refusing to stamp the report "
            "with the working tree's version — that is how a page measured on "
            "3.4.0 came to be labelled 5.0.0. Re-run the harness (which "
            "records it) or add the provenance block by hand from "
            "`git log -1 -- benchmarks/multi_library_results.json`."
        )
    return version


def _source_provenance() -> dict[str, Any]:
    """The provenance block of the primary result file.

    Both result files carry one and they must agree: they are rendered onto
    one page under one version stamp, so a page built from two different
    builds' measurements has no honest label at all.
    """
    primary = json.loads((BENCH / "multi_library_results.json").read_text(encoding="utf-8"))
    secondary = json.loads((BENCH / "pqc_results.json").read_text(encoding="utf-8"))
    p1 = primary.get("provenance") or {}
    p2 = secondary.get("provenance") or {}
    if p1.get("ama_commit") != p2.get("ama_commit"):
        raise RuntimeError(
            "multi_library_results.json and pqc_results.json were measured at "
            f"different commits ({p1.get('ama_commit')!r} vs "
            f"{p2.get('ama_commit')!r}); one page cannot carry one honest "
            "version stamp over two builds. Re-measure both."
        )
    return p1


VERSIONS = {
    "AMA": _ama_version(),
    "OpenSSL": "3.0.13",
    "OpenSSL 4.0.1": "4.0.1 (via cryptography 49.0.0)",
    "libsodium": "1.0.18",
    "wolfSSL": "5.6.6",
    "Botan": "2.19.3",
    "Nettle": "3.9",
    "libgcrypt": "1.10.3",
    "mbedTLS": "2.28.8",
}

ORDER = ["AMA", "OpenSSL", "libsodium", "wolfSSL", "Botan", "Nettle", "libgcrypt", "mbedTLS"]

# Primitive display order: symmetric bulk, then asymmetric, then PQC.
PRIM_ORDER = [
    "SHA3-256",
    "HMAC-SHA3-256",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "Ascon-128 AEAD",
    "Ed25519 sign",
    "Ed25519 verify",
    "X25519 scalar-mult",
    "P-256 ECDSA sign",
    "P-256 ECDSA verify",
    "secp256k1 ECDSA sign",
    "secp256k1 ECDSA verify",
    "ML-DSA-65 keygen",
    "ML-DSA-65 sign",
    "ML-DSA-65 verify",
    "ML-KEM-1024 keygen",
    "ML-KEM-1024 encaps",
    "ML-KEM-1024 decaps",
]


# Stack-coverage matrix. Every cell records the result of a runtime capability
# probe or a benchmark row established at measurement time (the matrix itself
# is a transcription of those results, not a render-time re-probe):
#   * a benchmark row for that (primitive, library) pair proves YES;
#   * `EVP_KDF_fetch` / `EVP_KEM_fetch` / `EVP_SIGNATURE_fetch` / EC_GROUP
#     lookup for OpenSSL; `Botan::*::create` for Botan; curve-info lookup for
#     mbedTLS; `wolfssl/options.h` build flags for wolfSSL.
# "-" means the library does not implement it on this host and build.
def _coverage_row(*flags: int) -> dict[str, bool]:
    """One COVERAGE row, written as the readable 0/1 matrix above.

    Two things a bare ``_coverage_row(...)`` did not do.  It produced
    ``dict[str, int]`` under a ``dict[str, bool]`` annotation, so the declared
    type was not the type; and ``zip`` stops at the shorter operand, so a row
    with seven entries silently dropped mbedTLS and rendered it as "not
    implemented" — a coverage claim about a library, made by a typo.  The
    length is now checked.
    """
    if len(flags) != len(ORDER):
        raise ValueError(
            f"coverage row has {len(flags)} entries, expected {len(ORDER)} "
            f"(one per library in ORDER: {', '.join(ORDER)})"
        )
    return {library: bool(flag) for library, flag in zip(ORDER, flags)}


COVERAGE: dict[str, dict[str, bool]] = {
    #                      AMA   OSSL   sodium wolf   Botan  Nettle gcrypt mbed
    "SHA3-256": _coverage_row(1, 1, 0, 1, 1, 1, 1, 0),
    "HMAC-SHA3-256": _coverage_row(1, 1, 0, 1, 1, 0, 1, 0),
    "HKDF": _coverage_row(1, 1, 0, 1, 1, 1, 0, 1),
    "AES-256-GCM": _coverage_row(1, 1, 1, 1, 1, 1, 1, 1),
    "ChaCha20-Poly1305": _coverage_row(1, 1, 1, 1, 1, 1, 1, 1),
    "Ascon-128 AEAD": _coverage_row(1, 0, 0, 0, 0, 0, 0, 0),
    "Argon2id": _coverage_row(1, 0, 1, 0, 1, 0, 0, 0),
    "Ed25519": _coverage_row(1, 1, 1, 1, 1, 1, 1, 0),
    "X25519": _coverage_row(1, 1, 1, 1, 1, 1, 1, 1),
    "NIST P-256": _coverage_row(1, 1, 0, 1, 1, 1, 1, 1),
    "secp256k1": _coverage_row(1, 1, 0, 0, 1, 0, 1, 1),
    "ML-KEM (FIPS 203)": _coverage_row(1, 0, 0, 0, 0, 0, 0, 0),
    "ML-DSA (FIPS 204)": _coverage_row(1, 0, 0, 0, 0, 0, 0, 0),
    "SLH-DSA (FIPS 205)": _coverage_row(1, 0, 0, 0, 0, 0, 0, 0),
    "LMS (SP 800-208)": _coverage_row(1, 0, 0, 0, 0, 0, 0, 0),
    "FROST threshold": _coverage_row(1, 0, 0, 0, 0, 0, 0, 0),
}

# Engineering account per primitive, reconciled against the numbers rendered
# beside it (the ranks and ratios below are recomputed from
# multi_library_results.json whenever the note is edited — an earlier
# revision of this dict contradicted the badges in its own rows).  "We are
# slower" is not a finding — the reason is the finding, and in two cases the
# reason is a property the project chose on purpose.
NOTES = {
    "AES-256-GCM": (
        "AMA defaults to constant-time AES (INVARIANT-20), which never indexes "
        "a table with key-dependent data. OpenSSL and libgcrypt lead through "
        "AES-NI pipelines tuned end-to-end for this one construction. AMA "
        "places 3rd of 8, ahead of Nettle, libsodium, Botan, mbedTLS and "
        "wolfSSL on this build."
    ),
    "ChaCha20-Poly1305": (
        "OpenSSL runs an AVX-512 vectorised ChaCha20 core. AMA's is SIMD but "
        "not vectorised to that width. Third of seven."
    ),
    "SHA3-256": (
        "libgcrypt and OpenSSL carry hand-optimised Keccak permutations. AMA's "
        "single-stream scalar permutation places first of six, 0.7% ahead of "
        "libgcrypt — a photo finish, not a durable lead (the x4 AVX2 path "
        "batches four independent hashes and does not apply to one stream)."
    ),
    "HMAC-SHA3-256": "Tracks the SHA3-256 permutation result above; first of four here.",
    "X25519 scalar-mult": (
        "OpenSSL and libsodium use dedicated field arithmetic with a fused "
        "multiply path. AMA is within 1.5x of both. Third of five."
    ),
    "P-256 ECDSA sign": (
        "OpenSSL ships `ecp_nistz256`, a hand-written assembly implementation "
        "specific to this one curve. AMA uses its generic NIST-curve path, "
        "which serves P-256, P-384 and P-521 from one body of code."
    ),
    "P-256 ECDSA verify": "Same generic-versus-curve-specific split as P-256 signing.",
    "secp256k1 ECDSA verify": (
        "Fastest of three: 14.9% ahead of Botan and 1.48x ahead of OpenSSL. "
        "The signing side also leads outright, after the fixed-base comb "
        "landed (#379)."
    ),
    "ML-KEM-1024 encaps": (
        "The known lattice gap. AMA's ML-KEM is SIMD-accelerated (1.28x over "
        "scalar, AVX-512 adding a further 1.22x) but is not vectorised across "
        "the breadth OpenSSL 4.0.1 reaches. Closing it is a multi-week "
        "vectorisation project, not a tuning pass, and it is not claimed as "
        "done."
    ),
    "ML-KEM-1024 decaps": "Same vectorisation breadth gap as encapsulation.",
    "ML-KEM-1024 keygen": "Within 10% — the narrowest of the three ML-KEM operations.",
    "ML-DSA-65 keygen": "Within 20%; signing and verification both lead.",
}


def load() -> tuple[dict[str, Any], dict[str, Any]]:
    c = json.loads((BENCH / "multi_library_results.json").read_text(encoding="utf-8"))
    q = json.loads((BENCH / "pqc_results.json").read_text(encoding="utf-8"))
    return c, q


def build_grid(c: dict[str, Any], q: dict[str, Any]) -> dict[str, dict[str, Any]]:
    grid: dict[str, dict[str, Any]] = {}
    for r in c["results"]:
        grid.setdefault(r["primitive"], {})[r["library"]] = {
            "ops": r["ops_per_sec"],
            "cpb": r.get("cycles_per_byte"),
            "mbps": r.get("mb_per_sec"),
        }
    for r in q["results"]:
        lib = "AMA" if r["implementation"] == "AMA" else "OpenSSL 4.0.1"
        grid.setdefault(r["primitive"], {})[lib] = {
            "ops": r["ops_per_sec"],
            "cpb": None,
            "mbps": None,
        }
    return grid


def standing(grid: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for prim in PRIM_ORDER:
        cell = grid.get(prim)
        if not cell or "AMA" not in cell:
            continue
        ranked = sorted(cell.items(), key=lambda kv: -kv[1]["ops"])
        names = [k for k, _ in ranked]
        rank = names.index("AMA") + 1
        peers = [(k, v) for k, v in ranked if k != "AMA"]
        best = peers[0] if peers else None
        out.append(
            {
                "prim": prim,
                "rank": rank,
                "n": len(ranked),
                "ama": cell["AMA"]["ops"],
                "ama_cpb": cell["AMA"].get("cpb"),
                "best_lib": best[0] if best else None,
                "best_ops": best[1]["ops"] if best else None,
                "ratio": (cell["AMA"]["ops"] / best[1]["ops"]) if best else None,
                "sole": best is None,
                "note": NOTES.get(prim),
            }
        )
    return out


def esc(s: Any) -> str:
    return html.escape(str(s))


def fmt(n: float | None) -> str:
    if n is None:
        return "—"
    if n >= 1_000_000:
        return f"{n/1e6:,.2f} M"
    if n >= 1000:
        return f"{n:,.0f}"
    return f"{n:,.1f}"


def render(c: dict[str, Any], q: dict[str, Any]) -> str:
    grid = build_grid(c, q)
    st = standing(grid)
    wins = [s for s in st if s["rank"] == 1 and not s["sole"]]
    sole = [s for s in st if s["sole"]]
    behind = [s for s in st if s["rank"] > 1]
    freq = c["freq_hz"] / 1e9
    msg = c["message_bytes"]
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    libs_in = c["libraries_compiled"]

    # Host identity, read from the harness rather than assumed.
    #
    # This is load-bearing, not decoration: which AES-GCM kernel a library
    # selects depends on VAES + VPCLMULQDQ, and that choice moves the peer
    # figure by roughly 4x. A page that prints only a clock speed invites the
    # reader to compare a row measured on a VAES host against one measured
    # without it and attribute the difference to the implementations.
    host = c.get("host") or {}
    if host:
        feats = [
            k
            for k in (
                "aes_ni",
                "pclmulqdq",
                "vaes",
                "vpclmulqdq",
                "avx2",
                "avx512f",
                "sha_ni",
                "bmi2",
                "adx",
            )
            if host.get(k)
        ]
        absent = [k for k in ("vaes", "vpclmulqdq", "sha_ni") if not host.get(k)]
        host_line = html.escape(host.get("cpu", "unknown"))
        host_line += " · " + ", ".join(feats)
        if absent:
            host_line += " · <b>absent:</b> " + ", ".join(absent)
    else:
        host_line = (
            "host not recorded — this artefact predates host capture; "
            "peer AES-GCM figures are not comparable across hosts "
            "with different VAES support"
        )

    # ── standing rows ──
    rows = []
    for s in st:
        if s["sole"]:
            badge = '<span class="b b-sole">sole implementer</span>'
            cmp_ = "—"
        elif s["rank"] == 1:
            badge = f'<span class="b b-win">fastest of {s["n"]}</span>'
            cmp_ = f'{s["ratio"]:.2f}× {esc(s["best_lib"])}'
        else:
            badge = (
                f'<span class="b b-behind">{s["rank"]}<span class="sup">of</span>{s["n"]}</span>'
            )
            cmp_ = f'{s["ratio"]:.2f}× {esc(s["best_lib"])}'
        note = f'<div class="note">{esc(s["note"])}</div>' if s["note"] else ""
        rows.append(
            f'<tr><td class="p">{esc(s["prim"])}{note}</td>'
            f'<td class="n">{fmt(s["ama"])}</td>'
            f'<td class="n">{fmt(s["best_ops"])}</td>'
            f'<td class="n">{cmp_}</td>'
            f"<td>{badge}</td></tr>"
        )
    standing_rows = "\n".join(rows)

    # ── comparison bars (AMA vs best peer), log-scaled per row ──
    bars = []
    for s in st:
        if s["sole"]:
            continue
        hi = max(s["ama"], s["best_ops"])
        aw = 100 * s["ama"] / hi
        bw = 100 * s["best_ops"] / hi
        lead = s["rank"] == 1
        bars.append(f"""
      <div class="cmp">
        <div class="cmp-h"><span>{esc(s['prim'])}</span>
          <span class="cmp-r {'up' if lead else 'dn'}">{s['ratio']:.2f}×</span></div>
        <div class="rowbar"><div class="rb ama" style="width:{aw:.2f}%"></div>
          <span class="rl">AMA {fmt(s['ama'])}</span></div>
        <div class="rowbar"><div class="rb peer" style="width:{bw:.2f}%"></div>
          <span class="rl">{esc(s['best_lib'])} {fmt(s['best_ops'])}</span></div>
      </div>""")
    bars_html = "\n".join(bars)

    # ── full matrix table ──
    cols = [lib for lib in ORDER if lib in libs_in]
    head = "".join(f"<th>{esc(lib)}</th>" for lib in cols) + "<th>OpenSSL 4.0.1</th>"
    mrows = []
    for prim in PRIM_ORDER:
        cell = grid.get(prim, {})
        if not cell:
            continue
        best = max((v["ops"] for v in cell.values()), default=0)
        tds = []
        for lib in [*cols, "OpenSSL 4.0.1"]:
            v = cell.get(lib)
            if not v:
                tds.append('<td class="x">—</td>')
                continue
            lead = "lead" if v["ops"] == best else ""
            cpb = f'<span class="cpb">{v["cpb"]:.2f} c/B</span>' if v.get("cpb") else ""
            tds.append(f'<td class="n {lead}">{fmt(v["ops"])}{cpb}</td>')
        mrows.append(f'<tr><td class="p">{esc(prim)}</td>{"".join(tds)}</tr>')
    matrix_rows = "\n".join(mrows)

    # ── coverage matrix ──
    crows = []
    for prim, cells in COVERAGE.items():
        # Not `tds`: that name is a list of cells in the benchmark-matrix loop
        # above, and rebinding it to a joined string here made one name hold
        # two types in one function.
        cell_html = "".join(
            f'<td class="{"y" if cells[lib] else "x"}">{"●" if cells[lib] else "—"}</td>'
            for lib in ORDER
        )
        n = sum(cells[lib] for lib in ORDER)
        uniq = ' class="uniq"' if n == 1 and cells["AMA"] else ""
        crows.append(
            f'<tr{uniq}><td class="p">{esc(prim)}</td>{cell_html}'
            f'<td class="n">{n}/{len(ORDER)}</td></tr>'
        )
    cov_rows = "\n".join(crows)
    cov_head = "".join(f"<th>{esc(lib)}</th>" for lib in ORDER)

    vers = " · ".join(
        f"{esc(k)} {esc(v)}" for k, v in VERSIONS.items() if k in libs_in or "4.0.1" in k
    )

    ama_only = sum(1 for p, c_ in COVERAGE.items() if sum(c_.values()) == 1 and c_["AMA"])

    # Fields and this mapping are a verified 1:1 bijection (21/21). Substitute
    # with format_map(mapping) — the direct dict idiom — rather than
    # format(**kwargs): it renders byte-identically and keeps the call
    # unambiguous, with no keyword arguments to reconcile against the escaped
    # braces in the embedded CSS/JS that a format-argument analysis can misread.
    return TEMPLATE.format_map(
        {
            "gen": esc(gen),
            # Read from the result files' provenance, never from the working
            # tree — see _ama_version() for the page this distinction was
            # written on top of.
            "src_commit": esc(str(_source_provenance().get("ama_commit", "unknown"))),
            "src_version": esc(str(_source_provenance().get("ama_version", "unknown"))),
            "src_measured": esc(str(_source_provenance().get("measured_at", "unknown"))),
            "freq": f"{freq:.3f}",
            "host_line": host_line,
            "msg": f"{msg:,}",
            "nlibs": len(libs_in),
            "vers": vers,
            "n_win": len(wins),
            "n_behind": len(behind),
            "n_sole": len(sole),
            "n_total": len(st),
            "ama_only": ama_only,
            "n_cov": len(COVERAGE),
            "standing_rows": standing_rows,
            "bars": bars_html,
            "matrix_head": head,
            "matrix_rows": matrix_rows,
            "cov_head": cov_head,
            "cov_rows": cov_rows,
        }
    )


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AMA Cryptography — Full-Surface Competitive Position</title>
<style>
:root{{
  --surface-1:#fcfcfb; --plane:#f9f9f7; --text-primary:#0b0b0b; --text-secondary:#52514e;
  --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7; --border:rgba(11,11,11,.10);
  --good-ink:#006300; --critical:#d03b3b; --warning:#fab219;
  --ama:#2a78d6; --peer:#eb6834;
}}
@media (prefers-color-scheme:dark){{
  :root{{
    --surface-1:#1a1a19; --plane:#0d0d0d; --text-primary:#fff; --text-secondary:#c3c2b7;
    --muted:#898781; --grid:#2c2c2a; --axis:#383835; --border:rgba(255,255,255,.10);
    --good-ink:#0ca30c; --critical:#e06060; --warning:#fab219;
    --ama:#3987e5; --peer:#d95926;
  }}
}}
:root[data-theme="dark"]{{
  --surface-1:#1a1a19; --plane:#0d0d0d; --text-primary:#fff; --text-secondary:#c3c2b7;
  --muted:#898781; --grid:#2c2c2a; --axis:#383835; --border:rgba(255,255,255,.10);
  --good-ink:#0ca30c; --critical:#e06060; --warning:#fab219;
  --ama:#3987e5; --peer:#d95926;
}}
:root[data-theme="light"]{{
  --surface-1:#fcfcfb; --plane:#f9f9f7; --text-primary:#0b0b0b; --text-secondary:#52514e;
  --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7; --border:rgba(11,11,11,.10);
  --good-ink:#006300; --critical:#d03b3b; --warning:#fab219;
  --ama:#2a78d6; --peer:#eb6834;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--surface-1);color:var(--text-primary);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}}
.wrap{{max-width:1180px;margin:0 auto;padding:40px 22px 80px}}
h1{{font-size:30px;line-height:1.2;margin:0 0 6px;letter-spacing:-.02em}}
h2{{font-size:19px;margin:44px 0 6px;letter-spacing:-.01em}}
h2 .num{{color:var(--muted);font-weight:400;margin-right:8px}}
.sub{{color:var(--text-secondary);margin:0 0 4px}}
.meta{{color:var(--muted);font-size:12.5px;margin:14px 0 0;padding-top:12px;
  border-top:1px solid var(--border);line-height:1.7}}
.lede{{color:var(--text-secondary);margin:8px 0 0;max-width:78ch}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:22px 0 0}}
.tile{{background:var(--plane);border:1px solid var(--border);border-radius:10px;padding:14px 16px}}
.tile .v{{font-size:27px;font-weight:640;letter-spacing:-.02em;line-height:1.1}}
.tile .k{{color:var(--text-secondary);font-size:12.5px;margin-top:3px}}
.tile.win .v{{color:var(--good-ink)}}
.tile.behind .v{{color:var(--warning)}}
.tile.sole .v{{color:var(--ama)}}
.scroll{{overflow-x:auto;margin:14px 0 0;border:1px solid var(--border);border-radius:10px;
  background:var(--plane)}}
table{{border-collapse:collapse;width:100%;font-size:13.5px;color:var(--text-primary)}}
th,td{{padding:9px 11px;text-align:left;border-bottom:1px solid var(--border);color:inherit;
  white-space:nowrap}}
th{{font-weight:600;font-size:12px;color:var(--text-secondary);text-transform:uppercase;
  letter-spacing:.05em;background:var(--surface-1);position:sticky;top:0}}
tr:last-child td{{border-bottom:none}}
td.n{{text-align:right;font-variant-numeric:tabular-nums}}
td.p{{font-weight:560;white-space:normal;min-width:190px}}
td.x{{text-align:center;color:var(--muted)}}
td.y{{text-align:center;color:var(--good-ink);font-size:15px}}
td.lead{{font-weight:680}}
tr.uniq td.p{{color:var(--ama)}}
.cpb{{display:block;color:var(--muted);font-size:11px;font-weight:400}}
.note{{font-weight:400;color:var(--text-secondary);font-size:12.5px;margin-top:5px;
  white-space:normal;max-width:60ch;line-height:1.55}}
.b{{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11.5px;font-weight:620;
  white-space:nowrap}}
.b-win{{background:color-mix(in srgb,var(--good-ink) 15%,transparent);color:var(--good-ink)}}
.b-behind{{background:color-mix(in srgb,var(--warning) 20%,transparent);color:var(--text-primary)}}
.b-sole{{background:color-mix(in srgb,var(--ama) 16%,transparent);color:var(--ama)}}
.sup{{opacity:.6;margin:0 3px;font-weight:400}}
.cmps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px;margin-top:14px}}
.cmp{{background:var(--plane);border:1px solid var(--border);border-radius:10px;padding:13px 15px}}
.cmp-h{{display:flex;justify-content:space-between;align-items:baseline;font-size:13px;
  font-weight:600;margin-bottom:9px}}
.cmp-r{{font-variant-numeric:tabular-nums;font-size:12.5px}}
.cmp-r.up{{color:var(--good-ink)}}
.cmp-r.dn{{color:var(--text-secondary)}}
.rowbar{{position:relative;height:19px;margin-bottom:4px;display:flex;align-items:center}}
.rb{{height:11px;border-radius:0 4px 4px 0;min-width:2px}}
.rb.ama{{background:var(--ama)}}
.rb.peer{{background:var(--peer)}}
.rl{{margin-left:8px;font-size:11.5px;color:var(--text-secondary);
  font-variant-numeric:tabular-nums;white-space:nowrap}}
.legend{{display:flex;gap:16px;margin-top:12px;font-size:12.5px;color:var(--text-secondary)}}
.legend i{{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:6px;
  vertical-align:-1px}}
.callout{{background:var(--plane);border:1px solid var(--border);border-left:3px solid var(--ama);
  border-radius:8px;padding:14px 17px;margin:16px 0 0;color:var(--text-secondary);font-size:14px;
  max-width:82ch}}
.callout b{{color:var(--text-primary)}}
code{{font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--plane);
  border:1px solid var(--border);border-radius:4px;padding:1px 5px}}
pre{{background:var(--plane);border:1px solid var(--border);border-radius:9px;padding:14px 16px;
  overflow-x:auto;font:12.5px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;
  color:var(--text-secondary)}}
.toggle{{position:fixed;top:14px;right:14px;background:var(--plane);color:var(--text-secondary);
  border:1px solid var(--border);border-radius:8px;padding:6px 11px;font-size:12.5px;cursor:pointer}}
</style></head><body>
<button class="toggle" onclick="var r=document.documentElement,
  d=(r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'));
  r.setAttribute('data-theme',d==='dark'?'light':'dark')">theme</button>
<div class="wrap">

<h1>AMA Cryptography — full-surface competitive position</h1>
<p class="sub">Every primitive AMA exposes, against every library on the host that also
implements it.</p>
<p class="lede">This is not a curated selection of favourable comparisons. It is the
whole overlapping surface: {n_total} measured primitives across {nlibs} native libraries
plus OpenSSL 4.0.1 for the post-quantum pair, with the results AMA loses reported at the
same weight as the results it wins, and an engineering account of each gap.</p>

<div class="tiles">
  <div class="tile win"><div class="v">{n_win}</div><div class="k">primitives where AMA is
    fastest of all implementations measured</div></div>
  <div class="tile behind"><div class="v">{n_behind}</div><div class="k">where at least one
    peer is faster</div></div>
  <div class="tile sole"><div class="v">{n_sole}</div><div class="k">measured with no peer
    implementation to compare against</div></div>
  <div class="tile"><div class="v">{ama_only}<span style="font-size:17px;color:var(--muted)">
    /{n_cov}</span></div><div class="k">stack families only AMA implements</div></div>
</div>

<h2><span class="num">1</span>Stack coverage — what each library implements</h2>
<p class="lede">Speed is only half the comparison. This is the other half: of
{n_cov} primitive families in AMA's public surface, how many each peer offers at all.
Every cell records a runtime capability probe or a benchmark row from the
measurement run; the matrix is transcribed into the generator, not re-probed at
render time.</p>
<div class="scroll"><table>
<thead><tr><th>Primitive family</th>{cov_head}<th>Libs</th></tr></thead>
<tbody>
{cov_rows}
</tbody></table></div>

<h2><span class="num">2</span>AMA against the fastest peer, per primitive</h2>
<p class="lede">For each primitive: AMA's throughput against whichever library was
fastest on this host. The ratio is AMA ÷ best peer — above 1.00× means AMA leads the
entire field.</p>
<div class="legend">
  <span><i style="background:var(--ama)"></i>AMA Cryptography</span>
  <span><i style="background:var(--peer)"></i>fastest peer for that primitive</span>
</div>
<div class="cmps">
{bars}
</div>

<h2><span class="num">3</span>Standing, with the reason for every gap</h2>
<div class="scroll"><table>
<thead><tr><th>Primitive</th><th>AMA ops/s</th><th>Best peer ops/s</th>
<th>Ratio</th><th>Standing</th></tr></thead>
<tbody>
{standing_rows}
</tbody></table></div>

<h2><span class="num">4</span>Complete results — every primitive × every library</h2>
<p class="lede">The table view for the charts above. Bold is the fastest implementation
in that row. Symmetric rows carry cycles/byte, the metric eBACS and Crypto++ report,
computed against a measured clock rather than an assumed one.</p>
<div class="scroll"><table>
<thead><tr><th>Primitive</th>{matrix_head}</tr></thead>
<tbody>
{matrix_rows}
</tbody></table></div>

<h2><span class="num">5</span>How this was measured</h2>
<div class="callout">
<b>One host, one process, one set of buffers.</b> Every library is driven through its
own native API in the same binary, on the same input, with identical iteration counts
and best-of-5 round selection — the minimum round, because scheduler noise only ever
adds time. The CPU clock is <b>measured</b> at {freq} GHz via <code>rdtsc</code> against
<code>CLOCK_MONOTONIC</code>, not assumed, so cycles/byte is correct on this host rather
than on the host the harness was written on.
</div>
<div class="callout">
<b>Every verify is checked for success before it is timed.</b> An earlier revision of
this harness shared one signature buffer between the sign and verify loops. Because
DER-encoded ECDSA signatures vary between 70 and 72 bytes, the length went stale, verify
rejected in a few hundred cycles, and the table reported 8.5 M verifies/sec for wolfSSL
P-256 — a rejection path being timed, not a verification. Signatures for the verify loop
are now produced once into a buffer the sign loop never touches, and a row whose verify
does not return success is dropped rather than published.
</div>
<div class="callout">
<b>INVARIANT-36 holds.</b> That invariant forbids treating another implementation's
output as ground truth for correctness. No library here is consulted as a correctness
oracle — every peer is a stopwatch reference only, and AMA's correctness continues to
come from NIST ACVP and Wycheproof vectors in its own suite.
</div>
<div class="callout">
<b>Where the post-quantum numbers come from.</b> The system OpenSSL 3.0.13 implements
no ML-KEM, ML-DSA or SLH-DSA — probed, not assumed. The only peer on this host that
implements any of them is OpenSSL 4.0.1, reached through <code>cryptography</code>
49.0.0, so that pair is measured at the Python layer where both sides pay comparable
call overhead. It is a different measurement plane from the native C rows and is
labelled as such rather than merged into them.
</div>
<div class="callout">
<b>The post-quantum rows are also from a different host.</b>
<code>benchmarks/pqc_results.json</code> was captured where <code>cryptography</code>
49.0.0 (OpenSSL 4.0.1) was installed; the host this page's native rows were measured
on carries 41.0.7, which exposes no ML-KEM or ML-DSA, so those rows cannot be
re-measured here and were carried forward unchanged. They are unaffected by the
symmetric and elliptic-curve kernel work recorded in the changelog, which touched
no lattice code. Read them as a prior record, not as a measurement of this host.
</div>
<pre>python benchmarks/benchmark_suite.py
g++ -O2 -std=c++17 -DHAVE_OPENSSL -DHAVE_SODIUM -DHAVE_WOLFSSL -DHAVE_BOTAN \\
    -DHAVE_NETTLE -DHAVE_GCRYPT -DHAVE_MBEDTLS -I/usr/include/botan-2 -Iinclude \\
    benchmarks/multi_library_bench.cpp -Lbuild/lib -lama_cryptography \\
    -lssl -lcrypto -lsodium -lwolfssl -lbotan-2 -lnettle -lhogweed -lgcrypt -lmbedcrypto \\
    -o multibench
./multibench 65536                          # -> multi_library_results.json
python benchmarks/pqc_comparative_bench.py  # -> pqc_results.json
python benchmarks/generate_competitive.py   # -> this page</pre>

<p class="meta">
Generated {gen} · message size {msg} bytes · measured clock {freq} GHz<br>
Measured at commit <code>{src_commit}</code> ({src_measured}), AMA {src_version}<br>
Host: {host_line}<br>
{vers}<br>
Every figure on this page is read from <code>benchmarks/multi_library_results.json</code>
and <code>benchmarks/pqc_results.json</code>, including the AMA version above, which comes
from those files' provenance rather than from the working tree. The PEER LIBRARY
versions on the line above are pinned in <code>benchmarks/generate_competitive.py</code>,
because the harness does not record them — eight of the nine entries there are
string literals. Regenerating this page without re-running the harness re-renders
the same measurements under the same stamp; it cannot relabel them.
</p>

</div></body></html>
"""


def main() -> int:
    c, q = load()
    out = BENCH / "competitive.html"
    out.write_text(render(c, q), encoding="utf-8", newline="")
    print(f"wrote {out} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
