# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The per-slot known-answer sweep must cover every SIMD slot and cannot pass vacuously.

``AMA_DISPATCH_ONLY=<slot>`` pins one SIMD kernel and leaves every other slot at
its scalar fallback.  ``tests/c/test_dispatch_only_env.c`` proved the pin
resolves; it executes no cryptography.  Until the sweep in
``tests/c/CMakeLists.txt`` existed, no CTest case ran a published-vector KAT
with a SIMD kernel pinned, and the MemorySanitizer lanes built with SIMD off —
so the kernels every wheel runs were verified against the standards' answers
only when a host's default wiring happened to select them, and never under
MSan at all.

These tests pin the sweep's structure, in both directions:

* the slot inventory is ONE list, identical in the dispatcher, the contract
  test, the header's documentation, the CTest foreach and the dudect matrix;
* every slot has at least one sweep cell, and every cell names an executable
  that calls the guard as the first statement of ``main()`` — the guard is what
  turns "pin not honoured" into Skipped or FAIL instead of a scalar pass;
* the mandated / optional split matches dudect.yml's, so a wiring regression on
  a mandated slot is red on the same runner classes in both sweeps;
* both negative-control cells exist and match the guard's verdict lines;
* the sweep's header comment names every cell whose executable is not a
  published-answer KAT, so the comment cannot describe the table as more
  than it is;
* both MemorySanitizer lanes build the SIMD kernels.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parent.parent
DISPATCH_C = REPO_ROOT / "src" / "c" / "dispatch" / "ama_dispatch.c"
DISPATCH_H = REPO_ROOT / "include" / "ama_dispatch.h"
CONTRACT_C = REPO_ROOT / "tests" / "c" / "test_dispatch_only_env.c"
CMAKE = REPO_ROOT / "tests" / "c" / "CMakeLists.txt"
DUDECT_YML = REPO_ROOT / ".github" / "workflows" / "dudect.yml"
STATIC_ANALYSIS_YML = REPO_ROOT / ".github" / "workflows" / "static-analysis.yml"
GUARD_H = REPO_ROOT / "tests" / "c" / "kat_slot_guard.h"

_CELL_RE = re.compile(
    r"^ama_kat_sweep_cell\((?P<slot>\S+)\s+(?P<exe>\S+)\s+(?P<required>\S+)\s+\"(?P<extra>[^\"]*)\"\)",
    re.M,
)

#: Slots whose CPU feature is silicon-dependent on the hosted runners, and so
#: may skip (must equal dudect.yml's OPTIONAL_SLOTS).
OPTIONAL_SLOTS = {"sha3-avx512x4", "aes-gcm-vaes", "kyber-sve2", "sha3-sve2", "dilithium-ntt-sve2"}

#: Executables whose answers are published (FIPS 202/203/204, SP 800-38D,
#: RFC 7748/8439/9106, NIST ACVP) and reach the pinned kernel.  Every other
#: swept executable proves something weaker, and the sweep's header comment in
#: tests/c/CMakeLists.txt must say what, on a ``not-published <exe>:`` line.
PUBLISHED_KATS = {
    "test_kat",
    "test_ml_kem_acvp_encaps",
    "test_sha3",
    "test_sha3_512_stream",
    "test_chacha20poly1305",
    "test_argon2_rfc9106",
    "test_x25519",
    "test_aes_gcm_kat",
}

_NOT_PUBLISHED_RE = re.compile(r"^#\s+not-published\s+(?P<exe>test_\w+):", re.M)


def _c_string_list(source: str, array_name: str) -> list[str]:
    body = re.search(rf"{array_name}\[\]\s*=\s*\{{(.*?)\}};", source, re.S)
    assert body is not None, f"{array_name} not found"
    return re.findall(r'"([^"]+)"', body.group(1))


def _dispatcher_inventory() -> list[str]:
    return _c_string_list(DISPATCH_C.read_text(encoding="utf-8"), "AMA_DISPATCH_ONLY_SLOTS")


def _contract_inventory() -> list[str]:
    return _c_string_list(CONTRACT_C.read_text(encoding="utf-8"), "KNOWN_SLOTS")


def _header_inventory() -> list[str]:
    text = DISPATCH_H.read_text(encoding="utf-8")
    block = re.search(r"Recognised slot names.*?ama_dispatch_active_slot\(\)", text, re.S)
    assert block is not None
    return re.findall(r'^\s*\*\s+"([a-z0-9-]+)"\s+—', block.group(0), re.M)


def _cmake_foreach_inventory() -> list[str]:
    text = CMAKE.read_text(encoding="utf-8")
    block = re.search(r"foreach\(slot\n(.*?)\)\n\s*add_test\(NAME test_dispatch_only_", text, re.S)
    assert block is not None
    names = [line.strip() for line in block.group(1).splitlines() if line.strip()]
    # x25519-avx2 is registered separately with its opt-in flag.
    assert "x25519-avx2" in text
    return [*names, "x25519-avx2"]


def _dudect_matrix_inventory() -> list[str]:
    doc: dict[str, Any] = yaml.safe_load(DUDECT_YML.read_text(encoding="utf-8"))
    return list(doc["jobs"]["dudect-simd-sweep"]["strategy"]["matrix"]["slot"])


def _cells() -> list[dict[str, str]]:
    return [m.groupdict() for m in _CELL_RE.finditer(CMAKE.read_text(encoding="utf-8"))]


# ---------------------------------------------------------------------------
# One inventory
# ---------------------------------------------------------------------------
def test_the_slot_inventory_is_one_list_everywhere() -> None:
    dispatcher = _dispatcher_inventory()
    assert len(dispatcher) == len(set(dispatcher)), "duplicate slot name in the dispatcher"
    views = {
        "tests/c/test_dispatch_only_env.c KNOWN_SLOTS": set(_contract_inventory()),
        "include/ama_dispatch.h documentation": set(_header_inventory()),
        "tests/c/CMakeLists.txt test_dispatch_only foreach": set(_cmake_foreach_inventory()),
        "dudect.yml matrix": set(_dudect_matrix_inventory()),
    }
    for where, seen in views.items():
        assert seen == set(dispatcher), (
            f"{where} disagrees with the dispatcher's AMA_DISPATCH_ONLY_SLOTS: "
            f"missing {sorted(set(dispatcher) - seen)}, extra {sorted(seen - set(dispatcher))}"
        )


def test_every_slot_has_a_sweep_cell_and_every_cell_names_a_real_slot() -> None:
    inventory = set(_dispatcher_inventory())
    cells = _cells()
    assert cells, "no ama_kat_sweep_cell() calls found"
    swept = {c["slot"] for c in cells}
    assert swept == inventory, (
        f"slots with no KAT cell: {sorted(inventory - swept)}; "
        f"cells naming no slot: {sorted(swept - inventory)}"
    )


def test_every_slot_has_a_published_vector_kat_not_only_an_equivalence_run() -> None:
    """Equivalence runs prove agreement with the scalar path; only a published
    vector proves the kernel computes the standard."""
    by_slot: dict[str, set[str]] = {}
    for c in _cells():
        by_slot.setdefault(c["slot"], set()).add(c["exe"])
    for slot, exes in sorted(by_slot.items()):
        assert exes & PUBLISHED_KATS, f"{slot}: every cell is an equivalence run ({sorted(exes)})"


def test_the_sweep_comment_names_every_cell_that_is_not_a_published_kat() -> None:
    """The comment above the sweep is what a reader takes a cell to prove.

    It used to say the table held "only" published-answer KATs plus the AES-GCM
    and X25519 equivalence runs, while test_sha3_x4, test_argon2id,
    test_hybrid_sig and test_agent_binding sat in it as well -- so a cell such
    as ``argon2-g-avx2 test_argon2id`` read as published-vector evidence for
    the AVX2 G kernel, which it is not.  The per-slot test above could not see
    that: it asks only that each slot have ONE published cell.  This one holds
    the comment's ``not-published`` list equal to the cells whose executable is
    not a published KAT, in both directions.
    """
    text = CMAKE.read_text(encoding="utf-8")
    listed = [m.group("exe") for m in _NOT_PUBLISHED_RE.finditer(text)]
    assert listed, "the sweep comment carries no not-published list"
    assert len(listed) == len(set(listed)), f"an executable is listed twice: {sorted(listed)}"
    assert not set(listed) & PUBLISHED_KATS, (
        f"listed as not published, but PUBLISHED_KATS says otherwise: "
        f"{sorted(set(listed) & PUBLISHED_KATS)}"
    )
    swept_unpublished = {c["exe"] for c in _cells()} - PUBLISHED_KATS
    assert set(listed) == swept_unpublished, (
        "the sweep comment's not-published list disagrees with the table: "
        f"cells nobody classified {sorted(swept_unpublished - set(listed))}, "
        f"listed but not swept {sorted(set(listed) - swept_unpublished)}"
    )


# ---------------------------------------------------------------------------
# No vacuous pass
# ---------------------------------------------------------------------------
def test_every_swept_executable_calls_the_guard_first() -> None:
    exes = sorted({c["exe"] for c in _cells()})
    for exe in exes:
        source = (REPO_ROOT / "tests" / "c" / f"{exe}.c").read_text(encoding="utf-8")
        assert '#include "kat_slot_guard.h"' in source, f"{exe}.c does not include the guard"
        main = re.search(r"^int main\([^)]*\)\s*\{\n(.*?)\n\}", source, re.M | re.S)
        assert main is not None, f"{exe}.c: main() not found"
        first = next(line for line in main.group(1).splitlines() if line.strip())
        assert first.strip().startswith("KAT_SLOT_GUARD_OR_EXIT();"), (
            f"{exe}.c: the guard is not the first statement of main(); a cryptographic "
            f"call before it would initialise the dispatch table before the pin is checked"
        )


def test_the_guard_refuses_in_both_directions() -> None:
    source = GUARD_H.read_text(encoding="utf-8")
    assert "return 77;" in source
    assert "return 1;" in source
    assert 'getenv("AMA_KAT_SWEEP_REQUIRED")' in source
    assert "ama_dispatch_active_slot()" in source
    assert "[kat-slot-guard] FAIL:" in source and "[kat-slot-guard] SKIP:" in source


def test_every_cell_pins_off_the_autotune_and_may_skip() -> None:
    text = CMAKE.read_text(encoding="utf-8")
    fn = re.search(r"function\(ama_kat_sweep_cell.*?endfunction\(\)", text, re.S)
    assert fn is not None
    body = fn.group(0)
    assert "AMA_DISPATCH_NO_AUTOTUNE=1" in body, "a demoted slot would make the cell scalar"
    assert "SKIP_RETURN_CODE 77" in body
    assert "AMA_KAT_SWEEP_REQUIRED=1" in body
    assert (
        "get_test_property(${exe} WORKING_DIRECTORY" in body
    ), "cells must inherit the base test's working directory or test_kat cannot find its vectors"


def test_the_negative_controls_match_the_guards_verdict_lines() -> None:
    text = CMAKE.read_text(encoding="utf-8")
    pattern = r"{name} PROPERTIES.*?PASS_REGULAR_EXPRESSION\s+\"([^\"]+)\""
    fail = re.search(pattern.format(name="kat_sweep_control_mandated_refusal_fails"), text, re.S)
    skip = re.search(pattern.format(name="kat_sweep_control_optional_refusal_skips"), text, re.S)
    assert fail is not None and skip is not None
    guard = GUARD_H.read_text(encoding="utf-8")
    # The CMake string escapes the brackets; the guard prints them literally.
    assert re.search(fail.group(1).replace("\\\\", "\\"), "[kat-slot-guard] FAIL: x")
    assert re.search(skip.group(1).replace("\\\\", "\\"), "[kat-slot-guard] SKIP: x")
    assert "AMA_KAT_SWEEP_REQUIRED=1" in text.split("kat_sweep_control_mandated_refusal_fails")[2]
    assert "[kat-slot-guard] FAIL:" in guard


# ---------------------------------------------------------------------------
# Mandated / optional split matches the dudect sweep
# ---------------------------------------------------------------------------
def test_optional_slots_are_the_only_ones_never_mandated() -> None:
    never_mandated = {c["slot"] for c in _cells() if c["required"] == "0"}
    sometimes_mandated = {c["slot"] for c in _cells() if c["required"] != "0"}
    assert never_mandated - sometimes_mandated == OPTIONAL_SLOTS
    assert not (OPTIONAL_SLOTS & sometimes_mandated), "an optional slot is mandated somewhere"


def test_optional_slots_match_dudect() -> None:
    doc: dict[str, Any] = yaml.safe_load(DUDECT_YML.read_text(encoding="utf-8"))
    steps = doc["jobs"]["dudect-simd-sweep"]["steps"]
    run = next(
        str(s["run"]) for s in steps if str(s.get("name", "")).startswith("Confirm dispatch slot")
    )
    m = re.search(r'OPTIONAL_SLOTS="([^"]*)"', run)
    assert m is not None
    assert set(m.group(1).split()) == OPTIONAL_SLOTS


def test_x25519_cell_carries_the_opt_in_flag() -> None:
    cells = [c for c in _cells() if c["slot"] == "x25519-avx2"]
    assert cells and all("AMA_DISPATCH_USE_X25519_AVX2=1" in c["extra"] for c in cells)


# ---------------------------------------------------------------------------
# MemorySanitizer builds the kernels it is meant to instrument
# ---------------------------------------------------------------------------
def test_both_msan_lanes_build_the_simd_kernels() -> None:
    doc: dict[str, Any] = yaml.safe_load(STATIC_ANALYSIS_YML.read_text(encoding="utf-8"))
    lanes = {"memory-sanitizer", "memory-sanitizer-kat"}
    assert lanes <= set(doc["jobs"]), "an MSan lane was renamed or removed"
    for job_id in sorted(lanes):
        configure = "\n".join(str(s.get("run", "")) for s in doc["jobs"][job_id]["steps"])
        assert "-DAMA_ENABLE_SIMD=ON" in configure, f"{job_id} does not build the SIMD kernels"
        assert "-DAMA_ENABLE_SIMD=OFF" not in configure
        assert "-DAMA_ENABLE_AVX512=ON" in configure, f"{job_id} does not build the AVX-512 kernel"


def test_the_kat_msan_lane_runs_the_sweep_cells() -> None:
    doc: dict[str, Any] = yaml.safe_load(STATIC_ANALYSIS_YML.read_text(encoding="utf-8"))
    runs = "\n".join(str(s.get("run", "")) for s in doc["jobs"]["memory-sanitizer-kat"]["steps"])
    assert "kat_sweep__.*__test_kat" in runs
    assert "--no-tests=error" in runs
