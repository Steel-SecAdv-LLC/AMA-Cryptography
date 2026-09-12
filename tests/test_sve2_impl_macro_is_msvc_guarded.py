# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""AMA_HAVE_SVE2_IMPL must be defined only where the +sve2 flag is applied.

Audit H5.  ``CMakeLists.txt`` applied ``-march=armv9-a+sve2`` to the SVE2
translation units inside ``if(NOT MSVC)``, but set
``add_compile_definitions(AMA_HAVE_SVE2_IMPL)`` OUTSIDE that guard, so it fired
for any ``CMAKE_SYSTEM_PROCESSOR`` matching ARM64 — MSVC included.  Every SVE2
TU guards its whole body on ``__ARM_FEATURE_SVE2``, which only that skipped flag
defines, so on MSVC ARM64 the SVE2 objects held zero defined symbols while
``src/c/dispatch/ama_dispatch.c`` still referenced ten SVE2 kernel symbols under
``AMA_HAVE_SVE2_IMPL``: LNK2019 unresolved externals — the exact break the NEON
block was rewritten to prevent.

Reproduced with the equivalent GCC condition (aarch64-linux-gnu-gcc, no +sve2):
``ama_kyber_sve2.o`` / ``ama_sha3_sve2.o`` / ``ama_dilithium_sve2.o`` each
compile to an object with zero defined global symbols; with ``+sve2`` they
define 6 / 1 / 3.  MSVC ARM64 is built by no CI lane, so this structural test is
the coverage: the macro must sit inside the NOT-MSVC block, and the dispatcher's
SVE2 references must all sit under it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CMAKELISTS = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
DISPATCH = (REPO_ROOT / "src" / "c" / "dispatch" / "ama_dispatch.c").read_text(encoding="utf-8")
SVE2_HEADER = (REPO_ROOT / "src" / "c" / "sve2" / "ama_sve2_internal.h").read_text(encoding="utf-8")

#: Every SVE2 kernel the SVE2 internal header declares.  Discovered rather than
#: hand-listed: a kernel added to the header without being added here would
#: otherwise escape the linkage audit entirely.
#:
#: The header is the right source, not the dispatcher: the dispatcher also names
#: non-kernel ``*_sve2`` tokens (tier and environment-variable strings such as
#: ``ama_kyber_sve2`` and the ``ama_has_arm_sve2`` predicate), and discovering
#: from it would make the symbol set follow whatever the dispatcher happens to
#: reference — which is the very thing under test.
SVE2_DECLARED_SYMBOLS = tuple(sorted(set(re.findall(r"\bama_[a-z0-9_]+_sve2\b", SVE2_HEADER))))

#: A header declaring fewer kernels than this has been truncated, not shrunk;
#: an empty discovery would make every assertion below vacuous.
MIN_SVE2_KERNELS = 10

#: Kernels the dispatcher deliberately does NOT wire, each with the reason.
#: Hand-written on purpose: "not wired" is a decision, so a kernel that falls
#: out of the dispatcher without an entry here is a regression, not a discovery.
#: Their references must still be guarded — the equivalence tests link them.
DELIBERATELY_UNWIRED: dict[str, str] = {
    "ama_kyber_poly_pointwise_sve2": (
        "the AVX2/NEON/SVE2 basemul kernels hold no vector instruction, and "
        "under callgrind the AVX2 one retires about 35% more instructions per "
        "call than the inline scalar basemul it displaces (which the compiler "
        "auto-vectorises when the slot is NULL). The slot stays NULL on every "
        "tier until a genuinely vectorised basemul exists; the kernels stay "
        "compiled for their equivalence tests."
    ),
}

#: The kernels the dispatcher is required to wire.
SVE2_KERNEL_SYMBOLS = tuple(sym for sym in SVE2_DECLARED_SYMBOLS if sym not in DELIBERATELY_UNWIRED)


def _cmake_block(source: str, opening: str) -> str:
    """The body of one CMake ``if(...)`` block, matched by its ``endif()``.

    Nesting-aware, so an inner ``if()`` does not close the outer one — "the rest
    of the file after the opening line" is not a block, and an assertion scoped
    that way passes on text the block does not contain.
    """
    assert source.count(opening) == 1, f"expected exactly one {opening!r} in CMakeLists.txt"
    start = source.index(opening) + len(opening)
    depth = 1
    out: list[str] = []
    for line in source[start:].splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("if("):
            depth += 1
        elif stripped.startswith("endif("):
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(line)
    raise AssertionError(f"no endif() closes {opening!r}")


def _not_msvc_subblock(sve2_block: str) -> str:
    """The body of the ``if(NOT MSVC)`` block within the SVE2 section, up to its
    ``else()`` — the region where the +sve2 flag is applied and the macro must
    live.  Bounded, so a match cannot leak into the ``else()`` arm or past it.
    """
    opening = "if(NOT MSVC)"
    assert sve2_block.count(opening) == 1, "the SVE2 section's NOT-MSVC guard moved or was renamed"
    start = sve2_block.index(opening) + len(opening)
    depth = 1
    out: list[str] = []
    for line in sve2_block[start:].splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("if("):
            depth += 1
        elif stripped.startswith(("else()", "elseif(")) and depth == 1:
            return "".join(out)
        elif stripped.startswith("endif("):
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(line)
    raise AssertionError("no else()/endif() closes the SVE2 if(NOT MSVC) block")


class TestTheMacroIsInsideTheFlagGuard:
    def test_the_sve2_section_exists(self) -> None:
        # Non-vacuity: the assertions below say nothing if the block is gone.
        block = _cmake_block(CMAKELISTS, "if(AMA_ENABLE_SIMD AND AMA_ENABLE_SVE2)")
        assert "-march=armv9-a+sve2" in block
        assert "add_compile_definitions(AMA_HAVE_SVE2_IMPL)" in block

    def test_the_macro_is_inside_the_not_msvc_guard(self) -> None:
        block = _cmake_block(CMAKELISTS, "if(AMA_ENABLE_SIMD AND AMA_ENABLE_SVE2)")
        guarded = _not_msvc_subblock(block)
        assert "add_compile_definitions(AMA_HAVE_SVE2_IMPL)" in guarded, (
            "AMA_HAVE_SVE2_IMPL is not inside the SVE2 if(NOT MSVC) block. Outside "
            "it, the macro fires on MSVC ARM64 while the +sve2 flag does not, so "
            "the dispatcher references ten SVE2 symbols the flag-less TUs never "
            "define — LNK2019 (audit H5)."
        )

    def test_the_flag_and_the_macro_share_the_one_guard(self) -> None:
        """Both the flag and the macro must be under the SAME NOT-MSVC block, so
        they can never drift apart — the macro true while the flag is absent."""
        block = _cmake_block(CMAKELISTS, "if(AMA_ENABLE_SIMD AND AMA_ENABLE_SVE2)")
        guarded = _not_msvc_subblock(block)
        assert "-march=armv9-a+sve2" in guarded
        # And the macro must NOT appear in the SVE2 block outside that guard.
        outside = block.replace(guarded, "")
        assert "AMA_HAVE_SVE2_IMPL" not in outside, (
            "AMA_HAVE_SVE2_IMPL also appears in the SVE2 section outside the "
            "NOT-MSVC guard; a build without the +sve2 flag would still define it"
        )


class TestTheDispatcherGatesEverySve2Reference:
    """With the macro undefined, no SVE2 symbol reference may survive.

    The macro guard only prevents the LNK2019 if the dispatcher references the
    SVE2 kernels EXCLUSIVELY under ``#ifdef AMA_HAVE_SVE2_IMPL``; an unguarded
    reference would keep the same unresolved-external even after the CMake fix.
    """

    def test_every_sve2_symbol_reference_is_under_the_macro(self) -> None:
        # Every DECLARED kernel, not only the wired ones: an unwired kernel that
        # reappears outside the guard is the same unresolved external.
        without = _strip_ifdef_blocks(DISPATCH, "AMA_HAVE_SVE2_IMPL")
        leaked = sorted(sym for sym in SVE2_DECLARED_SYMBOLS if sym in without)
        assert not leaked, (
            f"these SVE2 kernel symbols are referenced OUTSIDE "
            f"#ifdef AMA_HAVE_SVE2_IMPL: {leaked}. With the macro undefined "
            f"(MSVC ARM64) they are unresolved externals regardless of the CMake "
            f"fix."
        )

    def test_the_declared_kernel_set_is_not_empty(self) -> None:
        # Non-vacuity of the discovery itself: an empty or truncated header
        # would make every assertion in this file pass over nothing.
        assert len(SVE2_DECLARED_SYMBOLS) >= MIN_SVE2_KERNELS, (
            f"discovered only {len(SVE2_DECLARED_SYMBOLS)} SVE2 kernel(s) in "
            f"src/c/sve2/ama_sve2_internal.h (expected at least "
            f"{MIN_SVE2_KERNELS}): {list(SVE2_DECLARED_SYMBOLS)}"
        )

    def test_the_symbols_really_are_referenced_when_the_macro_is_defined(self) -> None:
        # Non-vacuity: the guard must actually contain the references, or the
        # test above would pass over a dispatcher that wires nothing.
        present = [sym for sym in SVE2_KERNEL_SYMBOLS if sym in DISPATCH]
        assert present == list(SVE2_KERNEL_SYMBOLS), (
            f"the dispatcher no longer references all SVE2 kernels; missing "
            f"{sorted(set(SVE2_KERNEL_SYMBOLS) - set(present))}. If the slot was "
            f"unwired on purpose, record it in DELIBERATELY_UNWIRED with the "
            f"evidence; do not delete the symbol from the audit."
        )

    def test_every_unwired_kernel_is_really_unwired(self) -> None:
        """DELIBERATELY_UNWIRED must not become a place to park live slots.

        Without this, an entry added to silence the test above would keep
        silencing it after the slot came back — and the audit would no longer
        describe the dispatcher.
        """
        for symbol, reason in DELIBERATELY_UNWIRED.items():
            assert symbol in SVE2_DECLARED_SYMBOLS, (
                f"{symbol} is listed as deliberately unwired but the SVE2 header "
                f"no longer declares it; drop the entry"
            )
            assert f"= {symbol}" not in DISPATCH, (
                f"{symbol} is listed as deliberately unwired but the dispatcher "
                f"assigns it to a slot; remove the DELIBERATELY_UNWIRED entry"
            )
            assert reason.strip(), f"{symbol} has no recorded reason"


def _strip_ifdef_blocks(source: str, macro: str) -> str:
    """``source`` with every ``#ifdef <macro>`` … ``#endif`` block removed.

    Nesting-aware on the preprocessor conditionals so an inner ``#if`` does not
    end the block early.  Used to ask what remains referenced when ``macro`` is
    undefined.  A depth-1 ``#else`` (or ``#elif``) RESUMES emission: that arm
    is exactly what compiles when the macro is undefined, so a dispatcher
    edited into ``#ifdef AMA_HAVE_SVE2_IMPL … #else <sve2 ref> #endif`` shape
    leaks the reference into the stripped view and fails the gate — the
    previous version dropped the else-arm with the guarded one, so that
    shape's unresolved external stayed invisible.  ``#ifndef <macro>`` is
    still not modelled (its body would need the inverse treatment); the
    dispatcher does not use it for SVE2, and if it starts to, the non-vacuity
    test alongside keeps the symbols themselves pinned.
    """
    lines = source.splitlines(keepends=True)
    out: list[str] = []
    skip_depth = 0
    for line in lines:
        stripped = line.lstrip()
        if skip_depth == 0 and re.match(rf"#ifdef\s+{re.escape(macro)}\b", stripped):
            skip_depth = 1
            continue
        if skip_depth > 0:
            if stripped.startswith(("#if", "#ifdef", "#ifndef")):
                skip_depth += 1
            elif stripped.startswith("#endif"):
                skip_depth -= 1
            elif skip_depth == 1 and stripped.startswith(("#else", "#elif")):
                # The macro-undefined arm: emit until this conditional closes.
                skip_depth = 0
                out.append(line)
            continue
        out.append(line)
    return "".join(out)


class TestTheStripperModelsElseArms:
    """The stripper is itself a model, and a model with a hole is a gate off.

    ``#ifdef AMA_HAVE_SVE2_IMPL … #else <ref> #endif``: the else-arm is what
    compiles when the macro is UNDEFINED, so a symbol there is exactly the
    unresolved external the gate exists to catch — and the stripper used to
    drop the else-arm along with the guarded one.
    """

    def test_a_reference_in_an_else_arm_survives_stripping(self) -> None:
        source = (
            "#ifdef AMA_HAVE_SVE2_IMPL\n"
            "  use(ama_keccak_f1600_sve2);\n"
            "#else\n"
            "  use(ama_keccak_f1600_sve2); /* leaks when undefined */\n"
            "#endif\n"
        )
        stripped = _strip_ifdef_blocks(source, "AMA_HAVE_SVE2_IMPL")
        assert "ama_keccak_f1600_sve2" in stripped

    def test_the_guarded_arm_is_still_removed(self) -> None:
        source = (
            "#ifdef AMA_HAVE_SVE2_IMPL\n"
            "  use(ama_keccak_f1600_sve2);\n"
            "#endif\n"
            "outside();\n"
        )
        stripped = _strip_ifdef_blocks(source, "AMA_HAVE_SVE2_IMPL")
        assert "ama_keccak_f1600_sve2" not in stripped
        assert "outside();" in stripped

    def test_an_inner_else_does_not_resume_emission(self) -> None:
        source = (
            "#ifdef AMA_HAVE_SVE2_IMPL\n"
            "#if OTHER\n"
            "  a();\n"
            "#else\n"
            "  use(ama_keccak_f1600_sve2);\n"
            "#endif\n"
            "#endif\n"
        )
        stripped = _strip_ifdef_blocks(source, "AMA_HAVE_SVE2_IMPL")
        assert "ama_keccak_f1600_sve2" not in stripped
