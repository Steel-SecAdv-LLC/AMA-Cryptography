# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``docs/ATTACK_SURFACE.md`` matches the tree, and the gap list is empty.

The 2026-10-08 diagnostics recorded two open items: no document mapped the
attack surface to its defences, and 13 exported entry points were reached
by no C test and no fuzz harness.  ``tools/measure_attack_surface.py``
generates the document, ``tests/c/test_export_coverage.c`` closed the 13,
and this gate holds both end states: the committed page is a pure function
of the tree (fixpoint), and no exported entry point is reached by neither
suite.  Deleting the C suite, or adding an ``AMA_API`` declaration with no
test or harness, fails this gate.
"""

from __future__ import annotations

from pathlib import Path

from tools.measure_attack_surface import (
    DOC,
    declared_abi,
    gaps,
    measure,
    render,
)

REPO = Path(__file__).resolve().parents[1]


def test_the_committed_page_is_at_fixpoint() -> None:
    """PIN: editing the page by hand, or changing the tree without
    regenerating, fails here with the regeneration command."""
    assert DOC.exists(), "docs/ATTACK_SURFACE.md is missing; regenerate with --write"
    expected = render(measure(REPO))
    assert DOC.read_text(encoding="utf-8") == expected, (
        "docs/ATTACK_SURFACE.md does not match the tree; regenerate with: "
        "python tools/measure_attack_surface.py --write"
    )


def test_every_entry_point_is_reached_by_a_c_test_or_fuzz_harness() -> None:
    """PIN: deleting tests/c/test_export_coverage.c reopens the 13 gaps the
    2026-10-08 diagnostics measured, and this names them."""
    missing = gaps(measure(REPO))
    assert missing == [], (
        "exported entry points reached by neither a C test nor a fuzz " f"harness: {missing}"
    )


def test_the_declared_abi_is_the_built_export_set() -> None:
    """RANGE: the instrument's ABI source (AMA_API declarations under
    include/) matches the shared object when one is built; without a build
    the declaration count alone is pinned, so the gate runs on a pristine
    checkout too."""
    declared = declared_abi(REPO)
    assert len(declared) == len(set(declared))
    lib = REPO / "build" / "lib" / "libama_cryptography.so"
    if not lib.exists():
        assert len(declared) >= 190
        return
    import re
    import subprocess

    out = subprocess.run(
        ["nm", "-D", "--defined-only", str(lib)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    exported = sorted({m.group(1) for m in re.finditer(r"\sT\s+(ama_\w+)", out)})
    assert exported == declared


def _plant(tmp_path: Path, with_test: bool) -> Path:
    (tmp_path / "include").mkdir(parents=True)
    (tmp_path / "include" / "x.h").write_text(
        "AMA_API int ama_planted_entry(void);\nAMA_API int ama_planted(void);\n",
        encoding="utf-8",
    )
    (tmp_path / "tests" / "c").mkdir(parents=True)
    if with_test:
        (tmp_path / "tests" / "c" / "test_planted.c").write_text(
            "int main(void) { return ama_planted_entry(); }\n", encoding="utf-8"
        )
    return tmp_path


def test_the_instrument_sees_a_gap_and_its_closure(tmp_path: Path) -> None:
    """PIN for the instrument: an unreferenced declaration is a gap, a C-test
    reference closes it, and the match is word-bounded — ``ama_planted`` is
    not credited with ``ama_planted_entry``'s reference."""
    missing = gaps(measure(_plant(tmp_path, with_test=False)))
    assert missing == ["ama_planted", "ama_planted_entry"]

    missing = gaps(measure(_plant(tmp_path / "covered", with_test=True)))
    assert missing == ["ama_planted"]
