#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the fuzz target registration verifier
(``tools/check_fuzz_target_registration.py``).

A fuzz harness is registered in three independent places — the CMake target
lists, the ``fuzzing.yml`` job matrix, and ``oss-fuzz/build.sh`` — and nothing
tied them together.  ``build.sh`` even carries a "keep in sync" comment and had
drifted anyway: ``fuzz_agent_binding`` was added to CMake and to the CI matrix
and never to ``build.sh``, so OSS-Fuzz never built it.  ``build.sh`` skips a
missing target with a warning and exits 0, which is why it stayed invisible.

Both directions are pinned here, because a checker that only ever reports
"clean" is indistinguishable from one that has stopped working.  The
non-detection cases matter as much as the detection ones: the first draft of
this checker produced three false positives, and each would have pushed a
maintainer to "fix" a repository that was already correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.check_fuzz_target_registration import (
    _cmake_targets,
    _ossfuzz_targets,
    _sources,
    _workflow_documented_exclusions,
    _workflow_targets,
    audit,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# The repository's own registration
# --------------------------------------------------------------------------


def test_repository_registration_is_consistent() -> None:
    failures = audit(REPO_ROOT)
    assert failures == [], "\n".join(failures)


def test_harnesses_are_discovered() -> None:
    sources = _sources(REPO_ROOT)
    assert len(sources) >= 15, f"only {len(sources)} harnesses discovered"
    assert "fuzz_ascon" in sources
    assert "fuzz_agent_binding" in sources


def test_support_translation_units_are_not_treated_as_harnesses() -> None:
    """``fuzz_rng.c`` supplies ``__wrap_ama_randombytes``; it is not a target.

    It also *names* ``LLVMFuzzerTestOneInput`` in a comment, so a substring
    test misclassifies it.  Both traps are live in this repository, and both
    produced a false positive in the first draft of the checker.
    """
    assert (REPO_ROOT / "fuzz" / "fuzz_rng.c").is_file()
    assert "fuzz_rng" not in _sources(REPO_ROOT)


def test_agent_binding_reaches_oss_fuzz() -> None:
    """Regression pin for the specific drift this checker was written for."""
    assert "fuzz_agent_binding" in _ossfuzz_targets(REPO_ROOT)
    assert "fuzz_agent_binding" in _cmake_targets(REPO_ROOT)


def test_ascon_is_registered_everywhere() -> None:
    assert "fuzz_ascon" in _cmake_targets(REPO_ROOT)
    assert "fuzz_ascon" in _ossfuzz_targets(REPO_ROOT)
    assert "fuzz_ascon" in _workflow_targets(REPO_ROOT)


def test_documented_exclusions_are_recognised() -> None:
    """A commented-out matrix entry is a deliberate, recorded exclusion.

    ``fuzz_sphincs`` is excluded from the per-PR lane because SPHINCS+ is too
    slow for CI, with the reason recorded beside it.  It must still be
    registered in both build lanes so OSS-Fuzz keeps running it.
    """
    excluded = _workflow_documented_exclusions(REPO_ROOT)
    assert "fuzz_sphincs" in excluded
    assert "fuzz_sphincs" not in _workflow_targets(REPO_ROOT)
    assert "fuzz_sphincs" in _cmake_targets(REPO_ROOT)
    assert "fuzz_sphincs" in _ossfuzz_targets(REPO_ROOT)


def test_cmake_comments_containing_parentheses_do_not_truncate_the_block() -> None:
    """A ")" inside a comment must not end the parsed list.

    The CMake lists carry comments like "(INVARIANT-30)".  Scanning for the
    first ")" without stripping comments first truncates the block and reports
    every target below the comment as unregistered — the checker's second
    false positive.
    """
    targets = _cmake_targets(REPO_ROOT)
    # These sit *after* a parenthesised comment in FUZZ_CORE_TARGETS.
    assert {"fuzz_agent_binding", "fuzz_ascon"} <= targets


# --------------------------------------------------------------------------
# Detection over a synthetic tree
# --------------------------------------------------------------------------


def _tree(
    tmp_path: Path,
    *,
    harnesses: list[str],
    cmake: list[str],
    workflow: list[str],
    ossfuzz: list[str],
) -> Path:
    (tmp_path / "fuzz").mkdir()
    for name in harnesses:
        (tmp_path / "fuzz" / f"{name}.c").write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n",
            encoding="utf-8",
        )
    entries = "\n".join(f"    {name}" for name in cmake)
    (tmp_path / "fuzz" / "CMakeLists.txt").write_text(
        f"set(FUZZ_CORE_TARGETS\n{entries}\n)\nset(FUZZ_PQC_TARGETS\n)\n",
        encoding="utf-8",
    )

    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    matrix = "\n".join(f"          - {name}" for name in workflow)
    (tmp_path / ".github" / "workflows" / "fuzzing.yml").write_text(
        f"jobs:\n  fuzz:\n    strategy:\n      matrix:\n        target:\n{matrix}\n",
        encoding="utf-8",
    )

    (tmp_path / "oss-fuzz").mkdir()
    array = "\n".join(f"    {name}" for name in ossfuzz)
    (tmp_path / "oss-fuzz" / "build.sh").write_text(
        f"FUZZ_TARGETS=(\n{array}\n)\n", encoding="utf-8"
    )
    return tmp_path


def test_missing_from_oss_fuzz_is_reported(tmp_path: Path) -> None:
    """The exact shape fuzz_agent_binding was in."""
    root = _tree(
        tmp_path,
        harnesses=["fuzz_a", "fuzz_b"],
        cmake=["fuzz_a", "fuzz_b"],
        workflow=["fuzz_a", "fuzz_b"],
        ossfuzz=["fuzz_a"],
    )
    failures = audit(root)
    assert len(failures) == 1
    assert "oss-fuzz/build.sh" in failures[0]
    assert "fuzz_b" in failures[0]


def test_missing_from_cmake_is_reported(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        harnesses=["fuzz_a", "fuzz_b"],
        cmake=["fuzz_a"],
        workflow=["fuzz_a", "fuzz_b"],
        ossfuzz=["fuzz_a", "fuzz_b"],
    )
    failures = audit(root)
    assert len(failures) == 1
    assert "fuzz/CMakeLists.txt" in failures[0]


def test_registry_naming_a_nonexistent_target_is_reported(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        harnesses=["fuzz_a"],
        cmake=["fuzz_a", "fuzz_ghost"],
        workflow=["fuzz_a"],
        ossfuzz=["fuzz_a"],
    )
    failures = audit(root)
    assert len(failures) == 1
    assert "fuzz_ghost" in failures[0]
    assert "no fuzz/<name>.c source" in failures[0]


def test_fully_consistent_tree_passes(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        harnesses=["fuzz_a", "fuzz_b"],
        cmake=["fuzz_a", "fuzz_b"],
        workflow=["fuzz_a", "fuzz_b"],
        ossfuzz=["fuzz_a", "fuzz_b"],
    )
    assert audit(root) == []


def test_support_file_without_entry_point_is_ignored(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        harnesses=["fuzz_a"],
        cmake=["fuzz_a"],
        workflow=["fuzz_a"],
        ossfuzz=["fuzz_a"],
    )
    # A support TU that merely mentions the entry point in a comment.
    (root / "fuzz" / "fuzz_helper.c").write_text(
        "/* runs before the first LLVMFuzzerTestOneInput call */\n" "void helper(void) {}\n",
        encoding="utf-8",
    )
    assert audit(root) == []


@pytest.mark.parametrize("missing_path", ["fuzz", "oss-fuzz/build.sh"])
def test_main_refuses_outside_the_repository_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_path: str
) -> None:
    """Running from the wrong directory must fail loudly, not report clean."""
    from tools.check_fuzz_target_registration import main

    monkeypatch.chdir(tmp_path)
    assert main() == 1
