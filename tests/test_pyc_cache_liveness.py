#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``_cache_header_is_live`` must agree with the interpreter that will run.

The POST ``execution-integrity`` stage exists because CPython does not execute
source, it executes compiled bytecode: a ``.pyc`` whose body does not
correspond to its signed ``.py`` runs whatever it contains.  The stage compares
each cached module against a fresh compile of the signed source — but only for
caches it believes the interpreter would actually load.  ``_cached_code_for``
skips anything ``_cache_header_is_live`` calls not-live, and a skip counts as a
pass.

So a wrong answer there is not cosmetic in either direction:

* **too strict** — a cache the interpreter would reject gets judged, and an
  ordinary stale ``.pyc`` becomes a hard POST failure on an importable tree;
* **too lax** — a cache the interpreter DOES execute is recorded as "no cached
  bytecode to bind", and poisoned bytecode runs while POST reports OPERATIONAL.

The function used to read the PEP 552 flag bits alone.  CPython's
``SourceLoader.get_code`` gates hash validation on
``_imp.check_hash_based_pycs != "never" and (check_source or
_imp.check_hash_based_pycs == "always")`` — a condition the flag bits cannot
express — so it was wrong in both directions, one per non-default setting of
that flag.  Measured before the fix, over the six (flag-bits x mode) cases: two
mismatches, one of each kind.  After: zero.

These tests are subprocess-driven because the property is about what a *freshly
started* interpreter does, and ``--check-hash-based-pycs`` can only be set at
start-up.
"""

from __future__ import annotations

import importlib.util as iu
import marshal
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SELF_TEST = REPO_ROOT / "ama_cryptography" / "_self_test.py"

#: (flags value, human label).  0b01 = hash-based, check_source clear;
#: 0b11 = hash-based, check_source set.  Timestamp caches (bit 0 clear) do not
#: involve ``check_hash_based_pycs`` at all and are covered by the stage's own
#: tests.
FLAG_CASES = ((0b01, "unchecked-hash"), (0b11, "check-source-hash"))
MODES = ("default", "never", "always")


def _plant_poisoned_cache(directory: Path, flags: int) -> tuple[Path, bytes]:
    """A module whose cache carries a WRONG source hash and a changed body.

    Returns the source path and the 12 header bytes after the magic number.
    """
    src = directory / "mod.py"
    src.write_text('MARKER = "clean"\n', encoding="utf-8")
    code = compile('MARKER = "POISONED"\n', str(src), "exec")
    cache = Path(iu.cache_from_source(str(src)))
    cache.parent.mkdir(parents=True, exist_ok=True)
    with open(cache, "wb") as handle:
        handle.write(iu.MAGIC_NUMBER)
        handle.write(struct.pack("<I", flags))
        handle.write(b"\x00" * 8)  # a hash the source cannot produce
        marshal.dump(code, handle)
    return src, cache.read_bytes()[4:16]


def _argv(mode: str) -> list[str]:
    if mode == "default":
        return [sys.executable]
    return [sys.executable, "--check-hash-based-pycs", mode]


def _cpython_executes_the_cache(directory: Path, mode: str) -> bool:
    """Ground truth: did a fresh interpreter run the poisoned body?"""
    proc = subprocess.run(
        [
            *_argv(mode),
            "-c",
            f"import sys; sys.path.insert(0, {str(directory)!r}); import mod; print(mod.MARKER)",
        ],
        capture_output=True,
        text=True,
        cwd=str(directory),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    return proc.stdout.strip() == "POISONED"


def _function_says_live(src: Path, header: bytes, mode: str) -> bool:
    """What the shipped function answers, in an interpreter started with ``mode``."""
    program = (
        "import importlib.util as iu\n"
        f"spec = iu.spec_from_file_location('st', {str(SELF_TEST)!r})\n"
        "module = iu.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        f"print(module._cache_header_is_live({str(src)!r}, bytes.fromhex({header.hex()!r})))\n"
    )
    proc = subprocess.run(
        [*_argv(mode), "-c", program],
        capture_output=True,
        text=True,
        env=dict(os.environ, AMA_POST_DIAGNOSTIC_IMPORT="1"),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    return proc.stdout.strip().splitlines()[-1] == "True"


@pytest.mark.parametrize("flags,label", FLAG_CASES, ids=[c[1] for c in FLAG_CASES])
@pytest.mark.parametrize("mode", MODES)
def test_liveness_matches_what_the_interpreter_does(
    tmp_path: Path, flags: int, label: str, mode: str
) -> None:
    """The whole property, one cell of the matrix per parameter set."""
    src, header = _plant_poisoned_cache(tmp_path, flags)
    executed = _cpython_executes_the_cache(tmp_path, mode)
    live = _function_says_live(src, header, mode)
    assert live == executed, (
        f"{label} under --check-hash-based-pycs={mode}: CPython "
        f"{'executed' if executed else 'rejected'} the cache while the function "
        f"reported live={live}. A cache the interpreter runs must be judged; one "
        f"it rejects must not be."
    )


def test_the_matrix_is_not_degenerate(tmp_path: Path) -> None:
    """Non-vacuity: the six cells must not all have the same ground truth.

    If CPython executed (or rejected) the poisoned cache in every
    configuration, the parametrised test above would pass for a function that
    returned a constant.
    """
    outcomes = set()
    for flags, _label in FLAG_CASES:
        for mode in MODES:
            directory = tmp_path / f"{flags}-{mode}"
            directory.mkdir()
            _plant_poisoned_cache(directory, flags)
            outcomes.add(_cpython_executes_the_cache(directory, mode))
    assert outcomes == {True, False}, outcomes
