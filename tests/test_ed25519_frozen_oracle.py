# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Replay the frozen Ed25519 oracle against the loaded native library.

``tests/oracle/ed25519_frozen_oracle.txt`` records 2,022 Ed25519 inputs and
the answers the since-removed vendored x86-64 backend gave for them at commit
``e848740``, the last tree that carried it: keypairs and signatures, single
and batch verification verdicts (honest signatures, the ``S + L`` malleable
twin, boundary ``S`` values, bit flips in every field, non-canonical and
small-order ``R``), the compressed-point decode rules, and the 32 output
bytes of every group-arithmetic entry point over unreduced scalars and
small-order points.  With that backend gone this fixture and the RFC 8032
§7.1 vectors are the independent oracles for the in-house backend, so it runs on
every Python lane — including ``windows-latest``, whose MSVC build takes the
fe51 path — and its C twin (``tests/c/test_ed25519_frozen_oracle.c``) runs on
every ctest lane.

The reader is ``tools/freeze_ed25519_oracle.py``'s own, so the tool that
writes the fixture and the test that replays it cannot disagree on the format.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ama_cryptography import pqc_backends
from tools.freeze_ed25519_oracle import FIXTURE_PATH, Library, replay

#: The record count the fixture was frozen with.  Pinned so a truncated
#: fixture cannot pass by replaying fewer cases than were recorded.
FROZEN_RECORDS = 2022


def _loaded_library_path() -> Path:
    """The filesystem path of the library the suite is running against.

    Read from the discovery record, not from the CDLL's ``_name``: on Linux a
    pre-load-verified library is mapped through ``/proc/self/fd/N`` and that
    descriptor is closed once the mapping exists, so ``_name`` is a path that
    no longer resolves.  A replay opened by that name only worked because the
    loader matched the already-mapped object by string.
    """
    if pqc_backends._native_lib is None:  # pragma: no cover - INVARIANT-7
        pytest.skip("native library unavailable")
    recorded = pqc_backends._NATIVE_LIB_PATH
    if not isinstance(recorded, str):  # pragma: no cover - discovery always records it
        raise RuntimeError("the loaded native library has no recorded path")
    path = Path(recorded)
    assert path.is_file(), f"recorded native library path does not exist: {path}"
    return path


def test_fixture_is_present_and_complete() -> None:
    assert FIXTURE_PATH.is_file(), FIXTURE_PATH
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    records = [line for line in lines if line and not line.startswith("#")]
    assert len(records) == FROZEN_RECORDS
    header = [line for line in lines if line.startswith("#")]
    assert any(line.startswith("# source-backend: vendored-x86-64") for line in header)
    assert any(line.startswith("# source-commit: e848740") for line in header)
    # Every record kind the format defines is present, so a regeneration that
    # dropped a family cannot pass on the count alone.
    kinds = {line[0] for line in records}
    assert kinds == set("KVBDPMAJRS")


def test_native_backend_reproduces_every_frozen_answer() -> None:
    lib = Library(_loaded_library_path())
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    checked, mismatches = replay(lib, lines)
    assert checked == FROZEN_RECORDS
    assert not mismatches, "\n".join(mismatches[:20])


def test_replay_detects_a_changed_answer() -> None:
    """Negative control (INVARIANT-2): a replayed mismatch is reported."""
    lib = Library(_loaded_library_path())
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    first_v = next(i for i, line in enumerate(lines) if line.startswith("V "))
    fields = lines[first_v].split()
    fields[-1] = "0" if fields[-1] == "1" else "1"
    lines[first_v] = " ".join(fields)
    checked, mismatches = replay(lib, lines)
    assert checked == FROZEN_RECORDS
    assert len(mismatches) == 1 and "verify verdict" in mismatches[0]
