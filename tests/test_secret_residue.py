#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""No live copy of a secret survives its holder's wipe (INVARIANT-6).

Runs ``tools/measure_secret_residue.py`` over its whole inventory: after each
operation, and after the caller zeroes the secret it was handed, no other
reachable copy may exist anywhere in the process.  The instrument's scope --
live copies, not freed memory -- is stated in the tool's docstring.

The control test plants the retention defect the continuous-RNG test once had
(keeping the raw sample rather than its digest) and requires the instrument
to find exactly that copy, so a scan that silently saw nothing would fail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "measure_secret_residue.py"

pytestmark = pytest.mark.skipif(
    not os.path.exists("/proc/self/mem"), reason="the scan reads /proc/self/mem (Linux)"
)


def test_no_operation_leaves_a_live_copy_of_its_secret() -> None:
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--json"],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=1800,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rows = json.loads(proc.stdout)
    assert len(rows) >= 13, "the inventory shrank"
    leaking = {row["operation"]: row["copies"] for row in rows if row["copies"]}
    assert not leaking, f"live copies of a secret survived the wipe: {leaking}"


def test_the_scan_finds_a_retained_copy() -> None:
    """Non-vacuity: a health state that keeps the raw sample is found."""
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(REPO / "tools")!r})
        import measure_secret_residue as tool
        import ama_cryptography._module_state as ms

        real = ms._resolve_native

        def keep_raw(name, registered, role):
            fn = real(name, registered, role)
            return (lambda window: bytes(window)) if name == "native_sha256" else fn

        ms._resolve_native = keep_raw
        print(len(tool.measure(lambda: ms.secure_token_bytearray(32))))
        """)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "1", proc.stdout
