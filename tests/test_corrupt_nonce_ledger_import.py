#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A corrupt persisted nonce ledger must not brick the library at import.

``crypto_api`` constructs a module-level disk-backed monitor at import, and
``NonceTracker._load_persisted`` deliberately raises ``RuntimeError`` on any
malformed line (a forgotten nonce could allow reuse). Before the fix that
RuntimeError propagated out of ``import ama_cryptography.crypto_api`` — a torn
final append after a crash or power loss, or a read-only or unresolvable HOME,
took the ENTIRE cryptographic library offline.

The fix degrades the import-time monitor to in-memory-only nonce tracking (with
a logged warning) instead of aborting import. These tests run in a subprocess
with an isolated HOME so the module-level ``_monitor`` is built fresh against a
planted ledger.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_IMPORT_PROBE = textwrap.dedent("""
    import ama_cryptography as ama
    import ama_cryptography.crypto_api as capi
    # library must be importable AND operational despite the corrupt ledger
    assert ama.module_status() == "OPERATIONAL", ama.module_status()
    # the module monitor exists (degraded to in-memory, not None)
    assert capi._monitor is not None
    print("IMPORT_OK")
    """)


def _import_with_home(tmp_home: Path) -> subprocess.CompletedProcess[str]:
    # A full-environment copy, not a three-key allowlist: a child Python on
    # Windows cannot even INITIALIZE without SYSTEMROOT (the OS RNG that
    # seeds hash randomization reads it), so the allowlisted env killed every
    # Windows lane with _Py_HashRandomization_Init before the probe ran a
    # line — and its hardcoded POSIX PATH was wrong there anyway.  The
    # isolation this test actually needs is narrower: the child must resolve
    # Path.home() to the scratch home (HOME on POSIX, USERPROFILE on Windows;
    # both set, both harmless cross-platform) and must not inherit AMA_*
    # overrides from the runner.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AMA_")}
    env["HOME"] = str(tmp_home)
    env["USERPROFILE"] = str(tmp_home)
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )


@pytest.mark.parametrize(
    "ledger_bytes",
    [
        b"deadbeefcafebabe,0011223344556677\ndeadbeef\n",  # torn final append (no comma)
        b"deadbeefcafebabe,0011223344556677\nnothex,alsohex!!\n",  # non-hex corruption
        b"\x00\x01\x02\x03 binary garbage \xff\xfe",  # binary corruption
        b"deadbeefcafebabe,\n",  # empty second field
    ],
    ids=["torn-append", "non-hex", "binary", "empty-field"],
)
def test_corrupt_ledger_does_not_brick_import(tmp_path: Path, ledger_bytes: bytes) -> None:
    home = tmp_path / "home"
    (home / ".ama_cryptography").mkdir(parents=True)
    (home / ".ama_cryptography" / "nonce_tracker.dat").write_bytes(ledger_bytes)
    result = _import_with_home(home)
    assert result.returncode == 0, (
        "import ama_cryptography aborted on a corrupt nonce ledger:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    assert "IMPORT_OK" in result.stdout, f"{result.stdout}\n{result.stderr}"


def test_clean_ledger_still_imports(tmp_path: Path) -> None:
    """Control: a clean HOME imports fine, so the tests above isolate the
    corruption, not some unrelated environment breakage."""
    home = tmp_path / "home"
    home.mkdir()
    result = _import_with_home(home)
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "IMPORT_OK" in result.stdout
