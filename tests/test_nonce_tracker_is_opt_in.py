# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The nonce ledger is opt-in, and the package says so.

``crypto_api`` builds a persistent ``NonceTracker`` at import (a ledger under
``~/.ama_cryptography``, an fsync-per-entry append path, a capacity policy and
an import-time degradation path), and no encrypt path in the package ever
calls ``check_nonce``: ``AESGCMProvider`` and ``SecureSession`` bound nonce use
through the durable per-key counter (INVARIANT-22) and never inspect nonce
values.  That is a defensible design — the tracker is public API for callers
who want (key, nonce) reuse detection around their own AEAD calls — but the
import-time comment and warning used to say cross-restart reuse detection "is
disabled" when the ledger could not load, which read as though the library had
been performing it.  The text now says opt-in; this pins the reading to the
code, so if someone wires the tracker into an encrypt path later, the text has
to change with it.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "ama_cryptography"
TRACKER_CALLS = {"check_nonce", "check_and_record"}


def _callers(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in TRACKER_CALLS:
                found.append(f"{path.name}:{node.lineno}:{node.func.attr}")
    return found


def test_no_encrypt_path_calls_the_tracker() -> None:
    """Only the monitor's own delegation (check_nonce -> check_and_record)
    calls into the tracker; every other module in the package is silent."""
    callers = {path.name: _callers(path) for path in sorted(PACKAGE.glob("*.py"))}
    outside = {name: calls for name, calls in callers.items() if calls and name != "monitoring.py"}
    assert outside == {}, (
        f"a package module now calls the nonce tracker: {outside}; the opt-in wording in "
        "crypto_api.py and monitoring.py must be rewritten to match"
    )
    assert any(
        c.endswith(":check_and_record") for c in callers["monitoring.py"]
    ), "the scan no longer sees the monitor's own delegation; the pattern broke"


def test_the_import_time_text_says_opt_in() -> None:
    source = (PACKAGE / "crypto_api.py").read_text(encoding="utf-8")
    assert "OPT-IN AmaCryptographyMonitor.check_nonce()" in source
    assert "the opt-in check_nonce() ledger" in source
    assert "nonce-reuse detection is disabled" not in source


def test_the_tracker_docstrings_say_opt_in() -> None:
    source = (PACKAGE / "monitoring.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    docs = {
        node.name: ast.get_docstring(node) or ""
        for node in ast.walk(tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
        and node.name in {"NonceTracker", "check_nonce"}
    }
    assert "Opt-in" in docs["NonceTracker"]
    assert "Opt-in" in docs["check_nonce"]


def test_the_library_encrypt_paths_use_the_counter_bound() -> None:
    """The bound that IS in the library: AESGCMProvider.encrypt reserves a
    durable per-key counter slot before drawing a nonce (INVARIANT-22)."""
    source = (PACKAGE / "crypto_api.py").read_text(encoding="utf-8")
    encrypt = source[source.index("    def encrypt(") : source.index("    def decrypt(")]
    assert "_reserve_counter_slot(key_id)" in encrypt
