#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Pins for tools/check_stdlib_hash_boundary.py — the INVARIANT-1 hashlib gate.

The gate's claim: every ``hashlib`` / ``_hashlib`` reference in the shipped
package sits inside a pinned, rationale-carrying trust-bootstrap allowlist,
so OpenSSL-backed stdlib hashing cannot quietly re-enter a production path.
A gate is only as good as its failure modes, so each is driven here: the
clean tree passes, a use outside the allowlist fails, growth inside an
allowlisted file fails, a stale allowlist entry fails, and docstring/comment
mentions do not count.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tools import check_stdlib_hash_boundary as gate


class TestTheRealTreeHoldsTheBoundary:
    def test_the_shipped_package_passes(self) -> None:
        assert gate.scan_package(gate.PACKAGE_DIR) == []

    def test_the_allowlist_counts_match_reality_exactly(self) -> None:
        """Each entry's count is live-recomputed — the allowlist cannot rot."""
        for name, (expected, _reason) in gate.ALLOWLIST.items():
            tree = ast.parse((gate.PACKAGE_DIR / name).read_text(encoding="utf-8"))
            assert gate.count_hash_references(tree) == expected, name

    def test_every_allowlist_entry_carries_a_reason(self) -> None:
        for name, (_expected, reason) in gate.ALLOWLIST.items():
            assert reason.strip(), f"{name}: an acknowledgement of nothing"


class TestTheGateFailsWhenItMust:
    def test_a_use_outside_the_allowlist_fails(self, tmp_path: Path) -> None:
        (tmp_path / "rogue.py").write_text("import hashlib\nX = hashlib.sha256(b'x')\n")
        failures = gate.scan_package(tmp_path)
        assert any(
            "rogue.py" in f and "not in the trust-bootstrap allowlist" in f for f in failures
        )

    def test_growth_inside_an_allowlisted_file_fails(self, tmp_path: Path) -> None:
        # One more reference than __init__.py's pinned count of 2.
        (tmp_path / "__init__.py").write_text(
            "import hashlib\nA = hashlib.sha3_256(b'a')\nB = hashlib.md5(b'b')\n"
        )
        failures = gate.scan_package(tmp_path)
        assert any("__init__.py" in f and "allowlist records 2" in f for f in failures)

    def test_a_stale_allowlist_entry_fails(self, tmp_path: Path) -> None:
        """Every allowlisted file must exist, or the entry could cover a
        future file it was never written for."""
        (tmp_path / "unrelated.py").write_text("x = 1\n")
        failures = gate.scan_package(tmp_path)
        stale = {f.split(":")[0] for f in failures if "allowlisted but absent" in f}
        assert stale == set(gate.ALLOWLIST)

    def test_an_empty_scan_refuses_to_pass(self, tmp_path: Path) -> None:
        failures = gate.scan_package(tmp_path)
        assert any("refusing to pass an empty scan" in f for f in failures)


class TestOnlyRealReferencesCount:
    def test_docstrings_and_comments_do_not_count(self) -> None:
        tree = ast.parse(
            '"""Docs may say hashlib.sha256 freely."""\n'
            "# hashlib.sha3_256 in a comment\n"
            "x = 1\n"
        )
        assert gate.count_hash_references(tree) == 0

    def test_imports_and_attributes_both_count(self) -> None:
        tree = ast.parse("import hashlib\nimport _hashlib\ny = hashlib.new('sha256')\n")
        assert gate.count_hash_references(tree) == 3

    def test_from_import_counts(self) -> None:
        tree = ast.parse("from hashlib import sha256\n")
        assert gate.count_hash_references(tree) == 1
