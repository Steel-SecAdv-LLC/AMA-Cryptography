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


class TestTheFourSilentBypassesAreClosed:
    """Each case below moved the pinned count by zero before the hardening.

    A gate that counts a *spelling* rather than a *binding* can be walked
    past four ways, and every one of them lands OpenSSL back on a production
    hashing path with the allowlist still reading green.  Each test states
    the count the old walker produced so the regression is legible.
    """

    def test_bare_names_from_a_from_import_count(self) -> None:
        """Old walker: 1 (the import); the two call sites were invisible."""
        tree = ast.parse(
            "from hashlib import sha256\n"
            "a = sha256(b'x').digest()\n"
            "b = sha256(b'y').digest()\n"
        )
        assert gate.count_hash_references(tree) == 3

    def test_uses_through_an_import_alias_count(self) -> None:
        """Old walker: 1 — the attribute root was not spelled ``hashlib``.

        ``__init__.py`` escaped this only because its alias happens to be
        ``_hashlib``, one of the two names the old walker hard-coded.
        """
        tree = ast.parse(
            "import hashlib as h\n"
            "a = h.sha256(b'x').digest()\n"
            "b = h.sha3_256(b'y').digest()\n"
        )
        assert gate.count_hash_references(tree) == 3

    def test_a_dynamic_import_counts(self) -> None:
        """Old walker: 0 — the module string never became an Import node."""
        assert (
            gate.count_hash_references(
                ast.parse("import importlib\nm = importlib.import_module('hashlib')\n")
            )
            == 1
        )
        assert gate.count_hash_references(ast.parse("m = __import__('hmac')\n")) == 1

    def test_stdlib_hmac_is_guarded_too(self) -> None:
        """Old walker: 0 — ``hmac`` was not a guarded module at all.

        On any libcrypto build ``hmac.new`` is OpenSSL computing an AMA MAC,
        which is the same INVARIANT-1 violation as ``hashlib.sha256``.
        """
        tree = ast.parse("import hmac\nt = hmac.new(b'k', b'm', 'sha256').digest()\n")
        assert gate.count_hash_references(tree) == 2

    def test_rebinding_a_direct_name_is_not_a_use(self) -> None:
        """Only Load contexts count, so the walker cannot over-count."""
        tree = ast.parse("from hashlib import sha256\nsha256 = None\n")
        assert gate.count_hash_references(tree) == 1


class TestTheScanReachesEveryFile:
    def test_a_subpackage_cannot_hide_a_use(self, tmp_path: Path) -> None:
        """The scan was non-recursive, so any subpackage was unscanned."""
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "mod.py").write_text("import hashlib\nX = hashlib.sha256(b'x')\n")
        failures = gate.scan_package(tmp_path)
        assert any("sub/mod.py" in f for f in failures)

    def test_pycache_is_not_scanned(self, tmp_path: Path) -> None:
        """Compiled leftovers are not source; scanning them fails honest trees."""
        (tmp_path / "real.py").write_text("x = 1\n")
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "stale.py").write_text("import hashlib\nX = hashlib.sha256(b'x')\n")
        # The absent-allowlist-entry failures are expected for a scratch tree;
        # what must NOT appear is a finding against the __pycache__ copy.
        assert not any("__pycache__" in f for f in gate.scan_package(tmp_path))
