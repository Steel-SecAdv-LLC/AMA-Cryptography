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

    def test_rebinding_the_module_root_is_followed(self) -> None:
        """The fifth bypass: old walker counted 2 (import + aliasing load).

        ``_h = hashlib`` bound the module to a name outside ``_module_roots``,
        so every later ``_h.sha3_256(...)`` moved the pinned count by zero —
        inside an allowlisted file that bought unlimited extra OpenSSL uses
        with the gate green.  Now: import (1) + the aliasing load (1) + each
        use through the alias (2) = 4.
        """
        tree = ast.parse(
            "import hashlib\n"
            "_h = hashlib\n"
            "a = _h.sha3_256(b'x').digest()\n"
            "b = _h.sha3_256(b'y').digest()\n"
        )
        assert gate.count_hash_references(tree) == 4

    def test_getattr_on_a_guarded_root_counts(self) -> None:
        """Old walker: 1 (the import) — the receiver was a Call argument,
        not an Attribute value, so ``getattr(hashlib, "sha3_256")()`` was
        free.  The bare load of the root is the reference."""
        tree = ast.parse("import hashlib\nf = getattr(hashlib, 'sha3_256')\nd = f(b'x')\n")
        assert gate.count_hash_references(tree) == 2

    def test_an_attribute_use_is_still_one_reference_not_two(self) -> None:
        """Counting root loads must not double-count ``hashlib.sha256``:
        the Name inside a counted Attribute is consumed by it."""
        tree = ast.parse("import hashlib\ny = hashlib.new('sha256')\n")
        assert gate.count_hash_references(tree) == 2


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


class TestRunTimeModuleNamesAreResolvedOrRefused:
    """Bypasses 7 and 8: a module named by an expression, or read from the cache.

    Measured before the fix: ``__import__('hash' + 'lib')``,
    ``sys.modules['hashlib']`` and ``import_module(n)`` with a variable ``n``
    each added zero to the count, so a file outside the allowlist carrying any
    of them passed the gate.
    """

    @staticmethod
    def _scan(tmp_path: Path, source: str, name: str = "rogue.py") -> list[str]:
        (tmp_path / name).write_text(source)
        return gate.scan_package(tmp_path)

    @staticmethod
    def _rogue(failures: list[str]) -> list[str]:
        return [f for f in failures if f.startswith("rogue.py")]

    def test_a_concatenated_dynamic_import_counts(self, tmp_path: Path) -> None:
        failures = self._scan(tmp_path, "m = __import__('hash' + 'lib')\n")
        assert any("not in the trust-bootstrap allowlist" in f for f in self._rogue(failures))

    def test_an_fstring_dynamic_import_counts(self, tmp_path: Path) -> None:
        source = "import importlib\nP = 'hash'\nm = importlib.import_module(f'{P}lib')\n"
        failures = self._scan(tmp_path, source)
        assert any("not in the trust-bootstrap allowlist" in f for f in self._rogue(failures))

    def test_a_variable_dynamic_import_fails_outright(self, tmp_path: Path) -> None:
        source = "import importlib\n\ndef load(n):\n    return importlib.import_module(n)\n"
        failures = self._rogue(self._scan(tmp_path, source))
        assert len(failures) == 1, failures
        assert "rogue.py:4: import_module(n)" in failures[0]
        assert "not allowlistable" in failures[0]

    def test_an_unresolvable_import_fails_even_in_an_allowlisted_file(self, tmp_path: Path) -> None:
        source = "import hashlib\nx = hashlib.sha256\ny = __import__(input())\n"
        failures = self._scan(tmp_path, source, name="__init__.py")
        assert any(f.startswith("__init__.py:3: __import__(input())") for f in failures), failures

    def test_sys_modules_subscript_of_a_guarded_module_counts(self, tmp_path: Path) -> None:
        for source in (
            "import sys\nh = sys.modules['hashlib']\n",
            "import sys as s\nh = s.modules['_hashlib']\n",
            "from sys import modules\nh = modules['hm' + 'ac']\n",
            "import sys\nh = sys.modules.get('hashlib')\n",
        ):
            sub = tmp_path / str(abs(hash(source)))
            sub.mkdir()
            failures = self._rogue(self._scan(sub, source))
            assert any("not in the trust-bootstrap allowlist" in f for f in failures), source

    def test_an_unresolvable_sys_modules_key_fails(self, tmp_path: Path) -> None:
        source = "import sys\n\ndef get(k):\n    return sys.modules[k]\n"
        failures = self._rogue(self._scan(tmp_path, source))
        assert failures and "sys.modules(k)" in failures[0], failures

    def test_module_own_name_and_literals_pass(self, tmp_path: Path) -> None:
        """The shapes the real package uses must stay clean (control)."""
        source = (
            "import importlib, sys\n"
            "me = sys.modules[__name__]\n"
            "pb = sys.modules.get('ama_cryptography.pqc_backends')\n"
            "def baselines():\n"
            "    names = ['ama_cryptography.crypto_api', 'ama_cryptography.key_management']\n"
            "    for mod_name in names:\n"
            "        importlib.import_module(mod_name)\n"
            "MODS = ('a.b', 'a.c')\n"
            "def verify():\n"
            "    for mod_name in MODS:\n"
            "        importlib.import_module(mod_name)\n"
            "def _load(lib):\n"
            "    return importlib.import_module(lib)\n"
            "_load('json')\n"
            "_load(lib='os')\n"
        )
        assert self._rogue(self._scan(tmp_path, source)) == []

    def test_a_loop_over_a_mutated_list_is_not_resolved(self, tmp_path: Path) -> None:
        source = (
            "import importlib\n"
            "def f(extra):\n"
            "    names = ['json']\n"
            "    names.append(extra)\n"
            "    for n in names:\n"
            "        importlib.import_module(n)\n"
        )
        failures = self._rogue(self._scan(tmp_path, source))
        assert failures and "import_module(n)" in failures[0], failures

    def test_a_loop_over_dict_items_is_not_resolved(self, tmp_path: Path) -> None:
        """The shape monitoring.verify_imports has."""
        source = (
            "import importlib\n"
            "def f(baselines):\n"
            "    for mod_name, path in baselines.items():\n"
            "        importlib.import_module(mod_name)\n"
        )
        failures = self._rogue(self._scan(tmp_path, source))
        assert failures and "import_module(mod_name)" in failures[0], failures

    def test_a_rebound_or_global_name_is_not_resolved(self, tmp_path: Path) -> None:
        source = (
            "import importlib\n"
            "N = 'json'\n"
            "def poison():\n"
            "    global N\n"
            "    N = 'hashlib'\n"
            "def f():\n"
            "    return importlib.import_module(N)\n"
            "def g(flag):\n"
            "    m = 'json'\n"
            "    if flag:\n"
            "        m = 'hashlib'\n"
            "    return importlib.import_module(m)\n"
        )
        failures = self._rogue(self._scan(tmp_path, source))
        assert [f.split(":")[1] for f in failures] == ["7", "12"], failures

    def test_a_private_helper_that_escapes_is_not_resolved(self, tmp_path: Path) -> None:
        """A helper passed around may be called with anything."""
        source = (
            "import importlib\n"
            "def _load(lib):\n"
            "    return importlib.import_module(lib)\n"
            "_load('json')\n"
            "REGISTRY = [_load]\n"
        )
        failures = self._rogue(self._scan(tmp_path, source))
        assert failures and "import_module(lib)" in failures[0], failures

    def test_a_private_helper_called_with_a_guarded_name_counts(self, tmp_path: Path) -> None:
        source = (
            "import importlib\n"
            "def _load(lib):\n"
            "    return importlib.import_module(lib)\n"
            "_load('json')\n"
            "_load('hashlib')\n"
        )
        failures = self._rogue(self._scan(tmp_path, source))
        assert any("not in the trust-bootstrap allowlist" in f for f in failures), failures
