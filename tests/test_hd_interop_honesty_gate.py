#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_hd_interop_honesty.py``.

``ama_cryptography/key_management.py`` derives its master key with the HMAC
key ``b"AMA Cryptography Master Key"`` where BIP32 specifies ``b"Bitcoin
seed"``.  The child KDF follows BIP32 exactly; the tree does not.  The source
file says it plainly: *no BIP32 test vector can pass here and no BIP32 wallet
or library derives the same keys from the same seed.*

So "BIP32-style" is true and "BIP32-compatible" is false, and the difference
is not pedantry — a reader who believes the latter hands this library a seed
phrase and expects their wallet's addresses back.

This was already corrected once.  ``CHANGELOG.md`` records it as KM-HD-001.
The correction shipped without a gate, and six sites still carried the false
claim afterwards: four in ``wiki/``, one in ``CRYPTOGRAPHY.md``, one in
``CSRC_STANDARDS.md``.  These tests exist so the third occurrence cannot
happen.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_hd_interop_honesty.py"
KEY_MANAGEMENT = REPO_ROOT / "ama_cryptography" / "key_management.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_hd_interop_honesty", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load()


def _fake_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    (tmp_path / "ama_cryptography").mkdir(parents=True, exist_ok=True)
    (tmp_path / "ama_cryptography" / "key_management.py").write_text("# stub\n")
    for relative, body in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------
# The claim the gate protects is actually true of the code
# --------------------------------------------------------------------------


def test_the_master_key_really_does_diverge_from_bip32() -> None:
    """The gate is only legitimate if the underlying fact holds.

    If someone ever changes the master HMAC key to BIP32's, this test fails
    and the gate should be deleted rather than worked around.
    """
    source = KEY_MANAGEMENT.read_text(encoding="utf-8")
    # The call site itself, not a mention of the constant in prose.
    assert '_hmac_sha512(b"AMA Cryptography Master Key"' in source, (
        "the master key is no longer derived with the AMA-specific HMAC key. "
        'If it now uses BIP32\'s b"Bitcoin seed", the tree may genuinely be '
        "BIP32-compatible — re-evaluate every claim in the documentation and "
        "delete this gate rather than working around it."
    )


# --------------------------------------------------------------------------
# What it must catch — the six real sites, as they were
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "- **HD Key Derivation** — BIP32-compatible hierarchical deterministic keys",
        "AMA Cryptography implements BIP32-compatible hierarchical deterministic",
        "**Elliptic curve operations** for BIP32-compatible HD key derivation.",
        'path["HD Path: m / purpose\'\\nBIP32-compatible, hardened-only"]',
        "- Used for HD key derivation (BIP32 compliance)",
        "The implementation is BIP-32 compliant.",
        "Fully BIP32 interoperable with standard wallets.",
        "This conforms to BIP-32.",
    ],
)
def test_each_false_claim_shape_fails(gate: ModuleType, tmp_path: Path, line: str) -> None:
    repo = _fake_repo(tmp_path, {"DOC.md": f"# Title\n\n{line}\n"})
    assert gate.find_claims(repo), f"not caught: {line}"


def test_the_standards_table_row_fails(gate: ModuleType, tmp_path: Path) -> None:
    """The row that the prose rules do NOT catch.

    It contains no 'compatible' and no 'compliant', yet asserts conformance
    more strongly than either: the Standard column of a conformance table IS
    the claim. Structured claims need a structured rule.
    """
    row = (
        "| secp256k1 | SEC 2 v2 / BIP-32 | 256-bit prime field | "
        "Certicom/Bitcoin curve; used for BIP-32 HD key derivation |"
    )
    repo = _fake_repo(tmp_path, {"CSRC_STANDARDS.md": f"| A | B | C | D |\n{row}\n"})
    assert not gate.find_claims(repo), "the prose rules should not catch this"
    assert gate.find_standards_table_claims(repo), "the table rule must catch it"


# --------------------------------------------------------------------------
# What it must NOT catch — the accurate wording
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "BIP32-style hierarchical deterministic key derivation.",
        "The child KDF follows BIP32's formulae exactly.",
        "The PRF is **HMAC-SHA-512** (BIP32-standard, delegated to the C backend).",
        "`derive_path(path)` accepts an explicit BIP32-style path.",
        "# Explicit BIP32 path — accepts both hardened (44') and non-hardened (44)",
        "the derived tree is deliberately not interoperable with a BIP32 wallet",
        "so the tree is NOT BIP32-compatible and no test vector applies",
        '`HDKeyDerivation` was documented "BIP32-compliant" while its master key',
        "2. Verify hardened-only BIP32 derivation is maintained",
    ],
)
def test_accurate_wording_passes(gate: ModuleType, tmp_path: Path, line: str) -> None:
    """A gate that bans the word outright would force the docs to say less.

    The goal is an accurate claim, not a silent one: 'BIP32-style' and 'the
    child KDF follows BIP32' are exactly what a reader needs.
    """
    repo = _fake_repo(tmp_path, {"DOC.md": f"# Title\n\n{line}\n"})
    assert not gate.find_claims(repo), f"false positive on accurate wording: {line}"


def test_the_changelog_is_exempt(gate: ModuleType, tmp_path: Path) -> None:
    """KM-HD-001's own entry has to quote the wording it retired."""
    repo = _fake_repo(
        tmp_path,
        {"CHANGELOG.md": '* KM-HD-001 — documented "BIP32-compliant" wrongly.\n'},
    )
    assert not gate.find_claims(repo)


# --------------------------------------------------------------------------
# Fail-closed, and the real tree
# --------------------------------------------------------------------------


def test_a_tree_with_no_documentation_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "ama_cryptography").mkdir(parents=True)
    (tmp_path / "ama_cryptography" / "key_management.py").write_text("# stub\n")
    assert gate.main(["--repo", str(tmp_path)]) == 2


def test_a_non_repository_fails_closed(gate: ModuleType, tmp_path: Path) -> None:
    assert gate.main(["--repo", str(tmp_path)]) == 2


def test_the_real_tree_makes_no_false_claim(gate: ModuleType) -> None:
    findings = gate.find_claims(REPO_ROOT) + gate.find_standards_table_claims(REPO_ROOT)
    assert not findings, "\n".join(
        f"{relative}:{number}: {line}" for relative, number, line, _ in findings
    )
