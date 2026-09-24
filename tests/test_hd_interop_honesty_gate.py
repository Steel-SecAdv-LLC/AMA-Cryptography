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
        # A negation elsewhere on the line used to exempt all of these: the
        # cue denied something else, and the claim went through with it.
        "HDKeyDerivation is BIP32-compatible, so you do not need a separate wallet library.",
        "Deliberately BIP32-compliant for wallet migration.",
        "It is BIP32-compatible and no longer needs a conversion shim.",
        "BIP32-compatible derivation; nothing is interoperable with SLIP-10, not yet.",
        "It is not only BIP32-compatible but fast.",
        "Not BIP32-style: it is BIP32-compliant.",
        "The derived tree is not SLIP-10 but is BIP32-compatible.",
        # One denied occurrence must not cover a second, affirmed one.
        "Earlier releases were not BIP32-compliant; this one is BIP32-compliant.",
        # The noun: `compatible` alone let this through.
        "Full BIP32 compatibility with hardware wallets.",
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
        # Denials that govern the phrase itself.
        "The tree is no longer BIP32-compatible, and never was.",
        "this is a non-BIP32-compatible tree",
        'So "BIP32-style" is true and "BIP32-compatible" is false.',
        "It does not conform to BIP32: the master key differs.",
        "a tree without BIP32 compatibility",
        "It isn't BIP32 compliant.",
        "The tree cannot be BIP32-compatible while the master key differs.",
    ],
)
def test_accurate_wording_passes(gate: ModuleType, tmp_path: Path, line: str) -> None:
    """A gate that bans the word outright would force the docs to say less.

    The goal is an accurate claim, not a silent one: 'BIP32-style' and 'the
    child KDF follows BIP32' are exactly what a reader needs.
    """
    repo = _fake_repo(tmp_path, {"DOC.md": f"# Title\n\n{line}\n"})
    assert not gate.find_claims(repo), f"false positive on accurate wording: {line}"


# --------------------------------------------------------------------------
# Where the claim can live — the package's own docstrings included
# --------------------------------------------------------------------------


def test_the_km_hd_001_docstring_is_caught(gate: ModuleType, tmp_path: Path) -> None:
    """KM-HD-001's false claim lived in a Python docstring, which the scan
    never read: restoring it passed the gate that was written for it."""
    source = (
        "class HDKeyDerivation:\n"
        '    """Hierarchical Deterministic Key Derivation (BIP32-compliant)"""\n'
        "\n"
        "    def derive_child_key(self):\n"
        '        """\n'
        "        Child Key Derivation (Private) - BIP32 Compliant\n"
        '        """\n'
    )
    repo = _fake_repo(tmp_path, {"DOC.md": "# Title\n"})
    (repo / "ama_cryptography" / "key_management.py").write_text(source, encoding="utf-8")
    found = {(relative, number) for relative, number, _line, _why in gate.find_claims(repo)}
    assert found == {
        ("ama_cryptography/key_management.py", 2),
        ("ama_cryptography/key_management.py", 6),
    }


def test_package_comments_and_messages_are_read_but_code_is_not(
    gate: ModuleType, tmp_path: Path
) -> None:
    """Prose is read; code is not.  Line 3 is ``BIP32 - compatible`` on two
    names, which the banned pattern matches as text: reading the file whole
    would report it, and an expression is not a claim."""
    source = (
        "# HD keys here are BIP32-compatible.\n"
        'ERROR = "derivation is BIP32 compliant"\n'
        "margin = BIP32-compatible  # arithmetic on two names\n"
    )
    repo = _fake_repo(tmp_path, {"DOC.md": "# Title\n"})
    (repo / "ama_cryptography" / "hd.py").write_text(source, encoding="utf-8")
    found = sorted(number for _relative, number, _line, _why in gate.find_claims(repo))
    assert found == [1, 2]


def test_documentation_at_any_depth_is_read(gate: ModuleType, tmp_path: Path) -> None:
    """The root was scanned non-recursively and only wiki/ and docs/ below it,
    so a README under examples/ or benchmarks/ was never read."""
    repo = _fake_repo(
        tmp_path,
        {
            "DOC.md": "# Title\n",
            "examples/README.md": "These examples are BIP32-compatible.\n",
            "benchmarks/notes/hd.rst": "HD derivation conforms to BIP32.\n",
        },
    )
    found = sorted(relative for relative, _number, _line, _why in gate.find_claims(repo))
    assert found == ["benchmarks/notes/hd.rst", "examples/README.md"]


def test_the_real_tree_scan_reaches_the_package_and_nested_docs(gate: ModuleType) -> None:
    """Non-vacuity for the widened scope on the real tree."""
    sources = {path.relative_to(REPO_ROOT).as_posix() for path in gate.scanned_sources()}
    assert "ama_cryptography/key_management.py" in sources
    docs = {path.relative_to(REPO_ROOT).as_posix() for path in gate.scanned_files()}
    assert any(relative.count("/") >= 2 for relative in docs), sorted(docs)
    assert not any(relative.startswith("docs/changelog/") for relative in docs)


@pytest.mark.parametrize(
    "text",
    [
        "HD derivation here is BIP32\ncompatible with hardware wallets.\n",
        "HD derivation here is BIP32-\ncompatible with hardware wallets.\n",
        "The derived tree conforms\nto BIP32.\n",
    ],
)
def test_a_claim_wrapped_across_two_lines_is_caught(
    gate: ModuleType, tmp_path: Path, text: str
) -> None:
    """Matching one physical line at a time never saw a phrase split by a wrap."""
    repo = _fake_repo(tmp_path, {"DOC.md": f"# Title\n\n{text}"})
    assert [number for _r, number, _l, _w in gate.find_claims(repo)] == [3]


def test_a_denial_wrapped_across_two_lines_passes(gate: ModuleType, tmp_path: Path) -> None:
    repo = _fake_repo(
        tmp_path, {"DOC.md": "# Title\n\nThe tree is not BIP32\ncompatible, by design.\n"}
    )
    assert gate.find_claims(repo) == []


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
