#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_algorithm_registry.py``.

CSRC_STANDARDS.md's first paragraph claims exhaustiveness ("maps every
cryptographic primitive implemented in AMA Cryptography ... Only algorithms
with shipping code are listed") and INVARIANTS.md's INVARIANT-1 Addendum makes
it binding ("Adding any new algorithm requires updating CSRC_STANDARDS.md ...
**before** implementation is permitted").  Nothing checked either.

Measured: run against ``CSRC_STANDARDS.md`` as it stood before this pass, the
gate reports **18** violations by name — ECDSA/ECDH over the NIST curves
(FIPS 186-5 and SP 800-56A rev. 3 both uncited, and P-256/P-384/P-521 each
missing an Algorithm-column row), LMS and HSS verification (SP 800-208),
ML-KEM-512, ML-KEM-768, ML-DSA-44, ML-DSA-87, SLH-DSA-SHAKE-128s,
HMAC-SHA-384, HMAC-SHA-512 and HMAC-SHA3-256 — all shipping code, in a
document that says it lists all of it.

The last three are why the gate has a parameter-set level at all: the
family-level check saw ``ama_hmac_*`` cite FIPS 198-1 through the HMAC-SHA-256
row and called the family covered, while three further HMAC constructions
shipped with no row.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_algorithm_registry.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_algorithm_registry", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, header: str, registry: str) -> Path:
    (tmp_path / "include").mkdir(parents=True, exist_ok=True)
    (tmp_path / "include" / "ama_cryptography.h").write_text(header, encoding="utf-8")
    (tmp_path / "CSRC_STANDARDS.md").write_text(registry, encoding="utf-8")
    return tmp_path


class TestTheShippedTree:
    def test_the_registry_is_complete_today(self, gate: ModuleType) -> None:
        assert gate.audit(REPO_ROOT) == []

    def test_the_scan_is_not_vacuous(self, gate: ModuleType) -> None:
        families = gate.discovered_families(REPO_ROOT / gate.HEADER)
        assert len(families) >= gate.MIN_FAMILIES, sorted(families)
        rows = gate.registry_rows(REPO_ROOT / gate.REGISTRY)
        assert len(rows) >= gate.MIN_REGISTRY_ROWS, len(rows)

    def test_the_families_the_audit_found_missing_are_now_mapped(self, gate: ModuleType) -> None:
        """Named individually, because these six are why the gate exists."""
        for family in ("nistp", "lms", "hss", "ml", "kem", "slhdsa"):
            assert gate.FAMILY_REGISTRY_TOKENS.get(family), family

    def test_every_parameter_set_is_declared_not_defaulted(self, gate: ModuleType) -> None:
        """The second level's version of the rule above.

        A parameter set the mapping does not know must FAIL, so the mapping
        cannot fall behind the header by accident.
        """
        discovered = gate.discovered_parameter_sets(REPO_ROOT / gate.HEADER)
        assert len(discovered) >= gate.MIN_PARAM_SETS, sorted(discovered)
        for identifier in discovered:
            assert identifier in gate.PARAM_SET_TOKENS, identifier

    def test_every_parameter_set_has_its_own_algorithm_row(self, gate: ModuleType) -> None:
        """Each token in its own Algorithm cell, not merely somewhere in a row."""
        rows = gate.registry_rows(REPO_ROOT / gate.REGISTRY)
        cells = gate.registry_algorithm_cells(rows)
        for identifier in sorted(gate.discovered_parameter_sets(REPO_ROOT / gate.HEADER)):
            token = gate.PARAM_SET_TOKENS[identifier]
            assert any(token in cell for cell in cells), (identifier, token)

    def test_every_support_surface_is_declared_not_defaulted(self, gate: ModuleType) -> None:
        """``None`` must be a decision, not the fallback for an unknown name."""
        families = gate.discovered_families(REPO_ROOT / gate.HEADER)
        for family in families:
            assert family in gate.FAMILY_REGISTRY_TOKENS, family

    def test_the_cli_reports_success(
        self, gate: ModuleType, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert gate.main(["--root", str(REPO_ROOT)]) == 0
        assert "primitive families" in capsys.readouterr().out


class TestTheRule:
    """Synthetic trees, so the rule is exercised rather than the shipped tree."""

    #: One prototype per family, plus the three HMAC variants that are
    #: distinguished by SYMBOL rather than by an enum, plus the parameter-set
    #: enums.  The enum block matters: without it the parameter-set scan sees
    #: nothing and the audit fails closed, which is the behaviour
    #: :meth:`test_a_header_with_no_parameter_sets_fails_closed` pins.
    HEADER = (
        "\n".join(
            f"AMA_API ama_error_t ama_{name}_op(void);"
            for name in (
                "sha3",
                "shake128",
                "shake256",
                "sha256",
                "sha384",
                "sha512",
                "pbkdf2",
                "hkdf",
                "argon2id",
                "aes256",
                "aes",
                "chacha20poly1305",
                "ascon",
                "kyber",
                "ml",
                "kem",
                "dilithium",
                "sphincs",
                "slhdsa",
                "lms",
                "hss",
                "ed25519",
                "x25519",
                "secp256k1",
                "nistp",
                "frost",
            )
        )
        + "\n"
        + "\n".join(
            f"AMA_API ama_error_t ama_hmac_{h}(void);" for h in ("sha384", "sha512", "sha3_256")
        )
        + "\n"
        + "\n".join(
            f"    {name} = {i},"
            for i, name in enumerate(
                (
                    "AMA_ML_DSA_44",
                    "AMA_ML_DSA_65",
                    "AMA_ML_DSA_87",
                    "AMA_ML_KEM_512",
                    "AMA_ML_KEM_768",
                    "AMA_ML_KEM_1024",
                    "AMA_SLHDSA_SHA2_256F",
                    "AMA_SLHDSA_SHAKE_128S",
                    "AMA_NIST_CURVE_P256",
                    "AMA_NIST_CURVE_P384",
                    "AMA_NIST_CURVE_P521",
                )
            )
        )
        + "\n"
    )

    #: Standard-column tokens: satisfied by a mention anywhere in the row.
    FAMILY_TOKENS = (
        "FIPS 202",
        "SHAKE128",
        "SHAKE256",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "FIPS 198-1",
        "NIST SP 800-132",
        "RFC 5869",
        "RFC 9106",
        "NIST SP 800-38D",
        "RFC 8439",
        "NIST SP 800-232",
        "ML-KEM-1024",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-DSA-65",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s",
        "NIST SP 800-208",
        "RFC 8032",
        "RFC 7748",
        "SEC 2 v2",
        "FIPS 186-5",
        "NIST SP 800-56A",
        "RFC 9591",
    )

    #: Algorithm-column tokens: each needs its OWN row's first cell.
    PARAM_TOKENS = (
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s",
        "P-256",
        "P-384",
        "P-521",
        "HMAC-SHA-384",
        "HMAC-SHA-512",
        "HMAC-SHA3-256",
    )

    @classmethod
    def _registry(cls, rows: int = 45, omit: str = "") -> str:
        """A registry that satisfies both levels, minus ``omit``.

        ``omit`` names a token to withhold; it is matched against the family
        tokens (Standard column) and the parameter-set tokens (Algorithm
        column) alike, so one parameter drives both negative controls.
        """
        lines = ["| Algorithm | Standard |", "|---|---|"]
        for token in cls.PARAM_TOKENS:
            if token == omit:
                lines.append("| withheld | filler |")
            else:
                lines.append(f"| {token} (alias) | filler |")
        for token in cls.FAMILY_TOKENS:
            if token == omit:
                lines.append("| row | filler-omitted |")
            else:
                lines.append(f"| row | {token} |")
        for i in range(len(lines) - 2, rows):
            lines.append(f"| filler-{i} | filler-{i} |")
        return "\n".join(lines) + "\n"

    def test_a_complete_registry_passes(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _tree(tmp_path, self.HEADER, self._registry())
        assert gate.audit(root) == []

    @pytest.mark.parametrize(
        "omit",
        [
            "FIPS 186-5",
            "NIST SP 800-56A",
            "NIST SP 800-208",
            "ML-KEM-512",
            "SLH-DSA-SHAKE-128s",
        ],
    )
    def test_a_missing_family_row_is_reported(
        self, gate: ModuleType, tmp_path: Path, omit: str
    ) -> None:
        root = _tree(tmp_path, self.HEADER, self._registry(omit=omit))
        problems = gate.audit(root)
        assert problems, f"accepted a registry with no {omit!r} row"
        assert any(omit in problem for problem in problems), problems

    @pytest.mark.parametrize(
        "omit", ["ML-DSA-44", "ML-DSA-87", "P-384", "HMAC-SHA-384", "HMAC-SHA-512", "HMAC-SHA3-256"]
    )
    def test_a_missing_parameter_set_row_is_reported(
        self, gate: ModuleType, tmp_path: Path, omit: str
    ) -> None:
        """The level the family check could not reach.

        ``ama_hmac_*`` maps to "FIPS 198-1" and ``ama_dilithium_*`` to
        "ML-DSA-65"; both stay satisfied here, so a failure can only come from
        the parameter-set pass.
        """
        root = _tree(tmp_path, self.HEADER, self._registry(omit=omit))
        problems = gate.audit(root)
        assert problems, f"accepted a registry whose Algorithm column omits {omit!r}"
        assert any(
            "Algorithm column" in problem and omit in problem for problem in problems
        ), problems

    def test_a_family_citation_does_not_satisfy_a_parameter_set(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """A row that MENTIONS the token elsewhere must not count.

        This is the PBKDF2 shape: "PBKDF2 with HMAC-SHA-512 PRF" sits in
        another algorithm's row and would satisfy a whole-row search.
        """
        registry = self._registry(omit="HMAC-SHA-512").replace(
            "| withheld | filler |", "| PBKDF2 | PBKDF2 with HMAC-SHA-512 PRF |"
        )
        root = _tree(tmp_path, self.HEADER, registry)
        problems = gate.audit(root)
        assert any("HMAC-SHA-512" in problem for problem in problems), problems

    def test_an_unmapped_family_is_reported(self, gate: ModuleType, tmp_path: Path) -> None:
        header = self.HEADER + "\nAMA_API ama_error_t ama_newalgo_keygen(void);\n"
        root = _tree(tmp_path, header, self._registry())
        problems = gate.audit(root)
        assert any("ama_newalgo_*" in problem for problem in problems), problems

    def test_an_unmapped_parameter_set_is_reported(self, gate: ModuleType, tmp_path: Path) -> None:
        """A new parameter set cannot be quietly left out of either file."""
        header = self.HEADER + "\n    AMA_ML_KEM_9999 = 9999,\n"
        root = _tree(tmp_path, header, self._registry())
        problems = gate.audit(root)
        assert any("AMA_ML_KEM_9999" in problem for problem in problems), problems

    def test_a_truncated_registry_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _tree(tmp_path, self.HEADER, "| Algorithm | Standard |\n|---|---|\n| a | b |\n")
        problems = gate.audit(root)
        assert problems and "looks truncated" in problems[0]

    def test_a_collapsed_header_scan_fails_closed(self, gate: ModuleType, tmp_path: Path) -> None:
        root = _tree(tmp_path, "AMA_API ama_error_t ama_sha3_op(void);\n", self._registry())
        problems = gate.audit(root)
        assert problems and "collapsed scan" in problems[0]

    def test_a_header_with_no_parameter_sets_fails_closed(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        """Families intact, enums gone: the second scan must not pass vacuously."""
        # Drop the enumerator lines only — they are the indented ones. The
        # AMA_API prototypes stay, so the family scan still sees 26 families
        # and the failure can only come from the parameter-set floor.
        header = "\n".join(
            line for line in self.HEADER.splitlines() if not line.startswith("    AMA_")
        )
        root = _tree(tmp_path, header, self._registry())
        problems = gate.audit(root)
        assert problems and "parameter sets" in problems[0], problems
