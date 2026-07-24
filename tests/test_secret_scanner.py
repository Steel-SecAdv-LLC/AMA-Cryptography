#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Detection tests for the in-house secret scanner (``tools/check_secrets.py``).

A secret scanner that is never tested against real credential shapes is
security theatre: it reports "clean" forever and nobody notices it stopped
matching.  These tests pin BOTH directions —

* **Detection** — each supported credential class is actually caught.
* **Non-detection** — the artefacts this repository legitimately publishes
  (NIST KAT vectors, the Ed25519 integrity public key, documentation
  placeholders) do NOT trip the scanner, because a scanner that cries wolf
  gets globally silenced, which is how real keys leak.

.. important::

   **Every credential fixture below is assembled at runtime from fragments and
   must stay that way.**  GitHub push protection scans the raw file text of
   every pushed commit, so a contiguous token-shaped literal here — even an
   obviously fake one — blocks the push for the whole branch (this happened
   with the Slack fixture on the first push of this file).  The alternative
   offered by the tooling is to click through a per-secret unblock exception,
   which trains maintainers to wave real findings through; assembling the
   fixtures instead keeps the detection coverage identical while leaving the
   platform control fully armed.  Do not "tidy" these back into single
   literals.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.check_secrets import (
    Finding,
    scan_file,
    scan_text,
    shannon_entropy,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# Credential fixtures are assembled from fragments at import time so that no
# line of this file is itself a contiguous credential-shaped literal.  This
# keeps BOTH scanners quiet on a file whose whole purpose is to contain
# credential shapes: GitHub push protection (which blocks the push) and this
# repository's own tools/check_secrets.py (which would otherwise flag its own
# test suite).  The strings handed to scan_text() below are byte-identical to
# the real shapes, so detection coverage is unchanged.
_ARMOUR = "-----" + "BEGIN "
_OPAQUE = "7Kq!zR9#" + "vX2$mW5^pL8&"
_OPAQUE2 = "9f8Ba7Cd6Ee5" + "Ff4Gg3Hh2Ii1Jj0Kk"


def _rules(findings: list[Finding]) -> set[str]:
    return {f.rule for f in findings}


class TestDetectsRealCredentials:
    """Every supported credential class must be caught."""

    def test_pem_private_key(self) -> None:
        text = _ARMOUR + "PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
        assert "private-key-block" in _rules(scan_text("x.pem", text))

    def test_rsa_private_key(self) -> None:
        assert "private-key-block" in _rules(scan_text("x.pem", _ARMOUR + "RSA PRIVATE KEY-----"))

    def test_openssh_private_key(self) -> None:
        assert "private-key-block" in _rules(
            scan_text("id_ed25519", _ARMOUR + "OPENSSH PRIVATE KEY-----")
        )

    def test_aws_access_key_id(self) -> None:
        key_id = "AKIA" + "IOSFODNN7EXAMPLE"
        assert "aws-access-key-id" in _rules(scan_text("cfg.py", f'aws_id = "{key_id}"'))

    def test_github_token(self) -> None:
        token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        assert "github-token" in _rules(scan_text("ci.py", f'tok = "{token}"'))

    def test_slack_token(self) -> None:
        # Assembled at runtime — see the module note on why no fixture in this
        # file may appear as a contiguous credential-shaped literal.
        token = "xox" + "b-123456789012-abcdefghijklmno"
        assert "slack-token" in _rules(scan_text("bot.py", f'hook = "{token}"'))

    def test_google_api_key(self) -> None:
        key = "AIza" + "SyD-1234567890abcdefghijklmnopqrstu"
        assert "google-api-key" in _rules(scan_text("maps.py", f'k = "{key}"'))

    def test_authorization_header(self) -> None:
        assert "authorization-header" in _rules(
            scan_text("client.py", "Authorization: " + "Bearer aGVsbG93b3JsZDEyMzQ1Njc4OTA=")
        )

    def test_high_entropy_assigned_password(self) -> None:
        # Opaque, non-placeholder, high entropy -> must be caught.
        assert "assigned-secret" in _rules(scan_text("app.py", 'db_password = "' + _OPAQUE + '"'))

    def test_high_entropy_api_key_assignment(self) -> None:
        assert "assigned-secret" in _rules(scan_text("app.py", 'api_key = "' + _OPAQUE2 + '"'))

    def test_env_file_is_flagged(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("API_TOKEN=abc123\n")
        findings = scan_file(env, tmp_path)
        assert "env-file" in _rules(findings)


class TestDoesNotFlagPublishedArtefacts:
    """Legitimate public material must not produce findings."""

    def test_kat_vectors_are_allowlisted(self) -> None:
        kat = REPO_ROOT / "tests" / "kat" / "fips203" / "ml_kem_1024.kat"
        if not kat.is_file():
            pytest.skip("KAT vector not present in this checkout")
        assert scan_file(kat, REPO_ROOT) == []

    def test_integrity_signature_module_is_allowlisted(self) -> None:
        sig = REPO_ROOT / "ama_cryptography" / "_integrity_signature.py"
        if not sig.is_file():
            pytest.skip("integrity signature module not generated in this checkout")
        assert scan_file(sig, REPO_ROOT) == []

    @pytest.mark.parametrize(
        "line",
        [
            'password = "your_secure_password_here"',
            'api_key = "changeme"',
            'token = "<REPLACE_WITH_TOKEN>"',
            'secret = "example-value-not-real"',
            'password = "${VAULT_PASSWORD}"',
            'password = "AAAAAAAAAAAAAAAA"',
        ],
    )
    def test_placeholders_are_not_flagged(self, line: str) -> None:
        assert scan_text("docs.py", line) == []

    def test_prose_mentioning_secrets_is_not_flagged(self) -> None:
        text = (
            "The master password is never written to disk; the derived key is\n"
            "wiped after use and the secret material stays in locked memory.\n"
        )
        assert scan_text("README.md", text) == []

    def test_explicit_optout_marker_is_honoured(self) -> None:
        token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        line = f'sample = "{token}"  # nosecret: documentation example'
        assert scan_text("doc.py", line) == []


class TestEntropyHelper:
    def test_repeated_characters_have_zero_entropy(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_empty_string_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_random_hex_has_high_entropy(self) -> None:
        assert shannon_entropy("9f8ba7cd6ee5ff4gg3hh2ii1jj0kk") > 3.0

    def test_english_prose_is_lower_than_key_material(self) -> None:
        prose = shannon_entropy("the quick brown fox jumps over")
        key = shannon_entropy("7Kq!zR9#vX2$mW5^pL8&nB3@")
        assert key > prose


class TestRepositoryIsClean:
    """The tracked tree must scan clean — this is the live gate."""

    def test_tracked_tree_has_no_findings(self) -> None:
        from tools.check_secrets import _tracked_files

        findings: list[Finding] = []
        for path in _tracked_files(REPO_ROOT, staged_only=False):
            findings.extend(scan_file(path, REPO_ROOT))
        assert findings == [], "\n".join(f.render() for f in findings)
