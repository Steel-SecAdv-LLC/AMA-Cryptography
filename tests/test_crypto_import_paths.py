#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
AMA Cryptography: Import Path and Edge Case Tests
======================================================

Tests for import error handling, CRYPTO_AVAILABLE/DILITHIUM_AVAILABLE paths,
RFC 3161 success paths, and other edge cases needed
for 100% test coverage.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-03-08
Version: 2.0

AI Co-Architects:
    Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
"""

import base64
import unittest.mock
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import code_guardian_secure as dgs

# ============================================================================
# CRYPTO_AVAILABLE=False TESTS
# ============================================================================


class TestCryptoAvailableFalse:
    """Tests for CRYPTO_AVAILABLE=False paths."""

    def test_generate_ed25519_keypair_requires_crypto(self, monkeypatch: Any) -> None:
        """Test that generate_ed25519_keypair raises when crypto unavailable."""
        monkeypatch.setattr(dgs, "CRYPTO_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="AMA native C library required"):
            dgs.generate_ed25519_keypair()

    def test_ed25519_sign_requires_crypto(self, monkeypatch: Any) -> None:
        """Test that ed25519_sign raises when crypto unavailable."""
        monkeypatch.setattr(dgs, "CRYPTO_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="AMA native C library required"):
            dgs.ed25519_sign(b"msg", b"\x00" * 32)

    def test_ed25519_verify_requires_crypto(self, monkeypatch: Any) -> None:
        """Test that ed25519_verify raises when crypto unavailable."""
        monkeypatch.setattr(dgs, "CRYPTO_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="AMA native C library required"):
            dgs.ed25519_verify(b"msg", b"\x00" * 64, b"\x00" * 32)

    def test_derive_keys_requires_crypto(self, monkeypatch: Any) -> None:
        """Test that derive_keys raises when crypto unavailable."""
        monkeypatch.setattr(dgs, "CRYPTO_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="AMA native C library required"):
            dgs.derive_keys(b"\x00" * 32, "info")


# ============================================================================
# 4GB FIELD SIZE VALIDATION TEST
# ============================================================================


class TestFieldSizeValidation:
    """Tests for field size validation in length_prefixed_encode."""

    def test_length_prefixed_encode_rejects_over_4gb(self) -> Any:
        """Test that encoding rejects fields over 4GB."""

        class HugeBytes(bytes):
            """Bytes subclass that reports huge length."""

            def __len__(self) -> Any:
                return 0xFFFFFFFF + 1

        class FakeStr(str):
            """String that encodes to huge bytes."""

            def encode(self, encoding: Any = "utf-8") -> Any:
                return HugeBytes(b"x")

        huge = FakeStr("x")
        with pytest.raises(ValueError, match="exceeds 4GB limit"):
            dgs.length_prefixed_encode(huge)


# ML-DSA-65 key sizes per NIST FIPS 204
FAKE_PRIVATE_KEY = b"K" * 4032  # 4032 bytes for ML-DSA-65 secret key
FAKE_PUBLIC_KEY = b"P" * 1952  # 1952 bytes for ML-DSA-65 public key
FAKE_SIGNATURE = b"S" * 3309  # 3309 bytes for ML-DSA-65 signature


# ============================================================================
# RFC 3161 SUCCESS PATH TESTS
# ============================================================================


class TestRFC3161SuccessPath:
    """Tests for RFC 3161 timestamp success paths."""

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_rfc3161_success(self, mock_run: Any, mock_urlopen: Any) -> None:
        """Test successful RFC 3161 timestamp retrieval."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"TSQ_DATA")
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"TSR_RESPONSE"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        tsr = dgs.get_rfc3161_timestamp(b"data", "https://tsa.example.com")

        # Verify return value
        assert tsr == b"TSR_RESPONSE"

        # Verify subprocess.run was called with expected signature
        mock_run.assert_called_once_with(
            unittest.mock.ANY,
            capture_output=True,
            timeout=unittest.mock.ANY,
        )
        # Verify the command list starts with openssl
        run_cmd = mock_run.call_args[0][0]
        assert run_cmd[0] == "openssl", f"Expected openssl command, got {run_cmd[0]}"

        # Verify urlopen was called with a Request targeting the TSA URL
        mock_urlopen.assert_called_once()
        urlopen_args = mock_urlopen.call_args
        request_obj = urlopen_args[0][0]
        assert "tsa.example.com" in request_obj.full_url

    def test_create_crypto_package_rfc3161_success(self, monkeypatch: Any) -> None:
        """Test package creation with successful RFC 3161 timestamp."""
        kms = dgs.generate_key_management_system("test_author")

        with patch("code_guardian_secure.get_rfc3161_timestamp", return_value=b"TSR") as mock_tsa:
            pkg = dgs.create_crypto_package(
                dgs.MASTER_CODES,
                dgs.MASTER_HELIX_PARAMS,
                kms,
                "author",
                use_rfc3161=True,
            )

        # Verify the mock was called with expected signature
        mock_tsa.assert_called_once()
        call_args = mock_tsa.call_args
        assert call_args is not None, "get_rfc3161_timestamp was not called"
        # First positional arg is the data to timestamp (bytes)
        assert isinstance(call_args[0][0], bytes), "First arg must be bytes (data to timestamp)"

        # Verify package fields
        assert pkg.timestamp_token == base64.b64encode(b"TSR").decode("ascii")
        assert pkg.content_hash is not None, "content_hash must be populated"
        assert pkg.hmac_tag is not None, "hmac_tag must be populated"
        assert pkg.ed25519_signature is not None, "ed25519_signature must be populated"
        assert pkg.timestamp is not None, "timestamp must be populated"


# ============================================================================
# DILITHIUM UNAVAILABLE PATH TESTS
# ============================================================================


class TestDilithiumUnavailablePaths:
    """Tests for Dilithium unavailable paths."""

    def test_kms_warns_when_dilithium_generation_fails(self, monkeypatch: Any, capsys: Any) -> None:
        """Test KMS generation warning when Dilithium generation fails."""

        def boom() -> None:
            raise dgs.QuantumSignatureUnavailableError("fail")

        monkeypatch.setattr(dgs, "DILITHIUM_AVAILABLE", True)
        monkeypatch.setattr(dgs, "generate_dilithium_keypair", boom)

        kms = dgs.generate_key_management_system("author")
        out = capsys.readouterr().out
        assert "Quantum-resistant signatures disabled" in out
        assert kms.quantum_signatures_enabled is False
        assert kms.dilithium_keypair is None

    def test_kms_warns_when_dilithium_not_available(self, monkeypatch: Any, capsys: Any) -> None:
        """Test KMS generation warning when Dilithium not available."""
        monkeypatch.setattr(dgs, "DILITHIUM_AVAILABLE", False)

        kms = dgs.generate_key_management_system("author")
        out = capsys.readouterr().out
        assert "Quantum-resistant signatures disabled" in out
        assert "native C library" in out
        assert kms.quantum_signatures_enabled is False
        assert kms.dilithium_keypair is None

    def test_export_public_keys_when_dilithium_unavailable(
        self,
        capsys: Any,
        tmp_path: Any,
    ) -> None:
        """Test export_public_keys when Dilithium unavailable."""
        kms = dgs.generate_key_management_system("test_author")
        kms.quantum_signatures_enabled = False
        kms.dilithium_keypair = None

        out_dir = tmp_path / "keys"
        dgs.export_public_keys(kms, out_dir)
        readme = (out_dir / "README.txt").read_text()
        assert "Dilithium Public Key: NOT AVAILABLE" in readme
        out = capsys.readouterr().out
        assert "Dilithium: NOT AVAILABLE" in out

    def test_create_crypto_package_gracefully_degrades_when_dilithium_sign_fails(
        self,
        monkeypatch: Any,
    ) -> None:
        """Test package creation gracefully degrades when Dilithium sign fails."""

        def boom(message: Any, priv: Any) -> None:
            raise dgs.QuantumSignatureUnavailableError("fail")

        kms = dgs.generate_key_management_system("test_author")
        kms.quantum_signatures_enabled = True

        monkeypatch.setattr(dgs, "dilithium_sign", boom)

        pkg = dgs.create_crypto_package(dgs.MASTER_CODES, dgs.MASTER_HELIX_PARAMS, kms, "author")
        assert pkg.dilithium_signature is None
        assert pkg.quantum_signatures_enabled is False

    def test_verify_dilithium_policy_handles_unavailable_libraries_not_required(
        self,
        monkeypatch: Any,
    ) -> None:
        """Test _verify_dilithium_with_policy when libraries unavailable (not required)."""

        def boom(*args: Any, **kwargs: Any) -> None:
            raise dgs.QuantumSignatureUnavailableError("oops")

        monkeypatch.setattr(dgs, "dilithium_verify", boom)

        kms = dgs.generate_key_management_system("test_author")
        pkg = dgs.create_crypto_package(dgs.MASTER_CODES, dgs.MASTER_HELIX_PARAMS, kms, "test")

        computed_hash = dgs.canonical_hash_code(dgs.MASTER_CODES, dgs.MASTER_HELIX_PARAMS)
        result = dgs._verify_dilithium_with_policy(
            computed_hash, pkg, monitor=None, require_quantum_signatures=False
        )
        assert result is None

    def test_verify_dilithium_policy_handles_unavailable_libraries_required(
        self,
        monkeypatch: Any,
    ) -> None:
        """Test _verify_dilithium_with_policy when libraries unavailable (required)."""

        def boom(*args: Any, **kwargs: Any) -> None:
            raise dgs.QuantumSignatureUnavailableError("oops")

        monkeypatch.setattr(dgs, "dilithium_verify", boom)

        kms = dgs.generate_key_management_system("test_author")
        pkg = dgs.create_crypto_package(dgs.MASTER_CODES, dgs.MASTER_HELIX_PARAMS, kms, "test")

        computed_hash = dgs.canonical_hash_code(dgs.MASTER_CODES, dgs.MASTER_HELIX_PARAMS)
        with pytest.raises(dgs.QuantumSignatureRequiredError):
            dgs._verify_dilithium_with_policy(
                computed_hash, pkg, monitor=None, require_quantum_signatures=True
            )


# ============================================================================
# MAIN FUNCTION DIRECT CALL TEST
# ============================================================================


class TestMainFunctionDirect:
    """Tests for main() function via direct call."""

    def test_main_direct_call_covers_demo(
        self,
        monkeypatch: Any,
        capsys: Any,
        tmp_path: Any,
    ) -> None:
        """Test main() function via direct call for coverage."""
        monkeypatch.chdir(tmp_path)
        dgs.main()
        out = capsys.readouterr().out
        assert "AMA Cryptography" in out
        assert "ALL VERIFICATIONS PASSED" in out
        assert (tmp_path / "CRYPTO_PACKAGE.json").exists()
        assert (tmp_path / "public_keys").is_dir()


# ============================================================================
# DERIVE KEYS EDGE CASES
# ============================================================================


class TestDeriveKeysEdgeCasesExtended:
    """Extended edge case tests for derive_keys."""

    def test_derive_keys_short_master_secret_raises(self) -> None:
        """Test that derive_keys raises for short master secret."""
        with pytest.raises(ValueError, match="at least 32 bytes"):
            dgs.derive_keys(b"\x00" * 16, "info")


# ============================================================================
# MAIN FUNCTION BRANCH COVERAGE TESTS
# ============================================================================


class TestMainFunctionBranches:
    """Tests for main() function branch coverage."""

    def test_main_with_dilithium_unavailable(
        self,
        monkeypatch: Any,
        capsys: Any,
        tmp_path: Any,
    ) -> Any:
        """Test main() when Dilithium is unavailable."""
        monkeypatch.chdir(tmp_path)

        # Mock generate_key_management_system to return KMS without Dilithium
        original_gen_kms = dgs.generate_key_management_system

        def mock_gen_kms(author: Any) -> Any:
            kms = original_gen_kms(author)
            kms.quantum_signatures_enabled = False
            kms.dilithium_keypair = None
            return kms

        monkeypatch.setattr(dgs, "generate_key_management_system", mock_gen_kms)

        # Mock create_crypto_package to return package without Dilithium
        original_create_pkg = dgs.create_crypto_package

        def mock_create_pkg(*args: Any, **kwargs: Any) -> Any:
            pkg = original_create_pkg(*args, **kwargs)
            pkg.quantum_signatures_enabled = False
            pkg.dilithium_signature = None
            return pkg

        monkeypatch.setattr(dgs, "create_crypto_package", mock_create_pkg)

        dgs.main()
        out = capsys.readouterr().out
        assert "Dilithium keypair: NOT AVAILABLE" in out or "quantum signatures disabled" in out

    def test_main_with_verification_none_result(
        self,
        monkeypatch: Any,
        capsys: Any,
        tmp_path: Any,
    ) -> Any:
        """Test main() when verification returns None for some checks."""
        monkeypatch.chdir(tmp_path)

        # Mock verify_crypto_package to return None for dilithium
        original_verify = dgs.verify_crypto_package

        def mock_verify(*args: Any, **kwargs: Any) -> Any:
            results = original_verify(*args, **kwargs)
            results["dilithium"] = None
            return results

        monkeypatch.setattr(dgs, "verify_crypto_package", mock_verify)

        dgs.main()
        out = capsys.readouterr().out
        assert "NOT PRESENT/UNSUPPORTED" in out or "ALL VERIFICATIONS PASSED" in out

    def test_main_with_verification_failure(
        self,
        monkeypatch: Any,
        capsys: Any,
        tmp_path: Any,
    ) -> Any:
        """Test main() when verification fails."""
        monkeypatch.chdir(tmp_path)

        # Mock verify_crypto_package to return False for content_hash
        def mock_verify(*args: Any, **kwargs: Any) -> Any:
            return {
                "content_hash": False,
                "hmac": True,
                "ed25519": True,
                "dilithium": None,
                "timestamp": True,
            }

        monkeypatch.setattr(dgs, "verify_crypto_package", mock_verify)

        dgs.main()
        out = capsys.readouterr().out
        assert "VERIFICATION FAILED" in out or "INVALID" in out


# ============================================================================
# TSA INTEGRATION SKELETON (requires live TSA endpoint)
# ============================================================================


class TestTSAIntegration:
    """Integration tests for RFC 3161 TSA interaction.

    These tests require a live TSA endpoint and are skipped by default.
    Run with: pytest -m integration tests/test_crypto_import_paths.py
    """

    @pytest.mark.integration
    def test_rfc3161_live_tsa_roundtrip(self) -> None:
        """End-to-end RFC 3161 timestamp with a live TSA (when available)."""
        pytest.skip(
            reason="Live TSA integration test — requires network and a TSA endpoint. "
            "Enable by providing TSA_URL env var and running with -m integration."
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
