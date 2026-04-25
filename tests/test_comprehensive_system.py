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
AMA Cryptography: Comprehensive System Test Suite
===================================================

100% System Testing for complete coverage of all cryptographic operations,
error paths, utility functions, and integration scenarios.

This test suite complements test_crypto_core_penetration.py by covering:
1. Secure memory wiping utilities
2. Export public keys functionality
3. RFC 3161 timestamp handling
4. Main demonstration function
5. Error paths and edge cases
6. Monitor integration paths
7. Quantum signature policy enforcement

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
Contact: steel.sa.llc@gmail.com
Date: 2026-04-17
Version: 2.2.0

AI Co-Architects:
    Eris | Eden ♱ | Veritas | X | Caduceus | Dev
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.equations import ETHICAL_VECTOR, MASTER_CODES, MASTER_HELIX_PARAMS
from ama_cryptography.exceptions import (
    QuantumSignatureRequiredError,
    QuantumSignatureUnavailableError,
)
from ama_cryptography.legacy_compat import (
    SIGNATURE_FORMAT_V1,
    SIGNATURE_FORMAT_V2,
    _verify_dilithium_with_policy,
    _verify_rfc3161_token,
    _verify_timestamp_value,
    build_signature_message,
    canonical_hash_code,
    create_crypto_package,
    create_ethical_hkdf_context,
    derive_keys,
    export_public_keys,
    generate_ed25519_keypair,
    generate_key_management_system,
    get_rfc3161_timestamp,
    length_prefixed_encode,
    secure_wipe,
    verify_crypto_package,
    verify_rfc3161_timestamp,
)
from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE


class TestSecureWipe:
    """Tests for secure memory wiping functionality."""

    def test_secure_wipe_bytearray(self) -> None:
        """Test that bytearray is properly wiped."""
        data = bytearray(b"sensitive_data_here")
        original_len = len(data)
        secure_wipe(data)
        # After wiping, all bytes should be zero
        assert all(b == 0 for b in data)
        assert len(data) == original_len

    def test_secure_wipe_empty_bytearray(self) -> None:
        """Test wiping empty bytearray."""
        data = bytearray()
        secure_wipe(data)
        assert len(data) == 0

    def test_secure_wipe_large_bytearray(self) -> None:
        """Test wiping large bytearray."""
        data = bytearray(secrets.token_bytes(10000))
        secure_wipe(data)
        assert all(b == 0 for b in data)

    def test_secure_wipe_immutable_bytes_raises(self) -> None:
        """Test that immutable bytes raises TypeError (fail-loud contract)."""
        data = b"immutable_data"
        with pytest.raises(TypeError, match="requires a mutable bytearray"):
            secure_wipe(data)

    def test_secure_wipe_non_bytearray_raises(self) -> None:
        """Test that non-bytearray types raise TypeError (fail-loud contract)."""
        with pytest.raises(TypeError, match="requires a mutable bytearray"):
            secure_wipe("string")  # type: ignore[arg-type]  # wrong type to verify TypeError rejection (TCS-001)
        with pytest.raises(TypeError, match="requires a mutable bytearray"):
            secure_wipe(12345)  # type: ignore[arg-type]  # wrong type to verify TypeError rejection (TCS-002)
        with pytest.raises(TypeError, match="requires a mutable bytearray"):
            secure_wipe(None)  # type: ignore[arg-type]  # wrong type to verify TypeError rejection (TCS-003)
        with pytest.raises(TypeError, match="requires a mutable bytearray"):
            secure_wipe([1, 2, 3])  # type: ignore[arg-type]  # wrong type to verify TypeError rejection (TCS-004)


class TestLengthPrefixedEncodeEdgeCases:
    """Additional edge case tests for length-prefixed encoding."""

    def test_encode_no_fields(self) -> None:
        """Test encoding with no fields."""
        result = length_prefixed_encode()
        assert result == b""

    def test_encode_single_empty_field(self) -> None:
        """Test encoding single empty field."""
        result = length_prefixed_encode("")
        assert result == b"\x00\x00\x00\x00"

    def test_encode_multiple_empty_fields(self) -> None:
        """Test encoding multiple empty fields."""
        result = length_prefixed_encode("", "", "")
        assert result == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def test_encode_special_characters(self) -> None:
        """Test encoding with special Unicode characters."""
        result = length_prefixed_encode("", "test")
        assert len(result) > 0

    def test_encode_very_long_field(self) -> None:
        """Test encoding with very long field."""
        long_data = "X" * 1000000  # 1MB
        result = length_prefixed_encode(long_data)
        assert len(result) == 4 + 1000000


class TestExportPublicKeys:
    """Tests for public key export functionality."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_export_creates_directory(self, kms: Any) -> None:
        """Test that export creates output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "new_keys_dir"
            export_public_keys(kms, output_dir)
            assert output_dir.exists()

    def test_export_creates_ed25519_key_file(self, kms: Any) -> None:
        """Test that Ed25519 public key file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            export_public_keys(kms, output_dir)
            ed25519_path = output_dir / "ed25519_public.key"
            assert ed25519_path.exists()
            with open(ed25519_path, "rb") as f:
                key_data = f.read()
            assert key_data == kms.ed25519_keypair.public_key

    def test_export_creates_dilithium_key_file_when_available(self, kms: Any) -> None:
        """Test that Dilithium public key file is created when available."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            export_public_keys(kms, output_dir)
            dilithium_path = output_dir / "dilithium_public.key"
            if kms.quantum_signatures_enabled and kms.dilithium_keypair:
                assert dilithium_path.exists()
                with open(dilithium_path, "rb") as f:
                    key_data = f.read()
                assert key_data == kms.dilithium_keypair.public_key
            else:
                assert not dilithium_path.exists()

    def test_export_creates_readme(self, kms: Any) -> None:
        """Test that README.txt is created with correct content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            export_public_keys(kms, output_dir)
            readme_path = output_dir / "README.txt"
            assert readme_path.exists()
            with open(readme_path) as f:
                content = f.read()
            assert "AMA Cryptography" in content
            assert kms.creation_date in content
            assert kms.version in content
            assert kms.ed25519_keypair.public_key.hex() in content

    def test_export_overwrites_existing_files(self, kms: Any) -> None:
        """Test that export overwrites existing files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            # Create initial export
            export_public_keys(kms, output_dir)
            # Create new KMS and export again
            kms2 = generate_key_management_system("different_author")
            export_public_keys(kms2, output_dir)
            # Verify new key is written
            ed25519_path = output_dir / "ed25519_public.key"
            with open(ed25519_path, "rb") as f:
                key_data = f.read()
            assert key_data == kms2.ed25519_keypair.public_key

    def test_export_nested_directory(self, kms: Any) -> None:
        """Test export to nested directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "level1" / "level2" / "keys"
            export_public_keys(kms, output_dir)
            assert output_dir.exists()
            assert (output_dir / "ed25519_public.key").exists()


class TestRFC3161Timestamp:
    """Tests for RFC 3161 timestamp functionality."""

    def test_timestamp_raises_on_tsa_failure(self) -> None:
        """Test that timestamp raises RuntimeError when TSA is unavailable."""
        # Use invalid URL to force failure — must not return None silently
        with pytest.raises(RuntimeError, match="timestamps are a security layer"):
            get_rfc3161_timestamp(b"test_data", "http://invalid.tsa.url/")

    def test_timestamp_raises_with_empty_data(self) -> None:
        """Test timestamp with empty data raises when TSA is unreachable."""
        with pytest.raises(RuntimeError, match="timestamps are a security layer"):
            get_rfc3161_timestamp(b"", "http://invalid.tsa.url/")

    @patch("subprocess.run")
    def test_timestamp_openssl_failure(self, mock_run: Any) -> None:
        """Test handling of OpenSSL command failure."""
        mock_run.return_value = MagicMock(returncode=1, stderr=b"OpenSSL error")
        result = get_rfc3161_timestamp(b"test_data")
        assert result is None

    @patch("subprocess.run")
    @patch("urllib.request.urlopen")
    def test_timestamp_network_failure_raises(self, mock_urlopen: Any, mock_run: Any) -> None:
        """Test that network failure raises RuntimeError (fail-loud)."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"query_data")
        mock_urlopen.side_effect = Exception("Network error")
        with pytest.raises(RuntimeError, match="timestamps are a security layer"):
            get_rfc3161_timestamp(b"test_data")


class TestTimestampValidation:
    """Tests for timestamp value validation."""

    def test_valid_current_timestamp(self) -> None:
        """Test that current timestamp is valid."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        assert _verify_timestamp_value(now) is True

    def test_future_timestamp_invalid(self) -> None:
        """Test that future timestamp is invalid."""
        from datetime import datetime, timedelta, timezone

        future = datetime.now(timezone.utc) + timedelta(days=1)
        assert _verify_timestamp_value(future.isoformat()) is False

    def test_very_old_timestamp_invalid(self) -> None:
        """Test that timestamp older than 10 years is invalid."""
        from datetime import datetime, timedelta, timezone

        old = datetime.now(timezone.utc) - timedelta(days=4000)
        assert _verify_timestamp_value(old.isoformat()) is False

    def test_malformed_timestamp_raises(self) -> None:
        """Test that malformed timestamp raises ValueError (fail-loud)."""
        with pytest.raises(ValueError, match="Invalid timestamp format"):
            _verify_timestamp_value("not-a-timestamp")
        with pytest.raises(ValueError, match="Invalid timestamp format"):
            _verify_timestamp_value("")
        with pytest.raises(ValueError, match="Invalid timestamp format"):
            _verify_timestamp_value("2025-13-45T99:99:99")


class TestDilithiumPolicyEnforcement:
    """Tests for Dilithium signature policy enforcement."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    @pytest.fixture
    def valid_package(self, kms: Any) -> Any:
        """Create valid package for testing."""
        return create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")

    def _build_signature_message_for_package(self, package: Any) -> Any:
        """Helper to build the correct signature message based on package format version."""
        computed_hash = canonical_hash_code(MASTER_CODES, MASTER_HELIX_PARAMS)
        sig_format = getattr(package, "signature_format_version", SIGNATURE_FORMAT_V1)
        if sig_format == SIGNATURE_FORMAT_V2:
            ethical_hash_bytes = bytes.fromhex(package.ethical_hash)
            return build_signature_message(computed_hash, ethical_hash_bytes, SIGNATURE_FORMAT_V2)
        return computed_hash

    def test_policy_not_required_missing_signature_returns_none(
        self,
        kms: Any,
        valid_package: Any,
    ) -> None:
        """Test that missing Dilithium signature returns None when not required."""
        # Create package without quantum signatures
        pkg = valid_package
        pkg.quantum_signatures_enabled = False
        pkg.dilithium_signature = None
        pkg.dilithium_pubkey = None

        signature_message = self._build_signature_message_for_package(pkg)
        result = _verify_dilithium_with_policy(
            signature_message, pkg, monitor=None, require_quantum_signatures=False
        )
        assert result is None

    def test_policy_required_missing_signature_raises(self, kms: Any, valid_package: Any) -> None:
        """Test that missing Dilithium signature raises when required."""
        pkg = valid_package
        pkg.quantum_signatures_enabled = False
        pkg.dilithium_signature = None
        pkg.dilithium_pubkey = None

        signature_message = self._build_signature_message_for_package(pkg)
        with pytest.raises(QuantumSignatureRequiredError):
            _verify_dilithium_with_policy(
                signature_message, pkg, monitor=None, require_quantum_signatures=True
            )

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_policy_required_valid_signature_passes(self, kms: Any, valid_package: Any) -> None:
        """Test that valid Dilithium signature passes when required."""
        if not valid_package.quantum_signatures_enabled:
            pytest.skip("Quantum signatures not enabled")

        signature_message = self._build_signature_message_for_package(valid_package)
        result = _verify_dilithium_with_policy(
            signature_message, valid_package, monitor=None, require_quantum_signatures=True
        )
        assert result is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_policy_required_invalid_signature_raises(self, kms: Any, valid_package: Any) -> None:
        """Test that invalid Dilithium signature raises when required."""
        if not valid_package.quantum_signatures_enabled:
            pytest.skip("Quantum signatures not enabled")

        # Tamper with signature
        original_bytes = bytes.fromhex(valid_package.dilithium_signature)
        tampered_bytes = bytearray(original_bytes)
        tampered_bytes[0] ^= 0xFF
        valid_package.dilithium_signature = tampered_bytes.hex()

        signature_message = self._build_signature_message_for_package(valid_package)
        with pytest.raises(QuantumSignatureRequiredError):
            _verify_dilithium_with_policy(
                signature_message, valid_package, monitor=None, require_quantum_signatures=True
            )


class TestVerifyCryptoPackageWithPolicy:
    """Tests for verify_crypto_package with quantum signature policy."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    @pytest.fixture
    def valid_package(self, kms: Any) -> Any:
        """Create valid package for testing."""
        return create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")

    def test_verify_without_policy_succeeds(self, kms: Any, valid_package: Any) -> None:
        """Test verification without quantum policy succeeds."""
        results = verify_crypto_package(
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            valid_package,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["ed25519"] is True

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_verify_with_policy_valid_package_succeeds(self, kms: Any, valid_package: Any) -> None:
        """Test verification with quantum policy on valid package succeeds."""
        if not valid_package.quantum_signatures_enabled:
            pytest.skip("Quantum signatures not enabled")

        results = verify_crypto_package(
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            valid_package,
            kms.hmac_key,
            require_quantum_signatures=True,
        )
        assert results["content_hash"] is True
        assert results["dilithium"] is True

    def test_verify_with_policy_missing_dilithium_raises(
        self,
        kms: Any,
        valid_package: Any,
    ) -> None:
        """Test verification with quantum policy raises when Dilithium missing."""
        valid_package.quantum_signatures_enabled = False
        valid_package.dilithium_signature = None
        valid_package.dilithium_pubkey = None

        with pytest.raises(QuantumSignatureRequiredError):
            verify_crypto_package(
                MASTER_CODES,
                MASTER_HELIX_PARAMS,
                valid_package,
                kms.hmac_key,
                require_quantum_signatures=True,
            )


class TestCryptoPackageWithRFC3161:
    """Tests for crypto package creation with RFC 3161 timestamps."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_package_without_rfc3161(self, kms: Any) -> None:
        """Test package creation without RFC 3161 timestamp."""
        pkg = create_crypto_package(
            MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test", use_rfc3161=False
        )
        assert pkg.timestamp_token is None

    def test_package_with_rfc3161_failure_raises(self, kms: Any) -> None:
        """Test package creation with RFC 3161 failure raises (fail-loud)."""
        # Use invalid TSA URL to force failure — must not silently succeed
        with pytest.raises(RuntimeError, match="timestamps are a security layer"):
            create_crypto_package(
                MASTER_CODES,
                MASTER_HELIX_PARAMS,
                kms,
                "test",
                use_rfc3161=True,
                tsa_url="http://invalid.tsa.url/",
            )

    def test_verify_rfc3161_returns_none_when_no_token(self, kms: Any) -> None:
        """Test RFC 3161 verification returns None when no token present."""
        pkg = create_crypto_package(
            MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test", use_rfc3161=False
        )
        results = verify_crypto_package(
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            pkg,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["rfc3161"] is None

    def test_verify_rfc3161_token_helper_returns_none_for_none_token(self) -> None:
        """Test _verify_rfc3161_token returns None for None token."""
        test_hash = b"test_hash_data"
        result = _verify_rfc3161_token(test_hash, None)
        assert result is None

    def test_verify_rfc3161_timestamp_with_invalid_token(self) -> None:
        """Test verify_rfc3161_timestamp returns False for invalid token."""
        test_data = b"test_data"
        invalid_token = b"invalid_token_data"
        result = verify_rfc3161_timestamp(test_data, invalid_token)
        assert result is False

    def test_verify_results_include_rfc3161_key(self, kms: Any) -> None:
        """Test that verification results include rfc3161 key."""
        pkg = create_crypto_package(
            MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test", use_rfc3161=False
        )
        results = verify_crypto_package(
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            pkg,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert "rfc3161" in results


class TestEthicalVectorIntegration:
    """Tests for ethical vector integration."""

    def test_ethical_vector_sum_equals_twelve(self) -> None:
        """Test that ethical vector weights sum to 12.0."""
        assert sum(ETHICAL_VECTOR.values()) == 12.0

    def test_ethical_vector_all_weights_equal_three(self) -> None:
        """Test that all ethical vector weights equal 3.0."""
        assert all(w == 3.0 for w in ETHICAL_VECTOR.values())

    def test_ethical_vector_has_four_pillars(self) -> None:
        """Test that ethical vector has exactly 4 pillars."""
        assert len(ETHICAL_VECTOR) == 4

    def test_ethical_context_with_none_uses_default(self) -> None:
        """Test that None ethical vector uses default."""
        ctx1 = create_ethical_hkdf_context(b"base", None)
        ctx2 = create_ethical_hkdf_context(b"base", ETHICAL_VECTOR)
        assert ctx1 == ctx2

    def test_derive_keys_with_none_ethical_vector(self) -> None:
        """Test key derivation with None ethical vector uses default."""
        master = secrets.token_bytes(32)
        fixed_salt = b"fixed_salt_for_testing_32_bytes!"
        keys1, _ = derive_keys(master, "test", ethical_vector=None, salt=fixed_salt)
        keys2, _ = derive_keys(master, "test", ethical_vector=ETHICAL_VECTOR, salt=fixed_salt)
        assert keys1 == keys2


class TestMainFunction:
    """Tests for the main demonstration function."""

    def test_main_runs_successfully(self) -> None:
        """Test that main function runs without errors."""
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography"],
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        assert result.returncode == 0

    def test_main_produces_expected_output(self) -> None:
        """Test that main function produces expected output."""
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "ama_cryptography"],
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        output = result.stdout or ""
        assert "AMA Cryptography" in output
        assert "Generating key management system" in output
        assert "Creating Omni-Code cryptographic package" in output
        assert "Verifying cryptographic package" in output
        assert "ALL VERIFICATIONS PASSED" in output

    def test_main_creates_output_files(self) -> None:
        """Test that main function creates expected output files."""
        repo_root = Path(__file__).parent.parent
        # Run from temp directory to avoid polluting repo
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set PYTHONPATH to include repo root so ama_cryptography can be imported
            env = os.environ.copy()
            env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")

            env["PYTHONUTF8"] = "1"
            result = subprocess.run(
                [sys.executable, "-m", "ama_cryptography"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=tmpdir,
                env=env,
                encoding="utf-8",
                errors="replace",
            )
            assert result.returncode == 0

            # Check output files
            assert (Path(tmpdir) / "CRYPTO_PACKAGE.json").exists()
            assert (Path(tmpdir) / "public_keys").exists()
            assert (Path(tmpdir) / "public_keys" / "ed25519_public.key").exists()

    def test_main_output_package_is_valid_json(self) -> None:
        """Test that output package is valid JSON."""
        repo_root = Path(__file__).parent.parent
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set PYTHONPATH to include repo root so ama_cryptography can be imported
            env = os.environ.copy()
            env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")

            env["PYTHONUTF8"] = "1"
            subprocess.run(
                [sys.executable, "-m", "ama_cryptography"],
                capture_output=True,
                timeout=120,
                cwd=tmpdir,
                env=env,
            )

            package_path = Path(tmpdir) / "CRYPTO_PACKAGE.json"
            with open(package_path) as f:
                pkg_data = json.load(f)

            # Verify expected fields
            assert "content_hash" in pkg_data
            assert "hmac_tag" in pkg_data
            assert "ed25519_signature" in pkg_data
            assert "timestamp" in pkg_data
            assert "author" in pkg_data
            assert "ethical_vector" in pkg_data


class TestCryptoPackageWithMonitor:
    """Tests for crypto package creation with monitor integration."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_package_creation_with_mock_monitor(self, kms: Any) -> None:
        """Test package creation with mock monitor."""
        mock_monitor = MagicMock()
        mock_monitor.monitor_crypto_operation = MagicMock()
        mock_monitor.record_package_signing = MagicMock()

        pkg = create_crypto_package(
            MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test", monitor=mock_monitor
        )

        # Verify monitor methods were called
        assert mock_monitor.monitor_crypto_operation.called
        assert mock_monitor.record_package_signing.called

        # Verify package is still valid
        assert pkg.content_hash is not None
        assert pkg.hmac_tag is not None

    def test_verify_package_with_mock_monitor(self, kms: Any) -> None:
        """Test package verification with mock monitor."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")

        mock_monitor = MagicMock()
        mock_monitor.monitor_crypto_operation = MagicMock()

        results = verify_crypto_package(
            MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key, monitor=mock_monitor
        )

        # Verify monitor methods were called
        assert mock_monitor.monitor_crypto_operation.called

        # Verify results are correct
        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["ed25519"] is True


class TestKMSGenerationEdgeCases:
    """Tests for KMS generation edge cases."""

    def test_kms_with_custom_ethical_vector(self) -> None:
        """Test KMS generation with custom ethical vector."""
        custom_vector = {"custom_pillar": 1.0}
        kms = generate_key_management_system("test", ethical_vector=custom_vector)
        assert kms.ethical_vector == custom_vector

    def test_kms_dilithium_keypair_when_available(self) -> None:
        """Test that KMS has Dilithium keypair when available."""
        kms = generate_key_management_system("test")
        if DILITHIUM_AVAILABLE:
            assert kms.dilithium_keypair is not None
            assert kms.quantum_signatures_enabled is True
        else:
            assert kms.dilithium_keypair is None
            assert kms.quantum_signatures_enabled is False

    def test_kms_creation_date_is_iso_format(self) -> None:
        """Test that KMS creation date is in ISO format."""
        kms = generate_key_management_system("test")
        from datetime import datetime

        # Should not raise
        datetime.fromisoformat(kms.creation_date)

    def test_kms_rotation_schedule_is_quarterly(self) -> None:
        """Test that default rotation schedule is quarterly."""
        kms = generate_key_management_system("test")
        assert kms.rotation_schedule == "quarterly"

    def test_kms_version_is_set(self) -> None:
        """Test that KMS version is set."""
        kms = generate_key_management_system("test")
        assert kms.version == "2.1"


class TestCryptoPackageFields:
    """Tests for CryptoPackage field validation."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_package_content_hash_is_64_hex_chars(self, kms: Any) -> None:
        """Test that content hash is 64 hex characters (32 bytes)."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert len(pkg.content_hash) == 64
        # Verify it's valid hex
        bytes.fromhex(pkg.content_hash)

    def test_package_hmac_tag_is_64_hex_chars(self, kms: Any) -> None:
        """Test that HMAC tag is 64 hex characters (32 bytes)."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert len(pkg.hmac_tag) == 64
        bytes.fromhex(pkg.hmac_tag)

    def test_package_ed25519_signature_is_128_hex_chars(self, kms: Any) -> None:
        """Test that Ed25519 signature is 128 hex characters (64 bytes)."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert len(pkg.ed25519_signature) == 128
        bytes.fromhex(pkg.ed25519_signature)

    def test_package_ed25519_pubkey_is_64_hex_chars(self, kms: Any) -> None:
        """Test that Ed25519 public key is 64 hex characters (32 bytes)."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert len(pkg.ed25519_pubkey) == 64
        bytes.fromhex(pkg.ed25519_pubkey)

    def test_package_ethical_hash_is_64_hex_chars(self, kms: Any) -> None:
        """Test that ethical hash is 64 hex characters (32 bytes)."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert len(pkg.ethical_hash) == 64
        bytes.fromhex(pkg.ethical_hash)

    def test_package_timestamp_is_iso_format(self, kms: Any) -> None:
        """Test that timestamp is in ISO format."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        from datetime import datetime

        datetime.fromisoformat(pkg.timestamp)

    def test_package_version_is_set(self, kms: Any) -> None:
        """Test that package version is set."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        assert pkg.version == "2.1"

    def test_package_author_is_set(self, kms: Any) -> None:
        """Test that package author is set correctly."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test_author")
        assert pkg.author == "test_author"


class TestExceptionClasses:
    """Tests for custom exception classes."""

    def test_quantum_signature_unavailable_error(self) -> None:
        """Test QuantumSignatureUnavailableError can be raised and caught."""
        with pytest.raises(QuantumSignatureUnavailableError):
            raise QuantumSignatureUnavailableError("Test message")

    def test_quantum_signature_required_error(self) -> None:
        """Test QuantumSignatureRequiredError can be raised and caught."""
        with pytest.raises(QuantumSignatureRequiredError):
            raise QuantumSignatureRequiredError("Test message")

    def test_exception_messages(self) -> None:
        """Test that exception messages are preserved."""
        msg = "Custom error message"
        try:
            raise QuantumSignatureUnavailableError(msg)
        except QuantumSignatureUnavailableError as e:
            assert msg in str(e)


class TestDataclassConversion:
    """Tests for dataclass conversion and serialization."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_crypto_package_to_dict(self, kms: Any) -> None:
        """Test CryptoPackage can be converted to dict."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg_dict = asdict(pkg)
        assert isinstance(pkg_dict, dict)
        assert "content_hash" in pkg_dict
        assert "hmac_tag" in pkg_dict

    def test_crypto_package_to_json(self, kms: Any) -> None:
        """Test CryptoPackage can be serialized to JSON."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        pkg_dict = asdict(pkg)
        json_str = json.dumps(pkg_dict)
        assert isinstance(json_str, str)
        # Verify it can be parsed back
        parsed = json.loads(json_str)
        assert parsed["content_hash"] == pkg.content_hash


class TestEd25519ErrorPaths:
    """Tests for Ed25519 error paths."""

    def test_ed25519_sign_wrong_key_length(self) -> None:
        """Test that signing with wrong key length raises ValueError."""
        from ama_cryptography.legacy_compat import ed25519_sign

        with pytest.raises(ValueError, match="32 bytes"):
            ed25519_sign(b"test", b"short_key")

    def test_ed25519_verify_wrong_signature_length(self) -> None:
        """Test that verifying with wrong signature length raises ValueError."""
        from ama_cryptography.legacy_compat import ed25519_verify

        keypair = generate_ed25519_keypair()
        with pytest.raises(ValueError, match="64 bytes"):
            ed25519_verify(b"test", b"short_sig", keypair.public_key)

    def test_ed25519_verify_wrong_pubkey_length(self) -> None:
        """Test that verifying with wrong public key length raises ValueError."""
        from ama_cryptography.legacy_compat import ed25519_verify

        with pytest.raises(ValueError, match="32 bytes"):
            ed25519_verify(b"test", b"x" * 64, b"short_pubkey")

    def test_ed25519_keypair_wrong_seed_length(self) -> None:
        """Test that generating keypair with wrong seed length raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            generate_ed25519_keypair(b"short_seed")


class TestVerificationExceptionHandling:
    """Tests for verification exception handling."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_verify_propagates_general_exceptions(self, kms: Any) -> None:
        """Test that verification propagates exceptions (fail-loud contract)."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")

        # Corrupt the package in a way that causes exceptions
        pkg.content_hash = "invalid"
        pkg.hmac_tag = "invalid"
        pkg.ed25519_signature = "invalid"
        pkg.ed25519_pubkey = "invalid"

        # Unexpected errors must propagate, not be swallowed
        with pytest.raises((ValueError, Exception)):
            verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)


class TestCodeCodesAndHelixParams:
    """Tests for Omni-Codes and helix parameters constants."""

    def test_master_codes_not_empty(self) -> None:
        """Test that MASTER_CODES is not empty."""
        assert len(MASTER_CODES) > 0

    def test_master_helix_params_has_seven_entries(self) -> None:
        """Test that MASTER_HELIX_PARAMS has 7 entries."""
        assert len(MASTER_HELIX_PARAMS) == 7

    def test_helix_params_are_tuples(self) -> None:
        """Test that helix params are tuples of (radius, pitch)."""
        for param in MASTER_HELIX_PARAMS:
            assert isinstance(param, tuple)
            assert len(param) == 2
            radius, pitch = param
            assert isinstance(radius, (int, float))
            assert isinstance(pitch, (int, float))

    def test_helix_params_positive_values(self) -> None:
        """Test that helix params have positive values."""
        for radius, pitch in MASTER_HELIX_PARAMS:
            assert radius > 0
            assert pitch > 0


class TestCanonicalHashEdgeCases:
    """Additional edge case tests for canonical hash."""

    def test_hash_with_empty_helix_params(self) -> None:
        """Test hashing with empty helix params list raises ValueError."""
        with pytest.raises(ValueError, match="helix_params cannot be empty"):
            canonical_hash_code("test_codes", [])

    def test_hash_with_single_helix_param(self) -> None:
        """Test hashing with single helix param."""
        result = canonical_hash_code("test_codes", [(1.0, 2.0)])
        assert len(result) == 32

    def test_hash_with_extreme_helix_values(self) -> None:
        """Test hashing with extreme helix values."""
        result = canonical_hash_code("test", [(0.0001, 0.0001), (99999.9999, 99999.9999)])
        assert len(result) == 32

    def test_hash_with_negative_helix_values(self) -> None:
        """Test hashing with negative helix values."""
        result = canonical_hash_code("test", [(-1.0, -2.0)])
        assert len(result) == 32


class TestPackageCreationEdgeCases:
    """Additional edge case tests for package creation."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_package_with_empty_codes(self, kms: Any) -> None:
        """Test package creation with empty Omni-Codes raises ValueError."""
        with pytest.raises(ValueError, match="codes cannot be empty"):
            create_crypto_package("", [], kms, "test")

    def test_package_with_unicode_author(self, kms: Any) -> None:
        """Test package creation with Unicode author name."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "")
        assert pkg.author == ""

    def test_package_with_long_author(self, kms: Any) -> None:
        """Test package creation with very long author name."""
        long_author = "A" * 10000
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, long_author)
        assert pkg.author == long_author


class TestDeriveKeysEdgeCases:
    """Additional edge case tests for key derivation."""

    def test_derive_single_key(self) -> None:
        """Test deriving single key."""
        master = secrets.token_bytes(32)
        keys, _ = derive_keys(master, "test", num_keys=1)
        assert len(keys) == 1
        assert len(keys[0]) == 32

    def test_derive_many_keys(self) -> None:
        """Test deriving many keys."""
        master = secrets.token_bytes(32)
        keys, _ = derive_keys(master, "test", num_keys=100)
        assert len(keys) == 100
        # All keys should be unique
        assert len({k.hex() for k in keys}) == 100

    def test_derive_keys_with_empty_info(self) -> None:
        """Test deriving keys with empty info string."""
        master = secrets.token_bytes(32)
        keys, _ = derive_keys(master, "", num_keys=3)
        assert len(keys) == 3

    def test_derive_keys_with_unicode_info(self) -> None:
        """Test deriving keys with Unicode info string."""
        master = secrets.token_bytes(32)
        keys, _ = derive_keys(master, "", num_keys=3)
        assert len(keys) == 3


class TestHMACEdgeCases:
    """Additional edge case tests for HMAC."""

    def test_hmac_with_empty_message(self) -> None:
        """Test HMAC with empty message."""
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(32)
        tag = hmac_authenticate(b"", key)
        assert len(tag) == 32
        assert hmac_verify(b"", tag, key) is True

    def test_hmac_with_large_message(self) -> None:
        """Test HMAC with large message."""
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(32)
        large_message = secrets.token_bytes(1000000)  # 1MB
        tag = hmac_authenticate(large_message, key)
        assert hmac_verify(large_message, tag, key) is True

    def test_hmac_with_64_byte_key(self) -> None:
        """Test HMAC with 64-byte key (recommended size)."""
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(64)
        message = b"test message"
        tag = hmac_authenticate(message, key)
        assert hmac_verify(message, tag, key) is True


class TestQuantumSignatureAvailability:
    """Tests for quantum signature availability handling."""

    def test_dilithium_available_flag(self) -> None:
        """Test that DILITHIUM_AVAILABLE flag is set correctly."""
        # Just verify it's a boolean
        assert isinstance(DILITHIUM_AVAILABLE, bool)

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="Dilithium not available")
    def test_dilithium_operations_work_when_available(self) -> None:
        """Test that Dilithium operations work when available."""
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        keypair = generate_dilithium_keypair()
        message = b"test message"
        sig = dilithium_sign(message, keypair.secret_key)
        assert dilithium_verify(message, sig, keypair.public_key) is True


class TestCryptoPackageIntegrity:
    """Tests for crypto package integrity verification."""

    @pytest.fixture
    def kms(self) -> Any:
        """Create KMS for testing."""
        return generate_key_management_system("test_author")

    def test_package_self_verification(self, kms: Any) -> None:
        """Test that a package can verify itself."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        results = verify_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, pkg, kms.hmac_key)
        # All non-None results should be True
        for key, value in results.items():
            if value is not None:
                assert value is True, f"{key} verification failed"

    def test_package_different_codes_fails(self, kms: Any) -> None:
        """Test that different Omni-Codes fail verification."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        results = verify_crypto_package(
            "different_codes",
            MASTER_HELIX_PARAMS,
            pkg,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["content_hash"] is False

    def test_package_different_helix_params_fails(self, kms: Any) -> None:
        """Test that different helix params fail verification."""
        pkg = create_crypto_package(MASTER_CODES, MASTER_HELIX_PARAMS, kms, "test")
        different_params = [(1.0, 1.0)]
        results = verify_crypto_package(
            MASTER_CODES,
            different_params,
            pkg,
            kms.hmac_key,
            require_quantum_signatures=False,
        )
        assert results["content_hash"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
