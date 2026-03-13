#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography End-to-End Integration Tests
============================================

Complete workflow integration tests covering:
1. Full cryptographic package lifecycle (create -> sign -> verify)
2. Key management workflows (generate -> rotate -> archive)
3. Multi-algorithm interoperability
4. Error recovery and graceful degradation
5. Performance regression detection
6. Humanitarian use case scenarios

Target: >80% code coverage for production readiness.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
"""

import json
import secrets
import tempfile
import time
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

import pytest


class TestFullCryptoPackageLifecycle:
    """End-to-end tests for complete cryptographic package workflows."""

    def test_complete_sign_verify_workflow(self) -> None:
        """Test complete workflow: generate keys -> create package -> verify."""
        from code_guardian_secure import (
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            create_crypto_package,
            generate_key_management_system,
            verify_crypto_package,
        )

        # Step 1: Generate key management system
        kms = generate_key_management_system("E2E Test Organization")
        assert kms is not None
        assert kms.hmac_key is not None
        assert kms.ed25519_keypair is not None

        # Step 2: Create cryptographic package
        package = create_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            kms=kms,
            author="E2E Test",
            use_rfc3161=False,
        )
        assert package is not None
        assert package.content_hash is not None
        assert package.ed25519_signature is not None

        # Step 3: Verify package
        results = verify_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        # All verifications should pass
        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["ed25519"] is True

    def test_package_serialization_roundtrip(self) -> None:
        """Test that packages can be serialized and deserialized correctly."""
        from code_guardian_secure import (
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            CryptoPackage,
            create_crypto_package,
            generate_key_management_system,
            verify_crypto_package,
        )

        kms = generate_key_management_system("Serialization Test")
        package = create_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            kms=kms,
            author="Serialization Test",
            use_rfc3161=False,
        )

        # Serialize to JSON
        package_dict = asdict(package)
        json_str = json.dumps(package_dict, indent=2)

        # Deserialize back
        loaded_dict = json.loads(json_str)
        loaded_package = CryptoPackage(**loaded_dict)

        # Verify the loaded package
        results = verify_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            package=loaded_package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["ed25519"] is True

    def test_tamper_detection(self) -> None:
        """Test that tampering with package data is detected."""
        from code_guardian_secure import (
            MASTER_CODES,
            MASTER_HELIX_PARAMS,
            create_crypto_package,
            generate_key_management_system,
            verify_crypto_package,
        )

        kms = generate_key_management_system("Tamper Test")
        package = create_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            kms=kms,
            author="Tamper Test",
            use_rfc3161=False,
        )

        # Tamper with the content hash
        original_hash = package.content_hash
        package.content_hash = "a" * 64  # Invalid hash

        results = verify_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        # Content hash verification should fail
        assert results["content_hash"] is False

        # Restore and tamper with signature
        package.content_hash = original_hash
        package.ed25519_signature = "b" * 128

        results = verify_crypto_package(
            codes=MASTER_CODES,
            helix_params=MASTER_HELIX_PARAMS,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        # Ed25519 verification should fail
        assert results["ed25519"] is False


class TestKeyManagementWorkflows:
    """End-to-end tests for key management operations."""

    def test_hd_key_derivation_determinism(self) -> None:
        """Test that HD key derivation is deterministic."""
        from ama_cryptography.key_management import HDKeyDerivation

        seed = b"test_seed_for_deterministic_derivation_32bytes!"

        # Derive keys twice with same seed
        hd1 = HDKeyDerivation(seed=seed)
        hd2 = HDKeyDerivation(seed=seed)

        key1, chain1 = hd1.derive_path("m/44'/0'/0'/0/0")
        key2, chain2 = hd2.derive_path("m/44'/0'/0'/0/0")

        assert key1 == key2
        assert chain1 == chain2

    def test_key_rotation_workflow(self) -> None:
        """Test complete key rotation workflow."""
        from ama_cryptography.key_management import KeyRotationManager

        manager = KeyRotationManager(rotation_period=timedelta(days=90))

        # Register initial key
        manager.register_key(
            "primary-key-v1",
            purpose="signing",
            max_usage=100,
        )
        assert manager.get_active_key() == "primary-key-v1"

        # Register replacement key
        manager.register_key(
            "primary-key-v2",
            purpose="signing",
            parent_id="primary-key-v1",
        )

        # Simulate usage
        for _ in range(50):
            manager.increment_usage("primary-key-v1")

        assert manager.keys["primary-key-v1"].usage_count == 50

        # Initiate rotation
        manager.initiate_rotation("primary-key-v1", "primary-key-v2")
        assert manager.get_active_key() == "primary-key-v2"

        # Complete rotation
        manager.complete_rotation("primary-key-v1")
        assert manager.keys["primary-key-v1"].status.name == "DEPRECATED"

    def test_secure_storage_encryption(self) -> None:
        """Test secure key storage with encryption."""
        from ama_cryptography.key_management import SecureKeyStorage

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureKeyStorage(
                Path(tmpdir),
                master_password="secure_test_password_456!",
            )

            # Store multiple keys
            test_keys = {
                "signing-key": secrets.token_bytes(32),
                "encryption-key": secrets.token_bytes(32),
                "backup-key": secrets.token_bytes(64),
            }

            for key_id, key_data in test_keys.items():
                storage.store_key(key_id, key_data, metadata={"test": True})

            # Retrieve and verify
            for key_id, original in test_keys.items():
                retrieved = storage.retrieve_key(key_id)
                assert retrieved == original

            # Delete and verify deletion
            for key_id in test_keys:
                storage.delete_key(key_id)
                assert storage.retrieve_key(key_id) is None


class TestMultiAlgorithmInteroperability:
    """Tests for algorithm switching and hybrid modes."""

    def test_algorithm_switching(self) -> None:
        """Test switching between different algorithms."""
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        message = b"Test message for algorithm switching"

        algorithms = [AlgorithmType.ED25519]

        # Check if PQC is available
        from ama_cryptography.pqc_backends import DILITHIUM_AVAILABLE

        if DILITHIUM_AVAILABLE:
            algorithms.append(AlgorithmType.ML_DSA_65)
            algorithms.append(AlgorithmType.HYBRID_SIG)

        for algo in algorithms:
            crypto = AmaCryptography(algorithm=algo)
            keypair = crypto.generate_keypair()
            signature = crypto.sign(message, keypair.secret_key)
            valid = crypto.verify(message, signature.signature, keypair.public_key)
            assert valid, f"Verification failed for {algo}"

    def test_cross_verification_fails(self) -> None:
        """Test that signatures from one algorithm don't verify with another."""
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        message = b"Cross verification test"

        # Sign with Ed25519
        ed_crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        ed_keypair = ed_crypto.generate_keypair()
        ed_signature = ed_crypto.sign(message, ed_keypair.secret_key)

        # Try to verify with different key (should fail)
        ed_crypto2 = AmaCryptography(algorithm=AlgorithmType.ED25519)
        ed_keypair2 = ed_crypto2.generate_keypair()

        valid = ed_crypto2.verify(message, ed_signature.signature, ed_keypair2.public_key)
        assert not valid


class TestErrorRecoveryAndGracefulDegradation:
    """Tests for error handling and graceful degradation."""

    def test_invalid_key_handling(self) -> None:
        """Test handling of invalid keys."""
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        message = b"Test message"

        # Invalid key should not crash, just fail verification
        invalid_key = b"invalid_key_data"
        keypair = crypto.generate_keypair()
        signature = crypto.sign(message, keypair.secret_key)

        # Verification with wrong key should return False, not crash
        result = crypto.verify(message, signature.signature, invalid_key)
        assert result is False

    def test_empty_message_handling(self) -> None:
        """Test handling of empty messages."""
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        empty_message = b""

        keypair = crypto.generate_keypair()
        signature = crypto.sign(empty_message, keypair.secret_key)
        valid = crypto.verify(empty_message, signature.signature, keypair.public_key)

        assert valid

    def test_pqc_unavailable_graceful_handling(self) -> None:
        """Test graceful handling when PQC is unavailable."""
        from unittest.mock import patch

        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography
        from ama_cryptography.pqc_backends import PQCUnavailableError

        # Mock Dilithium as unavailable to test error path
        with patch("ama_cryptography.pqc_backends.DILITHIUM_AVAILABLE", False):
            with pytest.raises(PQCUnavailableError):
                crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)
                crypto.generate_keypair()


class TestPerformanceRegression:
    """Performance regression tests."""

    def test_signature_performance(self) -> None:
        """Test that signature operations meet performance targets."""
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        message = b"Performance test message" * 100
        keypair = crypto.generate_keypair()

        # Benchmark signing
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            crypto.sign(message, keypair.secret_key)
        sign_time = (time.perf_counter() - start) / iterations

        # Benchmark verification
        signature = crypto.sign(message, keypair.secret_key)
        start = time.perf_counter()
        for _ in range(iterations):
            crypto.verify(message, signature.signature, keypair.public_key)
        verify_time = (time.perf_counter() - start) / iterations

        # Performance targets (generous for CI environments)
        assert sign_time < 0.01, f"Signing too slow: {sign_time:.4f}s"
        assert verify_time < 0.01, f"Verification too slow: {verify_time:.4f}s"

    def test_hash_performance(self) -> None:
        """Test that hashing operations meet performance targets."""
        import sys

        from code_guardian_secure import canonical_hash_code

        # Large input
        large_codes = "A" * 10000
        large_params = [(1.0, 2.0)] * 100

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            canonical_hash_code(large_codes, large_params)
        hash_time = (time.perf_counter() - start) / iterations

        # Performance threshold varies by platform due to CI environment variability.
        # Windows CI runners (especially Python 3.8) show ~4x slower performance than
        # Linux/macOS due to shared resources and Python 3.8's older hashlib.
        # Typical values: Linux ~0.002s, macOS ~0.003s, Windows 3.8 ~0.02s
        if sys.platform == "win32":
            threshold = 0.05  # 50ms for Windows CI (observed: ~20ms on Win 3.8)
        else:
            threshold = 0.01  # 10ms for Linux/macOS (observed: ~2-3ms)

        assert (
            hash_time < threshold
        ), f"Hashing too slow: {hash_time:.6f}s (threshold: {threshold}s)"


class TestHumanitarianUseCases:
    """Tests for humanitarian and crisis response scenarios."""

    def test_crisis_data_protection(self) -> None:
        """Test protecting sensitive crisis response data."""
        from code_guardian_secure import (
            create_crypto_package,
            generate_key_management_system,
            verify_crypto_package,
        )

        # Simulate crisis response data
        crisis_data = "GPS:34.0522,-118.2437|VICTIM_COUNT:15|SAFE_HOUSE:ACTIVE"
        helix_params = [(1.0, 2.0), (1.5, 2.5)]

        kms = generate_key_management_system("Crisis Response Unit")

        # Create protected package
        package = create_crypto_package(
            codes=crisis_data,
            helix_params=helix_params,
            kms=kms,
            author="Field Operator",
            use_rfc3161=False,
        )

        # Verify integrity
        results = verify_crypto_package(
            codes=crisis_data,
            helix_params=helix_params,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["ed25519"] is True

    def test_whistleblower_document_signing(self) -> None:
        """Test document signing for whistleblower protection."""
        from code_guardian_secure import (
            create_crypto_package,
            generate_key_management_system,
            verify_crypto_package,
        )

        # Simulate sensitive document
        document = "CONFIDENTIAL: Evidence of misconduct dated 2025-01-15"
        helix_params = [(1.0, 1.0)]

        kms = generate_key_management_system("Anonymous Source")

        package = create_crypto_package(
            codes=document,
            helix_params=helix_params,
            kms=kms,
            author="Anonymous",
            use_rfc3161=False,
        )

        # Package should be verifiable without revealing identity
        results = verify_crypto_package(
            codes=document,
            helix_params=helix_params,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        assert all(v is True for k, v in results.items() if v is not None)

    def test_medical_record_integrity(self) -> None:
        """Test medical record integrity verification."""
        from code_guardian_secure import (
            create_crypto_package,
            generate_key_management_system,
            verify_crypto_package,
        )

        # Simulate medical record
        medical_record = json.dumps(
            {
                "patient_id": "ANON-12345",
                "diagnosis": "Type 2 Diabetes",
                "prescription": "Metformin 500mg",
                "date": "2025-01-20",
            }
        )
        helix_params = [(1.0, 1.5), (2.0, 2.5)]

        kms = generate_key_management_system("Healthcare Provider")

        package = create_crypto_package(
            codes=medical_record,
            helix_params=helix_params,
            kms=kms,
            author="Dr. Smith",
            use_rfc3161=False,
        )

        # Verify record hasn't been tampered
        results = verify_crypto_package(
            codes=medical_record,
            helix_params=helix_params,
            package=package,
            hmac_key=kms.hmac_key,
            require_quantum_signatures=False,
        )

        assert results["content_hash"] is True
        assert results["hmac"] is True


class TestEthicalIntegration:
    """Tests for ethical framework integration."""

    def test_ethical_vector_in_key_derivation(self) -> None:
        """Test that ethical vector is properly integrated."""
        from code_guardian_secure import ETHICAL_VECTOR, create_ethical_hkdf_context

        # Verify ethical vector structure
        assert len(ETHICAL_VECTOR) == 4
        assert sum(ETHICAL_VECTOR.values()) == 12.0

        # Create ethical context with base context bytes
        base_context = b"test_context_for_ethical_integration"
        context = create_ethical_hkdf_context(base_context, ETHICAL_VECTOR)
        assert context is not None
        assert len(context) > 0

    def test_ethical_pillars_coverage(self) -> None:
        """Test that all 4 Omni-Code ethical pillars are present."""
        from code_guardian_secure import ETHICAL_VECTOR

        # The 4 Omni-Code Ethical Pillars, each governing a triad
        expected_pillars = [
            # Pillar 1: Omniscient — Triad of Wisdom
            "omniscient",
            # Pillar 2: Omnipotent — Triad of Agency
            "omnipotent",
            # Pillar 3: Omnidirectional — Triad of Geography
            "omnidirectional",
            # Pillar 4: Omnibenevolent — Triad of Integrity
            "omnibenevolent",
        ]

        for pillar in expected_pillars:
            assert pillar in ETHICAL_VECTOR, f"Missing pillar: {pillar}"
            assert ETHICAL_VECTOR[pillar] == 3.0


class TestCryptoAPIIntegration:
    """Integration tests for the crypto API module."""

    def test_pqc_capabilities_reporting(self) -> None:
        """Test PQC capabilities are correctly reported."""
        from ama_cryptography.crypto_api import get_pqc_capabilities

        caps = get_pqc_capabilities()

        assert "dilithium_available" in caps
        assert "kyber_available" in caps
        assert "sphincs_available" in caps
        assert "algorithms" in caps

    def test_constant_time_compare(self) -> None:
        """Test constant-time comparison function."""
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)

        # Equal values
        a = b"test_value_123"
        b = b"test_value_123"
        assert crypto.constant_time_compare(a, b) is True

        # Different values
        c = b"different_value"
        assert crypto.constant_time_compare(a, c) is False

        # Different lengths
        d = b"short"
        assert crypto.constant_time_compare(a, d) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
