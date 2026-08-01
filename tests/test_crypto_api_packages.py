#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Coverage closure for ``ama_cryptography.crypto_api.create_crypto_package``
and ``verify_crypto_package``.

These functions implement the 4-layer defense-in-depth package format
(SHA3-256, HMAC-SHA3-256, Ed25519+ML-DSA-65 signature, HKDF-SHA3-256 keys)
plus optional SPHINCS+, Kyber-KEM and RFC 3161 add-ons.  The legacy_compat
module also exposes a differently-shaped wrapper; the modern crypto_api
entry point previously had very low coverage.  This file exercises the
positive path, all optional add-ons, input validation and error branches.
"""

from __future__ import annotations

import pytest

from ama_cryptography.crypto_api import (
    DILITHIUM_AVAILABLE,
    KYBER_AVAILABLE,
    SPHINCS_AVAILABLE,
    AlgorithmType,
    AmaCryptography,
    CryptoPackageConfig,
    CryptoPackageResult,
    KyberUnavailableError,
    SphincsUnavailableError,
    _acquire_timestamp,
    create_crypto_package,
    get_pqc_capabilities,
    verify_crypto_package,
)

pytestmark = pytest.mark.skipif(
    not DILITHIUM_AVAILABLE,
    reason="Requires native Dilithium backend for HYBRID_SIG signatures",
)


# ---------------------------------------------------------------------------
# Positive path: minimal package
# ---------------------------------------------------------------------------


class TestCreateAndVerifyBasic:
    """End-to-end validation of the 4-layer package."""

    def test_minimal_package_round_trip(self) -> None:
        pkg = create_crypto_package(b"hello world")
        assert isinstance(pkg, CryptoPackageResult)
        assert pkg.metadata["defense_layers"] == 4
        assert pkg.metadata["multi_layer_defense"] is True
        assert len(pkg.derived_keys) >= 1
        assert pkg.hmac_tag and pkg.hmac_key

        pk = pkg.keypairs["HYBRID_SIG"].public_key
        verdict = verify_crypto_package(b"hello world", pkg, expected_public_key=pk)
        assert verdict["content_hash"] is True
        assert verdict["hmac"] is True
        assert verdict["primary_signature"] is True
        assert verdict["hkdf_keys"] is True
        assert verdict["core_valid"] is True
        assert verdict["all_valid"] is True
        # Backwards-compat alias
        assert verdict["primary"] is True

    def test_multiple_derived_keys(self) -> None:
        cfg = CryptoPackageConfig(num_derived_keys=5)
        pkg = create_crypto_package(b"payload", cfg)
        assert len(pkg.derived_keys) == 5
        pk = pkg.keypairs["HYBRID_SIG"].public_key
        v = verify_crypto_package(b"payload", pkg, expected_public_key=pk)
        assert v["hkdf_keys"] is True
        assert v["all_valid"] is True

    def test_content_tamper_fails_layer1(self) -> None:
        pkg = create_crypto_package(b"original")
        v = verify_crypto_package(b"tampered", pkg)
        assert v["content_hash"] is False
        # HMAC recomputed over tampered content also won't match
        assert v["hmac"] is False
        assert v["core_valid"] is False
        assert v["all_valid"] is False

    def test_hmac_key_tamper_fails_layer2(self) -> None:
        pkg = create_crypto_package(b"msg")
        # Swap the HMAC key — produces a different tag
        tampered = CryptoPackageResult(
            content_hash=pkg.content_hash,
            hmac_key=b"\x00" * 32,
            hmac_tag=pkg.hmac_tag,
            primary_signature=pkg.primary_signature,
            sphincs_signature=pkg.sphincs_signature,
            derived_keys=pkg.derived_keys,
            hkdf_salt=pkg.hkdf_salt,
            hkdf_master_secret=pkg.hkdf_master_secret,
            hkdf_info=pkg.hkdf_info,
            timestamp=pkg.timestamp,
            kem_ciphertext=pkg.kem_ciphertext,
            kem_shared_secret=pkg.kem_shared_secret,
            keypairs=pkg.keypairs,
            metadata=pkg.metadata,
        )
        v = verify_crypto_package(b"msg", tampered)
        assert v["hmac"] is False
        assert v["all_valid"] is False

    def test_derived_keys_tamper_fails_layer4(self) -> None:
        pkg = create_crypto_package(b"msg", CryptoPackageConfig(num_derived_keys=3))
        # Replace one derived key with zeros
        bad_keys = list(pkg.derived_keys)
        bad_keys[1] = b"\x00" * 32
        tampered = CryptoPackageResult(
            content_hash=pkg.content_hash,
            hmac_key=pkg.hmac_key,
            hmac_tag=pkg.hmac_tag,
            primary_signature=pkg.primary_signature,
            sphincs_signature=pkg.sphincs_signature,
            derived_keys=bad_keys,
            hkdf_salt=pkg.hkdf_salt,
            hkdf_master_secret=pkg.hkdf_master_secret,
            hkdf_info=pkg.hkdf_info,
            timestamp=pkg.timestamp,
            kem_ciphertext=pkg.kem_ciphertext,
            kem_shared_secret=pkg.kem_shared_secret,
            keypairs=pkg.keypairs,
            metadata=pkg.metadata,
        )
        v = verify_crypto_package(b"msg", tampered)
        assert v["hkdf_keys"] is False
        assert v["all_valid"] is False

    def test_empty_derived_keys_fails_fail_closed(self) -> None:
        """INVARIANT: zero derived keys must NOT trivially bypass Layer 4."""
        pkg = create_crypto_package(b"msg")
        tampered = CryptoPackageResult(
            content_hash=pkg.content_hash,
            hmac_key=pkg.hmac_key,
            hmac_tag=pkg.hmac_tag,
            primary_signature=pkg.primary_signature,
            sphincs_signature=pkg.sphincs_signature,
            derived_keys=[],  # fail-closed invariant
            hkdf_salt=pkg.hkdf_salt,
            hkdf_master_secret=pkg.hkdf_master_secret,
            hkdf_info=pkg.hkdf_info,
            timestamp=pkg.timestamp,
            kem_ciphertext=pkg.kem_ciphertext,
            kem_shared_secret=pkg.kem_shared_secret,
            keypairs=pkg.keypairs,
            metadata=pkg.metadata,
        )
        v = verify_crypto_package(b"msg", tampered)
        assert v["hkdf_keys"] is False


class TestCreateInputValidation:
    def test_non_bytes_content_raises(self) -> None:
        with pytest.raises(TypeError):
            create_crypto_package("not bytes")  # type: ignore[arg-type]  # intentional wrong type to verify TypeError (CAP-001)

    def test_empty_content_raises(self) -> None:
        with pytest.raises(ValueError):
            create_crypto_package(b"")

    def test_signing_keypair_wrong_type_raises(self) -> None:
        with pytest.raises(TypeError):
            create_crypto_package(
                b"payload",
                CryptoPackageConfig(signing_keypair="bad"),  # type: ignore[arg-type]  # intentional wrong type to verify TypeError (CAP-002)
            )

    def test_signing_keypair_wrong_arity_raises(self) -> None:
        with pytest.raises(TypeError):
            create_crypto_package(
                b"payload",
                CryptoPackageConfig(signing_keypair=(b"only_one",)),  # type: ignore[arg-type]  # intentional wrong arity to verify TypeError (CAP-003)
            )

    def test_signing_keypair_non_bytes_members_raises(self) -> None:
        with pytest.raises(TypeError):
            create_crypto_package(
                b"payload",
                CryptoPackageConfig(signing_keypair=("pk", "sk")),  # type: ignore[arg-type]  # intentional wrong element type to verify TypeError (CAP-004)
            )

    def test_signing_keypair_empty_member_raises(self) -> None:
        with pytest.raises(ValueError):
            create_crypto_package(
                b"payload",
                CryptoPackageConfig(signing_keypair=(b"", b"\x01" * 32)),
            )

    def test_signing_keypair_all_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            create_crypto_package(
                b"payload",
                CryptoPackageConfig(signing_keypair=(b"\x00" * 32, b"\x00" * 64)),
            )


class TestCreateWithPreGeneratedKeypair:
    def test_pre_generated_ed25519_keypair(self) -> None:
        """Caller-supplied keypair is used verbatim."""
        crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)
        kp = crypto.generate_keypair()
        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair=(kp.public_key, kp.secret_key),
        )
        pkg = create_crypto_package(b"payload", cfg)
        assert pkg.keypairs["ED25519"].public_key == kp.public_key
        assert pkg.keypairs["ED25519"].secret_key == kp.secret_key
        assert pkg.keypairs["ED25519"].metadata.get("source") == "pre-generated"
        v = verify_crypto_package(b"payload", pkg, expected_public_key=kp.public_key)
        assert v["all_valid"] is True


class TestSphincsAddOn:
    @pytest.mark.skipif(not SPHINCS_AVAILABLE, reason="SPHINCS+ backend unavailable")
    def test_create_and_verify_with_sphincs(self) -> None:
        cfg = CryptoPackageConfig(use_sphincs=True)
        pkg = create_crypto_package(b"long-term data", cfg)
        assert pkg.sphincs_signature is not None
        assert "SPHINCS_256F" in pkg.keypairs
        pk = pkg.keypairs["HYBRID_SIG"].public_key
        v = verify_crypto_package(b"long-term data", pkg, expected_public_key=pk)
        assert v.get("sphincs") is True
        assert v["all_valid"] is True

    def test_sphincs_requested_but_unavailable_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When SPHINCS+ is unavailable, requesting it raises fail-closed.

        Simulated by monkeypatching ``crypto_api.SPHINCS_AVAILABLE`` to
        ``False`` so the test exercises the error branch unconditionally,
        without relying on a platform skip that would be misclassified by
        ``AMA_CI_REQUIRE_BACKENDS``.  The string-path form of
        ``monkeypatch.setattr`` avoids an ``import ama_cryptography.crypto_api``
        that would duplicate the existing ``from ama_cryptography.crypto_api
        import ...`` at the top of this module.
        """
        monkeypatch.setattr("ama_cryptography.crypto_api.SPHINCS_AVAILABLE", False)
        cfg = CryptoPackageConfig(use_sphincs=True)
        with pytest.raises(SphincsUnavailableError):
            create_crypto_package(b"data", cfg)


class TestKyberAddOn:
    @pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber backend unavailable")
    def test_create_and_verify_with_kem(self) -> None:
        cfg = CryptoPackageConfig(use_kyber=True, include_kem=True)
        pkg = create_crypto_package(b"ke payload", cfg)
        assert pkg.kem_ciphertext is not None
        assert pkg.kem_shared_secret is not None
        assert "KYBER_1024" in pkg.keypairs
        pk = pkg.keypairs["HYBRID_SIG"].public_key
        v = verify_crypto_package(b"ke payload", pkg, expected_public_key=pk)
        assert v.get("kem") is True
        assert v["all_valid"] is True

    def test_kyber_requested_but_unavailable_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When Kyber is unavailable, requesting it raises fail-closed.

        Simulated by monkeypatching ``crypto_api.KYBER_AVAILABLE`` to
        ``False`` so the test exercises the error branch unconditionally,
        regardless of whether the real backend is present on the runner.
        The string-path form of ``monkeypatch.setattr`` avoids an
        ``import ama_cryptography.crypto_api`` that would duplicate the
        existing ``from`` import at the top of this module.
        """
        monkeypatch.setattr("ama_cryptography.crypto_api.KYBER_AVAILABLE", False)
        cfg = CryptoPackageConfig(use_kyber=True, include_kem=True)
        with pytest.raises(KyberUnavailableError):
            create_crypto_package(b"data", cfg)


class TestAcquireTimestamp:
    """Exercise the RFC 3161 helper in isolation."""

    def test_disabled_via_include_flag(self) -> None:
        cfg = CryptoPackageConfig(include_timestamp=False)
        assert _acquire_timestamp(b"payload", cfg) is None

    def test_disabled_via_tsa_mode(self) -> None:
        cfg = CryptoPackageConfig(include_timestamp=True, tsa_mode="disabled")
        assert _acquire_timestamp(b"payload", cfg) is None

    def test_mock_mode_returns_token(self) -> None:
        cfg = CryptoPackageConfig(include_timestamp=True, tsa_mode="mock")
        token = _acquire_timestamp(b"payload", cfg)
        assert token is not None and len(token) > 0

    def test_mock_mode_integrated_into_package(self) -> None:
        cfg = CryptoPackageConfig(include_timestamp=True, tsa_mode="mock")
        pkg = create_crypto_package(b"data", cfg)
        assert pkg.timestamp is not None
        assert pkg.metadata["timestamp_enabled"] is True


# ---------------------------------------------------------------------------
# Serialisation / pickle safety
# ---------------------------------------------------------------------------


class TestCryptoPackageSerialization:
    def test_to_dict_strips_secrets_by_default(self) -> None:
        pkg = create_crypto_package(b"data")
        d = pkg.to_dict()
        assert "hmac_key" not in d
        assert "hkdf_master_secret" not in d

    def test_to_dict_with_secrets(self) -> None:
        pkg = create_crypto_package(b"data")
        d = pkg.to_dict(include_secrets=True)
        assert d["hmac_key"] == pkg.hmac_key
        assert d["hkdf_master_secret"] == pkg.hkdf_master_secret

    def test_to_dict_strips_the_private_signing_key(self) -> None:
        """The most sensitive field in the package must not survive to_dict().

        Regression: ``_SECRET_FIELDS`` covered only ``hmac_key`` and
        ``hkdf_master_secret``, so the default — documented as stripping
        secrets — emitted ``keypairs[...].secret_key``, ~4 KB of Ed25519 +
        ML-DSA-65 private key. The assertions below fail on that code.
        """
        pkg = create_crypto_package(b"data")
        assert pkg.keypairs, "package must carry at least one keypair to test"
        # Non-vacuity: the live object really does hold a private key, so a
        # zero-length secret in the dict is stripping and not absence.
        assert all(len(kp.secret_key) > 0 for kp in pkg.keypairs.values())

        d = pkg.to_dict()
        for name, kp in d["keypairs"].items():
            assert kp.secret_key == b"", f"{name} private key leaked through to_dict()"
            assert kp.public_key == pkg.keypairs[name].public_key, "public key must survive"
        assert "derived_keys" not in d
        assert "kem_shared_secret" not in d

        # Redaction is a copy, never a mutation of the caller's package.
        assert all(len(kp.secret_key) > 0 for kp in pkg.keypairs.values())

        full = pkg.to_dict(include_secrets=True)
        assert full["keypairs"]["HYBRID_SIG"].secret_key == pkg.keypairs["HYBRID_SIG"].secret_key
        assert full["derived_keys"] == pkg.derived_keys

    def test_pickle_strips_the_private_signing_key(self) -> None:
        """Same leak, via ``__getstate__``. Public material still round-trips."""
        import pickle

        pkg = create_crypto_package(b"data")
        restored = pickle.loads(pickle.dumps(pkg))  # noqa: S301  --  self-produced blob (CAP-005)  # fmt: skip
        for name, kp in restored.keypairs.items():
            assert kp.secret_key == b"", f"{name} private key survived pickling"
            assert kp.public_key == pkg.keypairs[name].public_key
        assert restored.derived_keys == []
        assert restored.kem_shared_secret is None
        # Placeholders must keep their declared types, not collapse to b"".
        assert isinstance(restored.derived_keys, list)
        # Two restores must not share one placeholder list.
        other = pickle.loads(pickle.dumps(pkg))  # noqa: S301  --  self-produced blob (CAP-005)  # fmt: skip
        assert restored.derived_keys is not other.derived_keys

    def test_pickle_strips_secrets(self) -> None:
        import pickle

        pkg = create_crypto_package(b"data")
        blob = pickle.dumps(pkg)
        # Round-tripping a blob we just produced ourselves to verify
        # __getstate__/__setstate__ secret-stripping; no untrusted input
        # is deserialised here.
        restored = pickle.loads(blob)  # noqa: S301  --  self-produced blob, secret-stripping verification only (CAP-005)  # fmt: skip
        assert restored.hmac_key == b""
        assert restored.hkdf_master_secret == b""
        # Non-secret fields preserved
        assert restored.content_hash == pkg.content_hash


# ---------------------------------------------------------------------------
# get_pqc_capabilities — informational helper, also exercises backend probe
# ---------------------------------------------------------------------------


class TestGetPqcCapabilities:
    def test_shape(self) -> None:
        caps = get_pqc_capabilities()
        assert set(caps).issuperset(
            {
                "status",
                "dilithium_available",
                "kyber_available",
                "sphincs_available",
                "backend",
                "algorithms",
                "security_levels",
                "key_sizes",
            }
        )
        assert caps["status"] in ("AVAILABLE", "UNAVAILABLE")
        assert isinstance(caps["algorithms"], dict)
