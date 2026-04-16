#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Coverage boost tests for previously-untested error paths and edge branches.

These tests target measured coverage gaps in crypto_api, secure_memory,
pqc_backends, and _self_test. They exercise error-handling branches,
optional-feature toggles, and platform-specific fallbacks rather than
happy paths (which are covered elsewhere).
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

# Backend-availability flags resolved at import time so they can be used as
# `@pytest.mark.skipif` arguments. The repo's conftest converts skipif-marked
# backend skips into hard failures when AMA_CI_REQUIRE_BACKENDS=1; in-body
# pytest.skip() calls would silently bypass that enforcement, so we use markers.
try:
    from ama_cryptography.pqc_backends import (
        _AES_GCM_NATIVE_AVAILABLE,
        DILITHIUM_AVAILABLE,
        KYBER_AVAILABLE,
        SPHINCS_AVAILABLE,
        _native_lib,
    )

    AES_GCM_NATIVE_AVAILABLE = _native_lib is not None and _AES_GCM_NATIVE_AVAILABLE
except ImportError:
    DILITHIUM_AVAILABLE = False
    KYBER_AVAILABLE = False
    SPHINCS_AVAILABLE = False
    AES_GCM_NATIVE_AVAILABLE = False

skip_no_dilithium = pytest.mark.skipif(
    not DILITHIUM_AVAILABLE, reason="Dilithium native backend not available"
)
skip_no_kyber = pytest.mark.skipif(not KYBER_AVAILABLE, reason="Kyber native backend not available")
skip_no_sphincs = pytest.mark.skipif(
    not SPHINCS_AVAILABLE, reason="SPHINCS+ native backend not available"
)
skip_no_aes_gcm_native = pytest.mark.skipif(
    not AES_GCM_NATIVE_AVAILABLE,
    reason="Native AES-256-GCM backend not available (build with cmake)",
)


class TestAtomicWriteJson:
    def test_atomic_write_json_writes_data(self, tmp_path: Path) -> None:
        from ama_cryptography.crypto_api import _atomic_write_json

        target = tmp_path / "out.json"
        _atomic_write_json({"a": 1, "b": [2, 3]}, target)
        assert target.exists()
        assert json.loads(target.read_text()) == {"a": 1, "b": [2, 3]}

    def test_atomic_write_json_fdopen_failure_cleans_up(self, tmp_path: Path) -> None:
        from ama_cryptography import crypto_api

        target = tmp_path / "out.json"
        with mock.patch("os.fdopen", side_effect=OSError("simulated fdopen failure")):
            with pytest.raises(OSError, match="simulated fdopen failure"):
                crypto_api._atomic_write_json({"x": 1}, target)

        # No lingering .tmp files in the target directory
        assert not any(p.suffix == ".tmp" for p in tmp_path.iterdir())


@skip_no_aes_gcm_native
class TestAESGCMCounterPersistence:
    def _fresh_provider_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        from ama_cryptography import crypto_api

        monkeypatch.setattr(crypto_api.AESGCMProvider, "_ephemeral", False, raising=False)
        monkeypatch.setattr(
            crypto_api.AESGCMProvider,
            "_get_persist_path",
            classmethod(lambda cls: tmp_path / "counters.json"),
        )
        monkeypatch.setattr(crypto_api.AESGCMProvider, "_encrypt_counters", {}, raising=False)
        monkeypatch.setattr(crypto_api.AESGCMProvider, "_counters_dirty", 0, raising=False)
        return crypto_api.AESGCMProvider

    def test_persist_counters_writes_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Prov = self._fresh_provider_path(tmp_path, monkeypatch)
        key_id = b"\x00" * 8
        Prov._encrypt_counters[key_id] = 42
        provider = Prov()
        provider._persist_counters(_raising=True)

        persisted = json.loads((tmp_path / "counters.json").read_text())
        assert persisted[key_id.hex()] == 42

    def test_persist_counters_merges_on_disk_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Prov = self._fresh_provider_path(tmp_path, monkeypatch)
        key_id = b"\x11" * 8
        # Pre-existing on-disk counter is higher than in-memory
        (tmp_path / "counters.json").write_text(json.dumps({key_id.hex(): 100}))
        Prov._encrypt_counters[key_id] = 50
        provider = Prov()
        provider._persist_counters(_raising=True)

        assert Prov._encrypt_counters[key_id] == 100

    def test_persist_counters_corrupt_file_raises_when_raising(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Prov = self._fresh_provider_path(tmp_path, monkeypatch)
        (tmp_path / "counters.json").write_text("{not valid json")
        provider = Prov()
        with pytest.raises(RuntimeError, match=r"[Cc]orrupt"):
            provider._persist_counters(_raising=True)

    def test_persist_counters_corrupt_file_quarantines_when_not_raising(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Prov = self._fresh_provider_path(tmp_path, monkeypatch)
        (tmp_path / "counters.json").write_text("{not valid json")
        provider = Prov()
        provider._persist_counters(_raising=False)

        # Corrupt file preserved as .corrupt; new counters.json written
        assert (tmp_path / "counters.json.corrupt").exists()
        assert (tmp_path / "counters.json").exists()
        # Sanity: new file is valid JSON
        json.loads((tmp_path / "counters.json").read_text())

    def test_persist_counters_ephemeral_is_noop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import crypto_api

        monkeypatch.setattr(crypto_api.AESGCMProvider, "_ephemeral", True, raising=False)
        monkeypatch.setattr(
            crypto_api.AESGCMProvider,
            "_get_persist_path",
            classmethod(lambda cls: tmp_path / "counters.json"),
        )
        provider = crypto_api.AESGCMProvider()
        provider._persist_counters(_raising=True)
        assert not (tmp_path / "counters.json").exists()


class TestCryptoPackageSecretStripping:
    def _make_package(self) -> Any:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            num_derived_keys=2,
        )
        return create_crypto_package(b"test content", cfg)

    def test_to_dict_omits_secrets_by_default(self) -> None:
        pkg = self._make_package()
        d = pkg.to_dict()
        assert "hmac_key" not in d
        assert "hkdf_master_secret" not in d
        assert "hmac_tag" in d

    def test_to_dict_includes_secrets_when_asked(self) -> None:
        pkg = self._make_package()
        d = pkg.to_dict(include_secrets=True)
        assert "hmac_key" in d
        assert "hkdf_master_secret" in d

    def test_pickle_round_trip_strips_secrets(self) -> None:
        pkg = self._make_package()
        # Round-trip our own dataclass to verify __setstate__ secret-stripping.
        # The bytes deserialised here are produced by pickle.dumps() in the
        # same statement; no untrusted input is involved.
        blob = pickle.dumps(pkg)
        restored = pickle.loads(blob)  # noqa: S301  -- self-pickled trusted bytes (COV-005)
        # Secrets reset to b"" by __setstate__
        assert restored.hmac_key == b""
        assert restored.hkdf_master_secret == b""
        # Non-secret fields preserved
        assert restored.content_hash == pkg.content_hash
        assert restored.hmac_tag == pkg.hmac_tag


class TestCryptoPackageConfigValidation:
    def test_signing_keypair_wrong_type_raises(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair="not-a-tuple",  # type: ignore[arg-type]  # intentional wrong type to exercise TypeError guard (COV-001)
        )
        with pytest.raises(TypeError, match="tuple"):
            create_crypto_package(b"content", cfg)

    def test_signing_keypair_wrong_length_raises(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair=(b"a", b"b", b"c"),  # type: ignore[arg-type]  # intentional wrong tuple length to exercise TypeError guard (COV-002)
        )
        with pytest.raises(TypeError, match="tuple"):
            create_crypto_package(b"content", cfg)

    def test_signing_keypair_non_bytes_raises(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair=("pk", "sk"),  # type: ignore[arg-type]  # intentional str instead of bytes to exercise TypeError guard (COV-003)
        )
        with pytest.raises(TypeError, match="bytes"):
            create_crypto_package(b"content", cfg)

    def test_signing_keypair_empty_raises(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair=(b"", b""),
        )
        with pytest.raises(ValueError, match="non-empty"):
            create_crypto_package(b"content", cfg)

    def test_signing_keypair_all_zero_raises(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            signing_keypair=(b"\x00" * 32, b"\x00" * 64),
        )
        with pytest.raises(ValueError, match="all-zero"):
            create_crypto_package(b"content", cfg)


class TestAcquireTimestamp:
    def test_no_timestamp_requested_returns_none(self) -> None:
        from ama_cryptography.crypto_api import (
            CryptoPackageConfig,
            _acquire_timestamp,
        )

        cfg = CryptoPackageConfig(include_timestamp=False)
        assert _acquire_timestamp(b"content", cfg) is None

    def test_disabled_tsa_mode_returns_none(self) -> None:
        from ama_cryptography.crypto_api import (
            CryptoPackageConfig,
            _acquire_timestamp,
        )

        cfg = CryptoPackageConfig(include_timestamp=True, tsa_mode="disabled")
        assert _acquire_timestamp(b"content", cfg) is None

    def test_mock_mode_returns_token(self) -> None:
        from ama_cryptography.crypto_api import (
            CryptoPackageConfig,
            _acquire_timestamp,
        )

        cfg = CryptoPackageConfig(include_timestamp=True, tsa_mode="mock")
        tok = _acquire_timestamp(b"content", cfg)
        assert isinstance(tok, bytes) and len(tok) > 0

    def test_mock_mode_empty_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import crypto_api

        cfg = crypto_api.CryptoPackageConfig(include_timestamp=True, tsa_mode="mock")

        class _FakeResult:
            token = b""

        monkeypatch.setattr(crypto_api, "get_timestamp", lambda **kw: _FakeResult())
        with pytest.raises(RuntimeError, match="empty token"):
            crypto_api._acquire_timestamp(b"content", cfg)


class TestVerifyCryptoPackageErrorPaths:
    def _make_valid_package(self) -> Any:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            num_derived_keys=2,
        )
        return create_crypto_package(b"content for verification", cfg)

    def test_empty_derived_keys_fails_layer4(self) -> None:
        from ama_cryptography.crypto_api import verify_crypto_package

        pkg = self._make_valid_package()
        pkg.derived_keys = []  # Tamper
        results = verify_crypto_package(b"content for verification", pkg)
        assert results["hkdf_keys"] is False

    def test_unknown_sig_algorithm_falls_back_to_hybrid(self) -> None:
        from ama_cryptography.crypto_api import verify_crypto_package

        pkg = self._make_valid_package()
        # Inject a bogus algorithm name — should fall back to HYBRID_SIG lookup
        pkg.metadata = dict(pkg.metadata)
        pkg.metadata["signature_algorithm"] = "NONEXISTENT_ALG"
        results = verify_crypto_package(b"content for verification", pkg)
        # primary_signature may be False because HYBRID_SIG keypair is not in
        # package.keypairs under that name, but the call should not crash.
        assert "primary_signature" in results

    def test_hmac_tag_tamper_fails_layer2(self) -> None:
        from ama_cryptography.crypto_api import verify_crypto_package

        pkg = self._make_valid_package()
        pkg.hmac_tag = bytes(a ^ 0xFF for a in pkg.hmac_tag)
        results = verify_crypto_package(b"content for verification", pkg)
        assert results["hmac"] is False


class TestSecureMemoryCoverage:
    def test_secure_random_bytes_zero_size(self) -> None:
        from ama_cryptography.secure_memory import secure_random_bytes

        assert secure_random_bytes(0) == b""

    def test_secure_random_bytes_negative_raises(self) -> None:
        from ama_cryptography.secure_memory import secure_random_bytes

        with pytest.raises(ValueError, match="non-negative"):
            secure_random_bytes(-1)

    def test_get_status_returns_expected_keys(self) -> None:
        from ama_cryptography.secure_memory import get_status

        s = get_status()
        assert s["available"] is True
        assert s["backend"] == "stdlib"
        assert s["initialized"] is True
        assert "mlock_available" in s
        assert "memzero_backend" in s

    def test_detect_mlock_available_returns_bool(self) -> None:
        from ama_cryptography.secure_memory import _detect_mlock_available

        assert isinstance(_detect_mlock_available(), bool)

    def test_constant_time_compare_differing_length(self) -> None:
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"abc", b"abcd") is False
        assert constant_time_compare(b"", b"x") is False

    def test_constant_time_compare_equal(self) -> None:
        from ama_cryptography.secure_memory import constant_time_compare

        assert constant_time_compare(b"abc", b"abc") is True
        assert constant_time_compare(b"", b"") is True

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only mlock test")
    def test_secure_mlock_munlock_bytearray(self) -> None:
        from ama_cryptography.secure_memory import (
            SecureMemoryError,
            secure_mlock,
            secure_munlock,
        )

        buf = bytearray(b"secret data for locking test")
        try:
            secure_mlock(buf)
            locked = True
        except (SecureMemoryError, NotImplementedError):
            # mlock may fail in containers with RLIMIT_MEMLOCK=0. That is
            # acceptable; the code path was still exercised.
            locked = False
        if locked:
            secure_munlock(buf)

    def test_secure_mlock_empty_buffer_noop(self) -> None:
        from ama_cryptography.secure_memory import secure_mlock, secure_munlock

        # Empty buffer: no-op path, returns without raising
        secure_mlock(bytearray())
        secure_munlock(bytearray())


class TestPqcBackendsEdgeCases:
    def test_get_pqc_backend_info_structure(self) -> None:
        from ama_cryptography.pqc_backends import get_pqc_backend_info

        info = get_pqc_backend_info()
        assert isinstance(info, dict)
        assert "backend" in info

    @skip_no_dilithium
    def test_dilithium_sign_rejects_non_bytes_message(self) -> None:
        import ctypes

        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            generate_dilithium_keypair,
        )

        kp = generate_dilithium_keypair()
        with pytest.raises((TypeError, ValueError, ctypes.ArgumentError)):
            dilithium_sign("not bytes", kp.secret_key)  # type: ignore[arg-type]  # intentional str to exercise ctypes type rejection (COV-004)

    @skip_no_kyber
    def test_kyber_encapsulate_rejects_wrong_key_size(self) -> None:
        from ama_cryptography.pqc_backends import kyber_encapsulate

        with pytest.raises((ValueError, TypeError)):
            kyber_encapsulate(b"wrong size public key")

    @skip_no_dilithium
    def test_dilithium_verify_wrong_signature_returns_false(self) -> None:
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(b"original msg", kp.secret_key)
        # Tamper signature
        bad_sig = bytes(b ^ 0x01 for b in sig)
        assert dilithium_verify(b"original msg", bad_sig, kp.public_key) is False

    @skip_no_dilithium
    def test_dilithium_verify_wrong_message_returns_false(self) -> None:
        from ama_cryptography.pqc_backends import (
            dilithium_sign,
            dilithium_verify,
            generate_dilithium_keypair,
        )

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(b"message A", kp.secret_key)
        assert dilithium_verify(b"message B", sig, kp.public_key) is False

    @skip_no_sphincs
    def test_sphincs_verify_wrong_key_returns_false(self) -> None:
        from ama_cryptography.pqc_backends import (
            generate_sphincs_keypair,
            sphincs_sign,
            sphincs_verify,
        )

        kp1 = generate_sphincs_keypair()
        kp2 = generate_sphincs_keypair()
        sig = sphincs_sign(b"msg", kp1.secret_key)
        assert sphincs_verify(b"msg", sig, kp2.public_key) is False

    @skip_no_kyber
    def test_kyber_decapsulate_rejects_wrong_ciphertext_size(self) -> None:
        from ama_cryptography.pqc_backends import (
            generate_kyber_keypair,
            kyber_decapsulate,
        )

        kp = generate_kyber_keypair()
        with pytest.raises((ValueError, TypeError)):
            kyber_decapsulate(b"too short", kp.secret_key)

    @skip_no_dilithium
    def test_dilithium_keypair_repr_does_not_leak_secret(self) -> None:
        from ama_cryptography.pqc_backends import generate_dilithium_keypair

        kp = generate_dilithium_keypair()
        r = repr(kp)
        # Secret key should not appear as raw hex in repr
        assert kp.secret_key.hex() not in r

    @skip_no_kyber
    def test_kyber_keypair_repr_does_not_leak_secret(self) -> None:
        from ama_cryptography.pqc_backends import generate_kyber_keypair

        kk = generate_kyber_keypair()
        r = repr(kk)
        assert kk.secret_key.hex() not in r


class TestKeypairCache:
    def test_get_or_generate_returns_keypair(self) -> None:
        from ama_cryptography.crypto_api import AlgorithmType, KeypairCache

        cache = KeypairCache(algorithm=AlgorithmType.ED25519)
        pk, sk = cache.get_or_generate()
        assert isinstance(pk, bytes) and len(pk) > 0
        assert isinstance(sk, bytes) and len(sk) > 0

    def test_get_or_generate_caches_result(self) -> None:
        from ama_cryptography.crypto_api import AlgorithmType, KeypairCache

        cache = KeypairCache(algorithm=AlgorithmType.ED25519)
        pk1, sk1 = cache.get_or_generate()
        pk2, sk2 = cache.get_or_generate()
        assert pk1 == pk2
        assert sk1 == sk2

    def test_rotate_clears_cache(self) -> None:
        from ama_cryptography.crypto_api import AlgorithmType, KeypairCache

        cache = KeypairCache(algorithm=AlgorithmType.ED25519)
        pk1, _ = cache.get_or_generate()
        cache.rotate()
        pk2, _ = cache.get_or_generate()
        assert pk1 != pk2

    def test_finalizer_wipes_without_raising(self) -> None:
        from ama_cryptography.crypto_api import AlgorithmType, KeypairCache

        cache = KeypairCache(algorithm=AlgorithmType.ED25519)
        cache.get_or_generate()
        # The finalizer path delegates to _wipe_sk(); call that directly
        # rather than __del__ to avoid CodeQL Python/ExplicitCallToDel
        # while still exercising the secret-zeroing branch.
        cache._wipe_sk()
        assert cache._sk is None


@skip_no_aes_gcm_native
class TestAESGCMProviderValidation:
    def test_decrypt_rejects_wrong_key_length(self) -> None:
        from ama_cryptography.crypto_api import AESGCMProvider

        provider = AESGCMProvider()
        with pytest.raises(ValueError, match="32 bytes"):
            provider.decrypt(b"ct", b"short key", b"\x00" * 12, b"\x00" * 16, b"")

    def test_decrypt_rejects_wrong_nonce_length(self) -> None:
        from ama_cryptography.crypto_api import AESGCMProvider

        provider = AESGCMProvider()
        with pytest.raises(ValueError, match="12 bytes"):
            provider.decrypt(b"ct", b"\x00" * 32, b"short", b"\x00" * 16, b"")

    def test_decrypt_rejects_wrong_tag_length(self) -> None:
        from ama_cryptography.crypto_api import AESGCMProvider

        provider = AESGCMProvider()
        with pytest.raises(ValueError, match="16 bytes"):
            provider.decrypt(b"ct", b"\x00" * 32, b"\x00" * 12, b"short", b"")


class TestCreatePackageOptionalFeatures:
    @skip_no_sphincs
    def test_package_with_sphincs_addon(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            use_sphincs=True,
            num_derived_keys=1,
        )
        pkg = create_crypto_package(b"content", cfg)
        assert pkg.sphincs_signature is not None
        assert "SPHINCS_256F" in pkg.keypairs

    @skip_no_kyber
    def test_package_with_kyber_kem_addon(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            use_kyber=True,
            include_kem=True,
            num_derived_keys=1,
        )
        pkg = create_crypto_package(b"content", cfg)
        assert pkg.kem_ciphertext is not None
        assert pkg.kem_shared_secret is not None
        assert "KYBER_1024" in pkg.keypairs

    def test_verify_roundtrip_with_addons(self) -> None:
        from ama_cryptography.crypto_api import (
            AlgorithmType,
            CryptoPackageConfig,
            create_crypto_package,
            verify_crypto_package,
        )

        cfg = CryptoPackageConfig(
            signature_algorithm=AlgorithmType.ED25519,
            use_sphincs=SPHINCS_AVAILABLE,
            use_kyber=KYBER_AVAILABLE,
            include_kem=KYBER_AVAILABLE,
            num_derived_keys=1,
        )
        pkg = create_crypto_package(b"addon content", cfg)
        results = verify_crypto_package(b"addon content", pkg)
        assert results["content_hash"] is True
        assert results["hmac"] is True
        assert results["primary_signature"] is True
        assert results["hkdf_keys"] is True


class TestSelfTestEdgeCases:
    def test_verify_module_integrity_returns_tuple(self) -> None:
        from ama_cryptography import _self_test as st

        passed, detail = st.verify_module_integrity()
        assert isinstance(passed, bool)
        assert isinstance(detail, str)

    def test_self_test_results_accessible(self) -> None:
        from ama_cryptography import _self_test as st

        # Module-level result list exists and is iterable
        assert hasattr(st, "_SELF_TEST_RESULTS")
        results = st._SELF_TEST_RESULTS
        for item in results:
            assert len(item) == 3

    def test_self_test_aggregate_status_is_bool(self) -> None:
        from ama_cryptography import _self_test as st

        # Avoid re-running the full POST: _run_self_tests() re-executes the
        # probabilistic constant-time timing oracle, which is noise-sensitive
        # and uses internal retries. The module-level results are populated
        # at import time and sufficient for type/shape validation.
        results = st._SELF_TEST_RESULTS
        aggregate_passed = all(item[1] for item in results) if results else False
        assert isinstance(aggregate_passed, bool)
        assert isinstance(st.module_status(), str)
        assert isinstance(st.post_duration_ms(), float)

    def test_kat_functions_return_tuples(self) -> None:
        from ama_cryptography import _self_test as st

        # These kat functions are module-private. Exercise them directly to
        # cover the success paths.
        for fn_name in ("_kat_sha3_256", "_kat_hmac_sha3_256", "_kat_ed25519"):
            fn = getattr(st, fn_name, None)
            if fn is None:
                continue
            passed, detail = fn()
            assert isinstance(passed, bool)
            assert isinstance(detail, str)
