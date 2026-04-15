#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Tests for functionality added in prior sessions:
  - ama_hmac_sha3_256() native C implementation (RFC 2104 correctness)
  - Ed25519 64-byte expanded-key fast-path
  - constant_time_compare from secure_memory
  - INVARIANT-1 compliance (no stdlib hmac in ama_cryptography/)
"""

import hashlib
import hmac as stdlib_hmac
import secrets

from ama_cryptography.pqc_backends import native_hmac_sha3_256
from ama_cryptography.secure_memory import constant_time_compare

# ============================================================================
# 2.1 — ama_hmac_sha3_256() Native C Correctness
# ============================================================================


class TestNativeHmacSha3256Correctness:
    """RFC 2104 correctness against stdlib reference."""

    def _stdlib_ref(self, key: bytes, msg: bytes) -> bytes:
        return stdlib_hmac.new(key, msg, hashlib.sha3_256).digest()

    def test_basic_correctness(self) -> None:
        key = b"test-key"
        msg = b"test message"
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_empty_message(self) -> None:
        key = b"some-key"
        msg = b""
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_empty_key(self) -> None:
        key = b""
        msg = b"some message"
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_key_longer_than_block_size(self) -> None:
        # SHA3-256 block size (Keccak rate) = 136 bytes
        key = b"k" * 200
        msg = b"message"
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_key_exactly_block_size(self) -> None:
        key = b"k" * 136
        msg = b"message"
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_key_one_byte_over_block_size(self) -> None:
        key = b"k" * 137
        msg = b"message"
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_output_length(self) -> None:
        result = native_hmac_sha3_256(b"key", b"msg")
        assert len(result) == 32

    def test_output_is_bytes(self) -> None:
        result = native_hmac_sha3_256(b"key", b"msg")
        assert isinstance(result, bytes)

    def test_deterministic(self) -> None:
        key, msg = b"key", b"msg"
        assert native_hmac_sha3_256(key, msg) == native_hmac_sha3_256(key, msg)

    def test_different_keys_differ(self) -> None:
        msg = b"same message"
        assert native_hmac_sha3_256(b"key1", msg) != native_hmac_sha3_256(b"key2", msg)

    def test_different_messages_differ(self) -> None:
        key = b"same key"
        assert native_hmac_sha3_256(key, b"msg1") != native_hmac_sha3_256(key, b"msg2")

    def test_large_message(self) -> None:
        key = b"key"
        msg = b"x" * 100_000
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)

    def test_binary_key_and_message(self) -> None:
        key = bytes(range(256))
        msg = bytes(range(255, -1, -1))
        assert native_hmac_sha3_256(key, msg) == self._stdlib_ref(key, msg)


# ============================================================================
# 2.1 (Integration) — hmac_authenticate delegates to native C
# ============================================================================


class TestHmacSha3256Integration:
    """Tests that ama_cryptography.legacy_compat.hmac_authenticate uses the native C path."""

    def test_hmac_authenticate_matches_native(self) -> None:
        """hmac_authenticate must produce same output as native_hmac_sha3_256."""
        from ama_cryptography.legacy_compat import hmac_authenticate

        key = secrets.token_bytes(32)
        msg = b"integration-test-message"
        result = hmac_authenticate(msg, key)
        expected = native_hmac_sha3_256(key, msg)
        assert result == expected

    def test_hmac_verify_accepts_correct_mac(self) -> None:
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(32)
        msg = b"verify-message"
        mac = hmac_authenticate(msg, key)
        assert hmac_verify(msg, mac, key) is True

    def test_hmac_verify_rejects_tampered_mac(self) -> None:
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(32)
        msg = b"verify-message"
        mac = hmac_authenticate(msg, key)
        tampered = bytes([mac[0] ^ 0xFF]) + mac[1:]
        assert hmac_verify(msg, tampered, key) is False

    def test_hmac_verify_rejects_tampered_message(self) -> None:
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(32)
        msg = b"verify-message"
        mac = hmac_authenticate(msg, key)
        assert hmac_verify(b"tampered-message", mac, key) is False

    def test_hmac_verify_rejects_wrong_key(self) -> None:
        from ama_cryptography.legacy_compat import hmac_authenticate, hmac_verify

        key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        msg = b"message"
        mac = hmac_authenticate(msg, key)
        assert hmac_verify(msg, mac, wrong_key) is False


# ============================================================================
# 2.2 — Ed25519 Expanded-Key Fast-Path
# ============================================================================


class TestEd25519ExpandedKeyFastPath:
    """Verify the 64-byte expanded key optimization."""

    def test_keypair_private_key_is_64_bytes(self) -> None:
        from ama_cryptography.legacy_compat import generate_ed25519_keypair

        kp = generate_ed25519_keypair()
        assert len(kp.private_key) == 64, (
            f"Expected 64-byte expanded key, got {len(kp.private_key)}-byte key. "
            "The expanded-key optimization may not have applied correctly."
        )

    def test_keypair_public_key_is_32_bytes(self) -> None:
        from ama_cryptography.legacy_compat import generate_ed25519_keypair

        kp = generate_ed25519_keypair()
        assert len(kp.public_key) == 32

    def test_sign_with_64_byte_key_produces_valid_signature(self) -> None:
        from ama_cryptography.legacy_compat import (
            ed25519_sign,
            ed25519_verify,
            generate_ed25519_keypair,
        )

        kp = generate_ed25519_keypair()
        msg = b"fast-path test message"
        sig = ed25519_sign(msg, kp.private_key)
        assert ed25519_verify(msg, sig, kp.public_key)

    def test_sign_verify_roundtrip_multiple_messages(self) -> None:
        from ama_cryptography.legacy_compat import (
            ed25519_sign,
            ed25519_verify,
            generate_ed25519_keypair,
        )

        kp = generate_ed25519_keypair()
        for i in range(10):
            msg = f"message-{i}".encode()
            sig = ed25519_sign(msg, kp.private_key)
            assert ed25519_verify(msg, sig, kp.public_key), f"Failed on message {i}"

    def test_sign_is_deterministic(self) -> None:
        from ama_cryptography.legacy_compat import ed25519_sign, generate_ed25519_keypair

        kp = generate_ed25519_keypair()
        msg = b"determinism check"
        sig1 = ed25519_sign(msg, kp.private_key)
        sig2 = ed25519_sign(msg, kp.private_key)
        assert sig1 == sig2

    def test_sign_rejects_tampered_message(self) -> None:
        from ama_cryptography.legacy_compat import (
            ed25519_sign,
            ed25519_verify,
            generate_ed25519_keypair,
        )

        kp = generate_ed25519_keypair()
        msg = b"original"
        sig = ed25519_sign(msg, kp.private_key)
        assert not ed25519_verify(b"tampered", sig, kp.public_key)

    def test_sign_rejects_tampered_signature(self) -> None:
        from ama_cryptography.legacy_compat import (
            ed25519_sign,
            ed25519_verify,
            generate_ed25519_keypair,
        )

        kp = generate_ed25519_keypair()
        msg = b"original"
        sig = ed25519_sign(msg, kp.private_key)
        tampered_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
        assert not ed25519_verify(msg, tampered_sig, kp.public_key)

    def test_32_byte_seed_backward_compat(self) -> None:
        """ed25519_sign must still accept 32-byte seeds for backward compatibility."""
        from ama_cryptography.legacy_compat import (
            ed25519_sign,
            ed25519_verify,
            generate_ed25519_keypair,
        )

        kp = generate_ed25519_keypair()
        seed = kp.private_key[:32]  # extract 32-byte seed from expanded key
        msg = b"backward compat test"
        sig = ed25519_sign(msg, seed)
        assert ed25519_verify(msg, sig, kp.public_key)

    def test_seeded_keypair_produces_64_bytes(self) -> None:
        """Deterministic keypair from seed also stores 64-byte expanded key."""
        from ama_cryptography.legacy_compat import generate_ed25519_keypair

        seed = secrets.token_bytes(32)
        kp = generate_ed25519_keypair(seed=seed)
        assert len(kp.private_key) == 64

    def test_seeded_keypair_is_deterministic(self) -> None:
        from ama_cryptography.legacy_compat import generate_ed25519_keypair

        seed = secrets.token_bytes(32)
        kp1 = generate_ed25519_keypair(seed=seed)
        kp2 = generate_ed25519_keypair(seed=seed)
        assert kp1.private_key == kp2.private_key
        assert kp1.public_key == kp2.public_key


# ============================================================================
# 2.3 — No stdlib hmac in ama_cryptography/ source
# ============================================================================


class TestInvariant1NoStdlibHmac:
    """Verify INVARIANT-1: no stdlib hmac import in ama_cryptography/ source."""

    def test_no_stdlib_hmac_in_ama_cryptography(self) -> None:
        import ast
        from pathlib import Path

        ama_dir = Path("ama_cryptography")
        violations = []
        for py_file in ama_dir.glob("**/*.py"):
            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "hmac":
                            violations.append(f"{py_file}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module == "hmac":
                        violations.append(f"{py_file}:{node.lineno}")
        assert not violations, f"INVARIANT-1 violation: stdlib hmac imported in: {violations}"

    def test_no_stdlib_hmac_in_legacy_compat(self) -> None:
        import ast
        from pathlib import Path

        source = Path("ama_cryptography/legacy_compat.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert (
                        alias.name != "hmac"
                    ), f"ama_cryptography/legacy_compat.py:{node.lineno} imports stdlib hmac"
            elif isinstance(node, ast.ImportFrom):
                assert (
                    node.module != "hmac"
                ), f"ama_cryptography/legacy_compat.py:{node.lineno} imports from stdlib hmac"


# ============================================================================
# 2.4 — constant_time_compare
# ============================================================================


class TestConstantTimeCompare:
    """constant_time_compare from secure_memory must be correct."""

    def test_identical_bytes_return_true(self) -> None:
        a = b"same value here"
        assert constant_time_compare(a, a) is True

    def test_equal_bytes_return_true(self) -> None:
        a = b"value"
        b = b"value"
        assert constant_time_compare(a, b) is True

    def test_different_bytes_return_false(self) -> None:
        assert constant_time_compare(b"abc", b"xyz") is False

    def test_different_lengths_return_false(self) -> None:
        assert constant_time_compare(b"short", b"longer value") is False

    def test_empty_bytes_equal(self) -> None:
        assert constant_time_compare(b"", b"") is True

    def test_single_bit_difference(self) -> None:
        a = b"\x00" * 32
        b_val = b"\x00" * 31 + b"\x01"
        assert constant_time_compare(a, b_val) is False

    def test_32_byte_mac_comparison(self) -> None:
        """Simulates real MAC comparison scenario."""
        mac = secrets.token_bytes(32)
        assert constant_time_compare(mac, mac) is True
        tampered = bytes([mac[0] ^ 0x01]) + mac[1:]
        assert constant_time_compare(mac, tampered) is False
