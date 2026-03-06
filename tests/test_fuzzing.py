#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
Fuzzing tests using Hypothesis for property-based testing.

These tests verify that core cryptographic functions maintain their
invariants under random inputs, helping detect edge cases and
potential security issues.
"""

import os
import secrets

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

# Configure Hypothesis for CI environments - use fewer examples to prevent timeouts
# Set HYPOTHESIS_PROFILE=ci to use reduced examples, or default to "default" profile
_in_ci = os.environ.get("CI", "").lower() in ("1", "true", "yes") or os.environ.get(
    "GITHUB_ACTIONS", ""
).lower() in ("1", "true", "yes")

# CI profile: fewer examples, shorter deadlines to prevent timeouts
settings.register_profile(
    "ci",
    max_examples=50,
    deadline=5000,  # 5 second deadline per example
    suppress_health_check=[HealthCheck.too_slow],
)

# Default profile: more thorough testing for local development
settings.register_profile(
    "default",
    max_examples=100,
    deadline=None,
)

# Load the appropriate profile
settings.load_profile("ci" if _in_ci else os.environ.get("HYPOTHESIS_PROFILE", "default"))

# Late imports required - Hypothesis settings must be configured before importing test subjects
from code_guardian_secure import (  # noqa: E402
    DILITHIUM_AVAILABLE,
    SIGNATURE_FORMAT_V2,
    build_signature_message,
    canonical_hash_code,
    create_crypto_package,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    generate_key_management_system,
    hmac_authenticate,
    hmac_verify,
    length_prefixed_encode,
    secure_wipe,
    verify_crypto_package,
)

# Import Dilithium functions if available
if DILITHIUM_AVAILABLE:
    from code_guardian_secure import (
        dilithium_sign,
        dilithium_verify,
        generate_dilithium_keypair,
    )


class TestLengthPrefixFuzzing:
    """Fuzz tests for length-prefixed encoding."""

    @given(st.lists(st.text(max_size=500), min_size=1, max_size=20))
    def test_encoding_deterministic(self, fields):
        """Same input always produces same output (determinism)."""
        e1 = length_prefixed_encode(*fields)
        e2 = length_prefixed_encode(*fields)
        assert e1 == e2, "Encoding must be deterministic"

    @given(
        st.lists(st.text(max_size=100), min_size=1, max_size=10),
        st.lists(st.text(max_size=100), min_size=1, max_size=10),
    )
    def test_no_collisions(self, fields1, fields2):
        """Different inputs produce different outputs (collision resistance)."""
        assume(fields1 != fields2)
        e1 = length_prefixed_encode(*fields1)
        e2 = length_prefixed_encode(*fields2)
        assert e1 != e2, f"Collision detected: {fields1} vs {fields2}"

    @given(st.lists(st.binary(max_size=100), min_size=1, max_size=10))
    def test_binary_fields_roundtrip(self, fields):
        """Binary fields encode without error."""
        # Convert binary to strings for encoding
        str_fields = [f.hex() for f in fields]
        result = length_prefixed_encode(*str_fields)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestCanonicalHashFuzzing:
    """Fuzz tests for canonical Code hashing."""

    @given(
        st.text(min_size=1, max_size=1000, alphabet="ACGT"),
        st.lists(
            st.tuples(
                st.floats(min_value=0.01, max_value=100, allow_nan=False, allow_infinity=False),
                st.floats(min_value=0.01, max_value=100, allow_nan=False, allow_infinity=False),
            ),
            min_size=1,
            max_size=20,
        ),
    )
    def test_hash_deterministic(self, dna, params):
        """Hash is deterministic for same inputs."""
        h1 = canonical_hash_code(dna, params)
        h2 = canonical_hash_code(dna, params)
        assert h1 == h2, "Hash must be deterministic"
        assert len(h1) == 32, "SHA3-256 produces 32 bytes"

    @given(
        st.text(min_size=1, max_size=100, alphabet="ACGT"),
        st.text(min_size=1, max_size=100, alphabet="ACGT"),
    )
    def test_different_dna_different_hash(self, dna1, dna2):
        """Different Code sequences produce different hashes."""
        assume(dna1 != dna2)
        params = [(1.0, 1.0)]
        h1 = canonical_hash_code(dna1, params)
        h2 = canonical_hash_code(dna2, params)
        assert h1 != h2, f"Hash collision: {dna1} vs {dna2}"


class TestHMACFuzzing:
    """Fuzz tests for HMAC authentication."""

    @given(st.binary(max_size=10000))
    def test_hmac_roundtrip(self, message):
        """HMAC verify accepts valid tags."""
        key = secrets.token_bytes(32)
        tag = hmac_authenticate(message, key)
        assert hmac_verify(message, tag, key), "Valid HMAC must verify"

    @given(st.binary(max_size=1000))
    def test_modified_tag_fails(self, message):
        """Modified tags fail verification (integrity)."""
        key = secrets.token_bytes(32)
        tag = bytearray(hmac_authenticate(message, key))
        tag[0] ^= 0xFF  # Flip all bits in first byte
        assert not hmac_verify(message, bytes(tag), key), "Modified tag must fail"

    @given(st.binary(max_size=1000))
    def test_wrong_key_fails(self, message):
        """Wrong key fails verification (authentication)."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        assume(key1 != key2)
        tag = hmac_authenticate(message, key1)
        assert not hmac_verify(message, tag, key2), "Wrong key must fail"

    @given(st.binary(max_size=1000), st.binary(max_size=1000))
    def test_modified_message_fails(self, message1, message2):
        """Modified message fails verification."""
        assume(message1 != message2)
        key = secrets.token_bytes(32)
        tag = hmac_authenticate(message1, key)
        assert not hmac_verify(message2, tag, key), "Modified message must fail"


class TestEd25519Fuzzing:
    """Fuzz tests for Ed25519 signatures."""

    @given(st.binary(max_size=10000))
    def test_sign_verify_roundtrip(self, message):
        """Signatures verify correctly."""
        kp = generate_ed25519_keypair()
        sig = ed25519_sign(message, kp.private_key)
        assert ed25519_verify(message, sig, kp.public_key), "Valid signature must verify"

    @given(st.binary(max_size=1000))
    def test_modified_signature_fails(self, message):
        """Modified signatures fail verification."""
        kp = generate_ed25519_keypair()
        sig = bytearray(ed25519_sign(message, kp.private_key))
        sig[0] ^= 0xFF
        assert not ed25519_verify(message, bytes(sig), kp.public_key), "Modified sig must fail"

    @given(st.binary(max_size=1000))
    def test_wrong_key_fails(self, message):
        """Wrong public key fails verification."""
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        sig = ed25519_sign(message, kp1.private_key)
        assert not ed25519_verify(message, sig, kp2.public_key), "Wrong key must fail"


class TestSecureWipeFuzzing:
    """Fuzz tests for secure memory wiping."""

    @given(st.binary(min_size=1, max_size=10000))
    def test_wipe_zeros_all_bytes(self, data):
        """secure_wipe zeros all bytes in bytearray."""
        ba = bytearray(data)
        assume(any(b != 0 for b in ba))  # Ensure not already zeroed

        secure_wipe(ba)

        assert all(b == 0 for b in ba), "All bytes must be zeroed"
        assert len(ba) == len(data), "Length must be preserved"


class TestDomainSeparationFuzzing:
    """Fuzz tests for domain-separated signature message building."""

    @given(
        st.binary(min_size=32, max_size=32),  # content_hash (SHA3-256)
        st.binary(min_size=32, max_size=32),  # ethical_hash (SHA3-256)
    )
    def test_signature_message_deterministic(self, content_hash, ethical_hash):
        """Same inputs always produce same signature message."""
        msg1 = build_signature_message(content_hash, ethical_hash, SIGNATURE_FORMAT_V2)
        msg2 = build_signature_message(content_hash, ethical_hash, SIGNATURE_FORMAT_V2)
        assert msg1 == msg2, "Signature message must be deterministic"

    @given(
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=32, max_size=32),
    )
    def test_signature_message_length(self, content_hash, ethical_hash):
        """Signature message has expected length (78 bytes for v2)."""
        msg = build_signature_message(content_hash, ethical_hash, SIGNATURE_FORMAT_V2)
        # 9 (prefix) + 5 (version) + 32 (content_hash) + 32 (ethical_hash) = 78
        assert len(msg) == 78, f"Expected 78 bytes, got {len(msg)}"

    @given(
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=32, max_size=32),
    )
    def test_different_inputs_different_messages(self, ch1, eh1, ch2, eh2):
        """Different inputs produce different signature messages."""
        assume(ch1 != ch2 or eh1 != eh2)
        msg1 = build_signature_message(ch1, eh1, SIGNATURE_FORMAT_V2)
        msg2 = build_signature_message(ch2, eh2, SIGNATURE_FORMAT_V2)
        assert msg1 != msg2, "Different inputs must produce different messages"

    @given(st.binary(min_size=32, max_size=32))
    def test_signature_message_contains_domain_prefix(self, content_hash):
        """Signature message starts with domain prefix."""
        ethical_hash = secrets.token_bytes(32)
        msg = build_signature_message(content_hash, ethical_hash, SIGNATURE_FORMAT_V2)
        assert msg.startswith(b"AMA-PKG-v2"), "Message must start with domain prefix"

    @given(st.binary(min_size=32, max_size=32))
    def test_ed25519_signs_domain_separated_message(self, content_hash):
        """Ed25519 can sign and verify domain-separated messages."""
        ethical_hash = secrets.token_bytes(32)
        msg = build_signature_message(content_hash, ethical_hash, SIGNATURE_FORMAT_V2)

        kp = generate_ed25519_keypair()
        sig = ed25519_sign(msg, kp.private_key)
        assert ed25519_verify(
            msg, sig, kp.public_key
        ), "Ed25519 must verify domain-separated message"


class TestDilithiumFuzzing:
    """Fuzz tests for Dilithium (ML-DSA-65) signatures."""

    @given(st.binary(max_size=10000))
    def test_dilithium_sign_verify_roundtrip(self, message):
        """Dilithium signatures verify correctly."""
        if not DILITHIUM_AVAILABLE:
            return  # Skip if Dilithium not available

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(message, kp.private_key)
        assert dilithium_verify(
            message, sig, kp.public_key
        ), "Valid Dilithium signature must verify"

    @given(st.binary(max_size=1000))
    def test_dilithium_modified_signature_fails(self, message):
        """Modified Dilithium signatures fail verification."""
        if not DILITHIUM_AVAILABLE:
            return

        kp = generate_dilithium_keypair()
        sig = bytearray(dilithium_sign(message, kp.private_key))
        sig[0] ^= 0xFF
        assert not dilithium_verify(message, bytes(sig), kp.public_key), "Modified sig must fail"

    @given(st.binary(max_size=1000))
    def test_dilithium_wrong_key_fails(self, message):
        """Wrong Dilithium public key fails verification."""
        if not DILITHIUM_AVAILABLE:
            return

        kp1 = generate_dilithium_keypair()
        kp2 = generate_dilithium_keypair()
        sig = dilithium_sign(message, kp1.private_key)
        assert not dilithium_verify(message, sig, kp2.public_key), "Wrong key must fail"

    @given(st.binary(min_size=32, max_size=32))
    def test_dilithium_signs_domain_separated_message(self, content_hash):
        """Dilithium can sign and verify domain-separated messages."""
        if not DILITHIUM_AVAILABLE:
            return

        ethical_hash = secrets.token_bytes(32)
        msg = build_signature_message(content_hash, ethical_hash, SIGNATURE_FORMAT_V2)

        kp = generate_dilithium_keypair()
        sig = dilithium_sign(msg, kp.private_key)
        assert dilithium_verify(
            msg, sig, kp.public_key
        ), "Dilithium must verify domain-separated message"


class TestCryptoPackageFuzzing:
    """Fuzz tests for complete crypto package creation and verification."""

    @given(
        st.text(min_size=1, max_size=500, alphabet="ACGT"),
        st.lists(
            st.tuples(
                st.floats(min_value=0.1, max_value=10, allow_nan=False, allow_infinity=False),
                st.floats(min_value=0.1, max_value=10, allow_nan=False, allow_infinity=False),
            ),
            min_size=1,
            max_size=10,
        ),
    )
    def test_package_roundtrip(self, codes, helix_params):
        """Created packages verify successfully."""
        kms = generate_key_management_system("fuzz_test")
        pkg = create_crypto_package(codes, helix_params, kms, "fuzz_author")

        results = verify_crypto_package(
            codes,
            helix_params,
            pkg,
            kms.hmac_key,
            require_quantum_signatures=kms.quantum_signatures_enabled,
        )

        assert results["content_hash"], "Content hash must verify"
        assert results["hmac"], "HMAC must verify"
        assert results["ed25519"], "Ed25519 signature must verify"
        if kms.quantum_signatures_enabled:
            assert results["dilithium"], "Dilithium signature must verify when enabled"

    @given(
        st.text(min_size=1, max_size=100, alphabet="ACGT"),
        st.text(min_size=1, max_size=100, alphabet="ACGT"),
    )
    def test_tampered_dna_fails(self, dna1, dna2):
        """Verification fails when Omni-Codes are tampered."""
        assume(dna1 != dna2)
        params = [(1.0, 1.0)]
        kms = generate_key_management_system("fuzz_test")
        pkg = create_crypto_package(dna1, params, kms, "fuzz_author")

        results = verify_crypto_package(
            dna2,  # Different Code
            params,
            pkg,
            kms.hmac_key,
            require_quantum_signatures=False,
        )

        assert not results["content_hash"], "Tampered Code must fail content hash"
        assert not results["hmac"], "Tampered Code must fail HMAC"
        assert not results["ed25519"], "Tampered Code must fail Ed25519"
