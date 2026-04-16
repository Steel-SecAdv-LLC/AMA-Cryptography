#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
PR #224 Follow-up Tests
========================

Regression and validation tests for code paths introduced or modified
by PR #224 (security audit fixes).  Covers:

- HandshakeResponse.deserialize() validation (truncated, malformed,
  oversized inputs)
- create_handshake() KEM encapsulation result validation
- Length-prefixed HKDF encoding (ambiguous concatenation prevention)
- encapsulate_hybrid / decapsulate_hybrid input validation
- INVARIANT-7 RuntimeError enforcement in HybridCombiner.combine()
"""

from __future__ import annotations

import os
import struct
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ama_cryptography.hybrid_combiner import (
    _MAX_CT_BYTES,
    _MAX_SS_BYTES,
    HybridCombiner,
)
from ama_cryptography.secure_channel import (
    _MAX_FIELD_BYTES,
    SESSION_ID_BYTES,
    ChannelError,
    HandshakeResponse,
)


def _random(n: int) -> bytes:
    return os.urandom(n)


# ---------------------------------------------------------------------------
# Helpers: build valid HandshakeResponse wire data
# ---------------------------------------------------------------------------


def _build_handshake_response_wire(
    session_id: bytes | None = None,
    sig: bytes | None = None,
    pk: bytes | None = None,
    *,
    sig_len_override: int | None = None,
    pk_len_override: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    """Build HandshakeResponse wire format with optional overrides for fuzzing."""
    if session_id is None:
        session_id = _random(SESSION_ID_BYTES)
    if sig is None:
        sig = _random(64)
    if pk is None:
        pk = _random(32)

    sig_len = sig_len_override if sig_len_override is not None else len(sig)
    pk_len = pk_len_override if pk_len_override is not None else len(pk)

    return session_id + struct.pack(">I", sig_len) + sig + struct.pack(">I", pk_len) + pk + trailing


# ===========================================================================
# Task 1: HandshakeResponse.deserialize() Validation Tests
# ===========================================================================


class TestHandshakeResponseDeserializeValidation:
    """Validate all error paths in HandshakeResponse.deserialize()."""

    def test_truncated_below_minimum(self) -> None:
        """Input shorter than the minimum header (32 + 4 + 4 = 40 bytes) is rejected."""
        for size in (0, 1, 10, 39):
            with pytest.raises(ChannelError, match="Truncated HandshakeResponse"):
                HandshakeResponse.deserialize(b"\x00" * size)

    def test_exactly_minimum_with_zero_length_fields(self) -> None:
        """40 bytes with sig_len=0 and pk_len=0 should parse successfully."""
        session_id = _random(SESSION_ID_BYTES)
        wire = session_id + struct.pack(">I", 0) + struct.pack(">I", 0)
        assert len(wire) == 40
        result = HandshakeResponse.deserialize(wire)
        assert result.session_id == session_id
        assert result.signature == b""
        assert result.responder_public_key == b""

    def test_missing_signature_length_field(self) -> None:
        """Data that has session_id but is missing the sig_len field entirely."""
        data = _random(SESSION_ID_BYTES)  # only 32 bytes, missing sig_len
        with pytest.raises(ChannelError, match="Truncated"):
            HandshakeResponse.deserialize(data)

    def test_sig_len_exceeds_max_field_bytes(self) -> None:
        """sig_len exceeding _MAX_FIELD_BYTES is rejected as oversized."""
        session_id = _random(SESSION_ID_BYTES)
        data = session_id + struct.pack(">I", _MAX_FIELD_BYTES + 1) + b"\x00" * 100
        with pytest.raises(ChannelError, match=r"sig_len=.*exceeds maximum"):
            HandshakeResponse.deserialize(data)

    def test_sig_len_exceeds_available_data(self) -> None:
        """sig_len within max but exceeding remaining data is rejected."""
        session_id = _random(SESSION_ID_BYTES)
        sig_len = 1000
        data = session_id + struct.pack(">I", sig_len) + b"\x00" * 10  # only 10 bytes of sig
        with pytest.raises(ChannelError, match=r"Truncated HandshakeResponse.*sig_len"):
            HandshakeResponse.deserialize(data)

    def test_missing_public_key_length_field(self) -> None:
        """Data has valid signature but is truncated before pk_len field."""
        session_id = _random(SESSION_ID_BYTES)
        sig = _random(64)
        data = session_id + struct.pack(">I", len(sig)) + sig
        # Missing pk_len (4 bytes)
        with pytest.raises(ChannelError, match="missing public key length"):
            HandshakeResponse.deserialize(data)

    def test_pk_len_exceeds_max_field_bytes(self) -> None:
        """pk_len exceeding _MAX_FIELD_BYTES is rejected."""
        session_id = _random(SESSION_ID_BYTES)
        sig = _random(64)
        data = (
            session_id
            + struct.pack(">I", len(sig))
            + sig
            + struct.pack(">I", _MAX_FIELD_BYTES + 1)
            + b"\x00" * 100
        )
        with pytest.raises(ChannelError, match=r"pk_len=.*exceeds maximum"):
            HandshakeResponse.deserialize(data)

    def test_pk_len_exceeds_available_data(self) -> None:
        """pk_len within max but exceeding remaining data is rejected."""
        session_id = _random(SESSION_ID_BYTES)
        sig = _random(64)
        pk_len = 500
        data = (
            session_id
            + struct.pack(">I", len(sig))
            + sig
            + struct.pack(">I", pk_len)
            + b"\x00" * 10
        )
        with pytest.raises(ChannelError, match=r"Truncated HandshakeResponse.*pk_len"):
            HandshakeResponse.deserialize(data)

    def test_trailing_bytes_rejected(self) -> None:
        """Extra trailing bytes after all fields are rejected."""
        wire = _build_handshake_response_wire(trailing=b"\xff\xff")
        with pytest.raises(ChannelError, match="trailing bytes"):
            HandshakeResponse.deserialize(wire)

    def test_valid_round_trip(self) -> None:
        """A properly constructed wire message round-trips without error."""
        original = HandshakeResponse(
            session_id=_random(SESSION_ID_BYTES),
            signature=_random(2500),
            responder_public_key=_random(1184),
        )
        wire = original.serialize()
        restored = HandshakeResponse.deserialize(wire)
        assert restored.session_id == original.session_id
        assert restored.signature == original.signature
        assert restored.responder_public_key == original.responder_public_key

    def test_max_valid_field_lengths(self) -> None:
        """Fields at exactly _MAX_FIELD_BYTES are accepted (boundary test)."""
        sig = _random(_MAX_FIELD_BYTES)
        pk = _random(32)
        wire = _build_handshake_response_wire(sig=sig, pk=pk)
        result = HandshakeResponse.deserialize(wire)
        assert len(result.signature) == _MAX_FIELD_BYTES

    def test_corrupted_sig_len_prefix(self) -> None:
        """A sig_len that is huge (0xFFFFFFFF) is rejected."""
        session_id = _random(SESSION_ID_BYTES)
        data = session_id + struct.pack(">I", 0xFFFFFFFF) + _random(100)
        with pytest.raises(ChannelError, match="exceeds maximum"):
            HandshakeResponse.deserialize(data)


# ===========================================================================
# Task 2: create_handshake() KEM Validation Tests
# ===========================================================================


try:
    from ama_cryptography.pqc_backends import _native_lib

    NATIVE_AVAILABLE = _native_lib is not None
except ImportError:
    NATIVE_AVAILABLE = False

skip_no_native = pytest.mark.skipif(
    not NATIVE_AVAILABLE,
    reason="Native C library not available (build with cmake)",
)


@skip_no_native
class TestCreateHandshakeKEMValidation:
    """Verify create_handshake() rejects invalid KEM encapsulation results."""

    def _make_initiator(self) -> Any:
        # The skip_no_native gate checks _native_lib is non-None, but the
        # library may be loaded without Kyber/X25519/HKDF backends actually
        # available (e.g., built without AMA_USE_NATIVE_PQC).  Skip cleanly
        # if HybridKEMProvider construction or keygen fails for that reason.
        from ama_cryptography.crypto_api import HybridKEMProvider
        from ama_cryptography.secure_channel import SecureChannelInitiator

        try:
            provider = HybridKEMProvider()
            kp = provider.generate_keypair()
        except (RuntimeError, ImportError, AttributeError) as exc:
            pytest.skip(f"Hybrid KEM backend unavailable: {exc}")
        return SecureChannelInitiator(kp.public_key)

    def test_empty_shared_secret_rejected(self) -> None:
        """KEM returning empty shared secret raises HandshakeError."""
        from ama_cryptography.secure_channel import HandshakeError

        initiator = self._make_initiator()

        mock_result = MagicMock()
        mock_result.shared_secret = b""
        mock_result.ciphertext = _random(1568)

        with patch.object(initiator._kem, "encapsulate", return_value=mock_result):
            with pytest.raises(HandshakeError, match="invalid shared secret"):
                initiator.create_handshake()

    def test_none_shared_secret_rejected(self) -> None:
        """KEM returning None shared secret raises HandshakeError."""
        from ama_cryptography.secure_channel import HandshakeError

        initiator = self._make_initiator()

        mock_result = MagicMock()
        mock_result.shared_secret = None
        mock_result.ciphertext = _random(1568)

        with patch.object(initiator._kem, "encapsulate", return_value=mock_result):
            with pytest.raises(HandshakeError, match="invalid shared secret"):
                initiator.create_handshake()

    def test_wrong_size_shared_secret_rejected(self) -> None:
        """KEM returning wrong-size shared secret raises HandshakeError."""
        from ama_cryptography.secure_channel import KEY_BYTES, HandshakeError

        initiator = self._make_initiator()

        mock_result = MagicMock()
        mock_result.shared_secret = _random(KEY_BYTES + 1)
        mock_result.ciphertext = _random(1568)

        with patch.object(initiator._kem, "encapsulate", return_value=mock_result):
            with pytest.raises(HandshakeError, match="invalid shared secret"):
                initiator.create_handshake()

    def test_empty_ciphertext_rejected(self) -> None:
        """KEM returning empty ciphertext raises HandshakeError."""
        from ama_cryptography.secure_channel import KEY_BYTES, HandshakeError

        initiator = self._make_initiator()

        mock_result = MagicMock()
        mock_result.shared_secret = _random(KEY_BYTES)
        mock_result.ciphertext = b""

        with patch.object(initiator._kem, "encapsulate", return_value=mock_result):
            with pytest.raises(HandshakeError, match="empty ciphertext"):
                initiator.create_handshake()


# ===========================================================================
# Task 3: Length-Prefixed Encoding Regression Test
# ===========================================================================


class TestLengthPrefixedEncodingPreventsAmbiguousConcatenation:
    """Prove that the length-prefixed HKDF construction prevents
    ambiguous concatenation / component stripping attacks.

    Without length prefixes, different (ct1, ct2) pairs could produce
    the same salt byte string:
        ct1=b"AABB" || ct2=b"CC"  vs  ct1=b"AA" || ct2=b"BBCC"
    both yield the raw concatenation b"AABBCC".

    With length-prefixed encoding, the salt includes the length of each
    component, making the two cases unambiguously different.

    These tests use _hkdf_python directly since the construction logic
    (salt/info encoding) is what we're proving correct, not the native
    backend itself.
    """

    @staticmethod
    def _build_salt(ct1: bytes, ct2: bytes) -> bytes:
        """Build the length-prefixed salt as combine() does."""
        return struct.pack(">I", len(ct1)) + ct1 + struct.pack(">I", len(ct2)) + ct2

    @staticmethod
    def _build_info(label: bytes, pk1: bytes = b"", pk2: bytes = b"") -> bytes:
        """Build the length-prefixed info as combine() does."""
        return (
            label
            + struct.pack(">B", 2)
            + struct.pack(">I", len(pk1))
            + pk1
            + struct.pack(">I", len(pk2))
            + pk2
        )

    def test_ambiguous_ciphertexts_produce_different_outputs(self) -> None:
        """Two (ct1, ct2) pairs that would be ambiguous without length
        prefixes MUST produce different combined secrets."""
        label = b"ama-hybrid-kem-v2"

        ct1_a = b"AABB"
        ct2_a = b"CC"
        ct1_b = b"AA"
        ct2_b = b"BBCC"

        ss1 = b"\x01" * 32
        ss2 = b"\x02" * 32
        ikm = ss1 + ss2
        info = self._build_info(label)

        result_a = HybridCombiner._hkdf_python(
            salt=self._build_salt(ct1_a, ct2_a),
            ikm=ikm,
            info=info,
            okm_len=32,
        )
        result_b = HybridCombiner._hkdf_python(
            salt=self._build_salt(ct1_b, ct2_b),
            ikm=ikm,
            info=info,
            okm_len=32,
        )

        assert result_a != result_b, (
            "Length-prefixed encoding FAILED: different ciphertext pairs "
            "with the same raw concatenation produced identical HKDF output"
        )

    def test_ambiguous_shared_secrets_produce_different_outputs(self) -> None:
        """Two (ss1, ss2) pairs with the same total byte content but
        different split points MUST produce different combined secrets,
        since they form different IKM values."""
        label = b"ama-hybrid-kem-v2"
        ct1 = _random(32)
        ct2 = _random(1568)
        salt = self._build_salt(ct1, ct2)
        info = self._build_info(label)

        ss1_a = b"\xaa" * 48
        ss2_a = b"\xbb" * 16
        ss1_b = b"\xaa" * 16
        ss2_b = b"\xbb" * 48

        result_a = HybridCombiner._hkdf_python(
            salt=salt,
            ikm=ss1_a + ss2_a,
            info=info,
            okm_len=32,
        )
        result_b = HybridCombiner._hkdf_python(
            salt=salt,
            ikm=ss1_b + ss2_b,
            info=info,
            okm_len=32,
        )

        assert result_a != result_b, (
            "Different shared secret splits with same total bytes "
            "should produce different HKDF output"
        )

    def test_ambiguous_public_keys_produce_different_outputs(self) -> None:
        """Two (pk1, pk2) pairs with same raw concatenation MUST
        produce different combined secrets."""
        label = b"ama-hybrid-kem-v2"
        ss1 = _random(32)
        ss2 = _random(32)
        ct1 = _random(32)
        ct2 = _random(1568)
        salt = self._build_salt(ct1, ct2)
        ikm = ss1 + ss2

        pk1_a = b"XXYY"
        pk2_a = b"ZZ"
        pk1_b = b"XX"
        pk2_b = b"YYZZ"

        result_a = HybridCombiner._hkdf_python(
            salt=salt,
            ikm=ikm,
            info=self._build_info(label, pk1_a, pk2_a),
            okm_len=32,
        )
        result_b = HybridCombiner._hkdf_python(
            salt=salt,
            ikm=ikm,
            info=self._build_info(label, pk1_b, pk2_b),
            okm_len=32,
        )

        assert result_a != result_b, (
            "Length-prefixed encoding FAILED: different public key pairs "
            "with the same raw concatenation produced identical HKDF output"
        )


# ===========================================================================
# Additional: encapsulate_hybrid / decapsulate_hybrid Validation Tests
# ===========================================================================


class TestEncapsulateHybridValidation:
    """Verify encapsulate_hybrid() validates KEM callable outputs."""

    def setup_method(self) -> None:
        self.combiner = HybridCombiner(native_lib=None)
        self.pk_c = _random(32)
        self.pk_p = _random(1184)

    def _good_classical(self, pk: bytes) -> tuple[bytes, bytes]:
        return (_random(32), _random(32))

    def _good_pqc(self, pk: bytes) -> tuple[bytes, bytes]:
        return (_random(1568), _random(32))

    def test_classical_empty_ciphertext_rejected(self) -> None:
        with pytest.raises(ValueError, match="Classical ciphertext is empty"):
            self.combiner.encapsulate_hybrid(
                lambda pk: (b"", _random(32)),
                self._good_pqc,
                self.pk_c,
                self.pk_p,
            )

    def test_classical_empty_shared_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="Classical shared secret is empty"):
            self.combiner.encapsulate_hybrid(
                lambda pk: (_random(32), b""),
                self._good_pqc,
                self.pk_c,
                self.pk_p,
            )

    def test_pqc_empty_ciphertext_rejected(self) -> None:
        with pytest.raises(ValueError, match="PQC ciphertext is empty"):
            self.combiner.encapsulate_hybrid(
                self._good_classical,
                lambda pk: (b"", _random(32)),
                self.pk_c,
                self.pk_p,
            )

    def test_pqc_empty_shared_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="PQC shared secret is empty"):
            self.combiner.encapsulate_hybrid(
                self._good_classical,
                lambda pk: (_random(1568), b""),
                self.pk_c,
                self.pk_p,
            )

    def test_oversized_ciphertext_rejected(self) -> None:
        with pytest.raises(ValueError, match="ciphertext too large"):
            self.combiner.encapsulate_hybrid(
                lambda pk: (_random(_MAX_CT_BYTES + 1), _random(32)),
                self._good_pqc,
                self.pk_c,
                self.pk_p,
            )

    def test_oversized_shared_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="shared secret too large"):
            self.combiner.encapsulate_hybrid(
                lambda pk: (_random(32), _random(_MAX_SS_BYTES + 1)),
                self._good_pqc,
                self.pk_c,
                self.pk_p,
            )

    def test_non_bytes_return_rejected(self) -> None:
        with pytest.raises(TypeError, match=r"must return.*bytes"):
            self.combiner.encapsulate_hybrid(
                lambda pk: ("not_bytes", _random(32)),  # type: ignore[return-value]  # wrong type to verify TypeError rejection (PR224-001)
                self._good_pqc,
                self.pk_c,
                self.pk_p,
            )

    def test_boundary_max_ct_accepted(self) -> None:
        """Ciphertext at exactly _MAX_CT_BYTES passes validation
        (does not raise ValueError)."""
        mock_lib = MagicMock()
        mock_lib.ama_hkdf = MagicMock(return_value=0)
        combiner = HybridCombiner(native_lib=mock_lib)
        result = combiner.encapsulate_hybrid(
            lambda pk: (_random(_MAX_CT_BYTES), _random(32)),
            self._good_pqc,
            self.pk_c,
            self.pk_p,
        )
        assert isinstance(result.combined_secret, bytes)

    def test_boundary_max_ss_accepted(self) -> None:
        """Shared secret at exactly _MAX_SS_BYTES passes validation
        (does not raise ValueError)."""
        mock_lib = MagicMock()
        mock_lib.ama_hkdf = MagicMock(return_value=0)
        combiner = HybridCombiner(native_lib=mock_lib)
        result = combiner.encapsulate_hybrid(
            lambda pk: (_random(32), _random(_MAX_SS_BYTES)),
            self._good_pqc,
            self.pk_c,
            self.pk_p,
        )
        assert isinstance(result.combined_secret, bytes)


class TestDecapsulateHybridValidation:
    """Verify decapsulate_hybrid() validates KEM callable outputs."""

    def setup_method(self) -> None:
        self.combiner = HybridCombiner(native_lib=None)

    def test_classical_empty_shared_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="Classical shared secret is empty"):
            self.combiner.decapsulate_hybrid(
                lambda ct, sk: b"",
                lambda ct, sk: _random(32),
                _random(32),
                _random(1568),
                _random(32),
                _random(2400),
            )

    def test_pqc_empty_shared_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="PQC shared secret is empty"):
            self.combiner.decapsulate_hybrid(
                lambda ct, sk: _random(32),
                lambda ct, sk: b"",
                _random(32),
                _random(1568),
                _random(32),
                _random(2400),
            )

    def test_oversized_shared_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="shared secret too large"):
            self.combiner.decapsulate_hybrid(
                lambda ct, sk: _random(_MAX_SS_BYTES + 1),
                lambda ct, sk: _random(32),
                _random(32),
                _random(1568),
                _random(32),
                _random(2400),
            )

    def test_non_bytes_return_rejected(self) -> None:
        with pytest.raises(TypeError, match="must return bytes"):
            self.combiner.decapsulate_hybrid(
                lambda ct, sk: "not_bytes",  # type: ignore[return-value]  # wrong type to verify TypeError rejection (PR224-002)
                lambda ct, sk: _random(32),
                _random(32),
                _random(1568),
                _random(32),
                _random(2400),
            )


# ===========================================================================
# Task 7: INVARIANT-7 RuntimeError test (combine without native)
# ===========================================================================


class TestInvariant7RuntimeError:
    """Verify combine() raises RuntimeError, not a warning, when native
    HKDF is unavailable (INVARIANT-7 fix from PR #224)."""

    def test_raises_runtime_error_not_warning(self) -> None:
        combiner = HybridCombiner(native_lib=MagicMock(spec=[]))
        assert not combiner._has_native
        with pytest.raises(RuntimeError, match="INVARIANT-7"):
            combiner.combine(
                classical_ss=_random(32),
                pqc_ss=_random(32),
                classical_ct=_random(32),
                pqc_ct=_random(1568),
            )

    def test_error_message_mentions_native_build(self) -> None:
        combiner = HybridCombiner(native_lib=MagicMock(spec=[]))
        with pytest.raises(RuntimeError, match="cmake"):
            combiner.combine(
                classical_ss=_random(32),
                pqc_ss=_random(32),
                classical_ct=_random(32),
                pqc_ct=_random(1568),
            )


# ===========================================================================
# Task 7: Module-level constants are importable and correct
# ===========================================================================


class TestModuleLevelConstants:
    """Verify that promoted constants are importable and have expected values."""

    def test_max_ct_bytes(self) -> None:
        assert _MAX_CT_BYTES == 8192

    def test_max_ss_bytes(self) -> None:
        assert _MAX_SS_BYTES == 256

    def test_max_field_bytes(self) -> None:
        assert _MAX_FIELD_BYTES == 65536

    def test_constants_match_usage(self) -> None:
        """Constants in hybrid_combiner match the values used in validation."""
        combiner = HybridCombiner(native_lib=None)

        with pytest.raises(ValueError, match=str(_MAX_CT_BYTES)):
            combiner.encapsulate_hybrid(
                lambda pk: (_random(_MAX_CT_BYTES + 1), _random(32)),
                lambda pk: (_random(1568), _random(32)),
                _random(32),
                _random(1184),
            )
