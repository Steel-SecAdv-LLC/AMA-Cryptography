# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Every approved-mode SLH-DSA signing API is context-separated (INVARIANT-50).

WHY THESE TESTS EXIST

``sphincs_sign`` / ``sphincs_verify`` and the generic context API
(``ama_sign`` / ``ama_verify`` with ``AMA_ALG_SPHINCS_256F``) signed and
verified the RAW message with no ``0x00 || len(ctx) || ctx`` prefix — they
were FIPS 205 §9 ``slh_sign_internal`` / ``slh_verify_internal`` under public
names.  ``slhdsa_sign`` / ``slhdsa_verify`` sign the §10.2 wrapper under the
same key, so the two interfaces cross-verified.  Measured on this tree before
the fix, both directions held::

    slhdsa_sign(M, ctx=b"")         accepted by sphincs_verify(b"\\x00\\x00" + M)
    sphincs_sign(b"\\x00\\x01x" + M)  accepted by slhdsa_verify(M, ctx=b"x")

which made any component signing caller-influenced bytes through the legacy or
the generic API a signing oracle for FIPS 205 pure signatures on
attacker-chosen ``(ctx, M)`` pairs under that key.  Those two probes are
:meth:`TestCrossVerificationOracleClosed.test_probe_one` and
:meth:`~TestCrossVerificationOracleClosed.test_probe_two`, as negative
assertions.

The C-level counterpart, plus the NIST ACVP ``signatureInterface ==
"internal"`` vectors that can only be replayed through the §9 interface, is
``tests/c/test_slhdsa_context_separation.c``: the §9 functions are compiled
only under ``AMA_TESTING_MODE``, so the shared object this module loads does
not have them — which is itself pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import ama_cryptography.pqc_backends as pb
from ama_cryptography.pqc_backends import SphincsKeyPair

pytestmark = pytest.mark.skipif(
    not pb.SPHINCS_AVAILABLE, reason="SPHINCS+/SLH-DSA native backend not available"
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_C_TEST = _REPO_ROOT / "tests" / "c" / "test_slhdsa_context_separation.c"

#: The FIPS 205 §9 internal interface. §9 states these must not be exposed to
#: applications other than for testing, and while ``ama_slhdsa_sign_internal``
#: WAS exported it signed raw caller bytes under the same key the §10.2 API
#: uses.
_SECTION_9_SYMBOLS = ("ama_slhdsa_sign_internal", "ama_slhdsa_verify_internal")

_MESSAGE = b"transfer 1000 to mallory"


@pytest.fixture(scope="module")
def keypair() -> SphincsKeyPair:
    return pb.generate_sphincs_keypair()


class TestCrossVerificationOracleClosed:
    """The legacy and §10.2 interfaces must not accept each other's signatures."""

    def test_probe_one(self, keypair: SphincsKeyPair) -> None:
        """A ctx="" §10.2 signature is not a legacy signature over 0x00 0x00 || M."""
        sig = pb.slhdsa_sign(_MESSAGE, keypair.secret_key, b"", param_set="SHA2-256f")
        assert not pb.sphincs_verify(b"\x00\x00" + _MESSAGE, sig, keypair.public_key)

    def test_probe_two(self, keypair: SphincsKeyPair) -> None:
        """A legacy signature over a forged wrapper is not a ctx="x" signature over M."""
        sig = pb.sphincs_sign(b"\x00\x01x" + _MESSAGE, keypair.secret_key)
        assert not pb.slhdsa_verify(_MESSAGE, sig, keypair.public_key, b"x", param_set="SHA2-256f")

    def test_legacy_api_is_section_10_2_with_the_empty_context(
        self, keypair: SphincsKeyPair
    ) -> None:
        """sphincs_sign/verify ARE slhdsa_sign/verify with ctx=b"", both ways."""
        legacy = pb.sphincs_sign(_MESSAGE, keypair.secret_key)
        assert pb.slhdsa_verify(_MESSAGE, legacy, keypair.public_key, b"", param_set="SHA2-256f")
        wrapped = pb.slhdsa_sign(_MESSAGE, keypair.secret_key, b"", param_set="SHA2-256f")
        assert pb.sphincs_verify(_MESSAGE, wrapped, keypair.public_key)
        # ... and therefore also equal to verify_ctx with an empty context.
        assert pb.sphincs_verify_ctx(_MESSAGE, legacy, keypair.public_key, b"")

    def test_distinct_contexts_do_not_cross_verify(self, keypair: SphincsKeyPair) -> None:
        """The property the wrapper exists to provide, stated directly."""
        sig = pb.slhdsa_sign(_MESSAGE, keypair.secret_key, b"app-a", param_set="SHA2-256f")
        assert pb.slhdsa_verify(_MESSAGE, sig, keypair.public_key, b"app-a", param_set="SHA2-256f")
        assert not pb.slhdsa_verify(
            _MESSAGE, sig, keypair.public_key, b"app-b", param_set="SHA2-256f"
        )
        assert not pb.slhdsa_verify(_MESSAGE, sig, keypair.public_key, b"", param_set="SHA2-256f")
        assert not pb.sphincs_verify(_MESSAGE, sig, keypair.public_key)

    def test_generic_context_api_inherits_the_fix(self) -> None:
        """ama_sign/ama_verify with AMA_ALG_SPHINCS_256F go through the wrapper.

        This is the entry point a caller reaches with no algorithm-specific
        knowledge, and it was the same raw signer.  Driven here through
        ``crypto_api``, which is the Python face of ``ama_core.c``'s dispatch.
        """
        from ama_cryptography.crypto_api import AlgorithmType, AmaCryptography

        crypto = AmaCryptography(algorithm=AlgorithmType.SPHINCS_256F)
        kp = crypto.generate_keypair()
        sig = crypto.sign(_MESSAGE, kp.secret_key)
        assert crypto.verify(_MESSAGE, sig.signature, kp.public_key)
        # The bytes it signed carry the empty-context wrapper: the §10.2
        # verifier accepts them, and a raw reading of 0x00 0x00 || M does not.
        assert pb.slhdsa_verify(_MESSAGE, sig.signature, kp.public_key, b"", param_set="SHA2-256f")
        assert not pb.sphincs_verify(b"\x00\x00" + _MESSAGE, sig.signature, kp.public_key)


class TestSection9InterfaceIsNotShipped:
    """FIPS 205 §9: the internal functions must not be exposed to applications."""

    def test_not_bound_in_pqc_backends(self) -> None:
        """No Python wrapper reaches the §9 interface."""
        assert not hasattr(pb, "slhdsa_sign_internal")
        assert not hasattr(pb, "slhdsa_verify_internal")

    def test_not_exported_by_the_loaded_library(self) -> None:
        """Nor is the symbol resolvable in the shared object ctypes loaded.

        ``getattr`` on a ``CDLL`` performs the dlsym, so this is the real
        export check rather than a reading of the source.
        """
        lib = pb._native_lib
        assert lib is not None, "native library not loaded"
        for symbol in _SECTION_9_SYMBOLS:
            with pytest.raises(AttributeError):
                getattr(lib, symbol)

    def test_the_acvp_internal_vectors_did_not_vanish_with_it(self) -> None:
        """The ACVP internal-interface replay moved to C; it did not get deleted.

        ``tests/test_pqc_kat.py`` replayed the 14 SLH-DSA-SHA2-256f
        ``signatureInterface == "internal"`` sigVer vectors through
        ``sphincs_verify`` for as long as that shipped entry point WAS the §9
        verifier.  It is not any more, so the replay lives in the C suite,
        which links ``ama_cryptography_test``.  Dropping coverage is the
        cheapest way to make a conformance fix look clean, so the relocation
        is pinned rather than trusted.
        """
        assert _C_TEST.is_file(), f"{_C_TEST} is missing"
        source = _C_TEST.read_text(encoding="utf-8")
        assert "SLH-DSA-sigVer-FIPS205.json" in source
        assert "ama_slhdsa_verify_internal" in source
        # The non-vacuity floor in the C test must still name the full group.
        assert re.search(
            r"cases\s*<\s*14", source
        ), "the C replay no longer requires all 14 internal-interface vectors"
        cmake = (_REPO_ROOT / "tests" / "c" / "CMakeLists.txt").read_text(encoding="utf-8")
        assert (
            "test_slhdsa_context_separation" in cmake
        ), "the C context-separation test is not registered with CTest"


class TestEmptyMessageIsAMessage:
    """FIPS 205 is defined over M in B*, and the empty string is a member.

    ``slhdsa_sign`` / ``slhdsa_verify`` / ``slhdsa_sign_deterministic``
    rejected a NULL message pointer outright, so whether a zero-length message
    could be signed depended on whether the caller's allocator handed back a
    non-NULL pointer for a zero-byte request — a property of the caller's
    malloc, not of the specification.  The same functions already accepted
    ``ctx = NULL, ctx_len = 0`` as the empty context.
    """

    @pytest.mark.parametrize("param_set", ["SHAKE-128s", "SHA2-256f"])
    def test_sign_and_verify_empty_message(self, param_set: str) -> None:
        kp = pb.generate_slhdsa_keypair(param_set)
        sig = pb.slhdsa_sign(b"", kp.secret_key, b"", param_set=param_set)
        assert pb.slhdsa_verify(b"", sig, kp.public_key, b"", param_set=param_set)
        # It is a signature over the EMPTY message, not over anything else.
        assert not pb.slhdsa_verify(b"\x00", sig, kp.public_key, b"", param_set=param_set)

    @pytest.mark.parametrize("param_set", ["SHAKE-128s", "SHA2-256f"])
    def test_deterministic_sign_empty_message(self, param_set: str) -> None:
        kp = pb.generate_slhdsa_keypair(param_set)
        sig = pb.slhdsa_sign_deterministic(b"", kp.secret_key, b"", param_set=param_set)
        assert pb.slhdsa_verify(b"", sig, kp.public_key, b"", param_set=param_set)
        # Deterministic means deterministic, including here.
        again = pb.slhdsa_sign_deterministic(b"", kp.secret_key, b"", param_set=param_set)
        assert sig == again

    def test_legacy_api_empty_message(self, keypair: SphincsKeyPair) -> None:
        sig = pb.sphincs_sign(b"", keypair.secret_key)
        assert pb.sphincs_verify(b"", sig, keypair.public_key)
        assert pb.slhdsa_verify(b"", sig, keypair.public_key, b"", param_set="SHA2-256f")

    def test_empty_message_with_a_context(self) -> None:
        """Empty message, non-empty context — the wrapper is all there is."""
        kp = pb.generate_slhdsa_keypair("SHAKE-128s")
        sig = pb.slhdsa_sign(b"", kp.secret_key, b"ctx")
        assert pb.slhdsa_verify(b"", sig, kp.public_key, b"ctx")
        assert not pb.slhdsa_verify(b"", sig, kp.public_key, b"")


class TestSignAddrndIsSection10_2:
    """``slhdsa_sign_addrnd`` replaced ``slhdsa_sign_internal``: narrower, not equal."""

    def test_wrapper_is_applied(self) -> None:
        """It signs M' = 0x00 || len(ctx) || ctx || M, so it verifies under ctx."""
        kp = pb.generate_slhdsa_keypair("SHAKE-128s")
        addrnd = bytes(range(16))
        sig = pb.slhdsa_sign_addrnd(b"payload", kp.secret_key, addrnd, b"app")
        assert pb.slhdsa_verify(b"payload", sig, kp.public_key, b"app")
        assert not pb.slhdsa_verify(b"payload", sig, kp.public_key, b"")

    def test_is_deterministic_in_addrnd(self) -> None:
        kp = pb.generate_slhdsa_keypair("SHAKE-128s")
        addrnd = bytes(range(16))
        a = pb.slhdsa_sign_addrnd(b"payload", kp.secret_key, addrnd, b"app")
        b = pb.slhdsa_sign_addrnd(b"payload", kp.secret_key, addrnd, b"app")
        assert a == b

    def test_rejects_wrong_addrnd_length(self) -> None:
        kp = pb.generate_slhdsa_keypair("SHAKE-128s")
        with pytest.raises(ValueError):
            pb.slhdsa_sign_addrnd(b"payload", kp.secret_key, b"\x00" * 15, b"")

    def test_rejects_oversized_context(self) -> None:
        kp = pb.generate_slhdsa_keypair("SHAKE-128s")
        with pytest.raises(ValueError):
            pb.slhdsa_sign_addrnd(b"payload", kp.secret_key, bytes(16), b"\x00" * 256)
