# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-37 — the RFC 3161 API behaves the way it is named and documented.

``tools/check_verification_claim_honesty.py`` reads ``RFC3161_CAPABILITIES`` and
polices what the *documentation* may claim. Nothing in that arrangement stops
the table itself from being wrong — a table asserting ``tsa_signature: False``
while the code happily verified signatures would be harmless, but the reverse
would make every document in the repository quietly false again, with the gate
green throughout.

So this file drives the behaviour and asserts it matches the table. The
load-bearing test is
``test_a_token_with_a_nonsense_signature_still_satisfies_the_binding``: it
builds a token nobody signed, over attacker-chosen content, and requires the
binding check to accept it. That is an uncomfortable assertion to write down,
which is exactly why it belongs in the suite: it is the property that no
attestation claim removed under INVARIANT-37 could survive.

The rest pins the API shape the misreads were fixed by: the honest name, the
deprecated alias, the arguments that refuse, the record type that cannot be
collapsed into a truthy value, and the result key that announces itself.
"""

from __future__ import annotations

import hashlib
import warnings
from typing import Any

import pytest

from ama_cryptography._asn1 import (
    der_integer,
    der_null,
    der_octet_string,
    der_sequence,
    oid_from_string,
)
from ama_cryptography.rfc3161_timestamp import (
    RFC3161_CAPABILITIES,
    TimestampError,
    TimestampResult,
    TokenVerification,
    allow_mock_tsa,
    describe_token_verification,
    get_timestamp,
    verify_timestamp,
    verify_timestamp_binding,
    verify_token_binding,
)

DATA = b"the payload a token is supposed to be about"
SHA256_OID = "2.16.840.1.101.3.4.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"


# ---------------------------------------------------------------------------
# A token nobody signed, built entirely offline
# ---------------------------------------------------------------------------
def _der_set(*elements: bytes) -> bytes:
    body = b"".join(elements)
    if len(body) < 0x80:
        return bytes([0x31, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0x31, 0x80 | len(length)]) + length + body


def _signer_info() -> bytes:
    """Structurally complete, cryptographically meaningless.

    ``extract_tst_info`` refuses a ``SignedData`` whose ``signerInfos`` set is
    empty, so a forgery has to be well-formed. It does not have to be *signed*:
    the octets below are zeros.
    """
    return der_sequence(
        der_integer(1),
        der_sequence(der_sequence(), der_integer(1)),
        der_sequence(oid_from_string(SHA256_OID), der_null()),
        der_sequence(oid_from_string(OID_RSA_ENCRYPTION), der_null()),
        der_octet_string(b"\x00" * 32),
    )


def forge_token(data: bytes, gen_time: bytes = b"19700101000000Z") -> bytes:
    """A CMS ``SignedData`` over ``data`` with an arbitrary ``genTime``.

    No key is used anywhere in this function. That is the point.
    """
    tst_info = der_sequence(
        der_integer(1),
        oid_from_string("1.2.3.4.5"),
        der_sequence(
            der_sequence(oid_from_string(SHA256_OID), der_null()),
            der_octet_string(hashlib.sha256(data).digest()),
        ),
        der_integer(42),
        b"\x18" + bytes([len(gen_time)]) + gen_time,
    )
    signed_data = der_sequence(
        der_integer(3),
        _der_set(der_sequence(oid_from_string(SHA256_OID), der_null())),
        der_sequence(
            oid_from_string("1.2.840.113549.1.9.16.1.4"),
            b"\xa0" + bytes([len(der_octet_string(tst_info))]) + der_octet_string(tst_info),
        ),
        _der_set(_signer_info()),
    )
    return der_sequence(
        oid_from_string("1.2.840.113549.1.7.2"),
        (
            b"\xa0" + bytes([len(signed_data)]) + signed_data
            if len(signed_data) < 0x80
            else b"\xa0"
            + bytes([0x80 | (len(signed_data).bit_length() + 7) // 8])
            + len(signed_data).to_bytes((len(signed_data).bit_length() + 7) // 8, "big")
            + signed_data
        ),
    )


# ---------------------------------------------------------------------------
# The capability table tells the truth about the code
# ---------------------------------------------------------------------------
def test_a_token_with_a_nonsense_signature_still_satisfies_the_binding() -> None:
    """``tsa_signature: False`` is honest, demonstrated rather than asserted.

    The token below was built in this process, by this test, with no key and no
    TSA. Its signature octets are zeros and its ``genTime`` is the epoch. The
    binding check accepts it, because the binding is all it checks.

    Everything the documentation now says about RFC 3161 follows from this one
    fact, and every claim removed from the repository was contradicted by it.
    """
    token = forge_token(DATA)
    assert verify_token_binding(DATA, token) is True
    assert RFC3161_CAPABILITIES["tsa_signature"] is False
    assert RFC3161_CAPABILITIES["gen_time"] is False


def test_the_binding_still_discriminates_between_payloads() -> None:
    """The check is weak about issuers, not weak in general.

    Without this, the test above could be satisfied by a binding check that
    accepted everything — which would be a different and much worse defect.
    """
    token = forge_token(DATA)
    assert verify_token_binding(b"a different payload", token) is False


def test_capability_names_are_the_ones_the_record_reports() -> None:
    record = describe_token_verification(DATA, forge_token(DATA))
    withheld = {name for name, performed in RFC3161_CAPABILITIES.items() if not performed}
    assert record.not_verified == withheld
    assert record.not_verified == {"tsa_signature", "tsa_certificate_chain", "gen_time"}


def test_the_capability_table_is_immutable() -> None:
    """A mutable table would let a caller silence the gate's premise at runtime."""
    with pytest.raises(TypeError):
        RFC3161_CAPABILITIES["tsa_signature"] = True  # type: ignore[index]  # deliberately writing to a read-only mapping — this test asserts the immutability holds at runtime (RFC-001)


# ---------------------------------------------------------------------------
# TokenVerification cannot be collapsed into a truthy value
# ---------------------------------------------------------------------------
def test_token_verification_has_no_truth_value() -> None:
    """``if record:`` on a dataclass is always True — so it must raise instead.

    This is the fail-open failure a naive "return a rich object" fix would have
    introduced across every existing ``if verify...(...)`` call site.
    """
    record = describe_token_verification(DATA, forge_token(DATA))
    with pytest.raises(TypeError, match="no truth value"):
        bool(record)
    with pytest.raises(TypeError, match="no truth value"):
        if record:  # pragma: no branch
            pass


def test_token_verification_reports_the_binding_it_was_given() -> None:
    assert describe_token_verification(DATA, forge_token(DATA)).binding_verified is True
    assert describe_token_verification(b"other", forge_token(DATA)).binding_verified is False


def test_token_verification_never_claims_signature_or_chain() -> None:
    record = TokenVerification(binding_verified=True)
    assert record.signature_verified is False
    assert record.chain_verified is False


def test_describe_and_verify_agree() -> None:
    for payload in (DATA, b"other"):
        token = forge_token(DATA)
        assert describe_token_verification(payload, token).binding_verified is verify_token_binding(
            payload, token
        )


# ---------------------------------------------------------------------------
# The honest name, and the deprecated alias
# ---------------------------------------------------------------------------
def _mock_result(data: bytes) -> TimestampResult:
    with allow_mock_tsa():
        return get_timestamp(data, tsa_mode="mock")


def test_verify_timestamp_binding_takes_no_certificate_file() -> None:
    """An argument whose only behaviour is to raise does not belong in the signature."""
    import inspect

    assert "certificate_file" not in inspect.signature(verify_timestamp_binding).parameters


def test_verify_timestamp_is_deprecated_and_says_why() -> None:
    result = _mock_result(DATA)
    with allow_mock_tsa():
        with pytest.warns(DeprecationWarning, match="verify_timestamp_binding"):
            verify_timestamp(DATA, result)


def test_the_deprecated_alias_returns_what_the_new_name_returns() -> None:
    """A rename, not a behaviour change: ``if verify_timestamp(...)`` still means it."""
    result = _mock_result(DATA)
    with allow_mock_tsa():
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert verify_timestamp(DATA, result) is verify_timestamp_binding(DATA, result)
            assert verify_timestamp(b"other", result) is verify_timestamp_binding(b"other", result)


def test_verify_timestamp_binding_is_quiet() -> None:
    result = _mock_result(DATA)
    with allow_mock_tsa():
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            verify_timestamp_binding(DATA, result)
    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]


# ---------------------------------------------------------------------------
# Arguments that request unimplemented checks refuse, everywhere
# ---------------------------------------------------------------------------
def test_get_timestamp_refuses_certificate_file() -> None:
    with pytest.raises(TimestampError, match="certificate_file"):
        get_timestamp(DATA, certificate_file="tsa.pem", tsa_mode="online")


def test_verify_timestamp_refuses_certificate_file() -> None:
    result = _mock_result(DATA)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(TimestampError, match="certificate_file"):
            verify_timestamp(DATA, result, certificate_file="tsa.pem")


def test_legacy_verify_refuses_tsa_cert_path() -> None:
    from ama_cryptography.legacy_compat import verify_rfc3161_timestamp

    with pytest.raises(RuntimeError, match="tsa_cert_path"):
        verify_rfc3161_timestamp(DATA, forge_token(DATA), tsa_cert_path="tsa.pem")


def test_legacy_verify_without_the_argument_answers_the_binding() -> None:
    """Refusing the stronger question must not break the weaker one."""
    from ama_cryptography.legacy_compat import verify_rfc3161_timestamp

    assert verify_rfc3161_timestamp(DATA, forge_token(DATA)) is True
    assert verify_rfc3161_timestamp(b"other", forge_token(DATA)) is False


# ---------------------------------------------------------------------------
# The result key that announces itself
# ---------------------------------------------------------------------------
def test_reading_the_legacy_result_key_warns_and_the_correct_one_does_not() -> None:
    from ama_cryptography.legacy_compat import _VerificationResults

    results: Any = _VerificationResults({"rfc3161_binding": True, "rfc3161": True})

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert results["rfc3161_binding"] is True
        assert results.get("rfc3161_binding") is True
    assert not caught, "the correctly-named key must be silent"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert results["rfc3161"] is True  # deprecated alias, read on purpose
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert results.get("rfc3161") is True  # deprecated alias, read on purpose
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_the_results_mapping_is_still_a_dict() -> None:
    """Nothing about a verification routine should start failing over a rename."""
    from ama_cryptography.legacy_compat import _VerificationResults

    results = _VerificationResults({"rfc3161_binding": True, "rfc3161": True, "hmac": False})
    assert isinstance(results, dict)
    assert dict(results) == {"rfc3161_binding": True, "rfc3161": True, "hmac": False}
    assert results.get("absent", "default") == "default"
    assert "rfc3161" in results  # membership yields no verdict, so it is quiet
    assert sorted(results) == ["hmac", "rfc3161", "rfc3161_binding"]
