# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
RFC 8554 Appendix F — the HSS/LMS answer key, and the verifier it now answers.

**AMA verifies HSS/LMS signatures and does not produce them.** That asymmetry
is a decision, and the last section of this module asserts both halves of it so
neither can drift: `ama_hss_verify` must work, and nothing in the package may
offer to sign.

Why only the verifier
---------------------
LMS is a *stateful* scheme, and RFC 8554 §5.4.1 puts the whole of its security
in the state: the one-time leaf index must be durably reserved **before** a
signature is released. A signer that loses that race can, after a crash, sign a
second message under the same LM-OTS key, and two signatures under one LM-OTS
key let an attacker forge a third. That is a total break, and it lives in a
durable state manager rather than in the arithmetic — so shipping the signing
maths with an unvalidated state manager would produce something that passes
every vector below, looks production-ready, and is catastrophically unsafe in
exactly the circumstance it exists to survive.

Verification has none of that. It holds no secret, keeps no state, and cannot
be made unsafe by being called twice. It is also the half with the
interoperability value: HSS/LMS is deployed overwhelmingly as a firmware and
software-update signature, where there is one offline signer and an enormous
verifier population.

What this module checks
-----------------------
1. The corpus is still the RFC's, structurally (this half predates the
   implementation and is unchanged — a vendored answer key has to be shown to
   be the right answer before it is used as one).
2. Both published test cases verify, end to end, through the native verifier.
3. Every field is load-bearing: message, public key, each level's signature,
   the embedded intermediate public key, and the Merkle path.
4. The single-tree verifier and the signature-length walker are exercised on
   their own, not only through the HSS path.
5. Structural refusal: truncation, trailing data, wrong level counts, unknown
   typecodes, an out-of-range leaf index.

Deliberately *only* what RFC 8554 publishes. SP 800-208's approved parameter
sets and its §6.2 derivation are not implemented: the published PDF did not
yield reliable text, and guessing an approved parameter set is exactly the
speculative standards work this repository refuses. That exclusion is
unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import ama_cryptography
import ama_cryptography.pqc_backends as backends

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "kat" / "keyformats" / "rfc8554_hss_lms.json"

DATA: dict[str, Any] = json.loads(CORPUS.read_text())
RECORDS: list[dict[str, Any]] = DATA["records"]

#: The verifier lives in the unconditional C source list, so it is present in
#: every configuration that has a native library at all. Skipping is therefore
#: only ever "no native build", never "this feature was compiled out".
requires_native = pytest.mark.skipif(
    not backends._LMS_NATIVE_AVAILABLE,
    reason="native HSS/LMS verifier not built",
)


def _record(case: int, kind: str) -> dict[str, Any]:
    return next(r for r in RECORDS if r["case"] == case and r["kind"] == kind)


def _octets(case: int, kind: str) -> bytes:
    return bytes.fromhex(_record(case, kind)["hex"])


# ---------------------------------------------------------------------------
# 1. The corpus is the RFC's
# ---------------------------------------------------------------------------
def test_the_corpus_carries_both_published_test_cases() -> None:
    """RFC 8554 Appendix F publishes two complete cases, each with a public key,
    a message and a signature. A partial extraction would look usable."""
    assert len(RECORDS) == 6, [f"{r['case']}/{r['kind']}" for r in RECORDS]
    for case in (1, 2):
        for kind in ("public_key", "message", "signature"):
            assert _record(case, kind)["hex"], f"case {case} {kind} is empty"


def test_the_source_is_the_rfc() -> None:
    assert "rfc-editor.org/rfc/rfc8554" in DATA["source"]["url"]
    assert DATA["source"]["revision"] == "RFC 8554, April 2019"


@pytest.mark.parametrize("case", [1, 2])
def test_the_public_key_has_the_size_the_structure_implies(case: int) -> None:
    """An HSS public key is ``u32 levels || LMS public key``, and an LMS public
    key is ``u32 type || u32 otstype || I[16] || K[32]``.

    Derived from the structure rather than copied from a claim: 4 + 4 + 4 + 16
    + 32 = 60. Both published cases use a two-level tree; the parameter sets
    differ between them and are read back separately below.
    """
    record = _record(case, "public_key")
    assert record["bytes"] == 4 + 4 + 4 + 16 + 32 == 60


def test_the_header_constants_match_the_structure() -> None:
    """The two lengths the C header publishes are the same two the corpus has.

    ``AMA_LMS_PUBKEY_LEN`` was 60 when it was first written — the HSS length,
    not the LMS one — and every arithmetic use of it was off by the four octets
    of ``L``. The corpus is what caught it, so the relationship is pinned here
    rather than left to a reader adding 24 and 32 in their head.
    """
    assert backends.AMA_LMS_PUBKEY_LEN == 24 + 32 == 56
    assert backends.AMA_HSS_PUBKEY_LEN == 4 + backends.AMA_LMS_PUBKEY_LEN == 60
    assert len(_octets(1, "public_key")) == backends.AMA_HSS_PUBKEY_LEN


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        # Case 1: HSS with Nspk = 1 over LM_SHA256_M32_H5 / LMOTS_SHA256_N32_W8.
        #   LMOTS sig = u32 type + C[32] + y[34][32]        = 4 + 32 + 1088 = 1124
        #   LMS sig   = u32 q + LMOTS sig + u32 type + path[5][32]
        #                                                    = 4 + 1124 + 4 + 160 = 1292
        #   LMS pub   = u32 type + u32 otstype + I[16] + K[32]              = 56
        #   HSS sig   = u32 Nspk + sig[0] + pub[1] + sig[1]
        #                                          = 4 + 1292 + 56 + 1292 = 2644
        (1, 2644),
        # Case 2: top-level LM_SHA256_M32_H10 / LMOTS_SHA256_N32_W4, second
        # level LM_SHA256_M32_H5 / LMOTS_SHA256_N32_W8.
        #   LMOTS sig (w=4, p=67) = 4 + 32 + 67*32                = 2180
        #   sig[0] (h=10)         = 4 + 2180 + 4 + 320            = 2508
        #   pub[1]                                                =   56
        #   sig[1] (h=5, w=8)     = as case 1                     = 1292
        #   HSS sig               = 4 + 2508 + 56 + 1292          = 3860
        (2, 3860),
    ],
)
def test_the_signature_has_the_size_its_parameter_sets_imply(case: int, expected: int) -> None:
    """The size is re-derived above from the parameter sets, not asserted from
    the extraction. That distinction caught a real extractor bug: the block for
    case 1's signature originally ran on into "Test Case 2 Private Key" and
    picked up two SEED/I pairs — 96 extra octets, producing a 2740-octet
    "signature" that decoded to nothing and looked entirely plausible.
    """
    assert _record(case, "signature")["bytes"] == expected


@pytest.mark.parametrize("record", RECORDS, ids=[f"case{r['case']}-{r['kind']}" for r in RECORDS])
def test_every_value_is_well_formed_hexadecimal(record: dict[str, Any]) -> None:
    value = record["hex"]
    assert len(value) % 2 == 0, "an odd-length hex string cannot be octets"
    decoded = bytes.fromhex(value)  # raises on any non-hex character
    assert len(decoded) == record["bytes"], "the recorded length disagrees with the value"


def test_the_messages_are_the_texts_the_rfc_prints() -> None:
    """Appendix F prints an ASCII gutter beside the message octets, so the
    plaintext is recoverable and is a free check on the extraction: if the
    gutter had been concatenated into the value, this would be gibberish.
    """
    first = _octets(1, "message").decode("ascii")
    assert first.startswith("The powers not delegated to the United States")
    second = _octets(2, "message").decode("ascii")
    assert second.startswith("The enumeration in the Constitution, of certain rights")


def test_the_first_signature_declares_one_signed_public_key() -> None:
    """A structural spot-check on the assembled bytes, independent of the sizes.

    RFC 8554 §6.4: an HSS signature begins with ``u32 Nspk``. Case 1 prints
    ``Nspk 00000001``, so the first four octets must be exactly that — which
    they can only be if the concatenation started in the right place.
    """
    signature = _octets(1, "signature")
    assert int.from_bytes(signature[:4], "big") == 1
    # …and the LMS signature that follows opens with q = 5, as the RFC prints.
    assert int.from_bytes(signature[4:8], "big") == 5


@pytest.mark.parametrize(
    ("case", "lms_type", "lmots_type"),
    [
        # RFC 8554 §4.1 / §5.1 registry values, as each case prints them.
        # Case 1: LM_SHA256_M32_H5 (5) with LMOTS_SHA256_N32_W8 (4).
        (1, 5, 4),
        # Case 2's top-level tree is taller and its Winternitz parameter
        # smaller: LM_SHA256_M32_H10 (6) with LMOTS_SHA256_N32_W4 (3). That is
        # why its signature is 3860 octets rather than 2644 — see the size
        # derivation above — and asserting 5/4 for both cases would have been
        # a transcription rather than a reading.
        (2, 6, 3),
    ],
)
def test_the_public_keys_declare_the_parameter_sets_the_rfc_names(
    case: int, lms_type: int, lmots_type: int
) -> None:
    """Registry values read back out of the assembled key.

    Reading the fields proves the offsets are right, not merely the total
    length — a concatenation that started one field late would still be 60
    octets.
    """
    key = _octets(case, "public_key")
    assert int.from_bytes(key[0:4], "big") == 2, "levels"
    assert int.from_bytes(key[4:8], "big") == lms_type
    assert int.from_bytes(key[8:12], "big") == lmots_type


# ---------------------------------------------------------------------------
# 2. The verifier answers the answer key
# ---------------------------------------------------------------------------
@requires_native
@pytest.mark.parametrize("case", [1, 2])
def test_the_published_signatures_verify(case: int) -> None:
    assert backends.native_hss_verify(
        _octets(case, "message"), _octets(case, "signature"), _octets(case, "public_key")
    )


@requires_native
@pytest.mark.parametrize(
    ("case", "lms_type", "lmots_type", "h", "w"),
    [(1, 5, 4, 5, 8), (2, 6, 3, 10, 4)],
)
def test_the_parameters_are_reported_from_the_key(
    case: int, lms_type: int, lmots_type: int, h: int, w: int
) -> None:
    """The introspection path and the registry tables agree with the key itself.

    ``h`` and ``w`` come from the C tables; ``lms_type`` and ``lmots_type`` come
    from the key's own octets. Cross-checking them is what makes a wrong table
    row visible — a table that mapped typecode 6 to h=5 would still verify
    nothing, but it would verify nothing *silently*.
    """
    pub = _octets(case, "public_key")
    assert backends.native_hss_pubkey_levels(pub) == 2
    params = backends.native_lms_pubkey_params(pub[4:])
    assert params == {"lms_type": lms_type, "lmots_type": lmots_type, "h": h, "w": w}
    assert backends.LMS_TREE_HEIGHT[lms_type] == h
    assert backends.LMOTS_WINTERNITZ_W[lmots_type] == w


# ---------------------------------------------------------------------------
# 3. Every field is load-bearing
# ---------------------------------------------------------------------------
@requires_native
@pytest.mark.parametrize("case", [1, 2])
def test_every_signature_region_is_checked(case: int) -> None:
    """A verifier that ignores a field is indistinguishable from one that reads
    it until you flip that field.

    The stride lands in every structural region of the two-level signature:
    ``Nspk``, level 0's LM-OTS randomiser and chains, level 0's Merkle path,
    the embedded level-1 public key, and level 1's chains and path.
    """
    msg = _octets(case, "message")
    sig = _octets(case, "signature")
    pub = _octets(case, "public_key")
    stride = max(1, len(sig) // 48)
    for offset in [*range(0, len(sig), stride), len(sig) - 1]:
        mutated = bytearray(sig)
        mutated[offset] ^= 0x01
        assert not backends.native_hss_verify(
            msg, bytes(mutated), pub
        ), f"case {case}: flipping signature octet {offset} was not detected"


@requires_native
@pytest.mark.parametrize("case", [1, 2])
def test_the_message_is_bound(case: int) -> None:
    msg = _octets(case, "message")
    sig = _octets(case, "signature")
    pub = _octets(case, "public_key")

    for offset in (0, len(msg) // 2, len(msg) - 1):
        mutated = bytearray(msg)
        mutated[offset] ^= 0x01
        assert not backends.native_hss_verify(bytes(mutated), sig, pub)

    # Truncation and extension are message changes too.
    assert not backends.native_hss_verify(msg[:-1], sig, pub)
    assert not backends.native_hss_verify(msg + b"\x00", sig, pub)
    assert not backends.native_hss_verify(b"", sig, pub)


@requires_native
@pytest.mark.parametrize("case", [1, 2])
def test_the_public_key_is_bound(case: int) -> None:
    """Both halves of the LMS public key matter: the 16-octet identifier ``I``
    is mixed into every hash, and the 32-octet root is what the walk lands on.
    Only checking the root would miss an ``I`` that is ignored."""
    msg = _octets(case, "message")
    sig = _octets(case, "signature")
    pub = _octets(case, "public_key")

    for offset in range(12, 28):  # I
        mutated = bytearray(pub)
        mutated[offset] ^= 0x01
        assert not backends.native_hss_verify(msg, sig, bytes(mutated))
    for offset in range(28, 60):  # T[1]
        mutated = bytearray(pub)
        mutated[offset] ^= 0x01
        assert not backends.native_hss_verify(msg, sig, bytes(mutated))


@requires_native
def test_the_two_cases_do_not_verify_under_each_others_keys() -> None:
    assert not backends.native_hss_verify(
        _octets(1, "message"), _octets(2, "signature"), _octets(1, "public_key")
    )
    assert not backends.native_hss_verify(
        _octets(2, "message"), _octets(1, "signature"), _octets(2, "public_key")
    )


# ---------------------------------------------------------------------------
# 4. The single-tree verifier and the length walker, on their own
# ---------------------------------------------------------------------------
@requires_native
@pytest.mark.parametrize(("case", "level0_len"), [(1, 1292), (2, 2508)])
def test_the_levels_verify_independently(case: int, level0_len: int) -> None:
    """Split the HSS signature with the public length walker and check each
    level against the key that signed it.

    This gives ``ama_lms_verify`` and ``ama_lms_signature_length`` a positive
    exercise that does not run through ``ama_hss_verify``, so a bug in the HSS
    walker cannot mask a bug in either of them.
    """
    msg = _octets(case, "message")
    sig = _octets(case, "signature")
    pub = _octets(case, "public_key")

    body = sig[4:]
    sig0_len = backends.native_lms_signature_length(body)
    assert sig0_len == level0_len

    sig0 = body[:sig0_len]
    pub1 = body[sig0_len : sig0_len + backends.AMA_LMS_PUBKEY_LEN]
    sig1 = body[sig0_len + backends.AMA_LMS_PUBKEY_LEN :]

    # Level 0 signs level 1's public key; level 1 signs the message.
    assert backends.native_lms_verify(pub1, sig0, pub[4:])
    assert backends.native_lms_verify(msg, sig1, pub1)
    assert backends.native_lms_signature_length(sig1) == len(sig1)

    # Cross-level substitution must fail in both directions.
    assert not backends.native_lms_verify(msg, sig1, pub[4:])
    assert not backends.native_lms_verify(pub1, sig1, pub1)


@requires_native
def test_the_length_walker_refuses_what_it_cannot_bound() -> None:
    sig = _octets(1, "signature")
    body = sig[4:]
    assert backends.native_lms_signature_length(b"") == 0
    assert backends.native_lms_signature_length(body[:7]) == 0
    # A buffer one octet short of a complete LMS signature is not a signature.
    assert backends.native_lms_signature_length(body[:1291]) == 0
    # An unknown LM-OTS typecode is refused rather than resolved.
    broken = bytearray(body)
    broken[7] = 0x63
    assert backends.native_lms_signature_length(bytes(broken)) == 0
    # …and so is an unknown LMS typecode. It sits after the LM-OTS block, whose
    # length the LM-OTS typecode itself decides: q(4) + otstype(4) + C||y
    # (n * (p + 1) = 32 * 35 = 1120) puts it at offset 1128.
    lms_type_offset = 4 + 4 + 32 * (34 + 1)
    assert lms_type_offset == 1128
    broken = bytearray(body)
    broken[lms_type_offset + 3] = 0x63
    assert backends.native_lms_signature_length(bytes(broken)) == 0


# ---------------------------------------------------------------------------
# 5. Structural refusal
# ---------------------------------------------------------------------------
@requires_native
@pytest.mark.parametrize("case", [1, 2])
def test_truncation_and_trailing_data_are_refused(case: int) -> None:
    """Trailing data matters for the same reason a non-minimal DER length does:
    two byte strings that both verify for one message is signature
    malleability, reachable by anyone who can hand you a signature."""
    msg = _octets(case, "message")
    sig = _octets(case, "signature")
    pub = _octets(case, "public_key")

    for cut in (0, 1, 3, 4, 8, 12, len(sig) // 2, len(sig) - 1):
        assert not backends.native_hss_verify(msg, sig[:cut], pub)
    assert not backends.native_hss_verify(msg, sig + b"\x00", pub)
    assert not backends.native_hss_verify(msg, sig + sig, pub)


@requires_native
def test_the_level_count_must_match_the_public_key() -> None:
    msg = _octets(1, "message")
    sig = _octets(1, "signature")
    pub = _octets(1, "public_key")

    for nspk in (0, 2, 7, 0xFFFFFFFF):
        mutated = bytearray(sig)
        mutated[0:4] = nspk.to_bytes(4, "big")
        assert not backends.native_hss_verify(msg, bytes(mutated), pub)


@requires_native
def test_an_out_of_range_leaf_index_is_refused() -> None:
    """RFC 8554 Algorithm 6a step 2i: ``q`` must address a leaf of *this* tree.

    Case 1's top tree is h=5, so ``q`` must be below 32. An implementation that
    computed ``2^h + q`` without the bound would walk a node number outside the
    tree and — for the right ``q`` — could land back on a valid-looking root.
    """
    msg = _octets(1, "message")
    sig = _octets(1, "signature")
    pub = _octets(1, "public_key")

    for q in (32, 33, 1 << 20, 0xFFFFFFFF):
        mutated = bytearray(sig)
        mutated[4:8] = q.to_bytes(4, "big")
        assert not backends.native_hss_verify(msg, bytes(mutated), pub)


@requires_native
def test_unknown_typecodes_are_refused_not_resolved() -> None:
    """INVARIANT-35: a selector must never resolve to a neighbour."""
    msg = _octets(1, "message")
    sig = _octets(1, "signature")
    pub = _octets(1, "public_key")

    # An unrecognised LMS or LM-OTS typecode in the public key is a malformed
    # key, not a failed signature — the distinction is what tells a caller
    # whether to fix their key file or reject the signer.
    for offset, value in ((7, 0x63), (11, 0x63), (7, 0x00), (11, 0x00)):
        mutated = bytearray(pub)
        mutated[offset] = value
        with pytest.raises(ValueError):
            backends.native_hss_verify(msg, sig, bytes(mutated))

    for levels in (0, backends.AMA_HSS_MAX_LEVELS + 1, 0xFF):
        mutated = bytearray(pub)
        mutated[3] = levels
        with pytest.raises(ValueError):
            backends.native_hss_verify(msg, sig, bytes(mutated))
        with pytest.raises(ValueError):
            backends.native_hss_pubkey_levels(bytes(mutated))


@requires_native
@pytest.mark.parametrize("length", [0, 1, 3, 4, 8, 55, 59, 61, 120])
def test_a_public_key_of_the_wrong_length_is_refused(length: int) -> None:
    pub = _octets(1, "public_key")
    padded = (pub + bytes(length))[:length]
    with pytest.raises(ValueError):
        backends.native_hss_verify(_octets(1, "message"), _octets(1, "signature"), padded)


# ---------------------------------------------------------------------------
# 6. The asymmetry itself
# ---------------------------------------------------------------------------
def test_ama_does_not_offer_to_sign_with_lms() -> None:
    """The decision, stated as a test so it cannot drift.

    Adding a signer means deleting this test, which means someone has to argue
    for it — and the argument has to include the durable state manager, because
    that is what the assertion is really guarding. See the module docstring.
    """
    assert not backends.lms_signing_available()

    # An exact inventory rather than a keyword filter. A substring rule reads
    # "signature_length" as a signing API and would have to be loosened until
    # it stopped catching anything; an inventory makes *any* new HSS/LMS name —
    # signing or not — fail until someone updates this list on purpose, which
    # is the review step the state-manager argument has to pass through.
    expected_surface = {
        "AMA_HSS_MAX_LEVELS",
        "AMA_HSS_PUBKEY_LEN",
        "AMA_LMOTS_SHA256_N32_W1",
        "AMA_LMOTS_SHA256_N32_W2",
        "AMA_LMOTS_SHA256_N32_W4",
        "AMA_LMOTS_SHA256_N32_W8",
        "AMA_LMS_PUBKEY_LEN",
        "AMA_LMS_SHA256_M32_H10",
        "AMA_LMS_SHA256_M32_H15",
        "AMA_LMS_SHA256_M32_H20",
        "AMA_LMS_SHA256_M32_H25",
        "AMA_LMS_SHA256_M32_H5",
        "LMOTS_WINTERNITZ_W",
        "LMS_TREE_HEIGHT",
        "LMS_NATIVE_AVAILABLE",
        "_LMS_NATIVE_AVAILABLE",
        "_lms_require_native",
        "_setup_lms_ctypes",
        "lms_signing_available",
        "native_hss_pubkey_levels",
        "native_hss_verify",
        "native_lms_pubkey_params",
        "native_lms_signature_length",
        "native_lms_verify",
    }
    actual = {
        name
        for name in dir(backends)
        if "lms" in name.lower() or "hss" in name.lower() or "lmots" in name.lower()
    }
    assert actual == expected_surface, (
        "the HSS/LMS surface changed; if this adds a signer, the durable state "
        "manager (RFC 8554 §5.4.1) has to come with it — see the module docstring. "
        f"added={sorted(actual - expected_surface)} removed={sorted(expected_surface - actual)}"
    )
    # Nothing on the package's own namespace offers HSS/LMS signing either.
    for attribute in dir(ama_cryptography):
        lowered = attribute.lower()
        if "lms" in lowered or "hss" in lowered:
            assert "sign" not in lowered.replace("signature", ""), attribute


def test_ama_does_not_claim_xmss() -> None:
    """XMSS (RFC 8391) is a different address scheme and a different checksum
    and shares no structure with LMS. Nothing here implements it, and no
    vectors for it are vendored, so nothing may claim it."""
    for attribute in dir(ama_cryptography):
        assert "xmss" not in attribute.lower(), attribute
    for attribute in dir(backends):
        assert "xmss" not in attribute.lower(), attribute
