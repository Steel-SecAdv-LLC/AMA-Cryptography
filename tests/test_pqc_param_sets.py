#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
FIPS 203 / FIPS 204 parameter-set coverage.
==========================================

AMA shipped ML-KEM-1024 and ML-DSA-65 only. Both C implementations are now
parameter-driven, and this module is the gate that every parameter set is
*selectable, usable and correct* rather than merely declared:

* every advertised set generates, encapsulates/signs, and round-trips;
* the sizes the Python layer advertises match the sizes the C library
  reports, so ``ML_KEM_SIZES`` cannot drift away from the C parameter block;
* the deterministic seed entry points reproduce the vendored NIST KATs
  byte-for-byte — the only evidence that distinguishes "a working scheme" from
  "the *right* scheme";
* the sets are mutually incompatible in the ways they must be (a signature
  from one set does not verify under another, a ciphertext from one set is
  rejected by another), which is what catches a parameter block that silently
  falls back to a neighbouring set;
* the legacy ``ama_kyber_*`` / ``ama_dilithium_*`` Python wrappers still mean
  exactly ML-KEM-1024 / ML-DSA-65.

The KAT files under ``tests/kat/`` are the authority; a missing one fails
rather than skips, because a silently-skipped conformance test is the same
thing as no conformance test.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.pqc_backends as pb  # noqa: E402 -- import follows the repo-root sys.path insert above (PQCPS-001)

KAT_KEM = REPO_ROOT / "tests" / "kat" / "fips203"
KAT_DSA = REPO_ROOT / "tests" / "kat" / "fips204"

pytestmark = pytest.mark.skipif(
    not (pb._ML_KEM_NATIVE_AVAILABLE and pb._ML_DSA_NATIVE_AVAILABLE),
    reason="native ML-KEM/ML-DSA backend not built",
)


# ---------------------------------------------------------------------------
# KAT parsing
# ---------------------------------------------------------------------------
def _parse_records(path: Path) -> list[dict[str, str]]:
    """Parse the repository's ``key = hexvalue`` KAT format into records.

    A blank line separates records. Values are kept as strings so a record can
    carry both hex fields and small integers (``mlen``, ``ctx_len``).
    """
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


# ---------------------------------------------------------------------------
# Size agreement between the Python table and the C parameter block
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_sizes_match_native(ps: int) -> None:
    """The mirrored size table must agree with the library's own answer."""
    lib = pb._native_lib
    assert lib is not None
    assert lib.ama_ml_kem_public_key_bytes(ps) == pb.ML_KEM_SIZES[ps]["public_key"]
    assert lib.ama_ml_kem_secret_key_bytes(ps) == pb.ML_KEM_SIZES[ps]["secret_key"]
    assert lib.ama_ml_kem_ciphertext_bytes(ps) == pb.ML_KEM_SIZES[ps]["ciphertext"]
    assert lib.ama_ml_kem_param_set_name(ps).decode() == f"ML-KEM-{ps}"


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_sizes_match_native(ps: int) -> None:
    lib = pb._native_lib
    assert lib is not None
    assert lib.ama_ml_dsa_public_key_bytes(ps) == pb.ML_DSA_SIZES[ps]["public_key"]
    assert lib.ama_ml_dsa_secret_key_bytes(ps) == pb.ML_DSA_SIZES[ps]["secret_key"]
    assert lib.ama_ml_dsa_signature_bytes(ps) == pb.ML_DSA_SIZES[ps]["signature"]
    assert lib.ama_ml_dsa_param_set_name(ps).decode() == f"ML-DSA-{ps}"


def test_unknown_parameter_sets_are_rejected() -> None:
    """An unrecognised set must raise, never silently pick a neighbour."""
    for bad in (0, 256, 1023, 45, 66, "ML-KEM-1023", "Kyber", True):
        with pytest.raises(ValueError):
            # Deliberately wrong type/value: this asserts the parameter-set
            # boundary check fires (PQCPS-002).
            pb._ml_kem_id(cast(Any, bad))
    for bad in (0, 43, 88, "ML-DSA-46", "Dilithium", True):
        with pytest.raises(ValueError):
            # Same (PQCPS-003).
            pb._ml_dsa_id(cast(Any, bad))


def test_parameter_set_aliases_resolve() -> None:
    assert pb._ml_kem_id("ML-KEM-768") == pb.ML_KEM_768
    assert pb._ml_kem_id("Kyber512") == pb.ML_KEM_512
    assert pb._ml_dsa_id("Dilithium5") == pb.ML_DSA_87
    assert pb._ml_dsa_id("ML-DSA-44") == pb.ML_DSA_44


# ---------------------------------------------------------------------------
# ML-KEM round trips
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_roundtrip(ps: int) -> None:
    pk, sk = pb.native_ml_kem_keypair(ps)
    sizes = pb.ML_KEM_SIZES[ps]
    assert len(pk) == sizes["public_key"]
    assert len(sk) == sizes["secret_key"]

    ct, ss_enc = pb.native_ml_kem_encapsulate(ps, pk)
    assert len(ct) == sizes["ciphertext"]
    assert len(ss_enc) == 32
    assert pb.native_ml_kem_decapsulate(ps, ct, sk) == ss_enc


@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_implicit_rejection(ps: int) -> None:
    """A tampered ciphertext yields a different secret, not an error.

    FIPS 203 mandates implicit rejection: surfacing "invalid ciphertext" is
    precisely the oracle IND-CCA2 security removes.
    """
    pk, sk = pb.native_ml_kem_keypair(ps)
    ct, ss_enc = pb.native_ml_kem_encapsulate(ps, pk)
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    ss_bad = pb.native_ml_kem_decapsulate(ps, bytes(tampered), sk)
    assert len(ss_bad) == 32
    assert ss_bad != ss_enc


@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_wrong_lengths_rejected(ps: int) -> None:
    pk, sk = pb.native_ml_kem_keypair(ps)
    ct, _ = pb.native_ml_kem_encapsulate(ps, pk)
    with pytest.raises(ValueError):
        pb.native_ml_kem_encapsulate(ps, pk[:-1])
    with pytest.raises(ValueError):
        pb.native_ml_kem_decapsulate(ps, ct[:-1], sk)
    with pytest.raises(ValueError):
        pb.native_ml_kem_decapsulate(ps, ct, sk[:-1])
    with pytest.raises(ValueError):
        pb.native_ml_kem_keypair_from_seed(ps, b"\x00" * 31, b"\x00" * 32)


def test_ml_kem_sets_are_mutually_incompatible() -> None:
    """A ciphertext from one set must not be accepted by another.

    This is the test that catches a parameter block whose length checks are
    wired to the wrong row: sizes differ between the sets, so a mis-wired
    implementation would silently accept and produce a garbage secret.
    """
    pk512, _ = pb.native_ml_kem_keypair(pb.ML_KEM_512)
    _, sk768 = pb.native_ml_kem_keypair(pb.ML_KEM_768)
    ct512, _ = pb.native_ml_kem_encapsulate(pb.ML_KEM_512, pk512)
    with pytest.raises(ValueError):
        pb.native_ml_kem_decapsulate(pb.ML_KEM_768, ct512, sk768)
    with pytest.raises(ValueError):
        pb.native_ml_kem_encapsulate(pb.ML_KEM_768, pk512)


# ---------------------------------------------------------------------------
# ML-DSA round trips
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_roundtrip(ps: int) -> None:
    pk, sk = pb.native_ml_dsa_keypair(ps)
    sizes = pb.ML_DSA_SIZES[ps]
    assert len(pk) == sizes["public_key"]
    assert len(sk) == sizes["secret_key"]

    msg = b"AMA Cryptography ML-DSA parameter set coverage"
    sig = pb.native_ml_dsa_sign(ps, msg, sk)
    assert len(sig) == sizes["signature"]
    assert pb.native_ml_dsa_verify(ps, msg, sig, pk)
    assert not pb.native_ml_dsa_verify(ps, msg + b"!", sig, pk)


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_is_deterministic(ps: int) -> None:
    """AMA signs with the FIPS 204 deterministic variant (rnd = 0^256)."""
    pk, sk = pb.native_ml_dsa_keypair(ps)
    msg = b"determinism"
    assert pb.native_ml_dsa_sign(ps, msg, sk) == pb.native_ml_dsa_sign(ps, msg, sk)
    assert pb.native_ml_dsa_verify(ps, msg, pb.native_ml_dsa_sign(ps, msg, sk), pk)


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_tampered_signature_rejected(ps: int) -> None:
    pk, sk = pb.native_ml_dsa_keypair(ps)
    msg = b"tamper"
    sig = bytearray(pb.native_ml_dsa_sign(ps, msg, sk))
    # Flip a bit inside the packed `z` region, past the commitment hash.
    sig[len(sig) // 2] ^= 0x01
    assert not pb.native_ml_dsa_verify(ps, msg, bytes(sig), pk)


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_context_is_domain_separating(ps: int) -> None:
    """The §5.2 context wrapper must actually separate domains.

    ``ctx=None`` (internal interface) and ``ctx=b""`` (external/pure with an
    empty context) are different domains and must produce different
    signatures — a wrapper applied inconsistently would make them equal.
    """
    pk, sk = pb.native_ml_dsa_keypair(ps)
    msg = b"context separation"

    sig_internal = pb.native_ml_dsa_sign(ps, msg, sk)
    sig_empty_ctx = pb.native_ml_dsa_sign(ps, msg, sk, ctx=b"")
    sig_ctx = pb.native_ml_dsa_sign(ps, msg, sk, ctx=b"ama")

    assert sig_internal != sig_empty_ctx
    assert sig_empty_ctx != sig_ctx

    assert pb.native_ml_dsa_verify(ps, msg, sig_internal, pk)
    assert pb.native_ml_dsa_verify(ps, msg, sig_empty_ctx, pk, ctx=b"")
    assert pb.native_ml_dsa_verify(ps, msg, sig_ctx, pk, ctx=b"ama")

    # Cross-domain verification must fail in every direction.
    assert not pb.native_ml_dsa_verify(ps, msg, sig_internal, pk, ctx=b"")
    assert not pb.native_ml_dsa_verify(ps, msg, sig_empty_ctx, pk)
    assert not pb.native_ml_dsa_verify(ps, msg, sig_ctx, pk, ctx=b"")


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_oversized_context_rejected(ps: int) -> None:
    _, sk = pb.native_ml_dsa_keypair(ps)
    with pytest.raises(ValueError):
        pb.native_ml_dsa_sign(ps, b"m", sk, ctx=b"\x00" * 256)


def test_ml_dsa_sets_are_mutually_incompatible() -> None:
    """A signature from one set must not verify under another."""
    pk44, sk44 = pb.native_ml_dsa_keypair(pb.ML_DSA_44)
    pk87, _ = pb.native_ml_dsa_keypair(pb.ML_DSA_87)
    sig44 = pb.native_ml_dsa_sign(pb.ML_DSA_44, b"m", sk44)
    assert not pb.native_ml_dsa_verify(pb.ML_DSA_87, b"m", sig44, pk87)
    assert not pb.native_ml_dsa_verify(pb.ML_DSA_65, b"m", sig44, pk44)


# ---------------------------------------------------------------------------
# Vendored NIST known-answer tests — the conformance evidence
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("ps", "filename"),
    [
        (pb.ML_KEM_512, "ml_kem_512.kat"),
        (pb.ML_KEM_768, "ml_kem_768.kat"),
    ],
)
def test_ml_kem_known_answer_vectors(ps: int, filename: str) -> None:
    """Deterministic keygen + decapsulation against the vendored corpus.

    ``result = invalid`` records are adversarial. There are two shapes:

    * a well-formed-length ciphertext that decapsulates to something other
      than the listed secret — FIPS 203 implicit rejection, which must NOT
      surface as an error;
    * a wrong-length ciphertext, which is a caller/protocol error rather than
      an attacker-chosen ciphertext and is rejected outright.

    Both count as "did not produce the listed secret", which is the property
    being asserted; conflating them would let a length check disappear.
    """
    path = KAT_KEM / filename
    assert path.is_file(), f"missing vendored KAT: {path}"
    records = _parse_records(path)
    assert records, f"empty KAT file: {path}"

    checked_pk = 0
    rejected_by_length = 0
    for rec in records:
        d = bytes.fromhex(rec["d"])
        z = bytes.fromhex(rec["z"])
        pk, sk = pb.native_ml_kem_keypair_from_seed(ps, d, z)
        if "pk" in rec:
            assert pk == bytes.fromhex(rec["pk"]), "ML-KEM keygen diverged from KAT"
            checked_pk += 1
        ct = bytes.fromhex(rec["ct"])
        expected = bytes.fromhex(rec["ss"])
        valid = rec.get("result", "valid") == "valid"
        try:
            ss = pb.native_ml_kem_decapsulate(ps, ct, sk)
        except ValueError:
            assert not valid, "ML-KEM rejected a well-formed KAT ciphertext"
            rejected_by_length += 1
            continue
        if valid:
            assert ss == expected, "ML-KEM decapsulation diverged from KAT"
        else:
            assert ss != expected, "ML-KEM accepted an adversarial ciphertext"

    assert checked_pk > 0, "no KAT record carried an expected public key"
    assert rejected_by_length > 0, (
        "the corpus no longer contains a wrong-length ciphertext — the length "
        "check is now untested"
    )


@pytest.mark.parametrize(
    ("ps", "filename"),
    [
        (pb.ML_DSA_44, "ml_dsa_44.kat"),
        (pb.ML_DSA_87, "ml_dsa_87.kat"),
    ],
)
def test_ml_dsa_known_answer_vectors(ps: int, filename: str) -> None:
    """Deterministic keygen and signing against the vendored ACVP corpus."""
    path = KAT_DSA / filename
    assert path.is_file(), f"missing vendored KAT: {path}"
    records = _parse_records(path)
    assert records, f"empty KAT file: {path}"

    keygen_checked = 0
    siggen_checked = 0
    for rec in records:
        if "seed" in rec:
            pk, sk = pb.native_ml_dsa_keypair_from_seed(ps, bytes.fromhex(rec["seed"]))
            assert pk == bytes.fromhex(rec["pkey"]), "ML-DSA keygen pk diverged from KAT"
            assert sk == bytes.fromhex(rec["skey"]), "ML-DSA keygen sk diverged from KAT"
            keygen_checked += 1
        elif "sig" in rec:
            sk = bytes.fromhex(rec["skey"])
            msg = bytes.fromhex(rec["msg"]) if rec["msg"] else b""
            ctx = bytes.fromhex(rec["ctx"]) if rec.get("ctx") else b""
            mode = rec["sigmode"]
            sig = pb.native_ml_dsa_sign(ps, msg, sk, ctx=None if mode == "internal" else ctx)
            assert sig == bytes.fromhex(rec["sig"]), f"ML-DSA {mode} signature diverged from KAT"
            siggen_checked += 1

    assert keygen_checked > 0 and siggen_checked > 0, "KAT file exercised nothing"


# ---------------------------------------------------------------------------
# The legacy surface must not have moved
# ---------------------------------------------------------------------------
def test_legacy_kyber_wrapper_is_ml_kem_1024() -> None:
    """``generate_kyber_keypair`` must still mean exactly ML-KEM-1024."""
    kp = pb.generate_kyber_keypair()
    sizes = pb.ML_KEM_SIZES[pb.ML_KEM_1024]
    assert len(kp.public_key) == sizes["public_key"]
    assert len(bytes(kp.secret_key)) == sizes["secret_key"]

    encap = pb.kyber_encapsulate(kp.public_key)
    assert len(encap.ciphertext) == sizes["ciphertext"]
    # The parameter-driven path must decapsulate what the legacy path produced.
    assert (
        pb.native_ml_kem_decapsulate(pb.ML_KEM_1024, encap.ciphertext, bytes(kp.secret_key))
        == encap.shared_secret
    )


def test_legacy_dilithium_wrapper_is_ml_dsa_65() -> None:
    """``dilithium_sign`` must still mean exactly ML-DSA-65."""
    kp = pb.generate_dilithium_keypair()
    sizes = pb.ML_DSA_SIZES[pb.ML_DSA_65]
    assert len(kp.public_key) == sizes["public_key"]

    msg = b"legacy surface"
    sig = pb.dilithium_sign(msg, bytes(kp.secret_key))
    assert len(sig) == sizes["signature"]
    # The parameter-driven verifier must accept the legacy signer's output.
    assert pb.native_ml_dsa_verify(pb.ML_DSA_65, msg, sig, kp.public_key)
    # ...and vice versa.
    assert pb.dilithium_verify(
        msg, pb.native_ml_dsa_sign(pb.ML_DSA_65, msg, bytes(kp.secret_key)), kp.public_key
    )


# ---------------------------------------------------------------------------
# Private-key consistency checking
# ---------------------------------------------------------------------------
# An expanded ML-DSA or ML-KEM private key is internally redundant, and a key
# whose fields disagree is one that signs nothing verifiable or silently derives
# the wrong shared secret. `ama_ml_{dsa,kem}_privkey_check` is what makes that
# visible; RFC 9881 §8.2 and draft-ietf-lamps-kyber-certificates §C.4.1 publish
# the negative vectors, and tests/test_key_formats.py replays them through the
# PKCS#8 importer. These tests pin the backend surface itself — both the verdict
# form and the derive form — so neither can quietly stop checking.


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_privkey_check_accepts_a_real_key(ps: int) -> None:
    public, secret = pb.native_ml_dsa_keypair(ps)
    assert pb.native_ml_dsa_privkey_check(ps, secret)
    assert pb.native_ml_dsa_pubkey_from_privkey(ps, secret) == public


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
@pytest.mark.parametrize("field", ["rho", "tr", "s1", "t0"])
def test_ml_dsa_privkey_check_rejects_a_mutated_field(ps: int, field: str) -> None:
    """Flipping one bit in any load-bearing field must be caught.

    ``sk = rho || K || tr || s1 || s2 || t0``. Mutating ``rho`` changes the
    matrix A and therefore both ``t0`` and ``tr``; mutating ``tr`` or ``t0``
    breaks the stored copy directly; mutating ``s1`` changes the key those
    vectors imply. ``K`` is deliberately absent — it is the signing seed and is
    unconstrained by the rest of the key, so a check that claimed to catch it
    would be claiming something false.
    """
    _, secret = pb.native_ml_dsa_keypair(ps)
    sizes = pb.ML_DSA_SIZES[ps]
    offsets = {"rho": 0, "tr": 64, "s1": 128, "t0": sizes["secret_key"] - 1}
    mutated = bytearray(secret)
    mutated[offsets[field]] ^= 0x01
    assert not pb.native_ml_dsa_privkey_check(
        ps, bytes(mutated)
    ), f"a one-bit change to {field} went undetected"
    with pytest.raises(ValueError, match="inconsistent"):
        pb.native_ml_dsa_pubkey_from_privkey(ps, bytes(mutated))


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_rejects_out_of_range_secret_coefficients(ps: int) -> None:
    """FIPS 204 Algorithm 25: s1/s2 coefficients outside [-eta, eta] are invalid.

    The packing is not surjective onto its bit width — eta = 2 stores three bits
    for a five-value range — so an all-ones s1 region decodes to coefficients
    the specification forbids. Accepting them would let a malformed key into the
    signer, where it produces signatures nothing verifies and drives the
    rejection loop off its calibrated bounds.
    """
    _, secret = pb.native_ml_dsa_keypair(ps)
    mutated = bytearray(secret)
    mutated[128:160] = b"\xff" * 32
    assert not pb.native_ml_dsa_privkey_check(ps, bytes(mutated))
    # The signer must refuse it too, not merely the importer.
    with pytest.raises(ValueError):
        pb.native_ml_dsa_sign(ps, b"m", bytes(mutated))


@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_privkey_check_accepts_a_real_key(ps: int) -> None:
    public, secret = pb.native_ml_kem_keypair(ps)
    assert pb.native_ml_kem_privkey_check(ps, secret)
    assert pb.native_ml_kem_pubkey_from_privkey(ps, secret) == public


@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
@pytest.mark.parametrize("field", ["dk_pke", "ek", "h_ek"])
def test_ml_kem_privkey_check_rejects_a_mutated_field(ps: int, field: str) -> None:
    """``dk = dk_PKE || ek || H(ek) || z``; three of the four are redundant.

    ``H(ek)`` is caught by recomputing the digest. ``dk_PKE`` leaves the digest
    correct and is caught only by the pairwise round trip — which is the whole
    reason both checks exist. ``ek`` breaks the digest. ``z`` is absent for the
    same reason ML-DSA's ``K`` is: it is the implicit-rejection secret and
    nothing else in the key constrains it.
    """
    _, secret = pb.native_ml_kem_keypair(ps)
    sizes = pb.ML_KEM_SIZES[ps]
    t_bytes = sizes["secret_key"] - sizes["public_key"] - 64
    offsets = {"dk_pke": 0, "ek": t_bytes, "h_ek": t_bytes + sizes["public_key"]}
    mutated = bytearray(secret)
    mutated[offsets[field]] ^= 0x01
    assert not pb.native_ml_kem_privkey_check(
        ps, bytes(mutated)
    ), f"a one-bit change to {field} went undetected"
    with pytest.raises(ValueError, match="inconsistent"):
        pb.native_ml_kem_pubkey_from_privkey(ps, bytes(mutated))


@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_implicit_rejection_hides_a_mismatched_key(ps: int) -> None:
    """Why the pairwise check is not optional.

    FIPS 203 Algorithm 18 line 8 makes decapsulation with a wrong key return a
    *derived* secret rather than an error, by design. So a mutated ``dk_PKE``
    raises nothing anywhere downstream — the two parties simply hold different
    secrets, and the failure surfaces as an unexplained protocol error much
    later. This asserts that silence, which is what makes the import-time check
    the only place it can be caught.
    """
    public, secret = pb.native_ml_kem_keypair(ps)
    ciphertext, shared = pb.native_ml_kem_encapsulate(ps, public)
    mutated = bytearray(secret)
    mutated[0] ^= 0x01
    other = pb.native_ml_kem_decapsulate(ps, ciphertext, bytes(mutated))
    assert other != shared, "the mutation had no effect at all"
    assert len(other) == len(shared), "decapsulation errored instead of failing silently"


@pytest.mark.parametrize("ps", pb.ML_DSA_PARAM_SETS)
def test_ml_dsa_privkey_check_rejects_a_wrong_length_key(ps: int) -> None:
    _, secret = pb.native_ml_dsa_keypair(ps)
    for bad in (secret[:-1], secret + b"\x00"):
        with pytest.raises(ValueError, match="must be"):
            pb.native_ml_dsa_privkey_check(ps, bad)


@pytest.mark.parametrize("ps", pb.ML_KEM_PARAM_SETS)
def test_ml_kem_privkey_check_rejects_a_wrong_length_key(ps: int) -> None:
    _, secret = pb.native_ml_kem_keypair(ps)
    for bad in (secret[:-1], secret + b"\x00"):
        with pytest.raises(ValueError, match="must be"):
            pb.native_ml_kem_privkey_check(ps, bad)
