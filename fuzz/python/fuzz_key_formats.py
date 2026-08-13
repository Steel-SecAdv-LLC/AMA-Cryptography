#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Hostile-input fuzz harness for the DER / CBOR / JSON / PEM key parsers.

Why a harness and not just the pytest sweep
-------------------------------------------
``ama_cryptography/_asn1.py`` and ``ama_cryptography/key_formats.py`` are
hostile-input parsers by definition: anyone who can hand you a key file reaches
them. Fifteen C harnesses are registered under INVARIANT-33 for exactly this
reason, and these parsers had no equivalent — only a deterministic mutation
sweep inside ``tests/test_key_formats.py``.

That sweep is valuable and it is not fuzzing. It runs a fixed 120 mutations per
algorithm from one seed, so it explores the same neighbourhood on every run for
ever. A fuzzer runs for a time budget, keeps what it learns, and is *given*
structure-aware mutations aimed at the fields that decide control flow — ASN.1
tags, length octets, CBOR major types. The two find different things, so this
does not replace the sweep and the sweep does not replace this.

The contract this asserts
-------------------------
Narrow and total, and the same one the pytest sweep asserts, so a finding here
reproduces there:

1. For *any* input, every parser either returns a key or raises
   ``KeyFormatError`` / ``UnsupportedKeyFormatError``. Anything else — an
   ``IndexError`` off the end of a truncated buffer, a ``ValueError`` leaked
   from the native point decoder, a ``UnicodeDecodeError``, a ``RecursionError``
   from nested structure — is a finding. Leaking a raw ``ValueError`` from the
   native decoder was a real defect found this way.
2. Every accepted input is **canonical**: re-encoding the key reproduces the
   input byte for byte. Two byte strings that decode to one key is the same
   defect class as signature malleability, and it is what strict DER, minimal
   INTEGERs and deterministic CBOR exist to prevent.
3. No parser may hang. Inputs are bounded and a per-input wall-clock ceiling is
   enforced, so a quadratic blowup on a crafted length field is a finding rather
   than a timeout nobody attributes.

Engine
------
Self-contained by default: AMA's own generator and mutator, seeded from a fixed
value so a finding reproduces from its printed seed alone. Coverage guidance is
*optional* — ``--atheris`` hands the same entry point to Atheris when it is
installed — so the CI gate never depends on a third-party fuzzing engine being
available, and the harness is AMA's own work either way.

Usage::

    python3 fuzz/python/fuzz_key_formats.py                   # 60s, default seed
    python3 fuzz/python/fuzz_key_formats.py --seconds 300
    python3 fuzz/python/fuzz_key_formats.py --seed 12345      # reproduce
    python3 fuzz/python/fuzz_key_formats.py --input crash.bin # replay one file
    python3 fuzz/python/fuzz_key_formats.py --atheris         # if installed

Exits non-zero on the first contract violation, after writing the offending
input to ``--artifact-dir`` so CI can upload it.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import random
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ama_cryptography.key_formats as kf  # noqa: E402 -- follows the sys.path insert above
import ama_cryptography.pqc_backends as pb  # noqa: E402 -- same
from ama_cryptography._asn1 import (  # noqa: E402 -- same
    cbor_decode_canonical,
    cbor_encode_canonical,
)
from ama_cryptography.exceptions import (  # noqa: E402 -- same
    KeyFormatError,
    UnsupportedKeyFormatError,
)

#: The only exceptions a parser is allowed to raise. Everything else escapes to
#: a caller who cannot reasonably catch it, which is the finding.
ALLOWED = (KeyFormatError, UnsupportedKeyFormatError)

#: Ceiling on one parse. Generous — an ML-DSA-87 expandedKey import does a full
#: matrix expansion — but far below any plausible algorithmic blowup.
MAX_SECONDS_PER_INPUT = 5.0

#: Inputs are capped so the fuzzer spends its budget on structure rather than on
#: length. The largest legitimate input is an ML-DSA-87 PKCS#8 at ~4.9 kB.
MAX_INPUT_BYTES = 16384


class FindingError(Exception):
    """A contract violation, carrying the input that produced it."""

    def __init__(self, message: str, data: bytes, target: str) -> None:
        super().__init__(message)
        self.data = data
        self.target = target


# ---------------------------------------------------------------------------
# Targets — one per parser entry point
# ---------------------------------------------------------------------------
def _check_canonical(key: Any, data: bytes, encode: Callable[[Any], bytes], target: str) -> None:
    """An accepted input must be the only encoding of the key it decoded to."""
    try:
        reencoded = encode(key)
    except ALLOWED:
        # Re-encoding a key the parser just accepted must not fail. If it does,
        # the parser accepted something its own encoder cannot express.
        raise FindingError(
            f"{target}: accepted an input whose key cannot be re-encoded", data, target
        ) from None
    if reencoded != data:
        raise FindingError(
            f"{target}: accepted a non-canonical encoding — the key re-encodes to "
            f"{len(reencoded)} bytes that differ from the {len(data)} accepted",
            data,
            target,
        )


#: ``_as_der`` accepts a PEM *string* handed in as bytes, which is a documented
#: convenience (a caller who read a key file in binary mode gets the same
#: answer). So the canonical form of such an input is the PEM, not the DER, and
#: the check has to know which one it was given.
PEM_PREFIX = b"-----"


def target_spki(data: bytes) -> None:
    key = kf.load_spki(data)
    if data.startswith(PEM_PREFIX):
        if key.to_pem().encode().strip() != data.strip():
            raise FindingError("load_spki: accepted a non-canonical PEM", data, "load_spki")
        return
    _check_canonical(key, data, lambda k: k.to_spki(), "load_spki")


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """``(tag, value_offset, value_length)`` for the TLV at ``offset``.

    A minimal walker, deliberately separate from ``ama_cryptography._asn1``: a
    harness that used the parser under test to decide what the parser under test
    should have done would prove nothing.
    """
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        return tag, offset + 2, first
    count = first & 0x7F
    length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
    return tag, offset + 2 + count, length


def _strip_pkcs8_attributes(data: bytes) -> bytes:
    """Remove the ``[0] attributes`` element, re-encoding the outer SEQUENCE.

    ``OneAsymmetricKey``'s attributes are the one field this module accepts and
    does not re-emit, and that is documented ("parsed and discarded ... not
    re-emitted"): RFC 8410 §10.3's second example carries a "Curdle Chairs"
    friendly name, and refusing it would refuse a specification vector.

    So the canonicality property below is stated *modulo exactly that field* —
    which makes "attributes are the only thing we drop" a tested guarantee
    rather than a sentence in a docstring. Returns the input unchanged when
    there are no attributes.
    """
    tag, outer_off, outer_len = _tlv(data, 0)
    pos = outer_off
    kept = bytearray()
    found = False
    while pos < outer_off + outer_len:
        child_tag, value_off, value_len = _tlv(data, pos)
        end = value_off + value_len
        if child_tag == 0xA0:
            found = True
        else:
            kept.extend(data[pos:end])
        pos = end
    if not found:
        return data
    length = len(kept)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        body = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(body)]) + body
    return header + bytes(kept)


def target_pkcs8(data: bytes) -> None:
    """PKCS#8, where canonicality has to be stated against the *option space*.

    ``load_pkcs8`` does not record which options the file used, and the encoder
    legitimately emits several distinct forms for one key: with or without the
    public half, and — for ML-DSA/ML-KEM — in any of the three RFC 9881 §6
    ``CHOICE`` arms. So the property is not "re-encodes to itself under the
    default options", which a file carrying a public key fails for a good
    reason. It is the stronger and more useful statement:

        **the parser accepts nothing its own encoder cannot emit.**

    Every accepted input must be *one of* the encoder's outputs for the key it
    decoded to. That is what refuses a non-minimal length, a redundant
    ``[0] parameters``, a v2 version with no ``publicKey``, or a re-ordered
    field — each of which would otherwise give one key a second encoding.
    """
    key = kf.load_pkcs8(data)
    if data.startswith(PEM_PREFIX):
        # PEM handed in as bytes — canonical form is the PEM (see PEM_PREFIX).
        # The DER inside it is checked when the same bytes reach this target
        # through the pem_private path.
        return

    forms: list[bytes] = []
    alg = kf.ALGORITHMS[key.algorithm]
    arms = ("expandedKey", "both", "seed") if alg.kind == "pq" else ("auto",)
    for include in (False, True):
        for arm in arms:
            try:
                forms.append(key.to_pkcs8(include_public_key=include, pq_format=arm))
            except ALLOWED:
                continue  # e.g. a seed arm asked for on a key with no seed
    if not forms:
        raise FindingError(
            "load_pkcs8: accepted an input whose key cannot be re-encoded at all",
            data,
            "load_pkcs8",
        )
    try:
        candidate = _strip_pkcs8_attributes(data)
    except (IndexError, ValueError):
        candidate = data
    if candidate not in forms:
        raise FindingError(
            "load_pkcs8: accepted an encoding its own encoder never emits — "
            f"{len(data)} bytes accepted, none of the {len(forms)} legitimate "
            f"forms ({sorted({len(f) for f in forms})} bytes) match it, even "
            "after removing the [0] attributes this module documents as dropped",
            data,
            "load_pkcs8",
        )
    # And the accepted bytes must survive a second pass unchanged.
    if kf.load_pkcs8(data).key != key.key:
        raise FindingError("load_pkcs8: not idempotent", data, "load_pkcs8")


def target_pem_public(data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    key = kf.load_spki(text)
    if key.to_pem().encode() != data:
        # PEM carries a trailing newline the input may lack; compare normalised.
        if key.to_pem().strip().encode() != data.strip():
            raise FindingError("load_spki(PEM): non-canonical PEM accepted", data, "pem")


def target_pem_private(data: bytes) -> None:
    kf.load_pkcs8(data.decode("utf-8", "replace"))


#: The COSE_Key labels this module emits: kty(1), crv(-1), x(-2), y(-3), d(-4).
#: A COSE_Key is an *open map* — RFC 9052 §7 — and real keys carry `kid` (2) and
#: `alg` (3); a WebAuthn credential public key always carries `alg`. Rejecting
#: them would refuse most of the keys this format exists to read, so they are
#: accepted and not re-emitted. That makes them the COSE analogue of PKCS#8's
#: attributes, and the canonicality property below is stated modulo exactly
#: this set — so "unconsumed labels are the only thing we drop" is tested.
_COSE_EMITTED_LABELS = frozenset({1, -1, -2, -3, -4})


def target_cose_public(data: bytes) -> None:
    key = kf.cose_to_public_key(data)
    decoded = cbor_decode_canonical(data)
    consumed = {k: v for k, v in decoded.items() if k in _COSE_EMITTED_LABELS}
    if cbor_encode_canonical(consumed) != key.to_cose():
        raise FindingError(
            "cose_to_public_key: the labels the encoder emits do not round-trip — "
            "something other than an unconsumed label differs",
            data,
            "cose_to_public_key",
        )


def target_cose_private(data: bytes) -> None:
    kf.cose_to_private_key(data)


def target_cbor(data: bytes) -> None:
    """The CBOR layer on its own — the deterministic-encoding rule of
    RFC 8949 §4.2.1 is what makes a COSE_Key have exactly one encoding."""
    obj = cbor_decode_canonical(data)
    if cbor_encode_canonical(obj) != data:
        raise FindingError(
            "cbor_decode_canonical accepted a non-deterministic encoding", data, "cbor"
        )


def target_jwk_public(data: bytes) -> None:
    kf.jwk_to_public_key(data.decode("utf-8", "replace"))


def target_jwk_private(data: bytes) -> None:
    kf.jwk_to_private_key(data.decode("utf-8", "replace"))


def target_thumbprint(data: bytes) -> None:
    kf.jwk_thumbprint(data.decode("utf-8", "replace"))


TARGETS: dict[str, Callable[[bytes], None]] = {
    "spki": target_spki,
    "pkcs8": target_pkcs8,
    "pem_public": target_pem_public,
    "pem_private": target_pem_private,
    "cose_public": target_cose_public,
    "cose_private": target_cose_private,
    "cbor": target_cbor,
    "jwk_public": target_jwk_public,
    "jwk_private": target_jwk_private,
    "thumbprint": target_thumbprint,
}


def run_one(target: str, data: bytes) -> None:
    """Drive one target and enforce the contract. Raises ``FindingError`` on failure."""
    started = time.monotonic()
    try:
        TARGETS[target](data)
    except FindingError:
        raise
    except ALLOWED:
        # The contract's success case, and the reason this is not a bug: a
        # parser handed hostile input is *supposed* to reject it with
        # KeyFormatError or UnsupportedKeyFormatError. Those two are the whole
        # permitted vocabulary, so catching them and moving on is the harness
        # observing correct behaviour, not swallowing an error. Every other
        # exception type falls through to the clauses below and becomes a
        # finding.
        pass
    except RecursionError as exc:
        raise FindingError(
            f"{target}: recursion limit reached ({exc}) — a nested structure drove "
            "the parser off the stack rather than being refused",
            data,
            target,
        ) from None
    except Exception as exc:  # classifying *any* escape is the point
        raise FindingError(
            f"{target}: raised {type(exc).__name__} instead of KeyFormatError: {exc}",
            data,
            target,
        ) from None
    elapsed = time.monotonic() - started
    if elapsed > MAX_SECONDS_PER_INPUT:
        raise FindingError(
            f"{target}: took {elapsed:.1f}s on a {len(data)}-byte input, over the "
            f"{MAX_SECONDS_PER_INPUT}s ceiling",
            data,
            target,
        )


# ---------------------------------------------------------------------------
# Seed corpus
# ---------------------------------------------------------------------------
def _generated_keys() -> list[tuple[str, bytes]]:
    """A valid encoding of every algorithm in every format this module emits.

    Starting a fuzzer from an empty corpus means it spends its whole budget
    rediscovering that a key file begins with 0x30 — the same defect the C fuzz
    lane had before its seed corpora were wired up.
    """
    seeds: list[tuple[str, bytes]] = []
    for name, alg in kf.ALGORITHMS.items():
        if alg.kind == "okp":
            if name == "Ed25519":
                public, secret = pb.native_ed25519_keypair()
                secret = secret[:32]
            else:
                public, secret = pb.native_x25519_keypair()
        elif name == "secp256k1":
            import os

            secret = os.urandom(32)
            public = pb.native_secp256k1_pubkey_decompress(
                pb.native_secp256k1_pubkey_from_privkey(secret)
            )
        elif alg.kind == "ec":
            public, secret = pb.native_nistp_keypair(alg.ec_curve)
        elif alg.pq_family == "ml-dsa":
            public, secret = pb.native_ml_dsa_keypair(alg.pq_set)
        else:
            public, secret = pb.native_ml_kem_keypair(alg.pq_set)

        pub = kf.PublicKey(name, public)
        priv = kf.PrivateKey(name, secret, public)
        seeds.append(("spki", pub.to_spki()))
        seeds.append(("pem_public", pub.to_pem().encode()))
        seeds.append(("pkcs8", priv.to_pkcs8()))
        seeds.append(("pkcs8", priv.to_pkcs8(include_public_key=True)))
        seeds.append(("pem_private", priv.to_pem().encode()))
        if alg.kind != "pq":
            seeds.append(("cose_public", pub.to_cose()))
            seeds.append(("cbor", pub.to_cose()))
            seeds.append(("cose_private", priv.to_cose()))
            seeds.append(("jwk_public", json.dumps(pub.to_jwk()).encode()))
            seeds.append(("jwk_private", json.dumps(priv.to_jwk()).encode()))
            seeds.append(("thumbprint", json.dumps(pub.to_jwk()).encode()))
        else:
            # A seed-arm key, so the RFC 9881 §6 [0] IMPLICIT branch is reached.
            seed = bytes((0x5A + i) & 0xFF for i in range(alg.pq_seed_bytes))
            if alg.pq_family == "ml-dsa":
                pk2, sk2 = pb.native_ml_dsa_keypair_from_seed(alg.pq_set, seed)
            else:
                pk2, sk2 = pb.native_ml_kem_keypair_from_seed(alg.pq_set, seed[:32], seed[32:])
            seeded = kf.PrivateKey(name, sk2, pk2, seed)
            for arm in ("seed", "expandedKey", "both"):
                seeds.append(("pkcs8", seeded.to_pkcs8(pq_format=arm)))
    return seeds


def _corpus_records() -> list[tuple[str, bytes]]:
    """The vendored specification vectors, including the deliberately-bad keys.

    The inconsistent RFC 9881 / lamps-kyber keys are the most valuable seeds in
    the set: they are *nearly* valid, so mutations of them land deep in the
    consistency-checking code rather than bouncing off the DER layer.
    """
    import base64

    seeds: list[tuple[str, bytes]] = []
    corpus = REPO_ROOT / "tests" / "kat" / "keyformats"
    for path in sorted(corpus.glob("*.json")):
        data = json.loads(path.read_text())
        for record in data["records"]:
            if "pem_b64" not in record:
                continue
            try:
                der = base64.b64decode(record["pem_b64"], validate=True)
            except (ValueError, binascii.Error):
                continue
            target = "spki" if record.get("label") == "PUBLIC KEY" else "pkcs8"
            seeds.append((target, der))
    return seeds


def build_seed_corpus(extra_dir: Path | None = None) -> list[tuple[str, bytes]]:
    seeds = _generated_keys() + _corpus_records()
    if extra_dir and extra_dir.is_dir():
        for path in sorted(extra_dir.rglob("*")):
            if path.is_file() and path.stat().st_size <= MAX_INPUT_BYTES:
                # An input from the crash corpus is replayed against every
                # target, because the file name does not say which one found it.
                for target in TARGETS:
                    seeds.append((target, path.read_bytes()))
    return seeds


# ---------------------------------------------------------------------------
# Mutation — structure-aware, because the interesting octets are structural
# ---------------------------------------------------------------------------
#: ASN.1 tags and CBOR initial bytes worth substituting. A random byte reaches
#: these one time in 256; a dictionary reaches them on demand. This is the same
#: reasoning behind `fuzz/dictionaries/*.dict` for the C lane.
# fmt: off
INTERESTING_OCTETS = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0C,  # ASN.1 universal tags
    0x30, 0x31,                                       # SEQUENCE, SET
    0x80, 0x81, 0x82, 0x83, 0xA0, 0xA1, 0xA2, 0xA3,   # context-specific
    0x1F,                                             # high-tag-number form
    0x7F, 0x80, 0xFF,                                 # length-form boundaries
    0x84, 0x85,                                       # long-form length counts
    0x20, 0x40, 0x60, 0xA0, 0xC0, 0xE0,               # CBOR major types
    0x18, 0x19, 0x1A, 0x1B,                           # CBOR argument widths
])
# fmt: on

_LENGTH_DELTAS = (-2, -1, 1, 2, 127, 128, 255)


# Each mutator edits `buf` in place and must never raise; `mutate` picks one
# uniformly. Keeping them as separate named functions rather than one long
# `elif` chain means a new mutation is a new entry in `_MUTATORS`, and each one
# can be read (and, above, explained) on its own.


def _m_bit_flip(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)


def _m_interesting_octet(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    buf[rng.randrange(len(buf))] = rng.choice(INTERESTING_OCTETS)


def _m_truncate(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    del buf[rng.randrange(1, len(buf) + 1) :]


def _m_extend(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    buf.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16))))


def _m_length_nudge(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    # The second octet of a DER TLV is the start of the length, and the octet
    # after a long-form count is where a mismatch is most damaging.
    index = 1 if len(buf) > 1 and rng.random() < 0.5 else rng.randrange(len(buf))
    buf[index] = (buf[index] + rng.choice(_LENGTH_DELTAS)) & 0xFF


def _m_splice(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    other = rng.choice(pool) if pool else bytes(buf)
    if other:
        cut = rng.randrange(len(buf) + 1)
        take = other[: rng.randrange(1, min(len(other), 64) + 1)]
        buf[cut:cut] = take


def _m_delete_run(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    start = rng.randrange(len(buf))
    del buf[start : start + rng.randrange(1, 9)]


def _m_duplicate_run(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    start = rng.randrange(len(buf))
    run = bytes(buf[start : start + rng.randrange(1, 17)])
    buf[start:start] = run


def _m_saturate_run(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    start = rng.randrange(len(buf))
    fill = 0x00 if rng.random() < 0.5 else 0xFF
    for i in range(start, min(start + rng.randrange(1, 17), len(buf))):
        buf[i] = fill


def _m_nest(rng: random.Random, buf: bytearray, pool: list[bytes]) -> None:
    """Wrap the input in extra SEQUENCE headers.

    A parser that recurses without a depth bound dies here rather than in
    production.
    """
    for _ in range(rng.randrange(1, 40)):
        if len(buf) > MAX_INPUT_BYTES:
            break
        length = len(buf)
        header = bytearray([0x30])
        if length < 0x80:
            header.append(length)
        else:
            body = length.to_bytes((length.bit_length() + 7) // 8, "big")
            header.append(0x80 | len(body))
            header.extend(body)
        buf[:0] = header


_MUTATORS = (
    _m_bit_flip,
    _m_interesting_octet,
    _m_truncate,
    _m_extend,
    _m_length_nudge,
    _m_splice,
    _m_delete_run,
    _m_duplicate_run,
    _m_saturate_run,
    _m_nest,
)


def mutate(rng: random.Random, data: bytes, pool: list[bytes]) -> bytes:
    """One structure-aware edit. Returns bytes, never raises."""
    if not data:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 32)))
    buf = bytearray(data)
    rng.choice(_MUTATORS)(rng, buf, pool)
    return bytes(buf[:MAX_INPUT_BYTES])


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
def _write_artifact(directory: Path, finding: FindingError) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(finding.data).hexdigest()[:16]
    path = directory / f"crash-{finding.target}-{digest}.bin"
    path.write_bytes(finding.data)
    return path


def run_campaign(seconds: float, seed: int, artifact_dir: Path, corpus_dir: Path | None) -> int:
    rng = random.Random(seed)  # noqa: S311 -- deterministic fuzz-input generation, not key material
    seeds = build_seed_corpus(corpus_dir)
    pool = [data for _, data in seeds]
    print(f"seed={seed} corpus={len(seeds)} targets={len(TARGETS)} budget={seconds}s")

    # Pass 1: every seed against its own target, and against every other one —
    # a valid COSE_Key handed to load_pkcs8 is a legitimate hostile input.
    executed = 0
    deadline = time.monotonic() + seconds
    try:
        for target, data in seeds:
            run_one(target, data)
            executed += 1
        for target in TARGETS:
            for _, data in seeds:
                run_one(target, data)
                executed += 1

        # Pass 2: mutation, until the budget runs out.
        while time.monotonic() < deadline:
            target = rng.choice(list(TARGETS))
            base = rng.choice(pool)
            data = mutate(rng, base, pool)
            run_one(target, data)
            executed += 1
            if rng.random() < 0.02 and len(pool) < 4000:
                pool.append(data)  # keep some mutants as future bases
    except FindingError as finding:
        path = _write_artifact(artifact_dir, finding)
        print(f"\nFINDING after {executed} executions: {finding}")
        print(f"  input written to {path}")
        print(f"  reproduce with: python3 {Path(__file__).name} --input {path}")
        return 1

    print(f"OK: {executed} executions, no contract violation")
    return 0


def run_input(path: Path) -> int:
    data = path.read_bytes()
    failures = 0
    for target in TARGETS:
        try:
            run_one(target, data)
        except FindingError as finding:
            print(f"FINDING: {finding}")
            failures += 1
    if failures:
        return 1
    print(f"OK: {path} violates nothing across {len(TARGETS)} targets")
    return 0


def run_atheris(argv: list[str]) -> int:  # pragma: no cover - optional engine
    """Hand the same entry point to Atheris, when it happens to be installed.

    Deliberately optional. The gate must not depend on a third-party fuzzing
    engine being available, so this is a bonus lane rather than the lane.
    """
    try:
        import atheris
    except ImportError:
        print(
            "atheris is not installed; run without --atheris for the built-in engine",
            file=sys.stderr,
        )
        return 2

    targets = list(TARGETS)

    def one(raw: bytes) -> None:
        if not raw:
            return
        target = targets[raw[0] % len(targets)]
        try:
            run_one(target, raw[1:])
        except FindingError as finding:
            raise AssertionError(str(finding)) from None

    # Write the seed corpus somewhere libFuzzer can actually read it, and hand
    # it to Setup. Previously `build_seed_corpus(None)` was computed, printed
    # as "seeded with N inputs", and then used for nothing at all — the Atheris
    # run started cold, which is exactly the failure the module docstring says
    # the seed corpus exists to prevent ("a fuzzer from an empty corpus spends
    # its whole budget rediscovering that a key file begins with 0x30").
    #
    # Two things the seeds must get right, and neither was:
    #
    # `build_seed_corpus` returns (target_name, data) PAIRS, so writing each
    # element straight out raised `TypeError: memoryview: a bytes-like object is
    # required, not 'tuple'` — the --atheris lane died before Setup on every
    # invocation.
    #
    # And `one()` above spends raw[0] as a target selector, so a seed file must
    # carry that byte or every seed is dispatched to an arbitrary target with
    # its own first byte eaten (a DER seed starting 0x30 always lands on
    # index 48 % len(targets), and arrives truncated).  Prefix the selector that
    # reproduces the pairing the corpus was built with.
    seed_dir = Path(tempfile.mkdtemp(prefix="ama-fuzz-seeds-"))
    seeds = build_seed_corpus(None)
    for index, (target_name, blob) in enumerate(seeds):
        selector = targets.index(target_name)
        (seed_dir / f"seed-{index:04d}").write_bytes(bytes([selector]) + blob)
    print(f"seeded with {len(seeds)} inputs in {seed_dir}")

    # argv[0] is the program name by libFuzzer/sys.argv convention and Setup
    # discards it. `argv` here is the *unrecognised* remainder from
    # parse_known_args, which has no program name, so the first real libFuzzer
    # flag the user passed was being silently eaten.
    forwarded = [sys.argv[0]]
    forwarded.extend(a for a in argv if a != "--atheris")
    forwarded.append(str(seed_dir))

    with atheris.instrument_imports():
        atheris.Setup(forwarded, one)
    atheris.Fuzz()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seconds", type=float, default=60.0, help="wall-clock budget for the mutation pass"
    )
    parser.add_argument(
        "--seed", type=int, default=0x9881_C4, help="RNG seed; a finding reproduces from this alone"
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=Path("artifacts/python-parsers"),
        help="where a failing input is written",
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=None,
        help="extra seed inputs (e.g. previously saved crashes)",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="replay a single file against every target and exit",
    )
    parser.add_argument(
        "--atheris", action="store_true", help="use Atheris for coverage guidance, if installed"
    )
    args, rest = parser.parse_known_args(argv)

    if args.input is not None:
        return run_input(args.input)
    if args.atheris:
        return run_atheris(rest)
    return run_campaign(args.seconds, args.seed, args.artifact_dir, args.corpus_dir)


if __name__ == "__main__":
    raise SystemExit(main())
