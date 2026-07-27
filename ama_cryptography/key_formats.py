#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Key interoperability formats — PKCS#8, SPKI, PEM, JWK, COSE_Key.
================================================================

AMA's key handling was in-house only: opaque octet strings with AMA-defined
layouts. That is fine inside AMA and useless everywhere else. This module is
the boundary layer that lets an AMA key leave the library and come back —
into an X.509 certificate request, a TLS stack, a JOSE token, a COSE message,
a WebAuthn credential, or an HSM's PKCS#11 object.

Design commitments
------------------
**Private and public material never share a code path.** ``PublicKey`` and
``PrivateKey`` are separate types with separate encoders and decoders. There
is no ``encode(key)`` that decides which one it got, because the failure mode
of that design — a private key serialised into the slot where a public key was
expected — is unrecoverable and silent. A ``PrivateKey`` will not serialise
through a public encoder; the type system stops it before the bytes exist.

**Parsing is strict.** See ``ama_cryptography._asn1``: DER only (never BER),
minimal lengths and INTEGERs, no trailing data, deterministic CBOR only. A
permissive parser means two byte strings decode to the same key, which is the
same defect class as signature malleability and reachable by anyone who can
hand you a key file.

**Every algorithm is real.** Nothing here is a placeholder. Where a format has
no finished standard for an algorithm, the call raises
``UnsupportedKeyFormatError`` naming the reason rather than inventing an
encoding — see the limitations table below.

Support matrix
--------------
=================  ======  =======  =====  ====
Algorithm          SPKI    PKCS#8   JWK    COSE
=================  ======  =======  =====  ====
Ed25519            yes     yes      yes    yes
X25519             yes     yes      yes    yes
P-256/384/521      yes     yes      yes    yes
secp256k1          yes     yes      yes    yes
ML-DSA-44/65/87    yes     yes      no     no
ML-KEM-512/768/1024 yes    yes      no     no
=================  ======  =======  =====  ====

Standards followed
------------------
* **SPKI** — RFC 5280 §4.1.2.7 ``SubjectPublicKeyInfo``; RFC 5480 for the EC
  curves; RFC 8410 for Ed25519/X25519.
* **PKCS#8** — RFC 5958 ``OneAsymmetricKey``; RFC 5915 ``ECPrivateKey`` for
  the EC curves; RFC 8410 ``CurvePrivateKey`` for Ed25519/X25519.
* **PEM** — RFC 7468 (strict: 64-character lines, no headers, exact labels).
* **JWK** — RFC 7517/7518, RFC 8037 for OKP, RFC 8812 for secp256k1;
  thumbprints per RFC 7638.
* **COSE_Key** — RFC 9052/9053, RFC 8812 for secp256k1; deterministic CBOR
  per RFC 8949 §4.2.1.

Limitations, stated precisely
-----------------------------
* **ML-DSA and ML-KEM have no JWK or COSE encoding here.** The JOSE and COSE
  registrations for these algorithms were still drafts at the time of writing.
  Emitting a guess would produce keys that interoperate with nothing and that
  a future revision would have to break. ``UnsupportedKeyFormatError`` names
  this explicitly rather than failing obscurely.
* **PKCS#8 encryption (RFC 5958 ``EncryptedPrivateKeyInfo``) is not
  implemented.** Only the unencrypted form is read and written. Use
  ``ama_cryptography.key_management.SecureKeyStorage`` for keys at rest; a
  password-wrapped PKCS#8 needs a KDF-and-cipher policy decision that belongs
  with the storage layer, not the encoding layer.
* **Certificates are out of scope.** This module handles keys, not X.509
  structures that contain them.
* **Attributes in ``OneAsymmetricKey`` are parsed and discarded.** They are
  accepted so that third-party keys carrying them import cleanly, but nothing
  in AMA consumes them and they are not re-emitted.

Post-quantum private keys
-------------------------
All three arms of the RFC 9881 §6 ``CHOICE`` — ``seed``, ``expandedKey`` and
``both`` — are read and written, and all three are real:

* A ``seed`` is expanded through the deterministic keygen entry point, so it
  imports as a working key rather than an opaque blob.
* A seed that arrives is **kept** on the ``PrivateKey`` and re-emitted in the
  form it arrived in. Expansion is one-way (RFC 9881 §8.1), so dropping it
  would irreversibly downgrade a 34-octet key file into a multi-kilobyte one.
* A ``both`` key is checked: the seed must expand to the supplied
  ``expandedKey`` or the key is rejected as malformed (RFC 9881 §8.2).
* An ``expandedKey``-only key is checked too, which is the part implementations
  usually skip. ML-DSA's ``rho``, ``s1`` and ``s2`` determine ``t0`` and the
  public key and therefore ``tr``; ML-KEM's ``dk`` embeds ``ek`` and
  ``H(ek)``. Both are recomputed and required to agree. RFC 9881 §8.2 and
  draft-ietf-lamps-kyber-certificates §C.4.1 ship the negative vectors, and
  they are in the test suite.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Union

import ama_cryptography.pqc_backends as _pb
from ama_cryptography._asn1 import (
    DerReader,
    cbor_decode_canonical,
    cbor_encode_canonical,
    der_bit_string,
    der_integer,
    der_octet_string,
    der_sequence,
    der_tagged,
    oid_from_string,
)
from ama_cryptography.exceptions import KeyFormatError, UnsupportedKeyFormatError

__all__ = [
    "ALGORITHMS",
    "CONVENTIONAL_PUBLIC_KEY",
    "PQ_CONSISTENCY_ENV",
    "PrivateKey",
    "PublicKey",
    "conventional_include_public_key",
    "cose_to_private_key",
    "cose_to_public_key",
    "decode_pem",
    "encode_pem",
    "get_pq_import_consistency",
    "jwk_thumbprint",
    "jwk_to_private_key",
    "jwk_to_public_key",
    "load_pkcs8",
    "load_spki",
    "pq_import_consistency",
    "private_key_to_cose",
    "private_key_to_jwk",
    "public_key_to_cose",
    "public_key_to_jwk",
    "set_pq_import_consistency",
]


# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Alg:
    """Everything the encoders need to know about one algorithm."""

    name: str
    kind: str  # "okp" | "ec" | "pq"
    oid: str
    public_bytes: int
    private_bytes: int
    # EC only
    curve: str | None = None
    field_bytes: int = 0
    curve_oid: str | None = None
    jwk_crv: str | None = None
    cose_crv: int | None = None
    # OKP only
    okp_crv: str | None = None
    # PQ only
    pq_family: str | None = None
    pq_param_set: int | None = None
    pq_seed_bytes: int = 0

    # The kind-specific fields are Optional because one dataclass describes
    # three shapes, but within a branch that has already established the kind
    # they are never None. These accessors state that invariant once, so the
    # call sites read as the narrow types they are instead of carrying an
    # assertion — or a silenced type error — at each one. A wrong-kind access
    # is a programming error in this module, not a malformed input, so it
    # raises rather than being reachable from a key file.
    @property
    def ec_curve(self) -> str:
        if self.curve is None:
            raise AssertionError(f"{self.name} is not an EC algorithm")
        return self.curve

    @property
    def ec_curve_oid(self) -> str:
        if self.curve_oid is None:
            raise AssertionError(f"{self.name} is not an EC algorithm")
        return self.curve_oid

    @property
    def pq_set(self) -> int:
        if self.pq_param_set is None:
            raise AssertionError(f"{self.name} is not a post-quantum algorithm")
        return self.pq_param_set


# NIST CSOR OIDs for ML-DSA (2.16.840.1.101.3.4.3.17-19) and ML-KEM
# (2.16.840.1.101.3.4.4.1-3); RFC 8410 for Ed25519/X25519; RFC 5480 +
# SEC 2 for the EC named curves.
ALGORITHMS: dict[str, _Alg] = {
    "Ed25519": _Alg(
        name="Ed25519", kind="okp", oid="1.3.101.112",
        public_bytes=32, private_bytes=32, okp_crv="Ed25519", cose_crv=6,
    ),
    "X25519": _Alg(
        name="X25519", kind="okp", oid="1.3.101.110",
        public_bytes=32, private_bytes=32, okp_crv="X25519", cose_crv=4,
    ),
    "P-256": _Alg(
        name="P-256", kind="ec", oid="1.2.840.10045.2.1",
        public_bytes=64, private_bytes=32, curve="P-256", field_bytes=32,
        curve_oid="1.2.840.10045.3.1.7", jwk_crv="P-256", cose_crv=1,
    ),
    "P-384": _Alg(
        name="P-384", kind="ec", oid="1.2.840.10045.2.1",
        public_bytes=96, private_bytes=48, curve="P-384", field_bytes=48,
        curve_oid="1.3.132.0.34", jwk_crv="P-384", cose_crv=2,
    ),
    "P-521": _Alg(
        name="P-521", kind="ec", oid="1.2.840.10045.2.1",
        public_bytes=132, private_bytes=66, curve="P-521", field_bytes=66,
        curve_oid="1.3.132.0.35", jwk_crv="P-521", cose_crv=3,
    ),
    "secp256k1": _Alg(
        name="secp256k1", kind="ec", oid="1.2.840.10045.2.1",
        public_bytes=64, private_bytes=32, curve="secp256k1", field_bytes=32,
        curve_oid="1.3.132.0.10", jwk_crv="secp256k1", cose_crv=8,
    ),
    "ML-DSA-44": _Alg(
        name="ML-DSA-44", kind="pq", oid="2.16.840.1.101.3.4.3.17",
        public_bytes=1312, private_bytes=2560,
        pq_family="ml-dsa", pq_param_set=44, pq_seed_bytes=32,
    ),
    "ML-DSA-65": _Alg(
        name="ML-DSA-65", kind="pq", oid="2.16.840.1.101.3.4.3.18",
        public_bytes=1952, private_bytes=4032,
        pq_family="ml-dsa", pq_param_set=65, pq_seed_bytes=32,
    ),
    "ML-DSA-87": _Alg(
        name="ML-DSA-87", kind="pq", oid="2.16.840.1.101.3.4.3.19",
        public_bytes=2592, private_bytes=4896,
        pq_family="ml-dsa", pq_param_set=87, pq_seed_bytes=32,
    ),
    "ML-KEM-512": _Alg(
        name="ML-KEM-512", kind="pq", oid="2.16.840.1.101.3.4.4.1",
        public_bytes=800, private_bytes=1632,
        pq_family="ml-kem", pq_param_set=512, pq_seed_bytes=64,
    ),
    "ML-KEM-768": _Alg(
        name="ML-KEM-768", kind="pq", oid="2.16.840.1.101.3.4.4.2",
        public_bytes=1184, private_bytes=2400,
        pq_family="ml-kem", pq_param_set=768, pq_seed_bytes=64,
    ),
    "ML-KEM-1024": _Alg(
        name="ML-KEM-1024", kind="pq", oid="2.16.840.1.101.3.4.4.3",
        public_bytes=1568, private_bytes=3168,
        pq_family="ml-kem", pq_param_set=1024, pq_seed_bytes=64,
    ),
}

_BY_OID: dict[str, _Alg] = {}
_BY_CURVE_OID: dict[str, _Alg] = {}
for _alg in ALGORITHMS.values():
    if _alg.kind == "ec":
        assert _alg.curve_oid is not None
        _BY_CURVE_OID[_alg.curve_oid] = _alg
    else:
        _BY_OID[_alg.oid] = _alg

_JWK_CRV_TO_ALG = {a.jwk_crv: a for a in ALGORITHMS.values() if a.jwk_crv}
_OKP_CRV_TO_ALG = {a.okp_crv: a for a in ALGORITHMS.values() if a.okp_crv}
_COSE_EC2_TO_ALG = {a.cose_crv: a for a in ALGORITHMS.values() if a.kind == "ec"}
_COSE_OKP_TO_ALG = {a.cose_crv: a for a in ALGORITHMS.values() if a.kind == "okp"}

# COSE key types (RFC 9053 §7) and label numbers (RFC 9052 §7.1).
_COSE_KTY_OKP = 1
_COSE_KTY_EC2 = 2
_COSE_LBL_KTY = 1
_COSE_LBL_CRV = -1
_COSE_LBL_X = -2
_COSE_LBL_Y = -3
_COSE_LBL_D = -4

# RFC 8410 §7 / RFC 5958: the version numbers this layer emits and accepts.
_PKCS8_V1 = 0
_PKCS8_V2 = 1


# ---------------------------------------------------------------------------
# Import policy — PQ consistency checking
# ---------------------------------------------------------------------------
#: Environment variable that sets the process-wide default. Accepts ``0``/``1``,
#: ``off``/``on``, ``false``/``true``, ``no``/``yes`` (case-insensitive). Read
#: once at import; anything unrecognised is a hard error rather than a silent
#: fallback, because "the flag was misspelled so the check quietly stayed on"
#: and "…quietly went off" are both worse than a startup failure.
PQ_CONSISTENCY_ENV = "AMA_KEY_IMPORT_PQ_CONSISTENCY"

_TRUE = {"1", "on", "true", "yes"}
_FALSE = {"0", "off", "false", "no"}


def _initial_pq_consistency() -> bool:
    raw = os.environ.get(PQ_CONSISTENCY_ENV)
    if raw is None:
        return True
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise KeyFormatError(
        f"{PQ_CONSISTENCY_ENV}={raw!r} is not a recognised boolean; expected one "
        f"of {sorted(_TRUE | _FALSE)}"
    )


_PQ_CONSISTENCY_DEFAULT = _initial_pq_consistency()


def get_pq_import_consistency() -> bool:
    """Whether ML-DSA/ML-KEM consistency checks run on the import path.

    See :func:`set_pq_import_consistency` for what the checks are, what they
    cost, and what turning them off does and does not give up.
    """
    return _PQ_CONSISTENCY_DEFAULT


def set_pq_import_consistency(enabled: bool) -> bool:
    """Set the process-wide default. Returns the previous value.

    **The default is enabled, and that is the right setting for almost every
    caller.** This exists because the checks are not free and the import path is
    reachable by whoever supplies a key file:

    * An ``expandedKey``-only ML-DSA key is checked by re-expanding the matrix
      ``A`` and recomputing ``t0``, the public key and ``tr`` — a full key
      generation's worth of work.
    * An ``expandedKey``-only ML-KEM key is checked by recomputing ``H(ek)``
      *and* running an encapsulate/decapsulate round trip.
    * A ``both``-arm key is checked by expanding its seed and comparing.

    Measured costs are in ``docs/KEY_FORMATS.md``; ``benchmarks/keyformat_import.py``
    is what produces them. Roughly, importing an ML-DSA-87 ``expandedKey`` key
    costs about the same as generating one, which is three orders of magnitude
    more than parsing the DER around it. Anywhere key import is attacker-reachable
    and unauthenticated — a public endpoint that accepts uploaded keys, say — that
    ratio is a denial-of-service lever, and rate-limiting the endpoint is usually
    the better answer than disabling the check. Turning it off is for the case
    where the same keys are re-imported constantly from a store that already
    validated them.

    What stays true with the checks off:

    * Every structural check still runs — DER strictness, the ``CHOICE`` arm,
      lengths, the algorithm OID. This flag governs *cryptographic* consistency
      only.
    * ML-KEM still recovers its encapsulation key, because FIPS 203 §7.1 embeds
      ``ek`` verbatim in ``dk``; extracting it is a slice. If the file *also*
      carries a public key, the two are still required to be equal — that
      comparison is free.
    * A ``seed``-arm key is still expanded, because that is how the key is
      decoded at all, not a check.

    What is given up:

    * ML-DSA no longer derives a public key at import, so
      :attr:`PrivateKey.public_key` is ``None`` and :meth:`PrivateKey.public`
      runs the full check on first use instead. The cost moves; it does not
      vanish.
    * The RFC 9881 §8.2 / draft-ietf-lamps-kyber-certificates §C.4.1 negative
      vectors are no longer rejected at import. RFC 9881 §8.2 says an
      inconsistent key MUST be rejected as malformed, so a deployment that
      disables this is making a conformance decision, not a tuning one. For
      ML-KEM in particular the failure is *silent*: implicit rejection is
      designed not to raise, so a mutated ``dk_PKE`` simply derives a shared
      secret the sender never had.
    """
    global _PQ_CONSISTENCY_DEFAULT
    previous = _PQ_CONSISTENCY_DEFAULT
    _PQ_CONSISTENCY_DEFAULT = bool(enabled)
    return previous


@contextlib.contextmanager
def pq_import_consistency(enabled: bool) -> Iterator[None]:
    """Scope a policy change to a block, restoring the previous value after.

    Preferred over :func:`set_pq_import_consistency` for the same reason a
    context manager is preferred to a global flip anywhere else: a disabled
    security check that is never re-enabled is the failure mode, and this shape
    makes the disabled region visible in the source.
    """
    previous = set_pq_import_consistency(enabled)
    try:
        yield
    finally:
        set_pq_import_consistency(previous)


def _require_public(key: object) -> None:
    """Refuse anything that is not a ``PublicKey`` at a public encoder's door.

    ``PublicKey`` and ``PrivateKey`` are separate types, but that alone is not
    a boundary: both carry ``.algorithm`` and ``.key``, so a ``PrivateKey``
    duck-types straight through a public encoder and — for Ed25519 and X25519,
    where the secret and public halves are the same width — comes out the other
    side as a well-formed public encoding of the *secret* seed. Nothing about
    the result looks wrong. The check has to be explicit.
    """
    if not isinstance(key, PublicKey):
        raise KeyFormatError(
            f"expected a PublicKey, got {type(key).__name__}. Public and private "
            "keys do not share an encoder here; use the private-key entry point "
            "or pass key.public()."
        )


def _lookup(algorithm: str) -> _Alg:
    """Resolve an algorithm name, refusing anything unrecognised (INVARIANT-35)."""
    try:
        return ALGORITHMS[algorithm]
    except KeyError:
        raise KeyFormatError(
            f"unknown algorithm {algorithm!r}; expected one of {sorted(ALGORITHMS)}"
        ) from None


# ---------------------------------------------------------------------------
# Key types — deliberately not interchangeable
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PublicKey:
    """A public key in AMA's native representation, tagged with its algorithm.

    ``key`` is exactly what the AMA primitives consume: 32 octets for Ed25519
    and X25519, ``X || Y`` for the EC curves (no SEC 1 prefix), and the raw
    FIPS 203/204 encoding for ML-KEM/ML-DSA.
    """

    algorithm: str
    key: bytes

    def __post_init__(self) -> None:
        alg = _lookup(self.algorithm)
        if len(self.key) != alg.public_bytes:
            raise KeyFormatError(
                f"{self.algorithm} public key must be {alg.public_bytes} bytes, "
                f"got {len(self.key)}"
            )

    def to_spki(self) -> bytes:
        return _encode_spki(self)

    def to_pem(self) -> str:
        return encode_pem(self.to_spki(), "PUBLIC KEY")

    def to_jwk(self) -> dict[str, Any]:
        return public_key_to_jwk(self)

    def to_cose(self) -> bytes:
        return public_key_to_cose(self)


@dataclass(frozen=True)
class PrivateKey:
    """A private key in AMA's native representation, tagged with its algorithm.

    Deliberately a distinct type from ``PublicKey`` with no shared encoder.
    A private key cannot be passed to a public-key serialiser, because the
    silent failure that design permits — secret material written into a slot
    the caller intends to publish — has no recovery.

    ``key`` is the seed for Ed25519/X25519 (32 octets, the RFC 8410 form), the
    big-endian scalar for the EC curves, and the expanded FIPS 203/204 secret
    key for ML-KEM/ML-DSA. ``public_key`` is optional on construction and is
    derived when a format requires it.

    ``seed`` carries the ML-DSA ``xi`` (32 octets) or the ML-KEM ``d || z``
    (64 octets) when one is known, and is ``None`` for every other algorithm.
    It is kept because expansion is one-way: RFC 9881 §8.1 is explicit that
    "once a full key is expanded from seed and the seed discarded, the seed
    cannot be recreated, even if the full expanded private key is available".
    Dropping it on import would silently downgrade a 34-octet seed-form key
    file into a multi-kilobyte expanded one on the next write, irreversibly —
    so a key that arrives with a seed keeps it, and re-encodes in the form it
    arrived in.
    """

    algorithm: str
    key: bytes
    public_key: bytes | None = None
    seed: bytes | None = None

    def __post_init__(self) -> None:
        alg = _lookup(self.algorithm)
        if len(self.key) != alg.private_bytes:
            raise KeyFormatError(
                f"{self.algorithm} private key must be {alg.private_bytes} bytes, "
                f"got {len(self.key)}"
            )
        if self.public_key is not None and len(self.public_key) != alg.public_bytes:
            raise KeyFormatError(
                f"{self.algorithm} public key must be {alg.public_bytes} bytes, "
                f"got {len(self.public_key)}"
            )
        if self.seed is not None:
            if alg.kind != "pq":
                raise KeyFormatError(f"{self.algorithm} keys have no seed form")
            if len(self.seed) != alg.pq_seed_bytes:
                raise KeyFormatError(
                    f"{self.algorithm} seed must be {alg.pq_seed_bytes} bytes, "
                    f"got {len(self.seed)}"
                )

    def derive_public_key(self) -> PublicKey:
        """Recompute the public key from the secret, via the native backend."""
        return PublicKey(self.algorithm, _derive_public(_lookup(self.algorithm), self.key))

    def public(self) -> PublicKey:
        """The public half — cached if it was supplied, derived otherwise."""
        if self.public_key is not None:
            return PublicKey(self.algorithm, self.public_key)
        return self.derive_public_key()

    def to_pkcs8(
        self,
        *,
        include_public_key: bool | None = None,
        pq_format: str = "auto",
    ) -> bytes:
        """Encode as an unencrypted PKCS#8 ``OneAsymmetricKey`` (RFC 5958).

        Args:
            include_public_key: Whether to carry the public half. ``True`` and
                ``False`` say so outright; both are exercised in the test suite.

                ``None`` (the default) means **"whatever this algorithm's
                ecosystem conventionally emits"**, which is deliberately not a
                single answer across algorithms: byte equality with what
                reference encoders produce is the property this module exists
                to have, and a uniform default would break it for one group or
                the other. Because that makes ``None`` a parameter with more
                than one behaviour, the resolved answer is enumerated in
                :data:`CONVENTIONAL_PUBLIC_KEY` and available from
                :func:`conventional_include_public_key` rather than left to be
                inferred — for the EC curves, yes, inside RFC 5915
                ``ECPrivateKey``, as RFC 9500 §2.3's own keys do; for
                Ed25519/X25519, no, matching RFC 8410 §10.3's first example; for
                ML-DSA/ML-KEM, no, matching RFC 9881 Appendix C.

                Note that for the OKP and PQ algorithms, carrying the public
                key means the RFC 5958 ``[1] publicKey`` field, which raises the
                version to v2; older parsers are known to reject v2. For the EC
                curves it does not, because the public key goes inside
                ``ECPrivateKey`` where RFC 5915 already allows it.
            pq_format: Which arm of the ML-DSA/ML-KEM private-key ``CHOICE``
                to emit — ``"seed"``, ``"expandedKey"``, ``"both"``, or
                ``"auto"``. ``"auto"`` emits the seed form when a seed is
                known (the form RFC 9881 §8.1 RECOMMENDS, and the form a
                seed-carrying key was imported in) and the expanded form
                otherwise. Ignored for non-PQ algorithms.

        Raises:
            KeyFormatError: If ``pq_format="seed"`` or ``"both"`` is asked for
                on a key with no seed — the seed cannot be recovered from the
                expanded key, so there is nothing to emit and silently
                downgrading to the expanded form would be a lie about the
                format the caller requested.
        """
        return _encode_pkcs8(
            self, include_public_key=include_public_key, pq_format=pq_format
        )

    def to_pem(
        self,
        *,
        include_public_key: bool | None = None,
        pq_format: str = "auto",
    ) -> str:
        return encode_pem(
            self.to_pkcs8(include_public_key=include_public_key, pq_format=pq_format),
            "PRIVATE KEY",
        )

    def to_jwk(self) -> dict[str, Any]:
        return private_key_to_jwk(self)

    def to_cose(self) -> bytes:
        return private_key_to_cose(self)


def _derive_public(alg: _Alg, secret: bytes) -> bytes:
    """Recompute a public key from a secret using the native backend only.

    Every backend refusal becomes a ``KeyFormatError``, because at this layer it
    is a property of the *file* rather than of the call. That is the whole
    contract of this module's error handling: ``except KeyFormatError`` around a
    key import has to be sufficient.

    It was not. An EC private key whose scalar is zero or at least the group
    order — a perfectly constructible key file — reached
    ``native_nistp_pubkey_from_privkey``, which raised ``RuntimeError``, which
    escaped ``load_pkcs8`` entirely. Found by fuzz/python/fuzz_key_formats.py
    after 17.8 million executions.
    """
    if alg.kind == "okp":
        if alg.name == "Ed25519":
            public, _ = _pb.native_ed25519_keypair_from_seed(secret)
            return bytes(public)
        return _pb.native_x25519_key_exchange(secret, bytes([9]) + b"\x00" * 31)
    if alg.kind == "ec":
        try:
            if alg.name == "secp256k1":
                compressed = _pb.native_secp256k1_pubkey_from_privkey(secret)
                return _pb.native_secp256k1_pubkey_decompress(compressed)
            return _pb.native_nistp_pubkey_from_privkey(alg.ec_curve, secret)
        except (ValueError, RuntimeError) as exc:
            raise KeyFormatError(
                f"{alg.name} private key is not usable: {exc}"
            ) from None
    # ML-DSA and ML-KEM both recompute the public key from the expanded secret
    # key *and* verify the secret key's internal consistency while doing it —
    # see the two native entry points for what each checks and why. An
    # inconsistent key raises ValueError, which becomes a KeyFormatError here
    # because at this layer it is a property of the file, not of the call.
    try:
        if alg.pq_family == "ml-dsa":
            return _pb.native_ml_dsa_pubkey_from_privkey(alg.pq_set, secret)
        return _pb.native_ml_kem_pubkey_from_privkey(alg.pq_set, secret)
    except ValueError as exc:
        raise KeyFormatError(str(exc)) from None


# ---------------------------------------------------------------------------
# PEM (RFC 7468, strict)
# ---------------------------------------------------------------------------
_PEM_RE = re.compile(
    r"^-----BEGIN (?P<label>[A-Z0-9 ]+)-----\n(?P<body>[A-Za-z0-9+/=\n]*)"
    r"-----END (?P=label)-----\n?$"
)


def encode_pem(der: bytes, label: str) -> str:
    """Wrap DER in a strict RFC 7468 textual encoding (64-character lines)."""
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)] or [""]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def decode_pem(text: str, expected_label: str | None = None) -> tuple[str, bytes]:
    """Parse a single strict RFC 7468 block. Returns ``(label, der)``.

    Rejects the "lax" forms RFC 7468 §3 permits a *parser* to accept —
    explanatory text before the header, whitespace inside the base64,
    mismatched labels. A key file with unexplained bytes around it is one a
    caller should look at, not one this layer should quietly salvage.
    """
    # `str.strip()` with no argument was wrong here, and quietly so. Python's
    # notion of whitespace is Unicode's: it includes U+001C..U+001F (the file,
    # group, record and unit separators), U+000B, U+000C, U+0085, U+00A0 and
    # several Unicode space characters. None of those is whitespace in
    # RFC 7468, which is defined over a printable-ASCII alphabet plus CR and LF.
    # So a key file with a trailing 0x1F — or a NO-BREAK SPACE, or a LINE
    # SEPARATOR — was silently accepted by a parser whose stated position is
    # that "a key file with unexplained bytes around it is one a caller should
    # look at, not one this layer should quietly salvage".
    #
    # Stripping exactly the four characters RFC 7468 allows to surround a block
    # closes that. Found by fuzz/python/fuzz_key_formats.py.
    normalised = text.replace("\r\n", "\n").strip(" \t\r\n") + "\n"
    match = _PEM_RE.match(normalised)
    if not match:
        raise KeyFormatError("not a single strict RFC 7468 PEM block")
    label = match.group("label")
    if expected_label is not None and label != expected_label:
        raise KeyFormatError(f"expected PEM label {expected_label!r}, found {label!r}")

    body = match.group("body")
    for line in body.split("\n")[:-1]:
        if len(line) > 64:
            raise KeyFormatError("PEM line exceeds 64 characters")
    joined = "".join(body.split("\n"))
    try:
        der = base64.b64decode(joined, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KeyFormatError(f"invalid base64 in PEM body: {exc}") from None
    if not der:
        raise KeyFormatError("empty PEM body")
    # `validate=True` checks the *alphabet*, not the padding bits. RFC 4648
    # §3.5: "the pad bits MUST be set to zero by conforming encoders" — and
    # Python's decoder ignores them, so `...Of3N=` and `...Of3M=` decode to the
    # same octets. That is one key with many encodings, which is the defect this
    # module refuses everywhere else: non-minimal DER lengths, non-minimal
    # INTEGERs, non-deterministic CBOR. A PEM file is no different, and a
    # thumbprint or a fingerprint taken over the file rather than the key would
    # disagree across two encodings of one key.
    #
    # Re-encoding and comparing is the whole rule: base64 encoding is a
    # function, so the only string that survives is the one a conforming encoder
    # would have produced. Found by fuzz/python/fuzz_key_formats.py after 7.5
    # million executions.
    if base64.b64encode(der).decode("ascii") != joined:
        raise KeyFormatError(
            "non-canonical base64 in PEM body: the padding bits are not zero, or "
            "the padding is misplaced (RFC 4648 §3.5). One key must have one "
            "encoding."
        )
    return label, der


# ---------------------------------------------------------------------------
# SPKI — SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
# ---------------------------------------------------------------------------
def _algorithm_identifier(alg: _Alg) -> bytes:
    if alg.kind == "ec":
        return der_sequence(oid_from_string(alg.oid), oid_from_string(alg.ec_curve_oid))
    # RFC 8410 §3 and the NIST PQC registrations: parameters MUST be absent,
    # not NULL. Emitting NULL here is a common and quietly non-conformant bug.
    return der_sequence(oid_from_string(alg.oid))


def _encode_spki(key: PublicKey) -> bytes:
    _require_public(key)
    alg = _lookup(key.algorithm)
    if alg.kind == "ec":
        # SEC 1 uncompressed point, per RFC 5480 §2.2.
        payload = b"\x04" + key.key
    else:
        payload = key.key
    return der_sequence(_algorithm_identifier(alg), der_bit_string(payload))


def load_spki(data: Union[bytes, str]) -> PublicKey:
    """Parse a SubjectPublicKeyInfo, in DER or strict PEM.

    Raises:
        KeyFormatError: malformed, non-minimal, or internally inconsistent.
        UnsupportedKeyFormatError: well-formed but names an algorithm or curve
            this library does not implement.
    """
    der = _as_der(data, "PUBLIC KEY")
    outer = DerReader(der)
    seq = outer.read_sequence()
    outer.finish()

    alg_id = seq.read_sequence()
    oid = alg_id.read_oid()

    if oid == "1.2.840.10045.2.1":  # id-ecPublicKey
        if alg_id.peek_tag() is None:
            raise KeyFormatError("id-ecPublicKey requires a named-curve parameter")
        curve_oid = alg_id.read_oid()
        alg_id.finish()
        alg = _BY_CURVE_OID.get(curve_oid)
        if alg is None:
            raise UnsupportedKeyFormatError(
                f"EC curve OID {curve_oid} is not implemented; supported curves are "
                f"{sorted(a.name for a in _BY_CURVE_OID.values())}"
            )
        point = seq.read_bit_string()
        seq.finish()
        raw = _decode_sec1_point(alg, point)
        return PublicKey(alg.name, raw)

    alg = _BY_OID.get(oid)
    if alg is None:
        raise UnsupportedKeyFormatError(f"algorithm OID {oid} is not implemented")
    if alg_id.peek_tag() is not None:
        raise KeyFormatError(
            f"{alg.name} AlgorithmIdentifier must have absent parameters (RFC 8410 §3)"
        )
    alg_id.finish()
    payload = seq.read_bit_string()
    seq.finish()
    if len(payload) != alg.public_bytes:
        raise KeyFormatError(
            f"{alg.name} public key must be {alg.public_bytes} bytes, got {len(payload)}"
        )
    _validate_pq_public(alg, payload)
    return PublicKey(alg.name, payload)


def _validate_pq_public(alg: _Alg, public: bytes) -> None:
    """FIPS 203 §7.2 input validation for an imported ML-KEM encapsulation key.

    The EC curves have had import-time validation since this module was written,
    because an unvalidated point is the invalid-curve attack. ML-KEM has an
    analogue, less dramatic but just as silent: §7.2 requires the **modulus
    check** — every 12-bit coefficient of ``t_hat`` below ``q = 3329`` — and 767
    of every 4096 encodable values fail it. A key that fails is one every
    conformant peer rejects, so encapsulating to it yields a shared secret
    nobody else derives, and ML-KEM's implicit rejection guarantees nothing
    raises. Import is where it is visible.

    ML-DSA has no counterpart: FIPS 204's ``pkDecode`` puts no range constraint
    on ``t1`` (the 10-bit packing is onto), so every byte string of the right
    length names a public key. Checking the length is the whole type check, and
    it has already happened by the time this is called.
    """
    if alg.pq_family != "ml-kem":
        return
    if not _pb.native_ml_kem_pubkey_check(alg.pq_set, public):
        raise KeyFormatError(
            f"{alg.name} encapsulation key fails the FIPS 203 §7.2 modulus "
            "check: a coefficient is not below q. A conformant peer rejects "
            "this key, so encapsulating to it would derive a shared secret "
            "nobody else derives — and implicit rejection means nothing would "
            "report it."
        )


def _decode_sec1_point(alg: _Alg, point: bytes) -> bytes:
    """Decode a SEC 1 point to AMA's ``X || Y`` form, validating it.

    Validation is not optional here. A public key that is not on the named
    curve is the invalid-curve attack: an ECDH peer who supplies a point on a
    weaker curve recovers the private scalar from the results. So every path
    out of this function has proved curve membership, non-identity, and that
    both coordinates are canonical field elements in ``[0, p)`` (INVARIANT-29).
    """
    if not point:
        raise KeyFormatError("empty EC point")
    if point[0] == 0x00:
        raise KeyFormatError("the SEC 1 point at infinity is not a valid public key")
    if alg.name == "secp256k1":
        if point[0] == 0x04:
            if len(point) != 1 + 2 * alg.field_bytes:
                raise KeyFormatError("malformed uncompressed secp256k1 point")
            _validate_ec_public(alg, point[1:])
            return point[1:]
        if point[0] in (0x02, 0x03):
            if len(point) != 1 + alg.field_bytes:
                raise KeyFormatError("malformed compressed secp256k1 point")
            try:
                return _pb.native_secp256k1_pubkey_decompress(point)
            except ValueError as exc:
                raise KeyFormatError(f"invalid secp256k1 point: {exc}") from None
        raise KeyFormatError(f"unknown SEC 1 point prefix 0x{point[0]:02X}")
    # NIST prime curves: the native decoder validates canonicality, curve
    # membership and non-identity, and rejects a non-residue x outright. Its
    # refusal is a property of the key file, so it surfaces as KeyFormatError
    # rather than the backend's ValueError.
    try:
        return _pb.native_nistp_point_decode(alg.ec_curve, point)
    except ValueError as exc:
        raise KeyFormatError(f"invalid {alg.name} point: {exc}") from None


# ---------------------------------------------------------------------------
# PKCS#8 — OneAsymmetricKey (RFC 5958)
# ---------------------------------------------------------------------------
# The conventional `include_public_key` answer per algorithm kind — see
# PrivateKey.to_pkcs8. These are the forms the RFCs' own worked examples carry,
# so they are what a third-party parser is most likely to accept.
_CONVENTIONAL_PUBLIC = {"ec": True, "okp": False, "pq": False}

#: What ``include_public_key=None`` resolves to, stated per algorithm.
#:
#: ``None`` means "the conventional encoding for this algorithm", which is a
#: parameter with more than one default behaviour — defensible, because byte
#: equality with what reference encoders emit is the whole point of this module,
#: but not something a future maintainer should have to infer from a `kind`
#: lookup three functions away. So it is enumerated, exported, and tested:
#:
#: ===================  =====  ==========================================
#: Algorithm            None   Why
#: ===================  =====  ==========================================
#: P-256/384/521        True   inside RFC 5915 ``ECPrivateKey``, the form
#: secp256k1            True   RFC 9500 §2.3's own keys use
#: Ed25519, X25519      False  RFC 8410 §10.3's first example
#: ML-DSA-44/65/87      False  RFC 9881 Appendix C
#: ML-KEM-512/768/1024  False  draft-ietf-lamps-kyber-certificates App. C
#: ===================  =====  ==========================================
#:
#: Derived from the registry rather than transcribed, so an algorithm added to
#: ``ALGORITHMS`` cannot be missing from here;
#: ``test_the_conventional_table_covers_every_algorithm`` pins that both ways.
CONVENTIONAL_PUBLIC_KEY: dict[str, bool] = {
    name: _CONVENTIONAL_PUBLIC[alg.kind] for name, alg in ALGORITHMS.items()
}


def conventional_include_public_key(algorithm: str) -> bool:
    """Resolve ``include_public_key=None`` for ``algorithm``.

    Exported so a caller who needs to know what the default will do can ask,
    rather than encoding twice and comparing lengths.

    Raises:
        KeyFormatError: if ``algorithm`` is not one this library implements
            (INVARIANT-35 — a selector must never resolve to a neighbour).
    """
    _lookup(algorithm)
    return CONVENTIONAL_PUBLIC_KEY[algorithm]

_PQ_FORMATS = ("auto", "seed", "expandedKey", "both")


def _encode_pq_private_key(key: PrivateKey, alg: _Alg, pq_format: str) -> bytes:
    """The ML-DSA/ML-KEM private-key CHOICE (RFC 9881 §6)."""
    if pq_format not in _PQ_FORMATS:
        raise KeyFormatError(
            f"unknown pq_format {pq_format!r}; expected one of {list(_PQ_FORMATS)}"
        )
    if pq_format == "auto":
        pq_format = "seed" if key.seed is not None else "expandedKey"
    if pq_format in ("seed", "both") and key.seed is None:
        raise KeyFormatError(
            f"cannot emit the {alg.name} {pq_format!r} private-key form: this key "
            "has no seed, and a seed cannot be recovered from an expanded key "
            "(RFC 9881 §8.1). Use pq_format='expandedKey'."
        )
    if pq_format == "expandedKey":
        return der_octet_string(key.key)
    seed = key.seed
    if seed is None:  # pragma: no cover - the guard above already returned
        raise KeyFormatError(f"{alg.name} key has no seed")
    if pq_format == "seed":
        # IMPLICIT [0] OCTET STRING: the tag replaces the OCTET STRING's own,
        # so the seed octets follow the header directly.
        return der_tagged(0, seed, constructed=False)
    return der_sequence(der_octet_string(seed), der_octet_string(key.key))


def _encode_pkcs8(
    key: PrivateKey, *, include_public_key: bool | None, pq_format: str
) -> bytes:
    alg = _lookup(key.algorithm)
    if include_public_key is None:
        include_public_key = _CONVENTIONAL_PUBLIC[alg.kind]

    extra: list[bytes] = []
    version = _PKCS8_V1

    if alg.kind == "ec":
        # RFC 5915 ECPrivateKey inside the privateKey OCTET STRING. The
        # curve lives in the outer AlgorithmIdentifier, so [0] parameters are
        # omitted here per RFC 5915 §3.
        elements = [der_integer(1), der_octet_string(key.key)]
        if include_public_key:
            public = key.public_key or _derive_public(alg, key.key)
            elements.append(der_tagged(1, der_bit_string(b"\x04" + public)))
        inner = der_sequence(*elements)
    else:
        if alg.kind == "okp":
            # RFC 8410 §7: CurvePrivateKey ::= OCTET STRING, wrapped again.
            inner = der_octet_string(key.key)
        else:
            inner = _encode_pq_private_key(key, alg, pq_format)
        if include_public_key:
            public = key.public_key or _derive_public(alg, key.key)
            # RFC 5958 [1] IMPLICIT publicKey, which bumps the version to v2.
            extra = [der_tagged(1, b"\x00" + public, constructed=False)]
            version = _PKCS8_V2

    return der_sequence(
        der_integer(version),
        _algorithm_identifier(alg),
        der_octet_string(inner),
        *extra,
    )


def load_pkcs8(
    data: Union[bytes, str], *, verify_pq_consistency: bool | None = None
) -> PrivateKey:
    """Parse a PKCS#8 OneAsymmetricKey, in DER or strict PEM.

    The encrypted form (``EncryptedPrivateKeyInfo``) is not supported and is
    reported as such rather than failing obscurely.

    Args:
        verify_pq_consistency: Whether to run the ML-DSA/ML-KEM cryptographic
            consistency checks on this call. ``None`` (the default) uses the
            process-wide policy, which is itself enabled unless
            ``AMA_KEY_IMPORT_PQ_CONSISTENCY`` or
            :func:`set_pq_import_consistency` says otherwise. Ignored for the
            classical algorithms, whose derivation is both cheap and required
            to produce a public key at all. See
            :func:`set_pq_import_consistency` for what the checks are, what
            they cost, and precisely what is given up by skipping them.
    """
    if verify_pq_consistency is None:
        verify_pq_consistency = _PQ_CONSISTENCY_DEFAULT
    der = _as_der(data, "PRIVATE KEY")
    outer = DerReader(der)
    seq = outer.read_sequence()
    outer.finish()

    version = seq.read_integer()
    if version not in (_PKCS8_V1, _PKCS8_V2):
        raise KeyFormatError(f"unsupported PKCS#8 version {version}")

    alg_id = seq.read_sequence()
    oid = alg_id.read_oid()

    if oid == "1.2.840.10045.2.1":
        if alg_id.peek_tag() is None:
            raise KeyFormatError("id-ecPublicKey requires a named-curve parameter")
        curve_oid = alg_id.read_oid()
        alg_id.finish()
        alg = _BY_CURVE_OID.get(curve_oid)
        if alg is None:
            raise UnsupportedKeyFormatError(f"EC curve OID {curve_oid} is not implemented")
    else:
        alg = _BY_OID.get(oid)
        if alg is None:
            raise UnsupportedKeyFormatError(f"algorithm OID {oid} is not implemented")
        if alg_id.peek_tag() is not None:
            raise KeyFormatError(
                f"{alg.name} AlgorithmIdentifier must have absent parameters"
            )
        alg_id.finish()

    inner_bytes = seq.read_octet_string()
    outer_public: bytes | None = None
    seed: bytes | None = None

    # Optional [0] attributes (parsed and discarded) and [1] publicKey.
    while (tag := seq.peek_tag()) is not None:
        if tag == 0xA0:
            seq.read_tagged(0)  # attributes: accepted for interop, not consumed
        elif tag in (0xA1, 0x81):
            body = seq.read_tagged(1, constructed=bool(tag & 0x20))
            outer_public = _read_implicit_bit_string(body, alg)
        else:
            raise KeyFormatError(f"unexpected PKCS#8 field with tag 0x{tag:02X}")
    seq.finish()

    # RFC 5958 §2 ties the version to the presence of the publicKey field:
    # "If publicKey is present, then version is set to v2 else version is set
    # to v1." Both directions are enforced, because accepting either mismatch
    # means one key has two valid encodings — the malleability defect class this
    # module's strictness exists to close, and the same reasoning as the
    # minimal-length and minimal-INTEGER rules in `_asn1`.
    #
    # Note this is about the *outer* [1] publicKey only. An EC key carries its
    # public half inside RFC 5915 ECPrivateKey, which RFC 5958 does not see and
    # which correctly leaves the version at v1 — which is what RFC 9500 §2.3's
    # keys and the rest of the vendored corpus contain.
    if (outer_public is not None) != (version == _PKCS8_V2):
        if outer_public is None:
            raise KeyFormatError(
                "PKCS#8 version is v2 but no [1] publicKey is present; RFC 5958 §2 "
                "sets v2 if and only if publicKey is present"
            )
        raise KeyFormatError(
            "PKCS#8 carries a [1] publicKey but the version is v1; RFC 5958 §2 "
            "requires v2 when publicKey is present"
        )

    if alg.kind == "ec":
        secret, embedded = _parse_ec_private_key(inner_bytes, alg)
        public = embedded or outer_public
    elif alg.kind == "okp":
        reader = DerReader(inner_bytes)
        secret = reader.read_octet_string()
        reader.finish()
        if len(secret) != alg.private_bytes:
            raise KeyFormatError(
                f"{alg.name} private key must be {alg.private_bytes} bytes, "
                f"got {len(secret)}"
            )
        public = outer_public
    else:
        secret, derived, seed = _parse_pq_private_key(
            inner_bytes, alg, verify_pq_consistency
        )

    if alg.kind != "pq":
        public = public or outer_public
        if public is not None:
            _check_public_matches(alg, secret, public)
        return PrivateKey(alg.name, secret, public, seed)

    if verify_pq_consistency:
        if derived is None:
            # An expandedKey-only PQ key carries no public half to check
            # against, so nothing above has looked at its internal consistency.
            # Do it here: RFC 9881 §8.2 and its Appendix C.4 vectors are about
            # exactly this case, and a key that fails is one whose signatures
            # verify under no public key at all (ML-DSA) or that silently
            # derives the wrong shared secret (ML-KEM).
            derived = _derive_public(alg, secret)
        # `derived` is now known to correspond to `secret` — it came out of the
        # same keygen, or out of the check above. A public key the *file*
        # carries is therefore checked by comparing bytes, not by deriving a
        # second time: the previous shape re-ran the full expansion here, so a
        # seed-form key paid for two key generations to learn one fact.
        if outer_public is not None and outer_public != derived:
            raise KeyFormatError(
                f"{alg.name} key file is inconsistent: the private key does not "
                "correspond to the public key it carries"
            )
        return PrivateKey(alg.name, secret, derived, seed)

    # Policy says skip the cryptographic checks. `derived` is None here by
    # construction: with checks off, _parse_pq_private_key returns no derived
    # public key for the expandedKey and both arms, and the seed arm's expansion
    # is decoding rather than checking.
    public = derived if derived is not None else outer_public

    # Two things still hold, both for free — see set_pq_import_consistency for
    # the full contract.
    #
    # 1. FIPS 203 §7.1 lays dk out as `dk_PKE || ek || H(ek) || z`, so ML-KEM's
    #    encapsulation key is present verbatim and needs no recomputation. A
    #    key still imports with a usable public half.
    # 2. If the file *also* carries a public key, it must equal that embedded
    #    one. Comparing two byte strings costs nothing and still catches a file
    #    assembled from two different keys.
    #
    # ML-DSA has no such shortcut — rho/s1/s2 determine the public key only by
    # recomputing it — so its public half stays None and PrivateKey.public()
    # derives (and checks) on first use.
    if alg.pq_family == "ml-kem":
        embedded = _ml_kem_embedded_public_key(alg, secret)
        if public is not None and public != embedded:
            raise KeyFormatError(
                f"{alg.name} key file is inconsistent: the public key it carries "
                "is not the encapsulation key embedded in its own decapsulation key"
            )
        public = embedded
    else:
        public = None
    return PrivateKey(alg.name, secret, public, seed)


def _ml_kem_embedded_public_key(alg: _Alg, secret: bytes) -> bytes:
    """Slice ``ek`` out of an ML-KEM ``dk`` (FIPS 203 §7.1).

    ``dk = dk_PKE || ek || H(ek) || z``, and the trailing two fields are 32
    octets each, so the offset follows from the registry's own sizes rather
    than a second transcription of ``384k``. ``test_registry_sizes_agree_with_
    the_native_backend`` already pins those sizes against the C library.
    """
    offset = alg.private_bytes - alg.public_bytes - 64
    if offset < 0:  # pragma: no cover - the registry is checked against the backend
        raise KeyFormatError(f"{alg.name} key sizes are inconsistent")
    embedded = secret[offset : offset + alg.public_bytes]
    # Cheap enough to stay on even when the expensive checks are off: this is a
    # scan of 256k coefficients, not an encapsulation. With the checks *on* the
    # pairwise round trip covers it, because encapsulation performs §7.2 itself.
    _validate_pq_public(alg, embedded)
    return embedded


def _read_implicit_bit_string(reader: DerReader, alg: _Alg) -> bytes:
    """Read the [1] publicKey field, which is an IMPLICIT BIT STRING."""
    raw = reader._buf[reader._pos : reader._end]  # noqa: SLF001 -- implicit tagging strips the BIT STRING header, so the octets must be read directly (KF-001)
    if not raw:
        raise KeyFormatError("empty PKCS#8 publicKey field")
    if raw[0] != 0x00:
        raise KeyFormatError("PKCS#8 publicKey BIT STRING has unused bits")
    payload = raw[1:]
    if alg.kind == "ec":
        return _decode_sec1_point(alg, payload)
    if len(payload) != alg.public_bytes:
        raise KeyFormatError(
            f"{alg.name} public key must be {alg.public_bytes} bytes, got {len(payload)}"
        )
    _validate_pq_public(alg, payload)
    return payload


def _parse_ec_private_key(inner: bytes, alg: _Alg) -> tuple[bytes, bytes | None]:
    """Parse RFC 5915 ECPrivateKey."""
    reader = DerReader(inner)
    seq = reader.read_sequence()
    reader.finish()

    if seq.read_integer() != 1:
        raise KeyFormatError("ECPrivateKey version must be 1 (RFC 5915 §3)")
    secret = seq.read_octet_string()
    if len(secret) != alg.field_bytes:
        raise KeyFormatError(
            f"{alg.name} private key must be {alg.field_bytes} bytes, got {len(secret)}"
        )

    public: bytes | None = None
    while (tag := seq.peek_tag()) is not None:
        if tag == 0xA0:
            params = seq.read_tagged(0)
            curve_oid = params.read_oid()
            params.finish()
            if curve_oid != alg.ec_curve_oid:
                raise KeyFormatError(
                    "ECPrivateKey named curve disagrees with the "
                    "AlgorithmIdentifier — the key names two different curves"
                )
        elif tag == 0xA1:
            body = seq.read_tagged(1)
            public = _decode_sec1_point(alg, body.read_bit_string())
            body.finish()
        else:
            raise KeyFormatError(f"unexpected ECPrivateKey field tag 0x{tag:02X}")
    seq.finish()
    return secret, public


def _parse_pq_private_key(
    inner: bytes, alg: _Alg, verify_consistency: bool = True
) -> tuple[bytes, bytes | None, bytes | None]:
    """Parse the ML-DSA / ML-KEM private-key CHOICE (RFC 9881 §6).

    Returns ``(expanded_key, public_key_or_None, seed_or_None)``.

    Three arms are accepted: ``[0] seed``, a bare ``expandedKey`` OCTET STRING,
    and the ``both`` SEQUENCE. RFC 9881 §6 is explicit that the arm is selected
    by the ASN.1 tag — ``0x80``, ``0x04``, ``0x30`` — "rather than any other
    heuristic like length of the enclosing OCTET STRING", which is what this
    does.

    The seed arm is genuinely supported: it is expanded through the
    deterministic keygen entry point, so importing a seed yields a working key
    rather than an opaque blob. That expansion is unconditional and is *not*
    governed by ``verify_consistency``: with only a seed on hand there is no
    expanded key to return without it, so it is decoding rather than checking.

    When both arms are present they are required to agree — RFC 9881 §8.2 makes
    that check a SHOULD and says an inconsistent key MUST be rejected as
    malformed. That one *is* governed by ``verify_consistency``, because the
    ``expandedKey`` is usable on its own.
    """
    reader = DerReader(inner)
    tag = reader.peek_tag()
    if tag is None:
        raise KeyFormatError(f"empty {alg.name} private key")

    if tag == 0x80:  # [0] IMPLICIT seed — the tag replaces the OCTET STRING's
        body = reader.read_tagged(0, constructed=False)
        seed = body._buf[body._pos : body._end]  # noqa: SLF001 -- IMPLICIT [0] OCTET STRING carries no inner header (KF-002)
        reader.finish()
        expanded, public = _expand_pq_seed(alg, seed)
        return expanded, public, seed

    if tag == 0x04:  # expandedKey
        expanded = reader.read_octet_string()
        reader.finish()
        if len(expanded) != alg.private_bytes:
            raise KeyFormatError(
                f"{alg.name} expanded key must be {alg.private_bytes} bytes, "
                f"got {len(expanded)}"
            )
        return expanded, None, None

    if tag == 0x30:  # both
        seq = reader.read_sequence()
        reader.finish()
        seed = seq.read_octet_string()
        expanded = seq.read_octet_string()
        seq.finish()
        if len(seed) != alg.pq_seed_bytes:
            raise KeyFormatError(
                f"{alg.name} seed must be {alg.pq_seed_bytes} bytes, got {len(seed)}"
            )
        if len(expanded) != alg.private_bytes:
            raise KeyFormatError(
                f"{alg.name} expanded key must be {alg.private_bytes} bytes, "
                f"got {len(expanded)}"
            )
        if not verify_consistency:
            return expanded, None, seed
        from_seed, public = _expand_pq_seed(alg, seed)
        if from_seed != expanded:
            raise KeyFormatError(
                f"{alg.name} 'both' private key is inconsistent: the seed does "
                "not expand to the supplied expandedKey (RFC 9881 §8.2)"
            )
        return expanded, public, seed

    raise KeyFormatError(f"unrecognised {alg.name} private-key CHOICE tag 0x{tag:02X}")


def _expand_pq_seed(alg: _Alg, seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != alg.pq_seed_bytes:
        raise KeyFormatError(
            f"{alg.name} seed must be {alg.pq_seed_bytes} bytes, got {len(seed)}"
        )
    if alg.pq_family == "ml-dsa":
        public, secret = _pb.native_ml_dsa_keypair_from_seed(alg.pq_set, seed)
    else:
        public, secret = _pb.native_ml_kem_keypair_from_seed(
            alg.pq_set, seed[:32], seed[32:]
        )
    return secret, public


def _check_public_matches(alg: _Alg, secret: bytes, public: bytes) -> None:
    """A key file that carries both halves must not disagree about them.

    A mismatch is never benign: it is either corruption or a file assembled
    from two different keys, and importing it would produce signatures nobody
    can verify.
    """
    if _derive_public(alg, secret) != public:
        raise KeyFormatError(
            f"{alg.name} key file is inconsistent: the private key does not "
            "correspond to the public key it carries"
        )


def _as_der(data: Union[bytes, str], label: str) -> bytes:
    if isinstance(data, str):
        return decode_pem(data, label)[1]
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        if raw[:5] == b"-----":
            # A caller who read a key file in binary mode gets the same answer
            # as one who read it as text. But `bytes.decode("ascii")` raises
            # UnicodeDecodeError — a ValueError subclass, not a KeyFormatError —
            # so a file that begins with a PEM header and then contains a
            # non-ASCII octet escaped this layer entirely. Anything a caller
            # cannot reasonably catch is a defect here, not an edge case: the
            # whole point of a single error type is that `except KeyFormatError`
            # is sufficient at the boundary. Found by
            # fuzz/python/fuzz_key_formats.py.
            try:
                text = raw.decode("ascii", "strict")
            except UnicodeDecodeError as exc:
                raise KeyFormatError(
                    f"PEM text must be ASCII (RFC 7468 §2): {exc}"
                ) from None
            return decode_pem(text, label)[1]
        return raw
    raise KeyFormatError(f"expected bytes or a PEM string, got {type(data).__name__}")


# ---------------------------------------------------------------------------
# JWK — RFC 7517 / 7518 / 8037 / 8812
# ---------------------------------------------------------------------------
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise KeyFormatError(f"JWK member {field!r} must be a string")
    if value != value.strip() or "=" in value or "+" in value or "/" in value:
        raise KeyFormatError(
            f"JWK member {field!r} is not unpadded base64url (RFC 7515 §2)"
        )
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise KeyFormatError(f"JWK member {field!r} is not valid base64url: {exc}") from None


def _require_jwk_support(alg: _Alg, fmt: str) -> None:
    if alg.kind == "pq":
        raise UnsupportedKeyFormatError(
            f"{alg.name} has no standardised {fmt} encoding. The JOSE and COSE "
            "registrations for ML-DSA and ML-KEM were drafts when this was "
            "written; emitting a guess would produce keys that interoperate "
            "with nothing. Use SPKI or PKCS#8 for these algorithms."
        )


def public_key_to_jwk(key: PublicKey) -> dict[str, Any]:
    """Encode a public key as a JWK (RFC 7518 §6 / RFC 8037 §2)."""
    _require_public(key)
    alg = _lookup(key.algorithm)
    _require_jwk_support(alg, "JWK")
    if alg.kind == "okp":
        return {"kty": "OKP", "crv": alg.okp_crv, "x": _b64u(key.key)}
    half = alg.field_bytes
    return {
        "kty": "EC",
        "crv": alg.jwk_crv,
        "x": _b64u(key.key[:half]),
        "y": _b64u(key.key[half:]),
    }


def private_key_to_jwk(key: PrivateKey) -> dict[str, Any]:
    """Encode a private key as a JWK — includes the public members per RFC 7518."""
    alg = _lookup(key.algorithm)
    _require_jwk_support(alg, "JWK")
    jwk = public_key_to_jwk(key.public())
    jwk["d"] = _b64u(key.key)
    return jwk


def jwk_to_public_key(jwk: Union[dict[str, Any], str]) -> PublicKey:
    """Parse a JWK public key, rejecting one that carries a private member."""
    obj = _load_jwk(jwk)
    if "d" in obj:
        raise KeyFormatError(
            "this JWK carries a private key member 'd'; use jwk_to_private_key"
        )
    alg, members = _jwk_algorithm(obj)
    return PublicKey(alg.name, _jwk_public_bytes(alg, obj, members))


def jwk_to_private_key(jwk: Union[dict[str, Any], str]) -> PrivateKey:
    """Parse a JWK private key."""
    obj = _load_jwk(jwk)
    if "d" not in obj:
        raise KeyFormatError("JWK has no private key member 'd'")
    alg, members = _jwk_algorithm(obj)
    secret = _unb64u(obj["d"], "d")
    expected = alg.private_bytes if alg.kind == "okp" else alg.field_bytes
    if len(secret) != expected:
        raise KeyFormatError(
            f"{alg.name} JWK 'd' must be {expected} bytes, got {len(secret)}"
        )
    public = _jwk_public_bytes(alg, obj, members)
    _check_public_matches(alg, secret, public)
    return PrivateKey(alg.name, secret, public)


def _load_jwk(jwk: Union[dict[str, Any], str]) -> dict[str, Any]:
    if isinstance(jwk, str):
        try:
            obj = json.loads(jwk)
        except json.JSONDecodeError as exc:
            raise KeyFormatError(f"invalid JWK JSON: {exc}") from None
    else:
        obj = jwk
    if not isinstance(obj, dict):
        raise KeyFormatError("a JWK must be a JSON object")
    return obj


def _jwk_algorithm(obj: dict[str, Any]) -> tuple[_Alg, tuple[str, ...]]:
    kty = obj.get("kty")
    crv = obj.get("crv")
    # A JWK is parsed JSON, so `crv` can be any JSON type. Only a string can
    # name a curve; anything else is "not implemented" rather than a lookup
    # against a non-string key.
    if not isinstance(crv, str):
        crv = ""
    if kty == "OKP":
        alg = _OKP_CRV_TO_ALG.get(crv)
        if alg is None:
            raise UnsupportedKeyFormatError(f"OKP curve {crv!r} is not implemented")
        return alg, ("x",)
    if kty == "EC":
        alg = _JWK_CRV_TO_ALG.get(crv)
        if alg is None:
            raise UnsupportedKeyFormatError(f"EC curve {crv!r} is not implemented")
        return alg, ("x", "y")
    if kty in ("RSA", "oct"):
        raise UnsupportedKeyFormatError(f"JWK key type {kty!r} is not implemented")
    raise KeyFormatError(f"JWK 'kty' is missing or unrecognised: {kty!r}")


def _jwk_public_bytes(alg: _Alg, obj: dict[str, Any], members: tuple[str, ...]) -> bytes:
    parts = []
    for member in members:
        if member not in obj:
            raise KeyFormatError(f"JWK is missing required member {member!r}")
        raw = _unb64u(obj[member], member)
        width = alg.public_bytes if alg.kind == "okp" else alg.field_bytes
        if len(raw) != width:
            # RFC 7518 §6.2.1.2 is explicit that coordinates are fixed-width
            # and zero-padded; a short value is a different (invalid) key.
            raise KeyFormatError(
                f"{alg.name} JWK member {member!r} must be {width} bytes, got {len(raw)}"
            )
        parts.append(raw)
    public = b"".join(parts)
    if alg.kind == "ec":
        _validate_ec_public(alg, public)
    return public


def _validate_ec_public(alg: _Alg, public: bytes) -> None:
    """Prove an ``X || Y`` pair is a usable public key on ``alg``'s curve."""
    if alg.name == "secp256k1":
        # There is no separate secp256k1 validator, so the decompressor is
        # used as one: it refuses a non-canonical X and an X that is not on the
        # curve, and it *recomputes* Y from X and the requested parity. So
        # requiring the recomputed point to equal the supplied one proves both
        # coordinates — a Y that is wrong, or non-canonical, or the other root,
        # produces a different answer and is rejected.
        prefix = bytes([0x02 | (public[-1] & 1)])
        try:
            recovered = _pb.native_secp256k1_pubkey_decompress(
                prefix + public[: alg.field_bytes]
            )
        except ValueError as exc:
            raise KeyFormatError(f"invalid secp256k1 public key: {exc}") from None
        if recovered != public:
            raise KeyFormatError(
                "secp256k1 public key is not a valid curve point: its Y is not "
                "the coordinate its X implies"
            )
        return
    if not _pb.native_nistp_pubkey_validate(alg.ec_curve, public):
        raise KeyFormatError(f"{alg.name} public key is not a valid curve point")


def jwk_thumbprint(jwk: Union[dict[str, Any], str], *, hash_name: str = "sha256") -> bytes:
    """RFC 7638 JWK thumbprint.

    Built from the required members only, in lexicographic order, with no
    whitespace — which is what makes the value stable across encoders. Private
    members are excluded by construction: a thumbprint must be the same for a
    key and its public half.
    """
    obj = _load_jwk(jwk)
    alg, members = _jwk_algorithm(obj)
    required = ("crv", *members, "kty") if alg.kind else ()
    canonical = {name: obj[name] for name in sorted(required) if name in obj}
    missing = set(required) - set(canonical)
    if missing:
        raise KeyFormatError(f"JWK is missing thumbprint members {sorted(missing)}")
    payload = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    try:
        digest = hashlib.new(hash_name)
    except ValueError:
        raise KeyFormatError(f"unknown hash {hash_name!r} for a JWK thumbprint") from None
    digest.update(payload)
    return digest.digest()


# ---------------------------------------------------------------------------
# COSE_Key — RFC 9052 §7 / RFC 9053 §7 / RFC 8812
# ---------------------------------------------------------------------------
def public_key_to_cose(key: PublicKey) -> bytes:
    """Encode a public key as a deterministically-encoded COSE_Key."""
    _require_public(key)
    alg = _lookup(key.algorithm)
    _require_jwk_support(alg, "COSE")
    if alg.kind == "okp":
        return cbor_encode_canonical(
            {_COSE_LBL_KTY: _COSE_KTY_OKP, _COSE_LBL_CRV: alg.cose_crv,
             _COSE_LBL_X: key.key}
        )
    half = alg.field_bytes
    return cbor_encode_canonical(
        {_COSE_LBL_KTY: _COSE_KTY_EC2, _COSE_LBL_CRV: alg.cose_crv,
         _COSE_LBL_X: key.key[:half], _COSE_LBL_Y: key.key[half:]}
    )


def private_key_to_cose(key: PrivateKey) -> bytes:
    """Encode a private key as a COSE_Key with the ``d`` (-4) member."""
    alg = _lookup(key.algorithm)
    _require_jwk_support(alg, "COSE")
    decoded = cbor_decode_canonical(public_key_to_cose(key.public()))
    decoded[_COSE_LBL_D] = key.key
    return cbor_encode_canonical(decoded)


def cose_to_public_key(data: bytes) -> PublicKey:
    """Parse a COSE_Key public key, rejecting one that carries ``d``."""
    obj = _load_cose(data)
    if _COSE_LBL_D in obj:
        raise KeyFormatError(
            "this COSE_Key carries a private key member (-4); use cose_to_private_key"
        )
    alg = _cose_algorithm(obj)
    return PublicKey(alg.name, _cose_public_bytes(alg, obj))


def cose_to_private_key(data: bytes) -> PrivateKey:
    """Parse a COSE_Key private key."""
    obj = _load_cose(data)
    if _COSE_LBL_D not in obj:
        raise KeyFormatError("COSE_Key has no private key member (-4)")
    alg = _cose_algorithm(obj)
    secret = obj[_COSE_LBL_D]
    if not isinstance(secret, bytes):
        raise KeyFormatError("COSE_Key member -4 must be a byte string")
    expected = alg.private_bytes if alg.kind == "okp" else alg.field_bytes
    if len(secret) != expected:
        raise KeyFormatError(
            f"{alg.name} COSE_Key member -4 must be {expected} bytes, got {len(secret)}"
        )
    public = _cose_public_bytes(alg, obj)
    _check_public_matches(alg, secret, public)
    return PrivateKey(alg.name, secret, public)


def _load_cose(data: bytes) -> dict[Any, Any]:
    obj = cbor_decode_canonical(data)
    if not isinstance(obj, dict):
        raise KeyFormatError("a COSE_Key must be a CBOR map")
    return obj


def _cose_algorithm(obj: dict[Any, Any]) -> _Alg:
    kty = obj.get(_COSE_LBL_KTY)
    crv = obj.get(_COSE_LBL_CRV)
    # A COSE_Key is decoded CBOR, so `crv` can be any CBOR value — including a
    # nested map or array, which are *unhashable* in Python and made the
    # dictionary lookup below raise `TypeError: unhashable type: 'dict'`. That
    # escaped the format layer entirely: a caller doing `except KeyFormatError`
    # around a key import got a TypeError instead, from a byte string an
    # attacker chose. Only an integer names a COSE curve; anything else is "not
    # implemented" rather than a lookup against a value that cannot be a key.
    #
    # `_jwk_algorithm` already carried this fix for the JSON side, where `crv`
    # can be any JSON type. The CBOR side did not — the same defect, one format
    # over. Found by fuzz/python/fuzz_key_formats.py.
    if isinstance(crv, bool) or not isinstance(crv, int):
        crv = None
    if kty == _COSE_KTY_OKP:
        alg = _COSE_OKP_TO_ALG.get(crv)
        if alg is None:
            raise UnsupportedKeyFormatError(f"COSE OKP curve {crv!r} is not implemented")
        return alg
    if kty == _COSE_KTY_EC2:
        alg = _COSE_EC2_TO_ALG.get(crv)
        if alg is None:
            raise UnsupportedKeyFormatError(f"COSE EC2 curve {crv!r} is not implemented")
        return alg
    raise KeyFormatError(f"COSE_Key 'kty' (1) is missing or unrecognised: {kty!r}")


def _cose_public_bytes(alg: _Alg, obj: dict[Any, Any]) -> bytes:
    def member(label: int, width: int) -> bytes:
        if label not in obj:
            raise KeyFormatError(f"COSE_Key is missing required member {label}")
        raw = obj[label]
        if not isinstance(raw, bytes):
            raise KeyFormatError(f"COSE_Key member {label} must be a byte string")
        if len(raw) != width:
            raise KeyFormatError(
                f"{alg.name} COSE_Key member {label} must be {width} bytes, got {len(raw)}"
            )
        return raw

    if alg.kind == "okp":
        # A COSE_Key is an open map and a label this module does not consume —
        # `kid`, `alg` — must not make it unparseable. `y` (-3) is different in
        # kind: RFC 9053 §7 assigns it to the EC2 key type only, and an OKP key
        # has no y coordinate at all. Its presence does not mean "a label we do
        # not use", it means the file claims one key type and carries another's
        # material.
        #
        # Accepting it and dropping it gave one X25519 key two encodings — the
        # malleability class this module's strictness exists to close — and
        # invited a reader that keys off -3 rather than off kty to see an EC2
        # key where AMA sees an OKP one. Found by
        # fuzz/python/fuzz_key_formats.py.
        if _COSE_LBL_Y in obj:
            raise KeyFormatError(
                f"{alg.name} is an OKP key, but this COSE_Key carries the EC2 "
                "'y' member (-3); the map contradicts its own 'kty'"
            )
        return member(_COSE_LBL_X, alg.public_bytes)
    public = member(_COSE_LBL_X, alg.field_bytes) + member(_COSE_LBL_Y, alg.field_bytes)
    _validate_ec_public(alg, public)
    return public
