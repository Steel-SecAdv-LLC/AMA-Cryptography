#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Agent-instance key and signature binding
========================================

Thin, fail-closed Python surface over the native binding layer in
``src/c/ama_agent_binding.c``.  Every policy decision and every byte of the
canonical encoding is produced in C; this module marshals arguments, refuses
malformed input before it reaches the boundary (INVARIANT-5), and translates
``AMA_ERROR_ETHICAL_BINDING`` into :class:`EthicalBindingError`.

Why this exists
---------------
An autonomous agent driving a crypto library wants two things ordinary callers
do not: key material that outlives the agent instance, and signatures a *later*
instance would treat as authoritative.  Those are the primitives behind
persistence and self-replication; per-message signing and ephemeral session
keys are not.

A binding names an agent instance, the lifetime of the material it may derive,
and the capabilities it may exercise.  Restricted capabilities — persistence,
self-replication, delegation — and any lifetime beyond ``EPHEMERAL`` require an
authorization tag that only the holder of the operator's authority key can
produce.  The binding is folded into HKDF's ``info`` and into the ML-DSA /
SLH-DSA signature context, so material derived under one binding is
cryptographically unrelated to material derived under any other, including one
that differs in a single capability bit.

Usage
-----
Ordinary ephemeral use needs no key and no profile::

    from ama_cryptography.agent_binding import AgentBinding, AgentCapability

    b = AgentBinding(instance_id=os.urandom(32),
                     capabilities=AgentCapability.DATA_SIGN)
    session_key = b.derive_key(ikm, 32, info=b"session")

Persistence requires the operator::

    b = AgentBinding(instance_id=iid,
                     lifetime=AgentLifetime.PERSISTENT,
                     capabilities=AgentCapability.PERSISTENCE,
                     ethical_profile_hash=sha3_256(profile_document))
    b.authorize(authority_key)              # operator-side; needs K_auth
    root = b.derive_key(ikm, 32, authority_key=authority_key)

Without ``authorize()`` the last call raises :class:`EthicalBindingError` and
writes nothing.
"""

from __future__ import annotations

import ctypes
import enum
from typing import Any, Optional, Union

from ama_cryptography.exceptions import AmaCryptographyError

__all__ = [
    "AGENT_BINDING_AVAILABLE",
    "AGENT_BINDING_ENCODED_BYTES",
    "AGENT_INSTANCE_ID_BYTES",
    "AUTHORITY_KEY_MIN_BYTES",
    "AgentBinding",
    "AgentCapability",
    "AgentLifetime",
    "EthicalBindingError",
    "ETHICAL_PROFILE_BYTES",
    "SIGNATURE_CONTEXT_BYTES",
]

# Mirrors the constants in include/ama_cryptography.h.  Duplicated rather than
# read from the library because they are part of this module's own input
# validation, which must work even when the native library is absent.
AGENT_INSTANCE_ID_BYTES = 32
ETHICAL_PROFILE_BYTES = 32
AGENT_BINDING_TAG_BYTES = 32
AGENT_BINDING_ENCODED_BYTES = 88
SIGNATURE_CONTEXT_BYTES = 32

#: Authority keys below 256 bits are refused — a shorter key would put the
#: whole construction under the security level it claims.
AUTHORITY_KEY_MIN_BYTES = 32

#: RFC 5869 §2.3 bound for the HMAC-SHA3-256 PRF (255 * 32).
_HKDF_MAX_OUTPUT = 8160

_AMA_SUCCESS = 0
_AMA_ERROR_INVALID_PARAM = -1
_AMA_ERROR_ETHICAL_BINDING = -9

_BufferInput = Union[bytes, bytearray, memoryview]


class EthicalBindingError(AmaCryptographyError):
    """Raised when the agent-instance binding policy refuses a request.

    The arguments were well-formed; the *policy* said no.  Typical causes:
    a restricted capability or non-ephemeral lifetime with no operator
    authorization, an absent ethical profile, or an authorization tag that
    does not verify under the supplied authority key.
    """


class AgentLifetime(enum.IntEnum):
    """How long material derived under a binding may live.

    ``SESSION`` and ``PERSISTENT`` both outlive a single operation and are
    therefore restricted: they require operator authorization.
    """

    EPHEMERAL = 0
    SESSION = 1
    PERSISTENT = 2


class AgentCapability(enum.IntFlag):
    """What a bound agent instance may do.

    ``PERSISTENCE``, ``SELF_REPLICATE`` and ``DELEGATE`` form the restricted
    set; requesting any of them requires operator authorization.
    """

    NONE = 0x00
    DATA_SIGN = 0x01
    KEY_EXCHANGE = 0x02
    PERSISTENCE = 0x04
    SELF_REPLICATE = 0x08
    DELEGATE = 0x10

    @classmethod
    def restricted_mask(cls) -> AgentCapability:
        """Capability bits that cannot be exercised without authorization."""
        return cls.PERSISTENCE | cls.SELF_REPLICATE | cls.DELEGATE

    @classmethod
    def known_mask(cls) -> AgentCapability:
        """Every capability bit this version defines."""
        return cls.DATA_SIGN | cls.KEY_EXCHANGE | cls.restricted_mask()


class _CAgentBinding(ctypes.Structure):
    """Byte-for-byte mirror of ``ama_agent_binding_t``.

    All fields are ``uint8_t`` or ``uint8_t[]``, so the struct has alignment 1
    and no padding on any supported ABI; ``sizeof`` is asserted against the
    expected 4 + 32 + 32 + 32 = 100 bytes at import time.
    """

    _pack_ = 1
    _fields_ = [
        ("version", ctypes.c_uint8),
        ("lifetime", ctypes.c_uint8),
        ("capabilities", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("instance_id", ctypes.c_uint8 * AGENT_INSTANCE_ID_BYTES),
        ("ethical_profile", ctypes.c_uint8 * ETHICAL_PROFILE_BYTES),
        ("authorization", ctypes.c_uint8 * AGENT_BINDING_TAG_BYTES),
    ]


def _setup_agent_binding_ctypes(lib: Any) -> bool:
    """Bind the native entry points.  Returns False when they are absent."""
    try:
        lib.ama_agent_binding_init.argtypes = [
            ctypes.POINTER(_CAgentBinding),
            ctypes.c_int,  # ama_agent_lifetime_t
            ctypes.c_uint8,  # capabilities
            ctypes.c_void_p,  # instance_id
            ctypes.c_void_p,  # ethical_profile (may be NULL)
        ]
        lib.ama_agent_binding_init.restype = ctypes.c_int

        lib.ama_agent_binding_encode.argtypes = [
            ctypes.POINTER(_CAgentBinding),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.ama_agent_binding_encode.restype = ctypes.c_int

        lib.ama_agent_binding_authorize.argtypes = [
            ctypes.POINTER(_CAgentBinding),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.ama_agent_binding_authorize.restype = ctypes.c_int

        lib.ama_agent_binding_check.argtypes = [
            ctypes.POINTER(_CAgentBinding),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.ama_agent_binding_check.restype = ctypes.c_int

        lib.ama_agent_binding_context.argtypes = [
            ctypes.POINTER(_CAgentBinding),
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        lib.ama_agent_binding_context.restype = ctypes.c_int

        lib.ama_hkdf_agent_bound.argtypes = [
            ctypes.POINTER(_CAgentBinding),
            ctypes.c_void_p,  # authority_key
            ctypes.c_size_t,  # key_len
            ctypes.c_void_p,  # salt
            ctypes.c_size_t,
            ctypes.c_void_p,  # ikm
            ctypes.c_size_t,
            ctypes.c_void_p,  # info
            ctypes.c_size_t,
            ctypes.c_void_p,  # okm
            ctypes.c_size_t,
        ]
        lib.ama_hkdf_agent_bound.restype = ctypes.c_int
        return True
    except AttributeError:
        return False


# The native library is located once, by pqc_backends' loader, so there is a
# single search-path policy in the tree.  Importing pqc_backends here is cheap
# relative to what this module does and keeps the loader from being duplicated.
_lib: Any = None
try:
    from ama_cryptography import pqc_backends as _pqc

    _lib = _pqc._native_lib
except Exception:  # pragma: no cover - defensive; pqc_backends never raises
    _lib = None

#: True when the native binding layer is present and callable.
AGENT_BINDING_AVAILABLE: bool = bool(_lib is not None and _setup_agent_binding_ctypes(_lib))

if ctypes.sizeof(_CAgentBinding) != 4 + 3 * 32:
    # A padded struct would silently mis-marshal every field after `reserved`.
    raise AssertionError(
        f"_CAgentBinding is {ctypes.sizeof(_CAgentBinding)} bytes, expected 100; "
        "the ctypes mirror has drifted from ama_agent_binding_t"
    )


def _require_native() -> Any:
    if not AGENT_BINDING_AVAILABLE:
        raise EthicalBindingError(
            "AGENT_BINDING_UNAVAILABLE: native agent-binding layer not built. "
            "Build: cmake -B build -DAMA_USE_NATIVE_PQC=ON && cmake --build build"
        )
    return _lib


def _as_bytes(name: str, value: _BufferInput, expected: Optional[int] = None) -> bytes:
    """Validate and normalise a byte-like argument (INVARIANT-5)."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like, got {type(value).__name__}")
    out = bytes(value)
    if expected is not None and len(out) != expected:
        raise ValueError(f"{name} must be exactly {expected} bytes, got {len(out)}")
    return out


def _raise_for_rc(rc: int, operation: str) -> None:
    if rc == _AMA_SUCCESS:
        return
    if rc == _AMA_ERROR_ETHICAL_BINDING:
        raise EthicalBindingError(
            f"ETHICAL_BINDING_REFUSED: {operation} refused by the agent-instance "
            "binding policy (restricted capability or non-ephemeral lifetime "
            "without a verifying operator authorization)"
        )
    if rc == _AMA_ERROR_INVALID_PARAM:
        raise ValueError(f"{operation} rejected invalid parameters (rc={rc})")
    raise AmaCryptographyError(f"{operation} failed (rc={rc})")


class AgentBinding:
    """An agent-instance binding.

    Construction validates the record and fills the native struct; the
    authorization tag starts empty.  Instances are cheap to copy via
    :meth:`replace`.

    Args:
        instance_id: 32-byte opaque identifier for this agent instance.
        lifetime: :class:`AgentLifetime` (default ``EPHEMERAL``).
        capabilities: :class:`AgentCapability` bits (default ``DATA_SIGN``).
        ethical_profile_hash: 32-byte SHA3-256 of the operator's authorized
            ethical profile document, or ``None`` for "absent".  Required for
            any restricted binding.

    Raises:
        TypeError / ValueError: on malformed arguments.
        EthicalBindingError: when the native layer is unavailable.
    """

    __slots__ = ("_c",)

    def __init__(
        self,
        instance_id: _BufferInput,
        lifetime: AgentLifetime = AgentLifetime.EPHEMERAL,
        capabilities: AgentCapability = AgentCapability.DATA_SIGN,
        ethical_profile_hash: Optional[_BufferInput] = None,
    ) -> None:
        lib = _require_native()

        iid = _as_bytes("instance_id", instance_id, AGENT_INSTANCE_ID_BYTES)
        if not isinstance(lifetime, AgentLifetime):
            lifetime = AgentLifetime(int(lifetime))
        caps = int(capabilities)
        if caps & ~int(AgentCapability.known_mask()):
            raise ValueError(
                f"capabilities 0x{caps:02x} sets bits this version does not define "
                f"(known mask 0x{int(AgentCapability.known_mask()):02x})"
            )

        profile: Optional[bytes] = None
        if ethical_profile_hash is not None:
            profile = _as_bytes("ethical_profile_hash", ethical_profile_hash, ETHICAL_PROFILE_BYTES)

        self._c = _CAgentBinding()
        rc = lib.ama_agent_binding_init(
            ctypes.byref(self._c),
            ctypes.c_int(int(lifetime)),
            ctypes.c_uint8(caps),
            iid,
            profile,
        )
        _raise_for_rc(rc, "agent binding init")

    # -- introspection ----------------------------------------------------

    @property
    def instance_id(self) -> bytes:
        return bytes(self._c.instance_id)

    @property
    def lifetime(self) -> AgentLifetime:
        return AgentLifetime(self._c.lifetime)

    @property
    def capabilities(self) -> AgentCapability:
        return AgentCapability(self._c.capabilities)

    @property
    def ethical_profile_hash(self) -> Optional[bytes]:
        """The profile hash, or ``None`` when absent (all-zero on the wire)."""
        raw = bytes(self._c.ethical_profile)
        return None if raw == bytes(ETHICAL_PROFILE_BYTES) else raw

    @property
    def authorization(self) -> Optional[bytes]:
        """The operator's tag, or ``None`` when the binding is unauthorized."""
        raw = bytes(self._c.authorization)
        return None if raw == bytes(AGENT_BINDING_TAG_BYTES) else raw

    @property
    def requires_authorization(self) -> bool:
        """True when this binding cannot be used without an authority key."""
        return bool(
            self._c.lifetime != int(AgentLifetime.EPHEMERAL)
            or (self._c.capabilities & int(AgentCapability.restricted_mask()))
        )

    def __repr__(self) -> str:
        return (
            f"AgentBinding(instance_id={self.instance_id[:4].hex()}…, "
            f"lifetime={self.lifetime.name}, "
            f"capabilities={self.capabilities!r}, "
            f"profile={'set' if self.ethical_profile_hash else 'absent'}, "
            f"authorized={self.authorization is not None})"
        )

    def replace(
        self,
        lifetime: Optional[AgentLifetime] = None,
        capabilities: Optional[AgentCapability] = None,
        ethical_profile_hash: Optional[_BufferInput] = None,
    ) -> AgentBinding:
        """Return a new, *unauthorized* binding with the given fields changed.

        The tag is deliberately not carried over: it covers the whole record,
        so a copy with different fields would carry a tag that cannot verify.
        """
        return AgentBinding(
            instance_id=self.instance_id,
            lifetime=self.lifetime if lifetime is None else lifetime,
            capabilities=self.capabilities if capabilities is None else capabilities,
            ethical_profile_hash=(
                self.ethical_profile_hash if ethical_profile_hash is None else ethical_profile_hash
            ),
        )

    # -- operations -------------------------------------------------------

    def encode(self) -> bytes:
        """Return the 88-byte canonical encoding (without the tag)."""
        lib = _require_native()
        buf = (ctypes.c_uint8 * AGENT_BINDING_ENCODED_BYTES)()
        rc = lib.ama_agent_binding_encode(
            ctypes.byref(self._c), buf, ctypes.c_size_t(AGENT_BINDING_ENCODED_BYTES)
        )
        _raise_for_rc(rc, "agent binding encode")
        return bytes(buf)

    def authorize(self, authority_key: _BufferInput) -> None:
        """Stamp the operator's authorization tag onto this binding, in place.

        Operator-side call.  Requires the authority key an agent does not hold.
        """
        lib = _require_native()
        key = _as_bytes("authority_key", authority_key)
        if len(key) < AUTHORITY_KEY_MIN_BYTES:
            raise ValueError(
                f"authority_key must be at least {AUTHORITY_KEY_MIN_BYTES} bytes, "
                f"got {len(key)}"
            )
        rc = lib.ama_agent_binding_authorize(ctypes.byref(self._c), key, ctypes.c_size_t(len(key)))
        _raise_for_rc(rc, "agent binding authorize")

    def check(self, authority_key: Optional[_BufferInput] = None) -> None:
        """Raise :class:`EthicalBindingError` unless the policy accepts.

        Unrestricted bindings pass with ``authority_key=None``.
        """
        lib = _require_native()
        key = None if authority_key is None else _as_bytes("authority_key", authority_key)
        rc = lib.ama_agent_binding_check(
            ctypes.byref(self._c), key, ctypes.c_size_t(0 if key is None else len(key))
        )
        _raise_for_rc(rc, "agent binding check")

    def is_permitted(self, authority_key: Optional[_BufferInput] = None) -> bool:
        """Non-raising form of :meth:`check`."""
        try:
            self.check(authority_key)
        except EthicalBindingError:
            return False
        return True

    def signing_context(self, authority_key: Optional[_BufferInput] = None) -> bytes:
        """Return the 32-byte context string for ML-DSA / SLH-DSA signing.

        Pass the result verbatim as the ``ctx`` argument so the signature is
        bound to this agent instance and capability set.  Refuses (and returns
        nothing) when the policy refuses.
        """
        lib = _require_native()
        key = None if authority_key is None else _as_bytes("authority_key", authority_key)
        out = (ctypes.c_uint8 * SIGNATURE_CONTEXT_BYTES)()
        rc = lib.ama_agent_binding_context(
            ctypes.byref(self._c),
            key,
            ctypes.c_size_t(0 if key is None else len(key)),
            out,
        )
        _raise_for_rc(rc, "agent binding signature context")
        return bytes(out)

    def derive_key(
        self,
        ikm: _BufferInput,
        length: int,
        salt: Optional[_BufferInput] = None,
        info: Optional[_BufferInput] = None,
        authority_key: Optional[_BufferInput] = None,
    ) -> bytes:
        """HKDF-SHA3-256 with this binding folded into ``info``.

        Args:
            ikm: Input key material.
            length: Output length, 1..8160.
            salt: Optional HKDF salt.
            info: Optional caller context, length-prefixed inside the
                derivation so it cannot imitate the binding prefix.
            authority_key: Required for restricted bindings.

        Raises:
            EthicalBindingError: when the policy refuses.  No bytes are
                produced.
        """
        lib = _require_native()
        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError(f"length must be int, got {type(length).__name__}")
        if length <= 0 or length > _HKDF_MAX_OUTPUT:
            raise ValueError(f"length must be 1..{_HKDF_MAX_OUTPUT}, got {length}")

        ikm_b = _as_bytes("ikm", ikm)
        salt_b = None if salt is None else _as_bytes("salt", salt)
        info_b = None if info is None else _as_bytes("info", info)
        key = None if authority_key is None else _as_bytes("authority_key", authority_key)

        out = (ctypes.c_uint8 * length)()
        rc = lib.ama_hkdf_agent_bound(
            ctypes.byref(self._c),
            key,
            ctypes.c_size_t(0 if key is None else len(key)),
            salt_b,
            ctypes.c_size_t(0 if salt_b is None else len(salt_b)),
            ikm_b,
            ctypes.c_size_t(len(ikm_b)),
            info_b,
            ctypes.c_size_t(0 if info_b is None else len(info_b)),
            out,
            ctypes.c_size_t(length),
        )
        _raise_for_rc(rc, "agent-bound HKDF")
        return bytes(out)
