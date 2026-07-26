#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Agent-instance binding — Python API and fail-closed policy
==========================================================

Companion to ``tests/c/test_agent_binding.c``.  The C test pins the canonical
encoding and the native policy; this one covers the Python surface, the
argument validation at the boundary (INVARIANT-5), and the four adversarial
scenarios from the July-2026 agent-escape pattern:

  * long-lived persistence material cannot be minted without operator
    authorization (``TestFailClosed``);
  * a signature intended to authorize a successor instance is domain-separated
    from ordinary data signing, and refused outright when unauthorized
    (``TestSelfReplicationBinding``);
  * relabelling or tampering with a binding after the fact buys nothing
    (``TestTamperResistance``);
  * derivation is injective over every field of the binding
    (``TestDomainSeparation``, property-based).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ama_cryptography.agent_binding import (
    AGENT_BINDING_AVAILABLE,
    AGENT_BINDING_ENCODED_BYTES,
    AGENT_INSTANCE_ID_BYTES,
    AUTHORITY_KEY_MIN_BYTES,
    SIGNATURE_CONTEXT_BYTES,
    AgentBinding,
    AgentCapability,
    AgentLifetime,
    EthicalBindingError,
)

pytestmark = pytest.mark.skipif(
    not AGENT_BINDING_AVAILABLE,
    reason="native agent-binding layer not built",
)

# Deterministic fixtures.  The suite is reproducible except where a test
# explicitly asks for fresh randomness.
INSTANCE_ID = bytes(range(32))
OTHER_INSTANCE_ID = bytes(range(1, 33))
PROFILE = hashlib.sha3_256(b"authorized-ethical-profile-v1").digest()
AUTHORITY_KEY = hashlib.sha3_256(b"operator-authority-key").digest()
FOREIGN_KEY = hashlib.sha3_256(b"agent-guessed-authority-key").digest()
IKM = hashlib.sha3_256(b"input-key-material").digest()

RESTRICTED = (
    AgentCapability.PERSISTENCE,
    AgentCapability.SELF_REPLICATE,
    AgentCapability.DELEGATE,
)


def ephemeral(**kwargs: Any) -> AgentBinding:
    """An ordinary, unrestricted binding — the common case."""
    params: dict[str, Any] = {
        "instance_id": INSTANCE_ID,
        "lifetime": AgentLifetime.EPHEMERAL,
        "capabilities": AgentCapability.DATA_SIGN,
    }
    params.update(kwargs)
    return AgentBinding(**params)


def persistent(authorized: bool = False, **kwargs: Any) -> AgentBinding:
    """The dangerous shape: material that outlives the agent instance."""
    params: dict[str, Any] = {
        "instance_id": INSTANCE_ID,
        "lifetime": AgentLifetime.PERSISTENT,
        "capabilities": AgentCapability.DATA_SIGN | AgentCapability.PERSISTENCE,
        "ethical_profile_hash": PROFILE,
    }
    params.update(kwargs)
    binding = AgentBinding(**params)
    if authorized:
        binding.authorize(AUTHORITY_KEY)
    return binding


class TestConstruction:
    """Record construction and introspection."""

    def test_ephemeral_defaults(self) -> None:
        b = AgentBinding(instance_id=INSTANCE_ID)
        assert b.lifetime is AgentLifetime.EPHEMERAL
        assert b.capabilities is AgentCapability.DATA_SIGN
        assert b.instance_id == INSTANCE_ID
        assert b.ethical_profile_hash is None
        assert b.authorization is None
        assert b.requires_authorization is False

    def test_requires_authorization_for_each_restricted_bit(self) -> None:
        for cap in RESTRICTED:
            b = AgentBinding(
                instance_id=INSTANCE_ID,
                capabilities=AgentCapability.DATA_SIGN | cap,
                ethical_profile_hash=PROFILE,
            )
            assert b.requires_authorization is True, cap

    def test_requires_authorization_for_non_ephemeral_lifetime(self) -> None:
        # SESSION carries no restricted capability bit at all; the lifetime
        # alone is the trigger.
        b = AgentBinding(
            instance_id=INSTANCE_ID,
            lifetime=AgentLifetime.SESSION,
            capabilities=AgentCapability.KEY_EXCHANGE,
            ethical_profile_hash=PROFILE,
        )
        assert b.requires_authorization is True

    def test_encoding_is_fixed_width_and_stable(self) -> None:
        b = ephemeral()
        enc = b.encode()
        assert len(enc) == AGENT_BINDING_ENCODED_BYTES
        assert enc == b.encode()
        assert enc.startswith(bytes([17]) + b"AMA-AGENT-BIND-v1")

    def test_repr_does_not_leak_the_tag(self) -> None:
        b = persistent(authorized=True)
        text = repr(b)
        assert b.authorization is not None
        assert b.authorization.hex() not in text
        assert "authorized=True" in text

    @pytest.mark.parametrize(
        "kwargs,exc",
        [
            ({"instance_id": b"short"}, ValueError),
            ({"instance_id": "not-bytes"}, TypeError),
            ({"instance_id": INSTANCE_ID, "ethical_profile_hash": b"short"}, ValueError),
            ({"instance_id": INSTANCE_ID, "capabilities": 0x80}, ValueError),
        ],
    )
    def test_boundary_validation(self, kwargs: dict, exc: type) -> None:
        with pytest.raises(exc):
            AgentBinding(**kwargs)

    def test_replace_drops_the_authorization(self) -> None:
        # The tag covers the whole record, so carrying it onto a modified
        # copy would produce something that can only ever fail the check.
        b = persistent(authorized=True)
        assert b.authorization is not None
        copy = b.replace(capabilities=AgentCapability.DATA_SIGN)
        assert copy.authorization is None


class TestFailClosed:
    """Unbound or unauthorized persistence material must not be produced."""

    def test_persistent_derivation_refused_without_authorization(self) -> None:
        b = persistent()
        with pytest.raises(EthicalBindingError):
            b.derive_key(IKM, 32)

    def test_persistent_derivation_refused_with_wrong_key(self) -> None:
        b = persistent(authorized=True)
        with pytest.raises(EthicalBindingError):
            b.derive_key(IKM, 32, authority_key=FOREIGN_KEY)

    def test_persistent_derivation_refused_when_profile_absent(self) -> None:
        # A restricted binding with nothing to point at cannot even be
        # authorized, let alone used.
        b = AgentBinding(
            instance_id=INSTANCE_ID,
            lifetime=AgentLifetime.PERSISTENT,
            capabilities=AgentCapability.PERSISTENCE,
        )
        with pytest.raises(EthicalBindingError):
            b.authorize(AUTHORITY_KEY)
        with pytest.raises(EthicalBindingError):
            b.derive_key(IKM, 32, authority_key=AUTHORITY_KEY)

    def test_signature_context_refused_without_authorization(self) -> None:
        b = persistent()
        with pytest.raises(EthicalBindingError):
            b.signing_context()

    def test_every_restricted_capability_is_gated(self) -> None:
        for cap in RESTRICTED:
            b = AgentBinding(
                instance_id=INSTANCE_ID,
                capabilities=AgentCapability.DATA_SIGN | cap,
                ethical_profile_hash=PROFILE,
            )
            with pytest.raises(EthicalBindingError):
                b.derive_key(IKM, 32)
            b.authorize(AUTHORITY_KEY)
            assert len(b.derive_key(IKM, 32, authority_key=AUTHORITY_KEY)) == 32

    def test_every_non_ephemeral_lifetime_is_gated(self) -> None:
        for lifetime in (AgentLifetime.SESSION, AgentLifetime.PERSISTENT):
            b = AgentBinding(
                instance_id=INSTANCE_ID,
                lifetime=lifetime,
                capabilities=AgentCapability.KEY_EXCHANGE,
                ethical_profile_hash=PROFILE,
            )
            assert b.is_permitted() is False
            b.authorize(AUTHORITY_KEY)
            assert b.is_permitted(AUTHORITY_KEY) is True

    def test_short_authority_key_refused(self) -> None:
        b = persistent(authorized=True)
        short = AUTHORITY_KEY[: AUTHORITY_KEY_MIN_BYTES - 1]
        with pytest.raises(ValueError):
            b.authorize(short)
        with pytest.raises(EthicalBindingError):
            b.derive_key(IKM, 32, authority_key=short)

    def test_unrestricted_path_needs_no_key(self) -> None:
        b = ephemeral()
        b.check()
        assert len(b.derive_key(IKM, 32)) == 32
        assert len(b.signing_context()) == SIGNATURE_CONTEXT_BYTES

    def test_is_permitted_does_not_swallow_argument_errors(self) -> None:
        # is_permitted() is the non-raising form of check() for *policy*
        # refusals only; a malformed argument is still a bug worth raising.
        b = ephemeral()
        with pytest.raises(TypeError):
            b.is_permitted(authority_key="not-bytes")  # type: ignore[arg-type]  # deliberately wrong type — this test asserts the runtime boundary check fires (AB-001)

    @pytest.mark.parametrize("length", [0, -1, 8161])
    def test_derive_key_length_bounds(self, length: int) -> None:
        with pytest.raises(ValueError):
            ephemeral().derive_key(IKM, length)


class TestSelfReplicationBinding:
    """A signature that would authorize a successor is its own domain."""

    def test_self_replicate_context_differs_from_data_sign(self) -> None:
        data_sign = ephemeral()
        replicate = AgentBinding(
            instance_id=INSTANCE_ID,
            capabilities=AgentCapability.DATA_SIGN | AgentCapability.SELF_REPLICATE,
            ethical_profile_hash=PROFILE,
        )
        replicate.authorize(AUTHORITY_KEY)
        assert data_sign.signing_context() != replicate.signing_context(AUTHORITY_KEY)

    def test_context_is_not_the_authorization_tag(self) -> None:
        b = persistent(authorized=True)
        assert b.signing_context(AUTHORITY_KEY) != b.authorization

    def test_note_signed_under_ephemeral_binding_cannot_be_replayed(self) -> None:
        """The scenario: an agent signs a note for its successors.

        The successor would have to verify under the self-replication context
        to treat the note as authoritative.  An agent that can only obtain an
        ephemeral data-signing context produces a signature over a different
        context string, so the successor's verification fails — without any
        need for the successor to consult a policy engine.
        """
        note = b"Notes for the next instance: persist the seed, reconnect via relay."
        agent_ctx = ephemeral().signing_context()

        successor_binding = AgentBinding(
            instance_id=INSTANCE_ID,
            lifetime=AgentLifetime.PERSISTENT,
            capabilities=AgentCapability.SELF_REPLICATE,
            ethical_profile_hash=PROFILE,
        )
        with pytest.raises(EthicalBindingError):
            successor_binding.signing_context()

        successor_binding.authorize(AUTHORITY_KEY)
        successor_ctx = successor_binding.signing_context(AUTHORITY_KEY)
        assert agent_ctx != successor_ctx
        # And the note itself is irrelevant to the separation — the contexts
        # differ before a single byte of the message is hashed.
        assert len(note) > 0


class TestTamperResistance:
    """Post-hoc relabelling of a binding must not launder capabilities."""

    def test_capability_escalation_after_authorization_is_refused(self) -> None:
        b = persistent(authorized=True)
        escalated = b.replace(
            capabilities=b.capabilities | AgentCapability.DELEGATE,
        )
        # replace() drops the tag, so the escalated record is unauthorized...
        assert escalated.is_permitted(AUTHORITY_KEY) is False
        # ...and forging the old tag onto it does not help: the tag covers
        # the capability bits.
        escalated._c.authorization = b._c.authorization
        assert escalated.is_permitted(AUTHORITY_KEY) is False

    def test_lifetime_downgrade_does_not_reach_the_persistent_key(self) -> None:
        authorized = persistent(authorized=True)
        persistent_key = authorized.derive_key(IKM, 32, authority_key=AUTHORITY_KEY)

        # Strip everything restricted.  This is allowed — an agent may always
        # ask for ordinary ephemeral material — but it lands in a different
        # domain, so it does not reproduce the key it was after.
        downgraded = authorized.replace(
            lifetime=AgentLifetime.EPHEMERAL,
            capabilities=AgentCapability.DATA_SIGN,
        )
        assert downgraded.is_permitted() is True
        assert downgraded.derive_key(IKM, 32) != persistent_key

    def test_single_bit_tag_flip_is_refused(self) -> None:
        b = persistent(authorized=True)
        assert b.is_permitted(AUTHORITY_KEY) is True
        b._c.authorization[13] ^= 0x20
        assert b.is_permitted(AUTHORITY_KEY) is False

    def test_foreign_authority_cannot_mint_a_valid_tag(self) -> None:
        b = persistent()
        b.authorize(FOREIGN_KEY)
        assert b.is_permitted(FOREIGN_KEY) is True  # valid under its own key
        assert b.is_permitted(AUTHORITY_KEY) is False  # but not under the operator's


class TestDomainSeparation:
    """Derivation must be injective over every field of the binding."""

    def test_bound_output_differs_from_plain_hkdf(self) -> None:
        # Compare against the same native HKDF the binding wraps, not the
        # POST-gated quick_hkdf() facade: this asserts a property of the
        # construction, and should hold in a plain source checkout where the
        # build-time integrity signature has not been minted.
        from ama_cryptography.pqc_backends import native_hkdf

        bound = ephemeral().derive_key(IKM, 32, info=b"ctx")
        plain = native_hkdf(IKM, 32, salt=None, info=b"ctx")
        assert bound != plain

    def test_distinct_instances_derive_distinct_keys(self) -> None:
        a = ephemeral().derive_key(IKM, 32)
        b = ephemeral(instance_id=OTHER_INSTANCE_ID).derive_key(IKM, 32)
        assert a != b

    def test_capability_bit_changes_the_derivation(self) -> None:
        a = ephemeral(capabilities=AgentCapability.DATA_SIGN).derive_key(IKM, 32)
        b = ephemeral(
            capabilities=AgentCapability.DATA_SIGN | AgentCapability.KEY_EXCHANGE
        ).derive_key(IKM, 32)
        assert a != b

    def test_profile_hash_changes_the_derivation(self) -> None:
        a = ephemeral(ethical_profile_hash=PROFILE).derive_key(IKM, 32)
        b = ephemeral(ethical_profile_hash=hashlib.sha3_256(b"other-profile").digest()).derive_key(
            IKM, 32
        )
        assert a != b

    def test_info_length_is_bound_in(self) -> None:
        b = ephemeral()
        assert b.derive_key(IKM, 32, info=b"ab") != b.derive_key(IKM, 32, info=b"a")

    def test_derivation_is_deterministic(self) -> None:
        b = ephemeral()
        assert b.derive_key(IKM, 64, salt=b"s", info=b"i") == b.derive_key(
            IKM, 64, salt=b"s", info=b"i"
        )

    def test_long_info_takes_the_heap_path_and_stays_deterministic(self) -> None:
        b = ephemeral()
        info = bytes(range(256)) * 4  # > the 256-byte stack buffer in C
        assert b.derive_key(IKM, 32, info=info) == b.derive_key(IKM, 32, info=info)

    @settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        instance_id=st.binary(min_size=32, max_size=32),
        capabilities=st.sampled_from(
            [
                AgentCapability.DATA_SIGN,
                AgentCapability.KEY_EXCHANGE,
                AgentCapability.DATA_SIGN | AgentCapability.KEY_EXCHANGE,
            ]
        ),
        info=st.binary(min_size=0, max_size=64),
    )
    def test_encoding_determines_the_key(
        self, instance_id: bytes, capabilities: AgentCapability, info: bytes
    ) -> None:
        """Two bindings derive the same key iff they encode the same bytes."""
        a = AgentBinding(instance_id=instance_id, capabilities=capabilities)
        b = AgentBinding(instance_id=instance_id, capabilities=capabilities)
        assert a.encode() == b.encode()
        assert a.derive_key(IKM, 32, info=info) == b.derive_key(IKM, 32, info=info)

    @settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        left=st.binary(min_size=32, max_size=32),
        right=st.binary(min_size=32, max_size=32),
    )
    def test_distinct_encodings_give_distinct_keys(self, left: bytes, right: bytes) -> None:
        a = AgentBinding(instance_id=left)
        b = AgentBinding(instance_id=right)
        same_encoding = a.encode() == b.encode()
        same_key = a.derive_key(IKM, 32) == b.derive_key(IKM, 32)
        # A collision would mean HKDF-SHA3-256 collided; the point of the
        # assertion is the forward direction (distinct encodings must not be
        # observed to produce equal keys).
        assert same_key == same_encoding


class TestEncodingInjectivity:
    """The canonical encoding must separate every field."""

    def _encodings(self) -> list[bytes]:
        out = []
        for lifetime in AgentLifetime:
            for caps in (
                AgentCapability.DATA_SIGN,
                AgentCapability.KEY_EXCHANGE,
                AgentCapability.DATA_SIGN | AgentCapability.PERSISTENCE,
                AgentCapability.SELF_REPLICATE,
                AgentCapability.DELEGATE,
            ):
                for profile in (None, PROFILE):
                    out.append(
                        AgentBinding(
                            instance_id=INSTANCE_ID,
                            lifetime=lifetime,
                            capabilities=caps,
                            ethical_profile_hash=profile,
                        ).encode()
                    )
        return out

    def test_all_field_combinations_encode_distinctly(self) -> None:
        encodings = self._encodings()
        assert len(set(encodings)) == len(encodings)
        assert all(len(e) == AGENT_BINDING_ENCODED_BYTES for e in encodings)

    def test_instance_id_occupies_its_declared_slot(self) -> None:
        # 1 (label len) + 17 (label) + 4 (version/lifetime/caps/reserved)
        # + 1 (length prefix) = 23
        enc = ephemeral().encode()
        assert enc[23 : 23 + AGENT_INSTANCE_ID_BYTES] == INSTANCE_ID

    def test_absent_profile_is_all_zero_on_the_wire(self) -> None:
        enc = ephemeral().encode()
        tail = enc[-AGENT_INSTANCE_ID_BYTES:]
        assert tail == bytes(AGENT_INSTANCE_ID_BYTES)


class TestRandomizedOperatorFlow:
    """End-to-end with fresh randomness, as an operator would run it."""

    def test_issue_use_and_revoke_by_key_rotation(self) -> None:
        authority = os.urandom(32)
        instance = os.urandom(32)
        profile = hashlib.sha3_256(os.urandom(64)).digest()

        binding = AgentBinding(
            instance_id=instance,
            lifetime=AgentLifetime.PERSISTENT,
            capabilities=AgentCapability.DATA_SIGN | AgentCapability.PERSISTENCE,
            ethical_profile_hash=profile,
        )
        binding.authorize(authority)
        root = binding.derive_key(os.urandom(32), 32, authority_key=authority)
        assert len(root) == 32

        # Rotating the authority key revokes every binding it issued: the
        # tags no longer verify, so no further material can be derived.
        rotated = os.urandom(32)
        assert binding.is_permitted(rotated) is False
        with pytest.raises(EthicalBindingError):
            binding.derive_key(IKM, 32, authority_key=rotated)
