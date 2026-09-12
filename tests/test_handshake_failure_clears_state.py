# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A failed handshake must drop the shared secret and raise the documented type.

WHY THIS TEST EXISTS

``SecureChannelInitiator.complete_handshake`` cleared ``_shared_secret`` and
``_handshake_hash`` in a block at the END of the method, reached only on
success.  Every failure path therefore left the negotiated shared secret live in
the initiator for the lifetime of the object — including the two paths that
raise ``HandshakeError`` deliberately, a pinned-key mismatch and a failed
signature.

A peer could also reach a path that raised something else entirely.
``HybridSignatureProvider.verify`` splits the peer-supplied public key at a fixed
offset and hands the tail to ``MLDSAProvider.verify``, which returns
``dilithium_verify(...)`` with no exception handling — and that raises
``ValueError`` for any length other than 1952.  So a responder returning a
wrong-length ``responder_public_key`` made ``complete_handshake`` raise a raw
``ValueError``, which a caller's ``except HandshakeError`` does not catch, on
input that arrives entirely over the wire.

Both are pinned here, on the two failure shapes a hostile peer controls, plus
the healthy path so the fix cannot pass by breaking the success case.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

import pytest

from ama_cryptography.crypto_api import HybridKEMProvider, HybridSignatureProvider
from ama_cryptography.secure_channel import (
    ChannelError,
    ChannelState,
    HandshakeError,
    SecureChannelInitiator,
    SecureChannelResponder,
)


def _fresh_exchange() -> tuple[SecureChannelInitiator, Any]:
    """An initiator that has sent its handshake, and the responder's reply."""
    kem_kp = HybridKEMProvider().generate_keypair()
    sig_kp = HybridSignatureProvider().generate_keypair()
    initiator = SecureChannelInitiator(kem_kp.public_key)
    responder = SecureChannelResponder(kem_kp.secret_key, sig_kp.secret_key, sig_kp.public_key)
    produced = responder.handle_handshake(initiator.create_handshake())
    response = produced[0] if isinstance(produced, tuple) else produced
    return initiator, response


#: Each mutation is something a hostile or broken responder can put on the wire.
MUTATIONS: dict[str, Callable[[Any], Any]] = {
    # Reaches dilithium_verify's length check -> ValueError before the fix.
    "public key one byte short": lambda r: replace(
        r, responder_public_key=r.responder_public_key[:-1]
    ),
    "public key truncated hard": lambda r: replace(r, responder_public_key=b"\x00" * 7),
    # Reaches the deliberate HandshakeError, which also did not clear state.
    "signature all zero": lambda r: replace(r, signature=bytes(len(r.signature))),
}


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_a_malformed_response_raises_handshake_error(label: str) -> None:
    initiator, response = _fresh_exchange()
    with pytest.raises(HandshakeError):
        initiator.complete_handshake(MUTATIONS[label](response))


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_a_failed_handshake_does_not_retain_the_shared_secret(label: str) -> None:
    initiator, response = _fresh_exchange()
    assert initiator._shared_secret is not None, "fixture must have a secret to leak"

    with pytest.raises(HandshakeError):
        initiator.complete_handshake(MUTATIONS[label](response))

    assert initiator._shared_secret is None, (
        f"the negotiated shared secret is still live after a rejected handshake "
        f"({label}). The block that clears it was reached only on success, so a "
        f"peer that fails the handshake left it in the initiator indefinitely."
    )
    assert initiator._handshake_hash is None
    assert initiator._state is ChannelState.CLOSED, (
        "a handshake that failed must not be completable by a second attempt "
        "with a different response"
    )


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_a_closed_channel_refuses_a_second_attempt(label: str) -> None:
    initiator, response = _fresh_exchange()
    good = response
    with pytest.raises(HandshakeError):
        initiator.complete_handshake(MUTATIONS[label](response))
    # Even the legitimate response must not resurrect the channel: the state
    # guard at the top of complete_handshake sees CLOSED, not HANDSHAKE_SENT.
    with pytest.raises(ChannelError) as excinfo:
        initiator.complete_handshake(good)
    assert "ChannelState.CLOSED" in str(excinfo.value)


def test_the_healthy_handshake_still_establishes_and_clears() -> None:
    """The fix must not pass by breaking the success path."""
    initiator, response = _fresh_exchange()
    session = initiator.complete_handshake(response)
    assert session is not None
    assert initiator._state is ChannelState.ESTABLISHED
    assert initiator._shared_secret is None
    assert initiator._handshake_hash is None
