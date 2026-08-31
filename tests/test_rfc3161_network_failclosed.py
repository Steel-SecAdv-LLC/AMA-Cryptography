#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Item 19 — the RFC 3161 TSA path fails CLOSED under real network faults.

``tests/test_rfc3161_offline.py`` exercises mock and disabled modes; this file
exercises the ONE networked path in the shipped library
(``request_timestamp_exchange`` / ``request_timestamp_token`` /
``get_timestamp`` -> ``http.client.HTTPSConnection``) against faults induced at
the socket/DNS layer, NOT via mocks:

  * dead DNS      — an RFC 6761 ``.invalid`` host that cannot resolve;
  * unreachable   — RFC 5737 TEST-NET-1 (192.0.2.1), which is guaranteed not
                    to be routed, so the connect stalls until the timeout;
  * refused       — 127.0.0.1 on a port with no listener;
  * mid-handshake — a local socket that accepts the TCP connection and then
                    closes it before the TLS handshake completes.

Every case must raise ``TimestampError`` (or ``ValueError`` for a rejected
URL) — never return a token, never hang past the library's own deadline, and
never leak a raw ``OSError``/``ssl.SSLError`` to the caller. Keeping these in
the suite is the item's explicit requirement.

These tests make no outbound connection to any real TSA: TEST-NET-1 is
unrouted, ``.invalid`` never resolves, and the refused/mid-handshake cases talk
to a loopback socket this process owns. ``http.client.HTTPSConnection`` does
not consult HTTP(S)_PROXY, so the loopback and unrouted targets are hit
directly.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable

import pytest

from ama_cryptography import rfc3161_timestamp as ts

DIGEST = b"\x00" * 32
HASH = "sha256"

# Generous ceiling: the library bounds a single socket op at _TSA_TIMEOUT (10s)
# and the whole exchange at _TSA_TOTAL_DEADLINE (30s). A fail-closed path must
# return well within a small multiple of that, never hang unbounded.
_MAX_WALL = ts._TSA_TOTAL_DEADLINE + 15


def _elapsed(fn: Callable[[], object]) -> float:
    start = time.monotonic()
    fn()
    return time.monotonic() - start


class TestTsaNetworkFailsClosed:
    def test_dead_dns_raises_timestamperror(self) -> None:
        """An unresolvable host (.invalid) must surface as TimestampError."""
        with pytest.raises(ts.TimestampError):
            ts.request_timestamp_token(
                DIGEST, HASH, "https://tsa.this-host-does-not-resolve.invalid/tsr"
            )

    def test_dead_dns_is_bounded_in_time(self) -> None:
        def _call() -> None:
            with pytest.raises(ts.TimestampError):
                ts.request_timestamp_token(
                    DIGEST, HASH, "https://tsa.this-host-does-not-resolve.invalid/tsr"
                )

        assert _elapsed(_call) < _MAX_WALL

    def test_unreachable_testnet_address_times_out_closed(self) -> None:
        """RFC 5737 TEST-NET-1 is unrouted: connect stalls, then fails closed
        within the library's own deadline — no unbounded hang, no token."""

        def _call() -> None:
            with pytest.raises(ts.TimestampError):
                ts.request_timestamp_token(DIGEST, HASH, "https://192.0.2.1/tsr")

        assert _elapsed(_call) < _MAX_WALL

    def test_connection_refused_raises_timestamperror(self) -> None:
        """A loopback port with no listener refuses immediately."""
        # Bind to grab a free port, then close so nothing listens there.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with pytest.raises(ts.TimestampError):
            ts.request_timestamp_token(DIGEST, HASH, f"https://127.0.0.1:{port}/tsr")

    def test_mid_handshake_cut_raises_timestamperror(self) -> None:
        """A server that accepts the TCP connection then drops it before TLS
        completes must fail closed (ssl.SSLError is an OSError subclass, caught
        and re-raised as TimestampError), never yielding a token."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def _accept_then_drop() -> None:
            srv.settimeout(_MAX_WALL)
            try:
                while not stop.is_set():
                    try:
                        conn, _ = srv.accept()
                    except TimeoutError:
                        return
                    # Read a little of the client hello, then close hard.
                    try:
                        conn.recv(16)
                    except OSError:
                        pass
                    conn.close()
                    return
            finally:
                srv.close()

        t = threading.Thread(target=_accept_then_drop, daemon=True)
        t.start()
        try:
            with pytest.raises(ts.TimestampError):
                ts.request_timestamp_token(DIGEST, HASH, f"https://127.0.0.1:{port}/tsr")
        finally:
            stop.set()
            t.join(timeout=5)

    def test_non_https_url_is_refused_before_any_socket(self) -> None:
        """A plaintext TSA URL is rejected as ValueError before a connection —
        the transport is never allowed to downgrade off TLS."""
        with pytest.raises(ValueError):
            ts.request_timestamp_token(DIGEST, HASH, "http://192.0.2.1/tsr")

    def test_get_timestamp_wrapper_also_fails_closed(self) -> None:
        """The high-level get_timestamp() surface fails closed on the same
        faults (it must not swallow the error into a fake-valid result)."""
        result = None
        raised = False
        try:
            result = ts.get_timestamp(
                DIGEST,
                tsa_url="https://tsa.this-host-does-not-resolve.invalid/tsr",
                hash_algorithm="sha256",
            )
        except (ts.TimestampError, ts.TimestampUnavailableError, ValueError):
            raised = True
        # Either it raised, or it returned a result that is NOT a valid token.
        if not raised:
            assert result is None or not getattr(
                result, "success", False
            ), "get_timestamp returned a success result for an unresolvable TSA"
