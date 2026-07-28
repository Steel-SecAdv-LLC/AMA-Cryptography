#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A stand-in for ``http.client.HTTPResponse`` that reads like the real one.

Why this exists as a shared helper
----------------------------------
Three test sites independently mocked a TSA response with
``mock_response.read.return_value = body``. That is not a response object: it
hands back the *entire* body on every call, however few octets were asked for,
and never signals end of stream. A client that reads its body in one
unbounded ``read()`` cannot tell the difference, which is why the shape
survived — but the RFC 3161 client reads in bounded chunks against a total
deadline, so that a TSA cannot hold a signing process on a socket by dripping
one octet at a time. Against a ``return_value`` mock, that client reads the
same body forever and trips its own size ceiling.

The mock was wrong and the client was right, which is the case worth being
careful about: the natural repair is to "fix" the client back to a single
unbounded read, and the bug returns with tests that agree with it. So the
contract lives in one place, matches ``HTTPResponse.read`` — honour ``amt``,
return ``b""`` at EOF — and every site uses it.
"""

from __future__ import annotations

from typing import Any, Optional
from unittest.mock import MagicMock


class ResponseBody:
    """The readable half: a cursor over octets, refillable per request."""

    __slots__ = ("_remaining",)

    def __init__(self, body: bytes = b"") -> None:
        self._remaining = body

    def set(self, body: bytes) -> None:
        """Install the body the next ``read`` sequence will drain."""
        self._remaining = body

    def read(self, amount: Optional[int] = None) -> bytes:
        """Return up to ``amount`` octets, or all of them when ``amount`` is None.

        ``b""`` once drained, which is how end of stream is signalled — the
        property a ``return_value`` mock cannot express.
        """
        take = len(self._remaining) if amount is None else max(0, amount)
        out, self._remaining = self._remaining[:take], self._remaining[take:]
        return out


def make_response(
    status: int = 200, content_length: Optional[str] = None
) -> tuple[Any, ResponseBody]:
    """Return ``(mock_response, body)`` wired together.

    Call ``body.set(...)`` from the ``request`` side effect to answer with
    something derived from what the client actually posted.
    """
    body = ResponseBody()
    response = MagicMock(status=status)
    response.getheader.return_value = content_length
    response.read.side_effect = body.read
    return response, body
