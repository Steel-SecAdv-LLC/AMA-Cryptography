#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
AMA Cryptography — the one bounded-retry HTTPS fetch

Why this module exists
----------------------
Two scripts in this tree download reference material over HTTPS from the same
host, `raw.githubusercontent.com`, in bursts of ten to fifteen requests issued
back to back: `tools/refresh_wycheproof_corpus.py` (Wycheproof corpus
provenance) and `nist_vectors/fetch_vectors.py` (NIST ACVP vectors).  That host
answers a burst by resetting some of it.

Both were written with a single unretried `urlopen`, and both failed the same
way within an hour of each other on this branch:

  * `Corpus Provenance Gate` — three of fifteen fetches came back
    `[Errno 104] Connection reset by peer` while the other twelve verified,
    on a commit whose offline integrity check had just confirmed all fifteen
    files byte-for-byte.
  * `ACVP Validation Gate` — the vector fetch failed, and because that script
    swallowed the error and returned 0, the failure surfaced two steps later
    as `nist_vectors/results.json missing — harness crashed`.

The first was fixed in place.  That fixed one of two sites, which this
repository already has a name for: a fix applied to one of N identical sites is
a sample, not a fix.  So the policy lives here once, and both callers use it.

What the retry may and may not do
---------------------------------
It may survive a transport failure.  It may NOT convert a failure into a
success.  Concretely:

  * Only transport errors are retried.  A 404 or a 403 is an ANSWER about the
    resource; repeating the question cannot change it, so those fail on the
    first attempt.  429 and 5xx are the server reporting its own state.
  * The final attempt is unguarded and its exception propagates.
  * Nothing here ever sees a digest.  Content that arrives intact but WRONG is
    the caller's problem, compared once, and still fails there.

The scheme is checked rather than assumed: `urllib` also opens `file:` and
`ftp:`, so a URL reaching here from a manifest — which is the thing these
scripts exist to re-derive, not a trusted input — could otherwise read a local
path and have its contents vendored as "upstream".  That guard runs before any
attempt, so the retry cannot widen it.
"""

from __future__ import annotations

import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from http.client import HTTPMessage
from typing import IO, Any

#: Statuses worth another attempt: rate limiting and server-side failure.
RETRIABLE_STATUS = frozenset({429, 500, 502, 503, 504})

DEFAULT_ATTEMPTS = int(os.environ.get("AMA_FETCH_ATTEMPTS", "3"))
DEFAULT_BACKOFF = float(os.environ.get("AMA_FETCH_BACKOFF", "2"))
DEFAULT_TIMEOUT = 60


def is_retriable(exc: BaseException) -> bool:
    """True for a transport failure another attempt could plausibly fix."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRIABLE_STATUS
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError))


class _HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-applies the ``https://`` rule to every redirect target.

    ``urlopen``'s default ``HTTPRedirectHandler`` permits any ``Location``
    whose scheme is in ``("http", "https", "ftp", "")``.  Checking only the
    caller-supplied URL therefore secured the FIRST hop and nothing after it:
    a 302 to ``http://`` or ``ftp://`` was followed, in plaintext, by a
    function whose docstring says "the scheme is checked rather than assumed
    ... that guard runs before any attempt, so the retry cannot widen it" and
    whose two ``# nosec B310`` justifications read "https enforced".

    Raising rather than returning None so the failure is a refusal with a
    reason, not a silent stop at the redirect.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not newurl.startswith("https://"):
            # The refusal abandons the in-flight 302 transfer, so its response
            # must be released HERE: no caller ever sees it, and an fp left to
            # the garbage collector is exactly the ResourceWarning that Python
            # 3.14's finalizer handling escalated into a failure (unraisable
            # inside a deallocator) the first time this path ran end to end.
            # Close-then-raise keeps the refusal a refusal, leaking nothing.
            # Guarded: the live opener always hands a real fp, but the
            # handler's unit tests legitimately drive this policy check with
            # fp=None, where there is no transfer to release.
            if fp is not None:
                fp.close()
            raise ValueError(
                f"refusing a non-HTTPS redirect target: {newurl!r} "
                f"(HTTP {code} from {req.full_url!r})"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_https(req: urllib.request.Request, *, timeout: int, context: ssl.SSLContext) -> Any:
    """Open `req`, refusing any redirect that leaves HTTPS.

    An OpenerDirector rather than the module-level ``urlopen``, because that
    function builds its own opener per call and gives no way to install a
    redirect handler — which is the only place the scheme of a SECOND hop can
    be checked.  A separate function so the network boundary has one seam:
    tests drive the retry logic by replacing this, not by patching
    ``urllib.request`` module-wide.
    """
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _HTTPSOnlyRedirectHandler(),
    )
    # No `noqa: S310` / `nosec B310` here: neither ruff's S310 nor bandit's
    # B310 flags `OpenerDirector.open` — both key on `urllib.request.urlopen`
    # and `Request`, which carry theirs at the call sites above.  A marker for
    # a finding that does not exist is a marker nobody can check.
    return opener.open(req, timeout=timeout)


def fetch_bytes(
    url: str,
    *,
    user_agent: str,
    timeout: int = DEFAULT_TIMEOUT,
    attempts: int | None = None,
    backoff: float | None = None,
) -> bytes:
    """Download `url` over HTTPS, retrying only transport failures."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-HTTPS URL: {url!r}")

    total = DEFAULT_ATTEMPTS if attempts is None else attempts
    total = max(1, total)
    wait = DEFAULT_BACKOFF if backoff is None else backoff

    ctx = ssl.create_default_context()
    req = urllib.request.Request(  # noqa: S310  # nosec B310 -- https enforced directly above and on every redirect by _HTTPSOnlyRedirectHandler (FETCH-001)
        url, headers={"User-Agent": user_agent}
    )
    for attempt in range(1, total + 1):
        try:
            with _open_https(req, timeout=timeout, context=ctx) as resp:
                return bytes(resp.read())
        except Exception as exc:
            if attempt == total or not is_retriable(exc):
                raise
            delay = attempt * wait
            print(
                f"  .. {url.rsplit('/', 1)[-1]}: attempt {attempt}/{total} failed "
                f"({type(exc).__name__}: {exc}); retrying in {delay:.0f}s",
                file=sys.stderr,
            )
            if delay > 0:
                time.sleep(delay)
    raise AssertionError("unreachable: the loop either returns or raises")
