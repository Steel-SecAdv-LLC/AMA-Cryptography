# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the retry policy in ``tools/refresh_wycheproof_corpus.py``.

``--verify`` issues one HTTPS request per vendored file, back to back, and
raw.githubusercontent.com answers a burst of them by resetting some.  On one
run of this branch three of fifteen came back ``[Errno 104] Connection reset by
peer`` while the other twelve verified against upstream, and
``Corpus Provenance Gate`` went red on a commit whose offline integrity check
had just confirmed all fifteen files byte-for-byte against the manifest.

The properties under test are the same two the apt retry has: the transient
case is survived, and the retry can never turn a real failure into a pass.
That second half is the one that matters, so it is tested from three
directions — a permanent HTTP status is not retried, a non-transport error is
not retried, and a wrong digest is not a transport error at all and still
fails.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from email.message import Message
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import http_fetch  # noqa: E402 -- repo-root path insert above (FETCH-003)

TOOL_PATH = REPO_ROOT / "tools" / "refresh_wycheproof_corpus.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("refresh_wycheproof_corpus", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load()


class _Resp:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _urlopen_script(outcomes: list[Any]) -> tuple[Any, list[int]]:
    """A fake opener that plays `outcomes` in order, counting its calls.

    Installed over ``tools.http_fetch._open_https`` rather than over
    ``urllib.request.urlopen``: the fetcher now goes through an
    OpenerDirector, because that is the only place a redirect handler can
    re-apply the ``https://`` rule to a SECOND hop, and ``urlopen`` builds its
    own opener per call.  ``_open_https`` is the network boundary's single
    seam, so patching it keeps these tests about retry behaviour rather than
    about urllib's internals.
    """
    calls = [0]

    def fake(*_args: object, **_kwargs: object) -> _Resp:
        calls[0] += 1
        outcome = outcomes[min(calls[0] - 1, len(outcomes) - 1)]
        if isinstance(outcome, BaseException):
            raise outcome
        return _Resp(outcome)

    return fake, calls


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backoff is a property of the policy, not something to sit through."""
    monkeypatch.setattr(http_fetch, "DEFAULT_BACKOFF", 0.0)


URL = "https://raw.githubusercontent.com/o/r/deadbeef/vectors/x_test.json"


@pytest.fixture
def http_error() -> Iterator[Callable[[int, str], urllib.error.HTTPError]]:
    """Build HTTPErrors that own no operating-system resource, and close them.

    Two separate reasons this is a fixture rather than a bare constructor:

    `hdrs` is an email.message.Message and `fp` is an optional binary stream,
    so passing a bare dict and None needs a type suppression to get past
    mypy --strict. A suppression there would cover nothing but the convenience
    of not writing this, which is the kind INVARIANT-13 exists to keep out.

    And `fp` must be a real stream, not None. `urllib.error.HTTPError` fills a
    missing `fp` in for you, but with WHAT depends on the interpreter: Python
    3.11 uses `io.BytesIO()`, which owns nothing, while 3.14 uses
    `tempfile.TemporaryFile()`, which owns a file descriptor and whose
    `_TemporaryFileCloser.__del__` emits a ResourceWarning if it is collected
    unclosed. pytest turns that warning into a PytestUnraisableExceptionWarning
    and attributes it to whichever test happens to be running when the garbage
    collector fires — so ten leaked errors from this file surfaced as a single
    ExceptionGroup of ten sub-exceptions against
    `test_wycheproof_gate.py::test_real_drivers_pass_the_tripwire`, on
    Python 3.14 only, while 3.10 through 3.13 stayed green.

    Passing an explicit BytesIO means no descriptor is ever allocated, and
    closing at teardown means the release does not depend on when — or
    whether — the collector runs.
    """
    built: list[urllib.error.HTTPError] = []

    def make(status: int, msg: str) -> urllib.error.HTTPError:
        err = urllib.error.HTTPError(URL, status, msg, Message(), io.BytesIO(b""))
        built.append(err)
        return err

    yield make
    for err in built:
        err.close()


def test_a_reset_connection_is_retried_and_survived(monkeypatch: pytest.MonkeyPatch) -> None:
    """The observed failure: reset once, then served."""
    reset = urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))
    fake, calls = _urlopen_script([reset, b"payload"])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 3)
    assert tool.fetch_bytes(URL) == b"payload"
    assert calls[0] == 2


def test_the_final_attempt_is_unguarded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A transport error that never clears still fails, and does not loop forever."""
    reset = urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))
    fake, calls = _urlopen_script([reset])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 3)
    with pytest.raises(urllib.error.URLError):
        tool.fetch_bytes(URL)
    assert calls[0] == 3


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
def test_a_permanent_status_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    http_error: Callable[[int, str], urllib.error.HTTPError],
) -> None:
    """A 404 is an answer about the resource. Asking again cannot change it."""
    err = http_error(status, "nope")
    fake, calls = _urlopen_script([err])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 3)
    with pytest.raises(urllib.error.HTTPError):
        tool.fetch_bytes(URL)
    assert calls[0] == 1, "a permanent status must fail on the first attempt"


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_a_transient_status_is_retried(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    http_error: Callable[[int, str], urllib.error.HTTPError],
) -> None:
    err = http_error(status, "later")
    fake, calls = _urlopen_script([err, b"payload"])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 3)
    assert tool.fetch_bytes(URL) == b"payload"
    assert calls[0] == 2


def test_a_non_transport_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, calls = _urlopen_script([ValueError("something structural")])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 3)
    with pytest.raises(ValueError):
        tool.fetch_bytes(URL)
    assert calls[0] == 1


def test_the_https_guard_is_checked_before_any_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry loop must not weaken the scheme guard into something retriable."""
    fake, calls = _urlopen_script([b"local file contents"])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    with pytest.raises(ValueError):
        tool.fetch_bytes("file:///etc/passwd")
    assert calls[0] == 0


def test_a_wrong_digest_still_fails_and_is_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The property that makes the retry safe.

    A fetch that SUCCEEDS but returns the wrong bytes is not a transport
    failure and must not be given a second chance to agree: it is compared
    once, by verify_upstream, and reported as a provenance failure.
    """
    fake, calls = _urlopen_script([b"not the vendored bytes"])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 3)
    manifest = {
        "upstream": {"repository": "https://github.com/C2SP/wycheproof", "path": "testvectors_v1"},
        "files": {"x_test.json": {"sha256": "00" * 32}},
    }
    problems = tool.verify_upstream(manifest, "deadbeefcafe")
    assert len(problems) == 1
    assert "is not upstream's bytes" in problems[0]
    assert calls[0] == 1, "a digest mismatch must not be retried"


def test_the_fixture_errors_own_no_operating_system_resource(
    http_error: Callable[[int, str], urllib.error.HTTPError],
) -> None:
    """Pin the property whose absence broke Python 3.14, on every version.

    `urllib.error.HTTPError` substitutes a stream when `fp` is None, and what
    it substitutes is interpreter-dependent: `io.BytesIO()` on 3.11, a
    `tempfile.TemporaryFile()` on 3.14. The second owns a file descriptor and
    warns on collection if never closed, which pytest escalates into a failure
    against an unrelated test. Asserting the stream we passed is the one in
    place catches a revert to `None` on any version, including the ones where
    the consequence would not show.
    """
    err = http_error(503, "later")
    assert isinstance(err.fp, io.BytesIO), (
        "HTTPError must be given an explicit BytesIO; letting urllib pick "
        "yields a TemporaryFile on Python 3.14 and leaks a descriptor"
    )


def test_zero_attempts_still_makes_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """A misconfigured attempt count must not silently skip the fetch entirely."""
    fake, calls = _urlopen_script([b"payload"])
    monkeypatch.setattr(http_fetch, "_open_https", fake)
    monkeypatch.setattr(http_fetch, "DEFAULT_ATTEMPTS", 0)
    assert tool.fetch_bytes(URL) == b"payload"
    assert calls[0] == 1


class TestRedirectsCannotLeaveHTTPS:
    """The scheme guard must survive a 30x, not only the caller's string.

    ``fetch_bytes`` validated the URL it was handed and then called
    ``urllib.request.urlopen``, whose default ``HTTPRedirectHandler`` permits
    any ``Location`` whose scheme is in ``("http", "https", "ftp", "")``.  So
    the first hop was HTTPS and every hop after it could be plaintext — under a
    docstring saying "the scheme is checked rather than assumed ... that guard
    runs before any attempt, so the retry cannot widen it", and two
    ``# nosec B310`` justifications reading "https enforced".
    """

    @staticmethod
    def _handler() -> Any:
        return http_fetch._HTTPSOnlyRedirectHandler()

    @pytest.mark.parametrize(
        "target",
        [
            "http://mirror.invalid/corpus.json",
            "ftp://mirror.invalid/corpus.json",
            "file:///etc/passwd",
            "//mirror.invalid/corpus.json",
        ],
    )
    def test_a_redirect_off_https_is_refused(self, target: str) -> None:
        request = urllib.request.Request("https://origin.invalid/corpus.json")
        with pytest.raises(ValueError) as excinfo:
            self._handler().redirect_request(request, None, 302, "Found", {}, target)
        assert "non-HTTPS redirect target" in str(excinfo.value)

    def test_an_https_redirect_is_allowed(self) -> None:
        """The control: the handler must not refuse every redirect."""
        request = urllib.request.Request("https://origin.invalid/corpus.json")
        follow = self._handler().redirect_request(
            request, None, 302, "Found", Message(), "https://mirror.invalid/corpus.json"
        )
        assert follow is not None
        assert follow.full_url == "https://mirror.invalid/corpus.json"

    def test_the_fetcher_installs_the_handler(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-vacuity: the handler above must be the one actually in effect.

        Asserted on the opener ``_open_https`` builds, because a handler that
        exists and is not installed refuses nothing.
        """
        seen: list[Any] = []
        real_build = urllib.request.build_opener

        def capture(*handlers: Any) -> Any:
            seen.extend(handlers)
            return real_build(*handlers)

        monkeypatch.setattr(urllib.request, "build_opener", capture)
        request = urllib.request.Request("https://origin.invalid/x")
        with contextlib.suppress(Exception):
            # The connection is expected to fail; the OPENER is the subject.
            http_fetch._open_https(request, timeout=1, context=ssl.create_default_context())

        assert any(
            isinstance(handler, http_fetch._HTTPSOnlyRedirectHandler) for handler in seen
        ), f"the HTTPS-only redirect handler was not installed: {seen}"
