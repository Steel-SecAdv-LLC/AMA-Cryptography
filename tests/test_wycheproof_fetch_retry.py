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

import importlib.util
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
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
    """A fake urlopen that plays `outcomes` in order, counting its calls."""
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
    monkeypatch.setattr(tool, "_FETCH_BACKOFF", 0.0)


URL = "https://raw.githubusercontent.com/o/r/deadbeef/vectors/x_test.json"


def _http_error(status: int, msg: str) -> urllib.error.HTTPError:
    """An HTTPError built with the argument types urllib actually declares.

    `hdrs` is an email.message.Message and `fp` is an optional binary stream,
    so passing a bare dict needs a type suppression to get past mypy --strict.
    A suppression there would cover nothing but the convenience of not writing
    this function, which is the kind INVARIANT-13 exists to keep out.
    """
    return urllib.error.HTTPError(URL, status, msg, Message(), None)


def test_a_reset_connection_is_retried_and_survived(monkeypatch: pytest.MonkeyPatch) -> None:
    """The observed failure: reset once, then served."""
    reset = urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))
    fake, calls = _urlopen_script([reset, b"payload"])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 3)
    assert tool.fetch_bytes(URL) == b"payload"
    assert calls[0] == 2


def test_the_final_attempt_is_unguarded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A transport error that never clears still fails, and does not loop forever."""
    reset = urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))
    fake, calls = _urlopen_script([reset])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 3)
    with pytest.raises(urllib.error.URLError):
        tool.fetch_bytes(URL)
    assert calls[0] == 3


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
def test_a_permanent_status_is_not_retried(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    """A 404 is an answer about the resource. Asking again cannot change it."""
    err = _http_error(status, "nope")
    fake, calls = _urlopen_script([err])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 3)
    with pytest.raises(urllib.error.HTTPError):
        tool.fetch_bytes(URL)
    assert calls[0] == 1, "a permanent status must fail on the first attempt"


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_a_transient_status_is_retried(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    err = _http_error(status, "later")
    fake, calls = _urlopen_script([err, b"payload"])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 3)
    assert tool.fetch_bytes(URL) == b"payload"
    assert calls[0] == 2


def test_a_non_transport_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, calls = _urlopen_script([ValueError("something structural")])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 3)
    with pytest.raises(ValueError):
        tool.fetch_bytes(URL)
    assert calls[0] == 1


def test_the_https_guard_is_checked_before_any_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry loop must not weaken the scheme guard into something retriable."""
    fake, calls = _urlopen_script([b"local file contents"])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
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
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 3)
    manifest = {
        "upstream": {"repository": "https://github.com/C2SP/wycheproof", "path": "testvectors_v1"},
        "files": {"x_test.json": {"sha256": "00" * 32}},
    }
    problems = tool.verify_upstream(manifest, "deadbeefcafe")
    assert len(problems) == 1
    assert "is not upstream's bytes" in problems[0]
    assert calls[0] == 1, "a digest mismatch must not be retried"


def test_zero_attempts_still_makes_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """A misconfigured attempt count must not silently skip the fetch entirely."""
    fake, calls = _urlopen_script([b"payload"])
    monkeypatch.setattr(tool.urllib.request, "urlopen", fake)
    monkeypatch.setattr(tool, "_FETCH_ATTEMPTS", 0)
    assert tool.fetch_bytes(URL) == b"payload"
    assert calls[0] == 1
