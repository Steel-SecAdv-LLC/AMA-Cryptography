#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``tools/check_vector_provenance.py --verify-upstream``.

The offline half of that gate pins a SHA-256 per vendored vector, which proves
the bytes have not CHANGED since they were vendored.  It cannot prove they were
ever what upstream published — a corpus that never matched NIST verifies clean
forever, and the ANCHOR digests in ``tests/test_vector_provenance_gate.py`` do
not help, because they were computed from the same vendored bytes.

``--verify-upstream`` fetches and compares.  These tests drive it with a stubbed
fetcher so the logic is exercised without network, and pin the two properties
that make it worth having: it catches a vendored file that does not match
upstream, and it refuses to report success when it compared nothing.

The coverage rule is the other half.  Every pinned vector must sit in exactly
one of ``verbatim`` / ``derived`` / ``verified_elsewhere`` / ``unverifiable``,
so a corpus cannot be added without someone deciding how its provenance is
established — including deciding, explicitly and with a reason, that it cannot
be fetched.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_vector_provenance.py"
MANIFEST = REPO_ROOT / "tests" / "kat" / "PROVENANCE.json"

BUCKETS = ("verbatim", "derived", "verified_elsewhere", "unverifiable")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_vector_provenance", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate() -> ModuleType:
    return _load()


@pytest.fixture()
def manifest() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return loaded


# --------------------------------------------------------------------------
# The coverage rule, on the real manifest
# --------------------------------------------------------------------------


def test_every_pinned_vector_declares_how_its_provenance_is_established(
    manifest: dict[str, Any],
) -> None:
    pinned = set(manifest["files"])
    for relative in sorted(pinned):
        holding = [b for b in BUCKETS if relative in manifest.get(b, {})]
        assert holding, (
            f"{relative} is pinned but declares no provenance bucket. A vector "
            f"whose upstream nobody decided about is how a corpus drifts out from "
            f"under its own gate."
        )
        assert len(holding) == 1, f"{relative} is in several buckets: {holding}"


def test_no_bucket_names_a_file_the_manifest_does_not_pin(manifest: dict[str, Any]) -> None:
    pinned = set(manifest["files"])
    for bucket in BUCKETS:
        for relative in manifest.get(bucket, {}):
            assert relative in pinned, f"{bucket} names unpinned {relative}"


def test_every_unverifiable_entry_gives_a_reason(manifest: dict[str, Any]) -> None:
    """'Cannot be fetched' is only acceptable when it says why."""
    for relative, reason in manifest.get("unverifiable", {}).items():
        assert isinstance(reason, str) and len(reason) > 40, (
            f"{relative} is recorded as unverifiable with no real reason. The "
            f"bucket exists to make that decision visible, not to hide it."
        )


def test_every_verified_elsewhere_entry_names_the_tool(manifest: dict[str, Any]) -> None:
    for relative, entry in manifest.get("verified_elsewhere", {}).items():
        assert entry.get("by"), f"{relative} claims another tool verifies it but does not say which"
        tool = entry["by"].split()[0]
        assert (REPO_ROOT / tool).is_file(), f"{relative} names {tool}, which does not exist"


def test_the_fetchable_buckets_are_not_empty(manifest: dict[str, Any]) -> None:
    """A map where nothing is fetchable would pass vacuously forever."""
    assert manifest.get("verbatim"), "no vector is checked against upstream byte-for-byte"
    assert manifest.get("derived"), "no derivative has its upstream inputs checked"


def test_every_upstream_url_is_https_and_pinned(manifest: dict[str, Any]) -> None:
    """A moving ref would make this gate fail on upstream's schedule, not ours."""
    urls = [e["url"] for e in manifest.get("verbatim", {}).values()]
    for entry in manifest.get("derived", {}).values():
        urls.extend(s["url"] for s in entry["sources"])
    assert urls
    for url in urls:
        assert url.startswith("https://"), url
        for moving in ("/main/", "/master/", "/HEAD/"):
            assert moving not in url, (
                f"{url} points at a moving ref. Pin an immutable commit or tag, or "
                f"this gate reports upstream's churn as our drift."
            )


# --------------------------------------------------------------------------
# The comparison itself, driven with a stub fetcher
# --------------------------------------------------------------------------


def _stub_fetch(gate: ModuleType, monkeypatch: pytest.MonkeyPatch, table: dict[str, bytes]) -> None:
    def fake(url: str) -> bytes:
        if url not in table:
            raise RuntimeError(f"unexpected fetch: {url}")
        return table[url]

    monkeypatch.setattr(gate, "_fetch", fake)


def _truthful_table(manifest: dict[str, Any]) -> dict[str, bytes]:
    """What upstream would return if every vendored file really matched."""
    table: dict[str, bytes] = {}
    for relative, entry in manifest["verbatim"].items():
        table[entry["url"]] = (REPO_ROOT / relative).read_bytes()
    for relative, entry in manifest["derived"].items():
        loaded = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
        block = loaded[entry["source_block"]]
        for source in entry["sources"]:
            # A payload whose digest equals the recorded one.
            recorded = block[source["digest_field"]]
            table[source["url"]] = _preimage_for(recorded)
    return table


#: Digests are one-way, so a stub cannot produce a real preimage.  A payload
#: carrying this marker stands for "the file whose digest is <rest>", and
#: :func:`_stub_digests` makes the gate's own hashing honour that.
_PREIMAGE_MARKER = b"preimage-of:"


def _preimage_for(digest: str) -> bytes:
    return _PREIMAGE_MARKER + digest.encode("ascii")


def _stub_digests(gate: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hash every payload for real, except a marked stand-in for a preimage."""
    real = hashlib.sha256

    class _Digest:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def hexdigest(self) -> str:
            if self._data.startswith(_PREIMAGE_MARKER):
                return self._data[len(_PREIMAGE_MARKER) :].decode("ascii")
            return real(self._data).hexdigest()

    monkeypatch.setattr(gate, "hashlib", SimpleNamespace(sha256=_Digest))


def test_a_vendored_file_that_does_not_match_upstream_fails(
    gate: ModuleType,
    manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The case the whole gate exists for."""
    table = _truthful_table(manifest)
    victim = sorted(manifest["verbatim"])[0]
    table[manifest["verbatim"][victim]["url"]] = b"upstream published something else"
    _stub_fetch(gate, monkeypatch, table)
    assert gate.verify_upstream() == 1
    err = capsys.readouterr().err
    assert victim in err and "not what upstream published" in err


def test_a_derivative_whose_recorded_source_digest_is_stale_fails(
    gate: ModuleType,
    manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    table = _truthful_table(manifest)
    _stub_fetch(gate, monkeypatch, table)
    assert gate.verify_upstream() == 1
    assert "names an upstream it did not come from" in capsys.readouterr().err


def test_a_fetch_failure_is_never_a_pass(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(url: str) -> bytes:
        raise RuntimeError("network is down")

    monkeypatch.setattr(gate, "_fetch", boom)
    assert gate.verify_upstream() == 1
    assert "could not fetch" in capsys.readouterr().err


def test_the_real_manifest_verifies_against_truthful_upstreams(
    gate: ModuleType,
    manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Against upstreams that really published the vendored bytes, it passes.

    Every verbatim file and every derived source must be reported OK, and the
    run must exit 0.  The first revision asserted only ``rc == 1`` (the
    derived half could not match a stub), so a broken verbatim comparison --
    every file reported as not matching -- still exited 1 and passed.
    """
    table = _truthful_table(manifest)
    _stub_fetch(gate, monkeypatch, table)
    _stub_digests(gate, monkeypatch)
    rc = gate.verify_upstream()
    out = capsys.readouterr()
    assert rc == 0, out.err
    for relative in manifest["verbatim"]:
        assert f"verbatim   OK  {relative}" in out.out, relative
    derived_sources = 0
    for relative, entry in manifest["derived"].items():
        for source in entry["sources"]:
            derived_sources += 1
            assert f"derived    OK  {relative} <- {source['digest_field']}" in out.out
    assert manifest["verbatim"] and derived_sources, "nothing was compared"


def test_a_run_that_compares_nothing_is_not_a_pass(
    gate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Coverage satisfied, zero fetchable files: exit 2, not 0."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "files": {"v.json": "00" * 32},
                "verbatim": {},
                "derived": {},
                "verified_elsewhere": {},
                "unverifiable": {"v.json": "no public source"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "MANIFEST_PATH", manifest_path)
    assert gate.verify_upstream() == 2
    assert "no upstream comparison was actually performed" in capsys.readouterr().err


def test_the_offline_check_is_unaffected(gate: ModuleType) -> None:
    """--verify-upstream must not have changed the digest-only path."""
    assert gate.main([]) == 0
