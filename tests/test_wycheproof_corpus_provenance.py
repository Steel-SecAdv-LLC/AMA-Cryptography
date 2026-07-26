# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Automated provenance checks for the vendored Wycheproof corpus.

``tools/refresh_wycheproof_corpus.py`` re-derives the corpus provenance from
upstream and regenerates the manifest. These tests drive its *offline* half so
CI asserts, on every run and without network access, that every vendored file
still matches the SHA-256 and vector count recorded in ``manifest.json`` — and,
in the failure direction, that the check actually fails when a digest is wrong
(a provenance check that cannot fail is not a provenance check).

The upstream-bytes half (fetching from ``C2SP/wycheproof`` and comparing) needs
the network, so it is opt-in via ``AMA_WYCHEPROOF_ONLINE=1`` and skipped by
default to keep the suite hermetic.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "refresh_wycheproof_corpus.py"


def _load_tool() -> ModuleType:
    """Load tools/refresh_wycheproof_corpus.py — tools/ is not on sys.path, so
    importlib.util is the cleanest handle (mirrors tests/test_headers.py)."""
    spec = importlib.util.spec_from_file_location("refresh_wycheproof_corpus", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load_tool()


def test_vendored_corpus_matches_manifest(tool: ModuleType) -> None:
    """The provenance anchor: every vendored file's SHA-256 and vector count
    match the manifest, bidirectionally, and the totals add up. No network."""
    manifest = tool.load_manifest()
    problems = tool.verify_offline(manifest)
    assert problems == [], f"vendored corpus drifted from its manifest: {problems}"


def test_offline_verify_is_not_vacuous(tool: ModuleType) -> None:
    """Failure direction: corrupt one recorded digest and the check must flag
    exactly that file — so a real drift could never slip through as a pass."""
    manifest = copy.deepcopy(tool.load_manifest())
    victim = sorted(manifest["files"])[0]
    manifest["files"][victim]["sha256"] = "00" * 32
    problems = tool.verify_offline(manifest)
    assert any(
        victim in p and "sha256" in p for p in problems
    ), f"a wrong digest for {victim} was not caught: {problems}"


def test_offline_verify_catches_a_vector_count_drift(tool: ModuleType) -> None:
    """A silently added/removed vector must fail even if the digest field were
    (impossibly) still consistent — the count is asserted independently."""
    manifest = copy.deepcopy(tool.load_manifest())
    victim = sorted(manifest["files"])[0]
    manifest["files"][victim]["actualTests"] += 1
    manifest["totalVectors"] += 1
    problems = tool.verify_offline(manifest)
    assert any(
        victim in p and "actualTests" in p for p in problems
    ), f"a vector-count drift for {victim} was not caught: {problems}"


def test_derive_file_meta_counts_and_digest(tool: ModuleType) -> None:
    """derive_file_meta reproduces upstream's own accounting from raw bytes."""
    doc = {
        "algorithm": "TESTALG",
        "schema": "test_schema_v1.json",
        "numberOfTests": 3,
        "testGroups": [
            {"tests": [{"tcId": 1}, {"tcId": 2}]},
            {"tests": [{"tcId": 3}]},
        ],
    }
    raw = json.dumps(doc).encode("utf-8")
    meta = tool.derive_file_meta(raw)
    assert meta["actualTests"] == 3
    assert meta["numberOfTests"] == 3
    assert meta["testGroups"] == 2
    assert meta["bytes"] == len(raw)
    assert meta["algorithm"] == "TESTALG"
    assert meta["schema"] == "test_schema_v1.json"
    assert meta["sha256"] == hashlib.sha256(raw).hexdigest()


def test_upstream_url_targets_raw_github_at_the_commit(tool: ModuleType) -> None:
    manifest = tool.load_manifest()
    commit = manifest["upstream"]["commit"]
    url = tool.upstream_url(manifest, "ed25519_test.json", commit)
    assert url == (
        f"https://raw.githubusercontent.com/C2SP/wycheproof/{commit}"
        "/testvectors_v1/ed25519_test.json"
    )


@pytest.mark.skipif(
    os.environ.get("AMA_WYCHEPROOF_ONLINE") != "1",
    reason="network-dependent; set AMA_WYCHEPROOF_ONLINE=1 to check upstream bytes",
)
def test_vendored_bytes_match_upstream(tool: ModuleType) -> None:
    """Opt-in: fetch upstream at the pinned commit and confirm byte-identity."""
    manifest = tool.load_manifest()
    problems = tool.verify_upstream(manifest, manifest["upstream"]["commit"])
    assert problems == [], f"vendored bytes diverged from upstream: {problems}"
