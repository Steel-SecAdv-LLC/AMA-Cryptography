# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``nist_vectors/fetch_vectors.py``'s failure reporting.

The step whose only job is to acquire the NIST ACVP vectors used to report
success having acquired none: ``fetch_acvp_vectors`` printed ``[ERROR]`` and
continued, and ``main`` returned 0 unconditionally. So a fetch failure left the
`Fetch NIST ACVP vectors` step green, and the run surfaced two steps later as
``nist_vectors/results.json missing — harness crashed`` — a message that names
the wrong component and sends the reader to the wrong file.

That is a fail-open gate on the evidence behind a published FIPS attestation,
which is the one direction it must never fail in.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TOOL_PATH = REPO_ROOT / "nist_vectors" / "fetch_vectors.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("acvp_fetch_vectors", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load()


def test_a_failed_fetch_is_returned_not_swallowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Every algorithm that could not be fetched comes back to the caller."""
    monkeypatch.setattr(tool, "VECTORS_DIR", tmp_path)

    def boom(algo_dir: str, filename: str) -> dict[str, Any]:
        raise ConnectionResetError(104, "Connection reset by peer")

    monkeypatch.setattr(tool, "fetch_acvp_file", boom)
    failures = tool.fetch_acvp_vectors()
    assert len(failures) == len(
        tool.ACVP_FETCH_LIST
    ), "a fetch that acquired nothing must report every missing algorithm"


def test_main_fails_when_vectors_are_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The property that failed in CI: exit status must reflect the outcome.

    `main` returned 0 unconditionally, so the workflow step passed and the
    validation step took the blame for the missing file.
    """
    monkeypatch.setattr(tool, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(tool, "fetch_acvp_vectors", lambda: ["ML-KEM-keyGen-FIPS203"])
    monkeypatch.setattr(tool, "create_sha256_vectors", lambda: None)
    monkeypatch.setattr(tool, "create_aes256gcm_vectors", lambda: None)
    assert tool.main() == 1, "a fetch with missing vectors must fail the step"


def test_main_succeeds_when_everything_was_fetched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """...and the guard does not simply fail everything."""
    monkeypatch.setattr(tool, "VECTORS_DIR", tmp_path)
    monkeypatch.setattr(tool, "fetch_acvp_vectors", list)
    monkeypatch.setattr(tool, "create_sha256_vectors", lambda: None)
    monkeypatch.setattr(tool, "create_aes256gcm_vectors", lambda: None)
    assert tool.main() == 0


def test_the_fetch_goes_through_the_shared_retry_policy() -> None:
    """One retry policy, not one per fetcher.

    This defect existed in two places at once — here and in the Wycheproof
    corpus fetch — against the same host, and fixing only the first is what let
    the second fail an hour later. A second copy would regress that.
    """
    body = TOOL_PATH.read_text(encoding="utf-8")
    assert "http_fetch.fetch_bytes" in body, "ACVP fetch bypasses the shared policy"
    assert "urlopen" not in body, "ACVP fetch has grown its own unretried transport"
