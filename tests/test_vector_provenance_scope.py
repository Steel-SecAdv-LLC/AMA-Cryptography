# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The published-vector manifest must pin published vectors, and only those.

``tools/check_vector_provenance.py`` says of itself that its roots hold "bytes
published elsewhere [that] must not drift", and its failure message reads "a
vector that is not in the manifest is a vector this gate cannot notice being
rewritten".  Two things made both untrue.

**It swept whole directories.**  ``PROTECTED`` names roots, and
``_tracked_files`` hashed everything under them.  The manifest pinned
``nist_vectors/run_vectors.py`` (54 KB of first-party Python, "Copyright (C)
2025-2026 Steel Security Advisors LLC"), ``nist_vectors/fetch_vectors.py``,
``nist_vectors/.gitignore`` and four ``README.md`` files — seven of thirty-seven
entries that no upstream publishes.  The same branch put those Python files
under black, ruff and ``mypy --strict``, so a reformat would fail a gate whose
message says the file no longer matches what NIST published.

**And it consulted neither git nor .gitignore**, despite the name
``_tracked_files``.  ``nist_vectors/.gitignore`` lists twelve files the tooling
deliberately generates there — the ten ACVP JSONs ``fetch_vectors.py``
downloads, ``results.json``, ``validation_summary.json``, ``acvp_badge.json``.
Any of them present made the gate exit 1 on a developer who had simply run the
ACVP flow.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_vector_provenance.py"
MANIFEST = REPO_ROOT / "tests" / "kat" / "PROVENANCE.json"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_vector_provenance", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest_paths() -> list[str]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    files = data.get("files", data)
    return sorted(files)


def test_the_manifest_is_not_empty() -> None:
    """Non-vacuity: every assertion below iterates this list."""
    assert len(_manifest_paths()) >= 20


def test_the_manifest_pins_no_first_party_source() -> None:
    offenders = [
        path
        for path in _manifest_paths()
        if path.endswith((".py", ".md", ".sh", ".cfg", ".toml", ".gitignore"))
    ]
    assert not offenders, (
        "the published-vector manifest pins files no upstream publishes, so a "
        f"reformat or a type annotation reads as vector drift: {offenders}"
    )


def test_every_pinned_path_has_a_vector_suffix(tool: ModuleType) -> None:
    bad = [
        path for path in _manifest_paths() if Path(path).suffix.lower() not in tool.VECTOR_SUFFIXES
    ]
    assert not bad, bad


def test_a_generated_untracked_vector_is_not_demanded(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file the ACVP flow writes must not be reported as an unpinned vector.

    Driven through ``_tracked_files`` directly against a synthetic root, so the
    test neither writes into the repository nor depends on whether the ACVP
    flow has been run here.
    """
    root = tmp_path / "vectors"
    root.mkdir()
    (root / "published.json").write_text("{}", encoding="utf-8")
    (root / "generated.json").write_text("{}", encoding="utf-8")
    (root / "runner.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(tool, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        tool, "_git_tracked", lambda: frozenset({"vectors/published.json", "vectors/runner.py"})
    )

    found = {path.name for path in tool._tracked_files(root)}
    assert found == {"published.json"}, found


def test_a_tree_without_git_still_scans(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A source tarball has no git; refusing to run there is worse than running."""
    root = tmp_path / "vectors"
    root.mkdir()
    (root / "published.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(tool, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(tool, "_git_tracked", frozenset)

    assert {path.name for path in tool._tracked_files(root)} == {"published.json"}
