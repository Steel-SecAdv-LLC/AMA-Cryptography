#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the documented install extra verifier (``tools/check_documented_extras.py``).

``pip`` does not fail on an extra a distribution does not provide.  It warns,
installs the package *without* it, and exits 0 — so a stale or misspelled name
in an install instruction produces an incomplete install and a success
message, surfacing much later as an ``ImportError`` from a subsystem the
reader believes they enabled.

``wiki/Installation.md`` — published to the public GitHub Wiki by
``wiki-sync.yml`` — shipped ``pip install -e ".[secure-memory]"``, described
as *"Libsodium secure memory bindings"*, and listed the same name in its
*"Everything at once"* line.  No such extra ever existed; ``secure_memory``
is stdlib-only; and INVARIANT-1 forbids libsodium outright.

Both directions are pinned here, because a checker that only ever reports
"clean" is indistinguishable from one that has stopped working:

* **Detection** — the historical defect reproduced verbatim, in both the
  single-extra and comma-separated forms.
* **Non-detection** — declared extras, PEP 685 punctuation and case variants
  (which pip itself accepts), Markdown link syntax, and lines that are not
  install commands must not produce findings, since a checker that cries wolf
  gets bypassed.

The final tests sweep the repository's own documentation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.check_documented_extras import (
    audit,
    declared_extras,
    extras_in_line,
    normalise,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('pip install -e ".[dev]"', {"dev"}),
        (
            'pip install -e ".[monitoring,legacy,hsm,secure-memory,dev]"',
            {"monitoring", "legacy", "hsm", "secure-memory", "dev"},
        ),
        ("pip install ama-cryptography[math]", {"math"}),
        ("pip install -e .[dev]", {"dev"}),
        ('pip install "./pkg[a, b]"', {"a", "b"}),
    ],
)
def test_extras_are_extracted(line: str, expected: set[str]) -> None:
    assert extras_in_line(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        # Markdown link syntax: the bracket follows whitespace, not a name.
        "See the [Installation Guide](wiki/Installation.md) before pip install.",
        # A footnote-style reference, likewise.
        "pip install from source [1]",
        # No extras group at all.
        "pip install -r requirements-dev.txt",
    ],
)
def test_non_extras_brackets_are_not_extracted(line: str) -> None:
    assert extras_in_line(line) == set()


# --------------------------------------------------------------------------
# PEP 685 normalisation — pip's own comparison
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "declared"),
    [
        ("secure_memory", "secure-memory"),
        ("Secure-Memory", "secure-memory"),
        ("secure.memory", "secure-memory"),
        ("secure__memory", "secure-memory"),
    ],
)
def test_punctuation_and_case_variants_compare_equal(written: str, declared: str) -> None:
    """pip accepts these as the same extra, so the checker must too."""
    assert normalise(written) == normalise(declared)


# --------------------------------------------------------------------------
# Detection and non-detection over a synthetic tree
# --------------------------------------------------------------------------


def _tree(tmp_path: Path, doc: str, *, filename: str = "README.md") -> Path:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "ama-cryptography"\n'
        'version = "3.4.0"\n'
        "\n"
        "[project.optional-dependencies]\n"
        "dev = []\n"
        "monitoring = []\n"
        "legacy = []\n"
        "hsm = []\n"
        "all = []\n",
        encoding="utf-8",
    )
    (tmp_path / filename).write_text(doc, encoding="utf-8")
    return tmp_path


def test_undeclared_extra_is_reported(tmp_path: Path) -> None:
    root = _tree(tmp_path, 'pip install -e ".[secure-memory]"\n')
    failures, _, _ = audit(root)
    assert len(failures) == 1
    assert "secure-memory" in failures[0]
    assert "exiting 0" in failures[0]


def test_undeclared_extra_inside_a_list_is_reported(tmp_path: Path) -> None:
    """The 'Everything at once' shape: one bad name among several good ones."""
    root = _tree(tmp_path, 'pip install -e ".[monitoring,legacy,hsm,secure-memory,dev]"\n')
    failures, _, _ = audit(root)
    assert len(failures) == 1
    assert "secure-memory" in failures[0]
    for good in ("monitoring", "legacy", "hsm"):
        assert f"names extra '{good}'" not in failures[0]


def test_declared_extras_pass(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        'pip install -e ".[dev]"\n'
        'pip install -e ".[monitoring,legacy,hsm,dev]"\n'
        'pip install -e ".[all]"\n',
    )
    failures, _, _ = audit(root)
    assert failures == []


def test_changelog_is_excluded(tmp_path: Path) -> None:
    """A removed extra must stay readable in the entry that removed it."""
    root = _tree(tmp_path, "nothing here\n")
    (root / "CHANGELOG.md").write_text(
        '- Removed the `secure-memory` extra: `pip install -e ".[secure-memory]"`\n',
        encoding="utf-8",
    )
    failures, _, _ = audit(root)
    assert failures == []


# --------------------------------------------------------------------------
# The repository's own documentation
# --------------------------------------------------------------------------


def test_repository_documentation_names_only_declared_extras() -> None:
    failures, documented, sites = audit(REPO_ROOT)
    assert sites > 0, "no install commands were found to check"
    assert documented > 0
    assert failures == [], "\n".join(failures)


def test_secure_memory_extra_is_gone_from_the_public_wiki() -> None:
    """Regression pin for the specific defect this checker was written for."""
    text = (REPO_ROOT / "wiki" / "Installation.md").read_text(encoding="utf-8")
    assert "secure-memory]" not in text
    assert "secure_memory]" not in text


def test_fallback_parser_agrees_with_tomllib() -> None:
    """The Python 3.10 path must see exactly what the real TOML parser sees.

    ``tomllib`` is stdlib only from 3.11 and this project supports 3.10, so
    ``declared_extras`` falls back to reading the one table it needs. A
    fallback that quietly disagreed would make the checker pass on 3.10 while
    failing on 3.11, or vice versa.
    """
    from tools.check_documented_extras import _toml_load, declared_extras_fallback

    if _toml_load is None:  # pragma: no cover - running on 3.10
        pytest.skip("tomllib unavailable; only the fallback path exists here")

    pyproject = REPO_ROOT / "pyproject.toml"
    assert declared_extras_fallback(pyproject) == declared_extras(pyproject)


def test_every_declared_extra_is_documented_somewhere() -> None:
    """The other direction: an extra nobody is told about may as well not exist."""
    from tools.check_documented_extras import scan

    declared = declared_extras(REPO_ROOT / "pyproject.toml")
    documented = {normalise(extra) for extra in scan(REPO_ROOT)}
    undocumented = sorted(declared - documented)
    assert undocumented == [], (
        f"declared in pyproject.toml but named in no install instruction: "
        f"{', '.join(undocumented)}"
    )
