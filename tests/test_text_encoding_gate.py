# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls and wiring for ``tools/check_text_encoding.py``.

Each shape the gate exists to refuse is planted and must be reported; each
shape it must leave alone (binary modes, descriptor-level ``os.open``, an
``OpenerDirector.open(request)``, an explicit encoding) must not be.  The real
tree is then held to zero findings, and the exact defect that failed every
Windows leg of 187934e6 -- a bare ``write_text`` on a ``tmp_path / ...``
expression -- is replayed through the gate, because ruff's PLW1514 measurably
does not flag that receiver and this gate exists to.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tools import check_text_encoding as gate

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _messages(source: str) -> list[str]:
    return [f.message for f in gate.scan_source(textwrap.dedent(source), "snippet.py")]


@pytest.mark.parametrize(
    "source",
    [
        "p.read_text()\n",
        "p.write_text(data)\n",
        "(tmp_path / 'src' / 'x.pyx').write_text(text.replace('a', 'b', 1))\n",
        "open(path)\n",
        "open(path, 'w')\n",
        "open(path, mode='a+')\n",
        "io.open(path, 'r')\n",
        "os.fdopen(fd, 'w')\n",
        "path.open()\n",
        "path.open('w')\n",
        "tempfile.NamedTemporaryFile('w', suffix='.py')\n",
        "tempfile.SpooledTemporaryFile(mode='w+')\n",
    ],
    ids=[
        "read_text",
        "write_text",
        "the-187934e6-defect",
        "open-default",
        "open-w",
        "open-mode-kw",
        "io-open",
        "os-fdopen",
        "path-open-default",
        "path-open-w",
        "named-tempfile-text",
        "spooled-tempfile-text",
    ],
)
def test_a_text_access_without_an_encoding_is_reported(source: str) -> None:
    assert len(_messages(source)) == 1, source


@pytest.mark.parametrize(
    "source",
    [
        "p.read_text(encoding='utf-8')\n",
        "p.write_text(data, encoding='locale')\n",
        "open(path, 'rb')\n",
        "open(path, mode='wb')\n",
        "open(path, encoding='utf-8')\n",
        "os.fdopen(fd, 'wb')\n",
        "os.open(path, os.O_RDONLY)\n",
        "_os.open(str(p), flags, 0o600)\n",
        "opener.open(req, timeout=5)\n",
        "archive.open('member.txt')\n",
        "path.open('rb')\n",
        "tempfile.NamedTemporaryFile(suffix='.bin')\n",
        "tempfile.TemporaryFile('w+b')\n",
    ],
)
def test_a_binary_or_explicit_access_is_left_alone(source: str) -> None:
    assert _messages(source) == [], source


@pytest.mark.parametrize(
    "source",
    ["open(path, mode)\n", "p.read_text(**kwargs)\n", "open(path, 'w', **kw)\n"],
    ids=["computed-mode", "forwarded-kwargs", "text-mode-plus-kwargs"],
)
def test_an_undecidable_call_is_reported_not_guessed(source: str) -> None:
    assert len(_messages(source)) == 1, source


def test_the_tree_has_no_finding() -> None:
    findings, count = gate.scan(REPO_ROOT)
    assert findings == [], [f"{f.path}:{f.line}" for f in findings]
    assert count >= gate.MIN_FILES


def test_the_main_entry_point_passes_on_the_tree_and_fails_on_a_planted_site(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gate.main([]) == 0
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "bad.py").write_text(
        "from pathlib import Path\nPath('x').read_text()\n", encoding="utf-8"
    )
    assert gate.main(["--root", str(tmp_path), "--min-files", "1"]) == 1
    assert "tools/bad.py:2:" in capsys.readouterr().out


def test_a_scan_that_finds_too_few_files_fails(tmp_path: Path) -> None:
    """A mis-rooted run must not pass by scanning nothing."""
    assert gate.main(["--root", str(tmp_path)]) == 1


def test_build_output_and_virtual_environments_are_not_scanned(tmp_path: Path) -> None:
    for skipped in ("build", "_build", ".venv"):
        target = tmp_path / "tools" / skipped
        target.mkdir(parents=True)
        (target / "gen.py").write_text("open('x')\n", encoding="utf-8")
    findings, count = gate.scan(tmp_path)
    assert (findings, count) == ([], 0)


def test_the_gate_is_wired_into_ci() -> None:
    text = CI_YML.read_text(encoding="utf-8")
    assert "python tools/check_text_encoding.py" in text
