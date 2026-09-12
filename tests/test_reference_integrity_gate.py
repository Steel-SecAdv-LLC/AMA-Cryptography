# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_reference_integrity.py``.

The gate rejects citations a reader cannot resolve. A gate nobody has watched
fail is a gate nobody has watched, so every shape it claims to catch is driven
through it here, and — the half that matters more for a pattern-based check —
so is every shape it must NOT catch.

The false-positive cases are not padding; they are most of the point. Earlier
versions of this gate also matched "the audit's", "a previous session",
"another session" and "the audit session". Every one of them caught real
dangling references — and every one also matched correct prose, because
``tools/check_error_state_gating.py`` defines a function named ``audit()`` and
this package implements ``SessionStore``. A pattern that forces correct prose to
change in order to satisfy a linter is a worse defect than the one it caught,
and a gate that cries wolf is a gate that gets switched off. Those clauses were
dropped, the four dangling uses they had found were fixed by hand, and the cases
below pin the boundary so it cannot drift back.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.check_reference_integrity import (  # noqa: E402 -- repo-root path insert above (REF-001)
    EXEMPT,
    check,
    main,
    scan_text,
)


class TestTheShapesItMustCatch:
    """Each is a reference to something no reader of the repository can open."""

    @pytest.mark.parametrize(
        "text",
        [
            "# (2026-08 v5 audit, item 15 — alert-window suppression.)",
            "# see 2026-09 v5 audit for the rationale",
            "# fixed per item 15 of the audit",
            '"""Regression pin from the 2025-12 v4 audit."""',
        ],
    )
    def test_a_process_citation_is_reported(self, text: str) -> None:
        findings = scan_text(text)
        assert findings, f"not caught: {text!r}"
        assert "not in the repository" in findings[0][2]

    @pytest.mark.parametrize(
        "text",
        [
            "# the AEAD nonce at line 632",
            "# markers at lines 314 and 339",
            "# see line 1098 for the second draw",
            "# per lines 40",
        ],
    )
    def test_a_source_line_citation_is_reported(self, text: str) -> None:
        findings = scan_text(text)
        assert findings, f"not caught: {text!r}"
        assert "line number" in findings[0][2]

    def test_the_report_names_the_line_it_found(self) -> None:
        line, matched, _ = scan_text("alpha\nbeta\n# (2026-08 v5 audit)\n")[0]
        assert line == 3
        assert "2026-08 v5 audit" in matched


class TestTheShapesItMustNotCatch:
    """Correct prose must survive the gate untouched."""

    @pytest.mark.parametrize(
        "text",
        [
            # Protocol sessions are not development sessions.
            "# the AEAD nonce and this session ID are both bare draws",
            "* @param num_signers  Number of signers in this session",
            "ttl_seconds: Override default TTL for this session",
            "# a session that is closed in place must not be handed back",
            # `audit()` is a real function in tools/check_error_state_gating.py.
            "# Deleting the guard left the audit's output completely unchanged.",
            "# the one module this gate audits",
            # This package implements SessionStore/SessionState, so these read
            # as protocol prose.  Each phrasing below was written, caught real
            # instances, and was removed because it also matched correct code.
            "# a previous session's keys must not decrypt this one",
            "# rekeying starts another session",
            "# the audit session record is flushed on close",
            # Runtime messages carry a placeholder, not a citation.
            'raise ValueError(f"malformed entry at line {n}")',
            'printf("parse error at line %d\\n", lineno);',
            # A line COUNT is not a line citation.
            "# seventeen hundred lines above",
            "# the diff touched 632 lines",
        ],
    )
    def test_correct_prose_is_left_alone(self, text: str) -> None:
        assert scan_text(text) == [], f"false positive on: {text!r}"


class TestTheExemptionsAreHonest:
    """An exemption is a hole; each one here must still be load-bearing."""

    def test_there_are_exactly_three(self) -> None:
        assert set(EXEMPT) == {
            "CHANGELOG.md",
            "tools/check_reference_integrity.py",
            "tests/test_reference_integrity_gate.py",
        }, (
            "the exemption list changed — a new entry is a new place for an "
            "unresolvable citation to hide, and needs its own justification"
        )

    def test_each_carries_a_reason(self) -> None:
        for name, reason in EXEMPT.items():
            assert reason.strip(), f"{name} is exempt with no stated reason"

    @pytest.mark.parametrize("name", sorted(EXEMPT))
    def test_each_exempt_file_really_would_trip_the_gate(self, name: str) -> None:
        # The point of the exemption is that the file legitimately contains a
        # rejected shape.  If it no longer does, the exemption has outlived its
        # reason and is now only a hole.
        path = REPO_ROOT / name
        assert path.is_file(), f"{name} is exempt but does not exist"
        assert scan_text(path.read_text(encoding="utf-8")), (
            f"{name} no longer contains any rejected shape, so its exemption "
            "now proves nothing — remove it from EXEMPT"
        )

    def test_an_exempt_file_is_not_scanned(self) -> None:
        _, problems = check(REPO_ROOT)
        for name in EXEMPT:
            assert not any(p.startswith(f"{name}:") for p in problems)


class TestTheTreeIsClean:
    """The gate's verdict on the repository as it actually stands."""

    def test_every_citation_in_the_shipped_tree_resolves(self) -> None:
        checked, problems = check(REPO_ROOT)
        assert problems == [], "\n".join(problems)
        assert checked > 100, f"only {checked} files scanned — scope collapsed"

    def test_the_cli_agrees(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--repo", str(REPO_ROOT)]) == 0
        assert "every citation resolves" in capsys.readouterr().out

    def test_the_cli_reports_failure_on_a_planted_violation(self, tmp_path: Path) -> None:
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir()
        (pkg / "planted.py").write_text("# (2026-08 v5 audit, item 15)\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        assert main(["--repo", str(tmp_path)]) == 1

    def test_the_epilog_states_what_is_not_checked(self) -> None:
        text = subprocess.run(
            [sys.executable, "tools/check_reference_integrity.py", "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert "NOT checked" in text
        assert "CHANGELOG.md" in text
