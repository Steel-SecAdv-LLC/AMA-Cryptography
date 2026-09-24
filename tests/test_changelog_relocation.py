#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The 5.0.0 development journal left the CHANGELOG whole, and stays history.

``CHANGELOG.md`` had grown to 16,986 lines, 8,950 of them a dated per-pass
development journal recorded while 5.0.0 was prepared.  A first attempt to fix
that condensed the text and was reverted: condensing deletes the in-tree
rationale record.  The journal was therefore MOVED, verbatim, to
``docs/changelog/5.0.0-development-journal.md`` at commit ``974cb019``, and the
false ``## [5.0.0] - 2026-09-10`` heading (no 5.0.0 was ever tagged) became
``## [5.0.0] - Unreleased``.

"Verbatim" is a claim, so it is tested here rather than asserted in a commit
message:

* the pre-relocation file, read from git, partitions exactly into the spans
  that stayed and the spans that moved;
* the journal after its header is exactly the moved spans, in order, under two
  grouping headings, and no moved entry is left behind in the CHANGELOG;
* every retained span is unchanged — with named exceptions only: the figure
  ``tools/check_documented_counts.py`` refused once the heading stopped
  claiming a release date (see :data:`GLANCE_CORRECTION`), and the 5.0.0 row
  of the Version History Summary (see :data:`SUMMARY_ROW_CORRECTIONS`);
* reassembling the pre-relocation file from the two files as they stand gives
  back the pinned SHA-256 of the original, which holds without git history.

The journal is the same kind of document the CHANGELOG is, so the gates that
leave the CHANGELOG alone must leave it alone too.  Which files those are has
one definition, ``tools/_repo.py``'s :func:`is_historical_record`; its domain
is pinned below, and so is its effect on each gate that asks it: the journal is
exempt, and the same text anywhere else under ``docs/`` is still refused.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

from tools import _repo
from tools._repo import is_historical_record

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
JOURNAL_REL = "docs/changelog/5.0.0-development-journal.md"
JOURNAL = REPO_ROOT / JOURNAL_REL

#: The commit the journal was cut from, and the SHA-256 of its CHANGELOG.md.
BASE_COMMIT = "974cb019a2cf098495aaa6bbf4622b8cc8115484"
BASE_CHANGELOG_SHA256 = "58c84ba3ec3d9355db129636b031f198dbbf7232d7462cf7976699604faad9d7"

OLD_HEADING = "## [5.0.0] - 2026-09-10\n"
NEW_HEADING = "## [5.0.0] - Unreleased\n"
UNRELEASED_GROUP = "## Entries recorded under [Unreleased]\n\n"
RELEASE_GROUP = "## Entries recorded under [5.0.0]\n\n"
GLANCE_HEADING = "### Behavioural and breaking changes at a glance\n"
FIRST_RETAINED_ENTRY = "### Head `dfd35dcb`"
COMPLETION_ENTRY = "### Completion pass 2"
FIRST_CLASSIC_ENTRY = "### Security — a failed power-on self-test now fails the import"
V4_HEADING = "## [4.0.0] - 2026-08-01\n"

#: The one edit inside a retained span.  Row 1 of the glance table said 105
#: native entry points; ``tools/check_error_state_gating.py`` reports 107, and
#: INVARIANTS.md had said so since 2026-09-22.  Under the false date the
#: section was history to ``check_documented_counts.py``; headed
#: ``Unreleased`` it is the release notes being built, and the gate refused
#: the figure.  Named here so the exception is exactly one substitution.
GLANCE_CORRECTION = ("105 native entry points", "107 native entry points")

#: The two edits inside the retained tail, both on the 5.0.0 row of the
#: Version History Summary.  The row dated a release that was never tagged
#: (2026-09-10, the same false date the heading carried), and it totalled
#: ten breaking changes against a glance table of eleven.  Each substitution
#: must occur exactly once in the tail, so neither can widen into a licence.
SUMMARY_ROW_CORRECTIONS = (
    ("| 5.0.0 | 2026-09-10 |", "| 5.0.0 | Unreleased |"),
    ("BREAKING \u00d710 \u2014 see `[5.0.0]`", "BREAKING \u00d711 \u2014 see `[5.0.0]`"),
)


def _journal_body(journal: str) -> str:
    start = journal.index(UNRELEASED_GROUP)
    return journal[start:]


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _line_index(text: str, heading: str, start: int = 0) -> int:
    """Where ``heading`` starts a line of ``text`` — never a mention inside prose."""
    if text.startswith(heading, start) and (start == 0 or text[start - 1] == "\n"):
        return start
    return text.index("\n" + heading, max(start - 1, 0)) + 1


class TestTheTwoFilesReassembleTheOriginal:
    """Losslessness, proved without git history.

    Reassembling the pre-relocation CHANGELOG from the two files as they stand
    must reproduce its exact bytes (the SHA-256 pinned above).  A history-based
    variant read ``git show 974cb019:CHANGELOG.md``; it was dropped before
    merge because a squash or rebase merge leaves that commit unreachable from
    ``main``, where ``AMA_CI_REQUIRE_HISTORY`` would turn it into a failure.
    Exact reassembly implies what it checked: every moved span is in the
    journal in order, and every retained span is unchanged but for the one
    named correction.  New entries added above the first retained one are
    outside the reassembled span, so the test survives the CHANGELOG growing.
    """

    def test_reassembly_reproduces_the_pinned_bytes(self) -> None:
        changelog = _read(CHANGELOG)
        journal = _journal_body(_read(JOURNAL))
        moved_unreleased, moved_release = journal[len(UNRELEASED_GROUP) :].split(RELEASE_GROUP)

        preamble_end = _line_index(changelog, "## [Unreleased]\n\n") + len("## [Unreleased]\n\n")
        first_entry = changelog[
            _line_index(changelog, FIRST_RETAINED_ENTRY) : _line_index(changelog, NEW_HEADING)
        ]
        glance_and_classic = changelog[
            _line_index(changelog, GLANCE_HEADING) : _line_index(changelog, V4_HEADING)
        ]
        split_at = _line_index(glance_and_classic, FIRST_CLASSIC_ENTRY)
        before, after = GLANCE_CORRECTION
        glance = glance_and_classic[:split_at].replace(after, before)
        classic = glance_and_classic[split_at:]
        completion = _line_index(moved_release, COMPLETION_ENTRY)
        tail = changelog[_line_index(changelog, V4_HEADING) :]
        for original, corrected in SUMMARY_ROW_CORRECTIONS:
            assert tail.count(corrected) == 1, corrected
            tail = tail.replace(corrected, original)

        rebuilt = (
            changelog[:preamble_end]
            + first_entry
            + moved_unreleased
            + OLD_HEADING
            + "\n"
            + moved_release[:completion]
            + glance
            + moved_release[completion:]
            + "\n"
            + classic
            + tail
        )
        assert hashlib.sha256(rebuilt.encode("utf-8")).hexdigest() == BASE_CHANGELOG_SHA256


# ---------------------------------------------------------------------------
# The one definition of the historical record
# ---------------------------------------------------------------------------


class TestTheHistoricalRecordPredicate:
    @pytest.mark.parametrize(
        "path",
        [
            "CHANGELOG.md",
            "./CHANGELOG.md",
            JOURNAL_REL,
            "docs/changelog/6.0.0-development-journal.md",
            "docs/changelog/nested/notes.md",
            REPO_ROOT / "CHANGELOG.md",
            REPO_ROOT / JOURNAL_REL,
        ],
    )
    def test_the_records(self, path: str | Path) -> None:
        assert is_historical_record(path)

    @pytest.mark.parametrize(
        "path",
        [
            "README.md",
            "docs/CHANGELOG.md",  # named like the record, somewhere else
            "wiki/CHANGELOG.md",
            "tests/CHANGELOG.md",
            "docs/changelog",  # the directory itself
            "docs/changelogs/notes.md",
            "docs/changelog.md",
            "docs/changelog/../METRICS_REPORT.md",
            "xdocs/changelog/notes.md",
            "docs/BENCHMARK_HISTORY.md",
            "changelog.md",
        ],
    )
    def test_everything_else(self, path: str) -> None:
        assert not is_historical_record(path)

    def test_an_absolute_path_is_read_against_the_given_repository(self, tmp_path: Path) -> None:
        assert is_historical_record(tmp_path / "CHANGELOG.md", repo=tmp_path)
        assert is_historical_record(tmp_path / JOURNAL_REL, repo=tmp_path)
        assert not is_historical_record(tmp_path / "README.md", repo=tmp_path)
        # Outside the repository it names nothing in it.
        assert not is_historical_record(tmp_path / "CHANGELOG.md")
        assert not is_historical_record(tmp_path / "CHANGELOG.md", repo=tmp_path / "docs")

    def test_every_declared_record_exists(self) -> None:
        """A record the tree does not have is a dead exemption, not a record."""
        for name in _repo.HISTORICAL_RECORD_FILES:
            assert (REPO_ROOT / name).is_file(), name
        for directory in _repo.HISTORICAL_RECORD_DIRS:
            assert _repo.tracked_names(REPO_ROOT, f"{directory}/"), directory


# ---------------------------------------------------------------------------
# What that definition does in each gate that asks it
# ---------------------------------------------------------------------------

_JOURNAL_FIXTURE = "docs/changelog/9.9.9-development-journal.md"
_LIVE_FIXTURE = "docs/NOTES.md"


def _write(repo: Path, relative: str, text: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _flagged(problems: list[str], relative: str) -> bool:
    return any(relative in problem for problem in problems)


class TestTheGatesLeaveTheJournalAlone:
    """In a journal the text is history; one directory over it is a defect."""

    def test_documented_counts(self, tmp_path: Path) -> None:
        from tools import check_documented_counts as gate

        native, _cython = gate.count_error_state_entry_points()
        stale = f"The ERROR state inhibits {native + 5} native entry points.\n"
        _write(tmp_path, _JOURNAL_FIXTURE, stale)
        _write(tmp_path, _LIVE_FIXTURE, stale)
        problems = gate.check_entry_point_counts(tmp_path)
        assert _flagged(problems, _LIVE_FIXTURE), problems
        assert not _flagged(problems, _JOURNAL_FIXTURE), problems

    def test_documented_counts_test_count_claims(self, tmp_path: Path) -> None:
        from tools import check_documented_counts as gate

        claim = "`tests/test_long_gone.py` — 12 tests\n"
        _write(tmp_path, _JOURNAL_FIXTURE, claim)
        _write(tmp_path, _LIVE_FIXTURE, claim)
        problems = gate.check_test_counts(tmp_path)
        assert _flagged(problems, _LIVE_FIXTURE), problems
        assert not _flagged(problems, _JOURNAL_FIXTURE), problems

    def test_hd_interop_honesty(self, tmp_path: Path) -> None:
        from tools import check_hd_interop_honesty as gate

        claim = "The HD wallet is BIP32-compatible.\n"
        _write(tmp_path, _JOURNAL_FIXTURE, claim)
        _write(tmp_path, _LIVE_FIXTURE, claim)
        files = [finding[0] for finding in gate.find_claims(tmp_path)]
        assert files == [_LIVE_FIXTURE]

    def test_crypto_construction_docs(self, tmp_path: Path) -> None:
        from tools import check_crypto_construction_docs as gate

        _write(tmp_path, _JOURNAL_FIXTURE, "history\n")
        _write(tmp_path, _LIVE_FIXTURE, "present\n")
        _write(tmp_path, "CHANGELOG.md", "history\n")
        scanned = {p.relative_to(tmp_path).as_posix() for p in gate.scanned_files(tmp_path)}
        assert scanned == {_LIVE_FIXTURE}

    def test_documented_extras(self, tmp_path: Path) -> None:
        from tools import check_documented_extras as gate

        line = 'pip install -e ".[secure-memory]"\n'
        _write(tmp_path, _JOURNAL_FIXTURE, line)
        _write(tmp_path, _LIVE_FIXTURE, line)
        sites = gate.scan(tmp_path)
        assert [site[0] for site in sites["secure-memory"]] == [_LIVE_FIXTURE]

    def test_version_consistency_tag_pins(self, tmp_path: Path) -> None:
        from tools import check_version_consistency as gate

        pin = "pip install git+https://example.invalid/AMA-Cryptography.git@v4.0.0\n"
        _write(tmp_path, _JOURNAL_FIXTURE, pin)
        _write(tmp_path, _LIVE_FIXTURE, pin)
        problems, checked = gate.scan_tag_pins(tmp_path, "5.0.0")
        assert checked == 1
        assert _flagged(problems, _LIVE_FIXTURE), problems
        assert not _flagged(problems, _JOURNAL_FIXTURE), problems

    def test_reference_integrity(self, tmp_path: Path) -> None:
        from tools import check_reference_integrity as gate

        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        # Assembled, so this file does not itself carry the shape the gate
        # rejects (it is in the gate's scope, and not one of its exemptions).
        citation = " ".join(["Fixed per the (2026-08", "v5", "audit,", "item", "15)."]) + "\n"
        _write(tmp_path, _JOURNAL_FIXTURE, citation)
        _write(tmp_path, _LIVE_FIXTURE, citation)
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        checked, problems = gate.check(tmp_path)
        assert checked == 1
        assert _flagged(problems, _LIVE_FIXTURE), problems
        assert not _flagged(problems, _JOURNAL_FIXTURE), problems


def test_the_journal_names_its_own_provenance() -> None:
    """The header says what the file is, where it came from, and that it is dated."""
    header = _read(JOURNAL)[: _read(JOURNAL).index(UNRELEASED_GROUP)]
    assert BASE_COMMIT[:8] in header
    assert re.search(r"describe the tree on that\s+entry's date", header), header
