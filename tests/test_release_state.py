# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for tools/check_release_state.py (audit M12).

The gate refuses a release whose own shipped documents still call the version
unreleased.  Two lifecycle events are kept separate: tag-state markers ("not
tagged yet", the CHANGELOG "Unreleased" heading) become false the instant the
tag exists and are enforced always; PyPI-publish-state markers ("not published
yet") are decoupled from the tag and enforced only under ``--require-published``,
because on a release that does not publish to PyPI those rows stay true.

Behavioural assertions run against SYNTHETIC trees so they are independent of
the repository's own release phase: a "real tree must fail" assertion would
break the very commit a release engineer makes to clear the markers.  Against
the real tree we assert only that all release-state documents exist and are
scanned, plus a phase-robust witness: while the tree still carries the
"Unreleased" heading, the gate must flag it.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_release_state.py"


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    """Load tools/check_release_state.py as a module.

    The script lives in a non-package directory that isn't on sys.path, so
    importlib.util is the cleanest handle that doesn't require modifying the
    tool layout (mirrors tests/test_version_consistency.py)."""
    spec = importlib.util.spec_from_file_location("check_release_state", TOOL_PATH)
    assert spec is not None, f"could not build a ModuleSpec for {TOOL_PATH}"
    assert spec.loader is not None, f"ModuleSpec for {TOOL_PATH} has no loader"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _canonical_version() -> str:
    """The version under [project] in pyproject.toml, so these tests track the
    real release version instead of pinning a literal that goes stale.

    Read with the same line-anchored regex tools/check_version_consistency.py
    uses for the pyproject anchor, which avoids depending on tomllib (absent on
    the project's 3.10 support floor)."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None, "pyproject [project].version not found"
    return match.group(1)


# Prose that mirrors the phrasing the real shipped documents carry while a
# version is in preparation, so a synthetic tree is a faithful proxy for the
# thing the gate runs against at release time.
def _unreleased_tree(root: Path, version: str) -> None:
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## [{version}] - Unreleased\n\n- pending\n\n"
        "## Version History Summary\n\n| Version | Date | Description |\n|---|---|---|\n"
        f"| {version} | Unreleased | the release |\n",
        encoding="utf-8",
    )
    (root / "ARCHITECTURE.md").write_text(
        "# Architecture\n\n| Version | Date | Author | Changes |\n|---|---|---|---|\n"
        f"| {version} | Unreleased | Steel Security Advisors LLC | the release |\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text(
        "# AMA\n\n"
        "| PyPI (`pip install ama-cryptography`) | **Not published yet** | No |\n\n"
        f"> **`v{version}` is not tagged yet.** This tree is {version} in preparation.\n\n"
        "#### 3. PyPI — planned, not yet published\n\n"
        "pip does not install this library today.\n",
        encoding="utf-8",
    )
    (root / "SECURITY.md").write_text(
        f"# Security\n\n{version} is prepared but **not yet tagged or published**.\n",
        encoding="utf-8",
    )
    (root / "docs" / "index.rst").write_text(
        f"Welcome\n=======\n\n``v{version}`` **is not tagged yet.**\n", encoding="utf-8"
    )


def _released_tree(root: Path, version: str) -> None:
    (root / "docs").mkdir(parents=True, exist_ok=True)
    # Keep a Changelog keeps an empty [Unreleased] heading above the release;
    # a thematic break in it is not content.
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## [Unreleased]\n\n---\n\n## [{version}] - 2026-08-24\n\n"
        "- released\n\n## Version History Summary\n\n| Version | Date | Description |\n"
        f"|---|---|---|\n| {version} | 2026-08-24 | the release |\n",
        encoding="utf-8",
    )
    (root / "ARCHITECTURE.md").write_text(
        "# Architecture\n\n| Version | Date | Author | Changes |\n|---|---|---|---|\n"
        f"| {version} | 2026-08-24 | Steel Security Advisors LLC | the release |\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text(
        "# AMA\n\n"
        "| PyPI (`pip install ama-cryptography`) | **Published** | No |\n\n"
        f"> `v{version}` is tagged and available.\n\n"
        "#### 3. PyPI — published\n\n"
        "pip install ama-cryptography works.\n",
        encoding="utf-8",
    )
    (root / "SECURITY.md").write_text(
        f"# Security\n\n{version} is tagged and published.\n", encoding="utf-8"
    )
    (root / "docs" / "index.rst").write_text(
        f"Welcome\n=======\n\n``v{version}`` is tagged and available.\n", encoding="utf-8"
    )


# --------------------------------------------------------------------------
# Synthetic unreleased tree: the tag-state markers must be caught; the PyPI
# rows must be caught only under --require-published.
# --------------------------------------------------------------------------
class TestUnreleasedTree:
    def test_tag_state_markers_flagged_by_default(self, tool: ModuleType, tmp_path: Path) -> None:
        _unreleased_tree(tmp_path, "5.0.0")
        problems, scanned = tool.scan(tmp_path, "5.0.0", require_published=False)
        assert scanned == len(tool.RELEASE_STATE_FILES)
        blob = "\n".join(problems)
        assert "CHANGELOG.md" in blob and "Unreleased" in blob
        assert "README.md" in blob and "not tagged yet" in blob
        assert "SECURITY.md" in blob and "not yet tagged" in blob
        assert "index.rst" in blob and "not tagged yet" in blob

    def test_an_undated_version_row_is_flagged_in_every_table(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """PIN: the CHANGELOG summary row and the ARCHITECTURE revision row.

        Each is checked with every other marker cleared, so neither can pass
        on the strength of the CHANGELOG heading.
        """
        _released_tree(tmp_path, "5.0.0")
        for rel in ("CHANGELOG.md", "ARCHITECTURE.md"):
            path = tmp_path / rel
            released = path.read_text(encoding="utf-8")
            path.write_text(
                released.replace("| 5.0.0 | 2026-08-24 |", "| 5.0.0 | Unreleased |"),
                encoding="utf-8",
            )
            problems, _ = tool.scan(tmp_path, "5.0.0", require_published=False)
            flagged = [p for p in problems if f"{rel}:" in p and "version-table row" in p]
            assert flagged, (rel, problems)
            path.write_text(released, encoding="utf-8")

    def test_entries_under_the_bare_unreleased_heading_are_flagged(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """PIN: the tag ships them, so they are release content filed as post-release."""
        _released_tree(tmp_path, "5.0.0")
        path = tmp_path / "CHANGELOG.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "## [Unreleased]\n\n---\n", "## [Unreleased]\n\n---\n\n- a late fix\n"
            ),
            encoding="utf-8",
        )
        problems, _ = tool.scan(tmp_path, "5.0.0", require_published=False)
        assert any("[Unreleased]" in p and "a late fix" in p for p in problems), problems

    def test_a_version_row_about_another_version_is_not_flagged(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        _released_tree(tmp_path, "5.0.0")
        path = tmp_path / "ARCHITECTURE.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "| 6.0.0 | Unreleased | x | planned |\n",
            encoding="utf-8",
        )
        assert tool.scan(tmp_path, "5.0.0", require_published=False)[0] == []

    def test_pypi_rows_not_flagged_by_default(self, tool: ModuleType, tmp_path: Path) -> None:
        # PyPI publication is decoupled from the tag; on a non-publishing release
        # these rows are correct and must not be flipped, so the default run must
        # not report them.
        _unreleased_tree(tmp_path, "5.0.0")
        problems, _ = tool.scan(tmp_path, "5.0.0", require_published=False)
        blob = "\n".join(problems)
        assert "not published yet" not in blob.lower()
        assert "not yet published" not in blob.lower()

    def test_pypi_rows_flagged_with_require_published(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        _unreleased_tree(tmp_path, "5.0.0")
        problems, _ = tool.scan(tmp_path, "5.0.0", require_published=True)
        blob = "\n".join(problems).lower()
        # The tag-state markers are still there AND the two PyPI rows now appear.
        assert "not published yet" in blob
        assert "not yet published" in blob

    def test_require_published_is_a_superset(self, tool: ModuleType, tmp_path: Path) -> None:
        _unreleased_tree(tmp_path, "5.0.0")
        default, _ = tool.scan(tmp_path, "5.0.0", require_published=False)
        published, _ = tool.scan(tmp_path, "5.0.0", require_published=True)
        assert set(default).issubset(set(published))
        assert len(published) > len(default)


# --------------------------------------------------------------------------
# Synthetic released tree: both modes must pass.
# --------------------------------------------------------------------------
class TestReleasedTree:
    def test_passes_by_default(self, tool: ModuleType, tmp_path: Path) -> None:
        _released_tree(tmp_path, "5.0.0")
        problems, scanned = tool.scan(tmp_path, "5.0.0", require_published=False)
        assert problems == []
        assert scanned == len(tool.RELEASE_STATE_FILES)

    def test_passes_with_require_published(self, tool: ModuleType, tmp_path: Path) -> None:
        _released_tree(tmp_path, "5.0.0")
        problems, _ = tool.scan(tmp_path, "5.0.0", require_published=True)
        assert problems == []


# --------------------------------------------------------------------------
# Version scoping and missing files.
# --------------------------------------------------------------------------
class TestPrematureReleaseDates:
    """A version row may not date a release the CHANGELOG still calls unreleased.

    The 5.0.0 rows in the CHANGELOG's Version History Summary, ARCHITECTURE.md
    and SECURITY.md read ``2026-09-10`` for a tag that was never cut.  The tag
    preflight cannot see that — it runs only on a tag — so this half runs here,
    on every CI run.
    """

    def test_a_dated_row_under_an_unreleased_heading_is_reported(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        _unreleased_tree(tmp_path, "5.0.0")
        path = tmp_path / "ARCHITECTURE.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "| 5.0.0 | Unreleased |", "| 5.0.0 | 2026-09-10 |"
            ),
            encoding="utf-8",
        )
        problems = tool.premature_release_dates(tmp_path, "5.0.0")
        assert len(problems) == 1 and "ARCHITECTURE.md" in problems[0], problems
        assert "2026-09-10" in problems[0]

    def test_undated_rows_under_an_unreleased_heading_pass(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        _unreleased_tree(tmp_path, "5.0.0")
        assert tool.premature_release_dates(tmp_path, "5.0.0") == []

    def test_dated_rows_under_a_dated_heading_pass(self, tool: ModuleType, tmp_path: Path) -> None:
        _released_tree(tmp_path, "5.0.0")
        assert tool.premature_release_dates(tmp_path, "5.0.0") == []


class TestVersionScopingAndMissing:
    def test_changelog_heading_is_version_scoped(self, tool: ModuleType, tmp_path: Path) -> None:
        # A CHANGELOG heading for 5.0.0 must not be flagged when 6.0.0 is being
        # released: only the heading of the version under release is enforced.
        # 6.0.0 carries its own dated section, which a release must have.
        _unreleased_tree(tmp_path, "5.0.0")
        changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
        (tmp_path / "CHANGELOG.md").write_text(
            changelog.replace("# Changelog\n\n", "# Changelog\n\n## [6.0.0] - 2026-10-01\n\n"),
            encoding="utf-8",
        )
        problems, _ = tool.scan(tmp_path, "6.0.0", require_published=False)
        assert not any("CHANGELOG.md" in p for p in problems), problems

    def test_missing_release_state_file_fails(self, tool: ModuleType, tmp_path: Path) -> None:
        _released_tree(tmp_path, "5.0.0")
        (tmp_path / "SECURITY.md").unlink()
        problems, scanned = tool.scan(tmp_path, "5.0.0", require_published=False)
        assert scanned == len(tool.RELEASE_STATE_FILES) - 1
        assert any("SECURITY.md" in p and "not found" in p for p in problems)

    def test_a_historical_marker_about_another_version_is_not_flagged(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The two "tagged" phrase markers are version-scoped, like the heading.

        They used to carry no version anchor while ``scan()`` pointed them at
        the whole of CHANGELOG.md — the file most likely to legitimately
        discuss PAST unreleased states, and the exact over-broad sweep the
        curated file list's docstring says it exists to avoid.  A 5.0.0
        release note recording "v4.0.0 was not yet tagged when this landed"
        would have failed the release-day preflight.
        """
        _released_tree(tmp_path, "5.0.0")
        changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
        (tmp_path / "CHANGELOG.md").write_text(
            changelog + "\n- v4.0.0 was not yet tagged when this landed.\n",
            encoding="utf-8",
        )
        problems, _ = tool.scan(tmp_path, "5.0.0", require_published=False)
        assert problems == [], problems

    def test_a_marker_about_the_version_under_release_is_still_flagged(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The control: scoping must not weaken the live-marker catch."""
        _released_tree(tmp_path, "5.0.0")
        changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
        (tmp_path / "CHANGELOG.md").write_text(
            changelog + "\n- v5.0.0 is not yet tagged.\n", encoding="utf-8"
        )
        problems, _ = tool.scan(tmp_path, "5.0.0", require_published=False)
        assert any("not yet tagged" in p for p in problems), problems


# --------------------------------------------------------------------------
# The CHANGELOG's real pre-release form: notes under a version-less
# ``## [Unreleased]`` heading, no section for the version at all.
# --------------------------------------------------------------------------
def _changelog_tree(root: Path, changelog: str, version: str) -> None:
    _released_tree(root, version)
    (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")


class TestChangelogMustRecordTheRelease:
    """The marker set could only refuse a statement that is present.

    Before a release this CHANGELOG files its notes under Keep a Changelog's
    ``## [Unreleased]`` — no version in the brackets — and has no heading for
    the version at all.  Tagging ``v5.0.1`` from that state matched nothing,
    and the preflight passed a tag whose CHANGELOG called its own contents
    unreleased.
    """

    def test_notes_still_under_unreleased_with_no_section_fail(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The audited scenario, exactly."""
        _changelog_tree(
            tmp_path,
            "# Changelog\n\n## [Unreleased]\n\n- the 5.0.1 fixes\n\n"
            "## [5.0.0] - 2026-09-01\n\n- old\n",
            "5.0.1",
        )
        assert tool.main(["--version", "5.0.1", "--repo", str(tmp_path)]) == 1
        problems, _ = tool.scan(tmp_path, "5.0.1", require_published=False)
        assert any("no dated '## [5.0.1]" in p for p in problems), problems
        assert any("CHANGELOG.md:5:" in p and "[Unreleased]" in p for p in problems), problems

    def test_an_undated_version_heading_fails(self, tool: ModuleType, tmp_path: Path) -> None:
        _changelog_tree(tmp_path, "# Changelog\n\n## [5.0.1]\n\n- fixes\n", "5.0.1")
        problems, _ = tool.scan(tmp_path, "5.0.1", require_published=False)
        assert any("no dated '## [5.0.1]" in p for p in problems), problems

    def test_another_versions_dated_heading_does_not_count(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        _changelog_tree(tmp_path, "# Changelog\n\n## [5.0.10] - 2026-10-01\n\n- x\n", "5.0.1")
        problems, _ = tool.scan(tmp_path, "5.0.1", require_published=False)
        assert any("no dated '## [5.0.1]" in p for p in problems), problems

    def test_entries_left_under_unreleased_fail_even_with_a_dated_section(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Everything in the tree ships in the tag, so an entry left behind is misfiled."""
        _changelog_tree(
            tmp_path,
            "# Changelog\n\n---\n\n## [Unreleased]\n\n### Fixed\n\n- late fix\n\n"
            "## [5.0.1] - 2026-10-01\n\n- fixes\n",
            "5.0.1",
        )
        problems, _ = tool.scan(tmp_path, "5.0.1", require_published=False)
        assert len(problems) == 1 and "CHANGELOG.md:9:" in problems[0], problems

    def test_the_empty_placeholder_is_accepted(self, tool: ModuleType, tmp_path: Path) -> None:
        """The control: the convention itself — an empty ``[Unreleased]`` — stays legal."""
        _changelog_tree(
            tmp_path,
            "# Changelog\n\n---\n\n## [Unreleased]\n\n### Added\n\n***\n\n---\n\n"
            "## [5.0.1] - 2026-10-01\n\n### Fixed\n\n- fixes\n",
            "5.0.1",
        )
        problems, _ = tool.scan(tmp_path, "5.0.1", require_published=False)
        assert problems == [], problems
        assert tool.main(["--version", "5.0.1", "--repo", str(tmp_path)]) == 0


# --------------------------------------------------------------------------
# main() exit codes — the contract release.yml relies on.
# --------------------------------------------------------------------------
class TestMainExit:
    def test_exit_1_on_unreleased_tree(self, tool: ModuleType, tmp_path: Path) -> None:
        _unreleased_tree(tmp_path, "5.0.0")
        rc = tool.main(["--version", "5.0.0", "--repo", str(tmp_path)])
        assert rc == 1

    def test_exit_0_on_released_tree(self, tool: ModuleType, tmp_path: Path) -> None:
        _released_tree(tmp_path, "5.0.0")
        rc = tool.main(["--version", "5.0.0", "--repo", str(tmp_path)])
        assert rc == 0

    def test_exit_1_on_released_tree_when_publish_required_and_pypi_still_deferred(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        # Tag-state cleared but a PyPI row still says "not published yet": under a
        # publishing release that is a shipped falsehood and must fail.
        _released_tree(tmp_path, "5.0.0")
        (tmp_path / "README.md").write_text(
            "# AMA\n\n| PyPI | **Not published yet** | No |\n\n`v5.0.0` is tagged.\n",
            encoding="utf-8",
        )
        assert tool.main(["--version", "5.0.0", "--repo", str(tmp_path)]) == 0
        assert (
            tool.main(["--version", "5.0.0", "--repo", str(tmp_path), "--require-published"]) == 1
        )


# --------------------------------------------------------------------------
# Real tree: non-vacuity + a phase-robust witness.
# --------------------------------------------------------------------------
class TestRealTree:
    def test_all_release_state_files_present_and_scanned(self, tool: ModuleType) -> None:
        # Non-vacuity: the four documents the gate names must actually exist in
        # the tree, so a rename that silently drops one is caught here rather than
        # passing the gate by absence.
        version = _canonical_version()
        _, scanned = tool.scan(REPO_ROOT, version, require_published=False)
        assert scanned == len(tool.RELEASE_STATE_FILES)
        for rel in tool.RELEASE_STATE_FILES:
            assert (REPO_ROOT / rel).is_file(), f"release-state document missing: {rel}"

    def test_pre_release_tree_is_flagged(self, tool: ModuleType) -> None:
        # Phase-robust: while the CHANGELOG still carries the version's
        # "Unreleased" heading the tree is pre-release, and the gate MUST flag it
        # (this is the M12 defect the gate exists to catch). After a release
        # engineer dates that heading the precondition is false and nothing is
        # asserted, so the very commit that clears the markers is not broken.
        version = _canonical_version()
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        v = re.escape(version)
        still_unreleased = re.search(rf"##\s*\[{v}\][^\n]*Unreleased", changelog, re.IGNORECASE)
        problems, _ = tool.scan(REPO_ROOT, version, require_published=False)
        if still_unreleased:
            assert problems, (
                f"tree still carries the '## [{version}] - Unreleased' heading but the "
                "release-state gate found nothing to flag"
            )

    def test_no_version_row_dates_a_release_that_has_not_happened(self, tool: ModuleType) -> None:
        """Phase-robust: vacuous once the heading is dated, binding until then."""
        problems = tool.premature_release_dates(REPO_ROOT, _canonical_version())
        assert problems == [], "\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# Inventory guard: the set of release-state documents must not silently shrink.
# --------------------------------------------------------------------------
class TestInventory:
    def test_release_state_files_is_the_expected_set(self, tool: ModuleType) -> None:
        assert tool.RELEASE_STATE_FILES == (
            "CHANGELOG.md",
            "README.md",
            "SECURITY.md",
            "docs/index.rst",
            "ARCHITECTURE.md",
        )
