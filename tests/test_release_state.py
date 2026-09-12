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
        f"# Changelog\n\n## [{version}] - Unreleased\n\n- pending\n", encoding="utf-8"
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
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## [{version}] - 2026-08-24\n\n- released\n", encoding="utf-8"
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
class TestVersionScopingAndMissing:
    def test_changelog_heading_is_version_scoped(self, tool: ModuleType, tmp_path: Path) -> None:
        # A CHANGELOG heading for 5.0.0 must not be flagged when 6.0.0 is being
        # released: only the heading of the version under release is enforced.
        _unreleased_tree(tmp_path, "5.0.0")
        problems, _ = tool.scan(tmp_path, "6.0.0", require_published=False)
        assert not any("CHANGELOG.md" in p for p in problems)

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
        )
