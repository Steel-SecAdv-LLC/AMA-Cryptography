#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the workflow command verifier (``tools/check_workflow_commands.py``).

The checker exists because ``release.yml`` runs only on a tag push, so every
defect in it stays invisible until a release is attempted.  Three real ones
shipped that way — a retired ``macos-13`` runner label, a ``python -c`` payload
broken by YAML folding, and POSIX single-quoting handed to ``cmd.exe`` — and
each on its own was enough to produce a release with no binary artefacts.

A fourth class arrived with immutable releases, which freeze a release's tag
and assets at publish while leaving its title and notes editable: a ``name:``
that reset a hand-edited title, a ``body:`` without ``append_body`` that
destroyed hand-edited notes, and a prerelease that published before its assets
uploaded.  Same failure mode as the first three — invisible until a tag exists.

Both directions are pinned here, because a checker that only ever reports
"clean" is indistinguishable from one that has stopped working:

* **Detection** — each historical defect, reproduced verbatim, is reported with
  an actionable remedy.  For the release-publishing class the pre-fix step is
  replanted whole and must yield all three findings at once.
* **Non-detection** — the shapes this repository legitimately uses (escaped
  quotes inside a double-quoted payload, matrix references, multi-line shell
  scripts, a stable release drafted automatically by the action) do not produce
  false positives, since a checker that cries wolf gets bypassed.

The final test sweeps the repository's own workflows.  If a future edit
reintroduces any of these classes, that test fails on the pull request rather
than on release day.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from tools.check_workflow_commands import (
    RELEASE_ACTIONS,
    RETIRED_LABELS,
    SUPPORTED_LABELS,
    Report,
    check_inline_python,
    check_release_publishing,
    check_runner_labels,
    check_shell_parseable,
    check_windows_quoting,
    main,
    sweep,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_checks(source: str, name: str = "test.yml") -> Report:
    """Parse a workflow fragment and run every check over it."""
    document = yaml.safe_load(textwrap.dedent(source))
    report = Report()
    path = Path(name)
    check_runner_labels(path, document, report)
    check_inline_python(path, document, report)
    check_windows_quoting(path, document, report)
    check_shell_parseable(path, document, report)
    check_release_publishing(path, document, report)
    return report


def messages(report: Report) -> str:
    return "\n".join(f"{f.message} :: {f.remedy}" for f in report.findings)


class TestRunnerLabels:
    def test_retired_macos_13_is_reported(self) -> None:
        # The exact defect that made every wheel job queue until timeout.
        report = run_checks("""
            jobs:
              build:
                strategy:
                  matrix:
                    os: [ubuntu-latest, macos-13, windows-latest]
                runs-on: ${{ matrix.os }}
            """)
        assert len(report.findings) == 1
        assert "macos-13" in report.findings[0].message
        assert "retired" in report.findings[0].message

    def test_retired_label_names_its_replacement(self) -> None:
        # A diagnosis without a replacement leaves the reader where they
        # started; the whole point is that the job never fails fast.
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-20.04
            """)
        assert "ubuntu-24.04" in messages(report)

    def test_unknown_label_fails_closed(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: ubunut-latest
            """)
        assert len(report.findings) == 1
        assert "not a known GitHub-hosted image" in report.findings[0].message

    def test_supported_labels_pass(self) -> None:
        report = run_checks("""
            jobs:
              build:
                strategy:
                  matrix:
                    os: [ubuntu-latest, ubuntu-24.04-arm, macos-15, macos-15-intel, windows-latest]
                runs-on: ${{ matrix.os }}
            """)
        assert report.findings == []
        assert report.labels_checked == 5

    def test_labels_from_matrix_include_are_resolved(self) -> None:
        # An include-only matrix is how this repository pairs a runner with a
        # per-entry baseline file; leaving it unresolved would be a blind spot.
        report = run_checks("""
            jobs:
              bench:
                strategy:
                  matrix:
                    include:
                      - os: ubuntu-latest
                        cpu: x86_64
                      - os: macos-13
                        cpu: intel
                runs-on: ${{ matrix.os }}
            """)
        assert report.labels_checked == 2
        assert "macos-13" in messages(report)

    def test_list_form_runs_on_is_checked(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: [macos-13]
            """)
        assert "macos-13" in messages(report)

    def test_unresolvable_expression_is_reported_not_assumed_valid(self) -> None:
        # It must land in labels_unresolved, not silently inflate the count of
        # labels this checker claims to have verified.
        report = run_checks("""
            jobs:
              build:
                runs-on: ${{ inputs.runner }}
            """)
        assert report.findings == []
        assert report.labels_checked == 0
        assert report.labels_unresolved and "inputs.runner" in report.labels_unresolved[0]

    def test_supported_and_retired_sets_are_disjoint(self) -> None:
        assert not (SUPPORTED_LABELS & set(RETIRED_LABELS))


class TestInlinePythonPayloads:
    def test_folded_scalar_leading_space_is_reported(self) -> None:
        # Reproduces the historical failure exactly: a folded scalar joins the
        # block's lines with a space, so the payload arrives indented and the
        # interpreter raises IndentationError before running anything.
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      CIBW_TEST_COMMAND: >-
                        python -c "
                        import ama_cryptography as a;
                        print(a.__version__)
                        "
            """)
        assert report.payloads_checked == 1
        assert len(report.findings) == 1
        assert "does not compile" in report.findings[0].message

    def test_valid_single_line_payload_passes(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      CIBW_TEST_COMMAND: 'python -c "import ama_cryptography; print(1)"'
            """)
        assert report.payloads_checked == 1
        assert report.findings == []

    def test_escaped_quotes_inside_payload_are_not_false_positives(self) -> None:
        # This shape is used by release.yml's preflight step.  A non-greedy
        # match that stops at the first \" reports a truncated fragment as a
        # syntax error, which would make the checker unusable.
        report = run_checks(r"""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      v=$(python -c "
                      import re
                      m = re.search(r'^version\s*=\s*\"([^\"]+)\"', 'version = \"1.0\"')
                      print(m.group(1))
                      ")
            """)
        assert report.payloads_checked == 1
        assert report.findings == []

    def test_regex_escapes_in_payload_survive_unescaping(self) -> None:
        # \s and \d are not shell escapes; passing them through unchanged is
        # what keeps a valid payload valid.
        report = run_checks(r"""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: python -c "import re; print(re.compile(r'\s+\d'))"
            """)
        assert report.payloads_checked == 1
        assert report.findings == []

    def test_payload_in_run_block_is_checked(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: python -c "if True print('x')"
            """)
        assert len(report.findings) == 1
        assert "does not compile" in report.findings[0].message

    def test_python3_and_flags_are_matched(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: python3 -X utf8 -c "def ("
            """)
        assert report.payloads_checked == 1
        assert report.findings


class TestWindowsQuoting:
    def test_posix_single_quoting_in_windows_command_is_reported(self) -> None:
        # The exact defect: cmd.exe passes the quote through, so pip receives
        # "'cmake" as the requirement name.
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                steps:
                  - env:
                      CIBW_BEFORE_BUILD_WINDOWS: "pip install 'cmake>=4.3.4'"
            """)
        assert len(report.findings) == 1
        assert "single-quoting" in report.findings[0].message
        assert "double quotes" in report.findings[0].remedy

    def test_double_quoting_in_windows_command_passes(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                steps:
                  - env:
                      CIBW_BEFORE_BUILD_WINDOWS: 'pip install "cmake>=4.3.4"'
            """)
        assert report.windows_commands_checked == 1
        assert report.findings == []

    def test_shell_cmd_run_step_is_checked(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                steps:
                  - shell: cmd
                    run: pip install 'cython>=3.2.8'
            """)
        assert "single-quoting" in messages(report)

    def test_posix_quoting_in_linux_command_is_not_reported(self) -> None:
        # Single quotes are correct on Linux; flagging them there would be a
        # false positive that trains people to ignore the checker.
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      CIBW_BEFORE_BUILD_LINUX: "pip install 'cmake>=4.3.4'"
            """)
        assert report.windows_commands_checked == 0
        assert report.findings == []


class TestShellParseability:
    def test_unbalanced_quote_is_reported(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "unterminated
            """)
        assert "does not tokenise" in messages(report)

    def test_multi_line_script_is_left_alone(self) -> None:
        # Multi-line run blocks are shell scripts with heredocs and loops;
        # tokenising them as a single command would be meaningless.
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      cat <<'EOF' > f.txt
                      it's fine
                      EOF
            """)
        assert report.findings == []


def release_workflow(with_block: str) -> str:
    """A minimal tag-triggered workflow whose only step publishes a release."""
    indented = textwrap.indent(textwrap.dedent(with_block).strip("\n"), " " * 10)
    return (
        "name: Release\n"
        "on:\n"
        "  push:\n"
        "    tags: ['v*']\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: softprops/action-gh-release@v3.0.1\n"
        "        with:\n" + indented + "\n"
    )


class TestReleasePublishing:
    def test_name_input_is_reported(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                name: ${{ github.ref_name }}
                files: dist/*
                """))
        assert not report.ok
        assert "resets a hand-edited release title" in messages(report)

    def test_omitting_name_passes(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                files: dist/*
                """))
        assert report.ok, messages(report)

    def test_body_without_append_body_is_reported(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                body: |
                  Release notes generated by the workflow.
                files: dist/*
                """))
        assert not report.ok
        assert "destroys hand-edited release notes" in messages(report)

    def test_body_with_append_body_passes(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                body: |
                  Release notes generated by the workflow.
                append_body: true
                files: dist/*
                """))
        assert report.ok, messages(report)

    def test_body_path_is_covered_too(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                body_path: docs/releases/v3.4.0.md
                files: dist/*
                """))
        assert not report.ok
        assert "destroys hand-edited release notes" in messages(report)

    def test_prerelease_that_never_drafts_is_reported(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                files: dist/*
                draft: false
                prerelease: ${{ contains(github.ref_name, '-rc') }}
                """))
        assert not report.ok
        assert "assets freeze before they upload" in messages(report)

    def test_prerelease_drafted_by_the_same_condition_passes(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                files: dist/*
                draft: ${{ contains(github.ref_name, '-rc') }}
                prerelease: ${{ contains(github.ref_name, '-rc') }}
                """))
        assert report.ok, messages(report)

    def test_stable_release_with_draft_false_passes(self) -> None:
        """`prerelease: false` + `draft: false` is the correct stable shape.

        The action drafts a non-prerelease automatically and publishes it only
        after the assets upload, so this must not be flagged.
        """
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                files: dist/*
                draft: false
                prerelease: false
                """))
        assert report.ok, messages(report)

    def test_prerelease_without_assets_is_not_flagged(self) -> None:
        """With no `files:` there is nothing for the freeze to catch."""
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                draft: false
                prerelease: ${{ contains(github.ref_name, '-rc') }}
                """))
        assert report.ok, messages(report)

    def test_missing_draft_key_is_treated_as_never_drafting(self) -> None:
        report = run_checks(release_workflow("""
                tag_name: ${{ github.ref_name }}
                files: dist/*
                prerelease: true
                """))
        assert not report.ok
        assert "assets freeze before they upload" in messages(report)

    def test_non_release_steps_are_ignored(self) -> None:
        report = run_checks("""
            name: CI
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v5
                    with:
                      name: not-a-release-input
                      body: neither is this
            """)
        assert report.ok, messages(report)
        assert report.release_steps_checked == 0

    def test_step_security_fork_is_covered(self) -> None:
        report = run_checks("""
            name: Release
            on:
              push:
                tags: ['v*']
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                  - uses: step-security/action-gh-release@v3
                    with:
                      name: ${{ github.ref_name }}
                      files: dist/*
            """)
        assert not report.ok
        assert "resets a hand-edited release title" in messages(report)

    def test_every_listed_release_action_is_matched(self) -> None:
        for action in RELEASE_ACTIONS:
            report = run_checks(
                "name: Release\n"
                "on: [push]\n"
                "jobs:\n"
                "  publish:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                f"      - uses: {action}@v3\n"
                "        with:\n"
                "          files: dist/*\n"
            )
            assert report.release_steps_checked == 1, action


class TestReleasePublishingReplantedDefects:
    """The pre-fix release.yml shape must reproduce all three findings.

    Verified in both directions: the shape that shipped before the fix fails
    with one finding per defect, and the shape that replaced it passes.
    """

    PRE_FIX = """
        tag_name: ${{ github.ref_name }}
        name: ${{ github.ref_name }}
        body: |
          AMA Cryptography ${{ needs.preflight.outputs.version }}
        files: release-assets/*
        draft: false
        prerelease: ${{ contains(github.ref_name, '-rc') }}
        """

    POST_FIX = """
        tag_name: ${{ github.ref_name }}
        body: |
          AMA Cryptography ${{ needs.preflight.outputs.version }}
        files: release-assets/*
        append_body: true
        draft: ${{ contains(github.ref_name, '-rc') }}
        prerelease: ${{ contains(github.ref_name, '-rc') }}
        """

    def test_pre_fix_shape_reports_all_three(self) -> None:
        report = run_checks(release_workflow(self.PRE_FIX))
        text = messages(report)
        assert len(report.findings) == 3, text
        assert "resets a hand-edited release title" in text
        assert "destroys hand-edited release notes" in text
        assert "assets freeze before they upload" in text

    def test_post_fix_shape_passes(self) -> None:
        report = run_checks(release_workflow(self.POST_FIX))
        assert report.ok, messages(report)


class TestMalformedWorkflow:
    def test_unparseable_yaml_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "broken.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
        report = sweep(tmp_path)
        assert len(report.findings) == 1
        assert "could not be parsed" in report.findings[0].message

    def test_empty_directory_passes(self, tmp_path: Path) -> None:
        assert sweep(tmp_path).ok


class TestRepositoryWorkflows:
    """The gate must pass on this repository — and must be doing real work."""

    @pytest.fixture(scope="class")
    def report(self) -> Report:
        return sweep(REPO_ROOT / ".github" / "workflows")

    def test_repository_workflows_pass(self, report: Report) -> None:
        assert report.ok, messages(report)

    def test_every_runner_label_resolved(self, report: Report) -> None:
        # An unresolved label is an unchecked label.  If one appears, either
        # teach the resolver about it or accept a real blind spot knowingly.
        assert report.labels_unresolved == []

    def test_gate_actually_inspected_something(self, report: Report) -> None:
        # Guards against the checker silently becoming a no-op (a renamed
        # workflow directory, a glob that stops matching).
        assert report.labels_checked > 0
        assert report.payloads_checked > 0

    def test_main_exits_zero_on_this_repository(self) -> None:
        assert main([]) == 0
