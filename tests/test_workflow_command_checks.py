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

Both directions are pinned here, because a checker that only ever reports
"clean" is indistinguishable from one that has stopped working:

* **Detection** — each of the three historical defects, reproduced verbatim,
  is reported with an actionable remedy.
* **Non-detection** — the shapes this repository legitimately uses (escaped
  quotes inside a double-quoted payload, matrix references, multi-line shell
  scripts) do not produce false positives, since a checker that cries wolf
  gets bypassed.

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
    RETIRED_LABELS,
    SUPPORTED_LABELS,
    Report,
    check_inline_python,
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
