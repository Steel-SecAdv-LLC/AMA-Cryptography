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

import tools.check_workflow_commands as wf
from tools.check_workflow_commands import (
    MIN_WORKFLOWS,
    RELEASE_ACTIONS,
    RETIRED_LABELS,
    SUPPORTED_LABELS,
    Report,
    check_cmake_build_type,
    check_expression_syntax,
    check_gate_jobs_run_their_payload,
    check_inline_python,
    check_pytest_prerequisites,
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
    check_expression_syntax(path, document, report)
    check_cmake_build_type(path, document, report)
    check_pytest_prerequisites(path, document, report)
    check_gate_jobs_run_their_payload(path, document, report)
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


class TestExpressionSyntax:
    """An expression GitHub cannot parse makes the whole FILE produce no checks.

    `.github/workflows/arm-qemu.yml` carried
    ``name: Test at VL=${{ matrix.sve_vq * 128 }} bits``.  GitHub Actions
    expressions have no arithmetic — the grammar admits `!`, the comparisons,
    `&&`, `||`, indexing and the documented functions, and nothing else — so
    the file failed to parse and every job in it, including the SVE2 lanes it
    had just been extended with and the aggregating ``ARM QEMU Gate``, silently
    produced no check on any pull request.

    YAML parses the file perfectly well (the operator is inside a string as far
    as YAML is concerned), so the existing malformed-YAML guard could not see
    it.  It was found by dispatching the workflow, which is not a thing CI does.
    """

    def test_the_shipped_defect_is_caught(self) -> None:
        report = run_checks(textwrap.dedent("""
                name: probe
                on: workflow_dispatch
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    strategy:
                      matrix:
                        sve_vq: [1, 2]
                    steps:
                      - name: Test at VL=${{ matrix.sve_vq * 128 }} bits
                        run: echo hi
                """))
        assert not report.ok
        assert any("arithmetic" in f.message for f in report.findings), messages(report)

    @pytest.mark.parametrize(
        "expression",
        [
            "${{ matrix.n * 2 }}",
            "${{ matrix.n + 1 }}",
            "${{ (matrix.a) / 4 }}",
            "${{ matrix.a % 8 }}",
        ],
    )
    def test_every_arithmetic_operator_is_rejected(self, expression: str) -> None:
        report = run_checks(
            "name: p\non: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - name: {expression}\n        run: echo hi\n"
        )
        assert not report.ok, f"{expression} was accepted"

    @pytest.mark.parametrize(
        "expression",
        [
            # A slash inside a string literal is data, not division. This is
            # the shape that made the first draft of the check unusable: it
            # flagged every `github.ref != 'refs/heads/main'` in the tree.
            "${{ github.ref != 'refs/heads/main' && github.event_name != 'schedule' }}",
            "${{ !cancelled() }}",
            "${{ contains(needs.*.result, 'failure') }}",
            "${{ matrix.os }}",
            "${{ github.event.inputs.measurements || '100000' }}",
            "${{ steps.confirm.outputs.supported == 'true' }}",
            "${{ hashFiles('**/requirements*.txt') }}",
        ],
    )
    def test_legitimate_expressions_are_not_flagged(self, expression: str) -> None:
        report = run_checks(
            "name: p\non: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - name: step\n        if: {expression}\n        run: echo hi\n"
        )
        assert report.ok, messages(report)

    @pytest.mark.parametrize(
        "condition",
        [
            # The shape a negative control injected into ci.yml (NC-29b): a
            # bare `if:` carries no `${{`, so the first version of this check
            # never looked at it, and `=` was outside its rule anyway.
            "steps.setup-python.outcome = 'failure'",
            "${{ steps.setup-python.outcome = 'failure' }}",
            "matrix.n * 2",
            "github.event_name = 'push' && github.ref == 'refs/heads/main'",
        ],
    )
    def test_a_lone_equals_and_a_bare_if_are_rejected(self, condition: str) -> None:
        report = run_checks(
            "name: p\non: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            f"    if: {condition}\n    steps:\n      - run: echo hi\n"
        )
        assert not report.ok, f"{condition} was accepted"
        assert any("WHOLE FILE" in f.message for f in report.findings), messages(report)

    @pytest.mark.parametrize(
        "condition",
        [
            "steps.setup-python.outcome == 'failure'",
            "github.ref != 'refs/heads/main' && github.event_name != 'schedule'",
            "matrix.python-version >= '3.11' || matrix.os <= 'z'",
            "always()",
            "contains(github.ref, 'refs/tags/v=')",
            "github.event.inputs.tag == ''",
        ],
    )
    def test_legitimate_bare_conditions_are_not_flagged(self, condition: str) -> None:
        report = run_checks(
            "name: p\non: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            f"    if: {condition}\n    steps:\n      - run: echo hi\n"
        )
        assert report.ok, messages(report)
        assert report.expressions_checked == 1

    def test_the_check_inspects_something(self) -> None:
        """A silent no-op would pass every workflow in the tree."""
        report = sweep(REPO_ROOT / ".github" / "workflows")
        assert report.expressions_checked > 0

    def test_the_real_arm_workflow_parses_and_has_both_vector_lengths(self) -> None:
        """The fix, asserted on the file rather than on a fixture."""
        document = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "arm-qemu.yml").read_text(encoding="utf-8")
        )
        matrix = document["jobs"]["arm-qemu-sve2"]["strategy"]["matrix"]
        assert "include" in matrix, "the vector length must be carried, not computed"
        assert {entry["vl_bits"] for entry in matrix["include"]} == {128, 256}
        report = Report()
        check_expression_syntax(
            REPO_ROOT / ".github" / "workflows" / "arm-qemu.yml", document, report
        )
        assert report.ok, messages(report)


class TestCmakeBuildType:
    """A configure with no build type compiles with no -O flag at all.

    That is not a hypothetical style rule.  ``dudect.yml`` configured the
    AMA_TESTING_MODE archive without one and ran ten instruction-count
    constant-time targets against the result; those targets look for a
    transformation the optimizer performs, so at -O0 there was nothing to find
    and all ten passed.  Rebuilt at -O3, the ecdsa target measured a
    9,424-instruction key-dependent spread — a live Montgomery
    extra-reduction leak in the secp256k1 scalar arithmetic under clang 18.
    """

    def _fragment(self, command: str) -> str:
        return (
            "name: p\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - name: build\n        run: |\n"
            + "".join(f"          {line}\n" for line in command.split("\n"))
        )

    def test_missing_build_type_is_reported(self) -> None:
        report = run_checks(self._fragment("cmake -B build -DAMA_USE_NATIVE_PQC=ON"))
        assert not report.ok
        assert "no optimization flag at all" in messages(report)

    def test_release_is_accepted(self) -> None:
        report = run_checks(
            self._fragment("cmake -B build -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON")
        )
        assert report.ok, messages(report)

    def test_none_states_the_unoptimized_intent_and_is_accepted(self) -> None:
        """The strict-warning sweep wants -O0 deliberately; it must say so."""
        report = run_checks(self._fragment("cmake -B build -DCMAKE_BUILD_TYPE=None"))
        assert report.ok, messages(report)

    def test_explicit_dash_o_in_c_flags_is_accepted(self) -> None:
        """What the sanitizer jobs pass: the level is stated, just not as a type."""
        report = run_checks(
            self._fragment('cmake -B b -DCMAKE_C_FLAGS="-fsanitize=address -g -O1"')
        )
        assert report.ok, messages(report)

    def test_line_continuations_are_one_command(self) -> None:
        """Reading line by line would flag the first line of every multi-line configure."""
        report = run_checks(
            self._fragment(
                "cmake -B build \\\n  -DAMA_USE_NATIVE_PQC=ON \\\n  -DCMAKE_BUILD_TYPE=Release"
            )
        )
        assert report.ok, messages(report)

    def test_a_bare_cmake_with_every_flag_on_continuation_lines_is_seen(self) -> None:
        """`cmake \\` used to be invisible — neither counted nor checked.

        The matcher only started buffering when the FIRST physical line
        matched the configure pattern, and `cmake \\` does not (the character
        after the whitespace is a backslash).  So this spelling escaped the
        gate whose whole subject is the silently-unoptimized build.
        Continuations are now joined before matching.
        """
        missing = run_checks(self._fragment("cmake \\\n  -B build \\\n  -DAMA_USE_NATIVE_PQC=ON"))
        assert not missing.ok, "a build type is missing and must be reported"
        assert "no optimization flag at all" in messages(missing)
        assert missing.cmake_configures_checked == 1

        stated = run_checks(self._fragment("cmake \\\n  -B build \\\n  -DCMAKE_BUILD_TYPE=Release"))
        assert stated.ok, messages(stated)
        assert stated.cmake_configures_checked == 1

    def test_build_and_install_and_script_mode_are_not_configures(self) -> None:
        for command in ("cmake --build build -j4", "cmake --install build", "cmake -E rm -rf x"):
            report = run_checks(self._fragment(command))
            assert report.ok, f"{command}: {messages(report)}"
        assert run_checks(self._fragment("cmake --build build")).cmake_configures_checked == 0

    def test_cmake_as_a_package_or_requirement_is_not_a_configure(self) -> None:
        """`apt-install.sh cmake clang` and `pip install 'cmake>=4.4.0'` are not builds."""
        for command in (
            ".github/scripts/apt-install.sh cmake clang valgrind",
            "python -m pip install --upgrade pip 'cmake>=4.4.0' 'cython>=3.2.8'",
        ):
            report = run_checks(self._fragment(command))
            assert report.ok, f"{command}: {messages(report)}"
            assert run_checks(self._fragment(command)).cmake_configures_checked == 0

    def test_source_dir_form_is_a_configure(self) -> None:
        report = run_checks(self._fragment("cd build\ncmake .."))
        assert not report.ok
        assert report.cmake_configures_checked == 1

    def test_a_commented_out_configure_is_not_checked(self) -> None:
        report = run_checks(self._fragment("# cmake -B build"))
        assert report.ok, messages(report)
        assert report.cmake_configures_checked == 0


class TestPytestPrerequisites:
    """A pytest step that cannot start is not a lane.

    Since INVARIANT-39 a failed POST raises, and ``tests/conftest.py`` imports
    the package from ``pytest_configure``, so pytest in a library-less job exits
    3 with INTERNALERROR before collection.  Both real occurrences on this
    branch reached CI before anyone noticed; these cases decide them statically.
    """

    def test_pytest_without_a_build_is_reported(self) -> None:
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: pip install "pytest==9.1.1"
                  - run: python -m pytest tests/test_vector_provenance_gate.py -q
        """)
        assert len(report.findings) == 1, messages(report)
        assert "never builds the native library" in report.findings[0].message
        assert "AMA_POST_DIAGNOSTIC_IMPORT" in report.findings[0].remedy
        assert report.pytest_steps_checked == 1

    def test_the_exact_shape_that_shipped_at_725f2f1(self) -> None:
        """The job as it stood when the Corpus Provenance Gate went red.

        `Install pytest` fixed `No module named pytest` and nothing else; the
        next step still died with `CryptoModuleError`, exit 3.  Reproduced
        verbatim so a revert cannot pass.
        """
        report = run_checks("""
            jobs:
              vector-provenance:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v5
                  - uses: actions/setup-python@v6
                    with:
                      python-version: "3.12"
                  - name: Install pytest
                    run: pip install "pytest==9.1.1"
                  - name: Every NIST/Ascon/POST vector must match its recorded digest
                    run: python tools/check_vector_provenance.py
                  - name: The manifest alone must not be sufficient (anchor digests)
                    run: python -m pytest tests/test_vector_provenance_gate.py -q
        """)
        assert len(report.findings) == 1, messages(report)
        assert "vector-provenance" in report.findings[0].location

    def test_the_diagnostic_escape_satisfies_it(self) -> None:
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: pip install "pytest==9.1.1"
                  - env:
                      AMA_POST_DIAGNOSTIC_IMPORT: "1"
                    run: python -m pytest tests/test_vector_provenance_gate.py -q
        """)
        assert report.ok, messages(report)
        assert report.pytest_steps_checked == 1

    def test_the_escape_is_honoured_at_workflow_scope(self) -> None:
        report = run_checks("""
            env:
              AMA_POST_DIAGNOSTIC_IMPORT: "1"
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: python -m pytest tests/ -q
        """)
        assert report.ok, messages(report)

    def test_the_escape_is_honoured_at_job_scope(self) -> None:
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                env:
                  AMA_POST_DIAGNOSTIC_IMPORT: "1"
                steps:
                  - run: python -m pytest tests/ -q
        """)
        assert report.ok, messages(report)

    def test_an_expression_valued_escape_is_not_accepted(self) -> None:
        """A value decided on the runner is not evidence for a static check."""
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      AMA_POST_DIAGNOSTIC_IMPORT: ${{ matrix.diag }}
                    run: python -m pytest tests/ -q
        """)
        assert len(report.findings) == 1, messages(report)

    def test_build_pipeline_is_not_an_escape(self) -> None:
        """AMA_BUILD_PIPELINE=1 excuses only stale-artefact stages.

        A job with no library at all fails the ``native-backend`` stage for a
        reason no re-signing run repairs, so the import still raises.  A gate
        that accepted this flag would pass a job the runner cannot start.
        """
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      AMA_BUILD_PIPELINE: "1"
                    run: python -m pytest tests/ -q
        """)
        assert len(report.findings) == 1, messages(report)

    @pytest.mark.parametrize(
        "build",
        [
            "cmake --build build -j2",
            'pip install -e ".[dev,hsm]"',
            "pip install .",
            "pip install dist/ama_cryptography-5.0.0-cp311-cp311-linux_x86_64.whl",
            "python setup.py build_ext --inplace",
            "make c",
        ],
    )
    def test_a_preceding_build_satisfies_it(self, build: str) -> None:
        report = run_checks(
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f"      - run: {build}\n"
            "      - run: python -m pytest tests/ -q\n"
        )
        assert report.ok, messages(report)

    def test_a_build_after_the_pytest_step_does_not_satisfy_it(self) -> None:
        """Order matters: the library has to exist when pytest starts."""
        report = run_checks("""
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - run: python -m pytest tests/ -q
                  - run: cmake --build build -j2
        """)
        assert len(report.findings) == 1, messages(report)

    def test_a_build_in_another_job_does_not_satisfy_it(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: cmake --build build -j2
              test:
                runs-on: ubuntu-latest
                steps:
                  - run: python -m pytest tests/ -q
        """)
        assert len(report.findings) == 1, messages(report)
        assert "jobs.test" in report.findings[0].location

    def test_installing_pytest_is_not_running_pytest(self) -> None:
        """`pip install pytest` must not be read as an invocation.

        The unpinned spelling is the sharp case: the token is exactly
        ``pytest``, so a substring or bare-token search reports every job with
        a test dependency.
        """
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: pip install pytest
                  - run: python -m pip install "pytest==9.1.1" pytest-cov
        """)
        assert report.ok, messages(report)
        assert report.pytest_steps_checked == 0

    def test_a_comment_mentioning_pytest_is_not_an_invocation(self) -> None:
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      # pytest tests/ would need a library; this step does not run it
                      echo ok
        """)
        assert report.ok, messages(report)
        assert report.pytest_steps_checked == 0

    def test_a_heredoc_body_is_not_read_as_commands(self) -> None:
        """Payload handed to another interpreter is data, not this shell's work."""
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      python - <<'PY'
                      print("pytest tests/ -q")
                      PY
        """)
        assert report.ok, messages(report)
        assert report.pytest_steps_checked == 0

    def test_a_leading_env_assignment_does_not_hide_the_command(self) -> None:
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: AMA_CI_REQUIRE_BACKENDS=1 pytest tests/ -q
        """)
        assert len(report.findings) == 1, messages(report)
        assert report.pytest_steps_checked == 1

    def test_a_chained_command_is_seen(self) -> None:
        report = run_checks("""
            jobs:
              gate:
                runs-on: ubuntu-latest
                steps:
                  - run: echo start && python -m pytest tests/ -q
        """)
        assert len(report.findings) == 1, messages(report)

    def test_a_continuation_joined_build_counts(self) -> None:
        """`cmake --build` split by a backslash continuation is still a build."""
        report = run_checks(
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          cmake \\\n"
            "            --build build -j2\n"
            "      - run: python -m pytest tests/ -q\n",
        )
        assert report.ok, messages(report)


class TestGatedJobsRunTheirPayload:
    """A job a ``*-gate`` depends on must not be able to succeed doing nothing.

    This is the exact shape of audit H2: ``test-avx512`` sat in ``ci-gate``'s
    ``needs:`` with no job-level ``if:`` and its build/test steps behind
    ``if: steps.cpu.outputs.have_avx512 == '1'``.  On a runner without AVX-512
    those steps skipped, the job reported ``success`` (not ``skipped``), and the
    gate — which fails on ``skipped`` but not on a vacuous ``success`` — passed.
    """

    #: The defect: a gate-required job self-probes and gates its payload on the
    #: result, with no job-level `if:` to make the skip honest.
    DEFECT = """
        jobs:
          probe-gate:
            needs: [worker]
            runs-on: ubuntu-latest
            steps:
              - run: echo gate
          worker:
            runs-on: ubuntu-latest
            steps:
              - id: cpu
                run: echo "have=1" >> "$GITHUB_OUTPUT"
              - name: Build the thing
                if: steps.cpu.outputs.have == '1'
                run: cmake --build build
    """

    def test_self_probe_gated_payload_in_a_gated_job_is_reported(self) -> None:
        report = run_checks(self.DEFECT)
        assert not report.ok
        joined = messages(report)
        assert "worker" in joined
        assert "audit H2" in joined
        assert report.gate_required_jobs_checked == 1

    def test_a_job_level_if_is_the_honest_form_and_passes(self) -> None:
        """Job-level ``if:`` makes the skip a ``skipped`` result, which every
        ``*-gate`` in this repo already fails on — so it is not the defect."""
        source = """
            jobs:
              probe-gate:
                needs: [worker]
                runs-on: ubuntu-latest
                steps:
                  - run: echo gate
              worker:
                if: ${{ github.event_name == 'push' }}
                runs-on: ubuntu-latest
                steps:
                  - id: cpu
                    run: echo "have=1" >> "$GITHUB_OUTPUT"
                  - name: Build the thing
                    if: steps.cpu.outputs.have == '1'
                    run: cmake --build build
        """
        report = run_checks(source)
        assert report.ok, messages(report)

    def test_unconditional_payload_passes(self) -> None:
        """The fixed shape: the payload runs every time (as under emulation)."""
        source = """
            jobs:
              probe-gate:
                needs: [worker]
                runs-on: ubuntu-latest
                steps:
                  - run: echo gate
              worker:
                runs-on: ubuntu-latest
                steps:
                  - name: Build the thing
                    run: cmake --build build
                  - name: Run it under the emulator
                    run: sde64 -spr -- ./build/bin/test
        """
        report = run_checks(source)
        assert report.ok, messages(report)

    def test_outcome_gated_diagnostic_step_is_not_flagged(self) -> None:
        """A step gated on a PRIOR step's ``.outcome`` is a failure handler; it
        cannot manufacture a vacuous success, so it must not be flagged."""
        source = """
            jobs:
              probe-gate:
                needs: [worker]
                runs-on: ubuntu-latest
                steps:
                  - run: echo gate
              worker:
                runs-on: ubuntu-latest
                steps:
                  - id: build
                    run: cmake --build build
                  - name: Dump logs if the build failed
                    if: steps.build.outcome == 'failure'
                    run: cat build/CMakeFiles/CMakeError.log
        """
        report = run_checks(source)
        assert report.ok, messages(report)

    def test_self_probe_in_a_non_gated_job_is_not_this_check(self) -> None:
        """The scope is jobs a gate depends on.  A self-probe-gated step in a
        job no gate needs is outside this check's remit (it is not a required
        status), so it passes here."""
        source = """
            jobs:
              standalone:
                runs-on: ubuntu-latest
                steps:
                  - id: cpu
                    run: echo "have=1" >> "$GITHUB_OUTPUT"
                  - name: Build the thing
                    if: steps.cpu.outputs.have == '1'
                    run: cmake --build build
        """
        report = run_checks(source)
        assert report.ok, messages(report)
        assert report.gate_required_jobs_checked == 0


def _valid_workflow(index: int) -> str:
    """A minimal, structurally valid workflow — enough to clear the floor."""
    return textwrap.dedent(f"""
        name: filler-{index}
        on: [push]
        jobs:
          noop:
            runs-on: ubuntu-latest
            steps:
              - run: echo {index}
        """).lstrip()


class TestMalformedWorkflow:
    def test_unparseable_yaml_is_reported(self, tmp_path: Path) -> None:
        # Fill to the floor with valid files so the parse error is the sole
        # finding — otherwise the non-vacuity floor (below) would also fire and
        # this test would be asserting two unrelated things at once.
        for i in range(MIN_WORKFLOWS):
            (tmp_path / f"ok-{i}.yml").write_text(_valid_workflow(i), encoding="utf-8")
        (tmp_path / "broken.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
        report = sweep(tmp_path)
        parse_errors = [f for f in report.findings if "could not be parsed" in f.message]
        assert len(parse_errors) == 1, messages(report)
        assert parse_errors[0].workflow == "broken.yml"

    def test_empty_directory_fails_the_nonvacuity_floor(self, tmp_path: Path) -> None:
        # H7: an empty (or wrong-path) workflow set must FAIL, not pass over
        # nothing.  Before the floor this returned ok — the vacuity the floor
        # exists to remove.
        report = sweep(tmp_path)
        assert not report.ok
        assert any("floor" in f.message for f in report.findings), messages(report)

    def test_a_workflow_set_at_the_floor_does_not_trip_it(self, tmp_path: Path) -> None:
        # The floor must fire on too-few files and not on enough — a floor that
        # always fired would be as useless as one that never did.
        for i in range(MIN_WORKFLOWS):
            (tmp_path / f"ok-{i}.yml").write_text(_valid_workflow(i), encoding="utf-8")
        report = sweep(tmp_path)
        assert not any("floor" in f.message for f in report.findings), messages(report)


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
        assert report.cmake_configures_checked > 0
        assert report.pytest_steps_checked > 0
        assert report.gate_required_jobs_checked > 0

    def test_the_constant_time_gate_builds_an_optimized_library(self) -> None:
        """The specific configure whose build type was missing, pinned by name.

        The generic sweep above would also catch this, but not legibly: this is
        the job whose ten instruction-count targets were measuring an -O0
        library, and it is worth naming so a future edit that drops the flag
        fails with the reason attached.
        """
        document = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "dudect.yml").read_text(encoding="utf-8")
        )
        for job_id in ("ghash-scalar-invariance", "aead-verify-invariance"):
            steps = document["jobs"][job_id]["steps"]
            configures = [
                step["run"]
                for step in steps
                if isinstance(step, dict) and "cmake -B build" in (step.get("run") or "")
            ]
            assert configures, f"{job_id} no longer configures a build"
            assert all(
                "-DCMAKE_BUILD_TYPE=Release" in run for run in configures
            ), f"{job_id} must build the library it measures with optimization enabled"

    def test_main_exits_zero_on_this_repository(self) -> None:
        assert main([]) == 0


# ---------------------------------------------------------------------------
# Contract pinning (audit R1/R2).
#
# Mutation testing at PR #394 measured a 62.7 % kill rate for this file: 176 of
# 473 mutants survived the suite above.  The survivors clustered in two places
# the tests never reached — the data tables (every runner label, every retired
# label's replacement, every Windows command key, every shell escape) and the
# tokenising helpers that decide whether a command *is* pytest, *is* a library
# build, or *is* a cmake configure.  A table entry no test reads is an entry
# that can be deleted without consequence, and a detector no test drives can be
# inverted while the gate still reports the tree clean.
#
# The classes below drive each table entry by entry and each helper shape by
# shape.  Parametrising over the tables themselves (rather than over a copy)
# means a future entry is covered the moment it is added.
# ---------------------------------------------------------------------------


class TestEveryRunnerLabelInTheTablesIsEnforced:
    """The two label tables are the whole runner check.  An entry dropped from
    ``SUPPORTED_LABELS`` turns a valid workflow into a reported defect; an entry
    dropped from ``RETIRED_LABELS`` lets a job queue until timeout with the gate
    green — the exact failure that made every wheel job hang."""

    @staticmethod
    def _job(label: str) -> str:
        return f"jobs:\n  build:\n    runs-on: {label}\n    steps:\n      - run: echo hi\n"

    @pytest.mark.parametrize("label", sorted(SUPPORTED_LABELS))
    def test_a_supported_label_is_accepted(self, label: str) -> None:
        report = run_checks(self._job(label))
        assert report.findings == [], messages(report)

    @pytest.mark.parametrize("label", sorted(RETIRED_LABELS))
    def test_a_retired_label_is_reported_with_its_replacement(self, label: str) -> None:
        report = run_checks(self._job(label))
        assert len(report.findings) == 1, messages(report)
        finding = report.findings[0]
        assert label in finding.message
        assert "retired" in finding.message
        assert RETIRED_LABELS[label] in finding.remedy

    def test_the_two_tables_stay_disjoint(self) -> None:
        """A label may be supported or retired, never both: an overlap would
        make the supported arm win and silently un-retire an image."""
        assert not (SUPPORTED_LABELS & set(RETIRED_LABELS))

    def test_an_unknown_label_is_reported_as_a_typo(self) -> None:
        report = run_checks(self._job("ubuntu-lastest"))
        assert len(report.findings) == 1, messages(report)
        assert "not a known GitHub-hosted image" in report.findings[0].message


class TestRunsOnResolution:
    """``_resolve_runs_on`` decides which labels the checker actually reads.  A
    label it fails to resolve is a label it never validates."""

    def test_a_scalar_label_resolves(self) -> None:
        assert wf._resolve_runs_on("ubuntu-latest", {}) == (["ubuntu-latest"], [])

    def test_a_list_resolves_every_entry(self) -> None:
        resolved, unresolved = wf._resolve_runs_on(["self-hosted", "linux"], {})
        assert resolved == ["self-hosted", "linux"]
        assert unresolved == []

    def test_a_runner_group_resolves_through_its_labels(self) -> None:
        """``runs-on: {group: …, labels: […]}`` is the self-hosted form; reading
        the wrong key would leave those jobs unchecked."""
        resolved, _ = wf._resolve_runs_on({"group": "g", "labels": ["ubuntu-latest"]}, {})
        assert resolved == ["ubuntu-latest"]

    def test_a_runner_group_without_labels_resolves_to_nothing(self) -> None:
        assert wf._resolve_runs_on({"group": "g"}, {}) == ([], [])

    def test_a_matrix_reference_resolves_through_the_matrix(self) -> None:
        job = {"strategy": {"matrix": {"os": ["ubuntu-latest", "macos-15"]}}}
        resolved, unresolved = wf._resolve_runs_on("${{ matrix.os }}", job)
        assert resolved == ["ubuntu-latest", "macos-15"]
        assert unresolved == []

    def test_a_matrix_reference_with_no_literal_values_is_unresolved(self) -> None:
        """Reported, not assumed fine."""
        resolved, unresolved = wf._resolve_runs_on("${{ matrix.os }}", {})
        assert resolved == []
        assert unresolved == ["${{ matrix.os }}"]

    def test_a_non_matrix_expression_is_unresolved(self) -> None:
        _resolved, unresolved = wf._resolve_runs_on("${{ inputs.runner }}", {})
        assert unresolved == ["${{ inputs.runner }}"]

    def test_an_embedded_expression_is_unresolved_not_treated_as_a_label(self) -> None:
        _resolved, unresolved = wf._resolve_runs_on("ubuntu-${{ inputs.v }}", {})
        assert unresolved == ["ubuntu-${{ inputs.v }}"]

    def test_matrix_include_entries_contribute_labels(self) -> None:
        job = {"strategy": {"matrix": {"include": [{"os": "windows-2022"}]}}}
        resolved, _ = wf._resolve_runs_on("${{ matrix.os }}", job)
        assert resolved == ["windows-2022"]


class TestLiteralTruthDetection:
    """``${{ }}`` is decided on the runner; the checker must not pretend to
    know it in either direction."""

    @pytest.mark.parametrize("value", [True, "true", "TRUE", "  true  "])
    def test_definite_true(self, value: object) -> None:
        assert wf._is_literal_true(value) is True

    @pytest.mark.parametrize("value", [False, "false", "yes", "1", "${{ inputs.x }}", None])
    def test_not_definitely_true(self, value: object) -> None:
        assert wf._is_literal_true(value) is False

    @pytest.mark.parametrize("value", [False, "false", "FALSE", "  false  "])
    def test_definite_false(self, value: object) -> None:
        assert wf._is_literal_false(value) is True

    @pytest.mark.parametrize("value", [True, "true", "no", "0", "${{ inputs.x }}", None])
    def test_not_definitely_false(self, value: object) -> None:
        assert wf._is_literal_false(value) is False


class TestShellDoubleQuoteUnescaping:
    """Without this the checker compiles the source the YAML holds rather than
    the source the interpreter receives, and flags correct workflows."""

    @pytest.mark.parametrize("escaped,expected", sorted(wf._SH_DQ_ESCAPES.items()))
    def test_every_escape_in_the_table_is_applied(self, escaped: str, expected: str) -> None:
        assert wf._unescape_double_quoted(f"a\\{escaped}b") == f"a{expected}b"

    def test_a_regex_escape_survives_intact(self) -> None:
        r"""Python payloads are full of ``\s`` and ``\d``; consuming those
        backslashes would corrupt the source before it is compiled."""
        assert wf._unescape_double_quoted(r"re.match(r'\s+\d')") == r"re.match(r'\s+\d')"

    def test_a_trailing_backslash_is_passed_through(self) -> None:
        """The lookahead must stay inside the payload rather than reading past
        its end."""
        assert wf._unescape_double_quoted("a\\") == "a\\"

    def test_an_escape_at_the_very_end_is_applied(self) -> None:
        assert wf._unescape_double_quoted('a\\"') == 'a"'

    def test_an_escaped_backslash_consumes_both_characters(self) -> None:
        assert wf._unescape_double_quoted(r"a\\\"b") == 'a\\"b'


class TestEveryWindowsCommandKeyIsChecked:
    """Each key names an environment value ``cmd.exe`` executes.  A key dropped
    from the table is a Windows command nobody checks for POSIX quoting — the
    class of defect that shipped a release with no binary artefacts."""

    @pytest.mark.parametrize("key", sorted(wf.WINDOWS_COMMAND_KEYS))
    def test_posix_quoting_under_the_key_is_reported(self, key: str) -> None:
        report = run_checks(f"""
            jobs:
              build:
                runs-on: windows-latest
                env:
                  {key}: pip install 'cmake>=4.3.4'
                steps:
                  - run: echo hi
            """)
        assert len(report.findings) == 1, messages(report)
        assert "POSIX single-quoting" in report.findings[0].message

    def test_double_quoting_under_the_key_is_accepted(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                env:
                  CIBW_BEFORE_ALL_WINDOWS: pip install "cmake>=4.3.4"
                steps:
                  - run: echo hi
            """)
        assert report.findings == [], messages(report)

    def test_an_unlisted_environment_key_is_not_a_windows_command(self) -> None:
        """The check must key off the table, not off every string in ``env:``:
        a POSIX ``run:`` on Linux legitimately single-quotes."""
        report = run_checks("""
            jobs:
              build:
                runs-on: ubuntu-latest
                env:
                  SOME_LINUX_COMMAND: pip install 'cmake>=4.3.4'
                steps:
                  - run: echo hi
            """)
        assert report.findings == [], messages(report)

    def test_a_cmd_shell_run_step_is_checked(self) -> None:
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                steps:
                  - shell: cmd
                    run: pip install 'cmake>=4.3.4'
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_job_default_cmd_shell_is_honoured(self) -> None:
        """``defaults.run.shell`` at job scope selects the interpreter for every
        step that does not override it."""
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                defaults:
                  run:
                    shell: cmd
                steps:
                  - run: pip install 'cmake>=4.3.4'
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_later_cmd_step_is_still_checked(self) -> None:
        """A clean step earlier in the job must not end the scan."""
        report = run_checks("""
            jobs:
              build:
                runs-on: windows-latest
                steps:
                  - shell: cmd
                    run: echo clean
                  - shell: cmd
                    run: pip install 'cmake>=4.3.4'
            """)
        assert len(report.findings) == 1, messages(report)


class TestHereDocumentBodiesAreRemoved:
    """A here-document is data handed to another interpreter.  Reading its body
    as shell would make a Python payload mentioning ``pytest`` look like a test
    run — and would let a real, unbuilt pytest invocation hide behind one."""

    def test_the_body_is_dropped_and_the_terminator_ends_it(self) -> None:
        text = "cat <<EOF\npytest tests/\nEOF\necho after"
        assert wf._heredoc_stripped(text) == "cat <<EOF\necho after"

    def test_a_quoted_terminator_is_honoured(self) -> None:
        text = "cat <<'PY'\npytest tests/\nPY\necho after"
        assert wf._heredoc_stripped(text) == "cat <<'PY'\necho after"

    def test_the_dash_form_is_honoured(self) -> None:
        text = "cat <<-EOF\npytest tests/\nEOF\necho after"
        assert wf._heredoc_stripped(text) == "cat <<-EOF\necho after"

    def test_a_here_string_is_not_a_here_document(self) -> None:
        """``<<<`` is one line and needs nothing; treating it as an opener would
        swallow the rest of the script."""
        text = "python - <<<EOF\npytest tests/"
        assert wf._heredoc_stripped(text) == text

    def test_text_with_no_here_document_is_unchanged(self) -> None:
        assert wf._heredoc_stripped("pytest tests/\necho done") == "pytest tests/\necho done"

    def test_a_second_here_document_is_also_stripped(self) -> None:
        """One closed here-document must not stop the scan."""
        text = "cat <<A\nx\nA\ncat <<B\npytest tests/\nB\necho after"
        assert wf._heredoc_stripped(text) == "cat <<A\ncat <<B\necho after"


class TestCommandSplitting:
    """``_commands`` is what lets the checker ask "is pytest the COMMAND here?"
    rather than "does the word appear?"."""

    def test_separators_split_one_line_into_commands(self) -> None:
        assert list(wf._commands("a && b || c ; d | e")) == [["a"], ["b"], ["c"], ["d"], ["e"]]

    def test_leading_environment_assignments_are_removed(self) -> None:
        assert list(wf._commands("AMA_CI_REQUIRE_BACKENDS=1 pytest tests/")) == [
            ["pytest", "tests/"]
        ]

    def test_several_leading_assignments_are_removed(self) -> None:
        assert list(wf._commands("A=1 B=2 pytest tests/")) == [["pytest", "tests/"]]

    def test_a_flag_that_contains_equals_is_not_an_assignment(self) -> None:
        assert list(wf._commands("cmake -DX=ON .")) == [["cmake", "-DX=ON", "."]]

    def test_a_non_identifier_before_equals_is_not_an_assignment(self) -> None:
        assert list(wf._commands("a.b=1 pytest")) == [["a.b=1", "pytest"]]

    def test_comments_are_removed(self) -> None:
        """A step that merely mentions pytest in its rationale is not running
        it."""
        assert list(wf._commands("echo hi  # pytest tests/")) == [["echo", "hi"]]

    def test_a_fully_commented_line_yields_nothing(self) -> None:
        assert list(wf._commands("# pytest tests/")) == []

    def test_line_continuations_are_joined(self) -> None:
        assert list(wf._commands("cmake \\\n  --build build")) == [["cmake", "--build", "build"]]

    def test_quoting_is_resolved(self) -> None:
        assert list(wf._commands('pip install -e ".[dev,hsm]"')) == [
            ["pip", "install", "-e", ".[dev,hsm]"]
        ]

    def test_an_untokenizable_block_falls_back_rather_than_vanishing(self) -> None:
        """A command the tokeniser cannot read must not silently become a
        command that does not exist."""
        assert list(wf._commands("pytest 'unbalanced")) == [["pytest", "'unbalanced"]]

    def test_a_later_command_is_still_yielded(self) -> None:
        assert list(wf._commands("echo one\npytest tests/")) == [
            ["echo", "one"],
            ["pytest", "tests/"],
        ]


class TestBasename:
    @pytest.mark.parametrize(
        "token,expected",
        [
            ("pytest", "pytest"),
            ("/usr/bin/pytest", "pytest"),
            ("C:\\Python\\python.exe", "python.exe"),
            ("./build/bin/x", "x"),
            ("a/b/c/d", "d"),
        ],
    )
    def test_the_final_component_for_either_separator(self, token: str, expected: str) -> None:
        assert wf._basename(token) == expected


class TestPytestInvocationDetection:
    @pytest.mark.parametrize("command", ["pytest", "pytest.exe", "/usr/bin/pytest"])
    def test_pytest_as_the_command_counts(self, command: str) -> None:
        assert wf._invokes_pytest([command, "tests/"]) is True

    @pytest.mark.parametrize("interpreter", sorted(wf._PYTHON_COMMANDS))
    def test_every_python_spelling_runs_the_module_form(self, interpreter: str) -> None:
        assert wf._invokes_pytest([interpreter, "-m", "pytest", "tests/"]) is True

    def test_installing_pytest_is_not_invoking_it(self) -> None:
        assert wf._invokes_pytest(["pip", "install", "pytest"]) is False
        assert wf._invokes_pytest(["pip", "install", "pytest==9.1.1"]) is False

    def test_another_module_is_not_pytest(self) -> None:
        assert wf._invokes_pytest(["python", "-m", "build"]) is False

    def test_a_trailing_dash_m_with_nothing_after_it_is_not_pytest(self) -> None:
        assert wf._invokes_pytest(["python", "-m"]) is False

    def test_a_bare_interpreter_is_not_pytest(self) -> None:
        assert wf._invokes_pytest(["python"]) is False


class TestNativeLibraryBuildDetection:
    """The four routes this repository uses.  A route that stops being
    recognised makes every job using it look like it never builds the library,
    which turns a correct workflow into a reported defect; a route wrongly
    recognised lets a job run pytest with no library at all."""

    def test_cmake_build_counts(self) -> None:
        assert wf._builds_native_library(["cmake", "--build", "build"]) is True
        assert wf._builds_native_library(["cmake.exe", "--build", "build"]) is True

    def test_cmake_configure_alone_does_not_count(self) -> None:
        assert wf._builds_native_library(["cmake", "-B", "build"]) is False

    @pytest.mark.parametrize("target", ["c", "build", "all", "install", "dev"])
    def test_every_make_target_in_the_table_counts(self, target: str) -> None:
        assert wf._builds_native_library(["make", target]) is True
        assert wf._builds_native_library(["gmake", target]) is True

    def test_an_unlisted_make_target_does_not_count(self) -> None:
        assert wf._builds_native_library(["make", "docs"]) is False

    def test_setup_py_build_counts(self) -> None:
        assert wf._builds_native_library(["python", "setup.py", "build_ext"]) is True

    def test_setup_py_without_a_build_command_does_not_count(self) -> None:
        assert wf._builds_native_library(["python", "setup.py", "sdist"]) is False

    @pytest.mark.parametrize("pip", ["pip", "pip3", "pip.exe"])
    def test_installing_the_project_counts(self, pip: str) -> None:
        assert wf._builds_native_library([pip, "install", "."]) is True
        assert wf._builds_native_library([pip, "install", "-e", "."]) is True
        assert wf._builds_native_library([pip, "install", "-e", ".[dev,hsm]"]) is True

    def test_the_python_dash_m_pip_form_counts(self) -> None:
        assert wf._builds_native_library(["python", "-m", "pip", "install", "."]) is True

    def test_pip_deeper_in_the_argv_is_not_the_pip_form(self) -> None:
        assert wf._builds_native_library(["python", "-c", "x", "pip", "install", "."]) is False

    def test_installing_a_wheel_counts(self) -> None:
        assert wf._builds_native_library(["pip", "install", "dist/ama-5.0.0.whl"]) is True

    def test_installing_a_third_party_package_does_not_count(self) -> None:
        assert wf._builds_native_library(["pip", "install", "pytest"]) is False

    def test_pip_without_install_does_not_count(self) -> None:
        assert wf._builds_native_library(["pip", "download", "."]) is False

    def test_an_unrelated_command_does_not_count(self) -> None:
        assert wf._builds_native_library(["echo", "cmake --build"]) is False


class TestTheDiagnosticImportEscape:
    """A value decided on the runner is not an escape: a check that guessed
    would report a job as covered that may not be."""

    @pytest.mark.parametrize("value", sorted(wf._ESCAPE_TRUE))
    def test_every_truthy_spelling_is_accepted(self, value: str) -> None:
        assert wf._escape_is_set({"env": {wf._POST_IMPORT_ESCAPE: value}}) is True

    def test_the_yaml_boolean_is_accepted(self) -> None:
        assert wf._escape_is_set({"env": {wf._POST_IMPORT_ESCAPE: True}}) is True

    def test_a_falsey_value_is_not_the_escape(self) -> None:
        assert wf._escape_is_set({"env": {wf._POST_IMPORT_ESCAPE: "0"}}) is False

    def test_an_expression_is_not_the_escape(self) -> None:
        assert wf._escape_is_set({"env": {wf._POST_IMPORT_ESCAPE: "${{ inputs.x }}"}}) is False

    def test_any_scope_setting_it_is_enough(self) -> None:
        assert wf._escape_is_set({}, {}, {"env": {wf._POST_IMPORT_ESCAPE: "1"}}) is True

    def test_an_earlier_scope_without_it_does_not_end_the_search(self) -> None:
        assert wf._escape_is_set({"env": {}}, {"env": {wf._POST_IMPORT_ESCAPE: "1"}}) is True

    def test_an_earlier_scope_setting_it_falsey_does_not_end_the_search(self) -> None:
        assert (
            wf._escape_is_set(
                {"env": {wf._POST_IMPORT_ESCAPE: "0"}},
                {"env": {wf._POST_IMPORT_ESCAPE: "1"}},
            )
            is True
        )

    def test_no_scope_setting_it_is_not_the_escape(self) -> None:
        assert wf._escape_is_set({}, {"env": {"OTHER": "1"}}) is False

    def test_the_build_pipeline_flag_is_not_the_escape(self) -> None:
        """``AMA_BUILD_PIPELINE`` excuses only the stale-artefact stages; a job
        with no library at all fails for a reason no re-signing repairs."""
        assert wf._escape_is_set({"env": {"AMA_BUILD_PIPELINE": "1"}}) is False


class TestCmakeOptionDefaults:
    def test_options_and_their_defaults_are_read(self, tmp_path: Path) -> None:
        lists = tmp_path / "CMakeLists.txt"
        lists.write_text(
            'option(AMA_ENABLE_DUDECT "Build dudect harnesses" OFF)\n'
            'option(AMA_ENABLE_AVX2 "Build AVX2 kernels" ON)\n',
            encoding="utf-8",
        )
        assert wf.cmake_option_defaults(lists) == {
            "AMA_ENABLE_DUDECT": "OFF",
            "AMA_ENABLE_AVX2": "ON",
        }

    def test_a_missing_file_yields_nothing_rather_than_raising(self, tmp_path: Path) -> None:
        assert wf.cmake_option_defaults(tmp_path / "absent.txt") == {}


class TestCmakeGatedTargets:
    @staticmethod
    def _lists(tmp_path: Path, text: str) -> Path:
        path = tmp_path / "CMakeLists.txt"
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
        return path

    def test_a_target_inside_a_guard_carries_its_flag(self, tmp_path: Path) -> None:
        path = self._lists(
            tmp_path,
            """
            if(AMA_ENABLE_DUDECT)
              add_executable(test_dudect a.c)
            endif()
            """,
        )
        assert wf.cmake_gated_targets([path]) == {"test_dudect": {"AMA_ENABLE_DUDECT"}}

    def test_a_target_outside_every_guard_carries_none(self, tmp_path: Path) -> None:
        path = self._lists(
            tmp_path,
            """
            if(AMA_ENABLE_DUDECT)
              add_executable(test_dudect a.c)
            endif()
            add_executable(test_plain b.c)
            """,
        )
        assert wf.cmake_gated_targets([path])["test_plain"] == set()

    def test_an_elseif_replaces_the_frames_condition(self, tmp_path: Path) -> None:
        """``elseif`` opens a new condition in the same frame.  Treating it as a
        nested ``if`` would leave the stack unbalanced and attribute the outer
        flag to every target after ``endif``."""
        path = self._lists(
            tmp_path,
            """
            if(AMA_ENABLE_AVX2)
              add_executable(t_avx a.c)
            elseif(AMA_ENABLE_NEON)
              add_executable(t_neon b.c)
            endif()
            add_executable(t_after c.c)
            """,
        )
        gated = wf.cmake_gated_targets([path])
        assert gated["t_avx"] == {"AMA_ENABLE_AVX2"}
        assert gated["t_neon"] == {"AMA_ENABLE_NEON"}
        assert gated["t_after"] == set()

    def test_nested_guards_accumulate(self, tmp_path: Path) -> None:
        path = self._lists(
            tmp_path,
            """
            if(AMA_ENABLE_DUDECT)
              if(AMA_ENABLE_AVX2)
                add_executable(t_both a.c)
              endif()
            endif()
            """,
        )
        assert wf.cmake_gated_targets([path])["t_both"] == {
            "AMA_ENABLE_DUDECT",
            "AMA_ENABLE_AVX2",
        }

    def test_an_unreadable_file_does_not_end_the_scan(self, tmp_path: Path) -> None:
        good = self._lists(
            tmp_path,
            "if(AMA_ENABLE_DUDECT)\n  add_executable(test_dudect a.c)\nendif()\n",
        )
        assert wf.cmake_gated_targets([tmp_path / "absent.txt", good]) == {
            "test_dudect": {"AMA_ENABLE_DUDECT"}
        }


class TestCmakeConfigureExtraction:
    def test_a_configure_is_found(self) -> None:
        assert wf._cmake_configure_commands("cmake -B build -S .") == ["cmake -B build -S ."]

    def test_continuations_are_joined_into_one_command(self) -> None:
        commands = wf._cmake_configure_commands("cmake \\\n  -B build \\\n  -DX=ON")
        assert len(commands) == 1
        assert "-B build" in commands[0]
        assert "-DX=ON" in commands[0]

    def test_a_commented_configure_is_not_a_command(self) -> None:
        assert wf._cmake_configure_commands("# cmake -B build") == []

    def test_a_later_configure_is_still_found(self) -> None:
        """A comment line early in the block must not end the scan."""
        commands = wf._cmake_configure_commands("# set up\ncmake -B build")
        assert commands == ["cmake -B build"]

    def test_a_build_invocation_is_not_a_configure(self) -> None:
        assert wf._cmake_configure_commands("cmake --build build") == []

    def test_cmake_as_a_package_name_is_not_a_configure(self) -> None:
        assert wf._cmake_configure_commands("apt-get install -y cmake clang") == []


class TestBuildTypeReporting:
    @staticmethod
    def _run(command: str) -> Report:
        report = Report()
        check_cmake_build_type(
            Path("test.yml"),
            {"jobs": {"b": {"runs-on": "ubuntu-latest", "steps": [{"run": command}]}}},
            report,
        )
        return report

    def test_a_configure_with_no_build_type_is_reported(self) -> None:
        report = self._run("cmake -B build -S .")
        assert len(report.findings) == 1, messages(report)
        assert "no optimization flag at all" in report.findings[0].message

    def test_a_named_build_type_is_accepted(self) -> None:
        assert self._run("cmake -B build -DCMAKE_BUILD_TYPE=Release").findings == []

    def test_an_explicit_optimization_flag_is_accepted(self) -> None:
        assert self._run('cmake -B build -DCMAKE_C_FLAGS="-O2 -g"').findings == []

    def test_the_reported_command_is_truncated_with_an_ellipsis(self) -> None:
        """Long configures are elided so the finding stays readable; the marker
        is what tells the reader the text was cut."""
        long_command = "cmake -B build " + " ".join(f"-DX{i}=1" for i in range(40))
        message = self._run(long_command).findings[0].message
        assert message.endswith("...")
        assert len(long_command) > 110

    def test_a_short_command_is_quoted_whole(self) -> None:
        message = self._run("cmake -B build").findings[0].message
        assert message.endswith("cmake -B build")

    def test_a_second_offending_step_is_also_reported(self) -> None:
        report = Report()
        check_cmake_build_type(
            Path("test.yml"),
            {
                "jobs": {
                    "b": {
                        "runs-on": "ubuntu-latest",
                        "steps": [
                            {"run": "cmake -B one -DCMAKE_BUILD_TYPE=Release"},
                            {"run": "cmake -B two"},
                        ],
                    }
                }
            },
            report,
        )
        assert len(report.findings) == 1, messages(report)
        assert report.cmake_configures_checked == 2


class TestExpressionBodyExtraction:
    def test_a_delimited_expression_is_found(self) -> None:
        found = wf._iter_expression_bodies({"run": "echo ${{ 1 + 2 }}"})
        assert [body for _location, body in found] == [" 1 + 2 "]

    def test_a_bare_if_condition_is_found_whole(self) -> None:
        """GitHub evaluates ``if:`` as an expression with no delimiters, so the
        whole value is the body."""
        found = wf._iter_expression_bodies({"if": "steps.x.outcome = 'failure'"})
        assert found == [("if", "steps.x.outcome = 'failure'")]

    def test_a_delimited_if_is_read_as_an_expression_not_as_a_bare_condition(self) -> None:
        found = wf._iter_expression_bodies({"if": "${{ success() }}"})
        assert [body for _location, body in found] == [" success() "]

    def test_the_location_names_the_path(self) -> None:
        found = wf._iter_expression_bodies({"jobs": {"b": {"if": "always()"}}})
        assert found == [("jobs.b.if", "always()")]

    def test_list_indices_appear_in_the_location(self) -> None:
        found = wf._iter_expression_bodies({"steps": [{"if": "always()"}]})
        assert found == [("steps[0].if", "always()")]

    def test_a_top_level_string_reports_the_root(self) -> None:
        found = wf._iter_expression_bodies("echo ${{ 1 + 2 }}")
        assert found == [("<root>", " 1 + 2 ")]

    def test_a_second_expression_after_the_first_is_found(self) -> None:
        found = wf._iter_expression_bodies({"a": {"if": "always()"}, "b": {"if": "cancelled()"}})
        assert len(found) == 2


class TestNeedsNormalisation:
    def test_a_scalar_becomes_a_single_entry_list(self) -> None:
        assert wf._normalize_needs("build") == ["build"]

    def test_a_sequence_is_kept(self) -> None:
        assert wf._normalize_needs(["build", "test"]) == ["build", "test"]

    def test_anything_else_is_empty(self) -> None:
        assert wf._normalize_needs(None) == []
        assert wf._normalize_needs({"build": 1}) == []

    def test_only_gate_suffixed_jobs_contribute_requirements(self) -> None:
        document = {
            "jobs": {
                "ci-gate": {"needs": ["build"]},
                "notifier": {"needs": ["publish"]},
            }
        }
        assert wf._gate_required_jobs(document) == {"build"}


class TestSweepOverADirectory:
    def test_an_unparseable_workflow_is_reported_and_does_not_end_the_sweep(
        self, tmp_path: Path
    ) -> None:
        """A workflow the runner cannot parse never runs at all — and the files
        after it still have to be checked."""
        (tmp_path / "aaa_broken.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
        (tmp_path / "zzz_retired.yml").write_text(
            "jobs:\n  b:\n    runs-on: macos-13\n    steps:\n      - run: echo hi\n",
            encoding="utf-8",
        )
        report = sweep(tmp_path)
        assert any("could not be parsed as YAML" in f.message for f in report.findings)
        assert any("has been retired" in f.message for f in report.findings)

    def test_a_directory_below_the_floor_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "one.yml").write_text("jobs: {}\n", encoding="utf-8")
        report = sweep(tmp_path)
        assert any(f"floor {MIN_WORKFLOWS}" in f.message for f in report.findings)

    def test_the_repositorys_own_workflow_set_meets_the_floor(self) -> None:
        workflows = REPO_ROOT / ".github" / "workflows"
        count = len(list(workflows.glob("*.yml"))) + len(list(workflows.glob("*.yaml")))
        assert count >= MIN_WORKFLOWS


class TestTheCommandLineContract:
    def test_a_clean_directory_exits_zero_and_says_so(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        for index in range(MIN_WORKFLOWS):
            (tmp_path / f"w{index}.yml").write_text(
                "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
                encoding="utf-8",
            )
        assert main(["--workflows-dir", str(tmp_path)]) == 0
        assert "WORKFLOW COMMAND CHECK PASSED" in capsys.readouterr().out

    def test_a_directory_with_a_defect_exits_one(self, tmp_path: Path) -> None:
        for index in range(MIN_WORKFLOWS):
            (tmp_path / f"w{index}.yml").write_text(
                "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
                encoding="utf-8",
            )
        (tmp_path / "bad.yml").write_text(
            "jobs:\n  b:\n    runs-on: macos-13\n    steps:\n      - run: echo hi\n",
            encoding="utf-8",
        )
        assert main(["--workflows-dir", str(tmp_path)]) == 1

    def test_unresolved_labels_are_listed_rather_than_assumed_fine(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        for index in range(MIN_WORKFLOWS):
            (tmp_path / f"w{index}.yml").write_text(
                "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
                encoding="utf-8",
            )
        (tmp_path / "dyn.yml").write_text(
            "jobs:\n  b:\n    runs-on: ${{ inputs.runner }}\n    steps:\n      - run: echo hi\n",
            encoding="utf-8",
        )
        main(["--workflows-dir", str(tmp_path)])
        assert "could not resolve" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# Round two (audit R2).
#
# The first round lifted the kill rate from 62.7 % to 81.1 %, and reading the
# 89 survivors found a flaw in the round-one tests themselves: parametrising
# over a table (`@pytest.mark.parametrize("label", sorted(SUPPORTED_LABELS))`)
# tests the table against ITSELF.  Delete an entry and the parametrisation
# simply generates one case fewer — every case still passes, and the gate now
# rejects a runner label the repository legitimately uses, or accepts a retired
# one.  That is the same self-referential shape this whole audit exists to
# find, reproduced in the audit's own tests.
#
# So each curated table is pinned to a literal below.  The literal is the
# claim: these labels were verified against GitHub's published runner images on
# 2026-07-25, and a future edit must restate them rather than silently drop
# one.  The per-entry behaviour tests above stay — together they say "this is
# the set, and every member of it behaves".
# ---------------------------------------------------------------------------


class TestTheCuratedTablesAreWhatTheySay:
    def test_the_supported_runner_labels(self) -> None:
        assert SUPPORTED_LABELS == frozenset(
            {
                "ubuntu-latest",
                "ubuntu-24.04",
                "ubuntu-22.04",
                "ubuntu-24.04-arm",
                "ubuntu-22.04-arm",
                "macos-latest",
                "macos-26",
                "macos-15",
                "macos-14",
                "macos-26-intel",
                "macos-15-intel",
                "windows-latest",
                "windows-2025",
                "windows-2022",
            }
        )

    def test_the_retired_runner_labels_and_their_replacements(self) -> None:
        macos = "macos-15-intel (Intel x86_64) or macos-15 (Apple Silicon arm64)"
        assert RETIRED_LABELS == {
            "macos-13": macos,
            "macos-12": macos,
            "macos-11": macos,
            "ubuntu-20.04": "ubuntu-24.04 or ubuntu-latest",
            "ubuntu-18.04": "ubuntu-24.04 or ubuntu-latest",
            "windows-2019": "windows-2025 or windows-latest",
            "windows-2016": "windows-2025 or windows-latest",
        }

    def test_every_replacement_names_a_supported_label(self) -> None:
        """The remedy has to be actionable: a replacement naming an image that
        is itself retired would send the reader in a circle."""
        for retired, replacement in RETIRED_LABELS.items():
            assert replacement.strip(), retired
            assert any(label in replacement for label in SUPPORTED_LABELS), retired

    def test_the_windows_command_keys(self) -> None:
        assert wf.WINDOWS_COMMAND_KEYS == (
            "CIBW_BEFORE_ALL_WINDOWS",
            "CIBW_BEFORE_BUILD_WINDOWS",
            "CIBW_BEFORE_TEST_WINDOWS",
            "CIBW_TEST_COMMAND_WINDOWS",
            "CIBW_REPAIR_WHEEL_COMMAND_WINDOWS",
        )

    def test_the_release_actions(self) -> None:
        assert RELEASE_ACTIONS == (
            "softprops/action-gh-release",
            "step-security/action-gh-release",
        )

    def test_the_python_interpreter_spellings(self) -> None:
        assert wf._PYTHON_COMMANDS == frozenset(
            {"python", "python3", "py", "python.exe", "python3.exe"}
        )

    def test_the_truthy_spellings_of_the_diagnostic_import_escape(self) -> None:
        assert wf._ESCAPE_TRUE == frozenset({"1", "true", "yes", "on"})

    def test_the_shell_double_quote_escape_table(self) -> None:
        assert wf._SH_DQ_ESCAPES == {'"': '"', "\\": "\\", "$": "$", "`": "`", "\n": ""}


class TestGatedBinaryCheckingCannotBeSilentlyDisabled:
    """``check_cmake_gated_binaries`` is the check that caught a job running
    ``./build/bin/test_dudect`` it had never built.  Several single-token edits
    make it examine nothing while still reporting clean — reading the wrong
    CMakeLists, collapsing every job's run text to the empty string, or
    requiring a flag only for an option whose default is a string no option
    has.  Each is pinned by asserting the check FIRES on a job that needs it."""

    @staticmethod
    def _tree(tmp_path: Path) -> Path:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / "CMakeLists.txt").write_text(
            'option(AMA_ENABLE_DUDECT "dudect harnesses" OFF)\n'
            'option(AMA_ENABLE_AVX2 "avx2 kernels" ON)\n',
            encoding="utf-8",
        )
        (tmp_path / "tests" / "c").mkdir(parents=True)
        (tmp_path / "tests" / "c" / "CMakeLists.txt").write_text(
            "if(AMA_ENABLE_DUDECT)\n  add_executable(test_dudect a.c)\nendif()\n"
            "if(AMA_ENABLE_AVX2)\n  add_executable(test_avx a.c)\nendif()\n",
            encoding="utf-8",
        )
        return tmp_path / ".github" / "workflows" / "test.yml"

    @staticmethod
    def _job(*runs: str) -> dict[str, object]:
        return {
            "jobs": {
                "harness": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": run} for run in runs],
                }
            }
        }

    def test_running_an_unbuilt_gated_binary_is_reported(self, tmp_path: Path) -> None:
        report = Report()
        wf.check_cmake_gated_binaries(
            self._tree(tmp_path),
            self._job("cmake -B build -DCMAKE_BUILD_TYPE=Release", "./build/bin/test_dudect"),
            report,
        )
        assert len(report.findings) == 1, messages(report)
        assert "AMA_ENABLE_DUDECT" in report.findings[0].message
        assert report.gated_binaries_checked == 1

    def test_enabling_the_flag_clears_it(self, tmp_path: Path) -> None:
        report = Report()
        wf.check_cmake_gated_binaries(
            self._tree(tmp_path),
            self._job("cmake -B build -DAMA_ENABLE_DUDECT=ON", "./build/bin/test_dudect"),
            report,
        )
        assert report.findings == [], messages(report)
        assert report.gated_binaries_checked == 1

    def test_a_target_behind_an_on_by_default_guard_needs_no_flag(self, tmp_path: Path) -> None:
        """Demanding the flag for an ON-by-default option would be noise, and a
        rule that matched any default value would demand it for every target."""
        report = Report()
        wf.check_cmake_gated_binaries(
            self._tree(tmp_path),
            self._job("cmake -B build -DCMAKE_BUILD_TYPE=Release", "./build/bin/test_avx"),
            report,
        )
        assert report.findings == [], messages(report)

    def test_the_run_text_of_every_step_is_considered_together(self, tmp_path: Path) -> None:
        """The configure and the invocation are usually different steps; a
        check that saw only one step at a time would report every job."""
        report = Report()
        wf.check_cmake_gated_binaries(
            self._tree(tmp_path),
            self._job("cmake -B build -DAMA_ENABLE_DUDECT=ON", "./build/bin/test_dudect"),
            report,
        )
        assert report.findings == [], messages(report)

    def test_a_job_with_no_run_steps_does_not_end_the_scan(self, tmp_path: Path) -> None:
        report = Report()
        document = {
            "jobs": {
                "empty": {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v5"}]},
                "harness": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "cmake -B build\n./build/bin/test_dudect"}],
                },
            }
        }
        wf.check_cmake_gated_binaries(self._tree(tmp_path), document, report)
        assert len(report.findings) == 1, messages(report)

    def test_two_missing_flags_are_both_named(self, tmp_path: Path) -> None:
        """The remedy lists every flag the target needs, separated so a reader
        can tell them apart."""
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / "CMakeLists.txt").write_text(
            'option(AMA_ENABLE_DUDECT "d" OFF)\noption(AMA_ENABLE_SLOW "s" OFF)\n',
            encoding="utf-8",
        )
        (tmp_path / "tests" / "c").mkdir(parents=True)
        (tmp_path / "tests" / "c" / "CMakeLists.txt").write_text(
            "if(AMA_ENABLE_DUDECT)\n  if(AMA_ENABLE_SLOW)\n"
            "    add_executable(test_dudect a.c)\n  endif()\nendif()\n",
            encoding="utf-8",
        )
        report = Report()
        wf.check_cmake_gated_binaries(
            tmp_path / ".github" / "workflows" / "test.yml",
            self._job("cmake -B build", "./build/bin/test_dudect"),
            report,
        )
        assert len(report.findings) == 1, messages(report)
        assert "AMA_ENABLE_DUDECT, AMA_ENABLE_SLOW" in report.findings[0].message
        assert "-DAMA_ENABLE_DUDECT=ON" in report.findings[0].remedy


class TestCountersStartAtZero:
    """Every ``*_checked`` counter is reported as the gate's non-vacuity
    evidence.  One that started at anything but zero would overstate the work
    done by exactly that much on every run."""

    def test_a_fresh_report_has_counted_nothing(self) -> None:
        report = Report()
        for field in (
            "labels_checked",
            "windows_commands_checked",
            "cmake_configures_checked",
            "expressions_checked",
            "pytest_steps_checked",
            "gate_required_jobs_checked",
            "gated_binaries_checked",
            "payloads_checked",
        ):
            assert getattr(report, field) == 0, field
        assert report.findings == []
        assert report.labels_unresolved == []


class TestOneSkippedItemDoesNotEndTheScan:
    """Every checker walks jobs and steps and skips what does not apply.  A
    skip that stopped the walk instead would leave the rest of the file
    unchecked while still reporting clean — the largest single class among the
    surviving mutants, and the quietest failure a gate can have."""

    def test_a_step_without_a_run_block_does_not_end_the_build_type_scan(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v5
                  - run: cmake -B build -S .
            """)
        assert any("no optimization flag" in f.message for f in report.findings), messages(report)

    def test_a_clean_job_does_not_end_the_build_type_scan(self) -> None:
        report = run_checks("""
            jobs:
              clean:
                runs-on: ubuntu-latest
                steps:
                  - run: cmake -B build -DCMAKE_BUILD_TYPE=Release
              dirty:
                runs-on: ubuntu-latest
                steps:
                  - run: cmake -B build2 -S .
            """)
        assert any("no optimization flag" in f.message for f in report.findings), messages(report)
        assert report.cmake_configures_checked == 2

    def test_a_non_cmd_step_does_not_end_the_windows_quoting_scan(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: windows-latest
                steps:
                  - run: echo bash step
                  - shell: cmd
                    run: pip install 'cmake>=4.3.4'
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_parseable_command_does_not_end_the_shell_scan(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: echo fine
                  - run: echo "unbalanced
            """)
        assert any(
            "quot" in f.message.lower() or "pars" in f.message.lower() for f in report.findings
        ), messages(report)

    def test_a_clean_job_does_not_end_the_pytest_prerequisite_scan(self) -> None:
        report = run_checks("""
            jobs:
              built:
                runs-on: ubuntu-latest
                steps:
                  - run: pip install -e .
                  - run: pytest tests/
              unbuilt:
                runs-on: ubuntu-latest
                steps:
                  - run: pytest tests/
            """)
        assert len(report.findings) == 1, messages(report)
        assert "unbuilt" in report.findings[0].location
        assert report.pytest_steps_checked == 2

    def test_a_step_without_a_run_block_does_not_end_the_pytest_scan(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/setup-python@v6
                  - run: pytest tests/
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_clean_step_does_not_end_the_gate_payload_scan(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [probe]
                steps:
                  - run: echo gate
              probe:
                runs-on: ubuntu-latest
                steps:
                  - id: cpu
                    run: echo "have=1" >> $GITHUB_OUTPUT
                  - run: echo unconditional
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert len(report.findings) == 1, messages(report)
        assert "self-probe" in report.findings[0].message

    def test_a_job_a_gate_does_not_need_does_not_end_the_payload_scan(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [other, probe]
                steps:
                  - run: echo gate
              other:
                runs-on: ubuntu-latest
                steps:
                  - run: echo fine
              probe:
                runs-on: ubuntu-latest
                steps:
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert len(report.findings) == 1, messages(report)
        assert report.gate_required_jobs_checked == 2

    def test_a_scope_without_the_escape_does_not_end_the_search(
        self,
    ) -> None:
        assert (
            wf._escape_is_set({"env": {"OTHER": "1"}}, {"env": {wf._POST_IMPORT_ESCAPE: "1"}})
            is True
        )

    def test_a_first_expression_does_not_end_the_expression_scan(self) -> None:
        found = wf._iter_expression_bodies({"a": "echo ${{ 1 + 2 }}", "b": "echo ${{ 3 + 4 }}"})
        assert len(found) == 2

    def test_an_earlier_command_does_not_end_the_command_scan(self) -> None:
        assert list(wf._commands("\n\necho one\npytest tests/")) == [
            ["echo", "one"],
            ["pytest", "tests/"],
        ]


class TestReportedDetailIsUsable:
    def test_a_python_module_invocation_with_no_arguments_is_pytest(self) -> None:
        """`python -m pytest` with nothing after it is a real invocation; a
        scan window that needed a trailing argument would miss it."""
        assert wf._invokes_pytest(["python", "-m", "pytest"]) is True

    def test_a_yaml_false_is_not_the_diagnostic_import_escape(self) -> None:
        """`AMA_POST_DIAGNOSTIC_IMPORT: false` must not read as set."""
        assert wf._escape_is_set({"env": {wf._POST_IMPORT_ESCAPE: False}}) is False

    def test_several_offending_arguments_are_listed_separately(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: windows-latest
                steps:
                  - shell: cmd
                    run: pip install 'aaa>=1' 'bbb>=2'
            """)
        assert len(report.findings) == 1, messages(report)
        assert "'aaa>=1', 'bbb>=2'" in report.findings[0].message

    def test_a_configure_at_the_truncation_boundary_is_not_elided(self) -> None:
        """110 characters is the boundary: at or below it the command is quoted
        whole, above it the ellipsis says the text was cut."""
        report = Report()
        command = "cmake -B build " + "-DX=1 " * 15
        command = command[:110].rstrip()
        check_cmake_build_type(
            Path("t.yml"),
            {"jobs": {"b": {"runs-on": "ubuntu-latest", "steps": [{"run": command}]}}},
            report,
        )
        assert len(command) <= 110
        assert not report.findings[0].message.endswith("...")

    def test_a_matrix_include_entry_that_is_not_a_mapping_is_ignored(self) -> None:
        job = {"strategy": {"matrix": {"include": ["not-a-mapping", {"os": "macos-15"}]}}}
        resolved, _unresolved = wf._resolve_runs_on("${{ matrix.os }}", job)
        assert resolved == ["macos-15"]

    def test_a_string_with_no_expression_yields_nothing(self) -> None:
        assert wf._iter_expression_bodies({"run": "echo plain text"}) == []

    def test_a_continuation_joins_with_a_separator_not_a_splice(self) -> None:
        """Dropping the newline without a space would weld the two tokens
        together and hide the command."""
        assert list(wf._commands("cmake\\\n--build build")) == [["cmake", "--build", "build"]]
        assert wf._cmake_configure_commands("cmake\\\n-B build") == ["cmake -B build"]

    def test_only_a_run_block_and_env_or_with_values_are_commands(self) -> None:
        found = dict(
            wf._iter_command_strings(
                {
                    "jobs": {
                        "b": {
                            "steps": [
                                {
                                    "run": "echo hi",
                                    "env": {"K": "v"},
                                    "with": {"w": "x"},
                                    "name": "n",
                                }
                            ]
                        }
                    }
                }
            )
        )
        assert "jobs.b.steps.[0].run" in found
        assert "jobs.b.steps.[0].env.K" in found
        assert "jobs.b.steps.[0].with.w" in found
        assert not any(key.endswith(".name") for key in found)

    @pytest.mark.parametrize(
        "workflow",
        [
            "jobs:\n  b:\n    runs-on: macos-13\n    steps:\n      - run: echo hi\n",
            "jobs:\n  b:\n    runs-on: ubuntu-lastest\n    steps:\n      - run: echo hi\n",
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: cmake -B build -S .\n",
            'jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "unbalanced\n',
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest tests/\n",
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    if: steps.x.outcome = 'failure'\n    steps:\n      - run: echo hi\n",
        ],
    )
    def test_every_finding_tells_the_reader_what_to_do(self, workflow: str) -> None:
        """A finding with an empty message or remedy is a gate that fires and
        says nothing, which is barely better than one that does not fire."""
        report = run_checks(workflow)
        assert report.findings, "expected this shape to be reported"
        for finding in report.findings:
            assert finding.workflow.strip(), finding
            assert finding.location.strip(), finding
            assert len(finding.message.strip()) > 20, finding
            assert len(finding.remedy.strip()) > 20, finding


class TestTheSweepReportsWhatItCouldNotRead:
    def test_an_unparseable_file_finding_names_the_file_and_the_stake(self, tmp_path: Path) -> None:
        (tmp_path / "broken.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
        report = sweep(tmp_path)
        parse = [f for f in report.findings if "could not be parsed" in f.message]
        assert len(parse) == 1
        assert parse[0].workflow == "broken.yml"
        assert parse[0].location.strip()
        assert "never runs" in parse[0].remedy

    def test_the_floor_finding_names_the_directory(self, tmp_path: Path) -> None:
        (tmp_path / "one.yml").write_text("jobs: {}\n", encoding="utf-8")
        floor = [f for f in sweep(tmp_path).findings if "floor" in f.message]
        assert len(floor) == 1
        assert floor[0].workflow.strip()
        assert str(tmp_path) in floor[0].location


class TestTheGateRunsAsCiRunsIt:
    def test_invoking_the_script_sweeps_the_repositorys_workflows(self) -> None:
        """CI runs `python tools/check_workflow_commands.py`.  If the script
        entry point stopped dispatching to main() the process would exit 0
        having checked nothing."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "check_workflow_commands.py")],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "WORKFLOW COMMAND CHECK PASSED" in result.stdout
        assert "--help" not in result.stdout


class TestASkippedJobOrStepNeverEndsAWalk:
    """Round two left 19 surviving ``continue -> break`` mutants, every one of
    them the same failure: a job or step the checker legitimately skips would
    instead end the walk, leaving everything after it unexamined while the
    gate still reports clean.  Each case below puts the skippable thing FIRST
    and asserts the thing after it is still found."""

    def test_a_job_without_a_steps_list_does_not_end_the_step_walk(self) -> None:
        steps = list(
            wf._iter_steps(
                {"jobs": {"a": {"runs-on": "ubuntu-latest"}, "b": {"steps": [{"run": "x"}]}}}
            )
        )
        assert [job for job, _index, _step in steps] == ["b"]

    def test_a_job_without_steps_does_not_end_the_windows_scan(self) -> None:
        report = run_checks("""
            jobs:
              nosteps:
                runs-on: windows-latest
              real:
                runs-on: windows-latest
                steps:
                  - shell: cmd
                    run: pip install 'cmake>=4.3.4'
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_step_that_is_not_a_mapping_does_not_end_the_windows_scan(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: windows-latest
                steps:
                  - plain string, not a mapping
                  - shell: cmd
                    run: pip install 'cmake>=4.3.4'
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_multi_line_command_does_not_end_the_shell_scan(self) -> None:
        """Multi-line blocks are left to the shell; skipping one must not stop
        the single-line check that follows."""
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      echo one
                      echo two
                  - run: echo "unbalanced
            """)
        assert any("balance the quoting" in f.remedy for f in report.findings), messages(report)

    def test_a_step_with_no_uses_does_not_end_the_release_scan(self) -> None:
        report = run_checks("""
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                  - run: echo prepare
                  - uses: softprops/action-gh-release@v2
                    with:
                      name: overwritten title
            """)
        assert report.release_steps_checked == 1
        assert report.findings, messages(report)

    def test_an_unrelated_action_does_not_end_the_release_scan(self) -> None:
        report = run_checks("""
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v5
                  - uses: softprops/action-gh-release@v2
                    with:
                      name: overwritten title
            """)
        assert report.release_steps_checked == 1
        assert report.findings, messages(report)

    def test_a_named_build_type_does_not_end_the_configure_scan(self) -> None:
        report = Report()
        check_cmake_build_type(
            Path("t.yml"),
            {
                "jobs": {
                    "b": {
                        "steps": [
                            {"run": "cmake -B one -DCMAKE_BUILD_TYPE=Release\ncmake -B two -S ."}
                        ]
                    }
                }
            },
            report,
        )
        assert report.cmake_configures_checked == 2
        assert len(report.findings) == 1, messages(report)

    def test_an_explicit_optimisation_flag_does_not_end_the_configure_scan(self) -> None:
        report = Report()
        check_cmake_build_type(
            Path("t.yml"),
            {
                "jobs": {
                    "b": {
                        "steps": [{"run": 'cmake -B one -DCMAKE_C_FLAGS="-O2"\ncmake -B two -S .'}]
                    }
                }
            },
            report,
        )
        assert report.cmake_configures_checked == 2
        assert len(report.findings) == 1, messages(report)

    def test_a_run_block_that_is_not_a_string_is_skipped_not_crashed_on(self) -> None:
        """A `run:` written as a YAML sequence is malformed, not a reason to
        raise: the checker must skip it and keep going."""
        report = Report()
        check_cmake_build_type(
            Path("t.yml"),
            {
                "jobs": {
                    "b": {"steps": [{"run": ["cmake", "-B", "build"]}, {"run": "cmake -B x -S ."}]}
                }
            },
            report,
        )
        assert len(report.findings) == 1, messages(report)

    def test_a_bare_condition_does_not_end_the_expression_walk(self) -> None:
        found = wf._iter_expression_bodies({"if": "always()", "run": "echo ${{ 1 + 2 }}"})
        assert len(found) == 2, found

    def test_an_empty_fragment_does_not_end_the_command_walk(self) -> None:
        assert list(wf._commands("; pytest tests/")) == [["pytest", "tests/"]]

    def test_a_job_without_steps_does_not_end_the_pytest_walk(self) -> None:
        report = run_checks("""
            jobs:
              nosteps:
                runs-on: ubuntu-latest
              real:
                runs-on: ubuntu-latest
                steps:
                  - run: pytest tests/
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_step_that_is_not_a_mapping_does_not_end_the_pytest_walk(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - plain string
                  - run: pytest tests/
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_satisfied_pytest_step_does_not_end_the_count(self) -> None:
        """Every pytest invocation is counted, satisfied or not: the count is
        the check's non-vacuity evidence."""
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      pip install -e .
                      pytest tests/one
                      pytest tests/two
            """)
        assert report.findings == [], messages(report)
        assert report.pytest_steps_checked == 2

    def test_an_escaped_pytest_step_does_not_end_the_count(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                env:
                  AMA_POST_DIAGNOSTIC_IMPORT: "1"
                steps:
                  - run: |
                      pytest tests/one
                      pytest tests/two
            """)
        assert report.findings == [], messages(report)
        assert report.pytest_steps_checked == 2

    def test_a_gate_need_that_names_no_job_does_not_end_the_payload_walk(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [aaa-absent, zzz-probe]
                steps:
                  - run: echo gate
              zzz-probe:
                runs-on: ubuntu-latest
                steps:
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_job_level_condition_does_not_end_the_payload_walk(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [aaa-conditional, zzz-probe]
                steps:
                  - run: echo gate
              aaa-conditional:
                runs-on: ubuntu-latest
                if: github.event_name == 'push'
                steps:
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
              zzz-probe:
                runs-on: ubuntu-latest
                steps:
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert len(report.findings) == 1, messages(report)
        assert "zzz-probe" in report.findings[0].location

    def test_a_required_job_without_steps_does_not_end_the_payload_walk(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [aaa-nosteps, zzz-probe]
                steps:
                  - run: echo gate
              aaa-nosteps:
                runs-on: ubuntu-latest
              zzz-probe:
                runs-on: ubuntu-latest
                steps:
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert len(report.findings) == 1, messages(report)

    def test_a_step_that_is_not_a_mapping_does_not_end_the_payload_walk(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [probe]
                steps:
                  - run: echo gate
              probe:
                runs-on: ubuntu-latest
                steps:
                  - plain string
                  - if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert len(report.findings) == 1, messages(report)

    def test_an_expression_valued_escape_does_not_end_the_scope_search(self) -> None:
        assert (
            wf._escape_is_set(
                {"env": {wf._POST_IMPORT_ESCAPE: "${{ inputs.x }}"}},
                {"env": {wf._POST_IMPORT_ESCAPE: "1"}},
            )
            is True
        )


class TestFindingsNameTheThingTheyFound:
    def test_the_pytest_finding_names_the_step(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - name: Run the suite
                    run: pytest tests/ -v
            """)
        assert len(report.findings) == 1, messages(report)
        assert "Run the suite" in report.findings[0].location

    def test_an_unnamed_step_is_identified_by_its_index(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: echo setup
                  - run: pytest tests/
            """)
        assert len(report.findings) == 1, messages(report)
        assert "steps[1]" in report.findings[0].location

    def test_the_pytest_finding_quotes_the_command_with_its_spacing(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: pytest tests/ -v --tb=short --no-cov
            """)
        message = report.findings[0].message
        assert "`pytest tests/ -v --tb=short ...`" in message

    def test_the_gate_payload_finding_names_the_step(self) -> None:
        report = run_checks("""
            jobs:
              ci-gate:
                runs-on: ubuntu-latest
                needs: [probe]
                steps:
                  - run: echo gate
              probe:
                runs-on: ubuntu-latest
                steps:
                  - name: Run the KAT
                    if: steps.cpu.outputs.have == '1'
                    run: ./build/bin/kat
            """)
        assert "Run the KAT" in report.findings[0].location

    def test_a_configure_one_character_over_the_limit_is_elided(self) -> None:
        report = Report()
        command = "cmake -B build " + "-DX=" + "1" * (111 - 19)
        check_cmake_build_type(
            Path("t.yml"), {"jobs": {"b": {"steps": [{"run": command}]}}}, report
        )
        assert len(command) == 111
        message = report.findings[0].message
        assert message.endswith(command[:110] + "...")
        assert command not in message

    def test_a_configure_exactly_at_the_limit_is_quoted_whole(self) -> None:
        report = Report()
        command = "cmake -B build " + "-DX=" + "1" * (110 - 19)
        check_cmake_build_type(
            Path("t.yml"), {"jobs": {"b": {"steps": [{"run": command}]}}}, report
        )
        assert len(command) == 110
        assert not report.findings[0].message.endswith("...")

    def test_at_most_four_offending_arguments_are_listed(self) -> None:
        report = run_checks("""
            jobs:
              b:
                runs-on: windows-latest
                steps:
                  - shell: cmd
                    run: pip install 'a>1' 'b>1' 'c>1' 'd>1' 'e>1'
            """)
        message = report.findings[0].message
        assert message.count("'") == 8
        assert "'e>1'" not in message


class TestSmallDetectorContracts:
    def test_a_relative_path_with_a_trailing_slash_is_the_project(self) -> None:
        assert wf._builds_native_library(["pip", "install", "./"]) is True

    def test_an_expression_that_is_not_a_matrix_reference_is_not_resolved_through_one(
        self,
    ) -> None:
        """The prefix decides.  Dropping it resolves `${{ inputs.os }}` through
        the matrix by stripping seven characters from a name that never had the
        prefix — which lands on `os`, a key the matrix really does have — so a
        label the workflow never asks for is reported as verified and the real
        expression is never reported as unresolved."""
        job = {"strategy": {"matrix": {"os": ["ubuntu-latest"]}}}
        resolved, unresolved = wf._resolve_runs_on("${{ inputs.os }}", job)
        assert resolved == []
        assert unresolved == ["${{ inputs.os }}"]

    def test_a_matrix_reference_in_the_same_job_still_resolves(self) -> None:
        job = {"strategy": {"matrix": {"os": ["ubuntu-latest"]}}}
        resolved, unresolved = wf._resolve_runs_on("${{ matrix.os }}", job)
        assert resolved == ["ubuntu-latest"]
        assert unresolved == []

    def test_run_blocks_are_joined_with_a_newline_not_welded(self) -> None:
        """Concatenating two steps' run text would let a flag split across the
        boundary read as one flag, clearing a job that never set it."""
        repo = Path(__file__).resolve().parent.parent
        report = Report()
        document = {
            "jobs": {
                "harness": {
                    "steps": [
                        {"run": "echo -DAMA_ENABLE_DUDECT="},
                        {"run": "ON\n./build/bin/test_dudect"},
                    ]
                }
            }
        }
        wf.check_cmake_gated_binaries(repo / ".github" / "workflows" / "t.yml", document, report)
        assert len(report.findings) == 1, messages(report)
        assert "AMA_ENABLE_DUDECT" in report.findings[0].message

    def test_the_command_line_describes_itself(self) -> None:
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "check_workflow_commands.py"), "--help"],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0
        assert "Verify GitHub Actions runner labels" in result.stdout
        assert "directory of workflow files to check" in result.stdout
