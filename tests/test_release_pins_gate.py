# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls and wiring for ``tools/check_release_pins.py`` (INVARIANT-2).

A gate with no negative control has not been shown to be a gate.  Each class
below plants one of the shapes the gate exists to refuse — an unhashed line, a
floating ``>=`` specifier, a pin below a declared floor, a bare ``pip install``
in release.yml, a cibuildwheel step that builds in isolation — and asserts that
exactly that problem, and no other, is reported.  The real tree is then held to
the gate, and the two mutations the pin gate was written against (dropping a
pin's hashes, restoring a floating install) are replayed on a scratch copy so
the gate's ability to fail on the real files is demonstrated on every run.

The manifests' shape is also pinned directly: every hash 64 hex characters, LF
line endings only, the generator's canonical form — because pip's
``--require-hashes`` is only as strong as the bytes it is handed, and a CRLF
checkout or a hand-edited hash is the kind of drift that reads fine until
release day.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from tools import check_release_pins as pins

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
BUILD = "requirements-release-build.txt"
TOOLS = "requirements-release-tools.txt"
AS_OF = "2026-09-25"
DIGEST = "ab" * 32

FLOORS = [
    pins.Floor("setuptools", (84, 0, 0), "pyproject.toml"),
    pins.Floor("wheel", (0, 48, 0), "pyproject.toml"),
    pins.Floor("cmake", (4, 4, 3), "pyproject.toml"),
    pins.Floor("Cython", (3, 3, 0), "setup.py"),
    pins.Floor("numpy", (1, 24, 0), "setup.py"),
]
INTERPRETERS = ["3.10", "3.11", "3.12", "3.13", "3.14"]
MANIFEST_INSTALL = "pip install --require-hashes -r {project}/requirements-release-build.txt"
FRONTEND = "pip; args: --no-build-isolation"
SDIST_RUN = (
    "python -m pip install --require-hashes -r requirements-release-tools.txt\n"
    "python -m pip install --require-hashes -r requirements-release-build.txt\n"
    "python -m build --sdist --no-isolation\n"
    "pip install --no-build-isolation dist/*.tar.gz\n"
)


def _pin(
    name: str,
    version: str,
    marker: str | None = None,
    hashes: list[str] | None = None,
    notes: tuple[str, ...] = (),
) -> pins.Pin:
    return pins.Pin(name, version, marker, list(hashes or [DIGEST]), list(notes), 0, "==")


def _good_build_pins() -> list[pins.Pin]:
    return [
        _pin("setuptools", "84.0.0"),
        _pin("wheel", "0.48.0"),
        _pin("packaging", "26.3"),
        _pin("cmake", "4.4.3"),
        _pin("Cython", "3.3.0"),
        _pin("numpy", "2.2.6", 'python_version < "3.11"'),
        _pin("numpy", "2.4.6", 'python_version >= "3.11"'),
    ]


def _manifest_problems(text: str, name: str = BUILD) -> list[str]:
    """Problems for one manifest text, floors and interpreters as the tree has them."""
    parsed = pins.parse_manifest(text, name)
    report = pins.Report()
    pins.check_manifests({name: parsed}, FLOORS, INTERPRETERS, report)
    return report.problems


def _workflow(
    *,
    before_build: str = MANIFEST_INSTALL,
    frontend: str | None = FRONTEND,
    sdist_run: str = SDIST_RUN,
) -> dict[str, Any]:
    env: dict[str, Any] = {
        "CIBW_BUILD": "cp310-* cp311-*",
        "CIBW_BEFORE_BUILD_LINUX": before_build,
    }
    if frontend is not None:
        env["CIBW_BUILD_FRONTEND"] = frontend
    return {
        "jobs": {
            "build-wheels": {
                "steps": [{"name": "Build wheels", "uses": "pypa/cibuildwheel@abc", "env": env}]
            },
            "build-sdist": {"steps": [{"name": "Build sdist", "run": sdist_run}]},
        }
    }


def _workflow_problems(document: dict[str, Any]) -> list[str]:
    report = pins.Report()
    pins.check_workflow(document, report)
    return report.problems


def _scratch_tree(tmp_path: Path) -> Path:
    """A copy of every file the gate reads, free to corrupt.

    Bytes, not text, so the copies are the originals on every platform and a
    test that mutates one line is testing that line and not the line endings.
    """
    root = tmp_path / "tree"
    for relative in (BUILD, TOOLS, "pyproject.toml", "setup.py", ".github/workflows/release.yml"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REPO_ROOT / relative).read_bytes())
    return root


def _problems(root: Path) -> list[str]:
    report, fatal = pins.run_checks(root)
    assert fatal is None, fatal
    return report.problems


class TestManifestNegativeControls:
    """Each plants one defect in an otherwise canonical manifest."""

    def test_a_canonical_manifest_passes(self) -> None:
        """Non-vacuity for the class: the base the controls mutate is clean."""
        assert _manifest_problems(pins.render_manifest(BUILD, _good_build_pins(), AS_OF)) == []

    def test_a_line_without_a_hash_is_reported(self) -> None:
        pinned = _good_build_pins()
        pinned[3].hashes = []  # cmake
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "cmake==4.4.3" in problems[0]
        assert "carries no --hash" in problems[0]

    def test_a_floating_specifier_is_reported(self) -> None:
        text = pins.render_manifest(BUILD, _good_build_pins(), AS_OF)
        text = text.replace("cmake==4.4.3 \\", "cmake>=4.4.3 \\")
        problems = _manifest_problems(text)
        assert len(problems) == 1, problems
        assert "not pinned with `==`" in problems[0]
        assert ">=" in problems[0]

    def test_a_bare_name_is_reported(self) -> None:
        text = pins.render_manifest(BUILD, _good_build_pins(), AS_OF)
        text = text.replace("cmake==4.4.3 \\", "cmake \\")
        problems = _manifest_problems(text)
        assert len(problems) == 1, problems
        assert "no specifier" in problems[0]

    def test_a_pin_below_a_floor_is_reported(self) -> None:
        pinned = _good_build_pins()
        pinned[3] = _pin("cmake", "4.4.2")
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "cmake==4.4.2 is below the declared floor cmake>=4.4.3" in problems[0]

    def test_a_pin_equal_to_its_floor_passes(self) -> None:
        """The floor is inclusive; a gate that refused the floor itself would be wrong."""
        pinned = _good_build_pins()
        pinned[4] = _pin("Cython", "3.3.0")
        assert _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF)) == []

    def test_a_hash_that_is_not_sixty_four_hex_is_reported(self) -> None:
        pinned = _good_build_pins()
        pinned[0].hashes = ["ab" * 31]
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "--hash=sha256:<64 hex>" in problems[0]

    def test_a_marker_that_does_not_parse_is_reported(self) -> None:
        pinned = _good_build_pins()
        pinned[5] = _pin("numpy", "2.2.6", "python_version <")
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "does not parse" in problems[0]

    def test_a_missing_floor_package_is_reported(self) -> None:
        pinned = [pin for pin in _good_build_pins() if pin.name != "wheel"]
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "wheel (floor >=0.48.0) is not pinned" in problems[0]

    def test_two_pins_applying_on_one_interpreter_are_reported(self) -> None:
        pinned = _good_build_pins()
        pinned[6] = _pin("numpy", "2.4.6", 'python_version >= "3.10"')
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "2 pins apply on CPython 3.10" in problems[0]

    def test_an_interpreter_left_with_no_pin_is_reported(self) -> None:
        pinned = _good_build_pins()
        pinned[6] = _pin("numpy", "2.4.6", 'python_version >= "3.12"')
        problems = _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF))
        assert len(problems) == 1, problems
        assert "no pin applies on CPython 3.11" in problems[0]

    def test_a_platform_marker_is_undecided_rather_than_refused(self) -> None:
        """The gate knows the interpreter, not the platform, and does not guess."""
        pinned = _good_build_pins()
        pinned[3] = _pin("cmake", "4.4.3", 'sys_platform == "win32"')
        assert _manifest_problems(pins.render_manifest(BUILD, pinned, AS_OF)) == []

    def test_a_carriage_return_is_reported(self) -> None:
        text = pins.render_manifest(BUILD, _good_build_pins(), AS_OF).replace("\n", "\r\n")
        problems = _manifest_problems(text)
        assert any("carriage return" in problem for problem in problems), problems

    def test_a_missing_as_of_header_is_reported(self) -> None:
        text = pins.render_manifest(BUILD, _good_build_pins(), AS_OF)
        text = re.sub(r"^# Hash set as published by PyPI on: .*\n", "", text, flags=re.M)
        problems = _manifest_problems(text)
        assert len(problems) == 1, problems
        assert "Hash set as published by PyPI on" in problems[0]


class TestTheCanonicalFormIsEnforcedOnTheTree:
    """``run_checks`` also compares the file to what ``--refresh`` would write."""

    def test_an_unsorted_hash_list_is_reported(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        path = root / TOOLS
        text = path.read_text(encoding="utf-8")
        block = re.search(
            r"pip==26\.2\.1 \\\n"
            r"    --hash=sha256:([0-9a-f]{64}) \\\n"
            r"    --hash=sha256:([0-9a-f]{64})\n",
            text,
        )
        assert block is not None, "pip==26.2.1 publishes exactly two files (sdist + wheel)"
        first, second = block.groups()
        assert first < second, "the committed order is sorted"
        swapped = (
            text[: block.start()]
            + f"pip==26.2.1 \\\n    --hash=sha256:{second} \\\n    --hash=sha256:{first}\n"
            + text[block.end() :]
        )
        path.write_text(swapped, encoding="utf-8", newline="")
        problems = _problems(root)
        assert len(problems) == 1, problems
        assert "not in the generator's canonical form" in problems[0]


class TestWorkflowNegativeControls:
    """Each plants one offending command in an otherwise compliant workflow."""

    def test_the_two_permitted_shapes_pass(self) -> None:
        assert _workflow_problems(_workflow()) == []

    def test_a_bare_pip_install_is_reported_with_its_job_and_step(self) -> None:
        problems = _workflow_problems(_workflow(before_build="pip install 'cmake>=4.4.3'"))
        assert len(problems) == 1, problems
        assert "job 'build-wheels' step 0 (Build wheels) env CIBW_BEFORE_BUILD_LINUX" in problems[0]
        assert "cmake>=4.4.3" in problems[0]

    def test_a_pip_upgrade_in_a_run_block_is_reported(self) -> None:
        problems = _workflow_problems(
            _workflow(sdist_run="python -m pip install --upgrade pip\n" + SDIST_RUN)
        )
        assert len(problems) == 1, problems
        assert "job 'build-sdist' step 0 (Build sdist) run" in problems[0]
        assert "--upgrade pip" in problems[0]

    def test_a_manifest_install_without_require_hashes_is_reported(self) -> None:
        problems = _workflow_problems(
            _workflow(before_build="pip install -r {project}/requirements-release-build.txt")
        )
        assert len(problems) == 1, problems
        assert "without --require-hashes" in problems[0]

    def test_a_requirements_file_that_is_not_a_release_manifest_is_reported(self) -> None:
        problems = _workflow_problems(
            _workflow(before_build="pip install --require-hashes -r requirements-lock.txt")
        )
        assert len(problems) == 1, problems
        assert "not one of the release manifests" in problems[0]

    def test_an_index_option_is_reported(self) -> None:
        problems = _workflow_problems(
            _workflow(
                before_build=(
                    "pip install --require-hashes --extra-index-url https://x/ "
                    "-r {project}/requirements-release-build.txt"
                )
            )
        )
        assert len(problems) == 1, problems
        assert "names an index" in problems[0]

    def test_the_sdist_installed_with_isolation_is_reported(self) -> None:
        problems = _workflow_problems(
            _workflow(
                sdist_run=SDIST_RUN.replace("pip install --no-build-isolation", "pip install")
            )
        )
        assert len(problems) == 1, problems
        assert "add --no-build-isolation" in problems[0]

    def test_a_build_with_isolation_is_reported(self) -> None:
        problems = _workflow_problems(
            _workflow(sdist_run=SDIST_RUN.replace("--sdist --no-isolation", "--sdist"))
        )
        assert len(problems) == 1, problems
        assert "python -m build --sdist" in problems[0]
        assert "add --no-isolation" in problems[0]

    def test_a_cibuildwheel_step_without_the_frontend_is_reported(self) -> None:
        problems = _workflow_problems(_workflow(frontend=None))
        assert len(problems) == 1, problems
        assert "CIBW_BUILD_FRONTEND=None" in problems[0]
        assert "job 'build-wheels' step 0 (Build wheels)" in problems[0]

    def test_a_cibuildwheel_step_with_an_isolating_frontend_is_reported(self) -> None:
        problems = _workflow_problems(_workflow(frontend="build"))
        assert len(problems) == 1, problems
        assert "CIBW_BUILD_FRONTEND='build'" in problems[0]

    def test_the_build_frontend_form_is_accepted_too(self) -> None:
        assert _workflow_problems(_workflow(frontend="build; args: --no-isolation")) == []

    def test_the_frontend_is_resolved_from_the_job_scope(self) -> None:
        document = _workflow(frontend=None)
        document["jobs"]["build-wheels"]["env"] = {"CIBW_BUILD_FRONTEND": FRONTEND}
        assert _workflow_problems(document) == []

    def test_pip_download_and_pip_wheel_resolve_from_the_index_too(self) -> None:
        for subcommand in ("download", "wheel"):
            problems = _workflow_problems(_workflow(before_build=f"pip {subcommand} cmake"))
            assert len(problems) == 1, problems
            assert f"`pip {subcommand}` resolves from the index" in problems[0]

    def test_python_dash_m_pip_and_a_venv_pip_are_recognised(self) -> None:
        for command in (
            "/opt/venv/bin/python -X utf8 -m pip install cmake",
            "/opt/venv/bin/pip install cmake",
            "pip3 install cmake",
        ):
            problems = _workflow_problems(_workflow(sdist_run=command + "\n" + SDIST_RUN))
            assert len(problems) == 1, (command, problems)

    def test_a_pip_install_in_a_heredoc_or_comment_is_not_a_command(self) -> None:
        run = (
            "cat <<'EOF'\npip install something\nEOF\n"
            "# pip install nothing\n"
            "echo 'pip install' \\\n  quoted\n" + SDIST_RUN
        )
        assert _workflow_problems(_workflow(sdist_run=run)) == []

    def test_a_workflow_scope_cibw_command_is_walked(self) -> None:
        document = _workflow()
        document["env"] = {"CIBW_BEFORE_BUILD_MACOS": "pip install cython"}
        problems = _workflow_problems(document)
        assert len(problems) == 1, problems
        assert "workflow env CIBW_BEFORE_BUILD_MACOS" in problems[0]


class TestTheRealTree:
    def test_the_real_tree_passes(self) -> None:
        report, fatal = pins.run_checks(REPO_ROOT)
        assert fatal is None, fatal
        assert report.problems == []

    def test_the_non_vacuity_floors_equal_the_live_counts(self) -> None:
        """The floors are pinned to what release.yml carries, under review."""
        report, _ = pins.run_checks(REPO_ROOT)
        assert report.pip_installs == pins.MIN_PIP_INSTALLS >= 9
        assert report.manifest_installs == report.pip_installs - report.sdist_installs
        assert report.sdist_installs == 1
        assert report.cibuildwheel_steps == pins.MIN_CIBUILDWHEEL_STEPS == 2
        assert report.build_invocations == pins.MIN_BUILD_INVOCATIONS == 1
        assert report.interpreters == INTERPRETERS

    def test_every_manifest_hash_is_sixty_four_hex_and_no_pin_is_bare(self) -> None:
        for name in (BUILD, TOOLS):
            parsed = pins.parse_manifest((REPO_ROOT / name).read_text(encoding="utf-8"), name)
            assert parsed.problems == []
            assert parsed.pins, name
            for pin in parsed.pins:
                assert pin.hashes, pin.requirement
                for digest in pin.hashes:
                    assert re.fullmatch(r"[0-9a-f]{64}", digest), (pin.requirement, digest)

    def test_every_manifest_line_uses_lf_and_no_crlf(self) -> None:
        for name in (BUILD, TOOLS):
            data = (REPO_ROOT / name).read_bytes()
            assert b"\r" not in data, f"{name} carries a carriage return"
            assert data.endswith(b"\n"), f"{name} does not end in a newline"
            assert b"\n\n\n" not in data, f"{name} carries a double blank line"

    def test_the_build_manifest_covers_every_release_interpreter_for_numpy(self) -> None:
        """The split the numpy note describes, checked rather than described."""
        parsed = pins.parse_manifest((REPO_ROOT / BUILD).read_text(encoding="utf-8"), BUILD)
        numpy = [pin for pin in parsed.pins if pin.key == "numpy"]
        assert len(numpy) == 2
        assert {pin.marker for pin in numpy} == {
            'python_version < "3.11"',
            'python_version >= "3.11"',
        }

    def test_dropping_a_pins_hashes_fails_the_tree(self, tmp_path: Path) -> None:
        """The first mutation the gate was written against, replayed on a copy."""
        root = _scratch_tree(tmp_path)
        path = root / BUILD
        text = path.read_text(encoding="utf-8")
        mutated, count = re.subn(
            r"setuptools==84\.0\.0 \\\n(?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+",
            "setuptools==84.0.0\n",
            text,
        )
        assert count == 1
        path.write_text(mutated, encoding="utf-8", newline="")
        problems = _problems(root)
        assert len(problems) == 1, problems
        assert "setuptools==84.0.0` carries no --hash" in problems[0]

    def test_restoring_a_floating_install_fails_the_tree(self, tmp_path: Path) -> None:
        """The second mutation: the pre-manifest CIBW_BEFORE_BUILD_MACOS line."""
        root = _scratch_tree(tmp_path)
        path = root / ".github" / "workflows" / "release.yml"
        text = path.read_text(encoding="utf-8")
        old = (
            'CIBW_BEFORE_BUILD_MACOS: "pip install --require-hashes '
            '-r {project}/requirements-release-build.txt"'
        )
        assert text.count(old) == 1
        path.write_text(
            text.replace(
                old,
                "CIBW_BEFORE_BUILD_MACOS: \"pip install 'cmake>=4.4.3' "
                "'cython>=3.3.0' 'numpy>=1.24.0'\"",
            ),
            encoding="utf-8",
            newline="",
        )
        problems = _problems(root)
        assert len(problems) == 1, problems
        assert "CIBW_BEFORE_BUILD_MACOS" in problems[0]
        assert "job 'build-wheels'" in problems[0]

    def test_removing_a_frontend_line_fails_the_tree(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        path = root / ".github" / "workflows" / "release.yml"
        text = path.read_text(encoding="utf-8")
        line = '          CIBW_BUILD_FRONTEND: "pip; args: --no-build-isolation"\n'
        assert text.count(line) == 2
        path.write_text(text.replace(line, "", 1), encoding="utf-8", newline="")
        problems = _problems(root)
        assert len(problems) == 1, problems
        assert "CIBW_BUILD_FRONTEND=None" in problems[0]

    def test_a_runtime_dependency_would_fail_the_sdist_install(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        path = root / "pyproject.toml"
        text = path.read_text(encoding="utf-8")
        assert text.count("\ndependencies = []\n") == 1
        path.write_text(
            text.replace("\ndependencies = []\n", '\ndependencies = ["numpy"]\n'),
            encoding="utf-8",
            newline="",
        )
        problems = _problems(root)
        assert len(problems) == 1, problems
        assert "[project].dependencies is not the empty list" in problems[0]

    def test_the_ci_workflow_runs_the_gate_in_code_quality(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")
        assert "python tools/check_release_pins.py\n" in text
        suppression = text.index("python tools/check_suppression_hygiene.py")
        gate = text.index("python tools/check_release_pins.py")
        assert suppression < gate < text.index("python tools/check_required_contexts.py")


class TestTheFloorsAreReadNotRestated:
    def test_pyproject_floors_are_read_from_the_build_system_table(self) -> None:
        floors = pins.pyproject_floors((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert {pins.normalize(floor.name) for floor in floors} == {
            "setuptools",
            "wheel",
            "cmake",
            "cython",
            "numpy",
        }
        assert all(floor.source == "pyproject.toml" for floor in floors)

    def test_setup_floors_are_read_from_the_preflight_table(self) -> None:
        floors = pins.setup_floors((REPO_ROOT / "setup.py").read_text(encoding="utf-8"))
        assert {(pins.normalize(floor.name), floor.version) for floor in floors} == {
            (pins.normalize(floor.name), floor.version)
            for floor in pins.pyproject_floors(
                (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
            )
        }, "setup.py's preflight and pyproject.toml declare themselves identical"

    def test_raising_a_floor_above_a_pin_fails_the_tree(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        path = root / "pyproject.toml"
        text = path.read_text(encoding="utf-8")
        assert text.count('"cmake>=4.4.3"') == 1
        path.write_text(text.replace('"cmake>=4.4.3"', '"cmake>=4.5.0"'), encoding="utf-8")
        problems = _problems(root)
        assert len(problems) == 1, problems
        assert "cmake==4.4.3 is below the declared floor cmake>=4.5.0" in problems[0]

    def test_a_floor_that_is_not_greater_or_equal_cannot_be_run(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        path = root / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace('"cmake>=4.4.3"', '"cmake~=4.4.3"'),
            encoding="utf-8",
        )
        _, fatal = pins.run_checks(root)
        assert fatal is not None and "~=" in fatal

    def test_a_missing_floor_table_cannot_be_run(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        (root / "setup.py").write_text("print('no preflight')\n", encoding="utf-8")
        _, fatal = pins.run_checks(root)
        assert fatal is not None and "setup.py" in fatal


class TestTheMarkerEvaluator:
    def test_python_version_compares_as_a_version(self) -> None:
        node = pins.parse_marker('python_version < "3.11"')
        assert pins.evaluate_marker(node, {"python_version": "3.10"}) is True
        assert pins.evaluate_marker(node, {"python_version": "3.11"}) is False
        # A string comparison would put "3.9" after "3.11"; a version one does not.
        assert pins.evaluate_marker(node, {"python_version": "3.9"}) is True

    def test_and_or_and_parentheses(self) -> None:
        node = pins.parse_marker(
            '(python_version >= "3.10" and python_version < "3.12") or extra == "x"'
        )
        assert pins.evaluate_marker(node, {"python_version": "3.11", "extra": ""}) is True
        assert pins.evaluate_marker(node, {"python_version": "3.13", "extra": ""}) is False

    def test_an_unknown_variable_is_undecided(self) -> None:
        node = pins.parse_marker('sys_platform == "win32" and python_version >= "3.10"')
        assert pins.evaluate_marker(node, {"python_version": "3.11"}) is None
        assert pins.evaluate_marker(node, {"python_version": "3.9"}) is False

    @pytest.mark.parametrize(
        "marker",
        [
            "python_version <",
            'python_version < "3.11" and',
            "(python_version)",
            'foo == "1"',
            '"a" "b"',
        ],
    )
    def test_malformed_markers_raise(self, marker: str) -> None:
        with pytest.raises(pins.MarkerSyntaxError):
            pins.parse_marker(marker)


#: Every name pinned across both manifests, as written there (the canned reader
#: is keyed by the name the pin carries, exactly as PyPI is asked).
ALL_PINNED = (
    "setuptools",
    "wheel",
    "packaging",
    "cmake",
    "Cython",
    "numpy",
    "pip",
    "build",
    "pyproject_hooks",
)


def _table(seed: str) -> dict[str, list[str]]:
    return {name: [seed * 32] for name in ALL_PINNED}


def _canned(published: dict[str, list[str]]) -> pins.Fetcher:
    """A PyPI reader answering from a table, in the order the table gives."""

    def fetch(name: str, version: str) -> Any:
        return {
            "info": {"version": version},
            "urls": [{"digests": {"sha256": digest}} for digest in published[name]],
        }

    return fetch


class TestRefresh:
    """``--refresh`` is deterministic and ``--check`` reports without writing."""

    def test_the_output_is_a_function_of_the_pins_and_the_date(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        published = _table("44")
        published["pip"] = ["ff" * 32, "00" * 32]
        assert pins.refresh(root, AS_OF, False, _canned(published)) == 0
        first = (root / TOOLS).read_bytes()
        # Same table, reversed order: the hashes are sorted, so the bytes agree.
        reversed_table = {name: list(reversed(digests)) for name, digests in published.items()}
        assert pins.refresh(root, AS_OF, False, _canned(reversed_table)) == 0
        assert (root / TOOLS).read_bytes() == first
        text = first.decode("utf-8")
        assert f"# Hash set as published by PyPI on: {AS_OF}\n" in text
        assert (
            "pip==26.2.1 \\\n    --hash=sha256:"
            + "00" * 32
            + " \\\n    --hash=sha256:"
            + "ff" * 32
            + "\n"
        ) in text
        assert b"\r" not in first
        # A different date is a different file, and only the header line moves:
        # the note comments also carry a date, and a refresh must not touch them.
        header = f"# Hash set as published by PyPI on: {AS_OF}\n".encode("ascii")
        assert first.count(header) == 1
        assert pins.refresh(root, "2026-01-01", False, _canned(published)) == 0
        assert (root / TOOLS).read_bytes() == first.replace(
            header, b"# Hash set as published by PyPI on: 2026-01-01\n"
        )

    def test_notes_above_a_requirement_survive_a_refresh(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        before = pins.parse_manifest((root / TOOLS).read_text(encoding="utf-8"), TOOLS)
        assert any(pin.notes for pin in before.pins), "the fixture carries a note to preserve"
        assert pins.refresh(root, AS_OF, False, _canned(_table("44"))) == 0
        after = pins.parse_manifest((root / TOOLS).read_text(encoding="utf-8"), TOOLS)
        assert [pin.notes for pin in after.pins] == [pin.notes for pin in before.pins]
        assert [pin.requirement for pin in after.pins] == [pin.requirement for pin in before.pins]

    def test_check_reports_drift_and_writes_nothing(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        published = _table("55")
        original = (root / TOOLS).read_bytes()
        assert pins.refresh(root, AS_OF, True, _canned(published)) == 1
        assert (root / TOOLS).read_bytes() == original
        assert pins.refresh(root, AS_OF, False, _canned(published)) == 0
        assert pins.refresh(root, AS_OF, True, _canned(published)) == 0

    def test_a_version_mismatch_or_an_empty_file_list_is_refused(self) -> None:
        def wrong_version(name: str, version: str) -> Any:
            return {"info": {"version": "0.0"}, "urls": [{"digests": {"sha256": DIGEST}}]}

        def no_files(name: str, version: str) -> Any:
            return {"info": {"version": version}, "urls": []}

        def bad_digest(name: str, version: str) -> Any:
            return {"info": {"version": version}, "urls": [{"digests": {"sha256": "zz"}}]}

        for fetch in (wrong_version, no_files, bad_digest):
            with pytest.raises(ValueError):
                pins.release_hashes("pip", "26.2.1", fetch)

    def test_a_malformed_as_of_date_is_refused(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        assert pins.refresh(root, "yesterday", False, _canned({})) == 2

    def test_refresh_requires_as_of_on_the_command_line(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            pins.main(["--repo", str(_scratch_tree(tmp_path)), "--refresh"])
        assert excinfo.value.code == 2


class TestExitCodes:
    def test_zero_on_the_scratch_copy_of_the_tree(self, tmp_path: Path) -> None:
        assert pins.main(["--repo", str(_scratch_tree(tmp_path))]) == 0

    def test_one_on_a_failing_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _scratch_tree(tmp_path)
        path = root / TOOLS
        path.write_text(
            path.read_text(encoding="utf-8").replace("build==1.6.1 \\", "build>=1.6.1 \\"),
            encoding="utf-8",
            newline="",
        )
        assert pins.main(["--repo", str(root)]) == 1
        assert "RELEASE PIN CHECK FAILED" in capsys.readouterr().err

    def test_two_when_a_manifest_is_missing(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        (root / BUILD).unlink()
        assert pins.main(["--repo", str(root)]) == 2

    def test_two_when_release_yml_does_not_parse(self, tmp_path: Path) -> None:
        root = _scratch_tree(tmp_path)
        (root / ".github" / "workflows" / "release.yml").write_text("jobs: [\n", encoding="utf-8")
        assert pins.main(["--repo", str(root)]) == 2

    def test_the_offline_mode_rejects_refresh_only_options(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            pins.main(["--repo", str(_scratch_tree(tmp_path)), "--check"])
        assert excinfo.value.code == 2
