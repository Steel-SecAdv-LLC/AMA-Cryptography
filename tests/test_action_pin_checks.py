# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_action_pins.py`` (INVARIANT-24).

The gate is required in CI and had no test of its own, which is the same gap
INVARIANT-2 names about the Bandit gate: *"a gate with no negative control has
not been shown to be a gate at all."*

The defect INVARIANT-24 exists for was expensive and entirely silent.
``release.yml`` carried ``pypa/cibuildwheel@e9c4a96e…  # v3.2.0`` — a SHA that
is neither the ``v3.2.0`` tag object nor its dereferenced commit. Every wheel
job aborted with *"Unable to resolve action … unable to find version"*, which
is why the v3.2.0 and v3.3.0 releases both published **zero binary artefacts**.
``release.yml`` runs only on a tag push, so nothing resolved the pin until
release day.

Each rule below therefore gets driven with the failure it exists to catch, and
with the legitimate shape it must not fire on:

* a SHA advertised by no ref must fail (the historical defect);
* under ``--strict``, a version comment naming a tag the SHA is not under must
  fail — a comment naming the wrong version is how a pin drifts from what a
  reviewer believes is running;
* an unreachable upstream must be **inconclusive**, never a pass, because an
  unverified pin is not a verified one;
* a correct pin, with and without a comment, must pass.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_action_pins.py"

GOOD_SHA = "a" * 40
OTHER_SHA = "b" * 40


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_action_pins", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _workflow(tmp_path: Path, body: str, name: str = "wf.yml") -> Path:
    directory = tmp_path / "workflows"
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(body, encoding="utf-8")
    return directory


def _run(
    tool: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    pins: list[object],
    refs: Optional[dict[str, list[str]]],
    strict: bool = False,
) -> int:
    monkeypatch.setattr(tool, "find_pins", lambda _dir: pins)
    monkeypatch.setattr(tool, "list_remote_refs", lambda _repo, **_kw: refs)
    return int(tool.main(["--strict"] if strict else []))


class TestFindPins:
    def test_extracts_action_sha_and_comment(self, tool: ModuleType, tmp_path: Path) -> None:
        directory = _workflow(
            tmp_path,
            f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{GOOD_SHA}  # v5.0.1\n",
        )
        pins = tool.find_pins(directory)
        assert len(pins) == 1
        assert pins[0].action == "actions/checkout"
        assert pins[0].sha == GOOD_SHA
        assert pins[0].comment == "v5.0.1"
        assert pins[0].line_no == 4

    def test_sub_path_action_resolves_to_its_base_repo(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """``github/codeql-action/init`` is advertised by ``github/codeql-action``."""
        directory = _workflow(
            tmp_path, f"      - uses: github/codeql-action/init@{GOOD_SHA}  # v4\n"
        )
        pins = tool.find_pins(directory)
        assert pins[0].base_repo == "github/codeql-action"

    def test_a_mutable_tag_reference_is_not_counted_as_a_pin(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """Non-detection: ``@v1`` is a different violation (INVARIANT-4).

        This checker's subject is whether a *SHA* resolves. Reporting ``@v1``
        here would make its output about two rules at once and its failures
        harder to act on.
        """
        directory = _workflow(tmp_path, "      - uses: actions/checkout@v5\n")
        assert tool.find_pins(directory) == []

    def test_scans_yaml_as_well_as_yml(self, tool: ModuleType, tmp_path: Path) -> None:
        directory = _workflow(
            tmp_path, f"      - uses: actions/checkout@{GOOD_SHA}\n", name="other.yaml"
        )
        assert len(tool.find_pins(directory)) == 1

    def test_repository_pins_parse(self, tool: ModuleType) -> None:
        """Non-vacuity: the regex must match this repository's real workflows.

        A regex that matched nothing would make every assertion above pass
        against a synthetic corpus while the gate verified nothing real.
        """
        pins = tool.find_pins(REPO_ROOT / ".github" / "workflows")
        assert len(pins) > 10
        assert all(len(pin.sha) == 40 for pin in pins)


class TestDisplayRef:
    def test_prefers_a_tag_over_head(self, tool: ModuleType) -> None:
        """``git ls-remote`` advertises HEAD first.

        Keeping only the first match made a correctly tag-pinned action report
        as ``-> HEAD`` and made the version comment impossible to verify.
        """
        assert tool._display_ref(["HEAD", "refs/tags/v3.2.0"]) == "v3.2.0"

    def test_dereferenced_tag_suffix_is_stripped(self, tool: ModuleType) -> None:
        assert tool._display_ref(["refs/tags/v1.2.3^{}"]) == "v1.2.3"

    def test_falls_back_to_a_branch(self, tool: ModuleType) -> None:
        assert tool._display_ref(["refs/heads/main"]) == "main"

    def test_no_refs_is_not_an_exception(self, tool: ModuleType) -> None:
        assert tool._display_ref([]) == "<unknown>"


class TestVerdict:
    def test_unresolvable_sha_fails(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exact shape of the cibuildwheel defect: SHA on no ref at all."""
        pin = tool.Pin("release.yml", 12, "pypa/cibuildwheel", GOOD_SHA, "v3.2.0")
        rc = _run(tool, monkeypatch, [pin], {OTHER_SHA: ["refs/tags/v3.2.0"]})
        assert rc == 1

    def test_resolvable_sha_passes(self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
        pin = tool.Pin("release.yml", 12, "pypa/cibuildwheel", GOOD_SHA, "v4.1.1")
        rc = _run(tool, monkeypatch, [pin], {GOOD_SHA: ["HEAD", "refs/tags/v4.1.1"]})
        assert rc == 0

    def test_strict_rejects_a_comment_naming_the_wrong_tag(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pin = tool.Pin("release.yml", 12, "pypa/cibuildwheel", GOOD_SHA, "v3.2.0")
        refs = {GOOD_SHA: ["refs/tags/v4.1.1"]}
        assert _run(tool, monkeypatch, [pin], refs, strict=True) == 1

    def test_a_wrong_comment_is_tolerated_without_strict(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``--strict`` must be the thing that turns the comment check on.

        Without this, the flag would be decorative and CI's use of it
        meaningless.
        """
        pin = tool.Pin("release.yml", 12, "pypa/cibuildwheel", GOOD_SHA, "v3.2.0")
        refs = {GOOD_SHA: ["refs/tags/v4.1.1"]}
        assert _run(tool, monkeypatch, [pin], refs, strict=False) == 0

    def test_strict_accepts_a_dereferenced_tag_match(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An annotated tag advertises ``refs/tags/v1^{}`` for its commit.

        Failing this would make the gate un-satisfiable for every annotated
        tag, which is most of them.
        """
        pin = tool.Pin("ci.yml", 3, "actions/checkout", GOOD_SHA, "v5.0.1")
        refs = {GOOD_SHA: ["refs/tags/v5.0.1^{}"]}
        assert _run(tool, monkeypatch, [pin], refs, strict=True) == 0

    def test_strict_tolerates_a_sha_carrying_no_tag(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A branch-head pin has no tag to contradict the comment."""
        pin = tool.Pin("ci.yml", 3, "some/action", GOOD_SHA, "main")
        refs = {GOOD_SHA: ["refs/heads/main"]}
        assert _run(tool, monkeypatch, [pin], refs, strict=True) == 0

    def test_unreachable_upstream_is_inconclusive_not_a_pass(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ "Unverifiable is not valid" — the sentence INVARIANT-24 ends on.

        Exit 2, distinct from both 0 and 1, so a network outage cannot read as
        a green supply-chain control.
        """
        pin = tool.Pin("ci.yml", 3, "actions/checkout", GOOD_SHA, "v5.0.1")
        assert _run(tool, monkeypatch, [pin], None) == 2

    def test_a_real_missing_pin_outranks_an_unreachable_one(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A definite failure must not be downgraded to "inconclusive".

        ``missing`` is checked before ``unreachable``; if that order inverted,
        one unreachable repository would mask a genuinely bad pin in another.
        """
        pins = [
            tool.Pin("release.yml", 12, "pypa/cibuildwheel", GOOD_SHA, "v3.2.0"),
            tool.Pin("ci.yml", 3, "other/action", OTHER_SHA, "v1"),
        ]

        def _refs(repo: str, **_kw: object) -> Optional[dict[str, list[str]]]:
            return {} if repo == "pypa/cibuildwheel" else None

        monkeypatch.setattr(tool, "find_pins", lambda _dir: pins)
        monkeypatch.setattr(tool, "list_remote_refs", _refs)
        assert int(tool.main([])) == 1

    def test_no_pins_at_all_is_not_a_failure(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tool, "find_pins", lambda _dir: [])
        assert int(tool.main([])) == 0
