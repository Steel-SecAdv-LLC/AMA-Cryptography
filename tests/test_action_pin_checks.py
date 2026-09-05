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
        """``find_pins`` collects SHA pins only; ``find_unpinned`` is the other half.

        This used to end the story, with the comment "``@v1`` is a different
        violation (INVARIANT-4)" — and INVARIANT-4 had no enforcement anywhere,
        so recording the gap here is all that ever happened to it.  The split
        is still right (this collector's subject is whether a SHA resolves),
        but the other rule is now checked too, by
        :class:`TestUnpinnedReferencesAreRefused` below.
        """
        directory = _workflow(tmp_path, "      - uses: actions/checkout@v5\n")
        assert tool.find_pins(directory) == []
        # ...and the reference is not simply ignored by the gate as a whole.
        assert [u.ref for u in tool.find_unpinned(directory)] == ["actions/checkout@v5"]

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

    def test_no_pins_at_all_fails_closed(
        self, tool: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """This used to exit 0 — "No SHA-pinned actions found — nothing to
        verify."

        Every other gate in ``tools/`` refuses an empty scan
        (``check_vendor_isolation``, ``check_docker_pins``,
        ``check_secret_division``, ``check_compiler_warnings``,
        ``check_dudect_class_staging``, ``check_fuzz_input_reachability``).
        This repository pins 122 references, so an empty collection is a
        broken collector or a moved workflow directory, never a clean tree —
        and passing on it is the failure direction.
        """
        monkeypatch.setattr(tool, "find_pins", lambda _dir: [])
        assert int(tool.main([])) == 1


class TestUnpinnedReferencesAreRefused:
    """INVARIANT-4, which nothing enforced until 5.0.0.

    INVARIANTS.md: "All third-party GitHub Actions used in security workflows
    **must** be pinned to a full commit SHA, not a mutable tag (``@main``,
    ``@v1``, etc.)"; ARCHITECTURE.md restates it as an enforced invariant.  The
    only checker that reads workflow ``uses:`` lines matched
    ``@[0-9a-f]{40}`` exclusively, so a reference carrying no SHA was
    structurally invisible to it — the rule had a checker that could not see
    its violations.

    A mutable tag is not a cosmetic problem: whoever controls the upstream
    repository can move it, and the workflow then runs different code with no
    diff in this repository.
    """

    @pytest.mark.parametrize(
        "ref,label",
        [
            ("actions/checkout@v4", "a version tag"),
            ("actions/checkout@main", "a branch"),
            ("actions/checkout@3d3c42e", "an abbreviated SHA"),
            ("actions/checkout", "no ref at all"),
            ("some/action@3d3c42e5aac5ba805825da76410c181273ba90b1x", "41 characters"),
        ],
    )
    def test_an_unpinned_reference_is_reported(
        self, tool: ModuleType, tmp_path: Path, ref: str, label: str
    ) -> None:
        directory = _workflow(tmp_path, f"      - uses: {ref}\n")
        found = tool.find_unpinned(directory)
        assert found, f"accepted {label}: {ref}"
        assert found[0].ref == ref

    @pytest.mark.parametrize(
        "ref,label",
        [
            ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "a full SHA"),
            ("./.github/workflows/local.yml", "a local reusable workflow"),
            ("docker://alpine:3.19", "a container reference"),
        ],
    )
    def test_a_compliant_reference_is_accepted(
        self, tool: ModuleType, tmp_path: Path, ref: str, label: str
    ) -> None:
        directory = _workflow(tmp_path, f"      - uses: {ref}\n")
        assert tool.find_unpinned(directory) == [], label

    def test_a_commented_out_reference_is_not_a_violation(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        directory = _workflow(tmp_path, "#      - uses: actions/checkout@v4\n")
        assert tool.find_unpinned(directory) == []

    def test_the_slsa_generator_exemption_is_named_and_reasoned(
        self, tool: ModuleType, tmp_path: Path
    ) -> None:
        """The one reference that cannot comply, and why it is not a hole.

        The SLSA generator verifies that its caller referenced it by a
        semantic-version tag and fails otherwise, because the tag is what its
        provenance attests.  The exemption is keyed on the exact workflow path,
        not a prefix, so a different workflow from the same generator does not
        inherit it silently.
        """
        exempt = (
            "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"
        )
        assert exempt in tool._PIN_EXEMPT
        assert len(tool._PIN_EXEMPT[exempt]) > 80, "an exemption needs a stated reason"
        directory = _workflow(tmp_path, f"    uses: {exempt}@v2.1.0\n")
        assert tool.find_unpinned(directory) == []

        sibling = "slsa-framework/slsa-github-generator/.github/workflows/other.yml"
        directory = _workflow(tmp_path, f"    uses: {sibling}@v2.1.0\n")
        assert tool.find_unpinned(directory) != [], "the exemption leaked to a sibling workflow"

    def test_the_repository_has_no_unpinned_reference(self, tool: ModuleType) -> None:
        assert tool.find_unpinned(REPO_ROOT / ".github" / "workflows") == []

    def test_an_empty_pin_set_fails_closed(self, tool: ModuleType, tmp_path: Path) -> None:
        """ "Nothing to verify" used to exit 0.

        Every other gate in ``tools/`` refuses an empty scan. This repository
        pins 122 references, so an empty collection means the collector broke.
        """
        workflows = _workflow(tmp_path, "      - run: echo hi\n")
        assert tool.find_pins(workflows) == [], "the collector found a pin where there is none"

        # ...and the GATE refuses it.  Asserting only that the collector
        # returns [] is a statement about the collector, not about failing
        # closed, and this test is named for the latter: with the `if not pins`
        # branch deleted the assertion above still held.
        exit_code = tool.main(["--strict", "--root", str(tmp_path)])
        assert exit_code != 0, (
            "an empty pin set exited 0 — the gate passed vacuously on a tree "
            "where the collector found nothing to check"
        )
