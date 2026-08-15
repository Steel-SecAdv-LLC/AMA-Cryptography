#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The container base-image gate must fail on the conditions it names.

``tools/check_docker_pins.py`` exists because two properties of the published
images were unchecked: the bases were pinned by mutable tag, and one of them
(``alpine:3.18``) had been past end-of-support for fifteen months. A gate for
either is worth nothing unless it can actually fail, so both directions are
exercised on purpose-built input as well as on the real tree.

The end-of-support half is checked against an injected date rather than the
system clock: a test that passes only until some future morning is not a test.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from tools import check_docker_pins as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

_PINNED = "alpine:3.23@sha256:" + "f" * 64
_TODAY = _dt.date(2026, 8, 13)


def _write(tmp_path: Path, body: str, name: str = "Dockerfile") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _dockerfile(base: str = _PINNED, eol: str | None = "2027-11-01") -> str:
    head = f"# base-eol: {eol}\n" if eol else ""
    return f"{head}FROM {base} AS builder\nRUN echo hi\n"


class TestDigestPinning:
    def test_a_tag_only_base_is_flagged(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _dockerfile(base="alpine:3.23"))
        findings = gate.audit([path], today=_TODAY)
        assert len(findings) == 1, [f.render() for f in findings]
        assert "mutable pointer" in findings[0].render()

    @pytest.mark.parametrize(
        "base",
        [
            "alpine:3.23@sha256:" + "a" * 63,  # digest too short
            "alpine:3.23@sha256:" + "g" * 64,  # not hex
            "alpine:3.23@sha1:" + "a" * 40,  # wrong algorithm
        ],
    )
    def test_a_malformed_digest_is_not_accepted(self, tmp_path: Path, base: str) -> None:
        findings = gate.audit([_write(tmp_path, _dockerfile(base=base))], today=_TODAY)
        assert findings, f"{base} was accepted as a digest pin"

    def test_a_properly_pinned_base_passes(self, tmp_path: Path) -> None:
        assert gate.audit([_write(tmp_path, _dockerfile())], today=_TODAY) == []

    def test_a_stage_reference_is_not_treated_as_an_image(self, tmp_path: Path) -> None:
        """``FROM builder AS x`` names an earlier stage and cannot carry a digest."""
        body = f"# base-eol: 2027-11-01\nFROM {_PINNED} AS builder\nFROM builder AS runtime\n"
        assert gate.audit([_write(tmp_path, body)], today=_TODAY) == []

    def test_main_exits_nonzero_on_a_finding(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _dockerfile(base="ubuntu:22.04"))
        assert gate.main([str(path)]) == 1

    def test_main_exits_zero_on_clean_input(self, tmp_path: Path) -> None:
        assert gate.main([str(_write(tmp_path, _dockerfile()))]) == 0


class TestSupportWindow:
    def test_a_missing_declaration_is_flagged(self, tmp_path: Path) -> None:
        findings = gate.audit([_write(tmp_path, _dockerfile(eol=None))], today=_TODAY)
        assert len(findings) == 1
        assert "base-eol" in findings[0].render()

    def test_a_base_past_end_of_support_is_flagged(self, tmp_path: Path) -> None:
        """The alpine:3.18 case: EOL 2025-05-09, still in use in Aug 2026."""
        findings = gate.audit([_write(tmp_path, _dockerfile(eol="2025-05-09"))], today=_TODAY)
        assert len(findings) == 1
        assert findings[0].kind == gate.EOL_PASSED
        assert "left support" in findings[0].render()

    def test_the_gate_fires_before_support_lapses(self, tmp_path: Path) -> None:
        """The point of the grace window: fail while there is time to act."""
        soon = (_TODAY + _dt.timedelta(days=gate.GRACE_DAYS - 1)).isoformat()
        findings = gate.audit([_write(tmp_path, _dockerfile(eol=soon))], today=_TODAY)
        assert len(findings) == 1
        assert findings[0].kind == gate.EOL_APPROACHING
        assert "reaches end-of-support" in findings[0].render()

    def test_a_base_comfortably_in_support_passes(self, tmp_path: Path) -> None:
        far = (_TODAY + _dt.timedelta(days=gate.GRACE_DAYS + 1)).isoformat()
        assert gate.audit([_write(tmp_path, _dockerfile(eol=far))], today=_TODAY) == []


class TestSupportWindowIsEnforcedNotAdvised:
    """The warn-versus-fail question, settled as a behaviour rather than prose.

    ``check_docker_pins`` fails on the support window instead of warning.  The
    objection — a red gate with no diff behind it — is real, and answered in
    ``GRACE_DAYS``: the failure being replaced is ``alpine:3.18`` shipping in a
    published cryptography image for fifteen months after leaving support,
    which a warning would not have changed.  These pin the decision so a later
    "make it a warning" cannot land silently.
    """

    def test_both_states_fail_the_gate(self, tmp_path: Path) -> None:
        approaching = (_TODAY + _dt.timedelta(days=gate.GRACE_DAYS - 1)).isoformat()
        passed = (_TODAY - _dt.timedelta(days=1)).isoformat()
        for eol in (approaching, passed):
            path = _write(tmp_path, _dockerfile(eol=eol), name=f"Dockerfile.{eol}")
            assert gate.main([str(path)]) == 1, (
                f"eol={eol} must fail the gate, not merely report — a "
                f"warn-only support window is not a gate"
            )

    def test_the_two_states_are_distinguishable_without_reading_prose(self, tmp_path: Path) -> None:
        boundary = _TODAY.isoformat()  # today == eol: support has lapsed
        findings = gate.audit([_write(tmp_path, _dockerfile(eol=boundary))], today=_TODAY)
        assert [f.kind for f in findings] == [gate.EOL_PASSED]

        one_day_left = (_TODAY + _dt.timedelta(days=1)).isoformat()
        findings = gate.audit([_write(tmp_path, _dockerfile(eol=one_day_left))], today=_TODAY)
        assert [f.kind for f in findings] == [gate.EOL_APPROACHING]

    def test_every_finding_kind_is_labelled(self, tmp_path: Path) -> None:
        """No path may emit an unlabelled Finding — the default is a placeholder."""
        cases = [
            _dockerfile(eol=None),
            _dockerfile(eol=(_TODAY - _dt.timedelta(days=1)).isoformat()),
            _dockerfile(eol=(_TODAY + _dt.timedelta(days=1)).isoformat()),
            "# base-eol: 2099-01-01\nFROM alpine:3.23\n",
        ]
        seen = set()
        for i, body in enumerate(cases):
            for finding in gate.audit(
                [_write(tmp_path, body, name=f"Dockerfile.case{i}")], today=_TODAY
            ):
                assert finding.kind, f"unlabelled finding: {finding.render()}"
                seen.add(finding.kind)
        assert seen == {
            gate.EOL_UNDECLARED,
            gate.EOL_PASSED,
            gate.EOL_APPROACHING,
            gate.NOT_DIGEST_PINNED,
        }

    def test_the_shipped_dockerfiles_are_not_about_to_trip_the_gate(self) -> None:
        """A base whose window closes imminently is a finding waiting to happen.

        The gate answers "is it broken today"; this answers "is the tree one
        ordinary sprint away from breaking on a pull request that has nothing
        to do with containers".  Failing here is a prompt to bump the base
        deliberately rather than to discover it mid-review.
        """
        horizon = _dt.date.today() + _dt.timedelta(days=gate.GRACE_DAYS)
        imminent = gate.audit(today=horizon)
        assert (
            imminent == []
        ), "a shipped base leaves support within " f"{2 * gate.GRACE_DAYS} days:\n" + "\n".join(
            f.render() for f in imminent
        )


class TestExemptions:
    def test_the_oss_fuzz_base_is_exempt_but_must_explain_itself(self, tmp_path: Path) -> None:
        """An exemption that says nothing is indistinguishable from an oversight."""
        oss = REPO_ROOT / "oss-fuzz" / "Dockerfile"
        assert "oss-fuzz/Dockerfile" in gate.EXEMPT
        assert gate.audit([oss], today=_TODAY) == [], "the real OSS-Fuzz file should pass"

        # Same path, prose removed: the exemption must no longer be accepted.
        stripped = "FROM gcr.io/oss-fuzz-base/base-builder\nRUN echo hi\n"
        findings = gate.scan(oss, stripped, _TODAY)
        assert len(findings) == 1
        assert "does not say why" in findings[0].render()

    def test_a_non_exempt_file_cannot_borrow_the_exemption(self, tmp_path: Path) -> None:
        body = "# mentions oss-fuzz in passing\nFROM alpine:3.23\n"
        findings = gate.audit([_write(tmp_path, body)], today=_TODAY)
        assert findings, "an unlisted file must not be exempted by prose alone"


class TestScopeAndFailClosed:
    def test_the_real_tree_is_clean(self) -> None:
        findings = gate.audit()
        assert findings == [], "\n".join(f.render() for f in findings)

    def test_every_shipped_dockerfile_is_in_scope(self) -> None:
        found = {p.relative_to(REPO_ROOT).as_posix() for p in gate.dockerfiles()}
        for expected in (
            "docker/Dockerfile",
            "docker/Dockerfile.alpine",
            "docker/Dockerfile.c-api",
            "oss-fuzz/Dockerfile",
        ):
            assert expected in found, f"{expected} is not scanned"

    def test_missing_file_argument_is_a_usage_error(self, tmp_path: Path) -> None:
        assert gate.main([str(tmp_path / "nope")]) == 2

    def test_empty_scan_fails_closed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A scan that finds nothing is a broken scan, never a silent pass."""
        empty = tmp_path / "tree"
        empty.mkdir()
        monkeypatch.setattr(gate, "REPO_ROOT", empty)
        assert gate.main([]) == 2
