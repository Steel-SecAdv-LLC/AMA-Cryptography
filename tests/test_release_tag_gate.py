# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for ``tools/check_release_tag.py`` (INVARIANT-2).

A gate with no negative control has not been shown to be a gate. This module
builds throwaway repositories carrying each tag shape the gate is supposed to
distinguish and asserts the verdict on every one of them:

======================  =======  ==========================================
shape                   verdict  why it is the shape it is
======================  =======  ==========================================
missing                 FAIL     nothing to release from
lightweight             FAIL     ref -> commit; no object to sign
annotated, unsigned     FAIL     the shape of five of this repo's own tags
annotated, PGP-signed   PASS
annotated, SSH-signed   PASS
annotated, X.509-signed PASS
======================  =======  ==========================================

The three passing fixtures embed a signature *block* that is not a real
signature. That is deliberate and it is exactly what the tool claims to check:
its docstring states it verifies shape, not cryptography. A fixture that had to
carry a genuine signature would need a private key in the test suite, which
INVARIANT-17 forbids outright.

(The repository *does* ship a trust store — ``.github/allowed_signers`` — and
``tests/test_release_tag_trust_store.py`` performs the real cryptographic check
against it, on a real signature, with no private key anywhere. This module and
that one draw different lines on purpose: shape here, attribution there.)

The line these tests draw is the line the tool draws — and the
``test_a_real_signature_is_not_required`` case says so out loud so nobody later
reads a PASS here as a cryptographic result.

Tag objects are written with ``git hash-object -t tag`` rather than
``git tag -s`` for the same reason: ``git tag -s`` would need a configured
signing key, and the point is to exercise the parser against every shape
including ones no local key could produce.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator, cast

import pytest
import yaml

from tools.check_release_tag import (
    DESCRIPTION,
    SIGNATURE_DELIMITERS,
    SIGNATURE_HEADERS,
    branch_ref,
    check,
    is_signed,
    load_trusted_branches,
    main,
)

PGP_BLOCK = "-----BEGIN PGP SIGNATURE-----\nnot-a-real-signature\n-----END PGP SIGNATURE-----"
SSH_BLOCK = "-----BEGIN SSH SIGNATURE-----\nnot-a-real-signature\n-----END SSH SIGNATURE-----"
X509_BLOCK = "-----BEGIN SIGNED MESSAGE-----\nnot-a-real-signature\n-----END SIGNED MESSAGE-----"


def _env(repo: Path) -> dict[str, str]:
    """Inherited environment with the identity pinned and config isolated.

    Inherited rather than replaced: a hand-built environment has to carry
    everything the platform needs to launch a process, and on Windows that is
    more than ``PATH`` — ``SystemRoot`` and ``COMSPEC`` among others. Pinning
    ``HOME``/``USERPROFILE``/``GIT_CONFIG_GLOBAL`` to the throwaway repository
    is what actually provides the isolation these tests want: the developer's
    ``~/.gitconfig`` (a signing key, a ``commit.gpgsign``, a template dir)
    must not reach a fixture whose whole subject is signature presence.
    """
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "Gate Test",
            "GIT_AUTHOR_EMAIL": "gate@example.invalid",
            "GIT_COMMITTER_NAME": "Gate Test",
            "GIT_COMMITTER_EMAIL": "gate@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-01T00:00:00+0000",
            "GIT_COMMITTER_DATE": "2026-08-01T00:00:00+0000",
            "HOME": str(repo),
            "USERPROFILE": str(repo),
            "GIT_CONFIG_GLOBAL": str(repo / "gitconfig-absent"),
            "GIT_CONFIG_SYSTEM": str(repo / "gitconfig-absent"),
        }
    )
    return env


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env=_env(repo),
    )
    return result.stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A repository with exactly one commit and no tags."""
    _git(tmp_path, "init", "-q", "-b", "main", str(tmp_path))
    (tmp_path / "file.txt").write_text("content\n")
    _git(tmp_path, "add", "file.txt")
    _git(tmp_path, "commit", "-q", "-m", "initial")
    return tmp_path


def _write_tag_object(repo: Path, name: str, signature: str | None) -> None:
    """Create an annotated tag object, optionally with a signature block."""
    target = _git(repo, "rev-parse", "HEAD")
    body = (
        f"object {target}\n"
        f"type commit\n"
        f"tag {name}\n"
        f"tagger Gate Test <gate@example.invalid> 1785542400 +0000\n"
        f"\n"
        f"ama-cryptography {name}\n"
    )
    if signature is not None:
        body += signature + "\n"
    # BYTES, not text. With `text=True` Python wraps stdin in a TextIOWrapper
    # whose default newline translation rewrites every "\n" to "\r\n" on
    # Windows, so git receives `object <sha>\r` and rejects the object with
    # `badObjectSha1: invalid 'object' line format`. A git object's bytes are
    # a wire format, not platform text; encoding here keeps them that way, and
    # this is why the module tolerates no newline translation anywhere on the
    # write path.
    result = subprocess.run(
        ["git", "hash-object", "-t", "tag", "-w", "--stdin"],
        cwd=repo,
        input=body.encode("utf-8"),
        capture_output=True,
        check=True,
        env=_env(repo),
    )
    _git(repo, "update-ref", f"refs/tags/{name}", result.stdout.decode("ascii").strip())


class TestTheShapesThatMustFail:
    """Each of these is a shape this repository has actually shipped."""

    def test_a_missing_tag_fails(self, repo: Path) -> None:
        problems = check("v4.0.0", repo)
        assert problems
        assert "does not resolve" in problems[0]

    def test_a_lightweight_tag_fails(self, repo: Path) -> None:
        """Six of this repository's eleven historical tags are this shape."""
        _git(repo, "tag", "v4.0.0")
        problems = check("v4.0.0", repo)
        assert problems
        assert "lightweight" in problems[0]

    def test_the_lightweight_message_warns_about_the_checkout_trap(self, repo: Path) -> None:
        """A false red on a release gate is how release gates get disabled.

        ``actions/checkout`` writes a lightweight local ref for an annotated
        tag, so this exact failure can be reported for a correctly signed tag.
        The message has to say so or the operator's first move is to distrust
        the gate rather than the fetch.
        """
        _git(repo, "tag", "v4.0.0")
        assert "actions/checkout" in check("v4.0.0", repo)[0]

    def test_an_unsigned_annotated_tag_fails(self, repo: Path) -> None:
        """The shape of the five annotated tags this repository has shipped."""
        _write_tag_object(repo, "v4.0.0", signature=None)
        problems = check("v4.0.0", repo)
        assert problems
        assert "no signature block" in problems[0]

    def test_a_branch_of_the_same_name_does_not_satisfy_the_gate(self, repo: Path) -> None:
        """The ref is looked up under ``refs/tags/``, not by bare name.

        A bare name would resolve a same-named branch under git's
        disambiguation rules, and a release must not proceed from one.
        """
        _git(repo, "branch", "v4.0.0")
        problems = check("v4.0.0", repo)
        assert problems
        assert "does not resolve" in problems[0]


class TestTheShapeThatMustPass:
    @pytest.mark.parametrize(
        "signature", [PGP_BLOCK, SSH_BLOCK, X509_BLOCK], ids=["pgp", "ssh", "x509"]
    )
    def test_every_signature_format_git_emits_is_accepted(self, repo: Path, signature: str) -> None:
        """Accepting only one format would push maintainers to the unsigned path."""
        _write_tag_object(repo, "v4.0.0", signature=signature)
        assert check("v4.0.0", repo) == []

    def test_the_exit_code_follows_the_verdict(self, repo: Path) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        assert main(["v4.0.0", "--repo", str(repo)]) == 0
        _write_tag_object(repo, "v3.9.9", signature=None)
        assert main(["v3.9.9", "--repo", str(repo)]) == 1


class TestTheToolDoesNotOverclaim:
    """INVARIANT-37: the output must not describe a check that did not run."""

    def test_a_real_signature_is_not_required(self, repo: Path) -> None:
        """Stated as a test so a future reader cannot mistake PASS for verified.

        The fixture signature above is the literal text
        ``not-a-real-signature``. It passes. That is correct behaviour for a
        shape check and would be a serious defect in a verifier, which is why
        the tool never calls itself one.
        """
        _write_tag_object(repo, "v4.0.0", signature=PGP_BLOCK)
        assert check("v4.0.0", repo) == []

    def test_both_verdicts_say_the_signature_was_not_verified(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        main(["v4.0.0", "--repo", str(repo)])
        assert "NOT verified" in capsys.readouterr().out

        _git(repo, "tag", "v3.9.9")
        main(["v3.9.9", "--repo", str(repo)])
        assert "does not verify the signature" in capsys.readouterr().out.replace(
            "\n", " "
        ).replace("  ", " ")


class TestTheFixtureItselfIsPortable:
    """The fixture writes a git object; git objects are bytes, not text.

    The first version of this module passed ``input=`` as ``str`` with
    ``text=True``. On Linux and macOS that is a no-op; on Windows Python wraps
    stdin in a ``TextIOWrapper`` that rewrites every ``\\n`` to ``\\r\\n``, so
    git received ``object <sha>\\r`` and refused the object with
    ``badObjectSha1: invalid 'object' line format``. Seven tests failed on
    every Windows lane and none anywhere else.

    This is the control for that: a stray carriage return anywhere in the
    written object fails here on *all* platforms, rather than only on the one
    that translates newlines.
    """

    def test_the_written_tag_object_contains_no_carriage_returns(self, repo: Path) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        raw = subprocess.run(
            ["git", "cat-file", "tag", "refs/tags/v4.0.0"],
            cwd=repo,
            capture_output=True,
            check=True,
            env=_env(repo),
        ).stdout
        assert b"\r" not in raw
        assert raw.startswith(b"object ")
        assert SSH_BLOCK.encode() in raw


class TestTheSignatureScanner:
    def test_it_matches_nothing_in_an_ordinary_message(self) -> None:
        assert not is_signed("object abc\ntype commit\n\nama-cryptography 4.0.0\n")

    @pytest.mark.parametrize(("begin", "end"), SIGNATURE_DELIMITERS, ids=["pgp", "ssh", "x509"])
    def test_every_declared_format_is_actually_recognised(self, begin: str, end: str) -> None:
        """The constant and the predicate cannot drift apart."""
        assert is_signed(f"tagger x\n\nmessage\n{begin}\nbody\n{end}\n")

    def test_the_header_tuple_stays_in_step_with_the_pairs(self) -> None:
        assert SIGNATURE_HEADERS == tuple(b for b, _ in SIGNATURE_DELIMITERS)


class TestASignatureBlockIsAPairNotAMarker:
    """Raised in review: a substring test on BEGIN is not a gate.

    A tag message is free text. Under the original one-sided test, an
    *unsigned* annotated tag whose message quoted a BEGIN marker — a changelog
    line about signing, a pasted error, this repository's own documentation —
    satisfied the gate while carrying no signature. Fail-open, in the one
    place the whole module exists to fail closed.

    These are the controls for the tightened predicate. Each case is a body
    that a substring test accepts and a matched-pair test must reject.
    """

    @pytest.mark.parametrize("begin", SIGNATURE_HEADERS)
    def test_a_begin_marker_with_no_end_is_refused(self, begin: str) -> None:
        assert not is_signed(f"tagger x\n\nrelease notes\n{begin}\n")

    def test_an_end_marker_with_no_begin_is_refused(self) -> None:
        assert not is_signed("tagger x\n\nnotes\n-----END PGP SIGNATURE-----\n")

    def test_the_end_must_follow_the_begin_not_precede_it(self) -> None:
        assert not is_signed(
            "tagger x\n\n-----END SSH SIGNATURE-----\n-----BEGIN SSH SIGNATURE-----\n"
        )

    def test_mismatched_formats_do_not_pair_with_each_other(self) -> None:
        """A PGP opening and an SSH closing is not a block in either format."""
        assert not is_signed(
            "tagger x\n\n-----BEGIN PGP SIGNATURE-----\nz\n-----END SSH SIGNATURE-----\n"
        )

    def test_a_marker_quoted_inline_is_prose_not_structure(self) -> None:
        """Armour delimiters occupy a line of their own in every format."""
        assert not is_signed(
            "tagger x\n\nsee the -----BEGIN PGP SIGNATURE----- block below\n"
            "and its -----END PGP SIGNATURE----- terminator\n"
        )

    def test_a_realistic_release_message_about_signing_is_refused(self) -> None:
        """The concrete shape the reviewer described, end to end."""
        body = (
            "object " + "0" * 40 + "\ntype commit\ntag v4.0.0\n"
            "tagger Gate Test <gate@example.invalid> 1785542400 +0000\n\n"
            "ama-cryptography 4.0.0\n\n"
            "Release tags must now carry a -----BEGIN SSH SIGNATURE----- block;\n"
            "see tools/check_release_tag.py.\n"
        )
        assert not is_signed(body)

    def test_a_genuine_block_still_passes_beside_all_of_that(self) -> None:
        """Non-vacuity: the refusals above are about pairing, not about text."""
        assert is_signed(f"tagger x\n\nnotes\n{SSH_BLOCK}\n")


class TestTheGateIsWiredIntoTheReleasePipeline:
    """A check nothing runs is not a gate (INVARIANT-2).

    ``release.yml`` is exempt from ``check_gate_coverage.py`` — it never
    triggers on ``pull_request``, so branch protection cannot require any
    context it produces — which means nothing else in the repository would
    notice if this step were dropped.
    """

    def test_release_yml_invokes_the_checker(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        assert "tools/check_release_tag.py" in workflow

    def test_release_yml_force_fetches_the_tag_ref_first(self) -> None:
        """Without this the gate reports lightweight for every annotated tag."""
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        # rindex, not index: the first mention is in the operator runbook
        # comment at the top of the file. The step that actually runs it is
        # the last one, and the fetch has to precede *that*.
        invocation = workflow.rindex("tools/check_release_tag.py")
        preceding = workflow[:invocation]
        assert "refs/tags/${TAG}:refs/tags/${TAG}" in preceding
        assert "--force" in preceding[preceding.index("git fetch") :]


class TestAQueuedTagReleaseIsNeverCancelled:
    """A pushed tag's release waits its turn; a newer run does not drop it.

    The concurrency block carried ``cancel-in-progress: false`` and a comment
    saying "the second tag must wait".  That setting protects only the RUNNING
    release.  Under GitHub's default ``queue: single`` a concurrency group holds
    at most one PENDING run, and queuing another cancels the pending one.  With
    release A building and tag B pending, a third tag push or a
    workflow_dispatch dry run (same static group) cancelled B before it
    started: a pushed tag with no release and no artefacts.  ``queue: max``
    keeps the pending runs, first in first out.

    release.yml never runs on pull_request, so no PR check would notice any of
    these three settings being dropped; this pins them in the file.
    """

    @pytest.fixture(scope="class")
    def concurrency(self) -> dict[str, Any]:
        text = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        block = cast("dict[str, Any]", yaml.safe_load(text)).get("concurrency")
        assert isinstance(block, dict), "release.yml must declare a concurrency block"
        return cast("dict[str, Any]", block)

    def test_the_group_is_static(self, concurrency: dict[str, Any]) -> None:
        """One group for every run, so two different tags never publish at once."""
        assert concurrency.get("group") == "release"

    def test_a_running_release_is_not_cancelled(self, concurrency: dict[str, Any]) -> None:
        assert concurrency.get("cancel-in-progress") is False

    def test_pending_runs_queue_instead_of_replacing_each_other(
        self, concurrency: dict[str, Any]
    ) -> None:
        assert concurrency.get("queue") == "max", (
            "without `queue: max` the group keeps one pending run and cancels it "
            "when another is queued, so a tag pushed while a release is building "
            "is dropped by the next tag push or dry run"
        )


class TestTheUnanchoredReleaseGuardIsWired:
    """A canonical-repo tag must not publish an unanchored release (audit H3).

    release.yml never runs on pull_request, so nothing in PR CI would notice if
    this guard were dropped -- these tests pin its shape in the file itself.
    """

    @pytest.fixture(scope="class")
    def release(self) -> dict[str, Any]:
        text = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        return cast("dict[str, Any]", yaml.safe_load(text))

    def _preflight_guard_step(self, release: dict[str, Any]) -> dict[str, Any]:
        steps = release["jobs"]["preflight"]["steps"]
        matches = [s for s in steps if "unanchored release" in str(s.get("name", "")).lower()]
        assert len(matches) == 1, "expected exactly one preflight anchoring guard step"
        return cast("dict[str, Any]", matches[0])

    def test_the_guard_runs_on_every_version_tag_push(self, release: dict[str, Any]) -> None:
        # It must NOT be gated on the anchor variable — a guard that only runs
        # when already anchored is the vacuous shape this whole finding is about.
        condition = str(self._preflight_guard_step(release)["if"])
        assert "github.event_name == 'push'" in condition
        assert "startsWith(github.ref, 'refs/tags/v')" in condition
        assert "AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX" not in condition

    def test_the_guard_refuses_the_canonical_repo_without_an_anchor(
        self, release: dict[str, Any]
    ) -> None:
        step = self._preflight_guard_step(release)
        env = step.get("env", {})
        assert env.get("CANONICAL_REPO"), "the guard must name the canonical repository"
        assert "AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX" in str(env.get("ANCHOR_PUBKEY", ""))
        run = step["run"]
        # Fails closed on the canonical repo, and only there.
        assert "exit 1" in run
        assert "GITHUB_REPOSITORY" in run and "CANONICAL_REPO" in run

    def test_the_release_notes_state_the_anchoring_status(self, release: dict[str, Any]) -> None:
        steps = release["jobs"]["github-release"]["steps"]
        anchor_line = [s for s in steps if s.get("id") == "anchor_line"]
        assert len(anchor_line) == 1, "the release job must compute an anchoring notes line"
        body = next(
            s["with"]["body"]
            for s in steps
            if isinstance(s.get("with"), dict) and "body" in s["with"]
        )
        assert "steps.anchor_line.outputs.line" in body


class TestTheHelpOutputIsUsable:
    """``--help`` printed a usage line and no description at all.

    The parser was built with ``description=__doc__.split("\\n")[3]``, and
    index 3 of the module docstring is the blank line under the title
    underline. Every ``--help`` invocation since the tool was written printed
    the usage block, two option rows, and nothing that said what the tool
    checks or when it fails — while the docstring it was slicing runs to
    eighty lines of exactly that.

    Slicing a docstring by line number is the wrong construction regardless of
    the index: reflowing the header silently changes which line is picked, and
    nothing in the tool would report it. ``DESCRIPTION`` and ``EPILOG`` are
    named constants for that reason, and these tests assert they reach the
    rendered output rather than merely existing.
    """

    @staticmethod
    def _help_text() -> str:
        result = subprocess.run(
            [sys.executable, "tools/check_release_tag.py", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    def test_the_description_is_not_empty(self) -> None:
        assert DESCRIPTION.strip(), "the --help description is blank"

    def test_the_description_is_rendered(self) -> None:
        text = self._help_text()
        # argparse re-wraps the description, so compare on words rather than
        # on the string: a line-wrap must not be able to fail this test, and a
        # missing description must not be able to pass it.
        for word in ("annotated", "signed", "INVARIANT-10"):
            assert word in text, f"{word!r} missing from --help output"

    def test_the_epilog_carries_the_verdicts_and_the_ci_trap(self) -> None:
        text = self._help_text()
        assert "refs/tags/" in text
        assert "exit status" in text
        assert "git fetch --force origin refs/tags/<tag>:refs/tags/<tag>" in text

    def test_the_epilog_states_that_signatures_are_not_verified(self) -> None:
        """INVARIANT-37: the boundary is published, including in ``--help``.

        A reader who only ever sees ``--help`` must not come away thinking a
        PASS from this tool is a cryptographic result.
        """
        text = self._help_text()
        assert "NOT checked" in text
        assert "not verified" in text

    def test_the_description_is_not_sliced_out_of_the_docstring(self) -> None:
        """The construction, not just its current output.

        A future edit that reintroduced ``__doc__.split(...)`` would render
        correctly for exactly as long as the header stayed the same length,
        and would then go quiet.  Asserted over the parsed syntax tree rather
        than over the file's text, so the module's own comment *about* the old
        construction cannot trip it — a text search here would fail on the
        explanation of the very defect it is checking for.
        """
        tree = ast.parse(Path("tools/check_release_tag.py").read_text(encoding="utf-8"))
        parsers = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "ArgumentParser"
        ]
        assert len(parsers) == 1, f"expected one ArgumentParser, found {len(parsers)}"
        described = {
            keyword.arg: keyword.value
            for keyword in parsers[0].keywords
            if keyword.arg in {"description", "epilog"}
        }
        assert set(described) == {"description", "epilog"}
        for name, value in described.items():
            assert isinstance(value, ast.Name), (
                f"{name}= is a {type(value).__name__}, not a named constant; "
                "computing it from __doc__ is what rendered an empty --help"
            )


def _string_values(node: Any) -> Iterator[str]:
    """Every string VALUE anywhere in a parsed document (keys are not values)."""
    if isinstance(node, dict):
        for value in node.values():
            yield from _string_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _string_values(item)
    elif isinstance(node, str):
        yield node


def _release() -> dict[str, Any]:
    text = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    return cast("dict[str, Any]", yaml.safe_load(text))


def _cibuildwheel_steps(release: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        cast("dict[str, Any]", step)
        for job in release["jobs"].values()
        for step in job.get("steps") or []
        if isinstance(step, dict) and "cibuildwheel" in str(step.get("uses", ""))
    ]


class TestTheSigningSeedIsWithheldOutsideTagPushes:
    """The release signing seed reaches a run only when that run is a `v*` tag push.

    release.yml placed ``secrets.AMA_INTEGRITY_SIGNING_SEED_HEX`` in the
    environment of build-wheels and verify-reproducible-wheel, and forwarded it
    to verify-anchor, on EVERY trigger — so a workflow_dispatch dry run of an
    arbitrary branch ran that branch's setup.py, _build_sign.py and
    resign_wheel.py with the release signing key in its environment.  Every
    reference is now the guarded expression
    ``github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') &&
    secrets.X || ''``, and the anchor variable and the REQUIRE flag carry the
    same guard so a dispatch is an honest unanchored build rather than a
    fail-closed one.  release.yml never runs on pull_request, so nothing in PR
    CI would notice a guard being dropped; this pins every one of them.
    """

    GUARD = ("github.event_name == 'push'", "startsWith(github.ref, 'refs/tags/v')", "|| ''")

    @pytest.fixture(scope="class")
    def release(self) -> dict[str, Any]:
        return _release()

    def test_every_reference_to_the_secret_is_guarded_on_a_version_tag_push(
        self, release: dict[str, Any]
    ) -> None:
        references = [
            value
            for value in _string_values(release)
            if "AMA_INTEGRITY_SIGNING_SEED_HEX" in value and "secrets." in value
        ]
        # Non-vacuity: build-wheels' env, verify-reproducible-wheel's env and
        # verify-anchor's secrets: forwarding.  A walk that found nothing would
        # otherwise pass the loop below vacuously.
        assert len(references) >= 3, references
        for value in references:
            for fragment in self.GUARD:
                assert fragment in value, f"unguarded seed reference: {value!r}"

    def test_verify_anchor_runs_only_on_a_version_tag_push(self, release: dict[str, Any]) -> None:
        """With the seed withheld from a dispatch, an unconditional verify-anchor
        would fail closed on "secret not set" and take build-wheels down with it."""
        condition = str(release["jobs"]["verify-anchor"]["if"])
        assert "github.event_name == 'push'" in condition
        assert "startsWith(github.ref, 'refs/tags/v')" in condition
        assert "vars.AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX != ''" in condition

    def test_the_anchor_and_the_require_flag_carry_the_same_guard(
        self, release: dict[str, Any]
    ) -> None:
        """Consistency: an anchor plus REQUIRE=1 with no seed makes the signer refuse."""
        steps = _cibuildwheel_steps(release)
        assert len(steps) == 2, "build-wheels and verify-reproducible-wheel"
        for step in steps:
            for name in (
                "AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX",
                "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR",
                "AMA_INTEGRITY_SIGNING_SEED_HEX",
            ):
                value = str(step["env"][name])
                for fragment in self.GUARD:
                    assert fragment in value, f"{name} is not guarded: {value!r}"

    def test_build_wheels_still_proceeds_past_a_skipped_anchor_check(
        self, release: dict[str, Any]
    ) -> None:
        """A dispatch skips verify-anchor; build-wheels must read that as permission."""
        condition = str(release["jobs"]["build-wheels"]["if"])
        assert "needs['verify-anchor'].result != 'failure'" in condition
        assert "!cancelled()" in condition


def _commit(repo: Path, name: str) -> str:
    (repo / name).write_text(name + "\n", encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", name)
    return _git(repo, "rev-parse", "HEAD")


def _trust_config(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "release-trust.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _track_main_as_origin(repo: Path) -> None:
    """The ref release.yml has after `git fetch ... :refs/remotes/origin/main`."""
    _git(repo, "update-ref", "refs/remotes/origin/main", "refs/heads/main")


class TestTheTagMustDescendFromATrustedBranch:
    """Check 4: the tag's commit is reachable from a trusted branch.

    Checks 1-3 are about the tag object; a signed, annotated tag on a side
    branch passes all three.  These fixtures build that tag and each shape of
    a broken trust configuration, and assert the verdict on every one.
    """

    def test_a_signed_tag_on_the_trusted_branch_passes(self, repo: Path, tmp_path: Path) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _track_main_as_origin(repo)
        config = _trust_config(tmp_path, {"trusted_branches": ["main"]})
        assert check("v4.0.0", repo, config) == []

    def test_a_tag_on_an_older_trusted_commit_passes(self, repo: Path, tmp_path: Path) -> None:
        """Reachable, not equal: main has moved on since the tagged commit."""
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _commit(repo, "later.txt")
        _track_main_as_origin(repo)
        config = _trust_config(tmp_path, {"trusted_branches": ["main"]})
        assert check("v4.0.0", repo, config) == []

    def test_a_tag_on_a_side_branch_fails_and_names_the_branch(
        self, repo: Path, tmp_path: Path
    ) -> None:
        _track_main_as_origin(repo)
        _git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "side.txt")
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _git(repo, "checkout", "-q", "main")
        config = _trust_config(tmp_path, {"trusted_branches": ["main"]})
        problems = check("v4.0.0", repo, config)
        assert len(problems) == 1, problems
        assert "not reachable from any trusted branch" in problems[0]
        assert "refs/remotes/origin/main" in problems[0]

    def test_the_local_branch_form_is_selected_by_an_empty_prefix(
        self, repo: Path, tmp_path: Path
    ) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        config = _trust_config(tmp_path, {"trusted_branches": ["main"]})
        # No remote-tracking ref exists in this fixture: the default prefix
        # cannot resolve, the empty one resolves refs/heads/main.
        assert "does not resolve" in check("v4.0.0", repo, config)[0]
        assert check("v4.0.0", repo, config, branch_prefix="") == []

    def test_a_missing_config_fails(self, repo: Path, tmp_path: Path) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _track_main_as_origin(repo)
        problems = check("v4.0.0", repo, tmp_path / "absent.json")
        assert len(problems) == 1, problems
        assert "cannot be read" in problems[0]
        assert "a failure, not a pass" in problems[0]

    @pytest.mark.parametrize(
        "document",
        [
            {},
            {"trusted_branches": []},
            {"trusted_branches": "main"},
            {"trusted_branches": [""]},
            {"trusted_branches": [42]},
            ["main"],
        ],
        ids=["no-key", "empty-list", "string", "blank-name", "non-string", "not-an-object"],
    )
    def test_an_invalid_config_fails(self, repo: Path, tmp_path: Path, document: object) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _track_main_as_origin(repo)
        problems = check("v4.0.0", repo, _trust_config(tmp_path, document))
        assert len(problems) == 1, problems
        assert 'non-empty "trusted_branches" list' in problems[0]

    def test_a_config_that_is_not_json_fails(self, repo: Path, tmp_path: Path) -> None:
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _track_main_as_origin(repo)
        path = tmp_path / "release-trust.json"
        path.write_text("trusted_branches: [main]\n", encoding="utf-8")
        problems = check("v4.0.0", repo, path)
        assert len(problems) == 1, problems
        assert "not valid JSON" in problems[0]

    def test_an_unresolvable_trusted_branch_fails(self, repo: Path, tmp_path: Path) -> None:
        """A branch that is not there is not trusted; it is a misconfiguration."""
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _track_main_as_origin(repo)
        config = _trust_config(tmp_path, {"trusted_branches": ["main", "release"]})
        problems = check("v4.0.0", repo, config)
        assert len(problems) == 1, problems
        assert "trusted branch `refs/remotes/origin/release` does not resolve" in problems[0]

    def test_any_trusted_branch_suffices(self, repo: Path, tmp_path: Path) -> None:
        _track_main_as_origin(repo)
        _git(repo, "checkout", "-q", "-b", "release")
        _commit(repo, "release.txt")
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _git(repo, "update-ref", "refs/remotes/origin/release", "refs/heads/release")
        _git(repo, "checkout", "-q", "main")
        config = _trust_config(tmp_path, {"trusted_branches": ["main", "release"]})
        assert check("v4.0.0", repo, config) == []

    def test_a_tag_named_like_the_branch_cannot_shadow_it(self, repo: Path, tmp_path: Path) -> None:
        """The branch is resolved by full ref name, so refs/tags/origin/main is inert.

        Under git's short-name lookup a tag called ``origin/main`` resolves
        before the remote-tracking branch, which would let the tagger decide
        what "trusted" points at by pushing one more tag.
        """
        _track_main_as_origin(repo)
        _git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "side.txt")
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        _git(repo, "tag", "origin/main")  # a lightweight tag at the side commit
        _git(repo, "checkout", "-q", "main")
        assert _git(repo, "rev-parse", "origin/main") == _git(repo, "rev-parse", "refs/heads/side")
        config = _trust_config(tmp_path, {"trusted_branches": ["main"]})
        problems = check("v4.0.0", repo, config)
        assert len(problems) == 1, problems
        assert "not reachable" in problems[0]

    def test_shape_failures_are_reported_before_provenance(
        self, repo: Path, tmp_path: Path
    ) -> None:
        """A lightweight tag on a side branch reports the lightweight defect only."""
        _track_main_as_origin(repo)
        _git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "side.txt")
        _git(repo, "tag", "v4.0.0")
        _git(repo, "checkout", "-q", "main")
        problems = check("v4.0.0", repo, _trust_config(tmp_path, {"trusted_branches": ["main"]}))
        assert len(problems) == 1
        assert "lightweight" in problems[0]

    def test_the_exit_code_and_verdict_follow_provenance(
        self, repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _track_main_as_origin(repo)
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        config = _trust_config(tmp_path, {"trusted_branches": ["main"]})
        assert main(["v4.0.0", "--repo", str(repo), "--trust-config", str(config)]) == 0
        assert "reachable from a trusted branch" in capsys.readouterr().out
        _git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "side.txt")
        _write_tag_object(repo, "v3.9.9", signature=SSH_BLOCK)
        _git(repo, "checkout", "-q", "main")
        assert main(["v3.9.9", "--repo", str(repo), "--trust-config", str(config)]) == 1
        assert "not reachable" in capsys.readouterr().out

    def test_without_a_config_the_verdict_says_provenance_was_not_checked(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """INVARIANT-37: a PASS that skipped check 4 must say so."""
        _write_tag_object(repo, "v4.0.0", signature=SSH_BLOCK)
        assert main(["v4.0.0", "--repo", str(repo)]) == 0
        assert "Provenance NOT checked" in capsys.readouterr().out

    def test_the_branch_ref_forms(self) -> None:
        assert branch_ref("main", "origin/") == "refs/remotes/origin/main"
        assert branch_ref("main", "") == "refs/heads/main"
        assert branch_ref("main", "refs/heads/") == "refs/heads/main"

    def test_the_loader_never_returns_an_empty_list_without_a_problem(self, tmp_path: Path) -> None:
        """An empty list and no problem would read as "nothing to check" upstream."""
        empties: tuple[dict[str, Any], ...] = ({}, {"trusted_branches": []})
        for document in empties:
            branches, problems = load_trusted_branches(_trust_config(tmp_path, document))
            assert branches == [] and problems
        branches, problems = load_trusted_branches(
            _trust_config(tmp_path, {"trusted_branches": [" main "]})
        )
        assert branches == ["main"] and problems == []


class TestTheProvenanceGateIsWired:
    """release.yml runs check 4 with a configuration read from the trusted branch.

    release.yml never runs on pull_request, so nothing in PR CI would notice
    the step being dropped, the config being read from the checkout, or the
    checkout going back to depth 1 (under which `merge-base --is-ancestor`
    cannot answer).
    """

    @pytest.fixture(scope="class")
    def release(self) -> dict[str, Any]:
        return _release()

    def _provenance_step(self, release: dict[str, Any]) -> dict[str, Any]:
        steps = release["jobs"]["preflight"]["steps"]
        matches = [s for s in steps if "release provenance" in str(s.get("name", "")).lower()]
        assert len(matches) == 1, "expected exactly one preflight provenance step"
        return cast("dict[str, Any]", matches[0])

    def test_the_trust_config_is_read_from_origin_main_not_the_checkout(
        self, release: dict[str, Any]
    ) -> None:
        run = str(self._provenance_step(release)["run"])
        assert "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main" in run
        assert (
            'git show origin/main:.github/release-trust.json > "$RUNNER_TEMP/release-trust.json"'
            in run
        )
        assert (
            'python tools/check_release_tag.py "${TAG}" '
            '--trust-config "$RUNNER_TEMP/release-trust.json"'
        ) in run
        # The checkout's own copy must never be what the checker reads.
        assert "--trust-config .github/" not in run

    def test_the_step_runs_on_version_tag_pushes_only(self, release: dict[str, Any]) -> None:
        condition = str(self._provenance_step(release)["if"])
        assert "github.event_name == 'push'" in condition
        assert "startsWith(github.ref, 'refs/tags/v')" in condition

    def test_the_step_follows_the_signature_verification(self, release: dict[str, Any]) -> None:
        names = [str(step.get("name", "")) for step in release["jobs"]["preflight"]["steps"]]
        signature = next(i for i, name in enumerate(names) if "annotated, signed tag" in name)
        provenance = next(i for i, name in enumerate(names) if "release provenance" in name.lower())
        assert provenance == signature + 1

    def test_preflight_checks_out_full_history(self, release: dict[str, Any]) -> None:
        checkouts = [
            step
            for step in release["jobs"]["preflight"]["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        assert len(checkouts) == 1
        assert checkouts[0].get("with", {}).get("fetch-depth") == 0

    def test_the_committed_trust_config_names_main_only(self) -> None:
        branches, problems = load_trusted_branches(Path(".github/release-trust.json"))
        assert problems == []
        assert branches == ["main"]
