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
its docstring states it verifies shape, not cryptography, because verification
needs a trust store the repository does not ship. A fixture that had to carry a
genuine signature would need a private key in the test suite, which
INVARIANT-17 forbids outright. The line these tests draw is the line the tool
draws — and the ``test_a_real_signature_is_not_required`` case says so out loud
so nobody later reads a PASS here as a cryptographic result.

Tag objects are written with ``git hash-object -t tag`` rather than
``git tag -s`` for the same reason: ``git tag -s`` would need a configured
signing key, and the point is to exercise the parser against every shape
including ones no local key could produce.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from tools.check_release_tag import (
    DESCRIPTION,
    SIGNATURE_DELIMITERS,
    SIGNATURE_HEADERS,
    check,
    is_signed,
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
