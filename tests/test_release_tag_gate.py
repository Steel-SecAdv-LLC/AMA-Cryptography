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

import subprocess
from pathlib import Path

import pytest

from tools.check_release_tag import SIGNATURE_HEADERS, check, is_signed, main

PGP_BLOCK = "-----BEGIN PGP SIGNATURE-----\nnot-a-real-signature\n-----END PGP SIGNATURE-----"
SSH_BLOCK = "-----BEGIN SSH SIGNATURE-----\nnot-a-real-signature\n-----END SSH SIGNATURE-----"
X509_BLOCK = "-----BEGIN SIGNED MESSAGE-----\nnot-a-real-signature\n-----END SIGNED MESSAGE-----"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env={
            "GIT_AUTHOR_NAME": "Gate Test",
            "GIT_AUTHOR_EMAIL": "gate@example.invalid",
            "GIT_COMMITTER_NAME": "Gate Test",
            "GIT_COMMITTER_EMAIL": "gate@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-01T00:00:00+0000",
            "GIT_COMMITTER_DATE": "2026-08-01T00:00:00+0000",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(repo),
        },
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
    result = subprocess.run(
        ["git", "hash-object", "-t", "tag", "-w", "--stdin"],
        cwd=repo,
        input=body,
        capture_output=True,
        text=True,
        check=True,
    )
    _git(repo, "update-ref", f"refs/tags/{name}", result.stdout.strip())


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


class TestTheSignatureScanner:
    def test_it_matches_nothing_in_an_ordinary_message(self) -> None:
        assert not is_signed("object abc\ntype commit\n\nama-cryptography 4.0.0\n")

    @pytest.mark.parametrize("header", SIGNATURE_HEADERS)
    def test_every_declared_header_is_actually_recognised(self, header: str) -> None:
        """The constant and the predicate cannot drift apart."""
        assert is_signed(f"tagger x\n\nmessage\n{header}\nbody\n")


class TestTheGateIsWiredIntoTheReleasePipeline:
    """A check nothing runs is not a gate (INVARIANT-2).

    ``release.yml`` is exempt from ``check_gate_coverage.py`` — it never
    triggers on ``pull_request``, so branch protection cannot require any
    context it produces — which means nothing else in the repository would
    notice if this step were dropped.
    """

    def test_release_yml_invokes_the_checker(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text()
        assert "tools/check_release_tag.py" in workflow

    def test_release_yml_force_fetches_the_tag_ref_first(self) -> None:
        """Without this the gate reports lightweight for every annotated tag."""
        workflow = Path(".github/workflows/release.yml").read_text()
        # rindex, not index: the first mention is in the operator runbook
        # comment at the top of the file. The step that actually runs it is
        # the last one, and the fetch has to precede *that*.
        invocation = workflow.rindex("tools/check_release_tag.py")
        preceding = workflow[:invocation]
        assert "refs/tags/${TAG}:refs/tags/${TAG}" in preceding
        assert "--force" in preceding[preceding.index("git fetch") :]
