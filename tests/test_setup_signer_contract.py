# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``setup.py``'s integrity signer must not damage the tree or inherit strictness.

Signing became unconditional in this release — every build produces a signed
artefact, not only ``AMA_BUILD_PIPELINE=1`` ones.  That made two properties of
``CMakeBuild._run_integrity_signer`` load-bearing that had not been before, and
neither held.

**It deleted a tracked file.**  The method unlinked
``ama_cryptography/_integrity_signature.py`` before spawning the signer, so any
signer failure left the developer's checkout with a tracked file gone — a state
``git checkout`` is the only recovery from, and which the ``RuntimeError`` did
not mention.  Measured on this tree with the deletion form restored::

    AMA_FIPS_STRICT=1 python3 -m pip install . --no-cache-dir --force-reinstall
    -> exit 1, RuntimeError: FATAL: integrity signer failed (exit 1)
    git status --short ama_cryptography/_integrity_signature.py
    ->  D ama_cryptography/_integrity_signature.py

**And the deletion is what made the signer fail under a strict environment.**
The signer child imports ``ama_cryptography`` before ``_build_sign`` runs a
line.  With the artefact gone, POST records the integrity stage at
``digest-only`` strength — a SKIP, not a failure.  ``AMA_FIPS_STRICT=1``
escalates that SKIP to a hard failure and
``AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR=1`` fails the stage outright on an
unanchored build.  ``__init__``'s signer carve-out cannot cover either: it keys
on ``_all_failures_repairable``, and a SKIP produces no failed row at all.  So
an operator who exports either variable in their shell — the documented way to
run a strict build — could not ``pip install .``.

After both fixes, on the same tree::

    AMA_FIPS_STRICT=1 python3 -m pip install . --no-cache-dir --force-reinstall
    -> exit 0
    (signer forced to fail with an unknown flag)
    -> exit 1, "... The tree's previous artefact has been restored."
       artefact present: YES, byte-identical to before, no leftover .pre-sign

These tests are structural because the behavioural measurement above costs a
full CMake build and a wheel; they assert the exact code properties that
measurement established, so a revert of either fix fails here in milliseconds.

**The artefact is no longer tracked** (correction, AGENTS.md section 6.6).  The
account above was written while ``_integrity_signature.py`` was committed, and
committing it was itself the defect: AGENTS.md section 8.4 forbids committing a
locally built artefact, yet the Sphinx lane — which imports an unbuilt checkout
under ``AMA_SPHINX_BUILD=1`` — compared the committed artefact's
``INTEGRITY_DIGEST_HEX`` with the tree and refused the import as tampering
whenever a ``.py`` change left it stale, so every package edit had to commit a
fresh ephemeral key and one machine's native and binding digests.  The file is
now a build output: ``.gitignore`` lists it, ``MANIFEST.in`` keeps it out of the
sdist, and ``TestTheArtefactIsABuildOutput`` below fails if either stops being
true.  The move-aside still matters, for the previous build's artefact rather
than a tracked one.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest
from setuptools.command.egg_info import FileList

REPO_ROOT = Path(__file__).resolve().parent.parent
SETUP_PY = REPO_ROOT / "setup.py"

#: The per-build signed artefact and setup.py's transient move-aside of it.
ARTEFACT_PATHS = (
    "ama_cryptography/_integrity_signature.py",
    "ama_cryptography/_integrity_signature.py.pre-sign",
)
#: The tracked source-drift check the CI test lanes compare against the tree.
DIGEST_PATH = "ama_cryptography/_integrity_digest.txt"

#: Both describe how the INSTALLED module must behave, not how the signer's own
#: import must, and both turn the signer's necessarily-artefact-less import into
#: a hard failure.
STRICTNESS_VARIABLES = ("AMA_FIPS_STRICT", "AMA_INTEGRITY_REQUIRE_TRUST_ANCHOR")


def _signer_source() -> str:
    """The source text of ``CMakeBuild._run_integrity_signer``."""
    tree = ast.parse(SETUP_PY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_run_integrity_signer":
            return ast.get_source_segment(SETUP_PY.read_text(encoding="utf-8"), node) or ""
    # `raise`, not `pytest.fail()`: both fail the test, but only this one is a
    # terminating statement to a reader that does not know pytest's NoReturn
    # annotation, so the function has one exit shape rather than an explicit
    # return beside an implicit fall-through None (CodeQL alert 646).
    raise AssertionError("setup.py no longer defines _run_integrity_signer")


def test_the_method_still_exists() -> None:
    """Non-vacuity: every assertion below reads this source."""
    source = _signer_source()
    assert "_build_sign" in source
    assert "_integrity_signature.py" in source


def test_the_tracked_artefact_is_moved_aside_not_deleted() -> None:
    source = _signer_source()
    assert ".rename(" in source, (
        "the pre-sign artefact is not renamed anywhere; a deletion leaves the "
        "developer's checkout without its previous build's artefact on any "
        "signer failure"
    )
    # The only unlink of the artefact path itself would be a deletion.  Unlinks
    # of the `.pre-sign` side file are the cleanup and are fine.
    for line in source.splitlines():
        stripped = line.strip()
        if ".unlink(" not in stripped or stripped.startswith("#"):
            continue
        assert (
            "pre-sign" in stripped or "_aside" in stripped
        ), f"setup.py unlinks something other than the moved-aside copy: {stripped!r}"


def test_a_signer_failure_restores_the_artefact() -> None:
    source = _signer_source()
    assert "_restore_stashed_artefacts" in source, "nothing restores the moved-aside artefact"
    # The restore must run on ANY exception, not only CalledProcessError: a
    # KeyboardInterrupt or an OSError from subprocess would otherwise leave the
    # tree damaged in exactly the way the rename was introduced to prevent.
    assert "except BaseException" in source, (
        "the restore is not on a BaseException handler, so an interrupt or an "
        "OSError from subprocess leaves the artefact moved aside"
    )
    assert (
        "has been restored" in source
    ), "the RuntimeError does not tell the operator the tree was repaired"


@pytest.mark.parametrize("variable", STRICTNESS_VARIABLES)
def test_the_signer_child_does_not_inherit_strictness(variable: str) -> None:
    source = _signer_source()
    assert variable in source, (
        f"{variable} is not scrubbed from the signer child's environment, so a "
        f"developer who exports it cannot `pip install .`"
    )
    assert "env.pop(" in source, "nothing removes anything from the child env"


def test_the_bind_extensions_comment_matches_the_repair_flow() -> None:
    """The comment on ``--bind-extensions`` described the opposite policy.

    It read "The repair flow (`integrity --update --sign`) deliberately omits
    this", which was true of the revision it was written for and was inverted
    when the repair flow started binding too.  It pointed the reader at a help
    text that by then said the opposite.
    """
    source = _signer_source()
    # The historical wording survives only inside the sentence that withdraws
    # it, so match the claim, not the phrase.
    claim = "The repair flow (`integrity --update --sign`) deliberately omits"
    assert claim not in source, "setup.py still claims the repair flow omits --bind-extensions"
    assert (
        "BOTH callers pass this" in source
    ), "setup.py does not state the policy the code actually has"
    repair = (
        Path(__file__).resolve().parent.parent / "ama_cryptography" / "integrity.py"
    ).read_text(encoding="utf-8")
    assert "--bind-extensions" in repair, (
        "the repair flow no longer passes --bind-extensions; setup.py's comment "
        "must be updated with it rather than left describing the old policy"
    )


@pytest.mark.parametrize("document", ["SECURITY.md", "ARCHITECTURE.md"])
def test_the_documents_do_not_carry_the_withdrawn_binding_claim(document: str) -> None:
    """The same stale claim outlived its correction in more than one document.

    ``setup.py``'s comment was fixed when the repair flow started binding, and
    the test above pins it.  SECURITY.md's "Two artefact states exist by design"
    paragraph was not, so the security document and the CHANGELOG's own 5.0.0
    entry ("every build signs and binds, including the repair flow") said
    opposite things about the same command.  A reader of SECURITY.md would
    conclude a locally re-signed tree binds nothing; measured, ``integrity
    --update --sign`` binds every extension present -- six on a built tree
    here, and zero only in a checkout that has none.

    Fixing SECURITY.md alone was not enough.  ARCHITECTURE.md's 5.0.0 release
    row carried the identical assertion compressed into one clause -- "wheel
    pipeline binds, repair flow binds none" -- which a SECURITY.md-only check
    could not see, so the repository still contradicted itself in the document
    a reader reaches first.  Both are checked here.
    """
    text = (Path(__file__).resolve().parent.parent / document).read_text(encoding="utf-8")
    # The historical wording survives only inside the sentence that withdraws
    # it, so match the assertion, not the phrase.
    for claim in (
        "--sign` — the artefact this repository commits) binds none",
        "A source tree's binding coverage is therefore not an\nattestation claim at all",
        # ARCHITECTURE.md's release row compressed the same assertion into one
        # clause, which a SECURITY.md-only check could not see.
        "repair flow binds none",
    ):
        assert claim not in text, (
            f"{document} still asserts {claim!r}. The repair flow passes "
            f"--bind-extensions (ama_cryptography/integrity.py), so it binds every "
            f"extension beside the artefact."
        )
    assert (
        "signing callers bind" in text
    ), f"{document} does not state the policy the code actually has"


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _require_git_work_tree() -> None:
    """Skip outside a git checkout (an sdist); fail under AMA_CI_REQUIRE_HISTORY.

    The ``requires_git_history`` marker on each caller is what turns this skip
    into a failure in the CI lanes that check out the repository, so the
    tracking guards below cannot go silent there.
    """
    try:
        probe = _git("rev-parse", "--is-inside-work-tree")
    except OSError as exc:
        pytest.skip(f"git is not available: {exc}")
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        pytest.skip("not a git work tree (an sdist or an exported tree)")


class TestTheArtefactIsABuildOutput:
    """``_integrity_signature.py`` is generated by every build and never committed.

    AGENTS.md section 8.4 forbids committing it: it carries a per-build
    ephemeral key and the digests of one build's native library and binding
    extensions.  While it was tracked, the Sphinx lane (an unbuilt checkout
    imported under ``AMA_SPHINX_BUILD=1``) compared its ``INTEGRITY_DIGEST_HEX``
    with the tree, so every ``.py`` change had to commit a freshly built copy —
    the gate and the directive contradicted each other.  Measured on an export
    of d6270f28 with one ``.py`` edited and ``_integrity_digest.txt`` refreshed:
    with the stale artefact present the docs-build import raised
    ``CryptoModuleError: signed digest mismatch``; with it absent the same
    import succeeded on the digest-only path against ``_integrity_digest.txt``.
    """

    @pytest.mark.requires_git_history
    @pytest.mark.parametrize("path", ARTEFACT_PATHS)
    def test_the_artefact_is_not_tracked(self, path: str) -> None:
        _require_git_work_tree()
        listed = _git("ls-files", "--", path)
        assert listed.returncode == 0, listed.stderr
        assert listed.stdout.strip() == "", (
            f"{path} is tracked. It is a per-build output (ephemeral key, one "
            f"build's native and binding digests) that AGENTS.md section 8.4 "
            f"forbids committing: `git rm --cached {path}`, and commit "
            f"{DIGEST_PATH} alone for a .py source change."
        )

    @pytest.mark.requires_git_history
    @pytest.mark.parametrize("path", ARTEFACT_PATHS)
    def test_the_artefact_is_ignored(self, path: str) -> None:
        """``.gitignore`` must cover it, so a build cannot dirty the tree.

        ``--no-index`` evaluates the ignore rules alone, independent of
        whether the path is tracked — tracking is the test above.
        """
        _require_git_work_tree()
        result = _git("check-ignore", "--no-index", "--quiet", "--", path)
        assert result.returncode == 0, (
            f"{path} is not ignored by .gitignore, so every build leaves it as "
            f"an untracked file one `git add .` away from being committed."
        )

    @pytest.mark.requires_git_history
    def test_the_source_digest_stays_tracked(self) -> None:
        """The half that IS a property of the commit must remain committed.

        ci.yml::test and ci-build-test.yml::python-package snapshot this file
        before the install re-signs, and fail when a .py source moved without
        it.  Untracking it too would turn that source-drift check vacuous.
        """
        _require_git_work_tree()
        listed = _git("ls-files", "--error-unmatch", "--", DIGEST_PATH)
        assert listed.returncode == 0, f"{DIGEST_PATH} is not tracked: {listed.stderr}"
        ignored = _git("check-ignore", "--no-index", "--quiet", "--", DIGEST_PATH)
        assert ignored.returncode != 0, f"{DIGEST_PATH} is matched by .gitignore"

    @staticmethod
    def _manifest_survivors(files: list[str]) -> list[str]:
        """Apply MANIFEST.in's template lines to ``files`` as sdist does."""
        file_list = FileList()
        file_list.files = list(files)
        manifest = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        for raw in manifest.splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                file_list.process_template_line(line)
        return sorted(file_list.files)

    def test_the_sdist_does_not_carry_a_local_artefact(self) -> None:
        """setuptools adds every package .py to an sdist unless MANIFEST.in says not.

        Measured: before the exclude, ``python setup.py sdist`` in a tree that
        had run ``build_ext --inplace`` listed
        ``ama_cryptography/_integrity_signature.py``, shipping that machine's
        artefact inside the source distribution.  An sdist built without it
        installs, signs its own and imports ``fully_verified``.
        """
        survivors = self._manifest_survivors(
            [*ARTEFACT_PATHS, DIGEST_PATH, "ama_cryptography/integrity.py"]
        )
        for path in ARTEFACT_PATHS:
            assert path not in survivors, f"MANIFEST.in lets {path} into the sdist"
        # Non-vacuity: the exclusion is not so broad that it drops the tracked
        # digest or an ordinary module beside it.
        assert DIGEST_PATH in survivors
        assert "ama_cryptography/integrity.py" in survivors
