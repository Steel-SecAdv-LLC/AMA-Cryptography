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
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SETUP_PY = Path(__file__).resolve().parent.parent / "setup.py"

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
        "the pre-sign artefact is not renamed anywhere; a deletion leaves a "
        "tracked file gone in the developer's checkout on any signer failure"
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
