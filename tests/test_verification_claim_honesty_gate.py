# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""INVARIANT-37 — negative controls for ``tools/check_verification_claim_honesty.py``.

The repository passing this gate proves nothing on its own: a checker that
returns zero problems because it looks for the wrong thing passes identically to
one that works. INVARIANT-2 puts it plainly — a gate with no demonstrated
rejection direction has not been shown to be a gate. So every class of violation
is reproduced here against a synthetic tree and required to be caught, and the
near-miss cases that must *not* be caught are pinned too, because a gate people
have to route around is the failure mode this repository has already paid for
once (the Bandit severity regex that could never pass).

The test worth reading is
``test_flipping_a_capability_to_true_permits_its_claims``. It pins the property
the whole design rests on: the forbidden claims are derived from
``RFC3161_CAPABILITIES``, not listed in the checker, so implementing CMS
``SignerInfo`` verification and flipping one table entry permits the
corresponding documentation in the same commit — with no gate edit, and no
prohibition left standing after it stopped being true.

This file is one of the two the claim scan exempts, because it must contain the
very claims the gate forbids in order to feed them to it.
"""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_verification_claim_honesty.py"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_verification_claim_honesty", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load_tool()


def _write(repo: Path, relative: str, text: str) -> Path:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# The anchor: the repository holds the invariant today
# ---------------------------------------------------------------------------
def test_the_repository_holds_the_invariant(tool: ModuleType) -> None:
    capabilities = tool.load_capabilities()
    assert tool.scan_for_unperformed_claims(REPO_ROOT, capabilities) == []
    assert tool.scan_for_legacy_result_key(REPO_ROOT) == []
    assert tool.check_refusing_parameters(REPO_ROOT) == []
    assert tool.scan_for_removed_dependency(REPO_ROOT) == []
    assert tool.check_pattern_coverage(capabilities) == []


def test_the_cli_reports_success(tool: ModuleType) -> None:
    assert tool.main() == 0


# ---------------------------------------------------------------------------
# The capability table is the single source of truth, read two ways
# ---------------------------------------------------------------------------
def test_ast_parsed_table_equals_the_imported_one(tool: ModuleType) -> None:
    """The gate reads the table with ``ast``; everything else imports it.

    Two readings of one declaration is exactly the situation where a project
    ends up with two answers. The gate parses rather than imports so it can run
    in a lint job with nothing built — and this test is what stops the two
    diverging.
    """
    pytest.importorskip("ama_cryptography.rfc3161_timestamp")
    from ama_cryptography.rfc3161_timestamp import RFC3161_CAPABILITIES

    assert tool.load_capabilities() == dict(RFC3161_CAPABILITIES)


def test_the_withheld_capabilities_are_the_expected_three(tool: ModuleType) -> None:
    """A guard against the table being quietly emptied.

    Every check in this gate is a no-op if no capability is ``False``. Deleting
    an entry, or flipping one to ``True`` without implementing it, would turn
    the whole invariant green while making the repository's claims *less* true.
    """
    capabilities = tool.load_capabilities()
    withheld = {name for name, performed in capabilities.items() if not performed}
    assert withheld == {"tsa_signature", "tsa_certificate_chain", "gen_time"}


# ---------------------------------------------------------------------------
# Check 1 — claims of unperformed checks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "why"),
    [
        ("AMA provides trusted timestamps for every package.", "trusted timestamp"),
        ("Step 6 will verify the TSA signature before accepting.", "verifies TSA signature"),
        ("The token is verified by TSA public key.", "verified by the TSA"),
        ("Security: requires TSA private key compromise to forge.", "inverted forgery claim"),
        ("RFC 3161 gives third-party attestation of the content.", "attestation, in context"),
        ("The TSA timestamp provides proof-of-existence at a point in time.", "proof of existence"),
        ("Timestamps deliver non-repudiation of time for audit trails.", "non-repudiation of time"),
        ("The TSA layer validates the certificate chain to a root.", "chain validation"),
    ],
)
def test_a_claim_of_an_unperformed_check_is_caught(
    tool: ModuleType, tmp_path: Path, line: str, why: str
) -> None:
    _write(tmp_path, "docs/claim.md", f"# Doc\n\n{line}\n")
    problems = tool.scan_for_unperformed_claims(tmp_path, tool.load_capabilities())
    assert problems, f"gate missed a false claim ({why}): {line!r}"
    assert any("docs/claim.md" in problem for problem in problems)


@pytest.mark.parametrize(
    "line",
    [
        "AMA does not provide trusted timestamps; the binding is all it checks.",
        "It will never verify the TSA signature, because that is not implemented.",
        "This is not third-party attestation for an RFC 3161 token.",
        "The TSA token gives no proof-of-existence: genTime is unauthenticated.",
        "Certificate chain validation for the TSA is refused rather than approximated.",
    ],
)
def test_a_claim_negated_on_the_same_line_is_allowed(
    tool: ModuleType, tmp_path: Path, line: str
) -> None:
    _write(tmp_path, "docs/negated.md", f"# Doc\n\n{line}\n")
    assert tool.scan_for_unperformed_claims(tmp_path, tool.load_capabilities()) == []


@pytest.mark.parametrize(
    "line",
    [
        'The docstring opened with the retired claim "Third-party attestation" for TSA tokens.',
        'THREAT_MODEL.md wrongly recorded "RFC 3161 TSA with independent verification".',
        'The proof falsely said forgery "Requires TSA private key compromise".',
        'CHANGELOG erratum: this entry read "RFC 3161 trusted timestamps".',
        'The table asserted the opposite: "trusted timestamp" was never true.',
    ],
)
def test_citing_a_retired_claim_is_allowed_when_the_line_says_so(
    tool: ModuleType, tmp_path: Path, line: str
) -> None:
    """Quoting a false claim in order to retire it is a documentation act.

    INVARIANT-37's own text, this checker and the CHANGELOG all have to name
    the claims they are removing. The same-line rule then demands the citation
    marker sit beside the quote — a stricter requirement than a suppression
    comment, and a better one, because the reader gets the disclaimer at the
    same moment they get the quote. That adjacency is exactly what was missing
    from every one of the fifty.
    """
    _write(tmp_path, "docs/history.md", f"# Doc\n\n{line}\n")
    assert tool.scan_for_unperformed_claims(tmp_path, tool.load_capabilities()) == []


def test_a_citation_cue_on_a_neighbouring_line_does_not_excuse_the_quote(
    tool: ModuleType, tmp_path: Path
) -> None:
    """The citation cues relax *where* the disclaimer goes, never *whether*."""
    _write(
        tmp_path,
        "docs/history.md",
        """\
        # Doc

        The module promised third-party attestation for every RFC 3161 token.

        All of the above is a retired claim.
        """,
    )
    assert tool.scan_for_unperformed_claims(tmp_path, tool.load_capabilities())


def test_a_negation_on_a_different_line_does_not_excuse_the_claim(
    tool: ModuleType, tmp_path: Path
) -> None:
    """Same line, deliberately.

    This is the rule's whole point. The module docstring disclaimed attestation
    while fifty other places asserted it, and every one of those places was
    "qualified" somewhere else in the repository. A reader's eye is on the
    sentence in front of them.
    """
    _write(
        tmp_path,
        "docs/far_away.md",
        """\
        # Doc

        AMA provides trusted timestamps.

        (Note: none of the above is actually implemented.)
        """,
    )
    problems = tool.scan_for_unperformed_claims(tmp_path, tool.load_capabilities())
    assert problems, "a disclaimer two paragraphs away must not excuse the claim"


@pytest.mark.parametrize(
    "line",
    [
        "Constant-time C code reduces side-channel surface (requires independent verification).",
        "# Round trip and independent verification",
        "The ML-DSA layer offers non-repudiation of authorship.",
        "Structural integrity is checked by the canonical encoder.",
    ],
)
def test_generic_assurance_vocabulary_outside_rfc3161_context_is_not_caught(
    tool: ModuleType, tmp_path: Path, line: str
) -> None:
    """The false positives that would make this gate something people route around.

    "Independent verification" of the C code's side-channel behaviour, and the
    same phrase in an ECDSA round-trip test, are true statements about other
    subjects. A gate that flags them teaches everyone to add an exemption.
    """
    _write(tmp_path, "docs/unrelated.md", f"# Doc\n\n{line}\n")
    assert tool.scan_for_unperformed_claims(tmp_path, tool.load_capabilities()) == []


def test_flipping_a_capability_to_true_permits_its_claims(tool: ModuleType, tmp_path: Path) -> None:
    """The property the whole design exists for.

    A phrase denylist would freeze today's limitation into CI: the day CMS
    ``SignerInfo`` verification lands, the gate would start rejecting claims
    that had become true, and the fix would depend on somebody remembering a
    gate edit — the same class of memory this invariant exists because nobody
    had.

    Because the prohibitions are derived from ``RFC3161_CAPABILITIES``,
    implementing the check and flipping one entry permits the documentation in
    the same commit. Nothing else moves.
    """
    _write(
        tmp_path,
        "docs/future.md",
        "# Doc\n\nAMA will verify the TSA signature and provides trusted timestamps.\n",
    )
    withheld = tool.load_capabilities()
    assert tool.scan_for_unperformed_claims(tmp_path, withheld), "precondition"

    implemented = {**withheld, "tsa_signature": True}
    assert tool.scan_for_unperformed_claims(tmp_path, implemented) == [], (
        "with tsa_signature implemented, claims about it must stop being violations "
        "without anyone editing the gate"
    )

    # And the capabilities still withheld keep their own claims forbidden, so
    # flipping one entry does not open the floodgates.
    _write(
        tmp_path,
        "docs/future.md",
        "# Doc\n\nThe TSA token is cryptographic proof-of-existence at a point in time.\n",
    )
    assert tool.scan_for_unperformed_claims(
        tmp_path, implemented
    ), "gen_time is still False, so its claims must still be refused"


# ---------------------------------------------------------------------------
# Check 2 — the misnamed result key
# ---------------------------------------------------------------------------
def test_teaching_the_legacy_result_key_is_caught(tool: ModuleType, tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docs/example.md",
        '# Doc\n\n```python\nif results["rfc3161"] is True:\n    pass\n```\n',
    )
    problems = tool.scan_for_legacy_result_key(tmp_path)
    assert problems and "docs/example.md" in problems[0]


def test_the_legacy_key_via_get_is_also_caught(tool: ModuleType, tmp_path: Path) -> None:
    _write(tmp_path, "docs/example.md", '# Doc\n\n    ok = results.get("rfc3161")\n')
    assert tool.scan_for_legacy_result_key(tmp_path)


def test_naming_the_legacy_key_as_deprecated_is_allowed(tool: ModuleType, tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docs/example.md",
        '# Doc\n\n    legacy = results["rfc3161"]  # deprecated alias, warns when read\n',
    )
    assert tool.scan_for_legacy_result_key(tmp_path) == []


def test_the_correct_result_key_is_never_flagged(tool: ModuleType, tmp_path: Path) -> None:
    _write(tmp_path, "docs/example.md", '# Doc\n\n    ok = results["rfc3161_binding"]\n')
    assert tool.scan_for_legacy_result_key(tmp_path) == []


# ---------------------------------------------------------------------------
# Check 3 — refusing arguments are documented as refusing
# ---------------------------------------------------------------------------
def test_an_undocumented_refusing_parameter_is_caught(tool: ModuleType, tmp_path: Path) -> None:
    _write(
        tmp_path,
        "ama_cryptography/thing.py",
        '''\
        def verify(data, tsa_cert_path=None):
            """Check a token.

            Args:
                data: the payload.
            """
        ''',
    )
    problems = tool.check_refusing_parameters(tmp_path)
    assert problems and "tsa_cert_path" in problems[0]


def test_a_refusing_parameter_documented_without_refusal_is_caught(
    tool: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        "ama_cryptography/thing.py",
        '''\
        def verify(data, certificate_file=None):
            """Check a token.

            Args:
                certificate_file: path to the TSA certificate, used for pinning.
            """
        ''',
    )
    problems = tool.check_refusing_parameters(tmp_path)
    assert problems and "certificate_file" in problems[0]


def test_a_refusing_parameter_documented_as_refused_is_allowed(
    tool: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        "ama_cryptography/thing.py",
        '''\
        def verify(data, certificate_file=None):
            """Check a token.

            Args:
                certificate_file: Refused, not honoured — raises TimestampError.
            """
        ''',
    )
    assert tool.check_refusing_parameters(tmp_path) == []


# ---------------------------------------------------------------------------
# Check 4 — the removed third-party client
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "Online mode requires the `rfc3161ng` package.",
        "Install with: pip install rfc3161ng",
    ],
)
def test_instructing_the_removed_dependency_is_caught(
    tool: ModuleType, tmp_path: Path, line: str
) -> None:
    _write(tmp_path, "docs/install.md", f"# Doc\n\n{line}\n")
    problems = tool.scan_for_removed_dependency(tmp_path)
    assert problems and "rfc3161ng" in problems[0]


def test_describing_the_removal_is_allowed(tool: ModuleType, tmp_path: Path) -> None:
    _write(
        tmp_path,
        "docs/install.md",
        "# Doc\n\nRFC 3161 no longer requires the `rfc3161ng` package; it was removed.\n",
    )
    assert tool.scan_for_removed_dependency(tmp_path) == []


# ---------------------------------------------------------------------------
# Check 5 — the table cannot outgrow its enforcement
# ---------------------------------------------------------------------------
def test_a_withheld_capability_with_no_patterns_is_caught(tool: ModuleType) -> None:
    problems = tool.check_pattern_coverage({**tool.load_capabilities(), "revocation": False})
    assert any("revocation" in problem for problem in problems)


def test_a_pattern_bound_to_no_capability_is_caught(tool: ModuleType) -> None:
    capabilities = {
        name: value for name, value in tool.load_capabilities().items() if name != "tsa_signature"
    }
    problems = tool.check_pattern_coverage(capabilities)
    assert any("tsa_signature" in problem for problem in problems)


def test_the_exemption_list_is_exactly_the_two_self_referential_files(
    tool: ModuleType,
) -> None:
    """Every further exemption is a place the invariant stops applying.

    Both entries are self-referential — the checker states the forbidden claims
    to forbid them, this file states them to require rejection — which is a
    reason that cannot be extended to a third file.
    """
    assert tool.CLAIM_SCAN_EXEMPT == {
        "tools/check_verification_claim_honesty.py",
        "tests/test_verification_claim_honesty_gate.py",
    }
    assert Path(__file__).relative_to(REPO_ROOT).as_posix() in tool.CLAIM_SCAN_EXEMPT


def test_every_self_scoping_pattern_names_its_subject(tool: ModuleType) -> None:
    """A pattern exempt from the context gate must say what it is about itself."""
    assert tool.check_pattern_coverage(tool.load_capabilities()) == []


# ---------------------------------------------------------------------------
# Failure modes of the checker itself
# ---------------------------------------------------------------------------
def test_a_missing_capability_table_is_an_error_not_a_pass(
    tool: ModuleType, tmp_path: Path
) -> None:
    """Fail closed. A table the gate cannot find must not read as 'nothing withheld'."""
    source = _write(tmp_path, "ama_cryptography/rfc3161_timestamp.py", "X = 1\n")
    with pytest.raises(ValueError, match="RFC3161_CAPABILITIES"):
        tool.load_capabilities(source)


def test_a_malformed_capability_table_is_an_error(tool: ModuleType, tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "ama_cryptography/rfc3161_timestamp.py",
        'RFC3161_CAPABILITIES = {"tsa_signature": "no"}\n',
    )
    with pytest.raises(ValueError, match="str -> bool"):
        tool.load_capabilities(source)


def test_a_bare_dict_table_is_accepted(tool: ModuleType, tmp_path: Path) -> None:
    """The table is wrapped in MappingProxyType today; the parser must not depend on it."""
    source = _write(
        tmp_path,
        "ama_cryptography/rfc3161_timestamp.py",
        'RFC3161_CAPABILITIES = {"tsa_signature": False, "gen_time": True}\n',
    )
    assert tool.load_capabilities(source) == {"tsa_signature": False, "gen_time": True}
