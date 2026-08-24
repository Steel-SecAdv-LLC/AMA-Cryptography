# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for tools/check_version_consistency.py.

Focused on the C-source scan extension: a synthetic C file with a fake
version literal must be flagged, and a real-tree scan against the
checked-in src/c/ tree must continue to return zero hits (so the
default safety-net assertion is durable).
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_version_consistency.py"


@pytest.fixture(scope="module")
def tool_module() -> ModuleType:
    """Load tools/check_version_consistency.py as a module so we can
    call its scan function directly. The script lives in a non-package
    directory and isn't on sys.path, so importlib.util is the cleanest
    handle that doesn't require modifying the tool layout."""
    spec = importlib.util.spec_from_file_location("check_version_consistency", TOOL_PATH)
    assert spec is not None, f"could not build a ModuleSpec for {TOOL_PATH}"
    assert spec.loader is not None, f"ModuleSpec for {TOOL_PATH} has no loader"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_tree_returns_zero_hits(tool_module: ModuleType) -> None:
    """The shipped src/c/ tree must contain *no* embedded
    "X.Y.Z" version-string literals near a VERSION/version
    identifier — that's the steady-state invariant the check enforces.
    If this assertion ever fires, a stray literal slipped in and the
    canonical AMA_CRYPTOGRAPHY_VERSION_STRING macro should be used
    instead."""
    hits = tool_module.scan_c_sources_for_version_literals(REPO_ROOT / "src" / "c")
    assert hits == [], f"unexpected version literals in src/c/: {hits}"


def test_github_invariants_file_is_pointer() -> None:
    pointer = REPO_ROOT / ".github" / "INVARIANTS.md"
    assert (
        pointer.read_text(encoding="utf-8")
        == "# AMA Cryptography invariants\n\nCanonical copy: ../INVARIANTS.md\n"
    )


class TestTagPins:
    """README's own install commands must name the canonical version (M11).

    The predecessor swept docs/**/*.rst only, so README's `@vX.Y.Z` install
    pins — which are .md — went unchecked while the comment claimed to cover
    them (INVARIANT-32).
    """

    def test_the_real_tree_covers_the_readme_and_landing_page_pins(
        self, tool_module: ModuleType
    ) -> None:
        repo = TOOL_PATH.resolve().parent.parent
        problems, checked = tool_module.scan_tag_pins(repo, "5.0.0")
        assert problems == [], problems
        # README ships two install pins and docs/index.rst one; a sweep that
        # finds fewer has stopped seeing them — the vacuity M11 was about.
        assert checked >= 3, f"the tag-pin sweep found only {checked} pins"

    def test_a_stale_readme_style_md_pin_is_reported(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        (tmp_path / "README.md").write_text(
            'pip install "git+https://github.com/Steel-SecAdv-LLC/'
            'AMA-Cryptography.git@v4.0.0"\n',
            encoding="utf-8",
        )
        problems, checked = tool_module.scan_tag_pins(tmp_path, "5.0.0")
        assert checked == 1
        assert problems and "@v4.0.0" in problems[0] and "README.md" in problems[0]

    def test_a_matching_md_pin_passes(self, tool_module: ModuleType, tmp_path: Path) -> None:
        # The requirements-style pin README also carries.
        (tmp_path / "README.md").write_text(
            "ama-cryptography @ git+https://github.com/Steel-SecAdv-LLC/"
            "AMA-Cryptography.git@v5.0.0\n",
            encoding="utf-8",
        )
        problems, checked = tool_module.scan_tag_pins(tmp_path, "5.0.0")
        assert problems == [] and checked == 1

    def test_a_third_party_action_pin_is_not_a_package_pin(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        """INVARIANTS.md pins slsa-github-generator@v2.1.0 — a different repo,
        not the AMA package, so it must not be read as a stale version."""
        (tmp_path / "INVARIANTS.md").write_text(
            "uses: slsa-framework/slsa-github-generator/"
            ".github/workflows/generator_generic_slsa3.yml@v2.1.0\n",
            encoding="utf-8",
        )
        problems, checked = tool_module.scan_tag_pins(tmp_path, "5.0.0")
        assert problems == [] and checked == 0

    def test_changelog_and_compliance_pins_are_excluded(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        """A CHANGELOG entry or a dated attestation may pin an old tag."""
        (tmp_path / "CHANGELOG.md").write_text(
            "In v4.0.0, install with AMA-Cryptography.git@v4.0.0\n", encoding="utf-8"
        )
        compliance = tmp_path / "docs" / "compliance"
        compliance.mkdir(parents=True)
        (compliance / "OLD_ATTESTATION.md").write_text(
            "Generated against AMA-Cryptography.git@v3.0.0\n", encoding="utf-8"
        )
        problems, checked = tool_module.scan_tag_pins(tmp_path, "5.0.0")
        assert problems == [] and checked == 0


class TestInvariantRangeClaims:
    """ "INVARIANT-1 through INVARIANT-N" is a count in prose, and it went stale.

    The branch that took the register from 38 to 42 corrected three of the four
    documents naming the old range. By the time the register reached 43,
    `.github/copilot-instructions.md` still said 42 — a canonical-register
    extent that disagreed with the register, in the file that tells an
    assistant what the register is.
    """

    def test_the_real_tree_agrees_with_the_register(self, tool_module: ModuleType) -> None:
        repo = TOOL_PATH.resolve().parent.parent
        highest, register_problems = tool_module.invariant_register_extent(repo / "INVARIANTS.md")
        assert register_problems == [], register_problems
        problems, checked = tool_module.scan_invariant_range_claims(repo, highest)
        assert problems == [], problems
        assert checked >= 4, "the range claims stopped being found — the check is vacuous"

    def test_a_stale_range_is_reported(self, tool_module: ModuleType, tmp_path: Path) -> None:
        (tmp_path / "doc.md").write_text(
            "See INVARIANTS.md (INVARIANT-1 through INVARIANT-42).\n", encoding="utf-8"
        )
        problems, checked = tool_module.scan_invariant_range_claims(tmp_path, 43)
        assert checked == 1
        assert len(problems) == 1
        assert "INVARIANT-43" in problems[0] and "doc.md:1" in problems[0]

    @pytest.mark.parametrize("joiner", ["through", "to", "-", "\u2013", "\u2014"])
    def test_every_range_spelling_is_recognised(
        self, tool_module: ModuleType, tmp_path: Path, joiner: str
    ) -> None:
        (tmp_path / "doc.md").write_text(f"INVARIANT-1 {joiner} INVARIANT-9\n", encoding="utf-8")
        problems, checked = tool_module.scan_invariant_range_claims(tmp_path, 43)
        assert checked == 1, joiner
        assert len(problems) == 1, joiner

    def test_a_range_that_does_not_start_at_one_is_left_alone(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        """CHANGELOG.md's "INVARIANT-39 through INVARIANT-42" describes one
        release's scope. Forcing it to the register's maximum would rewrite
        release history into something false."""
        (tmp_path / "doc.md").write_text(
            "Security (INVARIANT-39 through INVARIANT-42)\n", encoding="utf-8"
        )
        problems, checked = tool_module.scan_invariant_range_claims(tmp_path, 43)
        assert checked == 0
        assert problems == []

    def test_a_wrapped_claim_is_caught_and_reported_on_one_line(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        """A claim that wraps must not escape, and must not be quoted back with
        a newline in it."""
        (tmp_path / "doc.md").write_text(
            "See INVARIANTS.md, INVARIANT-1\n  through INVARIANT-42.\n", encoding="utf-8"
        )
        problems, checked = tool_module.scan_invariant_range_claims(tmp_path, 43)
        assert checked == 1
        assert len(problems) == 1
        assert "INVARIANT-1 through INVARIANT-42" in problems[0]
        assert "\n" not in problems[0]

    def test_the_message_says_how_to_write_a_historical_quotation(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        """The check reads prose and cannot tell a quotation from a claim, so
        the message has to name the escape rather than leave a writer stuck."""
        (tmp_path / "doc.md").write_text("INVARIANT-1 through INVARIANT-42\n", encoding="utf-8")
        problems, _checked = tool_module.scan_invariant_range_claims(tmp_path, 43)
        assert "ending at INVARIANT-N" in problems[0]

    def test_a_gap_in_the_register_is_reported(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        """ "1 through N" only describes a set with no holes in it."""
        register = tmp_path / "INVARIANTS.md"
        register.write_text("## INVARIANT-1 - a\n\n## INVARIANT-3 - c\n", encoding="utf-8")
        highest, problems = tool_module.invariant_register_extent(register)
        assert highest == 3
        assert any("not contiguous" in row and "INVARIANT-2" in row for row in problems)

    def test_a_duplicate_heading_is_reported(self, tool_module: ModuleType, tmp_path: Path) -> None:
        register = tmp_path / "INVARIANTS.md"
        register.write_text(
            "## INVARIANT-1 - a\n\n## INVARIANT-2 - b\n\n## INVARIANT-2 - b again\n",
            encoding="utf-8",
        )
        _highest, problems = tool_module.invariant_register_extent(register)
        assert any("duplicate" in row for row in problems)

    def test_an_unreadable_register_fails_rather_than_passes(
        self, tool_module: ModuleType, tmp_path: Path
    ) -> None:
        register = tmp_path / "INVARIANTS.md"
        register.write_text("# no headings here\n", encoding="utf-8")
        highest, problems = tool_module.invariant_register_extent(register)
        assert highest == 0
        assert problems, "a register with nothing in it must not read as clean"


def _match_header(tool_module: ModuleType, text: str) -> tuple[str, str] | None:
    """First (version, trailing-qualifier) pair any doc-header pattern finds."""
    for pat in tool_module.DOC_HEADER_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1), m.group(2).strip()
    return None


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("**Version:** 3.4.0", ("3.4.0", "")),
        ("**Document Version:** 3.4.0", ("3.4.0", "")),
        ("| Version | 3.4.0 |", ("3.4.0", "")),
        ("| Document Version | 3.4.0 |", ("3.4.0", "")),
        ("**Project Release:** 3.4.0", ("3.4.0", "")),
        # The shape that escaped the scan entirely: a version header with a
        # trailing qualifier matched no pattern, so docs/DESIGN_NOTES.md and
        # docs/METRICS_REPORT.md sat on 3.1.0 across three releases while the
        # script reported "All declarations agree".
        ("**Version:** 3.1.0 + Unreleased", ("3.1.0", "+ Unreleased")),
        ("| Version | 3.1.0 + Unreleased |", ("3.1.0", "+ Unreleased")),
    ],
)
def test_doc_header_shapes_are_matched(
    tool_module: ModuleType, header: str, expected: tuple[str, str]
) -> None:
    """Every document-header shape in the tree must be *seen* by the scan.
    A shape that matches no pattern is reported as neither stale nor
    checked, which is the failure mode that let two documents drift."""
    assert _match_header(tool_module, header) == expected


def test_project_release_header_is_covered(tool_module: ModuleType) -> None:
    """CODE_OF_CONDUCT.md declares the release as `**Project Release:**`
    rather than `**Version:**`. It carried 3.0.0 through three releases
    because no pattern reached it."""
    coc = (REPO_ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    found = tool_module.DOC_HEADER_PATTERNS[2].search(coc)
    assert found is not None, "Project Release header is no longer being scanned"


def test_wiki_footer_badge_is_covered() -> None:
    """The wiki footer renders on every wiki page and carries a release
    badge in prose, so the *.md header scan cannot see it. It is checked
    by name; this pins that the text the check greps for still exists."""
    footer = (REPO_ROOT / "wiki" / "_Footer.md").read_text(encoding="utf-8")
    assert re.search(r"Not externally audited\s*·\s*v\d+\.\d+\.\d+", footer), (
        "wiki/_Footer.md release badge changed shape — "
        "tools/check_version_consistency.py greps for it by name"
    )


def test_package_docstring_version_agrees_with_dunder(tool_module: ModuleType) -> None:
    """The package module docstring's ``Version:`` field must match the
    authoritative ``__version__`` in the same file.  This is the exact
    self-contradiction that shipped: docstring on 3.1.0, ``__version__``
    on 3.4.0, and the checker reported agreement because it only read the
    dunder."""
    init = (REPO_ROOT / "ama_cryptography" / "__init__.py").read_text(encoding="utf-8")
    doc = re.search(tool_module.PACKAGE_DOCSTRING_VERSION_RE, init, re.M)
    dunder = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.M)
    assert doc is not None, "docstring Version field no longer matched — pattern drifted"
    assert dunder is not None
    doc_v, dunder_v = doc.group(1), dunder.group(1)
    assert doc_v == dunder_v, f"docstring Version {doc_v!r} != __version__ {dunder_v!r}"


def test_header_doxygen_version_agrees_with_macro(tool_module: ModuleType) -> None:
    """The public header's Doxygen ``@version`` tag must match its
    ``AMA_CRYPTOGRAPHY_VERSION_STRING`` macro — the second half of the
    same self-contradiction, on the C side."""
    hdr = (REPO_ROOT / "include" / "ama_cryptography.h").read_text(encoding="utf-8")
    tag = re.search(tool_module.HEADER_DOXYGEN_VERSION_RE, hdr, re.M)
    macro = re.search(r'AMA_CRYPTOGRAPHY_VERSION_STRING\s+"([^"]+)"', hdr)
    assert tag is not None, "@version tag no longer matched — pattern drifted"
    assert macro is not None
    assert tag.group(1) == macro.group(1), f"@version {tag.group(1)!r} != macro {macro.group(1)!r}"


def test_new_canonical_checks_catch_a_mismatch(tool_module: ModuleType) -> None:
    """The two new patterns must actually *see* a stale value so main()
    can flag it — a pattern that matches nothing would silently restore
    the original blind spot."""
    doc = re.search(tool_module.PACKAGE_DOCSTRING_VERSION_RE, "Version: 3.1.0\n", re.M)
    tag = re.search(tool_module.HEADER_DOXYGEN_VERSION_RE, " * @version 3.1.0\n", re.M)
    assert doc is not None and doc.group(1) == "3.1.0"
    assert tag is not None and tag.group(1) == "3.1.0"


def test_main_covers_the_two_canonical_in_file_declarations(
    tool_module: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """End-to-end: main() runs green on the real tree AND its output shows
    the two previously-uncovered declarations are now checked."""
    rc = tool_module.main()
    out = capsys.readouterr().out
    assert rc == 0, "version consistency check failed on the real tree"
    assert "ama_cryptography/__init__.py docstring Version field" in out
    assert "include/ama_cryptography.h @version tag" in out


def test_synthetic_c_file_is_flagged(tool_module: ModuleType, tmp_path: Path) -> None:
    """Drop a fake `#define MY_VERSION "9.9.9"` into a temp directory
    and confirm the scanner picks it up. Mirrors the pattern a future
    accidental commit would take."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    fake = src_dir / "fake_module.c"
    fake.write_text(
        "/* synthetic test fixture */\n"
        '#define MY_VERSION "9.9.9"\n'
        'static const char *version = "0.1.2";\n'
    )

    hits = tool_module.scan_c_sources_for_version_literals(src_dir)
    assert len(hits) == 2, f"expected 2 flagged lines, got: {hits}"
    joined = "\n".join(hits)
    assert "9.9.9" in joined
    assert "0.1.2" in joined
    assert "fake_module.c" in joined


def test_c_comments_are_ignored(tool_module: ModuleType, tmp_path: Path) -> None:
    """Version literals embedded in `/* ... */` block comments or `//`
    line comments are documentation, not code-shipped values, and
    should not trip the scanner. This avoids false positives on
    historical change-log notes inside source headers."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    f = src_dir / "comments_only.c"
    f.write_text(
        '/* Released in version "1.2.3" — historical note */\n'
        '// const char *legacy_version = "0.0.1";\n'
        "int main(void) { return 0; }\n"
    )
    assert tool_module.scan_c_sources_for_version_literals(src_dir) == []


def test_literal_without_version_identifier_is_ignored(
    tool_module: ModuleType, tmp_path: Path
) -> None:
    """A `"X.Y.Z"` literal that's not anywhere near a VERSION/version
    identifier (e.g. a protocol-spec quote) should not be flagged.
    The check is targeted at the identifier-and-literal coupling, not
    at any three-dotted-numbers string anywhere in C."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    f = src_dir / "no_version_ident.c"
    f.write_text('static const char *rfc_section = "5.2.1";\n' "int main(void) { return 0; }\n")
    assert tool_module.scan_c_sources_for_version_literals(src_dir) == []


def test_header_files_are_scanned(tool_module: ModuleType, tmp_path: Path) -> None:
    """Both `*.c` and `*.h` are in scope per the task spec — make sure
    a literal hidden in a header is also reported."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    h = src_dir / "fake_module.h"
    h.write_text('#define FAKE_VERSION "2.5.0"\n')
    hits = tool_module.scan_c_sources_for_version_literals(src_dir)
    assert any("fake_module.h" in hit and "2.5.0" in hit for hit in hits)


def test_standalone_uppercase_version_identifier_is_flagged(
    tool_module: ModuleType, tmp_path: Path
) -> None:
    """The bare uppercase `VERSION` identifier — no leading prefix
    characters — must still be picked up. Devin Review 2026-04-27
    found that an earlier draft of `_C_VERSION_IDENT_RE` required
    at least one prefix character before the `[Vv]ersion` substring,
    so `#define VERSION "1.2.3"` slipped through the safety net.
    This regression test pins the fixed regex against that
    false-negative case."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    f = src_dir / "standalone_upper.c"
    f.write_text('#define VERSION "1.2.3"\n')
    hits = tool_module.scan_c_sources_for_version_literals(src_dir)
    assert any("1.2.3" in hit for hit in hits), f"VERSION was not flagged: {hits}"


def test_standalone_titlecase_version_identifier_is_flagged(
    tool_module: ModuleType, tmp_path: Path
) -> None:
    """Same Devin Review 2026-04-27 false-negative, title-case
    variant: `#define Version "2.0.0"` must be flagged. Without
    the bare-`[Vv]ersion` alternative in the regex, this slipped
    through too."""
    src_dir = tmp_path / "c"
    src_dir.mkdir()
    f = src_dir / "standalone_title.c"
    f.write_text('#define Version "2.0.0"\n')
    hits = tool_module.scan_c_sources_for_version_literals(src_dir)
    assert any("2.0.0" in hit for hit in hits), f"Version was not flagged: {hits}"


def test_declared_version_scan_covers_the_tree(tool_module: ModuleType) -> None:
    """Every ``__version__``, docstring ``Version:`` and ``@version`` across the
    shipped Python and C trees is found and equals the canonical version. This
    is the whole-tree sweep the file-by-file checks are not — thirteen module
    stamps sat on 3.0.0 for four releases before it existed."""
    init = (REPO_ROOT / "ama_cryptography" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.M)
    assert m is not None
    canonical = m.group(1)
    stamps = tool_module.scan_declared_versions(REPO_ROOT)
    assert stamps, "scan found no version stamps — it is not looking where it should"
    stale = [(rel, ln, label, val) for rel, ln, label, val in stamps if val != canonical]
    assert stale == [], f"stale version stamps: {stale}"


def test_declared_version_scan_flags_a_stale_stamp(tool_module: ModuleType, tmp_path: Path) -> None:
    """A synthetic module carrying an old ``__version__`` and docstring
    ``Version:`` under a mocked tree must be flagged — the scan must actually
    detect drift, not walk quietly. Both stamp kinds are exercised."""
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "stale.py").write_text('"""m\n\nVersion: 3.0.0\n"""\n__version__ = "3.0.0"\n')
    stamps = tool_module.scan_declared_versions(tmp_path)
    seen = {(label, val) for _rel, _ln, label, val in stamps}
    assert ("__version__", "3.0.0") in seen
    assert ("Version:", "3.0.0") in seen


# ===========================================================================
# C constant transcriptions
# ===========================================================================
# The Python layer mirrors integer constants the public C header owns — error
# codes, key and tag sizes, algorithm and policy selectors. Every one is a
# second declaration of a value defined elsewhere, which is the same
# duplication this tool exists to police; a version string is just the one
# anybody notices when it drifts.
#
# `AMA_ERROR_INVALID_PARAM = -1` reached `pqc_backends.py` with no gate at all.
# Drift there is quieter than a stale version badge and worse: a module
# comparing a return code against the wrong number stops detecting the failure
# it was written to detect, and every success-path test still passes.
def test_c_constants_parse_out_of_the_real_header(tool_module: ModuleType) -> None:
    header = REPO_ROOT / "include" / "ama_cryptography.h"
    constants = tool_module.parse_c_constants(header)
    # Both definition shapes must be reached: an object-like #define and an
    # enumerator. If either regex stops matching, the gate silently narrows.
    assert constants["AMA_ML_DSA_65_PUBLIC_KEY_BYTES"] == 1952  # #define
    assert constants["AMA_ERROR_INVALID_PARAM"] == -1  # enumerator
    assert constants["AMA_SUCCESS"] == 0
    assert constants["AMA_AGENT_CAP_DELEGATE"] == 0x10  # hex, u-suffixed
    assert len(constants) > 80


def test_the_repository_transcriptions_all_agree(tool_module: ModuleType) -> None:
    """The anchor: every Python mirror equals its C definition, right now."""
    problems, checked = tool_module.scan_c_constant_transcriptions(REPO_ROOT)
    assert problems == [], "\n".join(problems)
    assert (
        checked >= tool_module._MIN_C_CONSTANT_TRANSCRIPTIONS
    ), f"only {checked} transcriptions matched; the scan is not resolving names"


def test_the_scan_catches_a_drifted_constant(tool_module: ModuleType, tmp_path: Path) -> None:
    """Failure direction, on the exact constant that had no gate."""
    header = tmp_path / "include" / "ama_cryptography.h"
    header.parent.mkdir(parents=True)
    header.write_text("typedef enum {\n    AMA_ERROR_INVALID_PARAM = -1,\n} ama_error_t;\n")
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "mirror.py").write_text("AMA_ERROR_INVALID_PARAM = -2\n")
    problems, checked = tool_module.scan_c_constant_transcriptions(tmp_path, header)
    assert checked == 1
    assert any("AMA_ERROR_INVALID_PARAM" in p and "-2" in p for p in problems), problems


def test_the_scan_matches_through_a_leading_underscore_and_a_dropped_prefix(
    tool_module: ModuleType, tmp_path: Path
) -> None:
    """The two naming conventions the Python layer actually uses.

    `_AMA_ERROR_VERIFY_FAILED` (private mirror, full name) and
    `ED25519_PUBLIC_KEY_BYTES` (public constant, `AMA_` prefix dropped) must
    both resolve, or half the mirrors in the package go unchecked while the
    tool reports success.
    """
    header = tmp_path / "include" / "ama_cryptography.h"
    header.parent.mkdir(parents=True)
    header.write_text(
        "typedef enum {\n    AMA_ERROR_VERIFY_FAILED = -4,\n} ama_error_t;\n"
        "#define AMA_ED25519_PUBLIC_KEY_BYTES 32\n"
    )
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "mirror.py").write_text("_AMA_ERROR_VERIFY_FAILED = -5\nED25519_PUBLIC_KEY_BYTES = 31\n")
    problems, checked = tool_module.scan_c_constant_transcriptions(tmp_path, header)
    assert checked == 2
    assert len(problems) == 2, problems


def test_the_scan_reaches_class_level_constants(tool_module: ModuleType, tmp_path: Path) -> None:
    """`crypto_api.py` keeps its size constants inside a class, so a scan that
    only walked module level would miss them entirely."""
    header = tmp_path / "include" / "ama_cryptography.h"
    header.parent.mkdir(parents=True)
    header.write_text("#define AMA_ED25519_SIGNATURE_BYTES 64\n")
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "sizes.py").write_text("class Sizes:\n    ED25519_SIGNATURE_BYTES = 63\n")
    problems, checked = tool_module.scan_c_constant_transcriptions(tmp_path, header)
    assert checked == 1 and len(problems) == 1, (problems, checked)


def test_unrelated_python_constants_are_not_flagged(
    tool_module: ModuleType, tmp_path: Path
) -> None:
    """A Python-only constant is not a transcription. Matching one would make
    the gate un-satisfiable and push a maintainer to rename working code."""
    header = tmp_path / "include" / "ama_cryptography.h"
    header.parent.mkdir(parents=True)
    header.write_text("#define AMA_ED25519_SIGNATURE_BYTES 64\n")
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "local.py").write_text("_TIMING_ITERATIONS = 10000\nMAX_RETRIES = 3\nDEBUG = True\n")
    problems, checked = tool_module.scan_c_constant_transcriptions(tmp_path, header)
    assert (problems, checked) == ([], 0)


def test_every_alias_names_a_constant_the_header_defines(tool_module: ModuleType) -> None:
    """The hand-written alias table is itself a transcription and can rot.

    An alias pointing at a constant the header no longer defines would silently
    stop checking the Python constant it was added for.
    """
    constants = tool_module.parse_c_constants(REPO_ROOT / "include" / "ama_cryptography.h")
    for (rel, name), c_name in tool_module.C_CONSTANT_ALIASES.items():
        assert c_name in constants, f"{rel}:{name} aliases {c_name}, which is not in the header"
        assert (REPO_ROOT / rel).is_file(), f"{rel} does not exist"


def test_an_alias_pointing_at_nothing_is_reported(
    tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    header = tmp_path / "include" / "ama_cryptography.h"
    header.parent.mkdir(parents=True)
    header.write_text("#define AMA_SOMETHING_ELSE 1\n")
    pkg = tmp_path / "ama_cryptography"
    pkg.mkdir()
    (pkg / "aliased.py").write_text("LOCAL_NAME = 16\n")
    monkeypatch.setattr(
        tool_module,
        "C_CONSTANT_ALIASES",
        {("ama_cryptography/aliased.py", "LOCAL_NAME"): "AMA_GONE"},
    )
    problems, _ = tool_module.scan_c_constant_transcriptions(tmp_path, header)
    assert any("AMA_GONE" in p and "does not define" in p for p in problems), problems


def test_a_missing_header_is_a_failure_not_a_pass(tool_module: ModuleType, tmp_path: Path) -> None:
    """Fail closed: no header means nothing was verified, which must not read
    as everything being fine."""
    problems, checked = tool_module.scan_c_constant_transcriptions(tmp_path, tmp_path / "nope.h")
    assert checked == 0 and problems, (problems, checked)


def test_repo_relative_is_posix_on_every_platform(tool_module: ModuleType) -> None:
    """The alias-table lookup key must not change shape with the runner OS.

    ``C_CONSTANT_ALIASES`` is keyed by ``ama_cryptography/ascon.py``.  With
    ``str(Path.relative_to(...))`` the scan derived
    ``ama_cryptography\\ascon.py`` on Windows, so every alias lookup missed:
    the aliased Ascon and agent-binding constants went unchecked on the Windows
    runners while the gate still printed a clean result, and the negative test
    below reported no problem at all.

    Driven through ``PureWindowsPath`` so this is a real regression test on
    Linux too — a Windows-only reproduction is one nobody runs before pushing.
    """
    from pathlib import PurePosixPath, PureWindowsPath

    win = tool_module.repo_relative(
        PureWindowsPath(r"C:\src\repo\ama_cryptography\ascon.py"),
        PureWindowsPath(r"C:\src\repo"),
    )
    assert win == "ama_cryptography/ascon.py", win

    posix = tool_module.repo_relative(
        PurePosixPath("/src/repo/ama_cryptography/ascon.py"), PurePosixPath("/src/repo")
    )
    assert posix == "ama_cryptography/ascon.py", posix
    assert win == posix


def test_alias_keys_are_written_in_the_form_the_scan_produces(
    tool_module: ModuleType,
) -> None:
    """Both halves of the contract, pinned together.

    ``repo_relative`` emits forward slashes; a hand-written key with a
    backslash would therefore never match, and the constant it names would go
    unchecked without anything failing.
    """
    for key in tool_module.C_CONSTANT_ALIASES:
        rel = key[0]
        assert "\\" not in rel, f"alias key {rel!r} is not in POSIX form"
        assert not rel.startswith("/"), f"alias key {rel!r} is not repo-relative"


def test_aliased_constants_are_actually_checked(tool_module: ModuleType) -> None:
    """Non-vacuity for the alias table on the *real* tree.

    ``test_an_alias_pointing_at_nothing_is_reported`` monkeypatches the table,
    so it cannot notice that the shipped entries resolve to nothing.  This one
    perturbs each real alias in turn and demands the scan complain: if the
    lookup silently misses — as it did on Windows — no perturbation is
    detected and this fails.
    """
    header = REPO_ROOT / "include" / "ama_cryptography.h"
    for (rel, name), c_name in tool_module.C_CONSTANT_ALIASES.items():
        real = tool_module.parse_c_constants(header)[c_name]
        problems, checked = tool_module.scan_c_constant_transcriptions(REPO_ROOT, header)
        assert checked > 0 and not problems, (problems, checked)
        # Now claim the header says something else, and require the mismatch
        # to surface against this alias specifically.
        patched = dict(tool_module.parse_c_constants(header))
        patched[c_name] = real + 1
        problems = _scan_with_constants(tool_module, patched, header)
        assert any(rel in p and name in p and c_name in p for p in problems), (
            f"perturbing {c_name} did not surface through the {rel}:{name} alias",
            problems,
        )


def _scan_with_constants(
    tool_module: ModuleType, constants: dict[str, int], header: Path
) -> list[str]:
    """Run the transcription scan against a doctored view of the header."""
    import unittest.mock

    with unittest.mock.patch.object(tool_module, "parse_c_constants", lambda _h: constants):
        problems, _ = tool_module.scan_c_constant_transcriptions(REPO_ROOT, header)
    reported: list[str] = problems
    return reported
