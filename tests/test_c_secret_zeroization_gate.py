#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The INVARIANT-6 C-zeroization gate must fail on the pattern it names.

``tools/check_c_secret_zeroization.py`` exists because the semgrep rule that
claimed this coverage could not run (scoped to ``src/c/**``; every scan targets
``ama_cryptography/`` only).  A replacement gate is worth nothing unless it can
actually fail, so this exercises BOTH directions — detection and non-detection —
on purpose-built input, plus the real tree.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from tools import check_c_secret_zeroization as gate

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Stand-in path for text scanned inline rather than read from a file.  A real
#: Path, not None: scan_text's signature says Path, mypy --strict enforces it,
#: and widening the production signature to Optional so a test can pass None
#: would be the test steering the code.
_INLINE = Path("<inline test source>")


def _write(tmp_path: Path, body: str, name: str = "probe.c") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


class TestDetection:
    """Every spelling of the anti-pattern is caught."""

    @pytest.mark.parametrize(
        "line,expected_name",
        [
            ("    memset(secret_key, 0, 32);", "secret_key"),
            ("    memset(private_scalar, 0, 32);", "private_scalar"),
            ("    memset(master_seed, 0, 64);", "master_seed"),
            ("    memset(round_keys, 0, 240);", "round_keys"),
            ("    memset(round_key, 0x00, 240);", "round_key"),
            ("    memset(tag_mask, 0, 16);", "tag_mask"),
            ("    memset(ipad, 0, 136);", "ipad"),
            ("    memset(opad, '\\0', 136);", "opad"),
            ("    memset(ctx->hmac_key, 0, 32);", "hmac_key"),
            ("    memset(st.session_secret, 0, 32);", "session_secret"),
            ("    memset(&kp_local, 0, sizeof(kp_local));", "kp_local"),
            ("    memset(sk_buf, 0, 64);", "sk_buf"),
            ("    memset(keys[i].signing_key, 0, 32);", "signing_key"),
            ("    memset( secret_bytes , 0 , 32 );", "secret_bytes"),
            # A cast on the destination is an ordinary C spelling; requiring
            # the destination to START with an identifier silently exempted it
            # from an ERROR-severity control whose semgrep counterpart cannot
            # run at all, so the regex here was the only enforcement.
            ("    memset((void *)ctx->hmac_key, 0, 32);", "hmac_key"),
            ("    memset((unsigned char *)secret_key, 0, 32);", "secret_key"),
            ("    memset((void*)&kp_local, 0, sizeof(kp_local));", "kp_local"),
            # An integer suffix on the zero was the same kind of bypass: the
            # value group ended at `0` and the pattern then demanded a comma.
            ("    memset(secret_key, 0U, 32);", "secret_key"),
            ("    memset(round_key, 0x00u, 240);", "round_key"),
        ],
    )
    def test_flags_secret_named_destinations(
        self, tmp_path: Path, line: str, expected_name: str
    ) -> None:
        path = _write(tmp_path, f"#include <string.h>\nvoid f(void) {{\n{line}\n}}\n")
        findings = gate.audit([path])
        assert len(findings) == 1, f"expected exactly one finding for: {line}"
        assert findings[0].dst == expected_name
        # The report must name the file, the line, and the replacement.
        rendered = findings[0].render()
        assert "ama_secure_memzero" in rendered
        assert expected_name in rendered

    def test_main_exits_nonzero_on_a_finding(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "#include <string.h>\nvoid f(void) {\n    memset(secret_key, 0, 32);\n}\n",
        )
        assert gate.main([str(path)]) == 1


class TestNonDetection:
    """Generic and correct code is not flagged — a noisy gate gets silenced."""

    @pytest.mark.parametrize(
        "line",
        [
            "    memset(block, 0, 16);",
            "    memset(buf, 0, sizeof(buf));",
            "    memset(out, 0, 32);",
            "    memset(ciphertext, 0, len);",
            "    ama_secure_memzero(secret_key, 32);",
            "    memset(secret_key, 0xFF, 32);",  # not a zeroization
        ],
    )
    def test_does_not_flag(self, tmp_path: Path, line: str) -> None:
        path = _write(tmp_path, f"#include <string.h>\nvoid f(void) {{\n{line}\n}}\n")
        assert gate.audit([path]) == []

    def test_ignores_the_pattern_inside_comments(self, tmp_path: Path) -> None:
        """Explanatory prose must not trip the gate — this repo has several.

        Both comment forms, including a block comment that spans lines.
        """
        body = (
            "#include <string.h>\n"
            "/* Do not write memset(secret_key, 0, 32) here — use\n"
            "   ama_secure_memzero(secret_key, 32) instead. */\n"
            "void f(void) {\n"
            "    // memset(master_seed, 0, 64);\n"
            "    ama_secure_memzero(secret_key, 32);\n"
            "}\n"
        )
        assert gate.audit([_write(tmp_path, body)]) == []

    def test_main_exits_zero_on_clean_input(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "#include <string.h>\nvoid f(void) {\n    ama_secure_memzero(secret_key, 32);\n}\n",
        )
        assert gate.main([str(path)]) == 0


class TestMultiLineCalls:
    """A call split across lines is the same violation.

    ``scan_text`` matched ``_MEMSET_RE`` against one line at a time, so the
    ordinary wrapped spelling of the call was invisible to it.  That is not a
    corner case: the wrap is forced by long destination expressions, which are
    disproportionately the member chains into secret state this rule exists for.
    An ERROR-severity gate that silently passes them is the failure mode this
    tool was written to remove from the semgrep rule it replaced.
    """

    @pytest.mark.parametrize(
        "body,expected_name,expected_line",
        [
            ("    memset(secret_key,\n           0,\n           32);", "secret_key", 3),
            ("    memset(\n        ctx->hmac_key,\n        0,\n        32);", "hmac_key", 3),
            (
                "    memset(keys[i].signing_key,\n           0x00,\n           32);",
                "signing_key",
                3,
            ),
            ("    memset(&kp_local,\n           '\\0',\n           8);", "kp_local", 3),
            (
                "    memset\n        (master_seed, 0,\n         64);",
                "master_seed",
                3,
            ),
        ],
    )
    def test_wrapped_call_is_flagged(
        self, tmp_path: Path, body: str, expected_name: str, expected_line: int
    ) -> None:
        path = _write(tmp_path, f"#include <string.h>\nvoid f(void) {{\n{body}\n}}\n")
        findings = gate.audit([path])
        assert len(findings) == 1, f"expected exactly one finding for:\n{body}"
        assert findings[0].dst == expected_name
        # The reported line is the line the call STARTS on, in the original
        # text — blanking preserves offsets precisely so this stays true.
        assert findings[0].line_no == expected_line

    def test_wrapped_call_across_a_comment_is_flagged(self, tmp_path: Path) -> None:
        """Blanking a comment must not break the call that straddles it."""
        body = (
            "#include <string.h>\n"
            "void f(void) {\n"
            "    memset(secret_key, /* scrub the expanded key */\n"
            "           0,\n"
            "           32);\n"
            "}\n"
        )
        findings = gate.audit([_write(tmp_path, body)])
        assert len(findings) == 1
        assert findings[0].dst == "secret_key"
        assert findings[0].line_no == 3

    def test_multi_line_comment_still_suppresses(self, tmp_path: Path) -> None:
        """The wrapped shape inside a comment is still prose, not code."""
        body = (
            "#include <string.h>\n"
            "/* Never write\n"
            "     memset(secret_key,\n"
            "            0,\n"
            "            32);\n"
            "   — use ama_secure_memzero. */\n"
            "void f(void) { ama_secure_memzero(secret_key, 32); }\n"
        )
        assert gate.audit([_write(tmp_path, body)]) == []

    def test_line_numbers_survive_earlier_blanking(self, tmp_path: Path) -> None:
        """Offsets are preserved, so a long preamble cannot shift the report."""
        preamble = "/*\n" + " * filler\n" * 40 + " */\n"
        body = (
            preamble + 'static const char *S = "x";\nvoid f(void) {\n    memset(sk_buf, 0, 8);\n}\n'
        )
        findings = gate.audit([_write(tmp_path, body)])
        assert len(findings) == 1
        expected = body.splitlines().index("    memset(sk_buf, 0, 8);") + 1
        assert findings[0].line_no == expected
        assert findings[0].text.strip() == "memset(sk_buf, 0, 8);"


class TestLiteralsDoNotHideCode:
    """String literals are blanked; character literals are not.

    A string containing ``//`` used to swallow the rest of the line under the
    per-line ``re.sub(r"//.*$", "", line)``, so a real violation after it on the
    same line was a silent miss.  A character literal, by contrast, carries one
    of the three spellings of the zero this rule matches (``'\\0'``) and must
    survive intact.
    """

    @pytest.mark.parametrize(
        "line",
        [
            '    puts("a//b"); memset(secret_key, 0, 32);',
            '    puts("/* not a comment */"); memset(secret_key, 0, 32);',
            "    c = '\"'; memset(secret_key, 0, 32);",
            "    c = '\\\\'; memset(secret_key, 0, 32);",
        ],
    )
    def test_literal_does_not_swallow_a_following_call(self, tmp_path: Path, line: str) -> None:
        path = _write(tmp_path, f"#include <string.h>\nvoid f(void) {{\n{line}\n}}\n")
        findings = gate.audit([path])
        assert len(findings) == 1, f"the gate failed open on: {line}"
        assert findings[0].dst == "secret_key"

    def test_call_shaped_string_literal_is_not_code(self, tmp_path: Path) -> None:
        body = (
            "#include <string.h>\n"
            "void f(void) {\n"
            '    log_it("memset(secret_key, 0, 32);");\n'
            "}\n"
        )
        assert gate.audit([_write(tmp_path, body)]) == []

    def test_escaped_quote_does_not_end_the_string(self, tmp_path: Path) -> None:
        body = (
            "#include <string.h>\n"
            "void f(void) {\n"
            '    log_it("he said \\" memset(secret_key, 0, 32); \\"");\n'
            "}\n"
        )
        assert gate.audit([_write(tmp_path, body)]) == []

    def test_backslash_continued_line_comment_stays_a_comment(self, tmp_path: Path) -> None:
        """C splices ``\\``-newline before comments are recognised (C11 5.1.1.2)."""
        body = (
            "#include <string.h>\n"
            "void f(void) {\n"
            "    // this comment continues: \\\n"
            "    memset(secret_key, 0, 32);\n"
            "}\n"
        )
        assert gate.audit([_write(tmp_path, body)]) == []

    def test_blanking_preserves_length_and_lines(self) -> None:
        """The offset->line mapping depends on this exactly."""
        text = 'a "str" b\n' "/* block\n" "   comment */ c\n" "// line comment\n" "d '\\0' e\n"
        blanked = gate.blank_comments_and_literals(text)
        assert len(blanked) == len(text)
        assert blanked.count("\n") == text.count("\n")
        for original, produced in zip(text.splitlines(), blanked.splitlines()):
            assert len(original) == len(produced)


class TestRemediationHintCompiles:
    """The suggested call must name the destination as the source writes it.

    ``dst`` is the trailing identifier — the right thing to match a naming
    convention against, and the wrong thing to paste into a fix.
    ``ama_secure_memzero(hmac_key, LEN)`` does not compile at a site whose
    destination is ``ctx->hmac_key``.
    """

    @pytest.mark.parametrize(
        "line,expected_target",
        [
            ("    memset(secret_key, 0, 32);", "secret_key"),
            ("    memset(ctx->hmac_key, 0, 32);", "ctx->hmac_key"),
            ("    memset(st.master_seed, 0, 64);", "st.master_seed"),
            ("    memset(keys[i].signing_key, 0, 32);", "keys[i].signing_key"),
            ("    memset(round_keys[r], 0, 16);", "round_keys[r]"),
            ("    memset(&kp_local, 0, sizeof(kp_local));", "&kp_local"),
            ("    memset( & kp_local , 0, 8);", "&kp_local"),
            ("    memset(s->t[i].u->private_scalar, 0, 32);", "s->t[i].u->private_scalar"),
        ],
    )
    def test_hint_uses_the_full_destination_expression(
        self, tmp_path: Path, line: str, expected_target: str
    ) -> None:
        path = _write(tmp_path, f"#include <string.h>\nvoid f(void) {{\n{line}\n}}\n")
        findings = gate.audit([path])
        assert len(findings) == 1, line
        assert findings[0].target == expected_target
        assert f"ama_secure_memzero({expected_target}, LEN)" in findings[0].render()

    def test_findings_without_an_expression_fall_back_to_the_name(self) -> None:
        """A Finding built by hand (older callers, tests) still renders."""
        bare = gate.Finding(Path("x.c"), 1, "secret_key", "memset(secret_key, 0, 8);")
        assert bare.target == "secret_key"
        assert "ama_secure_memzero(secret_key, LEN)" in bare.render()


class TestScopeAndFailClosed:
    def test_vendor_tree_is_excluded(self) -> None:
        """Third-party code is out of scope; first-party code is not."""
        scanned = gate.c_sources()
        assert scanned, "the scan found no C sources at all"
        assert not any("vendor" in p.parts for p in scanned)
        names = {p.name for p in scanned}
        assert "ama_consttime.c" in names
        assert "ama_kyber.c" in names

    def test_c_test_tree_is_in_scope(self) -> None:
        """tests/c is scanned, not merely described as scanned.

        The module docstring said "tests are deliberately in scope" while the
        walk only ever visited ``src/c``.  Two real matches sat in ``tests/c``
        unreported for as long as that was true.  This is the assertion that
        makes the sentence enforceable: if the second root is ever dropped,
        the gate stops reporting on the test tree and this fails.
        """
        scanned = gate.c_sources()
        test_tree = REPO_ROOT / "tests" / "c"
        from_tests = [p for p in scanned if test_tree in p.parents]
        assert from_tests, "tests/c/ contributed no files to the scan"
        names = {p.name for p in from_tests}
        assert "test_dudect.c" in names
        assert "test_secp256k1.c" in names

    def test_both_roots_are_walked(self) -> None:
        """Neither root may quietly stand in for the other."""
        roots = gate.scan_roots()
        assert gate.C_ROOT in roots
        assert gate.TEST_C_ROOT in roots
        for root in roots:
            assert gate.c_sources(root), f"no C sources found under {root}"

    def test_missing_file_argument_is_a_usage_error(self, tmp_path: Path) -> None:
        assert gate.main([str(tmp_path / "does-not-exist.c")]) == 2

    def test_empty_scan_fails_closed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A scan that finds no sources is an error, never a silent pass."""
        empty = tmp_path / "empty_src"
        empty.mkdir()
        monkeypatch.setattr(gate, "C_ROOT", empty)
        assert gate.main([]) == 2

    def test_empty_test_root_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty tests/c is an error too, even though src/c is populated.

        Checking only the union would let one whole tree silently drop out of
        the scan and still report a clean run on the strength of the other.
        """
        empty = tmp_path / "empty_tests_c"
        empty.mkdir()
        monkeypatch.setattr(gate, "TEST_C_ROOT", empty)
        assert gate.main([]) == 2

    def test_missing_test_root_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tests/c that is not there at all is an error, not a skip."""
        monkeypatch.setattr(gate, "TEST_C_ROOT", tmp_path / "absent")
        assert gate.main([]) == 2


class TestRealTree:
    def test_repository_is_clean(self) -> None:
        """The shipped C sources use ama_secure_memzero for secret scrubbing."""
        findings = gate.audit()
        assert findings == [], "\n".join(f.render() for f in findings)


class TestZeroValueAndDestinationSpellings:
    """Every value and destination form the gate must recognise.

    This tool is the SOLE enforcement of INVARIANT-6 — the module docstring
    records that the semgrep counterpart does not run and cannot be made to —
    so a form it does not recognise is a complete bypass of an ERROR-severity
    control, not a partial one.

    The class used to be named ``TestSpellingsThatUsedToSlipPast`` and its
    docstring said "All were verified as 0-finding on the gate as it stood".
    That is false for most of the corpus.  Measured by running the gate as it
    stood at the PR head (3baf6c3) over these two tables:

      ZERO_SPELLINGS, already flagged (9 of 16):
          0, 0x00, 0X00, 0x0000, 0U, 0u, 0L, 0UL, '\0'
      ZERO_SPELLINGS, silently missed (7):
          00, 000, 00U, (0), ( 0 ), (0U), (0x00)

      DESTINATION_FORMS, already flagged (5 of 11):
          secret_key, &round_keys, ctx->hmac_key, (void *)ctx->hmac_key,
          round_keys[i]
      DESTINATION_FORMS, silently missed (6):
          (secret_key), secret_key + 4, secret_key - 4,
          secret_key  +  OFFSET, ctx->hmac_key + 8, round_keys[i] + 2

    The already-flagged rows are regression guards — they are why the octal
    and parenthesised additions can be made without quietly dropping a form
    that used to be caught.  Only the second list of each pair was ever a
    silent bypass, and the name and docstring now say so.

    Both directions are asserted for every form the value group exists to
    cover, because a gate that flags more is only an improvement if it still
    flags nothing it should not.
    """

    #: The forms whose recognition this branch ADDED.  Measured, not assumed:
    #: see the class docstring for the command and the split.
    NEWLY_CLOSED_ZERO_SPELLINGS = frozenset({"00", "000", "00U", "(0)", "( 0 )", "(0U)", "(0x00)"})
    NEWLY_CLOSED_DESTINATION_FORMS = frozenset(
        {
            "(secret_key)",
            "secret_key + 4",
            "secret_key - 4",
            "secret_key  +  OFFSET",
            "ctx->hmac_key + 8",
            "round_keys[i] + 2",
        }
    )

    def test_the_newly_closed_lists_are_subsets_of_the_corpus(self) -> None:
        """The docstring's split must describe THESE tables, not a stale copy.

        Without this the two frozensets are prose in another font: an entry
        renamed in the corpus would leave the "newly closed" claim naming a
        form the suite no longer drives.
        """
        assert self.NEWLY_CLOSED_ZERO_SPELLINGS <= set(self.ZERO_SPELLINGS)
        assert self.NEWLY_CLOSED_DESTINATION_FORMS <= {
            form for form, _expected in self.DESTINATION_FORMS
        }
        assert len(self.NEWLY_CLOSED_ZERO_SPELLINGS) < len(self.ZERO_SPELLINGS), (
            "the class claims part of the corpus was already flagged; if every "
            "entry is newly closed the docstring's split is wrong"
        )

    ZERO_SPELLINGS = (
        "0",
        "0x00",
        "0X00",
        "0x0000",
        "0U",
        "0u",
        "0L",
        "0UL",
        "00",
        "000",
        "00U",
        "(0)",
        "( 0 )",
        "(0U)",
        "(0x00)",
        r"'\0'",
    )

    NON_ZERO_SPELLINGS = (
        "1",
        "0x10",
        "0xff",
        "1U",
        "n",
        "sizeof(x)",
        "'a'",
    )

    @pytest.mark.parametrize("value", ZERO_SPELLINGS)
    def test_every_zero_spelling_is_flagged(self, value: str) -> None:
        findings = gate.scan_text(f"memset(secret_key, {value}, 32);", _INLINE)
        assert len(findings) == 1, f"memset(secret_key, {value}, 32) was not flagged"
        assert findings[0].dst == "secret_key"

    @pytest.mark.parametrize("value", NON_ZERO_SPELLINGS)
    def test_no_non_zero_spelling_is_flagged(self, value: str) -> None:
        assert (
            gate.scan_text(f"memset(secret_key, {value}, 32);", _INLINE) == []
        ), f"memset(secret_key, {value}, 32) is not a zeroing call and must not be flagged"

    DESTINATION_FORMS = (
        ("secret_key", "secret_key"),
        ("(secret_key)", "secret_key"),
        ("&round_keys", "round_keys"),
        ("ctx->hmac_key", "hmac_key"),
        ("(void *)ctx->hmac_key", "hmac_key"),
        ("round_keys[i]", "round_keys"),
        ("secret_key + 4", "secret_key"),
        ("secret_key - 4", "secret_key"),
        ("secret_key  +  OFFSET", "secret_key"),
        ("ctx->hmac_key + 8", "hmac_key"),
        ("round_keys[i] + 2", "round_keys"),
    )

    @pytest.mark.parametrize("expression,expected", DESTINATION_FORMS)
    def test_destination_forms_resolve_to_the_object(self, expression: str, expected: str) -> None:
        findings = gate.scan_text(f"memset({expression}, 0, 32);", _INLINE)
        assert len(findings) == 1, f"memset({expression}, 0, 32) was not flagged"
        assert findings[0].dst == expected, (
            f"memset({expression}, ...) resolved to {findings[0].dst!r}; the "
            f"destination names {expected!r}, and resolving to anything else "
            f"means the secret-name test is applied to the wrong identifier"
        )

    def test_pointer_arithmetic_does_not_resolve_to_the_offset(self) -> None:
        """The specific mis-resolution: `secret_key + 4` used to name `4`."""
        assert gate._destination_name("secret_key + 4") == "secret_key"
        assert gate._destination_name("ctx->hmac_key + 8") == "hmac_key"

    def test_a_non_secret_destination_with_an_offset_is_still_clean(self) -> None:
        assert gate.scan_text("memset(buffer + 4, 0, 28);", _INLINE) == []


class TestMemsetBehindAMacro:
    """A function-like macro wrapping memset was a total bypass.

    The call site carries no ``memset`` token, so the token-anchored
    ``\bmemset\\s*\\(`` could not see it at all.  Verified on the gate as it
    stood: ``scan_text('#define CLR(x) memset((x),0,sizeof(x))\nCLR(secret_key);')``
    returned zero findings — the definition targets the non-secret parameter
    ``x`` and the call site carries no ``memset``.
    """

    def test_wrapper_macro_call_site_is_flagged(self) -> None:
        findings = gate.scan_text(
            "#define CLR(x) memset((x),0,sizeof(x))\nCLR(secret_key);", _INLINE
        )
        assert len(findings) == 1
        assert findings[0].dst == "secret_key"
        assert findings[0].line_no == 2, "the CALL SITE is the finding, not the #define"

    def test_the_flagged_parameter_is_the_one_the_body_zeroes(self) -> None:
        """A macro whose memset target is its SECOND parameter."""
        findings = gate.scan_text(
            "#define WIPE(n, p) memset((p), 0, (n))\nWIPE(32, secret_key);", _INLINE
        )
        assert len(findings) == 1
        assert findings[0].dst == "secret_key"

    def test_a_nested_comma_does_not_shift_the_parameter_mapping(self) -> None:
        findings = gate.scan_text(
            "#define CLR(x) memset((x),0,sizeof(x))\nCLR(round_keys[f(1, 2)]);", _INLINE
        )
        assert len(findings) == 1
        assert findings[0].dst == "round_keys"

    def test_a_multiline_macro_body_is_read(self) -> None:
        text = (
            "#define CLR(x) do { \\\n"
            "    memset((x), 0, sizeof(x)); \\\n"
            "} while (0)\n"
            "CLR(secret_key);"
        )
        findings = gate.scan_text(text, _INLINE)
        assert len(findings) == 1
        assert findings[0].dst == "secret_key"

    def test_an_object_like_alias_is_flagged(self) -> None:
        findings = gate.scan_text("#define CLR memset\nCLR(secret_key, 0, 32);", _INLINE)
        assert len(findings) == 1
        assert findings[0].dst == "secret_key"

    def test_an_alias_called_with_a_non_zero_value_is_not_flagged(self) -> None:
        assert gate.scan_text("#define CLR memset\nCLR(secret_key, 0xff, 32);", _INLINE) == []

    def test_a_macro_that_does_not_zero_is_not_flagged(self) -> None:
        assert (
            gate.scan_text("#define FILL(x) memset((x),0xff,sizeof(x))\nFILL(secret_key);", _INLINE)
            == []
        )

    def test_a_wrapper_called_with_a_non_secret_is_not_flagged(self) -> None:
        assert (
            gate.scan_text("#define CLR(x) memset((x),0,sizeof(x))\nCLR(plaintext);", _INLINE) == []
        )

    def test_an_undefined_macro_name_is_not_flagged(self) -> None:
        """No definition in this text: nothing is known to wrap memset."""
        assert gate.scan_text("CLR(secret_key);", _INLINE) == []

    def test_the_definition_line_is_not_reported_as_a_call(self) -> None:
        findings = gate.scan_text("#define CLR(x) memset((x),0,sizeof(x))", _INLINE)
        assert findings == []


class TestZeroingMacroScopeAndArity:
    """Three ways the macro table let a call site through, or flagged a fixed one.

    The table maps a function-like macro that bare-memsets one of its own
    parameters to the argument index that parameter occupies, so a call site
    naming a secret in that position is a finding.  As first written it had no
    arity and no preprocessor scope.
    """

    def test_a_macro_that_wipes_two_parameters_maps_both(self) -> None:
        """The collector ``break``ed on the first memset in the body.

        With a single ``{name: macro}`` lookup on top of that, only one index
        per name could ever be tested — every other argument at every call
        site was a complete bypass, for exactly the macros that do the most
        zeroing.  Measured before the fix: one finding, ``first_key``.
        """
        text = """
#define WIPE2(a, b) do { memset((a), 0, 32); memset((b), 0, 32); } while (0)
void f(void) {
    unsigned char first_key[32], second_key[32];
    WIPE2(first_key, second_key);
}
"""
        found = {finding.dst for finding in gate.scan_text(text, Path("probe.c"))}
        assert found == {"first_key", "second_key"}, found

    def test_undef_cancels_the_definition(self) -> None:
        """``#undef`` was invisible, so a remediated file still reported.

        Measured before the fix: one finding, ``secret_key`` — an
        ERROR-severity report on code that had already been fixed.
        """
        text = """
#define WIPE(a) memset((a), 0, 32)
#undef WIPE
#define WIPE(a) ama_secure_memzero((a), 32)
void f(void) {
    unsigned char secret_key[32];
    WIPE(secret_key);
}
"""
        assert gate.scan_text(text, Path("probe.c")) == []

    def test_a_non_zeroing_redefinition_supersedes(self) -> None:
        """A redefinition that does not zero simply added no entry.

        The original definition therefore stayed in force for the whole file.
        Measured before the fix: one finding, ``secret_key``.
        """
        text = """
#define WIPE(a) memset((a), 0, 32)
#define WIPE(a) ama_secure_memzero((a), 32)
void f(void) {
    unsigned char secret_key[32];
    WIPE(secret_key);
}
"""
        assert gate.scan_text(text, Path("probe.c")) == []

    def test_a_call_site_before_the_define_is_not_matched(self) -> None:
        """Control: scope cuts both ways, and the common case still reports."""
        text = """
void early(void) {
    unsigned char secret_key[32];
    WIPE(secret_key);
}
#define WIPE(a) memset((a), 0, 32)
void late(void) {
    unsigned char secret_key[32];
    WIPE(secret_key);
}
"""
        findings = gate.scan_text(text, Path("probe.c"))
        assert len(findings) == 1, [f.render() for f in findings]
        assert findings[0].line_no > 6, findings[0].line_no

    def test_unclosed_parentheses_stay_linear(self) -> None:
        r"""The call-site scan was O(N * filesize) on unbalanced parentheses.

        Every match of ``NAME\s*\(`` walked forward to the matching ``)`` and,
        when there was none, to end of file.  Measured before the fix on this
        exact input: 1594 ms / 6378 ms / 24828 ms at N = 2000 / 4000 / 8000 —
        4x per doubling.  After: 7.6 / 14.6 / 30.0 ms, 2x per doubling.

        This module's linearity is a stated, tested discipline (see
        ``TestPatternIsLinear``); the helper the call-site pass added had no
        case there, so the regression this file has already suffered twice was
        reintroduced in the one code path that was new.
        """
        import time

        timings = []
        for count in (2000, 4000):
            text = "#define WIPE(a) memset((a), 0, 32)\n" + "WIPE(secret_key\n" * count
            start = time.perf_counter()
            gate.scan_text(text, Path("probe.c"))
            timings.append(time.perf_counter() - start)
        assert timings[0] < 1.0, f"N=2000 took {timings[0]:.2f}s"
        growth = timings[1] / max(timings[0], 1e-6)
        assert growth < 3.0, (
            f"doubling the input multiplied the time by {growth:.2f} — linear is "
            f"~2.0x; the forward scan has regained its quadratic form"
        )


#: Rounds inside one linearity measurement.  Each round scans every size once,
#: and each size's estimate is the floor over the rounds.
_LINEARITY_ROUNDS = 7

#: Independent measurements before the test is allowed to fail.  See
#: :meth:`TestPatternIsLinear.test_growth_is_linear_not_merely_fast` for why
#: repeating sharpens the discrimination rather than loosening it.
_LINEARITY_ATTEMPTS = 3

#: Linear growth is ~2x per doubling, quadratic ~4x.  The gap is wide enough
#: that residual noise in a floor timing cannot cross it.
_LINEARITY_CEILING = 2.8


class TestPatternIsLinear:
    r"""The scanner must not be the thing that hangs CI.

    The first draft of ``_MEMSET_RE`` had two nullable quantifiers in sequence
    (``\\(\\s*&?\\s*``) and a starred group whose alternatives each began with
    ``\\s*``.  Both make the number of ways to split a run of whitespace grow
    with its length, so a line that enters the match and then fails backtracked
    polynomially — 16,000 spaces cost two seconds.  CodeQL flagged it, and this
    pins the fix.
    """

    def test_whitespace_run_does_not_blow_up(self) -> None:
        import time

        # Enters `memset(` then fails: the worst case for a backtracking engine.
        pathological = "memset(" + " " * 200_000 + "x"
        start = time.perf_counter()
        gate._MEMSET_RE.search(pathological)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"matching 200k spaces took {elapsed:.2f}s — the pattern has "
            f"regained polynomial backtracking"
        )

    def test_cast_group_whitespace_does_not_blow_up(self) -> None:
        """The cast group added for destination casts reintroduced the ReDoS.

        ``(?:\\(\\s*[A-Za-z_][A-Za-z0-9_ \\t]*\\**\\s*\\))?`` let the identifier
        class match whitespace and then handed the same run to ``\\s*`` before
        the closing paren, so a failing cast split a whitespace run in O(N)
        ways: measured 4x per doubling, 32k chars taking 7.7 s — enough to
        hang the CI step this gate runs in, which is the outcome the rest of
        this class exists to prevent.  Both whitespace shapes are driven here
        because they backtrack through different quantifiers.
        """
        import time

        for pathological in (
            "memset((void" + " \t" * 100_000 + "Y",
            "memset((a" + " " * 200_000 + "X",
        ):
            start = time.perf_counter()
            gate._MEMSET_RE.search(pathological)
            elapsed = time.perf_counter() - start
            assert elapsed < 1.0, (
                f"a failing cast over {len(pathological)} chars took "
                f"{elapsed:.2f}s — the cast group has regained backtracking"
            )

    @pytest.mark.parametrize(
        "prefix",
        [
            "memset((void",  # a failing cast
            "memset(secret_key +",  # a failing destination offset
            "memset(secret_key, ",  # a failing value
        ],
    )
    def test_growth_is_linear_not_merely_fast(self, prefix: str) -> None:
        """Ratio, not a wall-clock ceiling — and a floor, not a single sample.

        A wall-clock threshold passes a quadratic pattern on a fast runner and
        fails a linear one on a loaded shared runner — this file already
        carries two such thresholds, and the ReDoS they were written for was
        reintroduced twice regardless.  Doubling the input and asserting the
        time roughly doubles measures the property directly and is
        host-independent.

        Each size is timed as the fastest of seven runs, not once.
        Interference on a shared runner is one-sided — it can only make a
        scan look slower, never faster — so the minimum is the estimate of
        the machine's actual cost, the same estimator
        benchmarks/benchmark_runner.py uses for the same reason.  A single
        sample per size failed a genuinely linear pattern on the shared
        macOS runner at 3.60x and 2.89x (job 97259726006: one inflated
        middle sample poisons both ratios it appears in), while the
        pattern's floor doubles like it should; a quadratic pattern's floor
        still quadruples, so the discrimination the ceiling relies on is
        sharpened, not loosened.

        The runs are interleaved by ROUND — each round scans every size
        once — rather than exhausting one size's repeats back to back.
        Back-to-back repeats of one size all complete inside ~2 ms, so a
        contention burst longer than that cluster inflates every sample the
        minimum is drawn from while leaving the neighbouring size's floor
        clean, and the ratio breaks even though every individual sample
        obeyed the one-sided model: measured on a 4-core host under full
        synthetic saturation, the clustered form failed 2 of 6 runs.  A
        burst that spans one interleaved round slows every size in that
        round together — ratio-neutral — and each size's floor is then the
        minimum over seven temporally separated rounds.  The same
        saturation experiment on this form: 0 failures.

        The ceiling is 2.8x rather than 2.0x because even floor timings
        carry residual noise; quadratic growth is 4x and cubic 8x, so the
        gap is wide enough to discriminate.  Measured here at the time of
        writing: 1.71-2.07x across all three shapes.

        Interleaving was still not enough.  The macOS 3.14 lane read 2.94x
        for the failing-value shape on a commit that changed neither the
        pattern nor this gate, and the same measurement had been green on
        that runner one commit earlier -- so the code under test was
        bit-identical across the two outcomes.  Reproduced here: 1 failure
        in 8 runs under full synthetic saturation.  Interleaving equalises
        WHEN each size is sampled but not how LONG each sample is exposed,
        and the largest payload's scan is the longest, so a contention
        burst is likeliest to land on it -- a bias that is one-sided in
        exactly the direction that breaks the ratio.

        So the whole measurement is repeated, up to
        :data:`_LINEARITY_ATTEMPTS` times, and the test passes as soon as
        one comes back under the ceiling.  This sharpens the check rather
        than loosening it, and the one-sided noise model is why: noise can
        only ever inflate a sample, the floor over a round already discards
        all but the least-disturbed one, and a further measurement can only
        move each size's floor DOWN, towards its true cost.  Both floors
        therefore converge on truth as attempts accumulate, and the ratio
        converges on the pattern's real growth -- ~2x for a linear pattern
        and ~4x for a quadratic one.  A quadratic pattern cannot be
        retried under the ceiling: reaching 2.8x from 4x would need the
        SMALLER size's floor to be overestimated by 30% in every one of
        the attempts, which is the one thing the model forbids.  Measured
        under the same saturation that failed the single-shot form: 0
        failures in 10 runs, against 1 in 8 before.

        The other direction was checked by planting nested quantifiers in
        the value group -- ``0+`` as ``0*0*``, and the bounded
        ``(?:0{1,40})+`` -- and neither produced a ratio any number of
        retries could rescue, because neither COMPLETES: both ran past a
        300-second timeout at the sizes this test uses, and past it again
        at 2^8-2^10.  That is the honest shape of the discrimination here.
        A pattern that has lost linearity does not land just over the
        ceiling where a retry might reach it; it hangs, and what catches
        it is the absolute-time bound at the top of this class, which is
        1 second for 200,000 characters.  This ratio test guards the
        narrower case of growth that is superlinear but still fast, and
        for that case the retry costs nothing and removes the false
        positives.
        """
        import time

        pad = " " if not prefix.endswith(", ") else "0"
        payloads = [prefix + pad * (2**exponent) for exponent in (14, 15, 16)]

        def worst_ratio() -> float:
            """Largest adjacent floor ratio from one full interleaved measurement."""
            timings = [float("inf")] * len(payloads)
            for _ in range(_LINEARITY_ROUNDS):
                for index, payload in enumerate(payloads):
                    start = time.perf_counter()
                    gate.scan_text(payload, _INLINE)
                    timings[index] = min(timings[index], time.perf_counter() - start)
            return max(
                (
                    larger / smaller
                    for smaller, larger in itertools.pairwise(timings)
                    # A pair whose smaller side is too fast to measure a ratio from.
                    if smaller >= 1e-4
                ),
                default=0.0,
            )

        best = float("inf")
        for _ in range(_LINEARITY_ATTEMPTS):
            best = min(best, worst_ratio())
            if best < _LINEARITY_CEILING:
                return

        raise AssertionError(
            f"doubling the input multiplied the floor time by {best:.2f}x — the best "
            f"of {_LINEARITY_ATTEMPTS} independent measurements, each the fastest of "
            f"{_LINEARITY_ROUNDS} interleaved rounds per size — for {prefix!r}; linear "
            f"is ~2x and quadratic is ~4x, so the pattern has regained polynomial "
            f"backtracking"
        )

    def test_casts_the_gate_exists_for_still_match(self) -> None:
        """Linearity must not have cost the bypasses the cast group closed."""
        for line in (
            "memset((void*)ctx->secret_key, 0, 32);",
            "memset((void *)ctx->secret_key, 0, 32);",
            "memset((unsigned char *)kp.signing_key, 0, 32);",
            "memset((uint8_t *)&kp.signing_key, 0, 32);",
        ):
            assert gate._MEMSET_RE.search(line), line

    def test_member_chain_does_not_blow_up(self) -> None:
        import time

        pathological = "memset(" + "a->" * 50_000 + "!"
        start = time.perf_counter()
        gate._MEMSET_RE.search(pathological)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"matching a 50k-link member chain took {elapsed:.2f}s"

    def test_spacing_variants_still_match(self) -> None:
        """Linearity must not have cost the shapes the gate is for."""
        for line, expected in [
            ("memset(secret_key, 0, 32);", "secret_key"),
            ("memset( secret_key , 0 , 32 );", "secret_key"),
            ("memset(&kp_local, 0, 8);", "kp_local"),
            ("memset( & kp_local , 0, 8);", "kp_local"),
            ("memset(ctx->hmac_key, 0, 32);", "hmac_key"),
            ("memset(keys[i].signing_key, 0, 32);", "signing_key"),
        ]:
            match = gate._MEMSET_RE.search(line)
            assert match is not None, f"no match for: {line}"
            assert gate._destination_name(match.group("dst")) == expected, line

    @pytest.mark.parametrize("filler", ["[", "]", "a[b"])
    def test_destination_name_does_not_blow_up(self, filler: str) -> None:
        """``_destination_name`` is linear too, on unbalanced input included.

        The helper first stripped subscripts with ``re.sub(r"\\[[^\\]]*\\]", …)``.
        That is linear on the balanced expressions ``_MEMSET_RE`` produces, but
        each unmatched ``[`` makes the engine rescan to end-of-string looking
        for a ``]``, so 100,000 of them cost 5.5 s.  The helper is module-level
        and takes a plain string; nothing stops a caller handing it that.
        """
        import time

        pathological = filler * 100_000
        start = time.perf_counter()
        gate._destination_name(pathological)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"extracting from 100k {filler!r} took {elapsed:.2f}s — the helper "
            f"has regained superlinear behaviour"
        )

    @pytest.mark.parametrize(
        "expression,expected",
        [
            # Shapes _MEMSET_RE can produce: subscripts skipped, last
            # depth-0 identifier wins.
            ("secret_key", "secret_key"),
            ("ctx->hmac_key", "hmac_key"),
            ("st.master_seed", "master_seed"),
            ("round_keys[i]", "round_keys"),
            ("keys[i].signing_key", "signing_key"),
            ("s->t[i].u->private_scalar", "private_scalar"),
            ("x[y[z]].key_material", "key_material"),  # nested subscript
            ("tbl[i][j]", "tbl"),
            ("a[b[c]d]e", "e"),
            # Shapes only a direct caller can produce.  The scan tracks depth
            # rather than deleting bracket pairs, so an unterminated subscript
            # no longer returns the INDEX variable (`a[b` gave `b` before), and
            # text is never spliced across a removed pair (`a[b]c` gave `ac`,
            # an identifier that appears nowhere in the input).
            ("a[b", "a"),
            ("a[b]c", "c"),
            ("[a", ""),
            ("", ""),
        ],
    )
    def test_destination_name_extraction(self, expression: str, expected: str) -> None:
        assert gate._destination_name(expression) == expected
