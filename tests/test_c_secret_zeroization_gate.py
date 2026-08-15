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

from pathlib import Path

import pytest

from tools import check_c_secret_zeroization as gate

REPO_ROOT = Path(__file__).resolve().parent.parent


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

    def test_missing_file_argument_is_a_usage_error(self, tmp_path: Path) -> None:
        assert gate.main([str(tmp_path / "does-not-exist.c")]) == 2

    def test_empty_scan_fails_closed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A scan that finds no sources is an error, never a silent pass."""
        empty = tmp_path / "empty_src"
        empty.mkdir()
        monkeypatch.setattr(gate, "C_ROOT", empty)
        assert gate.main([]) == 2


class TestRealTree:
    def test_repository_is_clean(self) -> None:
        """The shipped C sources use ama_secure_memzero for secret scrubbing."""
        findings = gate.audit()
        assert findings == [], "\n".join(f.render() for f in findings)


class TestPatternIsLinear:
    """The scanner must not be the thing that hangs CI.

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
