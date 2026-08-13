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
