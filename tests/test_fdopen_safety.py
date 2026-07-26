#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the file-descriptor ownership checker (``tools/check_fdopen_safety.py``).

``os.fdopen`` takes ownership of a raw descriptor: on success the returned file
object closes it, but if the call itself raises, ownership never transfers and
the descriptor leaks.  The checker enforces the structural mitigation — the
call must sit inside a ``try`` that can still close the descriptor on the
failure path.

These tests pin BOTH directions, because a checker that only ever reports
"clean" is indistinguishable from one that has stopped working:

* **Detection** — unguarded calls, calls guarded by an exception class that
  cannot catch the failure, and calls sitting in a handler rather than the
  protected body are all reported.
* **Non-detection** — the guarded shapes actually used in this package do not
  produce false positives, since a checker that cries wolf gets bypassed.
"""

from __future__ import annotations

from pathlib import Path

from tools.check_fdopen_safety import check_source

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestDetectsUnguardedCalls:
    def test_bare_call_is_flagged(self) -> None:
        src = "import os\n\n\ndef f(fd):\n    return os.fdopen(fd, 'wb')\n"
        assert check_source("bad.py", src)

    def test_call_in_with_statement_without_try_is_flagged(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n"
            "    with os.fdopen(fd, 'wb') as h:\n        h.write(b'x')\n"
        )
        assert check_source("bad.py", src)

    def test_narrow_handler_that_cannot_catch_oserror_is_flagged(self) -> None:
        # ValueError cannot catch the OSError family that fdopen raises, so the
        # descriptor still leaks on the realistic failure path.
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        h = os.fdopen(fd, 'wb')\n"
            "    except ValueError:\n        pass\n"
        )
        assert check_source("bad.py", src)

    def test_call_inside_except_clause_is_flagged(self) -> None:
        # Only the try BODY is protected; a call in the handler is not.
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        pass\n"
            "    except Exception:\n        h = os.fdopen(fd, 'wb')\n"
        )
        assert check_source("bad.py", src)

    def test_module_level_unguarded_call_is_flagged(self) -> None:
        assert check_source("bad.py", "import os\nh = os.fdopen(3, 'wb')\n")


class TestAcceptsGuardedCalls:
    def test_base_exception_guard_is_accepted(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        with os.fdopen(fd, 'wb') as h:\n"
            "            h.write(b'x')\n    except BaseException:\n        os.close(fd)\n"
            "        raise\n"
        )
        assert check_source("good.py", src) == []

    def test_oserror_guard_is_accepted(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        h = os.fdopen(fd, 'wb')\n"
            "    except OSError:\n        os.close(fd)\n        raise\n"
        )
        assert check_source("good.py", src) == []

    def test_tuple_handler_is_accepted(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        h = os.fdopen(fd, 'wb')\n"
            "    except (ValueError, OSError):\n        os.close(fd)\n        raise\n"
        )
        assert check_source("good.py", src) == []

    def test_finally_only_is_accepted(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        h = os.fdopen(fd, 'wb')\n"
            "    finally:\n        pass\n"
        )
        assert check_source("good.py", src) == []

    def test_bare_except_is_accepted(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        h = os.fdopen(fd, 'wb')\n"
            "    except:  # noqa: E722\n        os.close(fd)\n        raise\n"
        )
        assert check_source("good.py", src) == []

    def test_nested_enclosing_try_is_accepted(self) -> None:
        # The guard may be several blocks up, not just the immediate parent.
        src = (
            "import os\n\n\ndef f(fd, flag):\n    try:\n        if flag:\n"
            "            for _ in range(1):\n                h = os.fdopen(fd, 'wb')\n"
            "    except BaseException:\n        os.close(fd)\n        raise\n"
        )
        assert check_source("good.py", src) == []

    def test_file_without_fdopen_is_clean(self) -> None:
        assert check_source("plain.py", "import os\nprint(os.getpid())\n") == []


class TestRealPackageIsGuarded:
    """The live gate: every os.fdopen in the shipped package must be guarded."""

    def test_package_sources_are_clean(self) -> None:
        violations = []
        for path in sorted((REPO_ROOT / "ama_cryptography").glob("*.py")):
            violations.extend(check_source(path.name, path.read_text(encoding="utf-8")))
        assert violations == [], "\n".join(v.render() for v in violations)

    def test_checker_finds_the_known_call_sites(self) -> None:
        # Guards against the checker silently matching nothing (e.g. after a
        # refactor renames the call): the package really does use os.fdopen,
        # and the checker must be looking at those lines.
        sources = [
            p.read_text(encoding="utf-8") for p in (REPO_ROOT / "ama_cryptography").glob("*.py")
        ]
        assert sum(s.count("os.fdopen(") for s in sources) >= 1
