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

import os
import shutil
import subprocess
import sys
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


class TestNothingCheckedIsNotClean:
    """An explicit path the checker cannot read is an error, not a clean run:
    it used to be dropped and the run printed "clean: 0 os.fdopen call
    site(s)"."""

    def test_an_unreadable_explicit_path_is_an_error(self, tmp_path: Path) -> None:
        from tools.check_fdopen_safety import main

        assert main(["--paths", str(tmp_path / "missing.py")]) == 2

    def test_a_readable_clean_path_passes(self, tmp_path: Path) -> None:
        from tools.check_fdopen_safety import main

        clean = tmp_path / "clean.py"
        clean.write_text("x = 1\n", encoding="utf-8")
        assert main(["--paths", str(clean)]) == 0


class TestEverySpellingOfTheCallIsExamined:
    """``_is_fdopen_call`` matched ``<x>.fdopen(...)`` and the literal name
    ``fdopen(...)`` only, so a call through an alias was never examined.
    Each source below is unguarded and was reported clean before the fix."""

    def test_an_import_alias_is_followed(self) -> None:
        src = "from os import fdopen as f\n\n\ndef w(fd):\n    return f(fd, 'wb')\n"
        found = check_source("bad.py", src)
        assert [v.line_no for v in found] == [5], found

    def test_an_assigned_alias_is_followed_through_a_chain(self) -> None:
        src = (
            "import os\nopen_fd = os.fdopen\nagain = open_fd\n\n\n"
            "def w(fd):\n    return again(fd, 'wb')\n"
        )
        assert [v.line_no for v in check_source("bad.py", src)] == [7]

    def test_a_getattr_spelling_is_a_call(self) -> None:
        src = "import os\n\n\ndef w(fd):\n    return getattr(os, 'fdopen')(fd, 'wb')\n"
        assert [v.line_no for v in check_source("bad.py", src)] == [5]

    def test_a_guarded_alias_call_is_accepted(self) -> None:
        """Non-detection: following the alias must not over-report."""
        src = (
            "from os import fdopen as f\n\n\ndef w(fd):\n    try:\n"
            "        return f(fd, 'wb')\n    except BaseException:\n"
            "        os.close(fd)\n        raise\n"
        )
        assert check_source("good.py", src) == []

    def test_an_unrelated_name_is_not_an_alias(self) -> None:
        src = "from io import open as f\n\n\ndef w(fd):\n    return f(fd, 'wb')\n"
        assert check_source("plain.py", src) == []


class TestATryGuardsOnlyWhatRunsInsideIt:
    """A ``try`` around a ``def`` guards the DEFINITION.

    The ancestor walk went straight through the function boundary, so a call
    in a body that runs later — outside any handler — counted as guarded by
    the ``try`` that happened to enclose its ``def``.  Both sources below were
    reported clean before the fix.
    """

    def test_a_try_around_a_def_does_not_guard_its_body(self) -> None:
        src = (
            "import os\ntry:\n    def opener(fd):\n"
            "        return os.fdopen(fd, 'wb')\nexcept OSError:\n    pass\n"
        )
        assert [v.line_no for v in check_source("bad.py", src)] == [4]

    def test_a_try_around_a_lambda_does_not_guard_its_body(self) -> None:
        src = (
            "import os\ntry:\n    opener = lambda fd: os.fdopen(fd, 'wb')\n"
            "except OSError:\n    pass\n"
        )
        assert [v.line_no for v in check_source("bad.py", src)] == [3]

    def test_a_generator_element_runs_when_iterated_not_when_built(self) -> None:
        src = (
            "import os\ntry:\n    handles = (os.fdopen(fd) for fd in (3, 4))\n"
            "except OSError:\n    pass\n"
        )
        assert [v.line_no for v in check_source("bad.py", src)] == [3]

    def test_the_eager_parts_of_a_deferred_scope_are_still_guarded(self) -> None:
        """Non-detection: a default value, and a generator's first iterable,
        are evaluated where they are written, inside the ``try``."""
        src = (
            "import os\ntry:\n    def w(h=os.fdopen(3, 'wb')):\n        return h\n"
            "    lines = (x for x in os.fdopen(4))\nexcept BaseException:\n    raise\n"
        )
        assert check_source("good.py", src) == []

    def test_a_try_inside_the_function_still_guards(self) -> None:
        src = (
            "import os\n\n\ndef f(fd):\n    try:\n        return os.fdopen(fd, 'wb')\n"
            "    except OSError:\n        os.close(fd)\n        raise\n"
        )
        assert check_source("good.py", src) == []


class TestATrackedFileInAnotherEncodingIsParsed:
    """Enumeration mode read every tracked file as UTF-8 and ``continue``d past
    a ``UnicodeDecodeError``: a PEP 263 latin-1 module with an unguarded
    ``os.fdopen`` was never parsed and the run printed "clean".  Driven the
    way CI runs the gate — as a script, over a git repository's tracked files.
    """

    @staticmethod
    def _repo(tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        (repo / "tools").mkdir(parents=True)
        for name in ("__init__.py", "_repo.py", "check_fdopen_safety.py"):
            shutil.copyfile(REPO_ROOT / "tools" / name, repo / "tools" / name)
        (repo / "clean.py").write_text("X = 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        return repo

    @staticmethod
    def _run(repo: Path) -> subprocess.CompletedProcess[str]:
        subprocess.run(["git", "add", "--", "."], cwd=repo, check=True)
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        return subprocess.run(
            [sys.executable, str(repo / "tools" / "check_fdopen_safety.py")],
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            check=False,
        )

    def test_a_declared_latin1_module_is_checked(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        (repo / "legacy.py").write_bytes(
            "# -*- coding: latin-1 -*-\nimport os\nNAME = 'café'\n\n\n"
            "def f(fd):\n    return os.fdopen(fd, 'wb')\n".encode("latin-1")
        )
        proc = self._run(repo)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "legacy.py:7" in proc.stdout

    def test_an_undecodable_module_is_reported_not_skipped(self, tmp_path: Path) -> None:
        """No declaration and not UTF-8: Python cannot import it either, so it
        is a parse failure — never a silent skip."""
        repo = self._repo(tmp_path)
        (repo / "broken.py").write_bytes(
            "import os\nNAME = 'café'\nh = os.fdopen(3)\n".encode("latin-1")
        )
        proc = self._run(repo)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "broken.py" in proc.stdout and "could not parse" in proc.stdout
