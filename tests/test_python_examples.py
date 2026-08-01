# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The shipped Python examples must run.

Why this file exists
--------------------
``examples/python/`` is documentation that executes, and nothing executed it.
Both files under test here were broken in the released tree, in ways no unit
test could see because no unit test imported them:

* ``basic_usage.py`` Examples 3 and 4 called ``legacy_compat``'s package API
  with the wrong keyword names — ``dna_codes=`` and ``pkg=`` against
  parameters actually named ``codes`` and ``package`` — so the script died on
  ``TypeError: create_crypto_package() got an unexpected keyword argument
  'dna_codes'`` after Example 2 had already printed "success".
* ``complete_demo.py`` passed ``numpy.random.randn(100)`` to
  ``AmaEquationEngine.converge()``, which accepted only ``_numeric`` types and
  raised ``ValueError: matmul: Input operand 0 does not have enough
  dimensions`` from four frames down.

Both are the kind of defect that survives indefinitely without an execution
gate, because reading the code does not reveal them.

What is asserted
----------------
Each example is run as a subprocess — the way a user runs it — and must exit
0.  Exit code alone would be a weak gate here: ``basic_usage.main()`` catches
every exception and returns 1, but a future edit could just as easily swallow
one, so each example's own success banner and the specific lines that prove
the fixed sections ran are required in the output too.

``complete_demo.py`` is additionally run with ``numpy`` blocked at import, so
the no-numpy path a default install actually takes is covered rather than
assumed.  The library has no runtime dependencies; an example that only works
with ``numpy`` installed would contradict that.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples" / "python"

#: Examples that talk to the network or start a web server are out of scope
#: for an execution gate; they are listed rather than silently skipped so the
#: exclusion is visible, and the test below fails if one of them disappears or
#: a new example appears without a decision being made about it.
RUNNABLE = ("basic_usage.py", "complete_demo.py")
NOT_RUNNABLE = ("flask_integration.py", "fastapi_integration.py")

#: Generous: complete_demo.py runs SLH-DSA/ML-DSA keygen and 100 engine steps,
#: which is slow on a loaded CI runner.  The point of the ceiling is to fail a
#: hang rather than to measure anything.
TIMEOUT_SECONDS = 900

_BLOCK_NUMPY = """\
import builtins, sys
_real = builtins.__import__


def _blocked(name, *args, **kwargs):
    if name == "numpy" or name.startswith("numpy."):
        raise ImportError("numpy is blocked for this test")
    return _real(name, *args, **kwargs)


builtins.__import__ = _blocked
sys.modules.pop("numpy", None)
"""


def _run_example(
    name: str,
    *,
    block_numpy: bool = False,
    io_encoding: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one example in a subprocess and return the completed process.

    A subprocess rather than ``runpy``: the examples call ``sys.exit()`` and
    mutate ``sys.path``, and running them in-process would let one example's
    imports and warning filters leak into the next test.

    **``PYTHONUTF8`` and ``PYTHONIOENCODING`` are stripped from the child
    environment unconditionally.** Both change how the example's own output is
    encoded, and a gate whose verdict depends on which CI step happened to
    export them is not a gate — it reports the workflow's configuration rather
    than the program's correctness. Removing them here means this module tests
    what a user gets from ``python complete_demo.py`` with no environment
    tuning, in every job that collects it.

    ``io_encoding`` puts one back deliberately, to *reproduce* a legacy output
    encoding rather than to avoid one; see :class:`TestExamplesSurviveALegacyOutputEncoding`.
    """
    script = EXAMPLES / name
    if block_numpy:
        source = (
            f"{_BLOCK_NUMPY}\nimport runpy\nrunpy.run_path({str(script)!r}, run_name='__main__')\n"
        )
        argv = [sys.executable, "-c", source]
    else:
        argv = [sys.executable, str(script)]

    env = dict(os.environ)
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    if io_encoding is not None:
        env["PYTHONIOENCODING"] = io_encoding

    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
        env=env,
    )


def _assert_ran(result: subprocess.CompletedProcess[str], *required: str) -> str:
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"exit={result.returncode}\n{output[-4000:]}"
    for fragment in required:
        assert fragment in output, f"missing {fragment!r} from output:\n{output[-4000:]}"
    return output


class TestExampleInventory:
    def test_every_example_is_classified(self) -> None:
        """A new example must be added to one list or the other, deliberately."""
        on_disk = {path.name for path in EXAMPLES.glob("*.py")}
        classified = set(RUNNABLE) | set(NOT_RUNNABLE)
        assert on_disk == classified, (
            f"unclassified: {sorted(on_disk - classified)}; "
            f"listed but absent: {sorted(classified - on_disk)}"
        )

    @pytest.mark.parametrize("name", NOT_RUNNABLE)
    def test_excluded_examples_at_least_parse(self, name: str) -> None:
        """Not executed, but they must still be syntactically valid Python.

        These start web servers, so running them is out of scope; compiling
        them is not, and a syntax error in shipped documentation should not
        need a human to notice it.
        """
        compile((EXAMPLES / name).read_text(encoding="utf-8"), name, "exec")


class TestBasicUsage:
    def test_runs_to_completion(self) -> None:
        result = _run_example("basic_usage.py")
        _assert_ran(
            result,
            "ALL EXAMPLES COMPLETED SUCCESSFULLY",
            "Example 1: Simple Message Signing",
            "Example 2: Key Management",
            "Example 3: Complete Data Protection",
            "Example 4: Humanitarian Use Case",
        )

    def test_example_3_verifies_anchored_and_reports_the_unanchored_contrast(self) -> None:
        """Example 3 is one of the two that did not run at all before this PR.

        It must reach the anchored verdict, and it must show the unanchored
        one beside it — the 4.0.0 breaking change is that those two differ, and
        an example that only printed the happy path would leave a reader
        expecting ``all_valid`` from an unanchored call.
        """
        output = _assert_ran(
            _run_example("basic_usage.py"),
            "all_valid: PASS",
            "key_pinned: PASS",
        )
        assert "Without an anchor:" in output
        assert "all_valid=False" in output

    def test_example_4_rejects_tampered_content(self) -> None:
        _assert_ran(
            _run_example("basic_usage.py"),
            "Data integrity verified: True",
            "Tampered copy rejected:  True",
        )


class TestCompleteDemo:
    def test_runs_to_completion(self) -> None:
        _assert_ran(
            _run_example("complete_demo.py"),
            "ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY",
            "6. DOUBLE-HELIX EVOLUTION ENGINE",
            "7. PERFORMANCE BENCHMARKING",
        )

    def test_runs_without_numpy(self) -> None:
        """The path a default install takes: no numpy, no failure."""
        output = _assert_ran(
            _run_example("complete_demo.py", block_numpy=True),
            "ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY",
        )
        assert "_numeric.Vec" in output, "the no-numpy fallback did not report itself"

    def test_exercises_the_ndarray_path_when_numpy_is_present(self) -> None:
        """The regression itself, run end to end rather than unit-tested.

        Without ``numpy`` installed this cannot be asserted, so it is skipped
        rather than quietly passing — a skip is visible in the report, and CI
        installs ``requirements-dev.txt``, which pins numpy.
        """
        pytest.importorskip("numpy")
        output = _assert_ran(_run_example("complete_demo.py"))
        assert "numpy.ndarray" in output, "the demo did not use the ndarray path"
        assert "numpy.asarray(final_state): shape=(100,)" in output

    def test_reports_a_real_phi_amplified_weight(self) -> None:
        """``config.get("alpha", 0)`` printed 0.0000 on every default engine.

        ``config`` holds only the overrides a caller passed, so on a
        default-constructed engine it is empty and the demo reported the φ³
        amplification of every weight as zero.
        """
        output = _assert_ran(_run_example("complete_demo.py"))
        assert "α (purity) weight: 1.5864" in output
        assert "0.3745 × φ³" in output


class TestExamplesSurviveALegacyOutputEncoding:
    """A non-UTF-8 stdout must not kill a shipped example.

    What this pins, and why it runs everywhere
    ------------------------------------------
    ``complete_demo.py`` prints ``✓``/``✗`` verdicts and ``φ³``/``σ`` labels.
    On Windows, Python uses the *locale* encoding — cp1252 on a default
    install — for stdout whenever it is **redirected** rather than attached to
    a console. So ``python complete_demo.py > out.txt``, and every CI job that
    captures output, died part-way through with

        UnicodeEncodeError: 'charmap' codec can't encode character '\\u2713'

    and then a second traceback from the ``except`` handler trying to report
    the first with ``✗``. Four Windows lanes went red on it.

    The obvious repair is ``PYTHONUTF8: "1"`` in the workflow. That is the
    wrong repair: it makes the *test* pass while leaving the defect in place
    for every user who runs the script by hand, and it hides the next
    occurrence. The example reconfigures its own streams instead
    (``complete_demo._make_stdio_encodable``), which is a property of the
    program rather than of the environment it happens to run in.

    A property of the program can be tested anywhere, so this does not wait
    for a Windows runner. ``PYTHONIOENCODING=cp1252`` reproduces the exact
    fault on Linux and macOS — verified: exit 1 with
    ``'charmap' codec can't encode character '\\u2717'`` before the fix, exit 0
    after — which means the guard is exercised on **every** job in the matrix
    rather than on the quarter of it that runs Windows.

    ``basic_usage.py`` is in the parametrisation despite printing only ASCII
    today. That is the point: it costs one subprocess, and it is what turns
    "someone adds a ✓ to basic_usage in six months" from a red Windows lane
    into a red lane everywhere, immediately.
    """

    #: cp1252 is the Windows default and is what the failing lanes actually
    #: used. ascii is the harsher case — it also rejects the ``—`` and ``·``
    #: that appear in prose — so a script passing under it is portable to any
    #: encoding at all.
    LEGACY_ENCODINGS = ("cp1252", "ascii")

    @pytest.mark.parametrize("encoding", LEGACY_ENCODINGS)
    @pytest.mark.parametrize("name", RUNNABLE)
    def test_example_completes_under_a_legacy_encoding(self, name: str, encoding: str) -> None:
        result = _run_example(name, io_encoding=encoding)
        assert result.returncode == 0, (
            f"{name} died under PYTHONIOENCODING={encoding}. A shipped example "
            f"must not depend on the console encoding.\n"
            f"{(result.stdout + result.stderr)[-3000:]}"
        )

    def test_the_reproduction_is_real(self) -> None:
        """Non-vacuity: cp1252 must genuinely be unable to encode what we print.

        If a future edit replaced every glyph with ASCII, the parametrised
        cases above would pass for a reason that has nothing to do with the
        guard, and the guard could then be deleted without anything going red.
        This asserts the hazard still exists — that ``complete_demo.py``
        contains at least one character cp1252 cannot represent — so the cases
        above are known to be exercising something.
        """
        source = (EXAMPLES / "complete_demo.py").read_text(encoding="utf-8")
        unencodable = {ch for ch in source if _cannot_encode(ch, "cp1252")}
        assert unencodable, (
            "complete_demo.py is now pure cp1252; the legacy-encoding cases "
            "above no longer test the stream guard, so either restore the "
            "glyphs or delete the guard and these tests together"
        )

    def test_utf8_output_is_still_produced_when_the_stream_allows_it(self) -> None:
        """The guard must not degrade output that was fine to begin with.

        ``errors='replace'`` would silently turn every verdict into ``?`` if
        the reconfiguration to UTF-8 failed. Asserting the glyph survives keeps
        "does not crash" from being satisfied by "prints nothing legible".
        """
        output = _assert_ran(_run_example("complete_demo.py"))
        assert "✓" in output, "the ✓ verdicts were replaced rather than encoded"


def _cannot_encode(character: str, encoding: str) -> bool:
    try:
        character.encode(encoding)
    except UnicodeEncodeError:
        return True
    return False
