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


def _run_example(name: str, *, block_numpy: bool = False) -> subprocess.CompletedProcess[str]:
    """Run one example in a subprocess and return the completed process.

    A subprocess rather than ``runpy``: the examples call ``sys.exit()`` and
    mutate ``sys.path``, and running them in-process would let one example's
    imports and warning filters leak into the next test.
    """
    script = EXAMPLES / name
    if block_numpy:
        source = (
            f"{_BLOCK_NUMPY}\nimport runpy\nrunpy.run_path({str(script)!r}, run_name='__main__')\n"
        )
        argv = [sys.executable, "-c", source]
    else:
        argv = [sys.executable, str(script)]
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
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
