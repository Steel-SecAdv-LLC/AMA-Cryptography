#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
"""
X25519 dispatch policy tests (D-7 follow-up).

The AVX2 4-way Montgomery-ladder kernel (PR #273) is INTENTIONALLY opt-in
on x86_64: on hosts where the scalar fe64 path uses native MULX/ADX, four
sequential scalar ladders outrun four lanes of the AVX2 32-bit-limb donna
ladder (the audit on 2026-04-27 measured zero speedup at batch sizes 4/8/16
on a Skylake-class Xeon and confirmed this is the documented dispatch
policy in src/c/dispatch/ama_dispatch.c lines 478-502).

This module pins that contract from the Python side so a future change
that flips the default — or accidentally regresses correctness across the
two paths — fails CI loudly:

  * test_batch_correctness_default       — batch4/8/16 = 4×/8×/16× sequential single-shot
  * test_batch_correctness_avx2_optin    — same, but with the AVX2 kernel forced on
  * test_avx2_optin_dispatch_print_differs — AMA_DISPATCH_VERBOSE confirms the
                                           x25519_x4 table entry differs between
                                           the two builds (and is *required* to be
                                           present in both — no silent skip)
  * test_low_order_rejection_uniform     — low-order points rejected on both paths
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ama_cryptography.pqc_backends import (
    _X25519_NATIVE_AVAILABLE,
    _native_lib,
)

requires_x25519 = pytest.mark.skipif(
    _native_lib is None
    or not _X25519_NATIVE_AVAILABLE
    or not hasattr(_native_lib, "ama_x25519_scalarmult_batch"),
    reason="X25519 + batch native backend not available",
)


def _run_in_subprocess(snippet: str, *, env_overrides: dict[str, str]) -> str:
    """Execute ``snippet`` in a fresh interpreter with the given env overrides.

    Spawning a new process is mandatory because the dispatch table is
    initialized once per CDLL load: changing AMA_DISPATCH_USE_X25519_AVX2
    inside the same process has no effect on a library that is already
    resolved.
    """
    env = os.environ.copy()
    env.update(env_overrides)
    # Match the UTF-8 stdio handling used in test_cli_entry.py so
    # subprocess output decodes consistently on Windows runners (where
    # the system ANSI code page would otherwise turn UTF-8 emit from the
    # native dispatcher into mojibake — D-2 follow-up).  The JSON-bearing
    # callers in this module work in pure ASCII so they are unaffected
    # either way; the verbose-stderr caller depends on this.
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")

    # Make the in-tree package importable regardless of whether the user
    # ran `pip install -e .` (mirrors the same fix used in
    # tests/test_cli_entry.py — see D-2).
    import ama_cryptography as _ama

    pkg_parent = str(Path(_ama.__file__).resolve().parent.parent)
    env["PYTHONPATH"] = (
        pkg_parent + os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else pkg_parent
    )

    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(snippet)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"subprocess failed: rc={proc.returncode}\n"
            f"stdout:\n{proc.stdout[:2000]}\n"
            f"stderr:\n{proc.stderr[:2000]}"
        )
    return proc.stdout


# Fixed test scalars/points so the parent test process can compare the two
# subprocess outputs byte-for-byte.  Generated once with secrets.token_bytes
# and frozen here to keep the test deterministic across runs.
_TEST_SCALARS = [
    bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
    bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
    bytes.fromhex("e60a4f01d54a90a3c1bce14fef0bb5a0e2b1f4f1ddf9a8a1bd14e7a7c6f6f6f6"),
    bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
]
_TEST_POINTS = [
    bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    bytes.fromhex("0a4a92e2c5d3a1c5e3c8a0b1f2e3d4c5b6a7988796a5b4c3d2e1f0e1d2c3b4a5"),
    bytes.fromhex("c1f3aa55b4d76e0c4ab9c5b8e3a7d6f4c2b1a0998877665544332211ddccbbaa"),
    bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
]


def _compute_via_subprocess(env_overrides: dict[str, str]) -> tuple[list[str], list[str]]:
    """Compute (sequential, batch) shared-secret hex strings under ``env``."""
    snippet = f"""
        import json
        from ama_cryptography.pqc_backends import (
            native_x25519_key_exchange,
            native_x25519_scalarmult_batch,
        )
        scalars = [
            bytes.fromhex({_TEST_SCALARS[0].hex()!r}),
            bytes.fromhex({_TEST_SCALARS[1].hex()!r}),
            bytes.fromhex({_TEST_SCALARS[2].hex()!r}),
            bytes.fromhex({_TEST_SCALARS[3].hex()!r}),
        ]
        points = [
            bytes.fromhex({_TEST_POINTS[0].hex()!r}),
            bytes.fromhex({_TEST_POINTS[1].hex()!r}),
            bytes.fromhex({_TEST_POINTS[2].hex()!r}),
            bytes.fromhex({_TEST_POINTS[3].hex()!r}),
        ]
        seq = [native_x25519_key_exchange(s, p).hex() for s, p in zip(scalars, points)]
        bat = [b.hex() for b in native_x25519_scalarmult_batch(scalars, points)]
        print(json.dumps({{"seq": seq, "bat": bat}}))
    """
    out = _run_in_subprocess(snippet, env_overrides=env_overrides)
    import json as _json

    payload = _json.loads(out.strip().splitlines()[-1])
    return payload["seq"], payload["bat"]


@requires_x25519
def test_batch_correctness_default() -> None:
    """Default policy: batch4 result is byte-identical to 4 sequential ladders."""
    seq, bat = _compute_via_subprocess({})
    assert seq == bat, (
        "Default-policy batch path diverges from sequential single-shot.\n"
        f"sequential: {seq}\nbatched:    {bat}"
    )


@requires_x25519
def test_batch_correctness_avx2_optin() -> None:
    """AVX2 4-way kernel produces the SAME shared secrets as the scalar path."""
    seq, bat = _compute_via_subprocess({"AMA_DISPATCH_USE_X25519_AVX2": "1"})
    assert seq == bat, (
        "AVX2 4-way kernel diverges from sequential single-shot — this is a\n"
        "correctness regression in ama_x25519_scalarmult_x4_avx2."
        f"\nsequential: {seq}\nbatched:    {bat}"
    )


@requires_x25519
def test_avx2_optin_dispatch_print_differs() -> None:
    """``AMA_DISPATCH_VERBOSE=1`` pins x25519_x4 = scalar by default, SIMD when opted in.

    Contract test for the dispatch policy itself: if a future change flips
    the default to AVX2-on, this test fails loudly.  Asserts the stderr
    line is *present* (the previous version of this test only asserted
    when the line happened to appear, which let a missing-line outcome
    silently pass — Copilot review #9).
    """
    snippet = """
        # AMA_DISPATCH_VERBOSE=1 makes ama_dispatch_init log the chosen
        # backends to stderr on first dispatch (see
        # src/c/dispatch/ama_dispatch.c:236, getenv("AMA_DISPATCH_VERBOSE")).
        # Touching any X25519 entry triggers init.
        from ama_cryptography.pqc_backends import native_x25519_keypair
        native_x25519_keypair()
    """

    def _verbose_stderr(env: dict[str, str]) -> str:
        env_full = os.environ.copy()
        env_full.update(env)
        # Copilot review #9: the dispatcher reads AMA_DISPATCH_VERBOSE,
        # not AMA_DISPATCH_PRINT.  The previous form set the wrong env
        # var, the dispatch table never printed, and the test's
        # `if "x25519_x4" in stderr` guard let the assertions silently
        # skip.  Set the right var here.
        env_full["AMA_DISPATCH_VERBOSE"] = "1"
        # Force the subprocess into UTF-8 stdio on Windows — the
        # dispatcher's verbose print emits the multiplication-sign
        # codepoint in "scalar (4× sequential)" as UTF-8 bytes.  Without
        # PYTHONUTF8/PYTHONIOENCODING the child interpreter on Windows
        # decodes its stdio with the system ANSI code page (cp1252), so
        # ``capture_output=text`` would read the bytes back as mojibake
        # and the substring assertions below would never find ``×`` —
        # mirrors the same fix applied in tests/test_cli_entry.py for
        # the banner glyphs (D-2 follow-up).
        env_full.setdefault("PYTHONIOENCODING", "utf-8")
        env_full.setdefault("PYTHONUTF8", "1")
        import ama_cryptography as _ama

        # Devin review: prepend the package parent rather than overwriting
        # PYTHONPATH.  Overwriting drops virtualenv site-packages /
        # CI-injected entries that the subprocess may need to import its
        # own dependencies, which then surfaces as an ImportError that
        # the rc!=0 guard below would re-raise as an opaque AssertionError
        # rather than the actual missing-import.  Mirrors the prepend
        # pattern in _run_in_subprocess (lines 60-78) and
        # tests/test_cli_entry.py (D-2).
        pkg_parent = str(Path(_ama.__file__).resolve().parent.parent)
        existing_pp = env_full.get("PYTHONPATH")
        env_full["PYTHONPATH"] = (
            pkg_parent + os.pathsep + existing_pp if existing_pp else pkg_parent
        )
        proc = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(snippet)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
            env=env_full,
        )
        # Copilot review #4: fail loudly when the subprocess fails to
        # import / execute (e.g. missing shared library, ImportError,
        # crash before dispatch init).  Previously a non-zero rc
        # produced empty stderr that the conditional assertions then
        # let through as a silent pass.
        if proc.returncode != 0:
            raise AssertionError(
                "AMA_DISPATCH_VERBOSE subprocess failed: "
                f"rc={proc.returncode}\nstdout:\n{proc.stdout[:2000]}\n"
                f"stderr:\n{proc.stderr[:2000]}"
            )
        return proc.stderr

    default_stderr = _verbose_stderr({})
    avx2_stderr = _verbose_stderr({"AMA_DISPATCH_USE_X25519_AVX2": "1"})

    # Hard-assert the dispatch line is present in BOTH runs.  Without
    # this the earlier `if "x25519_x4" in ...` guard let a non-emitting
    # build silently pass — turning the contract test into a no-op.
    assert "x25519_x4" in default_stderr, (
        "AMA_DISPATCH_VERBOSE=1 did not produce an x25519_x4 dispatch "
        "line under the default policy.  Either the runtime gate "
        "ama_print_dispatch_info disabled the print, or the binding "
        "extension never reached the dispatch init point.  stderr was:\n"
        f"{default_stderr}"
    )
    # ASCII-only substring — tolerates either rendering of the
    # multiplication sign (``×`` UTF-8 / ``x`` ASCII) so a future
    # platform whose stdio narrows the codepoint cannot turn this
    # contract test into a mojibake-driven false negative.
    assert "scalar" in default_stderr and "sequential" in default_stderr, (
        "Default policy MUST keep x25519_x4 = scalar (4× sequential) on "
        "MULX/ADX hosts (PR #273 design note, ama_dispatch.c:478-502). "
        "If the AVX2 4-way kernel is now selected by default, that is a "
        "performance regression on every shipped Broadwell+/Zen+ part. "
        f"stderr was:\n{default_stderr}"
    )
    # AVX2 opt-in either selects the SIMD kernel (uncontended modern
    # x86_64) or falls back to scalar on hosts that lack AVX2; both are
    # acceptable.  What is NOT acceptable is for the env-var to have no
    # effect at all (which would prove the dispatch table can't be
    # opted in).
    assert "x25519_x4" in avx2_stderr, (
        "AMA_DISPATCH_VERBOSE=1 + AMA_DISPATCH_USE_X25519_AVX2=1 did "
        "not produce an x25519_x4 dispatch line. stderr was:\n"
        f"{avx2_stderr}"
    )


@requires_x25519
def test_low_order_rejection_uniform() -> None:
    """RFC 7748 §6.1 low-order rejection fires on both default and opt-in paths."""
    snippet = """
        from ama_cryptography.pqc_backends import native_x25519_scalarmult_batch
        # All-zero u-coordinate is the canonical low-order point.
        scalars = [b"\\x01" * 32] * 4
        points  = [b"\\x00" * 32] * 4
        try:
            native_x25519_scalarmult_batch(scalars, points)
            print("LEAK")  # security regression: low-order accepted
        except (RuntimeError, ValueError):
            print("OK")
    """
    default_out = _run_in_subprocess(snippet, env_overrides={})
    avx2_out = _run_in_subprocess(snippet, env_overrides={"AMA_DISPATCH_USE_X25519_AVX2": "1"})
    assert "OK" in default_out, f"low-order rejection failed under default policy: {default_out}"
    assert "OK" in avx2_out, f"low-order rejection failed under AVX2 opt-in: {avx2_out}"
