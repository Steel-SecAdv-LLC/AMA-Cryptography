#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
Coverage for the ``python -m ama_cryptography`` CLI entry point
(``ama_cryptography/__main__.py``).

The stub just re-exports ``legacy_compat.main`` behind the standard
``if __name__ == "__main__"`` guard.  ``main()`` is a demonstration
routine that walks through the full crypto pipeline and prints to
stdout — we invoke it as a subprocess so the guard actually fires
and the module is counted as executed.

Native-backend guard
--------------------
``ama_cryptography.__main__`` imports ``legacy_compat`` which in turn
raises ``RuntimeError`` at module-load time when the native Ed25519 or
HKDF C accelerators are unavailable (INVARIANT-7).  That means
``importlib.import_module("ama_cryptography.__main__")`` — and any
subprocess invocation of the CLI — can blow up on builds that didn't
ship those native symbols (e.g. Windows runners where the native
library failed to link).  Every test in this module is guarded by
``requires_native_backend`` so it skips cleanly in those environments
instead of erroring out; in ``AMA_CI_REQUIRE_BACKENDS=1`` CI runs
where the backends are mandatory the skip is promoted back to a hard
failure by ``tests/conftest.py``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ama_cryptography.pqc_backends import (
    _ED25519_NATIVE_AVAILABLE,
    _HKDF_NATIVE_AVAILABLE,
    _native_lib,
)

requires_native_backend = pytest.mark.skipif(
    _native_lib is None or not _ED25519_NATIVE_AVAILABLE or not _HKDF_NATIVE_AVAILABLE,
    reason=(
        "Native C library (Ed25519 + HKDF) required — "
        "legacy_compat fails-closed at import time without it"
    ),
)


@requires_native_backend
def test_main_module_subprocess(tmp_path: Path) -> None:
    """``python -m ama_cryptography`` exits 0 and prints the banner.

    Invoked with ``cwd=tmp_path`` so the demonstration routine's
    artefacts (``public_keys/``, ``CRYPTO_PACKAGE.json``) stay inside
    pytest's temp dir and do not pollute the working tree.

    ``PYTHONUTF8=1`` + ``PYTHONIOENCODING=utf-8`` are propagated to the
    child interpreter so the Unicode banner symbols (✠ ♱ ⚛ ⊛) render
    correctly on Windows runners where the system ANSI code page is
    cp1252. ``encoding="utf-8"`` is set on the subprocess call so the
    parent-side decoding matches the child's stdout encoding
    regardless of the parent's locale.
    """
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    proc = subprocess.run(
        [sys.executable, "-m", "ama_cryptography"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
        cwd=str(tmp_path),
        env=env,
    )
    assert proc.returncode == 0, (
        f"python -m ama_cryptography failed with rc={proc.returncode}\n"
        f"stdout: {proc.stdout[:2000]}\n"
        f"stderr: {proc.stderr[:2000]}"
    )
    assert "AMA Cryptography" in proc.stdout


@requires_native_backend
def test_legacy_compat_main_callable() -> None:
    """``legacy_compat.main`` is importable and is a zero-arg callable."""
    from ama_cryptography.legacy_compat import main

    assert callable(main)
    # signature: def main() -> None
    import inspect

    sig = inspect.signature(main)
    assert len(sig.parameters) == 0


@requires_native_backend
def test_main_module_imports_legacy_main() -> None:
    """Loading ``ama_cryptography.__main__`` in-process instruments line 3."""
    import importlib

    # Force a fresh import so coverage counts the module-body statements
    # even when the interpreter has previously loaded it (e.g. via a
    # subprocess test before this one).
    module = importlib.import_module("ama_cryptography.__main__")
    assert callable(module.main)
