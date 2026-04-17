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
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_main_module_subprocess(tmp_path: Path) -> None:
    """``python -m ama_cryptography`` exits 0 and prints the banner.

    Invoked with ``cwd=tmp_path`` so the demonstration routine's
    artefacts (``public_keys/``, ``CRYPTO_PACKAGE.json``) stay inside
    pytest's temp dir and do not pollute the working tree.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "ama_cryptography"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=str(tmp_path),
    )
    assert proc.returncode == 0, (
        f"python -m ama_cryptography failed with rc={proc.returncode}\n"
        f"stdout: {proc.stdout[:2000]}\n"
        f"stderr: {proc.stderr[:2000]}"
    )
    assert "AMA Cryptography" in proc.stdout


def test_legacy_compat_main_callable() -> None:
    """``legacy_compat.main`` is importable and is a zero-arg callable."""
    from ama_cryptography.legacy_compat import main

    assert callable(main)
    # signature: def main() -> None
    import inspect

    sig = inspect.signature(main)
    assert len(sig.parameters) == 0


def test_main_module_imports_legacy_main() -> None:
    """Loading ``ama_cryptography.__main__`` in-process instruments line 3."""
    import importlib

    # Force a fresh import so coverage counts the module-body statements
    # even when the interpreter has previously loaded it (e.g. via a
    # subprocess test before this one).
    module = importlib.import_module("ama_cryptography.__main__")
    assert callable(module.main)
