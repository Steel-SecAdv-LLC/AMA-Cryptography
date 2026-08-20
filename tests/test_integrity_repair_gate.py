#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Which integrity failures ``AMA_BUILD_PIPELINE=1`` may import through.

``ama_cryptography.__init__`` raises on a failed POST, with one carve-out: the
tools that REPAIR a failed integrity check live inside the package, so a hard
raise would wall them off behind the very fault they exist to clear.  The
carve-out is supposed to cover only the outcomes a signing run legitimately
expects in a tree it is about to re-sign.

Its integrity half did not narrow anything.  The condition read

    _integrity_stage_failed = any(name == "integrity" and ok is False for ...)
    ...
    (name == "integrity" and _integrity_stage_failed)

and the failing row is itself the witness that makes the ``any()`` true, so the
conjunct reduced to ``name == "integrity"``: every integrity failure qualified,
including "Ed25519 signature did NOT verify — module tampered".  A release
container carrying the flag for its whole lifetime — the scenario the comment
names — could smoke-test a wheel whose signature did not verify and exit 0,
which is the "failure in the log, success in the exit code" fail-open the block
exists to close.

The distinction is now carried structurally by
``_self_test.integrity_failure_was_stale_binding()``, the counterpart of
``pqc_backends.native_backend_refused_on_digest()``, and these tests pin both
directions of it plus the binding-strength downgrade that shares the machinery.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
from pathlib import Path
from typing import Any, Iterator

import pytest

from ama_cryptography import _artefact_source
from ama_cryptography import _self_test as st

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"


def _resolve_native_lib() -> Path | None:
    """Locate the built native library the way the package itself does.

    The literal ``build/lib/libama_cryptography.so`` this replaced could never
    exist on macOS (``.dylib``) or Windows (``.dll``) even when the library was
    built, and MSVC emits to ``build/bin/Release`` rather than ``build/lib``.
    The three call sites below skip on ``not NATIVE_LIB.exists()`` with the
    reason ``"native library not built at build/lib"`` — which
    ``tests/conftest.py`` escalates to a hard CI FAILURE because it names a
    backend.  So the stale path did not degrade to a skip; it turned every
    macOS and Windows job red while the backend was in fact present.  This is
    the same defect already fixed in ``tests/test_verify_install_oob.py``;
    ``_find_native_library_path`` is the package's own discovery and knows
    every search dir and platform suffix.
    """
    try:
        from ama_cryptography.pqc_backends import _find_native_library_path

        return _find_native_library_path()
    except Exception:
        return None


NATIVE_LIB = _resolve_native_lib()

pytestmark = pytest.mark.fips

_ARTEFACT = "ama_cryptography._integrity_signature"
_GOOD_DIGEST = "ab" * 32
_OTHER_DIGEST = "cd" * 32


@pytest.fixture(autouse=True)
def _restore_classifier() -> Iterator[None]:
    """Leave the module-level failure classification as it was found."""
    saved_kind = st._INTEGRITY_FAILURE_KIND
    saved_strength = st._INTEGRITY_STRENGTH
    yield
    st._INTEGRITY_FAILURE_KIND = saved_kind
    st._INTEGRITY_STRENGTH = saved_strength


def _package() -> types.ModuleType:
    """The ``ama_cryptography`` package object.

    Resolved through ``sys.modules`` rather than a second ``import
    ama_cryptography``: this module already imports the package in
    ``from``-form (``from ama_cryptography import _self_test as st``), and
    mixing the two import styles for one module is what CodeQL flagged as
    alerts 624 and 625.  The entry is guaranteed present because importing
    the ``_self_test`` submodule imports its package first.
    """
    return sys.modules["ama_cryptography"]


def _install_artefact(monkeypatch: pytest.MonkeyPatch, **fields: Any) -> None:
    """Put a synthetic artefact SOURCE FILE in front of the real one.

    This used to install a synthetic module object into ``sys.modules`` and
    onto the package attribute, because ``_verify_signed_integrity`` reached
    the artefact with ``from ama_cryptography import _integrity_signature``.
    It no longer does: an ordinary import reads the artefact's ``__pycache__``
    bytecode, which nothing has validated when the pre-load gates and the POST
    ``integrity`` stage consult it, so the literals are now parsed from the
    source text (see ``ama_cryptography._artefact_source``).

    Writing a real file is therefore the right seam, and a strictly better one:
    it exercises the parser these controls actually use, rather than handing
    them an object that skips it.
    """
    lines = [f"{name} = {value!r}\n" for name, value in fields.items()]
    path = _artefact_dir(monkeypatch) / "_integrity_signature.py"
    path.write_text("".join(lines), encoding="utf-8")
    monkeypatch.setattr(_artefact_source, "artefact_path", lambda *_a, **_k: path)


def _artefact_dir(monkeypatch: pytest.MonkeyPatch) -> Path:
    """A per-test scratch directory for synthetic artefacts.

    ``monkeypatch`` is taken (and unused) so every caller keeps the same shape
    and the directory's lifetime is obviously tied to a single test.
    """
    del monkeypatch
    return Path(tempfile.mkdtemp(prefix="ama-artefact-"))


def _remove_artefact(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the reader at a path that does not exist (a tree with no signature)."""
    missing = _artefact_dir(monkeypatch) / "absent.py"
    monkeypatch.setattr(_artefact_source, "artefact_path", lambda *_a, **_k: missing)


class TestFailureClassification:
    """``stale-binding`` is repairable; everything else is tampering."""

    def test_no_failure_is_not_stale(self, monkeypatch: pytest.MonkeyPatch) -> None:
        st._INTEGRITY_FAILURE_KIND = None
        assert st.integrity_failure_was_stale_binding() is False

    def test_stale_source_digest_is_repairable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A .py file changed post-build: the state ``--update --sign`` clears."""
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _OTHER_DIGEST)
        _install_artefact(
            monkeypatch,
            INTEGRITY_DIGEST_HEX=_GOOD_DIGEST,
            INTEGRITY_PUBKEY_HEX="00" * 32,
            INTEGRITY_SIGNATURE_HEX="00" * 64,
        )
        ok, detail = st.verify_module_integrity()
        assert ok is False
        assert "signed digest mismatch" in detail
        assert st.integrity_failure_was_stale_binding() is True

    def test_missing_field_is_tampering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _GOOD_DIGEST)
        _install_artefact(
            monkeypatch,
            INTEGRITY_DIGEST_HEX=_GOOD_DIGEST,
            INTEGRITY_PUBKEY_HEX="00" * 32,
            # INTEGRITY_SIGNATURE_HEX deliberately absent
        )
        ok, detail = st.verify_module_integrity()
        assert ok is False
        assert "malformed" in detail
        assert st.integrity_failure_was_stale_binding() is False

    def test_non_hex_fields_are_tampering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _GOOD_DIGEST)
        _install_artefact(
            monkeypatch,
            INTEGRITY_DIGEST_HEX=_GOOD_DIGEST,
            INTEGRITY_PUBKEY_HEX="zz" * 32,
            INTEGRITY_SIGNATURE_HEX="00" * 64,
        )
        ok, _detail = st.verify_module_integrity()
        assert ok is False
        assert st.integrity_failure_was_stale_binding() is False

    def test_wrong_field_sizes_are_tampering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _GOOD_DIGEST)
        _install_artefact(
            monkeypatch,
            INTEGRITY_DIGEST_HEX=_GOOD_DIGEST,
            INTEGRITY_PUBKEY_HEX="00" * 16,  # 16 bytes, not 32
            INTEGRITY_SIGNATURE_HEX="00" * 64,
        )
        ok, _detail = st.verify_module_integrity()
        assert ok is False
        assert st.integrity_failure_was_stale_binding() is False

    def test_trust_anchor_mismatch_is_tampering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An artefact signed under a key the compiled anchor does not name."""
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _GOOD_DIGEST)
        monkeypatch.setattr(
            st,
            "_validate_trust_anchor",
            lambda _pubkey_hex: (None, "integrity trust anchor mismatch: signed_pubkey=00..."),
        )
        _install_artefact(
            monkeypatch,
            INTEGRITY_DIGEST_HEX=_GOOD_DIGEST,
            INTEGRITY_PUBKEY_HEX="00" * 32,
            INTEGRITY_SIGNATURE_HEX="00" * 64,
        )
        ok, detail = st.verify_module_integrity()
        assert ok is False
        assert "trust anchor mismatch" in detail
        assert st.integrity_failure_was_stale_binding() is False

    def test_bad_signature_is_tampering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The headline case: the artefact verifies against nothing.

        Requires the native Ed25519 verifier, since a signature that fails to
        verify is the outcome under test rather than one that can be faked.
        """
        from ama_cryptography import pqc_backends

        if not pqc_backends._ED25519_NATIVE_AVAILABLE:
            pytest.skip("native Ed25519 verifier unavailable in this tree")
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _GOOD_DIGEST)
        _install_artefact(
            monkeypatch,
            INTEGRITY_DIGEST_HEX=_GOOD_DIGEST,
            INTEGRITY_PUBKEY_HEX="11" * 32,
            INTEGRITY_SIGNATURE_HEX="22" * 64,
        )
        ok, detail = st.verify_module_integrity()
        assert ok is False
        assert "did NOT verify" in detail or "verify raised" in detail
        assert st.integrity_failure_was_stale_binding() is False, (
            "a signature that does not verify is tampering; re-signing would "
            "launder it, so AMA_BUILD_PIPELINE must not import through it"
        )

    def test_digest_only_mismatch_is_repairable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The unsigned twin of the stale-source case, repaired the same way."""
        digest_file = tmp_path / "_integrity_digest.txt"
        digest_file.write_text(_GOOD_DIGEST, encoding="utf-8")
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _OTHER_DIGEST)
        monkeypatch.setattr(st, "_INTEGRITY_DIGEST_FILE", digest_file)
        _remove_artefact(monkeypatch)

        ok, detail = st.verify_module_integrity()
        assert ok is False
        assert "Module digest mismatch" in detail
        assert st.integrity_failure_was_stale_binding() is True

    def test_missing_digest_file_is_tampering(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Neither artefact nor digest file: nothing a re-sign is repairing."""
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _OTHER_DIGEST)
        monkeypatch.setattr(st, "_INTEGRITY_DIGEST_FILE", tmp_path / "absent.txt")
        _remove_artefact(monkeypatch)

        ok, detail = st.verify_module_integrity()
        assert ok is False
        assert "missing" in detail
        assert st.integrity_failure_was_stale_binding() is False

    def test_classification_is_reset_per_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A stale verdict must not survive into a later, healthy check.

        The flag is consumed at import time, after POST; a value left over from
        a previous call would answer for a run that never set it.
        """
        st._INTEGRITY_FAILURE_KIND = st._INTEGRITY_FAILURE_STALE_BINDING
        digest_file = tmp_path / "_integrity_digest.txt"
        digest_file.write_text(_GOOD_DIGEST, encoding="utf-8")
        monkeypatch.setattr(st, "_compute_module_digest", lambda: _GOOD_DIGEST)
        monkeypatch.setattr(st, "_INTEGRITY_DIGEST_FILE", digest_file)
        _remove_artefact(monkeypatch)

        ok, _detail = st.verify_module_integrity()
        assert ok is True
        assert st.integrity_failure_was_stale_binding() is False


class TestBindingStrengthDowngrade:
    """``_check_binding_extensions``' ``exact`` flag must reach the strength.

    The contract states that "an uncovered (executing, unverified) extension
    additionally drops the integrity strength below full", and
    ``_build_sign``'s ``--bind-extensions`` help repeats it.  The caller
    unpacked the flag into ``_b_exact`` and never read it, so a developer tree
    with built extensions and a repair-flow artefact (which binds none of them)
    reported integrity PASS and ``module_attestation()['fully_verified'] ==
    True`` over code that had already imported and executed unchecked.
    """

    def test_uncovered_extension_is_reported_as_drift(self, tmp_path: Path) -> None:
        ext = tmp_path / "sha3_binding.cpython-311-x86_64-linux-gnu.so"
        ext.write_bytes(b"not really an extension")
        ok, note, exact = st._check_binding_extensions({}, anchored=False, pkg_dir=tmp_path)
        assert ok is True, "drift on a developer build is a warning, not a failure"
        assert exact is False
        assert "present but not covered" in note

    def test_clean_tree_is_exact(self, tmp_path: Path) -> None:
        ok, _note, exact = st._check_binding_extensions({}, anchored=False, pkg_dir=tmp_path)
        assert (ok, exact) == (True, True)

    def test_uncovered_extension_is_not_full_strength(self) -> None:
        """The value a release gate reads must show the gap."""
        assert "signed-bindings-unverified" in _run_integrity_stage_strengths()

    def test_bindings_unverified_is_recorded_as_a_skip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not a PASS: it lands in tests_skipped and out of fully_verified."""
        monkeypatch.setattr(st, "verify_module_integrity", lambda: (True, "detail"))
        monkeypatch.setattr(st, "_INTEGRITY_STRENGTH", "signed-bindings-unverified")
        monkeypatch.setattr(st, "_SELF_TEST_RESULTS", [])
        passed, error = st._run_integrity_stage()
        assert (passed, error) == (True, None)
        assert st._SELF_TEST_RESULTS[-1][1] is None, "must be a SKIP, not a PASS"

    def test_bindings_unverified_fails_under_fips_strict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(st, "verify_module_integrity", lambda: (True, "detail"))
        monkeypatch.setattr(st, "_INTEGRITY_STRENGTH", "signed-bindings-unverified")
        monkeypatch.setattr(st, "_SELF_TEST_RESULTS", [])
        monkeypatch.setenv(st._AMA_FIPS_STRICT_ENV, "1")
        passed, error = st._run_integrity_stage()
        assert passed is False
        assert error is not None and "not full-strength" in error


def _run_integrity_stage_strengths() -> tuple[str, ...]:
    """The strength values ``_run_integrity_stage`` treats as below full."""
    source = Path(st.__file__).read_text(encoding="utf-8")
    start = source.index("def _run_integrity_stage")
    end = source.index("def _run_execution_integrity_stage")
    body = source[start:end]
    return tuple(
        value
        for value in ("digest-only", "signed-native-unverified", "signed-bindings-unverified")
        if f'"{value}"' in body
    )


class TestImportGateEndToEnd:
    """The carve-out, exercised through a real interpreter.

    Skipped where the package copy cannot load a native library, since without
    the Ed25519 verifier the signature check cannot run at all and the case
    under test is unreachable.
    """

    @staticmethod
    def _tree(tmp_path: Path) -> Path:
        root = tmp_path / "tree"
        shutil.copytree(PKG_DIR, root / "ama_cryptography")
        return root

    @staticmethod
    def _run(code: str, cwd: Path, **env_extra: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(cwd)
        # The copied tree carries no shared object, and a missing native
        # backend is a broken build that hard-fails POST on its own — which
        # would mask the integrity-stage outcome these tests are about.
        if NATIVE_LIB is not None:
            env["AMA_CRYPTO_LIB_PATH"] = str(NATIVE_LIB)
        env.update(env_extra)
        return subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code)],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_tampered_signature_is_refused_even_in_a_build_pipeline(self, tmp_path: Path) -> None:
        from ama_cryptography import pqc_backends

        if not pqc_backends._ED25519_NATIVE_AVAILABLE:
            pytest.skip("native Ed25519 verifier unavailable in this tree")
        artefact = PKG_DIR / "_integrity_signature.py"
        if not artefact.is_file():
            pytest.skip("no signed-integrity artefact in the source tree")
        if NATIVE_LIB is None:
            pytest.skip("no native library discoverable by the package loader")

        root = self._tree(tmp_path)
        copied = root / "ama_cryptography" / "_integrity_signature.py"
        text = copied.read_text(encoding="utf-8")
        # Flip one hex digit of the signature: the digest it covers is
        # untouched, so this is a signature that verifies against nothing —
        # tampering, not staleness.
        marker = 'INTEGRITY_SIGNATURE_HEX = "'
        head, _, tail = text.partition(marker)
        assert tail, "artefact does not carry INTEGRITY_SIGNATURE_HEX"
        flipped = ("0" if tail[0] != "0" else "1") + tail[1:]
        copied.write_text(head + marker + flipped, encoding="utf-8")

        diag = self._run("import ama_cryptography", root, AMA_BUILD_PIPELINE="1")
        assert diag.returncode != 0, (
            "a wheel whose Ed25519 signature does not verify imported with exit "
            "code 0 inside a build pipeline — the fail-open the repair carve-out "
            "is supposed to exclude"
        )
        assert "POST" in (diag.stdout + diag.stderr)

    def test_stale_source_digest_still_imports_for_the_signer(self, tmp_path: Path) -> None:
        """The repair flow the carve-out exists for must keep working."""
        artefact = PKG_DIR / "_integrity_signature.py"
        if not artefact.is_file():
            pytest.skip("no signed-integrity artefact in the source tree")
        if NATIVE_LIB is None:
            pytest.skip("no native library discoverable by the package loader")

        root = self._tree(tmp_path)
        target = root / "ama_cryptography" / "exceptions.py"
        target.write_text(
            target.read_text(encoding="utf-8") + "\n# edited after signing\n", encoding="utf-8"
        )

        result = self._run(
            "import ama_cryptography; print('IMPORTED')", root, AMA_BUILD_PIPELINE="1"
        )
        assert result.returncode == 0, (
            "a stale source digest must still import under AMA_BUILD_PIPELINE=1, "
            "or the in-package re-signing tool cannot run: "
            f"{result.stdout}{result.stderr}"
        )
        assert "IMPORTED" in result.stdout
