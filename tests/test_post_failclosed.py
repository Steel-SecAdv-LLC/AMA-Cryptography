#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
FIPS 140-3 POST fail-closed behaviour
=====================================

Regression coverage for a family of defects that shared one shape: the module
detected its own failure, said so in the log, and then reported success to
everything that could act on it.

Concretely, before this suite existed:

* ``ama_cryptography/__init__.py`` discarded the return value of ``_post()``.
  POST could log ``CRITICAL: FIPS 140-3 POST FAILURE: ...``, set the module
  state to ERROR, and ``import ama_cryptography`` still succeeded with exit
  code 0.  Every build script and health check that treated a clean import as
  proof of a working module reported success over a module that had just
  announced its own failure.

* Not one of the eighty public native entry points in ``pqc_backends`` checked
  the module state, so the FIPS §4.9.2 "error state" inhibited no cryptographic
  output at all outside ``crypto_api``.

* A native library that could not be found was reported as
  ``native Ed25519 not built``, sending operators to fix a C build that was
  usually fine.

* A checkout with no native backend imported cleanly with a warning, skipping
  eight of eleven self-tests — the "warning without a hard stop" that
  INVARIANT-7 names as unacceptable.

Import-level behaviour is exercised in subprocesses because it cannot be
observed from inside a process that has already imported the package.

Run with:  pytest tests/test_post_failclosed.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

pytestmark = pytest.mark.fips


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_python(code: str, cwd: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run ``code`` in a fresh interpreter rooted at ``cwd``."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    # An installed copy of the package would shadow the tree under test.
    env["PYTHONPATH"] = str(cwd)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def tree_without_native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package with the native library removed.

    This reproduces the reported condition exactly: sources intact, integrity
    artefacts intact, no discoverable ``libama_cryptography``.
    """
    root = tmp_path_factory.mktemp("no_native")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    for pattern in ("*.so", "*.so.*", "*.dylib", "*.dll", "*.pyd"):
        for artefact in (root / "ama_cryptography").glob(pattern):
            artefact.unlink()
    return root


@pytest.fixture(scope="module")
def tree_with_native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package with whatever native library the tree has."""
    root = tmp_path_factory.mktemp("with_native")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    if not any((root / "ama_cryptography").glob("libama_cryptography*")):
        pytest.skip("native library not built in this tree")
    return root


# ---------------------------------------------------------------------------
# 1. A failed POST must fail the import
# ---------------------------------------------------------------------------


class TestImportFailsClosed:
    """``import ama_cryptography`` must not succeed over a failed POST."""

    def test_missing_native_backend_makes_import_raise(self, tree_without_native: Path) -> None:
        """The exact reported scenario: no native library, script prints 'verified'.

        The failure mode being pinned is not "POST logged something" — POST
        logged the failure correctly all along.  It is that the process exited
        0 and the caller's success line ran.
        """
        result = _run_python(
            """
            import ama_cryptography
            print("verified")
            """,
            cwd=tree_without_native,
        )

        assert result.returncode != 0, (
            "import succeeded with a failed POST — a caller cannot distinguish "
            "this from a working module.\nstdout:\n" + result.stdout
        )
        assert "verified" not in result.stdout, (
            "the caller's success path ran despite the POST failure"
        )
        assert "CryptoModuleError" in result.stderr

    def test_failure_message_names_the_real_cause(self, tree_without_native: Path) -> None:
        """The diagnostic must describe the search, not assert a broken build.

        ``native Ed25519 not built`` was a claim about the C build, and it was
        usually false: the library was built and simply not on the search path.
        """
        result = _run_python("import ama_cryptography", cwd=tree_without_native)

        combined = result.stdout + result.stderr
        assert "no native library found" in combined
        assert "searched directories" in combined
        # The remedy has to be present, and it has to be the right remedy.
        assert "cmake" in combined or "AMA_CRYPTO_LIB_PATH" in combined
        assert "not built — cannot verify signature" not in combined, (
            "the misleading legacy diagnostic is back"
        )

    def test_healthy_tree_imports_and_is_fully_verified(self, tree_with_native: Path) -> None:
        """The fix must not make a good build unusable."""
        result = _run_python(
            """
            import ama_cryptography as a
            att = a.module_attestation()
            assert att["state"] == "OPERATIONAL", att
            assert att["fully_verified"] is True, att
            assert att["tests_skipped"] == 0, att
            assert att["native_backend"]["loaded"] is True, att
            print("OK")
            """,
            cwd=tree_with_native,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout

    def test_diagnostic_flag_permits_import_but_not_crypto(
        self, tree_without_native: Path
    ) -> None:
        """The triage escape hatch buys introspection, never cryptography."""
        result = _run_python(
            """
            import ama_cryptography as a
            assert a.module_status() == "ERROR"
            att = a.module_attestation()
            assert att["fully_verified"] is False, att

            import ama_cryptography.pqc_backends as pb
            try:
                pb.native_sha3_256(b"x")
            except a.CryptoModuleError:
                print("REFUSED")
            else:
                raise AssertionError("crypto ran in the ERROR state")
            """,
            cwd=tree_without_native,
            env_extra={"AMA_POST_DIAGNOSTIC_IMPORT": "1"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "REFUSED" in result.stdout

    def test_build_pipeline_flag_does_not_excuse_a_kat_failure(
        self, tmp_path: Path, tree_with_native: Path
    ) -> None:
        """AMA_BUILD_PIPELINE=1 covers a stale artefact, not a broken algorithm.

        A release container carries that flag for its whole lifetime.  If it
        excused every POST failure, the same container could smoke-test a wheel
        whose Known Answer Tests fail and still call it built.

        The KAT is broken at the source level and the integrity artefacts are
        then regenerated, so POST reaches the KAT stage with a *valid* integrity
        result — isolating the policy under test from the stale-digest case it
        is allowed to forgive.
        """
        root = tmp_path / "broken_kat"
        shutil.copytree(tree_with_native / "ama_cryptography", root / "ama_cryptography")

        self_test = root / "ama_cryptography" / "_self_test.py"
        source = self_test.read_text(encoding="utf-8")
        # Corrupt the negative expected value inside the SHA3-256 KAT (the
        # empty-message digest), leaving the algorithm itself intact so it is
        # the *KAT* that fails, not SHA3 generally.
        marker = '"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"'
        assert marker in source, "SHA3-256 KAT vector moved; update this test"
        self_test.write_text(source.replace(marker, marker[:-2] + 'ff"', 1), encoding="utf-8")

        # No re-sign needed. The SHA3-256 CAST now runs BEFORE the integrity
        # stage (NIST IG 10.3.A), so the broken KAT fails POST first — a KAT
        # failure, which AMA_BUILD_PIPELINE=1 does not excuse. Editing
        # _self_test.py also stales the .py digest, but POST never reaches the
        # integrity stage to notice, which is the point: the build-pipeline flag
        # forgives a stale artefact, never a broken algorithm.
        result = _run_python(
            """
            import ama_cryptography  # noqa: F401
            print("IMPORTED")
            """,
            cwd=root,
            env_extra={"AMA_BUILD_PIPELINE": "1"},
        )
        assert result.returncode != 0, (
            "AMA_BUILD_PIPELINE=1 excused a failing Known Answer Test; a release "
            "container could smoke-test a broken wheel and call it built.\n"
            + result.stdout
        )
        assert "IMPORTED" not in result.stdout
        assert "SHA3-256" in result.stdout + result.stderr


# ---------------------------------------------------------------------------
# 2. Error state inhibits cryptographic output (FIPS 140-3 §4.9.2)
# ---------------------------------------------------------------------------


class TestErrorStateInhibitsOutput:
    """No cryptographic output may leave the module while it is in ERROR."""

    #: One representative from each family that reaches the native library.
    #: The exhaustive check is static and lives in
    #: ``tools/check_error_state_gating.py`` (exercised below) — this list is
    #: the behavioural spot-check that the static rule has the effect claimed.
    OPERATIONS = (
        "native_ed25519_keypair()",
        "native_ed25519_sign(b'm', bytes(64))",
        "native_sha3_256(b'm')",
        "native_sha256(b'm')",
        "native_hmac_sha3_256(bytes(32), b'm')",
        "native_hkdf(bytes(32), bytes(16), b'i', 32)",
        "native_aes256_gcm_encrypt(bytes(32), bytes(12), b'p', b'')",
        "generate_kyber_keypair()",
        "generate_dilithium_keypair()",
        "native_ml_kem_keypair(1024)",
        "native_ml_dsa_keypair(65)",
        "native_x25519_keypair()",
        "native_chacha20poly1305_encrypt(bytes(32), bytes(12), b'p', b'')",
        "frost_keygen_trusted_dealer(2, 3)",
    )

    def test_every_family_refuses_in_error_state(self, tree_with_native: Path) -> None:
        # Injected as a single-line literal: a multi-line interpolation would
        # defeat textwrap.dedent's common-prefix detection in _run_python.
        ops = repr(list(self.OPERATIONS))
        result = _run_python(
            f"""
            import ama_cryptography as a
            import ama_cryptography._self_test as st
            import ama_cryptography.pqc_backends as pb

            assert a.module_status() == "OPERATIONAL"
            st._set_error("simulated POST failure")

            OPS = {ops}
            leaked = []
            for src in OPS:
                try:
                    eval("pb." + src)
                except a.CryptoModuleError:
                    pass
                except Exception as exc:
                    leaked.append((src, "wrong exception: %r" % (exc,)))
                else:
                    leaked.append((src, "PRODUCED OUTPUT"))
            if leaked:
                raise SystemExit("LEAKED: %r" % (leaked,))
            print("ALL REFUSED")
            """,
            cwd=tree_with_native,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ALL REFUSED" in result.stdout

    def test_static_gate_covers_every_native_entry_point(self) -> None:
        """The exhaustive rule is enforced by a tool, not by this test's list."""
        checker = REPO_ROOT / "tools" / "check_error_state_gating.py"
        assert checker.is_file(), "the error-state gating checker is missing"
        result = subprocess.run(
            [sys.executable, str(checker)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_gate_tool_detects_an_ungated_function(self, tmp_path: Path) -> None:
        """A checker that cannot fail is not a checker.

        Runs the checker's own audit logic over a synthetic module so the
        negative case is proven without mutating the real source tree.
        """
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        module = tmp_path / "fake_backends.py"
        module.write_text(
            textwrap.dedent(
                '''
                def gated_op(x):
                    """Doc."""
                    check_crypto_permitted()
                    return _native_lib.ama_thing(x)

                def ungated_op(x):
                    """Doc."""
                    return _native_lib.ama_thing(x)

                def _private_op(x):
                    return _native_lib.ama_thing(x)

                def pure_python(x):
                    return x + 1
                '''
            ),
            encoding="utf-8",
        )

        ungated, stale, checked = gate.audit(module, exempt={})
        assert stale == []
        assert checked == 2, "only public functions touching _native_lib count"
        assert [name for name, _ in ungated] == ["ungated_op"]


# ---------------------------------------------------------------------------
# 3. Guard semantics
# ---------------------------------------------------------------------------


class TestCheckCryptoPermitted:
    """The guard must be permissive enough for POST and strict everywhere else."""

    @pytest.fixture(autouse=True)
    def _restore_state(self):
        from ama_cryptography import _self_test as st

        saved = (st._MODULE_STATE, st._ERROR_REASON, st._SELF_TEST_THREAD)
        yield
        st._MODULE_STATE, st._ERROR_REASON, st._SELF_TEST_THREAD = saved

    def test_permits_operational(self) -> None:
        from ama_cryptography import _self_test as st

        st._MODULE_STATE = "OPERATIONAL"
        st.check_crypto_permitted()  # must not raise

    def test_refuses_error_and_names_root_cause(self) -> None:
        from ama_cryptography import _self_test as st
        from ama_cryptography.exceptions import CryptoModuleError

        st._MODULE_STATE = "ERROR"
        st._ERROR_REASON = "sentinel root cause"
        with pytest.raises(CryptoModuleError, match="sentinel root cause"):
            st.check_crypto_permitted()

    def test_permits_self_test_only_on_the_post_thread(self) -> None:
        """POST's own KATs may call the primitives; other threads may not.

        Widening the allowance to "any thread while state is SELF_TEST" would
        open the whole native surface for the duration of every
        ``reset_module()`` call — which is precisely the window an operator
        opens after a failure.
        """
        from ama_cryptography import _self_test as st
        from ama_cryptography.exceptions import CryptoModuleError

        st._MODULE_STATE = "SELF_TEST"
        st._SELF_TEST_THREAD = threading.get_ident()
        st.check_crypto_permitted()  # this thread is the POST thread

        outcome: List[object] = []

        def other_thread() -> None:
            try:
                st.check_crypto_permitted()
                outcome.append("permitted")
            except CryptoModuleError:
                outcome.append("refused")

        worker = threading.Thread(target=other_thread)
        worker.start()
        worker.join(timeout=30)
        assert outcome == ["refused"]

    def test_post_clears_the_thread_allowance(self) -> None:
        """The allowance must not survive the run that granted it."""
        from ama_cryptography import _self_test as st

        assert st._SELF_TEST_THREAD is None, (
            "a completed POST left its thread allowance set; the guard would "
            "stay permissive on that thread for the life of the process"
        )


# ---------------------------------------------------------------------------
# 4. Attestation tells skips apart from passes
# ---------------------------------------------------------------------------


class TestAttestation:
    """``OPERATIONAL`` is a weaker claim than "everything was tested"."""

    @pytest.fixture
    def fresh_post(self):
        """Re-run POST so these assertions describe a known run.

        ``module_attestation()`` reports live global state, and the rest of the
        suite legitimately perturbs it — several modules drive the state machine
        directly to exercise failure paths.  Re-running POST makes the
        assertions here independent of test order rather than of test hygiene.
        """
        from ama_cryptography import _self_test as st

        assert st.reset_module() is True, st.module_error_reason()
        yield st

    def test_reports_fully_verified_on_a_complete_run(self, fresh_post) -> None:
        att = fresh_post.module_attestation()
        assert att["state"] == "OPERATIONAL"
        assert att["fully_verified"] is True, att
        assert att["tests_skipped"] == 0, att

    def test_digest_only_integrity_is_not_fully_verified(self, fresh_post) -> None:
        """An unsigned digest is corruption detection, not tamper detection.

        It passes, so it is not a failure — but it is not the check the signed
        path performs, and a release gate has to be able to see the difference.
        Recorded as a skip so it lands in the same machinery as an untested
        algorithm rather than being promoted to a pass.
        """
        st = fresh_post
        saved = list(st._SELF_TEST_RESULTS)
        try:
            st._SELF_TEST_RESULTS[:] = [
                ("integrity", None, "Module integrity verified (digest-only fallback: ...)")
            ] + [row for row in saved if row[0] != "integrity"]
            att = st.module_attestation()
            assert att["fully_verified"] is False, (
                "a module verified only by an unsigned plaintext digest "
                "reported itself as fully verified"
            )
            assert any(name == "integrity" for name, _ in att["skipped"])
        finally:
            st._SELF_TEST_RESULTS[:] = saved

    def test_a_skip_is_not_a_pass(self, fresh_post) -> None:
        st = fresh_post

        saved = list(st._SELF_TEST_RESULTS)
        try:
            st._SELF_TEST_RESULTS.append(("ML-KEM-1024", None, "skipped (backend absent)"))
            att = st.module_attestation()
            assert att["fully_verified"] is False, (
                "a run with an untested approved algorithm reported itself as "
                "fully verified"
            )
            assert att["tests_skipped"] == 1
            assert att["skipped"][0][0] == "ML-KEM-1024"
        finally:
            st._SELF_TEST_RESULTS[:] = saved

    def test_carries_native_backend_provenance(self) -> None:
        from ama_cryptography import module_attestation

        native = module_attestation()["native_backend"]
        assert set(native) >= {"loaded", "path", "searched_dirs", "errors"}


# ---------------------------------------------------------------------------
# 5. Integrity verdicts are tri-state
# ---------------------------------------------------------------------------


class TestIntegrityTriState:
    """"Cannot verify" and "verification failed" are different claims."""

    def test_missing_artefact_is_not_a_tamper_verdict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No artefact means "nothing was checked", not "the check failed"."""
        from ama_cryptography import _self_test as st

        # ``None`` in sys.modules makes an import of that name raise
        # ImportError, which is the condition the function branches on.  The
        # attribute on the parent package has to go too: ``from pkg import mod``
        # resolves through the parent's namespace first when the submodule has
        # already been imported once, and would otherwise sail past the patch.
        import ama_cryptography as pkg

        monkeypatch.setitem(sys.modules, "ama_cryptography._integrity_signature", None)
        monkeypatch.delattr(pkg, "_integrity_signature", raising=False)
        verdict, detail = st._verify_signed_integrity("00" * 32)
        assert verdict is None, (
            f"a missing artefact must be 'cannot verify' (None), got {verdict!r}: {detail}"
        )
        assert "no signed-integrity artefact" in detail

    def test_absent_verifier_is_not_a_tamper_verdict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reported bug: a missing native library read as tampering.

        ``_ED25519_NATIVE_AVAILABLE`` being False means the verifier could not
        run.  A verifier that did not run has detected nothing.
        """
        from ama_cryptography import _self_test as st
        from ama_cryptography import pqc_backends as pb

        monkeypatch.setattr(pb, "_ED25519_NATIVE_AVAILABLE", False)
        from ama_cryptography import _integrity_signature as sig_mod

        verdict, detail = st._verify_signed_integrity(sig_mod.INTEGRITY_DIGEST_HEX)
        assert verdict is None, (
            f"an unavailable verifier must be 'cannot verify' (None), got "
            f"{verdict!r}: {detail}"
        )
        assert "not built" not in detail, "the misleading build claim is back"

    def test_digest_mismatch_is_a_tamper_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import _self_test as st

        verdict, detail = st._verify_signed_integrity("ff" * 32)
        assert verdict is False, (
            f"a present-but-wrong artefact must be False, got {verdict!r}: {detail}"
        )
        assert "mismatch" in detail

    def test_verdict_is_not_carried_by_the_message_text(self) -> None:
        """The dispatch must not depend on prose.

        ``verify_module_integrity`` used to classify the outcome with
        ``"no signed-integrity artefact" not in detail``.  Rewording a message
        silently reclassified tampering as a benign fallback or the reverse.
        """
        import io
        import tokenize

        source = (PKG_DIR / "_self_test.py").read_text(encoding="utf-8")
        # Strip comments and docstrings so this pins the *code*, not the prose
        # that explains why the code is written this way.
        code_only = "".join(
            token.string
            for token in tokenize.generate_tokens(io.StringIO(source).readline)
            if token.type not in (tokenize.COMMENT, tokenize.STRING)
        )
        assert "signed-integrityartefact" not in code_only.replace(" ", ""), (
            "the security-critical branch is a substring test against a "
            "human-readable message again"
        )

        # And positively: the dispatch must be on the tri-state verdict.
        assert "if signed_ok is True:" in source
        assert "if signed_ok is False:" in source


# ---------------------------------------------------------------------------
# 6. Native-backend discovery diagnostics
# ---------------------------------------------------------------------------


class TestNativeBackendDiagnostics:
    """A library that is present-but-broken must not look like a missing one."""

    def test_records_the_loader_error_for_an_unloadable_file(self, tmp_path: Path) -> None:
        from ama_cryptography import pqc_backends as pb

        broken = tmp_path / "libama_cryptography.so"
        broken.write_bytes(b"this is not an ELF object\n")

        before = len(pb._LOAD_DIAGNOSTICS["errors"])
        assert pb._try_load_library(broken) is None
        errors = pb._LOAD_DIAGNOSTICS["errors"]
        assert len(errors) == before + 1, "the loader error was discarded again"
        path, message = errors[-1]
        assert path == str(broken)
        assert message, "an empty loader message is no better than silence"

    def test_summary_distinguishes_broken_from_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ama_cryptography import pqc_backends as pb

        # The "loaded" branch of the summary keys off the real _native_lib
        # handle, not the mutable scratch dict, so the broken/absent branches
        # are only reachable with no library actually loaded.  monkeypatch
        # restores _native_lib after the test.
        monkeypatch.setattr(pb, "_native_lib", None)
        saved = {k: (list(v) if isinstance(v, list) else v) for k, v in pb._LOAD_DIAGNOSTICS.items()}
        try:
            pb._LOAD_DIAGNOSTICS.update(
                {
                    "loaded": False,
                    "path": None,
                    "errors": [("/somewhere/libama_cryptography.so", "wrong ELF class")],
                    "searched_dirs": ["/somewhere"],
                    "candidates": ["/somewhere/libama_cryptography.so"],
                }
            )
            broken_summary = pb.native_backend_load_summary()
            assert "FOUND but could not be loaded" in broken_summary
            assert "wrong ELF class" in broken_summary

            pb._LOAD_DIAGNOSTICS.update({"errors": [], "candidates": []})
            absent_summary = pb.native_backend_load_summary()
            assert "no native library found" in absent_summary
            assert "cmake" in absent_summary
        finally:
            pb._LOAD_DIAGNOSTICS.clear()
            pb._LOAD_DIAGNOSTICS.update(saved)

    def test_diagnostics_are_a_copy(self) -> None:
        from ama_cryptography import pqc_backends as pb

        snapshot = pb.native_backend_diagnostics()
        snapshot["searched_dirs"].append("/injected")
        assert "/injected" not in pb._LOAD_DIAGNOSTICS["searched_dirs"]


# ---------------------------------------------------------------------------
# 7. INVARIANT-7 is enforced where it actually runs
# ---------------------------------------------------------------------------


class TestInvariant7Enforcement:
    """"A warning without a hard stop" is explicitly not an acceptable substitute."""

    def test_no_backend_fails_post_rather_than_skipping(
        self, tree_without_native: Path
    ) -> None:
        result = _run_python(
            """
            import ama_cryptography  # noqa: F401
            """,
            cwd=tree_without_native,
            env_extra={"AMA_POST_DIAGNOSTIC_IMPORT": "1"},
        )
        assert result.returncode == 0, result.stderr
        combined = result.stdout + result.stderr
        assert "INVARIANT-7" in combined, (
            "a backend-less import did not cite the invariant it violates"
        )

    def test_docs_build_override_is_honoured(self, tree_without_native: Path) -> None:
        """The one exception INVARIANT-7 carves out must still work.

        Sphinx autodoc has to import the package to read signatures.  The
        override permits the import; it must not permit cryptography.
        """
        result = _run_python(
            """
            import ama_cryptography as a
            import ama_cryptography.pqc_backends as pb
            print("STATE", a.module_status())
            assert a.module_attestation()["fully_verified"] is False
            try:
                pb.native_sha3_256(b"x")
            except Exception as exc:
                print("REFUSED", type(exc).__name__)
            else:
                raise AssertionError("crypto ran under the docs override")
            """,
            cwd=tree_without_native,
            env_extra={"AMA_SPHINX_BUILD": "1"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "REFUSED" in result.stdout
