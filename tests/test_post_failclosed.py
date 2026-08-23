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

import hashlib
import os
import shutil
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from types import ModuleType
from typing import Any, Generator

import pytest

from tests.conftest import native_library_present

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

pytestmark = pytest.mark.fips


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_python(
    code: str,
    cwd: Path,
    env_extra: dict[str, str] | None = None,
    *,
    isolated: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run ``code`` in a fresh interpreter rooted at ``cwd``.

    ``isolated=True`` adds ``-S`` (do not import ``site``). The no-native tests
    need it. When this test suite runs against an *editable* install
    (``pip install -e .``, as CI does), setuptools registers a meta-path finder
    via a ``.pth`` file that maps ``ama_cryptography.*`` — including the compiled
    Cython bindings — back to the developer's build tree. That finder resolves
    ``ama_cryptography.sha3_binding`` even when the copy under ``cwd`` has had
    every ``.so`` removed, so ``native_sha3_256`` finds a working Cython backend
    and the "no native backend" premise is silently false. ``-S`` skips
    ``.pth`` processing, so the subprocess sees only the copy on ``PYTHONPATH``
    (still honoured under ``-S``) and the stdlib — a genuinely backend-free tree,
    which is also what a real deployment without the C library looks like (the
    Cython bindings dynamically link ``libama_cryptography`` and cannot load
    without it). The core package imports with no third-party dependency
    (INVARIANT-1), so dropping ``site`` costs these subprocesses nothing.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    # An installed copy of the package would shadow the tree under test.
    env["PYTHONPATH"] = str(cwd)
    # ...and AMA_CRYPTO_LIB_PATH would hand the tree a native backend, which
    # is the one thing this fixture exists to withhold.  The loader's own
    # error message tells the reader to "point AMA_CRYPTO_LIB_PATH at an
    # existing build", so running this suite the documented way exported it —
    # and these subprocesses then found a backend, which silently falsified
    # the "no native backend" premise and produced 5 failures that say nothing
    # about the code.  Scrubbing PYTHONPATH and not this was half a fixture.
    env.pop("AMA_CRYPTO_LIB_PATH", None)
    env.update(env_extra or {})
    argv = [sys.executable, "-S", "-c"] if isolated else [sys.executable, "-c"]
    return subprocess.run(
        [*argv, textwrap.dedent(code)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _drop_unbound_extensions(pkg_root: Path) -> None:
    """Remove compiled binding extensions the signed artefact does not cover.

    A source-tree artefact deliberately binds NO extensions: they are
    per-interpreter and not reproducible, so binding one tree's would read as
    a digest MISMATCH — a tampering verdict — on every other machine (see
    ``_build_sign``'s ``--bind-extensions`` help).  The documented consequence
    is that a tree carrying built-but-uncovered extensions is *correctly*
    reported at below-full integrity strength.

    ``pip install -e .`` builds six such extensions into the package
    directory, so a fixture that copies the package wholesale inherits them
    and can never be "fully verified" — which is what turned five tests red
    across ubuntu, macOS and arm once the strength downgrade stopped being
    dead code.  Dropping the uncovered ones makes the copied tree internally
    consistent, which is the state these tests mean by "healthy".
    """
    try:
        from ama_cryptography import _integrity_signature as _sig

        covered = set(getattr(_sig, "INTEGRITY_BINDING_DIGESTS_HEX", {}) or {})
    except Exception:
        covered = set()
    for suffix in (".so", ".pyd", ".dylib"):
        for path in pkg_root.glob(f"*{suffix}"):
            if path.name.startswith(("libama_cryptography", "ama_cryptography.dll")):
                continue  # the native library, bound separately
            if path.name not in covered:
                path.unlink()


@pytest.fixture(scope="module")
def tree_without_native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package with the native library removed.

    This reproduces the reported condition exactly: sources intact, integrity
    artefacts intact, no discoverable ``libama_cryptography``.
    """
    root = tmp_path_factory.mktemp("no_native")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    # No _drop_unbound_extensions here: the loop below removes every compiled
    # artefact anyway, which is this fixture's whole point.
    for pattern in ("*.so", "*.so.*", "*.dylib", "*.dll", "*.pyd"):
        for artefact in (root / "ama_cryptography").glob(pattern):
            artefact.unlink()
    return root


@pytest.fixture(scope="module")
def tree_with_native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package with whatever native library the tree has."""
    root = tmp_path_factory.mktemp("with_native")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    _drop_unbound_extensions(root / "ama_cryptography")
    if not native_library_present(root / "ama_cryptography"):
        pytest.skip("native library not built in this tree")
    return root


#: The binding extensions ``TestCythonBindingsGated`` needs to exist for its
#: probe to reach any Cython entry point at all.
_REQUIRED_BINDING_STEMS = ("ed25519_binding", "hmac_binding", "sha3_binding")


def _binding_extension_names(pkg_root: Path) -> set[str]:
    """Compiled binding extensions present in ``pkg_root``, by module stem."""
    stems: set[str] = set()
    for suffix in (".so", ".pyd", ".dylib"):
        for path in pkg_root.glob(f"*{suffix}"):
            if path.name.startswith(("libama_cryptography", "ama_cryptography.dll")):
                continue
            stems.add(path.name.split(".", 1)[0])
    return stems


@pytest.fixture(scope="module")
def tree_with_bindings(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of the package that KEEPS its compiled binding extensions.

    ``tree_with_native`` drops every extension the signed artefact does not
    cover, and in a source tree ``INTEGRITY_BINDING_DIGESTS_HEX`` is ``{}`` by
    design, so it drops ALL of them.  That is right for the tests that need an
    internally consistent tree, and fatal for the one test whose subject is the
    extensions themselves: its probe's ``import ... except ImportError`` arm
    fired on every run, and the assertion's ``or "SKIP" in result.stdout``
    escape turned that into a pass.  Measured on this tree — the fixture
    removed all six extensions and the probe printed
    ``SKIP: Cython bindings not compiled`` — so the only behavioural proof that
    the Cython bindings inhibit output in the FIPS ERROR state had stopped
    executing any of the code it names.

    Keeping the extensions means this copy reports at below-full integrity
    strength ("binding extensions PARTIALLY covered (developer build)"), which
    is the CORRECT verdict for a tree carrying built-but-uncovered extensions
    and is not what this test asserts on.  A genuinely unbuilt tree skips here,
    in the parent process, so it is reported as ``skipped`` rather than passing
    on a string the assertion happens to accept.
    """
    root = tmp_path_factory.mktemp("with_bindings")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    if not native_library_present(root / "ama_cryptography"):
        pytest.skip("native library not built in this tree")
    present = _binding_extension_names(root / "ama_cryptography")
    missing = [stem for stem in _REQUIRED_BINDING_STEMS if stem not in present]
    if missing:
        pytest.skip(
            "Cython binding extensions not built in this tree "
            f"(missing: {', '.join(missing)}); build with "
            "`python setup.py build_ext --inplace`"
        )
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
            isolated=True,
        )

        assert result.returncode != 0, (
            "import succeeded with a failed POST — a caller cannot distinguish "
            "this from a working module.\nstdout:\n" + result.stdout
        )
        assert (
            "verified" not in result.stdout
        ), "the caller's success path ran despite the POST failure"
        assert "CryptoModuleError" in result.stderr

    def test_failure_message_names_the_real_cause(self, tree_without_native: Path) -> None:
        """The diagnostic must describe the search, not assert a broken build.

        ``native Ed25519 not built`` was a claim about the C build, and it was
        usually false: the library was built and simply not on the search path.
        """
        result = _run_python("import ama_cryptography", cwd=tree_without_native, isolated=True)

        combined = result.stdout + result.stderr
        assert "no native library found" in combined
        assert "searched directories" in combined
        # The remedy has to be present, and it has to be the right remedy.
        assert "cmake" in combined or "AMA_CRYPTO_LIB_PATH" in combined
        assert (
            "not built — cannot verify signature" not in combined
        ), "the misleading legacy diagnostic is back"

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

    def test_diagnostic_flag_permits_import_but_not_crypto(self, tree_without_native: Path) -> None:
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
            isolated=True,
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
            "container could smoke-test a broken wheel and call it built.\n" + result.stdout
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

    #: The SHAKE and HKDF-SHA-2 public wrappers reach the native library only
    #: INDIRECTLY: ``native_shake128`` is ``return _native_shake(...)`` and
    #: ``native_hkdf_sha256`` is ``return _native_hkdf_sha2(...)``, and each
    #: shared helper reaches the C kernel through ``getattr(_native_lib, fn)``.
    #: A body-level AST scan of the public wrapper sees no native call, so
    #: ``tools/check_error_state_gating.py`` cannot cover them — this list is
    #: their ONLY output-inhibition enforcement, so every wrapper is named here,
    #: not one representative per family.
    INDIRECT_OPERATIONS = (
        "native_shake128(b'm', 16)",
        "native_shake256(b'm', 16)",
        "native_hkdf_sha256(bytes(32), 32)",
        "native_hkdf_sha384(bytes(32), 32)",
        "native_hkdf_sha512(bytes(32), 32)",
        # SHA-512/384, SHA3-384 and PBKDF2 route through _native_sha2_ext /
        # _native_pbkdf2 — the same getattr indirection, the same blindness
        # in the static gate, the same rule: every wrapper, not a sample.
        "native_sha512(b'm')",
        "native_sha384(b'm')",
        "native_sha3_384(b'm')",
        "native_pbkdf2_hmac_sha256(b'p', b's', 1, 32)",
        "native_pbkdf2_hmac_sha512(b'p', b's', 1, 32)",
    )

    def test_indirect_native_surfaces_refuse_in_error_state(self, tree_with_native: Path) -> None:
        """SHAKE / HKDF-SHA-2 reach native through a private helper, so the
        static gate is blind to them; assert their runtime refusal directly."""
        ops = repr(list(self.INDIRECT_OPERATIONS))
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
            import check_error_state_gating as gate  # type: ignore[import-not-found]  # loaded from tools/ via runtime sys.path insert; mypy cannot see it (PFC-001)
        finally:
            sys.path.pop(0)

        module = tmp_path / "fake_backends.py"
        module.write_text(
            textwrap.dedent('''
                def gated_op(x):
                    """Doc."""
                    check_crypto_permitted()
                    return _native_lib.ama_thing(x)

                def gated_via_attribute(x):
                    """Guard reached through a module reference — still a real
                    guard call, and must not be reported as ungated."""
                    _module_state.check_crypto_permitted()
                    return _native_lib.ama_thing(x)

                def ungated_op(x):
                    """Doc."""
                    return _native_lib.ama_thing(x)

                def _private_op(x):
                    return _native_lib.ama_thing(x)

                def pure_python(x):
                    return x + 1
                '''),
            encoding="utf-8",
        )

        ungated, stale, checked = gate.audit(module, exempt={})
        assert stale == []
        assert checked == 3, "only public functions touching _native_lib count"
        assert [name for name, _ in ungated] == ["ungated_op"]

    def test_gate_tool_sees_a_symbol_selected_by_a_conditional(self, tmp_path: Path) -> None:
        """A native symbol chosen with ``a if cond else b`` is still a native call.

        ``_native_handle_aliases`` matched only two flat shapes —
        ``getattr(_native_lib, name)`` and ``_native_lib.ama_x`` — so a symbol
        selected between two of those was invisible, the body appeared to make
        no native call, and ``audit()`` skipped the function without ever
        asking whether it was gated.

        That was live: ``native_nistp_ecdsa_verify`` in ``pqc_backends.py``
        binds ``fn = _native_lib.ama_..._raw_ex if raw else _native_lib.ama_..._ex``
        and is a public module-level entry point in the one module this gate
        audits.  Removing its guard changed the audit's output not at all.

        The annotated-assignment case is here for the same reason: an
        annotation on the binding is not a different kind of binding.
        """
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        module = tmp_path / "fake_conditional.py"
        module.write_text(
            textwrap.dedent('''
                from typing import Callable

                def ungated_conditional(x, raw):
                    """The shape pqc_backends actually uses."""
                    fn = _native_lib.ama_verify_raw if raw else _native_lib.ama_verify
                    return fn(x)

                def gated_conditional(x, raw):
                    """Same shape, correctly guarded — must NOT be reported."""
                    check_crypto_permitted()
                    fn = _native_lib.ama_verify_raw if raw else _native_lib.ama_verify
                    return fn(x)

                def ungated_annotated(x):
                    """An annotation does not make it a different binding."""
                    fn: Callable = _native_lib.ama_thing
                    return fn(x)

                def ungated_getattr_conditional(x, raw):
                    """Conditional over the getattr route."""
                    fn = getattr(_native_lib, "a") if raw else getattr(_native_lib, "b")
                    return fn(x)
                '''),
            encoding="utf-8",
        )

        ungated, stale, checked = gate.audit(module, exempt={})
        assert stale == []
        assert checked == 4, "every conditional/annotated binding must be audited"
        assert sorted(name for name, _ in ungated) == [
            "ungated_annotated",
            "ungated_conditional",
            "ungated_getattr_conditional",
        ]

    def test_gate_tool_does_not_demand_a_guard_for_a_wrapped_reference(
        self, tmp_path: Path
    ) -> None:
        """The widening must not over-reach into "mentions the library".

        ``x = wrapper(_native_lib.ama_y)`` does not bind ``x`` to the native
        symbol, so calling ``x`` is not a native call and the function must not
        be required to carry a guard.  A gate that fires on correct code is one
        people learn to bypass, which is why the recursion covers only the
        forms that ARE the resulting callable.
        """
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        module = tmp_path / "fake_wrapped.py"
        module.write_text(
            textwrap.dedent('''
                def passes_symbol_to_a_wrapper(x):
                    """Not a native call: `handle` is whatever wrapper returns."""
                    handle = _wrap(_native_lib.ama_thing)
                    return handle(x)
                '''),
            encoding="utf-8",
        )

        ungated, stale, checked = gate.audit(module, exempt={})
        assert ungated == []
        assert stale == []
        assert checked == 0, "a wrapped reference is not a native entry point"

    def test_gate_tool_rejects_a_guard_placed_after_the_native_call(self, tmp_path: Path) -> None:
        """A guard that runs after the C call cannot inhibit its output.

        ``audit_pyx`` has rejected this ordering since it was written; the
        Python half asked only whether a guard appeared anywhere in the body,
        so the two halves of one gate enforced different rules. FIPS 140-3
        §4.9.2 output inhibition is about *not producing* the output, which a
        guard reached afterwards does not achieve.
        """
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        module = tmp_path / "fake_backends.py"
        module.write_text(
            textwrap.dedent('''
                def guard_after_call(x):
                    """The C kernel has already run and produced output."""
                    out = _native_lib.ama_thing(x)
                    check_crypto_permitted()
                    return out

                def guard_before_call(x):
                    """Correct ordering — must not be flagged."""
                    check_crypto_permitted()
                    return _native_lib.ama_thing(x)
                '''),
            encoding="utf-8",
        )

        ungated, _stale, checked = gate.audit(module, exempt={})
        assert checked == 2
        assert [name for name, _ in ungated] == ["guard_after_call"]

    def test_gate_tool_sees_a_native_symbol_reached_through_an_alias(self, tmp_path: Path) -> None:
        """Resolving the symbol and calling it in two statements is still a call.

        ``getattr(_native_lib, name)(...)`` was matched only as a single
        expression. Split in two, neither line matched: the binding is not a
        call and the call is of a plain local name. A function using that shape
        reached the C kernel while the gate recorded it as making no native
        call at all — and a function that makes no native call is never
        required to carry a guard.
        """
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        module = tmp_path / "fake_backends.py"
        module.write_text(
            textwrap.dedent('''
                def aliased_getattr(x):
                    """Two-statement getattr indirection, no guard."""
                    fn = getattr(_native_lib, "ama_thing")
                    return fn(x)

                def aliased_attribute(x):
                    """Bound by attribute access, then called. No guard."""
                    fn = _native_lib.ama_thing
                    return fn(x)

                def aliased_but_gated(x):
                    """Same indirection, guarded first — must not be flagged."""
                    check_crypto_permitted()
                    fn = getattr(_native_lib, "ama_thing")
                    return fn(x)

                def probe_only(x):
                    """An un-called probe configures a signature; not a call."""
                    fn = getattr(_native_lib, "ama_thing", None)
                    return fn is not None
                '''),
            encoding="utf-8",
        )

        ungated, _stale, checked = gate.audit(module, exempt={})
        assert checked == 3, "the un-called probe must not count as a native call"
        assert [name for name, _ in ungated] == ["aliased_attribute", "aliased_getattr"] or [
            name for name, _ in ungated
        ] == ["aliased_getattr", "aliased_attribute"], ungated

    def test_gate_tool_covers_cython_binding_pyx(self, tmp_path: Path) -> None:
        """The gate's .pyx auditor must flag an ungated cy_* binding function."""
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        good = tmp_path / "good.pyx"
        good.write_text(
            textwrap.dedent('''
                def cy_thing(bytes x):
                    """Docstring naming ama_thing() to bait the native scan."""
                    check_crypto_permitted()
                    cdef int rc = ama_thing(<const unsigned char*>x)
                    return rc
                '''),
            encoding="utf-8",
        )
        assert gate.audit_pyx(good) == [], "a correctly gated binding was flagged"

        bad = tmp_path / "bad.pyx"
        bad.write_text(
            textwrap.dedent('''
                def cy_thing(bytes x):
                    """Doc."""
                    cdef int rc = ama_thing(<const unsigned char*>x)
                    return rc
                '''),
            encoding="utf-8",
        )
        assert [n for n, _ in gate.audit_pyx(bad)] == ["cy_thing"]

        after = tmp_path / "after.pyx"
        after.write_text(
            textwrap.dedent('''
                def cy_thing(bytes x):
                    """Doc."""
                    cdef int rc = ama_thing(<const unsigned char*>x)
                    check_crypto_permitted()
                    return rc
                '''),
            encoding="utf-8",
        )
        assert [n for n, _ in gate.audit_pyx(after)] == ["cy_thing"], (
            "a guard placed AFTER the native call must still be flagged — output "
            "is already produced by then"
        )


# ---------------------------------------------------------------------------
# 2b. key_formats must not export secret key material in the error state
# ---------------------------------------------------------------------------


class TestKeyFormatsInhibitsSecretExport:
    """FIPS 140-3 §4.9.2: private-key serialisation is secret-key output."""

    @pytest.fixture(autouse=True)
    def _restore_state(self) -> Generator[None, None, None]:
        # The raw state lives in the _module_state leaf — rebinding it anywhere
        # else would not be seen by the guards (and _self_test deliberately does
        # not re-export the raw names, so the stale spelling fails loudly).
        from ama_cryptography import _module_state as ms

        saved = (ms._MODULE_STATE, ms._ERROR_REASON)
        yield
        ms._MODULE_STATE, ms._ERROR_REASON = saved

    def test_private_key_export_refuses_in_error_state(self, tree_with_native: Path) -> None:
        result = _run_python(
            """
            import ama_cryptography as a
            import ama_cryptography._self_test as st
            import ama_cryptography.key_formats as kf
            import ama_cryptography.pqc_backends as pb

            pk, sk = pb.native_ed25519_keypair()
            priv = kf.PrivateKey("Ed25519", sk[:32], pk)
            # Healthy export works.  Asserted without writing the literal
            # private-key PEM header, so the repository secret-scanner does not
            # flag a marker that guards no actual key.
            pem = priv.to_pem()
            assert pem.startswith("-----BEGIN") and "PRIVATE KEY" in pem

            st._set_error("simulated POST failure")
            leaked = []
            for name in ("to_pkcs8", "to_pem", "to_jwk", "to_cose"):
                try:
                    getattr(priv, name)()
                except a.CryptoModuleError:
                    pass
                except Exception as exc:
                    leaked.append((name, "wrong exception: %r" % (exc,)))
                else:
                    leaked.append((name, "EXPORTED SECRET"))
            if leaked:
                raise SystemExit("LEAKED: %r" % (leaked,))
            print("ALL REFUSED")
            """,
            cwd=tree_with_native,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ALL REFUSED" in result.stdout


# ---------------------------------------------------------------------------
# 2c. Cython binding modules must be gated (they are public submodules)
# ---------------------------------------------------------------------------


class TestCythonBindingsGated:
    """A direct importer of a binding submodule must not reach ungated crypto."""

    def test_bindings_refuse_in_error_state(self, tree_with_bindings: Path) -> None:
        """Every Cython entry point refuses once the module is faulted.

        The import is NOT wrapped in ``try/except ImportError`` any more: the
        fixture has already established that the extensions exist, so an
        ImportError here is a real failure and must surface as one.  The
        previous form swallowed it and printed a token the assertion accepted,
        which is how this test came to run zero lines of the code it names.

        The entry-point list is not hand-maintained either — it is derived from
        each binding module's own ``cy_*`` surface, so a binding that grows a
        new entry point is covered the day it lands rather than the day someone
        remembers to add it here.
        """
        result = _run_python(
            """
            import ama_cryptography as a
            import ama_cryptography._self_test as st
            import ama_cryptography.ed25519_binding as eb
            import ama_cryptography.hmac_binding as hb
            import ama_cryptography.sha3_binding as sb
            import ama_cryptography.hkdf_binding as kb
            import ama_cryptography.dilithium_binding as db

            # Every probe is a call the entry point ACCEPTS when the module is
            # healthy.  That matters: a call with the wrong arity raises
            # TypeError during argument conversion, before the gate is ever
            # consulted, so it would report "refused" without the gate having
            # done anything.  Building the probe table against a healthy module
            # first (below) is what rules that out.
            pk, sk = eb.cy_ed25519_keypair(bytes(32))
            sig = eb.cy_ed25519_sign(b"m", sk)
            dpk, dsk = db.cy_dilithium_keygen()
            dsig = db.cy_dilithium_sign(b"m", dsk)

            probes = {
                "ed25519_binding.cy_ed25519_keypair":
                    lambda: eb.cy_ed25519_keypair(bytes(32)),
                "ed25519_binding.cy_ed25519_sign":
                    lambda: eb.cy_ed25519_sign(b"m", sk),
                "ed25519_binding.cy_ed25519_verify":
                    lambda: eb.cy_ed25519_verify(sig, b"m", pk),
                "ed25519_binding.cy_ed25519_batch_verify":
                    lambda: eb.cy_ed25519_batch_verify([(b"m", sig, pk)]),
                "hmac_binding.cy_hmac_sha3_256":
                    lambda: hb.cy_hmac_sha3_256(bytes(32), b"m"),
                "sha3_binding.cy_sha3_256":
                    lambda: sb.cy_sha3_256(b"m"),
                "hkdf_binding.cy_hkdf":
                    lambda: kb.cy_hkdf(bytes(32), 32, bytes(16), b"info"),
                "dilithium_binding.cy_dilithium_keygen":
                    lambda: db.cy_dilithium_keygen(),
                "dilithium_binding.cy_dilithium_sign":
                    lambda: db.cy_dilithium_sign(b"m", dsk),
                "dilithium_binding.cy_dilithium_verify":
                    lambda: db.cy_dilithium_verify(dsig, b"m", dpk),
            }

            modules = {
                "ed25519_binding": eb,
                "hmac_binding": hb,
                "sha3_binding": sb,
                "hkdf_binding": kb,
                "dilithium_binding": db,
            }
            entry_points = []
            for mod_name, mod in modules.items():
                for attr in dir(mod):
                    if attr.startswith("cy_") and callable(getattr(mod, attr)):
                        entry_points.append(mod_name + "." + attr)
            if not entry_points:
                raise SystemExit("NO ENTRY POINTS DISCOVERED")

            # Discovery drives the probe table, not the other way round: an
            # entry point that grows without a probe is a hard failure here
            # rather than a silent hole in the only behavioural coverage these
            # bindings have.
            unprobed = sorted(set(entry_points) - set(probes))
            if unprobed:
                raise SystemExit("UNPROBED ENTRY POINTS: %r" % (unprobed,))
            stale = sorted(set(probes) - set(entry_points))
            if stale:
                raise SystemExit("PROBES FOR ABSENT ENTRY POINTS: %r" % (stale,))

            # Each probe must SUCCEED while the module is healthy.  Without
            # this, a probe that was wrong in some other way (bad argument
            # types, a stale signature) would raise on the faulted run too and
            # be scored as a refusal.
            for name in entry_points:
                probes[name]()

            st._set_error("simulated POST failure")

            leaked = []
            for name in entry_points:
                try:
                    probes[name]()
                except a.CryptoModuleError:
                    pass
                except Exception as exc:
                    leaked.append((name, repr(exc)))
                else:
                    leaked.append((name, "PRODUCED OUTPUT"))
            if leaked:
                raise SystemExit("LEAKED: %r" % (leaked,))
            print("ALL REFUSED (%d entry points)" % len(entry_points))
            """,
            cwd=tree_with_bindings,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ALL REFUSED" in result.stdout, result.stdout + result.stderr
        # Non-vacuity: the probe must have found entry points to call.  A run
        # that discovered zero would print "ALL REFUSED (0 entry points)" and
        # otherwise look identical to a successful one.
        count = int(result.stdout.split("ALL REFUSED (")[1].split(" ")[0])
        assert count >= len(_REQUIRED_BINDING_STEMS), (
            f"only {count} Cython entry point(s) discovered",
            result.stdout,
        )


# ---------------------------------------------------------------------------
# 2d. Class-based and cross-module crypto surfaces refuse in the error state
# ---------------------------------------------------------------------------


class TestClassAndCrossModuleInhibition:
    """The error state must inhibit output from class methods and from modules
    that reach the native library indirectly — the blind spots that let
    AmaContext, HybridCombiner, AgentBinding and SessionStore run crypto while
    the module was faulted."""

    def test_surfaces_refuse_in_error_state(self, tree_with_native: Path) -> None:
        # AmaContext (pqc_backends class methods) is covered authoritatively by
        # the static gate; this behavioural test covers the modules that reach
        # native INDIRECTLY through a private helper, which the AST gate cannot
        # see: HybridCombiner (via _hkdf_native), AgentBinding (via
        # _require_native), and SessionStore (RNG-minted session token). Each is
        # called with valid arguments so a refusal is unambiguous.
        result = _run_python(
            """
            import ama_cryptography as a
            import ama_cryptography._self_test as st
            import ama_cryptography.hybrid_combiner as hc
            import ama_cryptography.agent_binding as ab
            import ama_cryptography.session as se

            # Prove the healthy path first, so a refusal in the error state is
            # a state effect and not a broken call.
            hc.HybridCombiner().combine(b"\\x11" * 32, b"\\x22" * 32, b"c1", b"c2")
            healthy = ab.AgentBinding(
                bytes(32), ab.AgentCapability.DATA_SIGN, list(ab.AgentLifetime)[0]
            )
            healthy.encode()
            se.SessionStore().create()

            st._set_error("simulated POST failure")

            probes = [
                ("HybridCombiner.combine",
                 lambda: hc.HybridCombiner().combine(b"\\x11" * 32, b"\\x22" * 32, b"c1", b"c2")),
                ("AgentBinding.__init__",
                 lambda: ab.AgentBinding(bytes(32), ab.AgentCapability.DATA_SIGN,
                                         list(ab.AgentLifetime)[0])),
                ("AgentBinding.encode", healthy.encode),
                ("SessionStore.create", lambda: se.SessionStore().create()),
            ]
            leaked = []
            for name, fn in probes:
                try:
                    fn()
                except a.CryptoModuleError:
                    pass
                except Exception as exc:
                    leaked.append((name, "%s: %s" % (type(exc).__name__, exc)))
                else:
                    leaked.append((name, "PRODUCED OUTPUT"))
            if leaked:
                raise SystemExit("LEAKED: %r" % (leaked,))
            print("ALL REFUSED")
            """,
            cwd=tree_with_native,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ALL REFUSED" in result.stdout

    def test_gate_reports_class_methods(self) -> None:
        """The gate must descend into classes and flag an ungated method."""
        import ast as _ast

        sys.path.insert(0, str(REPO_ROOT / "tools"))
        try:
            import check_error_state_gating as gate
        finally:
            sys.path.pop(0)

        src = textwrap.dedent("""
            class Ctx:
                def sign(self, m):
                    return self._native_lib.ama_sign(m)

                def _helper(self):
                    return _native_lib.ama_thing()

            class _Private:
                def sign(self, m):
                    return _native_lib.ama_sign(m)
            """)
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(src)
            path = Path(fh.name)
        try:
            ungated, _stale, _checked = gate.audit(path, exempt={})
            names = [n for n, _ in ungated]
            assert "Ctx.sign" in names, names
            assert "Ctx._helper" not in names, "private method must be skipped"
            assert not any(n.startswith("_Private") for n in names), "private class skipped"
        finally:
            path.unlink()
        assert _ast is not None


# ---------------------------------------------------------------------------
# 3. Guard semantics
# ---------------------------------------------------------------------------


class TestCheckCryptoPermitted:
    """The guard must be permissive enough for POST and strict everywhere else."""

    @pytest.fixture(autouse=True)
    def _restore_state(self) -> Generator[None, None, None]:
        # State pokes target _module_state, the leaf the guards read; the guard
        # is still CALLED through _self_test in these tests, so the re-export
        # facade is exercised against the leaf's state in the same breath.
        from ama_cryptography import _module_state as ms

        saved = (ms._MODULE_STATE, ms._ERROR_REASON, ms._SELF_TEST_THREAD)
        yield
        ms._MODULE_STATE, ms._ERROR_REASON, ms._SELF_TEST_THREAD = saved

    def test_reexports_are_the_leaf_objects(self) -> None:
        """_self_test's guard names must BE the leaf's functions, not copies.

        A divergent copy would read different state than the one tests and
        operators drive, making every assertion through the facade a no-op.
        """
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st

        assert st.check_crypto_permitted is ms.check_crypto_permitted
        assert st.check_operational is ms.check_operational
        assert st.module_status is ms.module_status
        assert st.module_error_reason is ms.module_error_reason
        assert st.secure_token_bytes is ms.secure_token_bytes
        assert st._set_error is ms._set_error
        assert st._set_operational is ms._set_operational
        # The raw state names must NOT be reachable through the facade: a
        # rebind there would silently diverge from what the guards enforce.
        assert not hasattr(st, "_MODULE_STATE")
        assert not hasattr(st, "_ERROR_REASON")
        assert not hasattr(st, "_SELF_TEST_THREAD")

    def test_permits_operational(self) -> None:
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st

        ms._MODULE_STATE = "OPERATIONAL"
        st.check_crypto_permitted()  # must not raise

    def test_refuses_error_and_names_root_cause(self) -> None:
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st
        from ama_cryptography.exceptions import CryptoModuleError

        ms._MODULE_STATE = "ERROR"
        ms._ERROR_REASON = "sentinel root cause"
        with pytest.raises(CryptoModuleError, match="sentinel root cause"):
            st.check_crypto_permitted()

    def test_permits_self_test_only_on_the_post_thread(self) -> None:
        """POST's own KATs may call the primitives; other threads may not.

        Widening the allowance to "any thread while state is SELF_TEST" would
        open the whole native surface for the duration of every
        ``reset_module()`` call — which is precisely the window an operator
        opens after a failure.
        """
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st
        from ama_cryptography.exceptions import CryptoModuleError

        ms._MODULE_STATE = "SELF_TEST"
        ms._SELF_TEST_THREAD = threading.get_ident()
        st.check_crypto_permitted()  # this thread is the POST thread

        outcome: list[object] = []

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
        from ama_cryptography import _module_state as ms

        assert ms._SELF_TEST_THREAD is None, (
            "a completed POST left its thread allowance set; the guard would "
            "stay permissive on that thread for the life of the process"
        )


# ---------------------------------------------------------------------------
# 4. Attestation tells skips apart from passes
# ---------------------------------------------------------------------------


class TestAttestation:
    """``OPERATIONAL`` is a weaker claim than "everything was tested"."""

    @pytest.fixture
    def fresh_post(self) -> Generator[ModuleType, None, None]:
        """Re-run POST so these assertions describe a known run.

        ``module_attestation()`` reports live global state, and the rest of the
        suite legitimately perturbs it — several modules drive the state machine
        directly to exercise failure paths.  Re-running POST makes the
        assertions here independent of test order rather than of test hygiene.
        """
        from ama_cryptography import _self_test as st

        assert st.reset_module() is True, st.module_error_reason()
        yield st

    def test_reports_fully_verified_on_a_complete_run(self, fresh_post: ModuleType) -> None:
        """A run in which every row passed reports itself fully verified.

        The completeness is CONSTRUCTED rather than assumed.  The ambient tree
        legitimately may not be complete: ``pip install -e .`` builds binding
        extensions that a source-tree artefact deliberately does not cover, and
        the documented consequence is an integrity SKIP and below-full
        strength.  Asserting on the ambient state therefore tested the
        environment, not ``module_attestation`` — and failed on every CI job
        that installs the package.  Substituting a passing row for that stage
        keeps the property this test is named for.
        """
        st = fresh_post
        saved = list(st._SELF_TEST_RESULTS)
        try:
            st._SELF_TEST_RESULTS[:] = [
                (name, True if passed is None else passed, detail) for name, passed, detail in saved
            ]
            att = st.module_attestation()
            assert att["state"] == "OPERATIONAL"
            assert att["fully_verified"] is True, att
            assert att["tests_skipped"] == 0, att
        finally:
            st._SELF_TEST_RESULTS[:] = saved

    def test_digest_only_integrity_is_not_fully_verified(self, fresh_post: ModuleType) -> None:
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

    def test_a_skip_is_not_a_pass(self, fresh_post: ModuleType) -> None:
        st = fresh_post

        saved = list(st._SELF_TEST_RESULTS)
        # Measure the DELTA, not an absolute.  The ambient tree may already
        # carry a legitimate skip (an editable install's binding extensions are
        # uncovered by a source-tree artefact by design), which made the old
        # `== 1` read `assert 2 == 1` on every CI job that installs the
        # package.  One added skip must add exactly one, and must drag
        # fully_verified down — that is the property.
        before = st.module_attestation()["tests_skipped"]
        try:
            st._SELF_TEST_RESULTS.append(("ML-KEM-1024", None, "skipped (backend absent)"))
            att = st.module_attestation()
            assert att["fully_verified"] is False, (
                "a run with an untested approved algorithm reported itself as " "fully verified"
            )
            assert att["tests_skipped"] == before + 1
            assert "ML-KEM-1024" in [name for name, _detail in att["skipped"]]
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
    """ "Cannot verify" and "verification failed" are different claims."""

    def test_missing_artefact_is_not_a_tamper_verdict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No artefact means "nothing was checked", not "the check failed"."""
        # ``None`` in sys.modules makes an import of that name raise
        # ImportError, which is the condition the function branches on.  The
        # attribute on the parent package has to go too: ``from pkg import mod``
        # resolves through the parent's namespace first when the submodule has
        # already been imported once, and would otherwise sail past the patch.
        from ama_cryptography import _self_test as st

        # The parent package object, taken from sys.modules rather than via a
        # second ``import ama_cryptography`` spelling: the package is already
        # imported (the line above guarantees it), and mixing ``import`` with
        # ``from ... import`` for the same module in one file is the exact
        # pattern the code scanner flags.
        pkg = sys.modules["ama_cryptography"]

        # Point the artefact reader at a path that does not exist.  Removing
        # the module from ``sys.modules`` no longer simulates an unsigned tree:
        # ``_verify_signed_integrity`` parses the artefact's SOURCE, because
        # reading it through the import system meant reading unvalidated
        # ``__pycache__`` bytecode at a point where nothing had checked it.
        del pkg  # kept above for the import-style note; not the seam any more
        from ama_cryptography import _artefact_source

        monkeypatch.setattr(
            _artefact_source, "artefact_path", lambda *_a, **_k: tmp_path / "absent.py"
        )
        verdict, detail = st._verify_signed_integrity("00" * 32)
        assert (
            verdict is None
        ), f"a missing artefact must be 'cannot verify' (None), got {verdict!r}: {detail}"
        assert "no signed-integrity artefact" in detail

    def test_absent_verifier_is_not_a_tamper_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
            f"an unavailable verifier must be 'cannot verify' (None), got " f"{verdict!r}: {detail}"
        )
        assert "not built" not in detail, "the misleading build claim is back"

    def test_digest_mismatch_is_a_tamper_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ama_cryptography import _self_test as st

        verdict, detail = st._verify_signed_integrity("ff" * 32)
        assert (
            verdict is False
        ), f"a present-but-wrong artefact must be False, got {verdict!r}: {detail}"
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
        saved = {
            k: (list(v) if isinstance(v, list) else v) for k, v in pb._LOAD_DIAGNOSTICS.items()
        }
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
    """ "A warning without a hard stop" is explicitly not an acceptable substitute."""

    def test_no_backend_fails_post_rather_than_skipping(self, tree_without_native: Path) -> None:
        result = _run_python(
            """
            import ama_cryptography  # noqa: F401
            """,
            cwd=tree_without_native,
            isolated=True,
            env_extra={"AMA_POST_DIAGNOSTIC_IMPORT": "1"},
        )
        assert result.returncode == 0, result.stderr
        combined = result.stdout + result.stderr
        assert (
            "INVARIANT-7" in combined
        ), "a backend-less import did not cite the invariant it violates"

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
            isolated=True,
            env_extra={"AMA_SPHINX_BUILD": "1"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "REFUSED" in result.stdout


class TestContinuousRNGTest:
    """FIPS 140-3 §4.9.2 continuous RNG test — the control's own integrity.

    These pin two properties the implementation is easy to lose: the
    compare-and-store is atomic (so the one fault it exists to catch cannot slip
    through an interleaving), and it never retains the caller's key material.
    """

    def test_compare_and_store_is_atomic_under_concurrency(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stuck RNG must be caught even when many threads draw at once.

        Without a lock this is a check-then-act race: threads A and B both read
        the same stale ``previous``, both compare their identical stuck value
        against it, both pass, and two consecutive identical outputs are issued
        as key material with the control silently satisfied.

        Eight threads on a ``Barrier`` are not enough to produce that
        interleaving, and this test used to be exactly that.  The health digest
        is computed BEFORE the critical section, so the unlocked check-then-act
        window is about five pure-Python bytecodes; under the GIL a switch
        lands inside it essentially never.  Measured against a build with
        ``_rng_lock`` removed: 60 consecutive runs of the eight-thread
        scenario, 0 failures.  The test asserted a property it could not
        observe, and the branch's own description of it — "reverting the lock
        makes all 8 threads receive the stuck value" — was false.

        The window is now held open from inside, by instrumenting the state
        the critical section reads rather than the code that reads it:
        ``_rng_state`` is replaced with a mapping whose first eight reads of
        ``previous`` rendezvous on a barrier before returning.  With the lock,
        one thread is inside and the other seven are queued on the lock, so
        that barrier can never fill and times out — one success, seven
        refusals.  Without the lock, all eight are inside together, the
        barrier fills immediately, all eight read ``None`` and all eight are
        issued the identical stuck buffer.  The two outcomes are structurally
        different rather than probabilistically different, which is what makes
        this an assertion instead of a hope.

        The timeout is the only cost, and it is paid only on the correct
        build: 0.5 s once.
        """
        from ama_cryptography import _module_state as ms
        from ama_cryptography.exceptions import CryptoModuleError

        saved_previous = ms._rng_state["previous"]
        saved_state = ms._MODULE_STATE
        saved_reason = ms._ERROR_REASON
        stuck = b"\xa5" * 32

        try:
            ms._rng_state["previous"] = None
            ms._MODULE_STATE = "OPERATIONAL"
            ms._ERROR_REASON = None

            # Force the "stuck DRBG" condition: every draw returns the same
            # buffer.  Patched through monkeypatch's dotted-target form so it is
            # undone automatically — assigning to ``ms.secrets.token_bytes``
            # directly would mutate the shared stdlib module for every other
            # test in the session, including any running concurrently.
            def _stuck_token_bytes(n: int) -> bytes:
                return stuck[:n] if n <= 32 else stuck * (n // 32 + 1)

            monkeypatch.setattr(
                "ama_cryptography._module_state.secrets.token_bytes",
                _stuck_token_bytes,
            )

            refusals: list[BaseException] = []
            successes: list[bytes] = []
            start = threading.Barrier(8)
            # Filled only if eight threads are inside the critical section at
            # once — which is precisely what the lock must prevent.
            inside = threading.Barrier(8)

            class _RendezvousState(dict[str, Any]):
                """A ``_rng_state`` that holds the check-then-act window open.

                Only the ``previous`` read is instrumented, and only while the
                threads are running; every other access behaves as a dict.
                """

                def __getitem__(self, key: str) -> Any:
                    value = super().__getitem__(key)
                    if key == "previous":
                        try:
                            inside.wait(timeout=0.5)
                        except threading.BrokenBarrierError:
                            # The lock is doing its job: the other seven
                            # threads cannot get here.
                            pass
                    return value

            monkeypatch.setattr(ms, "_rng_state", _RendezvousState(previous=None))

            def draw() -> None:
                start.wait()
                try:
                    successes.append(ms.secure_token_bytes(32))
                except CryptoModuleError as exc:
                    refusals.append(exc)

            threads = [threading.Thread(target=draw) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Exactly one draw may establish the baseline; every other draw sees
            # the identical value and must be refused.  The pre-lock code let
            # several through.
            assert len(successes) <= 1, (
                f"{len(successes)} identical draws were issued as key material; "
                "the continuous RNG test must catch consecutive identical outputs"
            )
            assert refusals, "a stuck RNG must trip the continuous test"
            assert (
                len(refusals) == 7
            ), f"expected the other seven draws to be refused, got {len(refusals)}"
            assert ms.module_status() == "ERROR"
        finally:
            # token_bytes and _rng_state are restored by monkeypatch's teardown.
            ms._rng_state["previous"] = saved_previous
            ms._MODULE_STATE = saved_state
            ms._ERROR_REASON = saved_reason

    def test_health_state_does_not_retain_issued_key_material(self) -> None:
        """The health state stores a digest, never the bytes handed to the caller.

        For the common 32-byte draw CPython returns the same object for
        ``buf[:32]``, so storing the sample pinned live key material — an
        Ed25519 seed, say — in module state until the next draw.
        """
        from ama_cryptography import _module_state as ms

        saved_previous = ms._rng_state["previous"]
        try:
            ms._rng_state["previous"] = None
            issued = ms.secure_token_bytes(32)
            stored = ms._rng_state["previous"]

            assert stored is not None
            assert stored != issued, "health state must not hold the issued bytes"
            assert stored is not issued
            assert stored == hashlib.sha256(issued).digest()
        finally:
            ms._rng_state["previous"] = saved_previous

    def test_post_seeds_the_health_state_in_digest_form(self) -> None:
        """POST's seed must match what secure_token_bytes compares against.

        If POST stored the raw sample while the draw compares digests, the first
        comparison after POST could never match and the very first post-POST
        draw would escape the continuous check entirely.
        """
        from ama_cryptography import _module_state as ms
        from ama_cryptography import _self_test as st

        saved_previous = ms._rng_state["previous"]
        saved_results = list(st._SELF_TEST_RESULTS)
        try:
            ms._rng_state["previous"] = None
            passed, reason = st._run_rng_stage()
            assert passed, reason
            stored = ms._rng_state["previous"]
            assert stored is not None
            assert len(stored) == 32  # a SHA-256 digest, not a raw token
        finally:
            ms._rng_state["previous"] = saved_previous
            st._SELF_TEST_RESULTS[:] = saved_results
