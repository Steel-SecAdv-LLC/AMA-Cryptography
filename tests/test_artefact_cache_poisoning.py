#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A poisoned ``__pycache__`` for the integrity artefact must not disarm the
pre-load gates.

The two pre-load controls in this package exist for one reason: a compiled
object runs code the moment it is mapped, so detection has to happen BEFORE the
mapping or it prevents nothing.

* ``__init__._refuse_tampered_bindings_before_import()`` — refuses a binding
  extension whose bytes do not match the signed artefact, before importing it;
* ``pqc_backends._expected_native_digest()`` — the same rule for
  ``libama_cryptography`` itself.

Both obtained the signed digests with ``from ama_cryptography import
_integrity_signature``. That is an ordinary import, so what it reads is
``__pycache__/_integrity_signature.cpython-3XX.pyc`` whenever a cache exists
whose PEP 552 header matches the source's ``(mtime, size)`` — and nothing has
validated that cache at either point, because the POST stage that binds cached
bytecode to signed source (``execution-integrity``) runs after both.

Measured against the code before the fix, in a scratch copy: with one poisoned
``.pyc`` and ``_integrity_signature.py`` left byte-identical (so its Ed25519
signature still verifies), the pre-import gate did not fire and the tampered
extension's module-init function ran::

    OUTCOME: CryptoModuleError: … power-on self-tests FAILED
    BINDING MODULES THAT EXECUTED: [… 'ama_cryptography.hkdf_binding' …]
    TAMPERED ONE EXECUTED: True

POST caught it afterwards, which is exactly the ordering the gate was added to
correct. After the fix the same inputs give::

    OUTCOME: ImportError: … a signed binding extension does not match the artefact
    BINDING MODULES THAT EXECUTED: []

These tests reproduce that end to end. They are slow (a real sign, a real
subprocess import) but there is no smaller seam: the property is about which
code has executed by the time a decision is made, and only a fresh interpreter
can answer that.
"""

from __future__ import annotations

import hashlib
import importlib.util
import marshal
import os
import re
import shutil
import struct
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import native_library_path

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "ama_cryptography"

#: Every assertion in this module is about the TEXT a refusal produced — which
#: gate fired, and therefore how much code had run before it did.  Read through
#: the runner's code page, that verdict depends on the console rather than on
#: the package: the import-time diagnostics go out through ``logging``, whose
#: handler turns a UnicodeEncodeError into "--- Logging error ---" and drops
#: the record, so a refusal that DID happen would read as one that did not.
#:
#: ci.yml's Windows pytest step deliberately sets no PYTHONUTF8 (its
#: tests/test_python_examples.py lane needs a real cp1252 console), so the
#: guarantee is made here, per child, rather than assumed from the job.  Until
#: this pass these four tests skipped on every Windows job — the fixture looked
#: for `libama_cryptography*` and the DLL has no `lib` prefix — so the question
#: had never arisen.
_UTF8_CHILD_ENV = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

#: ``text=True`` alone decodes with the PARENT's locale encoding, which is the
#: same lottery from the other end.  Pinned to UTF-8, with ``errors="replace"``
#: so a stray undecodable byte degrades one character rather than raising out
#: of ``subprocess.run`` and failing the test for a reason unrelated to it.
_UTF8_PIPES: dict[str, Any] = {"text": True, "encoding": "utf-8", "errors": "replace"}

pytestmark = pytest.mark.fips


def _binding_extensions(pkg: Path) -> list[Path]:
    out: list[Path] = []
    for suffix in (".so", ".pyd", ".dylib"):
        for path in pkg.glob(f"*{suffix}"):
            if path.name.startswith(("libama_cryptography", "ama_cryptography.dll")):
                continue
            if "_binding" in path.name:
                out.append(path)
    return sorted(out)


@pytest.fixture(scope="module")
def signed_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A package copy whose artefact actually BINDS the compiled extensions.

    A source-tree artefact binds none by design, so the gate under test would
    have nothing to check; ``--bind-extensions`` is the release-pipeline mode
    that gives it something.
    """
    root = tmp_path_factory.mktemp("poison")
    shutil.copytree(PKG_DIR, root / "ama_cryptography")
    pkg = root / "ama_cryptography"
    shutil.rmtree(pkg / "__pycache__", ignore_errors=True)

    if not _binding_extensions(pkg):
        # "native" is load-bearing in this reason, not decoration: conftest's
        # AMA_CI_REQUIRE_BACKENDS escalation matches skip reasons against
        # _BACKEND_SKIP_REASONS, and neither "binding" nor "extensions" is in
        # it — so this skip, in the ONLY end-to-end coverage of the pre-import
        # binding gate and the __pycache__ poisoning attack, could not be
        # escalated in CI.  The word is also the accurate one: these are the
        # compiled native extension modules.
        pytest.skip(
            "no compiled native binding extensions in this tree; build with "
            "`python setup.py build_ext --inplace`"
        )
    if native_library_path(pkg) is None:
        pytest.skip("native library not built in this tree")

    env = dict(os.environ, AMA_BUILD_PIPELINE="1", PYTHONPATH=str(root), **_UTF8_CHILD_ENV)
    proc = subprocess.run(
        [sys.executable, "-m", "ama_cryptography._build_sign", "--bind-extensions"],
        cwd=str(root),
        env=env,
        capture_output=True,
        timeout=600,
        **_UTF8_PIPES,
    )
    if proc.returncode != 0:
        # Same reason the reason names "native": signing runs the in-tree
        # Ed25519 kernels through ctypes, so a signing failure IS a backend
        # failure and CI must be able to escalate it.
        pytest.skip(
            "could not sign the scratch tree with the native Ed25519 signing "
            f"kernels: {proc.stderr.strip()[-400:]}"
        )
    return root


def _poison_artefact_cache(pkg: Path, replacements: dict[str, str]) -> None:
    """Write a ``.pyc`` for the artefact with digests replaced, source untouched.

    The header carries the UNMODIFIED source's ``(mtime, size)``, which is what
    makes CPython accept the cache without recompiling — the whole mechanism of
    the attack.
    """
    src = pkg / "_integrity_signature.py"
    original = src.read_text(encoding="utf-8")
    stat = src.stat()

    poisoned = original
    for name, digest in replacements.items():

        def _swap(match: re.Match[str], replacement: str = digest) -> str:
            return match.group(1) + replacement + match.group(3)

        pattern = r'("' + re.escape(name) + r'":\s*")([0-9a-f]{64})(")'
        poisoned, count = re.subn(pattern, _swap, poisoned)
        if count == 0:
            # The native digest is a bare assignment, not a dict entry.
            poisoned, count = re.subn(
                r"(" + re.escape(name) + r'\s*=\s*")([0-9a-f]{64})(")',
                _swap,
                poisoned,
            )
        assert count == 1, f"could not rewrite {name} in the artefact source"

    code = compile(poisoned, str(src), "exec")
    cache = Path(importlib.util.cache_from_source(str(src)))
    cache.parent.mkdir(parents=True, exist_ok=True)
    with open(cache, "wb") as handle:
        handle.write(importlib.util.MAGIC_NUMBER)
        handle.write(struct.pack("<I", 0))  # PEP 552: timestamp-validated
        handle.write(struct.pack("<I", int(stat.st_mtime) & 0xFFFFFFFF))
        handle.write(struct.pack("<I", stat.st_size & 0xFFFFFFFF))
        marshal.dump(code, handle)

    assert src.read_text(encoding="utf-8") == original, "the source must stay byte-identical"


def _import_and_report(root: Path) -> tuple[str, list[str], str]:
    """Import the package in a fresh interpreter; report outcome, what ran, output."""
    probe = textwrap.dedent("""
        import sys
        try:
            import ama_cryptography
            outcome = "IMPORTED"
        except BaseException as exc:
            outcome = type(exc).__name__
        loaded = sorted(
            m for m in sys.modules
            if m.startswith("ama_cryptography.") and "binding" in m
        )
        print("OUTCOME=" + outcome)
        print("EXECUTED=" + ",".join(loaded))
        """)
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(root),
        env=dict(os.environ, PYTHONPATH=str(root), **_UTF8_CHILD_ENV),
        capture_output=True,
        timeout=600,
        **_UTF8_PIPES,
    )
    outcome = ""
    executed: list[str] = []
    for line in proc.stdout.splitlines():
        if line.startswith("OUTCOME="):
            outcome = line.split("=", 1)[1]
        elif line.startswith("EXECUTED="):
            payload = line.split("=", 1)[1]
            executed = [m for m in payload.split(",") if m]
    assert outcome, proc.stdout + proc.stderr
    return outcome, executed, proc.stdout + proc.stderr


class TestTheGateIsRealBeforeTheAttack:
    """Non-vacuity: the fixture's tree must import cleanly, and the gate must fire
    on a plain tampered extension.  Without both, the attack test below could
    pass for reasons unrelated to the poisoning."""

    def test_the_untampered_tree_imports(self, signed_tree: Path) -> None:
        outcome, executed, _output = _import_and_report(signed_tree)
        assert outcome == "IMPORTED", outcome
        assert executed, "no binding extension executed — the gate would have nothing to guard"

    def test_a_tampered_binding_is_refused(self, signed_tree: Path, tmp_path: Path) -> None:
        root = tmp_path / "plain"
        shutil.copytree(signed_tree, root)
        pkg = root / "ama_cryptography"
        shutil.rmtree(pkg / "__pycache__", ignore_errors=True)
        target = _binding_extensions(pkg)[0]
        data = bytearray(target.read_bytes())
        data[-1] ^= 0x01
        target.write_bytes(bytes(data))

        outcome, executed, _output = _import_and_report(root)
        assert outcome == "ImportError", outcome
        assert executed == [], f"a binding executed despite the refusal: {executed}"


class TestPoisonedArtefactCacheCannotDisarmTheGate:
    def test_a_forged_binding_digest_in_pycache_does_not_pass(
        self, signed_tree: Path, tmp_path: Path
    ) -> None:
        """The regression this module exists for.

        Tamper one signed extension, then write a ``.pyc`` for the artefact in
        which that extension's entry carries the TAMPERED bytes' digest. The
        source keeps its original digests and its valid signature. Nothing may
        execute.
        """
        root = tmp_path / "poisoned"
        shutil.copytree(signed_tree, root)
        pkg = root / "ama_cryptography"
        shutil.rmtree(pkg / "__pycache__", ignore_errors=True)

        target = _binding_extensions(pkg)[0]
        data = bytearray(target.read_bytes())
        data[-1] ^= 0x01
        target.write_bytes(bytes(data))
        forged = hashlib.sha3_256(bytes(data)).hexdigest()

        _poison_artefact_cache(pkg, {target.name: forged})

        outcome, executed, _output = _import_and_report(root)
        assert executed == [], (
            "a poisoned artefact bytecode cache let a tampered binding extension "
            f"execute: {executed}"
        )
        assert outcome == "ImportError", outcome

    def test_a_forged_native_digest_in_pycache_does_not_pass(
        self, signed_tree: Path, tmp_path: Path
    ) -> None:
        """The same attack against the pre-load check on the native library.

        ``_expected_native_digest`` read the artefact the same way, so a forged
        ``INTEGRITY_NATIVE_DIGEST_HEX`` in the cache would have let a tampered
        ``libama_cryptography`` be mapped — which runs its ELF constructors.
        """
        root = tmp_path / "poisoned_native"
        shutil.copytree(signed_tree, root)
        pkg = root / "ama_cryptography"
        shutil.rmtree(pkg / "__pycache__", ignore_errors=True)

        # `native_library_path`, not `sorted(glob("libama_cryptography*"))[0]`.
        # Two reasons, both measured on CI:
        #
        #  * on Windows the file is `ama_cryptography.dll` — no `lib` prefix —
        #    so the glob matched nothing, the fixture skipped, and the CI
        #    escalation turned all four tests in this module into errors on
        #    every windows-latest job;
        #  * on macOS the copied tree holds `libama_cryptography.5.0.0.dylib`
        #    and `libama_cryptography.dylib`, and `.5` sorts before `.d`, so
        #    `[0]` tampered with the versioned copy while the loader opens the
        #    bare name.  The pre-load check then compared an UNTAMPERED file,
        #    passed, and POST caught the poisoned cache one stage later — the
        #    test failed on all five macos-latest jobs asserting "refused
        #    before mapping", for the one reason that would also make a real
        #    attack succeed.
        #
        # `native_library_path` resolves the name `pqc_backends._get_lib_names`
        # actually opens, which is also the file `_build_sign` hashed into
        # INTEGRITY_NATIVE_DIGEST_HEX.
        target = native_library_path(pkg)
        if target is None:
            pytest.skip("no in-package native library to tamper with")
        data = bytearray(target.read_bytes())
        data[-1] ^= 0x01
        target.write_bytes(bytes(data))
        forged = hashlib.sha3_256(bytes(data)).hexdigest()

        _poison_artefact_cache(pkg, {"INTEGRITY_NATIVE_DIGEST_HEX": forged})

        outcome, _executed, output = _import_and_report(root)
        # "not IMPORTED" is NOT the assertion: POST's integrity stage fails on
        # the forged cache anyway, so a vacuous test would pass even with the
        # pre-load check disarmed.  What must hold is that the refusal is the
        # PRE-LOAD one — the object was never mapped.
        assert "refused before mapping" in output, (
            "the tampered native library was not refused before mapping; the "
            "poisoned cache disarmed the pre-load digest check\n" + output[-2000:]
        )
        assert outcome != "IMPORTED", output[-2000:]


class TestTheParserFailsWithTheOneExceptionCallersHandle:
    """Every unusable artefact must arrive as ``ArtefactSourceError``.

    ``load_artefact_fields`` is the trust bootstrap: the pre-load gates call
    it and are written to treat ``ArtefactSourceError`` as "no usable artefact,
    refuse".  A different exception type escaping it is not a cosmetic
    difference — it is an unhandled exception on the path that decides whether
    a native object may be mapped.

    ``UnicodeDecodeError`` derives from ``ValueError``, not ``OSError``, so a
    non-UTF-8 artefact went straight past the ``except OSError`` handler and
    out of the function raw.  Measured before the fix::

        LEAKED UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff …
    """

    @staticmethod
    def _staged(tmp_path: Path, payload: bytes) -> Path:
        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_integrity_signature.py").write_bytes(payload)
        return pkg

    def test_a_non_utf8_artefact_raises_artefact_source_error(self, tmp_path: Path) -> None:
        from ama_cryptography._artefact_source import ArtefactSourceError, load_artefact_fields

        pkg = self._staged(tmp_path, b"INTEGRITY_DIGEST_HEX = '\xff\xfe'\n")
        with pytest.raises(ArtefactSourceError, match="is not UTF-8 text"):
            load_artefact_fields(pkg)

    def test_an_unparseable_artefact_raises_artefact_source_error(self, tmp_path: Path) -> None:
        from ama_cryptography._artefact_source import ArtefactSourceError, load_artefact_fields

        pkg = self._staged(tmp_path, b"INTEGRITY_DIGEST_HEX = (\n")
        with pytest.raises(ArtefactSourceError, match="not parseable Python"):
            load_artefact_fields(pkg)

    def test_an_empty_artefact_is_an_error_not_an_unsigned_tree(self, tmp_path: Path) -> None:
        """A truncated artefact is a signed tree with its signatures removed.

        It parses cleanly to zero literals, so it used to yield an
        ``ArtefactFields`` that answered ``None`` to every digest lookup:
        ``__init__._refuse_tampered_bindings_before_import`` took its
        ``not signed -> return`` branch and
        ``pqc_backends._expected_native_digest`` returned ``None``, and both
        pre-load gates passed without comparing anything — before any shared
        object was mapped, which is the moment they exist to act on.

        Not hypothetical, and not only reachable by an attacker:
        ``_write_signature_module`` used ``Path.write_text``, which truncates in
        place, so every re-sign passed through this exact state.  That write is
        atomic now, and this is the rule that makes the state refuse rather
        than pass.
        """
        from ama_cryptography._artefact_source import ArtefactSourceError, load_artefact_fields

        for label, payload in (
            ("empty", b""),
            ("docstring only", b'"""nothing here"""\n'),
            ("comment only", b"# nothing here\n"),
        ):
            pkg = self._staged(tmp_path / label.replace(" ", "_"), payload)
            with pytest.raises(ArtefactSourceError, match="no literal assignments"):
                load_artefact_fields(pkg)

    def test_a_missing_artefact_is_none_not_an_error(self, tmp_path: Path) -> None:
        """The one absence that is a normal state: an unsigned tree."""
        from ama_cryptography._artefact_source import load_artefact_fields

        pkg = tmp_path / "ama_cryptography"
        pkg.mkdir(parents=True, exist_ok=True)
        assert load_artefact_fields(pkg) is None

    def test_every_failure_mode_is_one_exception_type(self, tmp_path: Path) -> None:
        """Swept, so a new decode path cannot reintroduce a second type.

        Each payload is a different way for the artefact to be unusable; none
        may produce anything other than ArtefactSourceError.
        """
        from ama_cryptography._artefact_source import ArtefactSourceError, load_artefact_fields

        payloads = (
            b"\xff\xfe\x00\x00",
            b"X = '\xc3'\n",
            b"X = (\n",
            b"import os\nX = os.environ\n",
            b"",
        )
        for i, payload in enumerate(payloads):
            pkg = self._staged(tmp_path / f"case{i}", payload)
            try:
                returned = load_artefact_fields(pkg)
            except ArtefactSourceError:
                continue  # the one exception every caller of the gate handles
            except Exception as exc:
                raise AssertionError(
                    f"payload {payload!r} raised {type(exc).__name__}, not "
                    f"ArtefactSourceError; a caller of the trust bootstrap "
                    f"would see an unhandled exception"
                ) from exc
            # Reaching here is the case this loop could not see.  The accepting
            # branch was a bare `pass`, so a payload that did not raise AT ALL
            # fell through it and the iteration asserted nothing — which is how
            # `b""` sat in this list, returning an empty ArtefactFields, while
            # the docstring above claimed every payload produced
            # ArtefactSourceError.  An empty artefact answers None to every
            # digest lookup, so both pre-load gates took their
            # nothing-to-check branch.
            raise AssertionError(
                f"payload {payload!r} did not raise at all; "
                f"load_artefact_fields returned {returned!r}. None is the "
                f"documented answer for a MISSING artefact only — a present "
                f"but unusable one must raise, or a caller that reads None as "
                f"'nothing to check against' silently loses the check."
            )
