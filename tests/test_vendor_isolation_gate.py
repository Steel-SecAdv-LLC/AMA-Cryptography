# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""
Tests for ``tools/check_vendor_isolation.py`` (INVARIANT-1).

The gate exists because "no third-party cryptographic implementation is linked,
imported or called" was, before it, enforced against *subprocess invocations*
only (``tools/check_corpus_originality.py``) and otherwise asserted by comments
and intent.  A control that has never been shown to fail is indistinguishable
from one that cannot, so every check here is exercised in both directions:

* the **source** check must flag a vendor import, a ``ctypes`` load naming a
  vendor library, and an import of the comparator package;
* the **library** check must flag a genuinely OpenSSL-linked object — the
  interpreter's own ``_ssl`` extension is used as the positive control, so the
  ELF/Mach-O/PE parsing is validated against a real binary rather than a
  fixture;
* the parsers must agree with the platform's own tools where those exist;
* and a check whose evidence is absent (missing library, unparseable file, a
  package directory with no sources) must be a failure, not a silent pass.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from tools import check_vendor_isolation as gate

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = REPO_ROOT / "tools" / "check_vendor_isolation.py"


def write_package(tmp_path: Path, body: str, name: str = "mod.py") -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir(exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / name).write_text(body, encoding="utf-8")
    return pkg


class TestSourceCheck:
    def test_clean_package_passes(self, tmp_path: Path) -> None:
        pkg = write_package(tmp_path, "import hashlib\nimport os\n")
        assert gate.check_source(pkg) == []

    @pytest.mark.parametrize(
        ("statement", "vendor"),
        [
            ("import nacl", "libsodium"),
            ("import nacl.signing", "libsodium"),
            ("from cryptography.hazmat.primitives import hashes", "OpenSSL"),
            ("import OpenSSL", "OpenSSL"),
            ("from Crypto.Cipher import AES", "PyCryptodome"),
            ("import wolfcrypt", "wolfSSL"),
            ("import botan3", "Botan"),
            ("import nettle", "Nettle"),
            ("import gcrypt", "libgcrypt"),
            ("import mbedtls", "mbedTLS"),
        ],
    )
    def test_vendor_import_is_flagged(self, tmp_path: Path, statement: str, vendor: str) -> None:
        pkg = write_package(tmp_path, statement + "\n")
        violations = gate.check_source(pkg)
        assert len(violations) == 1
        assert vendor in violations[0].detail

    def test_comparator_package_import_is_flagged(self, tmp_path: Path) -> None:
        pkg = write_package(tmp_path, "from benchmarks import benchmark_runner\n")
        violations = gate.check_source(pkg)
        assert len(violations) == 1
        assert "comparator package" in violations[0].detail

    @pytest.mark.parametrize(
        "call",
        [
            'ctypes.CDLL("libcrypto.so.3")',
            'ctypes.cdll.LoadLibrary("/usr/lib/libsodium.so.23")',
            'ctypes.util.find_library("libmbedcrypto")',
        ],
    )
    def test_ctypes_load_of_a_vendor_library_is_flagged(self, tmp_path: Path, call: str) -> None:
        """No import statement names these, which is the point."""
        pkg = write_package(tmp_path, f"import ctypes\nlib = {call}\n")
        violations = gate.check_source(pkg)
        assert violations, "a ctypes load naming a vendor library must be flagged"

    def test_ctypes_load_of_our_own_library_passes(self, tmp_path: Path) -> None:
        pkg = write_package(
            tmp_path, 'import ctypes\nlib = ctypes.CDLL("libama_cryptography.so.5")\n'
        )
        assert gate.check_source(pkg) == []

    def test_naming_a_vendor_in_prose_is_not_a_violation(self, tmp_path: Path) -> None:
        """Scholarship and wire-format spellings are not invocations."""
        pkg = write_package(
            tmp_path,
            '"""Accepts the SEC 1 / OpenSSL alias prime256v1."""\n'
            "# Approach follows libsodium's ed25519 clamping.\n"
            'CURVE_ALIASES = {"prime256v1": "P-256"}\n',
        )
        assert gate.check_source(pkg) == []

    def test_relative_imports_are_not_vendor_imports(self, tmp_path: Path) -> None:
        pkg = write_package(tmp_path, "from . import sibling\nfrom .sub import thing\n")
        assert gate.check_source(pkg) == []

    def test_empty_directory_is_a_failure_not_a_clean_scan(self, tmp_path: Path) -> None:
        empty = tmp_path / "nothing"
        empty.mkdir()
        violations = gate.check_source(empty)
        assert violations
        assert "refusing to report a clean scan of nothing" in violations[0].detail


class TestShippedPackageIsClean:
    """The property itself, on the tree as committed."""

    def test_package_source_is_clean(self) -> None:
        assert gate.check_source(REPO_ROOT / "ama_cryptography") == []


class TestLibraryCheck:
    def test_missing_library_is_a_failure(self, tmp_path: Path) -> None:
        violations = gate.check_library(tmp_path / "absent.so")
        assert violations
        assert "refusing to report clean" in violations[0].detail

    def test_unparseable_file_is_a_failure(self, tmp_path: Path) -> None:
        junk = tmp_path / "not-a-binary.so"
        junk.write_bytes(b"this is not an object file at all\n")
        violations = gate.check_library(junk)
        assert violations
        assert "could not parse" in violations[0].detail

    def test_openssl_linked_object_is_flagged(self) -> None:
        """Positive control: the interpreter's own _ssl extension.

        This validates the parser against a real vendor-linked binary on
        whatever platform the suite runs on, rather than against a fixture
        that could agree with a wrong parser.
        """
        ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
        candidates = [
            Path(sysconfig.get_config_var("DESTSHARED") or "") / f"_ssl{ext_suffix}",
        ]
        try:
            import _ssl

            if getattr(_ssl, "__file__", None):
                candidates.insert(0, Path(_ssl.__file__))
        except ImportError:  # pragma: no cover - _ssl is present on CI
            pass

        target = next((p for p in candidates if p.is_file()), None)
        if target is None:  # pragma: no cover - statically linked interpreter
            pytest.skip("no dynamically linked _ssl extension to use as a control")

        violations = gate.check_library(target)
        assert violations, f"{target} links OpenSSL and must be flagged"
        assert any("OpenSSL" in v.detail for v in violations)

    def test_ama_library_is_clean_when_built(self) -> None:
        built = REPO_ROOT / "build" / "lib" / "libama_cryptography.so"
        if not built.is_file():
            pytest.skip("native library not built in this tree")
        assert gate.check_library(built) == []


class TestBinaryParsers:
    """The parsers must agree with the platform's own tools."""

    def test_elf_dependencies_match_readelf(self) -> None:
        built = REPO_ROOT / "build" / "lib" / "libama_cryptography.so"
        if not built.is_file():
            pytest.skip("native library not built in this tree")
        readelf = shutil.which("readelf")
        if readelf is None:
            pytest.skip("readelf not available")

        info = gate.parse_binary(built)
        if info.fmt != "ELF":
            pytest.skip(f"library is {info.fmt}, not ELF")

        out = subprocess.run(
            [readelf, "-d", str(built)], capture_output=True, text=True, check=True
        ).stdout
        expected = {
            line.split("[", 1)[1].rstrip("]").strip()
            for line in out.splitlines()
            if "(NEEDED)" in line and "[" in line
        }
        assert set(info.dependencies) == expected

    def test_elf_undefined_symbols_match_nm(self) -> None:
        built = REPO_ROOT / "build" / "lib" / "libama_cryptography.so"
        if not built.is_file():
            pytest.skip("native library not built in this tree")
        nm = shutil.which("nm")
        if nm is None:
            pytest.skip("nm not available")

        info = gate.parse_binary(built)
        if info.fmt != "ELF":
            pytest.skip(f"library is {info.fmt}, not ELF")

        out = subprocess.run(
            [nm, "-D", "--undefined-only", str(built)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        expected = {line.split()[-1] for line in out.splitlines() if line.strip()}
        # nm strips the @GLIBC_x.y version suffix from some spellings and not
        # others, so compare on the bare symbol name.
        got = {sym.split("@", 1)[0] for sym in info.undefined_symbols}
        assert got == {sym.split("@", 1)[0] for sym in expected}

    def test_truncated_elf_raises_rather_than_reporting_clean(self, tmp_path: Path) -> None:
        truncated = tmp_path / "truncated.so"
        truncated.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 32)
        with pytest.raises((ValueError, struct.error, IndexError)):
            gate.parse_binary(truncated)

    def test_32_bit_elf_is_rejected_rather_than_misparsed(self, tmp_path: Path) -> None:
        elf32 = tmp_path / "elf32.so"
        elf32.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 128)
        with pytest.raises(ValueError, match="64-bit"):
            gate.parse_binary(elf32)


class TestRuntimeCheck:
    def test_runtime_check_is_clean_on_this_tree(self) -> None:
        violations = gate.check_runtime(REPO_ROOT)
        # A tree without a built library cannot import the package at all;
        # that is reported as a violation (fail-closed), not as clean.
        if violations and "could not be imported" in violations[0].detail:
            pytest.skip("native library not built in this tree")
        assert violations == []

    def test_a_resident_vendor_binding_is_flagged(self, tmp_path: Path) -> None:
        """Inject an OpenSSL binding into every interpreter via sitecustomize.

        This is the transitive-import case the source scan cannot see: no
        `import` statement in this repository names the module, and it is
        nonetheless resident in the process that runs AMA's code.
        """
        pytest.importorskip("cryptography")
        inject = tmp_path / "inject"
        inject.mkdir()
        (inject / "sitecustomize.py").write_text("import cryptography\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(GATE_PATH), "--runtime"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**_clean_env(), "PYTHONPATH": str(inject)},
        )
        if "could not be imported" in proc.stderr:
            pytest.skip("native library not built in this tree")
        assert proc.returncode == 1
        assert "'cryptography' is resident" in proc.stderr


def _clean_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


class TestWiredIntoCI:
    def test_ci_workflow_invokes_the_gate(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "tools/check_vendor_isolation.py" in workflow

    def test_ci_invocation_passes_a_library(self) -> None:
        """The source and runtime checks run by default; the library check
        only runs when a path is given, so the CI call must give one."""
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        idx = workflow.index("tools/check_vendor_isolation.py")
        assert "--library" in workflow[idx : idx + 400]


class TestVendorTableIsComplete:
    def test_every_owner_forbidden_vendor_is_screened(self) -> None:
        """The seven implementations named in the repository's policy."""
        screened = {v.name for v in gate.VENDORS}
        required = {
            "OpenSSL",
            "libsodium",
            "wolfSSL",
            "Botan",
            "Nettle",
            "libgcrypt",
            "mbedTLS",
        }
        assert required <= screened

    def test_every_vendor_is_identifiable_somehow(self) -> None:
        for vendor in gate.VENDORS:
            assert (
                vendor.modules or vendor.library_names or vendor.symbol_prefixes
            ), f"{vendor.name} has no identifying marker and can never be detected"

    def test_stdlib_openssl_accelerators_are_not_screened(self) -> None:
        """`hashlib`/`_hashlib`/`_ssl` are CPython's own stdlib.

        INVARIANT-1 admits `hashlib` for hashing; screening the interpreter's
        accelerator modules would make this gate fail on a stock CPython
        rather than on an AMA defect.
        """
        screened_modules = {m for v in gate.VENDORS for m in v.modules}
        assert screened_modules.isdisjoint({"hashlib", "_hashlib", "_ssl", "ssl"})
