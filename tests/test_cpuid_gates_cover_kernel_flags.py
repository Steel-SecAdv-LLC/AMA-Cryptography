# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""The CPUID gate of each per-file-flagged x86 kernel checks every ISA its flags enable.

``src/c/avx2/ama_aes_gcm_avx2.c`` is compiled ``-maes -mpclmul -mssse3
-msse4.1`` and ``src/c/ama_sha256_ni.c`` ``-msha -mssse3 -msse4.1``; the
compiler is then free to use every one of those extensions, and does (the
shipped AES-GCM kernel carries pshufb and pinsrb besides AESENC and
PCLMULQDQ).  A host whose CPUID masks one of them — a hypervisor can mask
any bit independently — must therefore be refused the kernel, or it takes
#UD on the first such instruction.

For a while ``src/c/dispatch/ama_dispatch.c`` said the opposite: that SSSE3
and SSE4.1 "are not CPUID-gated separately here" because the AES-NI bit
"already implies them", while ``ama_has_aes_ni()`` did gate them.  A
maintainer following that comment could drop the terms as redundant.  This
test is what stops that: it derives the required bits from the build's own
per-file flags in ``CMakeLists.txt`` and requires the kernel's gate to test
every one.

The property is enforced redundantly for AES-GCM — the dispatcher installs
the kernel under ``ama_has_aes_ni() && ama_has_pclmulqdq()`` and BOTH
functions test SSSE3 and SSE4.1 — so the test checks the union of the two
bodies, not either one: removing the terms from one function leaves the
property intact, removing them from both fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CMAKE = REPO_ROOT / "CMakeLists.txt"
CPUID = REPO_ROOT / "src" / "c" / "ama_cpuid.c"
DISPATCH = REPO_ROOT / "src" / "c" / "dispatch" / "ama_dispatch.c"
SHA256 = REPO_ROOT / "src" / "c" / "ama_sha256.c"

#: Compiler flag -> the cached CPUID bit in src/c/ama_cpuid.c that licenses it.
FLAG_TO_BIT = {
    "-maes": "has_aes_ni_cached",
    "-mpclmul": "has_pclmulqdq_cached",
    "-mssse3": "has_ssse3_cached",
    "-msse4.1": "has_sse41_cached",
    "-msha": "has_sha_ni_cached",
}


def _flags(pattern: str) -> list[str]:
    text = CMAKE.read_text(encoding="utf-8")
    match = re.search(pattern + r'\s+PROPERTIES\s+COMPILE_FLAGS\s+"([^"]+)"', text)
    assert match, f"CMakeLists.txt no longer sets per-file flags matching {pattern!r}"
    flags = match.group(1).split()
    unknown = [flag for flag in flags if flag not in FLAG_TO_BIT]
    assert not unknown, (
        f"per-file flags {unknown} have no CPUID bit mapped here; add the bit the "
        "kernel's gate must test to FLAG_TO_BIT and to the gate itself"
    )
    return flags


def _gate_body(function: str) -> str:
    """Body of the x86 definition of ``int <function>(void)`` (the one that reads CPUID)."""
    text = CPUID.read_text(encoding="utf-8")
    bodies = re.findall(
        r"^int " + re.escape(function) + r"\(void\) \{\n(.*?)^\}", text, re.MULTILINE | re.DOTALL
    )
    real = [body for body in bodies if "_cached" in body]
    assert len(real) == 1, f"expected one CPUID-reading definition of {function}, found {len(real)}"
    # Comments name bits too; only the code counts.
    return re.sub(r"/\*.*?\*/", "", real[0], flags=re.DOTALL)


@pytest.mark.parametrize(
    ("kernel", "flag_pattern", "gates", "install_site", "install_guard"),
    [
        (
            "AES-NI GCM",
            r"set_source_files_properties\(\$\{AMA_X86_AESNI_SOURCES\}",
            ("ama_has_aes_ni", "ama_has_pclmulqdq"),
            DISPATCH,
            r"if \(ama_has_aes_ni\(\) && ama_has_pclmulqdq\(\)\) \{\s*"
            r"dispatch_table\.aes_gcm_encrypt = ama_aes256_gcm_encrypt_avx2;",
        ),
        (
            "SHA-NI SHA-256",
            r"set_source_files_properties\(src/c/ama_sha256_ni\.c",
            ("ama_has_sha_ni",),
            SHA256,
            r"if \(ama_has_sha_ni\(\)\)",
        ),
    ],
)
def test_the_gate_tests_every_bit_the_kernel_is_compiled_for(
    kernel: str,
    flag_pattern: str,
    gates: tuple[str, ...],
    install_site: Path,
    install_guard: str,
) -> None:
    assert re.search(install_guard, install_site.read_text(encoding="utf-8")), (
        f"{kernel}: {install_site.relative_to(REPO_ROOT)} no longer installs the kernel "
        f"under {' && '.join(gates)}; update this test to the new gate"
    )
    required = {FLAG_TO_BIT[flag] for flag in _flags(flag_pattern)}
    tested = set()
    for gate in gates:
        body = _gate_body(gate)
        tested |= {bit for bit in FLAG_TO_BIT.values() if re.search(r"\b" + bit + r"\b", body)}
    missing = sorted(required - tested)
    assert not missing, (
        f"{kernel}: compiled with flags licensing {sorted(required)} but its CPUID gate "
        f"({', '.join(gates)}) never tests {missing}; a host that masks one of them "
        "would be handed the kernel and fault on its first such instruction"
    )
