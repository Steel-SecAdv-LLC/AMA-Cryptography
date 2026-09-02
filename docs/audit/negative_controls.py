#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Phase D negative controls for the PR #394 readiness-falsification mandate.

For every gate below: inject a minimal violation into the real tree, run the
gate and record its (expected non-zero) exit code, revert, run the gate on
the clean tree and record exit 0.  Every run goes through
``docs/audit/run_logged.sh`` so it lands in ``docs/audit/ledger.tsv`` with a
retained log, and one row per control is appended to
``docs/audit/PR394_NEGATIVE_CONTROLS.tsv``.

A gate that cannot be made to fail is reported as CANNOT-FAIL, which the
mandate treats as a release-blocking finding.

Run from the repository root with the audit venv first on PATH::

    python docs/audit/negative_controls.py [--only NC-05,NC-07]
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "docs" / "audit" / "run_logged.sh"
TSV = REPO / "docs" / "audit" / "PR394_NEGATIVE_CONTROLS.tsv"
# Scratch root for clones and builds a control needs: the caller's choice via
# NC_SCRATCH, else a fresh temporary directory (never a fixed path).
SCRATCH = Path(os.environ.get("NC_SCRATCH") or tempfile.mkdtemp(prefix="nc-scratch-"))


@dataclass
class Control:
    id: str
    gate: str
    violation: str
    setup: str  # bash, run from the repo root
    teardown: str  # bash, run from the repo root (always executed)
    violated_cmd: str  # bash, expected non-zero
    clean_cmd: str  # bash, expected zero
    permanent_test: str
    cleanup: str = (
        "true"  # bash, run after the clean run (scratch artefacts the clean run still needs)
    )


def sh(script: str, check: bool = False) -> int:
    proc = subprocess.run(["bash", "-o", "pipefail", "-c", script], cwd=REPO)
    if check and proc.returncode != 0:
        raise RuntimeError(f"setup failed rc={proc.returncode}: {script[:120]}")
    return proc.returncode


def logged(row_id: str, purpose: str, log: str, cmd: str) -> int:
    return subprocess.run(
        [str(RUNNER), row_id, purpose, log, "--", "bash", "-o", "pipefail", "-c", cmd],
        cwd=REPO,
    ).returncode


CONTROLS: list[Control] = [
    Control(
        "NC-02",
        "tools/check_algorithm_registry.py (INVARIANT-1 addendum)",
        "the ML-KEM-1024 row is deleted from CSRC_STANDARDS.md while the primitive still ships",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('CSRC_STANDARDS.md'); L=p.read_text().splitlines(True)\nout=[l for l in L if not ('ML-KEM-1024' in l and l.lstrip().startswith('|'))]\nassert len(out)<len(L); p.write_text(''.join(out))\nEOF",
        "git checkout -- CSRC_STANDARDS.md",
        "python tools/check_algorithm_registry.py",
        "python tools/check_algorithm_registry.py",
        "tests/test_algorithm_registry_gate.py",
    ),
    Control(
        "NC-03",
        "tools/check_apt_retry.py",
        "one workflow step calls apt-get directly instead of .github/scripts/apt-install.sh",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('.github/workflows/ci.yml'); t=p.read_text()\nold='.github/scripts/apt-install.sh build-essential cmake'\nassert old in t; p.write_text(t.replace(old,'sudo apt-get install -y build-essential cmake',1))\nEOF",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_apt_retry.py",
        "python tools/check_apt_retry.py",
        "tests/test_apt_retry_gate.py",
    ),
    Control(
        "NC-04",
        "tools/check_bandit_severity.py",
        "a Bandit JSON report carrying one High-severity, High-confidence finding",
        "mkdir -p $NC_SCRATCH && python3 - <<'EOF'\nimport json,os\nS=os.environ['NC_SCRATCH']\nbase={'SEVERITY.UNDEFINED':0,'SEVERITY.LOW':0,'SEVERITY.MEDIUM':0,'SEVERITY.HIGH':0,'CONFIDENCE.UNDEFINED':0,'CONFIDENCE.LOW':0,'CONFIDENCE.MEDIUM':0,'CONFIDENCE.HIGH':0,'loc':10,'nosec':0,'skipped_tests':0}\nbad=dict(base); bad['SEVERITY.HIGH']=1; bad['CONFIDENCE.HIGH']=1\njson.dump({'results':[{'issue_severity':'HIGH','issue_confidence':'HIGH','test_id':'B602','filename':'x.py','line_number':1,'issue_text':'nc probe'}],'metrics':{'_totals':bad}},open(f'{S}/bandit-bad.json','w'))\njson.dump({'results':[],'metrics':{'_totals':base}},open(f'{S}/bandit-clean.json','w'))\nEOF",
        "true",
        "python tools/check_bandit_severity.py $NC_SCRATCH/bandit-bad.json",
        "python tools/check_bandit_severity.py $NC_SCRATCH/bandit-clean.json",
        "tests/test_bandit_severity_gate.py",
    ),
    Control(
        "NC-05",
        "tools/check_c_secret_zeroization.py (INVARIANT-6)",
        "a C source under src/c/ zeroes a secret-named buffer with bare memset()",
        "printf '/* nc probe */\\n#include <string.h>\\nvoid nc(unsigned char *secret_key){ memset(secret_key, 0, 32); }\\n' > src/c/nc_probe.c && git add -N src/c/nc_probe.c",
        "git rm -q --cached src/c/nc_probe.c 2>/dev/null; rm -f src/c/nc_probe.c",
        "python tools/check_c_secret_zeroization.py",
        "python tools/check_c_secret_zeroization.py",
        "tests/test_c_secret_zeroization_gate.py",
    ),
    Control(
        "NC-06",
        "tools/check_choco_retry.py",
        "one workflow step calls choco install directly instead of .github/scripts/choco-install.ps1",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('.github/workflows/ci.yml'); L=p.read_text().splitlines(True)\ni=next(k for k,l in enumerate(L) if 'choco-install.ps1' in l and '&' in l)\nL[i]='        choco install softhsm.install -y\\n'; p.write_text(''.join(L))\nEOF",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_choco_retry.py",
        "python tools/check_choco_retry.py",
        "tests/test_choco_retry_gate.py",
    ),
    Control(
        "NC-08",
        "tools/check_corpus_originality.py (INVARIANT-36)",
        "a test module spawns the openssl binary to produce reference material",
        'printf \'# Copyright (C) 2025-2026 Steel Security Advisors LLC\\n# SPDX-License-Identifier: Apache-2.0\\nimport subprocess\\n\\n\\ndef ref():\\n    return subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"], capture_output=True).stdout\\n\' > tests/nc_probe_originality.py && git add -N tests/nc_probe_originality.py',
        "git rm -q --cached tests/nc_probe_originality.py 2>/dev/null; rm -f tests/nc_probe_originality.py",
        "python tools/check_corpus_originality.py",
        "python tools/check_corpus_originality.py",
        "tests/test_corpus_originality.py (if present) / this control",
    ),
    Control(
        "NC-09",
        "tools/check_ctypes_abi.py (INVARIANT-42)",
        "one ctypes argtypes declaration drops a parameter the C header declares",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('ama_cryptography/pqc_backends.py'); t=p.read_text()\nold='lib.ama_dilithium_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]'\nassert old in t; p.write_text(t.replace(old,'lib.ama_dilithium_keypair.argtypes = [ctypes.c_char_p]',1))\nEOF",
        "git checkout -- ama_cryptography/pqc_backends.py",
        "python tools/check_ctypes_abi.py",
        "python tools/check_ctypes_abi.py",
        "tests/test_ctypes_abi_gate.py",
    ),
    Control(
        "NC-10",
        "tools/check_docker_pins.py",
        "the first FROM in docker/Dockerfile loses its @sha256 digest pin",
        "python3 - <<'EOF'\nimport re\nfrom pathlib import Path\np=Path('docker/Dockerfile'); t=p.read_text()\nn=re.subn(r'(^FROM\\s+\\S+?)@sha256:[0-9a-f]{64}', r'\\1', t, count=1, flags=re.M)\nassert n[1]==1; p.write_text(n[0])\nEOF",
        "git checkout -- docker/Dockerfile",
        "python tools/check_docker_pins.py",
        "python tools/check_docker_pins.py",
        "tests/test_docker_pins_gate.py",
    ),
    Control(
        "NC-11",
        "tools/check_documented_counts.py",
        "README.md states a test-function count one below the measured value",
        "python3 - <<'EOF'\nimport re\nfrom pathlib import Path\np=Path('README.md'); t=p.read_text()\nm=re.search(r'([0-9]{1,3}(?:,[0-9]{3})*) test functions', t); assert m, 'no test-function count in README'\nn=int(m.group(1).replace(',',''))-1\np.write_text(t[:m.start(1)]+f'{n:,}'+t[m.end(1):])\nEOF",
        "git checkout -- README.md",
        "python tools/check_documented_counts.py",
        "python tools/check_documented_counts.py",
        "tests/test_documented_counts_gate.py",
    ),
    Control(
        "NC-12",
        "tools/check_documented_extras.py (INVARIANT-32)",
        "README.md documents an install extra that pyproject.toml does not define",
        "printf '\\n```bash\\npip install ama-cryptography[ncprobe]\\n```\\n' >> README.md",
        "git checkout -- README.md",
        "python tools/check_documented_extras.py",
        "python tools/check_documented_extras.py",
        "tests/test_documented_extras.py",
    ),
    Control(
        "NC-13",
        "tools/check_fdopen_safety.py",
        "a tool wraps a raw descriptor with os.fdopen() without closing it on failure",
        "printf '# Copyright (C) 2025-2026 Steel Security Advisors LLC\\n# SPDX-License-Identifier: Apache-2.0\\nimport os\\n\\n\\ndef nc(path):\\n    fd = os.open(path, os.O_RDONLY)\\n    f = os.fdopen(fd)\\n    return f.read()\\n' > tools/nc_probe_fdopen.py && git add -N tools/nc_probe_fdopen.py",
        "git rm -q --cached tools/nc_probe_fdopen.py 2>/dev/null; rm -f tools/nc_probe_fdopen.py",
        "python tools/check_fdopen_safety.py",
        "python tools/check_fdopen_safety.py",
        "tests/test_fdopen_safety.py (if present) / this control",
    ),
    Control(
        "NC-14",
        "tools/check_fuzz_target_registration.py (INVARIANT-33)",
        "a new fuzz/fuzz_*.c harness exists that CMake, fuzzing.yml and oss-fuzz do not register",
        "printf '/* Copyright (C) 2025-2026 Steel Security Advisors LLC */\\n/* SPDX-License-Identifier: Apache-2.0 */\\n#include <stddef.h>\\n#include <stdint.h>\\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\\n' > fuzz/fuzz_ncprobe.c && git add -N fuzz/fuzz_ncprobe.c",
        "git rm -q --cached fuzz/fuzz_ncprobe.c 2>/dev/null; rm -f fuzz/fuzz_ncprobe.c",
        "python tools/check_fuzz_target_registration.py",
        "python tools/check_fuzz_target_registration.py",
        "tests/test_fuzz_target_registration.py (if present) / this control",
    ),
    Control(
        "NC-15",
        "tools/check_gate_coverage.py (INVARIANT-31)",
        "ci.yml gains a pull-request job that the CI Gate does not need",
        "printf '\\n  nc-orphan-job:\\n    name: NC orphan job\\n    runs-on: ubuntu-latest\\n    steps:\\n      - run: echo orphan\\n' >> .github/workflows/ci.yml",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_gate_coverage.py",
        "python tools/check_gate_coverage.py",
        "tests/test_gate_coverage.py",
    ),
    Control(
        "NC-16",
        "tools/check_headers.py --check",
        "a tracked Python file without the license header",
        "printf 'x = 1\\n' > tools/nc_probe_noheader.py && git add -N tools/nc_probe_noheader.py",
        "git rm -q --cached tools/nc_probe_noheader.py 2>/dev/null; rm -f tools/nc_probe_noheader.py",
        "python tools/check_headers.py --check",
        "python tools/check_headers.py --check",
        "tests/test_headers.py",
    ),
    Control(
        "NC-17",
        "tools/check_keygen_pct.py (INVARIANT-41)",
        "one keygen entry point releases its keypair without the pairwise consistency test",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('ama_cryptography/pqc_backends.py'); L=p.read_text().splitlines(True)\ni=next(k for k,l in enumerate(L) if l.strip()=='pairwise_test_signature(')\nL[i]=L[i].replace('pairwise_test_signature(','(lambda *a, **k: None)(')\np.write_text(''.join(L))\nEOF",
        "git checkout -- ama_cryptography/pqc_backends.py",
        "python tools/check_keygen_pct.py",
        "python tools/check_keygen_pct.py",
        "tests/test_keygen_pct_gate.py",
    ),
    Control(
        "NC-18",
        "tools/check_line_endings.py",
        "a tracked text file is rewritten with CRLF line endings in the working tree",
        "sed -i 's/$/\\r/' CONTRIBUTING.md",
        "git checkout -- CONTRIBUTING.md",
        "python tools/check_line_endings.py",
        "python tools/check_line_endings.py",
        "tests/test_line_endings_gate.py",
    ),
    Control(
        "NC-19",
        "tools/check_log_message_encodability.py (INVARIANT-43)",
        "a package log call carries a literal outside cp1252",
        "printf '\\nlogger.warning(\"nc probe \\xe2\\x86\\x92 arrow\")\\n' >> ama_cryptography/monitoring.py",
        "git checkout -- ama_cryptography/monitoring.py",
        "python tools/check_log_message_encodability.py",
        "python tools/check_log_message_encodability.py",
        "tests/test_log_message_encodability_gate.py",
    ),
    Control(
        "NC-20",
        "tools/check_reference_integrity.py",
        "a shipped document cites a source line number",
        "python3 -c \"open('ARCHITECTURE.md','a').write('\\\\nThe nonce is drawn at li' + 'ne 42 of secure_channel.py.\\\\n')\"",
        "git checkout -- ARCHITECTURE.md",
        "python tools/check_reference_integrity.py",
        "python tools/check_reference_integrity.py",
        "tests/test_reference_integrity_gate.py",
    ),
    Control(
        "NC-21",
        "tools/check_release_state.py (release.yml preflight)",
        "the tree as it stands: 5.0.0 is about to be tagged while CHANGELOG.md, README.md, SECURITY.md and docs/index.rst still call it unreleased",
        "rm -rf $NC_SCRATCH/relrepo && git clone -q --shared . $NC_SCRATCH/relrepo && cd $NC_SCRATCH/relrepo && python3 - <<'EOF'\nimport re\nfrom pathlib import Path\nedits={'CHANGELOG.md':[('## [5.0.0] - Unreleased','## [5.0.0] - 2026-09-02')],'README.md':[('is not tagged yet','is tagged'),('Not published yet','Published'),('not yet published','published')],'SECURITY.md':[('is prepared but **not yet tagged','is **tagged')],'docs/index.rst':[('**is not tagged yet','**is tagged')]}\nfor f,subs in edits.items():\n    p=Path(f); s=p.read_text()\n    for a,b in subs:\n        assert a in s, (f,a)\n        s=s.replace(a,b)\n    p.write_text(s)\nEOF",
        "true",
        "python tools/check_release_state.py --version 5.0.0",
        "cd $NC_SCRATCH/relrepo && python tools/check_release_state.py --version 5.0.0",
        "tests/test_release_state_gate.py (if present) / this control",
        cleanup="rm -rf $NC_SCRATCH/relrepo",
    ),
    Control(
        "NC-22",
        "tools/check_secrets.py (INVARIANT-23)",
        "a tracked source file assigns an AWS access key id (identifier and value are assembled at run time so this driver's own source does not carry them)",
        "python3 - <<'EOF'\nident=''.join(chr(c) for c in [65,87,83,95,65,67,67,69,83,83,95,75,69,89,95,73,68])\nvalue=''.join(chr(c) for c in [65,75,73,65,81,90,55,77,51,80,57,75,50,76,53,78,56,82,52,84])\nopen('tools/nc_probe_secret.py','w').write('# Copyright (C) 2025-2026 Steel Security Advisors LLC\\n# SPDX-License-Identifier: Apache-2.0\\n' + ident + ' = ' + repr(value) + '\\n')\nEOF\ngit add -N tools/nc_probe_secret.py",
        "git rm -q --cached tools/nc_probe_secret.py 2>/dev/null; rm -f tools/nc_probe_secret.py",
        "python tools/check_secrets.py",
        "python tools/check_secrets.py",
        "tests/test_secret_scanner.py",
    ),
    Control(
        "NC-23",
        "tools/check_semgrep_severity.py",
        "a Semgrep JSON report carrying one ERROR-severity finding",
        "mkdir -p $NC_SCRATCH && python3 - <<'EOF'\nimport json,os\nS=os.environ['NC_SCRATCH']\nres={'check_id':'ama.nc-probe','path':'ama_cryptography/x.py','start':{'line':1,'col':1},'end':{'line':1,'col':2},'extra':{'severity':'ERROR','message':'nc probe','lines':'x'}}\njson.dump({'results':[res],'errors':[],'paths':{'scanned':['ama_cryptography/x.py']}},open(f'{S}/semgrep-bad.json','w'))\njson.dump({'results':[],'errors':[],'paths':{'scanned':['ama_cryptography/x.py']}},open(f'{S}/semgrep-clean.json','w'))\nEOF",
        "true",
        "python tools/check_semgrep_severity.py $NC_SCRATCH/semgrep-bad.json",
        "python tools/check_semgrep_severity.py $NC_SCRATCH/semgrep-clean.json",
        "tests/test_semgrep_severity_gate.py",
    ),
    Control(
        "NC-24",
        "tools/check_stdlib_hash_boundary.py (INVARIANT-1)",
        "a package module outside the five-file trust bootstrap imports hashlib",
        "printf '\\nimport hashlib  # nc probe\\n' >> ama_cryptography/monitoring.py",
        "git checkout -- ama_cryptography/monitoring.py",
        "python tools/check_stdlib_hash_boundary.py",
        "python tools/check_stdlib_hash_boundary.py",
        "tests/test_stdlib_hash_boundary_gate.py",
    ),
    Control(
        "NC-25",
        "tools/check_suppression_hygiene.py (INVARIANT-13)",
        "a bare '# nosec' with no rule id and no justification",
        "printf '# Copyright (C) 2025-2026 Steel Security Advisors LLC\\n# SPDX-License-Identifier: Apache-2.0\\nimport subprocess\\n\\nsubprocess.call(\"ls\", shell=True)  # nosec\\n' > tools/nc_probe_nosec.py && git add -N tools/nc_probe_nosec.py",
        "git rm -q --cached tools/nc_probe_nosec.py 2>/dev/null; rm -f tools/nc_probe_nosec.py",
        "python tools/check_suppression_hygiene.py",
        "python tools/check_suppression_hygiene.py",
        "tests/test_suppression_hygiene_gate.py",
    ),
    Control(
        "NC-27",
        "tools/check_vector_provenance.py",
        "one pinned published test-vector file gains a trailing byte",
        "python3 - <<'EOF'\nimport json\nfrom pathlib import Path\nm=json.load(open('tests/kat/PROVENANCE.json'))\ndef first(o):\n    if isinstance(o,dict):\n        for k,v in o.items():\n            if isinstance(k,str) and k.startswith('tests/kat/') and Path(k).is_file(): return k\n            r=first(v)\n            if r: return r\n    elif isinstance(o,list):\n        for v in o:\n            r=first(v)\n            if r: return r\n    return None\nf=first(m) or next(str(p) for p in Path('tests/kat').rglob('*.rsp'))\nPath('.nc_vector_path').write_text(f)\nwith open(f,'ab') as h: h.write(b'\\n')\nprint('tampered', f)\nEOF",
        'f=$(cat .nc_vector_path 2>/dev/null); [ -n "$f" ] && git checkout -- "$f"; rm -f .nc_vector_path',
        "python tools/check_vector_provenance.py",
        "python tools/check_vector_provenance.py",
        "tests/test_vector_provenance_gate.py",
    ),
    Control(
        "NC-28",
        "tools/check_version_consistency.py",
        "the package __version__ disagrees with every other declaration site",
        'sed -i \'s/^__version__ = "5.0.0"/__version__ = "5.0.1"/\' ama_cryptography/__init__.py',
        "git checkout -- ama_cryptography/__init__.py",
        "python tools/check_version_consistency.py",
        "python tools/check_version_consistency.py",
        "tests/test_version_consistency.py (if present) / this control",
    ),
    Control(
        "NC-29",
        "tools/check_workflow_commands.py (INVARIANT-25): runner labels",
        "one job's runs-on names a runner label GitHub does not offer",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('.github/workflows/ci.yml'); t=p.read_text()\nold='runs-on: ubuntu-latest'\nassert old in t; p.write_text(t.replace(old,'runs-on: ubuntu-lastest',1))\nEOF",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_workflow_commands.py",
        "python tools/check_workflow_commands.py",
        "tests/test_workflow_command_checks.py",
    ),
    Control(
        "NC-29b",
        "tools/check_workflow_commands.py: check_expression_syntax()",
        "one job condition uses '=' where the expression grammar needs '=='",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('.github/workflows/ci.yml'); L=p.read_text().splitlines(True)\ni=next(k for k,l in enumerate(L) if l.strip().startswith('if: ') and '==' in l)\nL[i]=L[i].replace('==','=',1); p.write_text(''.join(L))\nEOF",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_workflow_commands.py",
        "python tools/check_workflow_commands.py",
        "tests/test_workflow_command_checks.py",
    ),
    Control(
        "NC-29c",
        "tools/check_workflow_commands.py: check_expression_syntax()",
        "one bare (undelimited) job `if:` condition computes with arithmetic",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('.github/workflows/ci.yml'); L=p.read_text().splitlines(True)\ni=next(k for k,l in enumerate(L) if l.strip().startswith('if: ') and '==' in l and '${{' not in l)\nL[i]=L[i].rstrip('\\n')+' && matrix.n * 2\\n'; p.write_text(''.join(L))\nEOF",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_workflow_commands.py",
        "python tools/check_workflow_commands.py",
        "tests/test_workflow_command_checks.py",
    ),
    Control(
        "NC-30",
        "tools/check_error_state_gating.py (INVARIANT-39 / FIPS 140-3 4.9.2)",
        "one native-reaching entry point loses its check_crypto_permitted() guard",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('ama_cryptography/pqc_backends.py'); L=p.read_text().splitlines(True)\ni=next(k for k,l in enumerate(L) if l.strip().startswith('check_crypto_permitted()'))\nL[i]=L[i].replace('check_crypto_permitted()','pass',1); p.write_text(''.join(L))\nEOF",
        "git checkout -- ama_cryptography/pqc_backends.py",
        "python tools/check_error_state_gating.py",
        "python tools/check_error_state_gating.py",
        "tests/test_error_state_gating.py (if present) / this control",
    ),
    Control(
        "NC-33",
        "tools/check_export_allowlist.py (audit B2)",
        "the library relinked without its version script, exporting internal symbols and a non-ama_ global",
        "mkdir -p $NC_SCRATCH && ( [ -f $NC_SCRATCH/build-nc-nolto/lib/libama_cryptography.so ] || (cmake -S . -B $NC_SCRATCH/build-nc-nolto -DCMAKE_BUILD_TYPE=Release -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_LTO=OFF >/dev/null && cmake --build $NC_SCRATCH/build-nc-nolto -j4 >/dev/null) ) && printf 'int nc_leaked_symbol(void){return 1;}\\n' > $NC_SCRATCH/nc_export.c && gcc -shared -fPIC -o $NC_SCRATCH/nc-export.so $NC_SCRATCH/nc_export.c $(find $NC_SCRATCH/build-nc-nolto/CMakeFiles/ama_cryptography.dir -name '*.o' | sort) -lpthread",
        "true",
        "python tools/check_export_allowlist.py $NC_SCRATCH/nc-export.so",
        "python tools/check_export_allowlist.py build-release/lib/libama_cryptography.so",
        "tests/test_export_allowlist.py (if present) / this control",
    ),
    Control(
        "NC-34",
        "tools/check_vendor_isolation.py --library (INVARIANT-1)",
        "the library relinked against OpenSSL with a translation unit that calls EVP_MD_CTX_new",
        "mkdir -p $NC_SCRATCH && ( [ -f $NC_SCRATCH/build-nc-nolto/lib/libama_cryptography.so ] || (cmake -S . -B $NC_SCRATCH/build-nc-nolto -DCMAKE_BUILD_TYPE=Release -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_LTO=OFF >/dev/null && cmake --build $NC_SCRATCH/build-nc-nolto -j4 >/dev/null) ) && printf '#include <openssl/evp.h>\\nint nc_uses_openssl(void){ EVP_MD_CTX *c = EVP_MD_CTX_new(); EVP_MD_CTX_free(c); return 0; }\\n' > $NC_SCRATCH/nc_vendor.c && gcc -shared -fPIC -o $NC_SCRATCH/nc-vendor.so $NC_SCRATCH/nc_vendor.c $(find $NC_SCRATCH/build-nc-nolto/CMakeFiles/ama_cryptography.dir -name '*.o' | sort) -Wl,--version-script=cmake/ama_exports.map -lcrypto -lpthread",
        "true",
        "python tools/check_vendor_isolation.py --library $NC_SCRATCH/nc-vendor.so",
        "python tools/check_vendor_isolation.py --library build-release/lib/libama_cryptography.so",
        "tests/test_vendor_isolation_gate.py",
    ),
    Control(
        "NC-35",
        "tools/check_release_tag.py (INVARIANT-10): lightweight tag",
        "a lightweight (un-annotated, unsigned) release tag in a scratch clone",
        "rm -rf $NC_SCRATCH/tagrepo && git clone -q --shared . $NC_SCRATCH/tagrepo && git -C $NC_SCRATCH/tagrepo tag v9.9.9",
        "rm -rf $NC_SCRATCH/tagrepo",
        "cd $NC_SCRATCH/tagrepo && python tools/check_release_tag.py v9.9.9",
        "python tools/check_release_tag.py v4.0.0",
        "tests/test_release_tag_gate.py",
    ),
    Control(
        "NC-35b",
        "tools/check_release_tag.py (INVARIANT-10): annotated but unsigned tag",
        "an annotated, unsigned release tag in a scratch clone",
        "rm -rf $NC_SCRATCH/tagrepo2 && git clone -q --shared . $NC_SCRATCH/tagrepo2 && git -C $NC_SCRATCH/tagrepo2 -c user.name=nc -c user.email=nc@example.invalid tag -a -m 'nc unsigned' v9.9.8",
        "rm -rf $NC_SCRATCH/tagrepo2",
        "cd $NC_SCRATCH/tagrepo2 && python tools/check_release_tag.py v9.9.8",
        "python tools/check_release_tag.py v4.0.0",
        "tests/test_release_tag_gate.py",
    ),
    Control(
        "NC-36",
        "benchmarks/check_baseline_justification.py (baseline-guard.yml)",
        "a commit that lowers a benchmark floor in benchmarks/baseline.json with no justification in the PR body",
        "rm -rf $NC_SCRATCH/baserepo && git clone -q --shared . $NC_SCRATCH/baserepo && cd $NC_SCRATCH/baserepo && python3 - <<'EOF'\nimport json,re\nfrom pathlib import Path\np=Path('benchmarks/baseline.json'); t=p.read_text()\nm=re.search(r'\"baseline_value\":\\s*([0-9.]+)', t); assert m, 'no baseline_value field found'\nv=float(m.group(1)); t=t[:m.start(1)]+f'{v*0.5:.6f}'+t[m.end(1):]; p.write_text(t)\nEOF\ngit -C $NC_SCRATCH/baserepo -c user.name=nc -c user.email=nc@example.invalid commit -q -am 'nc: lower a floor' && printf 'no justification here\\n' > $NC_SCRATCH/pr-body.txt",
        "rm -rf $NC_SCRATCH/baserepo",
        "cd $NC_SCRATCH/baserepo && python benchmarks/check_baseline_justification.py --base-ref HEAD~1 --head-ref HEAD --pr-body-file $NC_SCRATCH/pr-body.txt",
        "python benchmarks/check_baseline_justification.py --base-ref HEAD --head-ref HEAD --pr-body-file /dev/null",
        "tests/test_benchmark_baseline_infra.py",
    ),
    Control(
        "NC-31",
        "tools/check_avx_scoping.py (audit M3)",
        "the library rebuilt with a library-wide -mavx2 (the original SIGILL defect)",
        "cmake -S . -B $NC_SCRATCH/build-nc-avx2 -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS=-mavx2 -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_LTO=OFF >/dev/null && cmake --build $NC_SCRATCH/build-nc-avx2 -j4 >/dev/null",
        "true",
        "python tools/check_avx_scoping.py --lib $NC_SCRATCH/build-nc-avx2/lib/libama_cryptography.so",
        "python tools/check_avx_scoping.py --lib build-release/lib/libama_cryptography.so",
        "tests/test_avx_scoping_gate.py",
    ),
    Control(
        "NC-32",
        "tools/check_secret_division.py (KyberSlash)",
        "ama_kyber_decapsulate rebuilt with a division whose operands derive from the secret key and ciphertext",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('src/c/ama_kyber.c'); L=p.read_text().splitlines(True)\nstart=[k for k,l in enumerate(L) if l.startswith('AMA_API ama_error_t ama_kyber_decapsulate(')][-1]\nj=next(k for k in range(start,start+8) if L[k].rstrip().endswith('{'))\nL.insert(j+1,'    { volatile uint32_t nc_div = (uint32_t)ct[0] / ((uint32_t)sk[0] | 1u); (void)nc_div; } /* nc probe */\\n')\np.write_text(''.join(L))\nEOF\ncmake -S . -B $NC_SCRATCH/build-nc-div -DCMAKE_BUILD_TYPE=Release -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_LTO=OFF >/dev/null && cmake --build $NC_SCRATCH/build-nc-div -j4 >/dev/null",
        "git checkout -- src/c/ama_kyber.c",
        "python tools/check_secret_division.py --lib $NC_SCRATCH/build-nc-div/lib/libama_cryptography.so",
        "python tools/check_secret_division.py --lib build-release/lib/libama_cryptography.so",
        "tests/test_secret_division_gate.py",
    ),
    Control(
        "NC-07",
        "tools/check_compiler_warnings.py (frozen allowlist)",
        "a strict-lane build log carrying one warning outside the allowlist",
        "mkdir -p $NC_SCRATCH && (cmake -S . -B $NC_SCRATCH/build-strict -DCMAKE_BUILD_TYPE=None -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS='-Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wconversion -Wno-sign-conversion -Werror=missing-prototypes -Werror=shadow -Werror=unused-function' -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_LTO=OFF >/dev/null && LC_ALL=C cmake --build $NC_SCRATCH/build-strict -j4 2>&1 | tee $NC_SCRATCH/build-warnings-clean.log >/dev/null) && cp $NC_SCRATCH/build-warnings-clean.log $NC_SCRATCH/build-warnings-bad.log && printf '/home/user/AMA-Cryptography/src/c/ama_kyber.c:10:5: warning: unused variable \\x27nc\\x27 [-Wunused-variable]\\n' >> $NC_SCRATCH/build-warnings-bad.log",
        "true",
        "python tools/check_compiler_warnings.py $NC_SCRATCH/build-warnings-bad.log",
        "python tools/check_compiler_warnings.py $NC_SCRATCH/build-warnings-clean.log",
        "tests/test_compiler_warning_gate.py",
    ),
    Control(
        "NC-26",
        "tools/check_type_check_scope.py",
        "a mypy line-coverage report that covers one file instead of the whole tracked scope",
        "mkdir -p $NC_SCRATCH && rm -rf $NC_SCRATCH/mypy-partial && MYPYPATH=. mypy --strict --explicit-package-bases --linecoverage-report $NC_SCRATCH/mypy-partial tools/check_headers.py >/dev/null",
        "true",
        "python tools/check_type_check_scope.py $NC_SCRATCH/mypy-partial/coverage.json",
        "rm -rf $NC_SCRATCH/mypy-full && MYPYPATH=. mypy --strict --explicit-package-bases --linecoverage-report $NC_SCRATCH/mypy-full ama_cryptography/ tests/ tools/ benchmarks/ examples/ fuzz/python/ nist_vectors/ schemas/ wycheproof_vectors/ docs/conf.py setup.py ama_cryptography_monitor.py verification/v5-audit/refleak_soak.py verification/v5-audit/diff_fuzz.py docs/audit/ && python tools/check_type_check_scope.py $NC_SCRATCH/mypy-full/coverage.json",
        "tests/test_type_check_scope_gate.py",
    ),
    Control(
        "NC-01",
        "tools/check_action_pins.py --strict (INVARIANT-24)",
        "one action pin's SHA is altered to a commit that does not exist upstream",
        "python3 - <<'EOF'\nimport re\nfrom pathlib import Path\np=Path('.github/workflows/ci.yml'); t=p.read_text()\nm=re.search(r'uses: actions/checkout@([0-9a-f]{40})', t); assert m\nsha=m.group(1); bad=sha[:-1]+('0' if sha[-1]!='0' else '1')\np.write_text(t.replace(sha,bad,1))\nEOF",
        "git checkout -- .github/workflows/ci.yml",
        "python tools/check_action_pins.py --strict",
        "python tools/check_action_pins.py --strict",
        "tests/test_action_pins.py (if present) / this control",
    ),
    Control(
        "NC-40",
        "tools/build_post_kats.py --check (POST vector provenance)",
        "one committed FIPS 140-3 power-on self-test vector file gains a trailing byte",
        "printf '\\n' >> ama_cryptography/_post_kats/ml_kem_1024_kat.json",
        "git checkout -- ama_cryptography/_post_kats/ml_kem_1024_kat.json",
        "python tools/build_post_kats.py --check",
        "python tools/build_post_kats.py --check",
        "tests/test_post_kats_build.py (if present) / this control",
    ),
    Control(
        "NC-41",
        "tools/build_keyformat_corpus.py --verify",
        "one key-format corpus record loses its last two hex digits (declared byte count no longer matches)",
        "python3 - <<'EOF'\nimport json\nfrom pathlib import Path\np=Path('tests/kat/keyformats/rfc8554_hss_lms.json'); d=json.loads(p.read_text())\nrecs=d['records'] if isinstance(d,dict) and 'records' in d else d\nr=next(r for r in (recs if isinstance(recs,list) else recs.values()) if isinstance(r,dict) and isinstance(r.get('hex'),str))\nr['hex']=r['hex'][:-2]\np.write_text(json.dumps(d, indent=2)+'\\n')\nEOF",
        "git checkout -- tests/kat/keyformats/rfc8554_hss_lms.json",
        "python tools/build_keyformat_corpus.py --verify",
        "python tools/build_keyformat_corpus.py --verify",
        "tests/test_keyformat_corpus_provenance.py",
    ),
    Control(
        "NC-42",
        "tools/refresh_wycheproof_corpus.py --offline (corpus-provenance.yml)",
        "one vendored Wycheproof vector file gains a trailing byte",
        "printf '\\n' >> wycheproof_vectors/vectors/aes_gcm_test.json",
        "git checkout -- wycheproof_vectors/vectors/aes_gcm_test.json",
        "python tools/refresh_wycheproof_corpus.py --offline",
        "python tools/refresh_wycheproof_corpus.py --offline",
        "tests/test_wycheproof_corpus_provenance.py",
    ),
    Control(
        "NC-43",
        "tools/generate_sbom.py --check (INVARIANT-11)",
        "the committed C-library SBOM loses one component entry",
        "python3 - <<'EOF'\nimport json\nfrom pathlib import Path\np=Path('docs/compliance/sbom-c-library.json'); d=json.loads(p.read_text())\ncomps=d.get('components') or []\nassert comps, 'no components'\ncomps.pop()\np.write_text(json.dumps(d, indent=2)+'\\n')\nEOF",
        "git checkout -- docs/compliance/sbom-c-library.json",
        "python tools/generate_sbom.py --check",
        "python tools/generate_sbom.py --check",
        "tests/test_sbom_generation.py (if present) / this control",
    ),
    Control(
        "NC-44",
        "tools/generate_visuals.py --check",
        "the committed visuals manifest records one more test than the tree has",
        "python3 - <<'EOF'\nimport json\nfrom pathlib import Path\np=Path('assets/visuals_manifest.json'); d=json.loads(p.read_text())\nd['test_coverage']['total_tests']+=1\np.write_text(json.dumps(d, indent=2)+'\\n')\nEOF",
        "git checkout -- assets/visuals_manifest.json",
        "python tools/generate_visuals.py --check",
        "python tools/generate_visuals.py --check",
        "tests/test_visual_assets_gate.py",
    ),
    Control(
        "NC-46",
        "tools/check_verification_claim_honesty.py (INVARIANT-37)",
        "README.md claims AMA verifies the TSA signature and certificate chain, capabilities RFC3161_CAPABILITIES withholds",
        "printf '\\nAMA verifies the TSA signature and the TSA certificate chain of every RFC 3161 timestamp token.\\n' >> README.md",
        "git checkout -- README.md",
        "python tools/check_verification_claim_honesty.py",
        "python tools/check_verification_claim_honesty.py",
        "tests/test_verification_claim_honesty_gate.py",
    ),
    Control(
        "NC-47",
        "tools/check_dudect_class_staging.py",
        "a dudect harness branches on class_idx between the class draw and the opening timer",
        "python3 - <<'EOF'\nfrom pathlib import Path\np=Path('tests/c/test_dudect.c'); L=p.read_text().splitlines(True)\ni=next(k for k,l in enumerate(L) if 'uint64_t start = dudect_get_time_ns();' in l)\nL.insert(i,'        if (class_idx) { volatile int nc_probe = 1; (void)nc_probe; }\\n')\np.write_text(''.join(L))\nEOF",
        "git checkout -- tests/c/test_dudect.c",
        "python tools/check_dudect_class_staging.py",
        "python tools/check_dudect_class_staging.py",
        "tests/test_dudect_staging_gate.py",
    ),
]


_CHECKOUT = re.compile(r"^git checkout -- (?P<paths>.+)$")


def _checkout_paths(command: str) -> list[str] | None:
    """The paths a `git checkout -- ...` teardown names, or None if it is not one."""
    m = _CHECKOUT.match(command.strip())
    return m.group("paths").split() if m else None


class _Snapshot:
    """Working-tree bytes of the files a control edits, taken before its setup.

    A teardown written as `git checkout -- <file>` restores the INDEX copy,
    which discards any uncommitted edit the auditor has made to that file:
    this driver's own full run reverted README.md and ci.yml calibrations made
    minutes earlier.  So the driver snapshots the working-tree bytes before
    the violation is injected and puts those bytes back afterwards; the git
    command in the recipe is kept for the record but never executed.
    """

    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        self.bytes = {q: (REPO / q).read_bytes() for q in paths if (REPO / q).is_file()}

    def restore(self) -> None:
        for q, data in self.bytes.items():
            (REPO / q).write_bytes(data)


def run_control(c: Control) -> tuple[str, str, str]:
    env_prefix = f"export NC_SCRATCH={SCRATCH}; export PATH=/opt/ama-venv/bin:$PATH; "
    # `violated` keeps "not-run" when the setup raises; `clean` is always
    # assigned below (its `finally` runs whatever the command did), so it is
    # annotated rather than pre-seeded with a value nothing reads.
    violated = "not-run"
    clean: str
    # Files the recipe would `git checkout` are snapshotted from the WORKING
    # TREE first and put back byte-for-byte; the git command is never run.
    snapshot = _Snapshot((_checkout_paths(c.teardown) or []) + (_checkout_paths(c.cleanup) or []))
    try:
        sh(env_prefix + c.setup, check=True)
        rc_v = logged(
            f"{c.id}-v",
            f"negative control (violated): {c.gate}",
            f"phaseD/{c.id}-violated",
            env_prefix + c.violated_cmd,
        )
        violated = str(rc_v)
    except RuntimeError as exc:
        print(f"    {exc}", flush=True)
    finally:
        if _checkout_paths(c.teardown) is not None:
            snapshot.restore()
        else:
            sh(env_prefix + c.teardown)
    try:
        rc_c = logged(
            f"{c.id}-c",
            f"negative control (clean): {c.gate}",
            f"phaseD/{c.id}-clean",
            env_prefix + c.clean_cmd,
        )
        clean = str(rc_c)
    finally:
        if _checkout_paths(c.cleanup) is not None:
            snapshot.restore()
        else:
            sh(env_prefix + c.cleanup)
    verdict = (
        "OK"
        if (violated not in ("0", "not-run") and clean == "0")
        else (
            "CANNOT-FAIL"
            if violated == "0"
            else "CLEAN-NOT-ZERO" if clean != "0" else "SETUP-FAILED"
        )
    )
    return violated, clean, verdict


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    SCRATCH.mkdir(parents=True, exist_ok=True)
    rows = []
    for c in CONTROLS:
        if only and c.id not in only:
            continue
        print(f"=== {c.id} {c.gate}", flush=True)
        violated, clean, verdict = run_control(c)
        print(f"    violated exit={violated} clean exit={clean} -> {verdict}", flush=True)
        row = "\t".join(
            [
                c.id,
                c.gate,
                c.violation,
                c.violated_cmd.replace("\t", " ").replace("\n", " "),
                violated,
                clean,
                verdict,
                c.permanent_test,
                f"docs/audit/logs/phaseD/{c.id}-violated.log ; docs/audit/logs/phaseD/{c.id}-clean.log",
            ]
        )
        rows.append(row)
        _write_row(row)
    bad = [r for r in rows if r.split("\t")[6] != "OK"]
    print(f"\n{len(rows)} controls, {len(bad)} not OK")
    return 1 if bad else 0


HEADER = "\t".join(
    [
        "id",
        "gate",
        "violation_injected",
        "command",
        "exit_when_violated",
        "exit_when_clean",
        "verdict",
        "permanent_test",
        "log",
    ]
)


def _write_row(row: str) -> None:
    """Replace the control's row in the TSV (one row per id, sorted by id).

    A re-run after a gate fix supersedes the earlier row here; the earlier
    attempt is not lost — every run also appended NC-<id>-v / -c rows to
    docs/audit/ledger.tsv, and a gate that could not fail is a finding in
    docs/audit/PR394_FINDINGS.yaml with the before/after logs named.
    """
    existing: dict[str, str] = {}
    if TSV.is_file():
        for line in TSV.read_text(encoding="utf-8").splitlines()[1:]:
            if line.strip():
                existing[line.split("\t", 1)[0]] = line
    existing[row.split("\t", 1)[0]] = row

    def key(item: tuple[str, str]) -> tuple[int, str]:
        digits = "".join(ch for ch in item[0] if ch.isdigit())
        return (int(digits) if digits else 0, item[0])

    body = "\n".join(line for _, line in sorted(existing.items(), key=key))
    TSV.write_text(HEADER + "\n" + body + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
