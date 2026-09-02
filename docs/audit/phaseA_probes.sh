#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# docs/audit/phaseA_probes.sh — the capability probes behind
# docs/audit/PR394_CAPABILITIES.md.  Every line of that document that states
# a tool is present, absent, or usable is backed by a row this script writes to
# docs/audit/ledger.tsv and a log under docs/audit/logs/phaseA/.
#
# Re-run from the repository root:  bash docs/audit/phaseA_probes.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
R="$here/run_logged.sh"
P="phaseA"
export PATH=/opt/ama-venv/bin:$PATH

$R A-01 "clone completeness and HEAD" $P/git-head -- \
  bash -c 'git rev-parse HEAD; git rev-parse --abbrev-ref HEAD; git status --porcelain | wc -l; git fsck --connectivity-only 2>&1 | tail -2'
$R A-02 "true commit count main..HEAD (all / merges / non-merge)" $P/git-count -- \
  bash -c 'git rev-list --count origin/main..HEAD; git rev-list --count --merges origin/main..HEAD; git rev-list --count --no-merges origin/main..HEAD; git merge-base origin/main HEAD; git rev-parse origin/main'
$R A-03 "host CPU, kernel, memory, disk" $P/host -- \
  bash -c 'uname -a; cat /etc/os-release | head -2; lscpu | grep -E "Model name|^CPU\(s\)|Flags"; free -g | head -2; df -h . | tail -1'
$R A-04 "cmake versions (system and pip shim)" $P/cmake -- \
  bash -c '/usr/bin/cmake --version | head -1; cmake --version | head -1; which cmake'
$R A-05 "C compilers" $P/compilers -- \
  bash -c 'gcc --version | head -1; clang --version | head -1; aarch64-linux-gnu-gcc-13 --version | head -1; gcc -m32 -x c -o /dev/null - <<<"int main(void){return 0;}" && echo "gcc -m32 ok"'
$R A-06 "qemu-user aarch64 and SVE vector lengths reachable" $P/qemu-sve -- \
  bash -c 'qemu-aarch64-static --version | head -1; t=$(mktemp -d); printf "#include <arm_sve.h>\n#include <stdio.h>\nint main(void){printf(\"VL=%%lu bytes\\\\n\",(unsigned long)svcntb());return 0;}\n" > $t/sve.c; aarch64-linux-gnu-gcc-13 -march=armv9-a+sve2 -static $t/sve.c -o $t/sve && for vl in 16 32 64 128 256; do printf "sve-default-vector-length=%s: " $vl; qemu-aarch64-static -cpu max,sve-default-vector-length=$vl $t/sve; done; printf "cortex-a53 (no SVE): "; qemu-aarch64-static -cpu cortex-a53 $t/sve; echo "exit=$?"'
$R A-07 "valgrind" $P/valgrind -- valgrind --version
$R A-08 "clang sanitizers: ASan MSan TSan UBSan compile+run" $P/sanitizers -- \
  bash -c 't=$(mktemp -d); printf "#include <stdio.h>\nint main(void){printf(\"ok\\\\n\");return 0;}\n" > $t/h.c; for s in address memory thread undefined; do printf "%s: " $s; clang -fsanitize=$s $t/h.c -o $t/h_$s && $t/h_$s; done'
$R A-09 "clang libFuzzer" $P/libfuzzer -- \
  bash -c 't=$(mktemp -d); printf "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){(void)d;(void)n;return 0;}\n" > $t/f.c; clang -fsanitize=fuzzer $t/f.c -o $t/f && $t/f -runs=10'
$R A-10 "atheris" $P/atheris -- python3 -c 'import atheris; print("atheris", atheris.__file__)'
$R A-11 "semgrep" $P/semgrep -- semgrep --version
$R A-12 "cppcheck" $P/cppcheck -- cppcheck --version
$R A-13 "clang-tidy" $P/clang-tidy -- clang-tidy --version
$R A-14 "CodeQL CLI (bundle 2.20.0, downloaded this session)" $P/codeql -- \
  bash -c '/tmp/claude-0/-home-user-AMA-Cryptography/d1d010bd-84d8-545d-aa0f-7630a9d5067a/scratchpad/codeql/codeql/codeql version 2>/dev/null | grep -v JAVA_TOOL; /tmp/claude-0/-home-user-AMA-Cryptography/d1d010bd-84d8-545d-aa0f-7630a9d5067a/scratchpad/codeql/codeql/codeql resolve languages 2>/dev/null | grep -E "^(python|cpp|actions) "'
$R A-15 "mypy ruff black bandit" $P/pytools -- \
  bash -c 'mypy --version; ruff --version; black --version | head -1; bandit --version | head -1'
$R A-16 "softhsm2 + PyKCS11 + pkcs11-tool" $P/softhsm -- \
  bash -c 'softhsm2-util --version; ls -la /usr/lib/softhsm/libsofthsm2.so; python3 -c "import PyKCS11; print(\"PyKCS11\", PyKCS11.__version__ if hasattr(PyKCS11, \"__version__\") else \"ok\")"; pkcs11-tool --help 2>&1 | head -1'
$R A-17 "sigstore python client + cosign" $P/sigstore -- \
  bash -c 'sigstore --version; cosign version 2>&1 | grep -E "GitVersion|GitCommit"'
$R A-18 "gh CLI (expected absent; GitHub reached via MCP)" $P/gh -- bash -c 'command -v gh || { echo "gh ABSENT"; exit 3; }'
$R A-19 "mutmut" $P/mutmut -- bash -c 'python3 -c "import mutmut, importlib.metadata as m; print(\"mutmut\", m.version(\"mutmut\"))"'
$R A-20 "python, pytest, hypothesis, Cython, numpy, scipy" $P/python -- \
  bash -c 'python3 --version; pytest --version; python3 -c "import hypothesis, Cython, numpy, scipy; print(hypothesis.__version__, Cython.__version__, numpy.__version__, scipy.__version__)"'
$R A-21 "network: corpora and package indexes the suite gates on" $P/network -- \
  bash -c 'for u in https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/README.md https://raw.githubusercontent.com/C2SP/wycheproof/master/README.md https://csrc.nist.gov/ https://pypi.org/simple/pip/ https://files.pythonhosted.org/ https://rekor.sigstore.dev/api/v1/log https://tuf-repo-cdn.sigstore.dev/1.root.json https://api.github.com/ https://github.com/ https://registry-1.docker.io/v2/ https://www.rfc-editor.org/; do printf "%-70s " "$u"; curl -sS -o /dev/null -w "%{http_code}\n" --max-time 30 "$u" || echo "curl-fail"; done'
$R A-22 "docker" $P/docker -- bash -c 'docker version 2>&1 | head -3; docker info >/dev/null 2>&1 && echo daemon-up || echo daemon-DOWN'
$R A-23 "hardware absent: vaes vpclmulqdq sha_ni sve2 (lscpu flags)" $P/hw-absent -- \
  bash -c 'for f in avx512f avx512vl avx512bw vaes vpclmulqdq sha_ni sve sve2; do printf "%-12s " $f; lscpu | grep -q -w "$f" && echo present || echo ABSENT; done; echo "os: $(uname -s) (no Windows, no macOS, no real HSM, no AArch64 silicon)"'
$R A-24 "Release C build + ctest (baseline, this host)" $P/ctest-release -- \
  bash -c 'cd build-release && ctest -N | tail -1 && ctest -j4 2>&1 | grep -E "tests passed|Total Test time"'
