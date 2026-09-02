#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# PR #394 readiness falsification — §13 validation of the commit under audit.
# Every lane CI runs is replicated here from the workflow recipes, and every
# invocation is a ledger row (V-<lane>) with a retained log, so the
# attestation cites rows rather than memories.  Nothing here is skipped
# silently: a lane that cannot run records a non-zero exit.
#
# Usage: docs/audit/validate.sh            (from the repository root)
set -u
export PATH=/opt/ama-venv/bin:$PATH
R=docs/audit/run_logged.sh
NPROC=$(nproc)
STRICT='-Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wconversion -Wno-sign-conversion -Werror=missing-prototypes -Werror=shadow -Werror=unused-function'
mkdir -p docs/audit/logs/validate

# ---- Refs: the attestation's "no other ref was touched" evidence -----------
$R V-refs "every ref this clone knows, and the commits this branch adds over origin/main" validate/refs -- sh -c 'git for-each-ref --format="%(refname) %(objectname:short)"; echo "--- origin/main..HEAD:"; git log --oneline origin/main..HEAD; echo "--- status:"; git status --short --branch'

# ---- Python: lint, format, types, scope, security scanners -----------------
$R V-ruff  "ruff check . (ci.yml Lint)"                          validate/ruff  -- ruff check .
$R V-black "black --check . (ci.yml Format)"                     validate/black -- black --check .
rm -rf .mypy-coverage
$R V-mypy  "mypy --strict over the CI file set (+ docs/audit/)" validate/mypy  -- env MYPYPATH=. mypy --strict --explicit-package-bases --linecoverage-report .mypy-coverage ama_cryptography/ tests/ tools/ benchmarks/ examples/ fuzz/python/ nist_vectors/ schemas/ wycheproof_vectors/ docs/conf.py setup.py ama_cryptography_monitor.py verification/v5-audit/refleak_soak.py verification/v5-audit/diff_fuzz.py docs/audit/
$R V-gate-check_type_check_scope "every tracked .py was type-checked" validate/gate-type-check-scope -- python tools/check_type_check_scope.py .mypy-coverage/coverage.json
bandit -r ama_cryptography/ setup.py tools/ -f json -o bandit-report.json --exit-zero > docs/audit/logs/validate/bandit-run.log 2>&1
$R V-gate-check_bandit_severity "Bandit High/High findings gate" validate/gate-bandit -- python tools/check_bandit_severity.py bandit-report.json
semgrep --config .semgrep.yml ama_cryptography/ setup.py tools/ --json -o semgrep-report.json > docs/audit/logs/validate/semgrep-run.log 2>&1
$R V-gate-check_semgrep_severity "Semgrep ERROR findings gate" validate/gate-semgrep -- python tools/check_semgrep_severity.py semgrep-report.json

# ---- Python test suite (the CI Test job) ----------------------------------
$R V-pytest "full Python suite, native backends required (ci.yml Test)" validate/pytest -- env AMA_CI_REQUIRE_BACKENDS=1 python -m pytest tests/ -v --tb=short --no-cov -p no:cacheprovider

# ---- Repository gates, with CI's arguments --------------------------------
for g in check_action_pins:--strict check_algorithm_registry check_apt_retry check_c_secret_zeroization check_choco_retry check_corpus_originality check_docker_pins check_documented_counts check_documented_extras check_dudect_class_staging check_error_state_gating check_export_allowlist check_fdopen_safety check_fuzz_input_reachability check_fuzz_target_registration check_gate_coverage check_headers:--check check_keygen_pct check_line_endings check_log_message_encodability check_secrets check_stdlib_hash_boundary check_suppression_hygiene check_vector_provenance check_vendor_isolation check_verification_claim_honesty check_version_consistency check_workflow_commands check_reference_integrity; do
  name=${g%%:*}; args=${g#*:}; [ "$args" = "$g" ] && args=""
  # shellcheck disable=SC2086
  $R "V-gate-$name" "gate $name $args" "validate/gate-$name" -- python tools/$name.py $args
done

# Gates that need a built library, with the artefact CI gives them.
$R V-gate-check_avx_scoping "no AVX/AVX2 opcode outside the per-file kernel scopes (x86-64 shared library)" validate/gate-check_avx_scoping -- python tools/check_avx_scoping.py --lib build-release/lib/libama_cryptography.so
$R V-gate-check_secret_division "no divide instruction on a secret operand (x86-64 shared library)" validate/gate-check_secret_division-x86 -- python tools/check_secret_division.py --lib build-release/lib/libama_cryptography.so
$R V-gate-check_secret_division-arm "no divide instruction on a secret operand (AArch64 cross build)" validate/gate-check_secret_division-arm -- python tools/check_secret_division.py --lib build-arm/lib/libama_cryptography.so
$R V-gate-check_secret_division-sve2 "no divide instruction on a secret operand (AArch64 SVE2 build)" validate/gate-check_secret_division-sve2 -- python tools/check_secret_division.py --lib build-arm-sve2/lib/libama_cryptography.so

# The release-state gate is a release-day check: on an untagged head whose docs
# correctly say "not tagged yet" its refusal IS the pass, so the row records the
# refusal rather than treating it as a lane failure.  NC-21 drives the other
# direction (docs flipped to released without the tag -> the same exit 1).
$R V-gate-check_release_state "release-state gate on the untagged head (exit 1 is the correct answer: the docs still say unreleased)" validate/gate-check_release_state -- sh -c 'python tools/check_release_state.py --version 5.0.0; test $? -eq 1'

# ---- C lanes on the existing CI-recipe builds -----------------------------
for b in build-release build-asan; do
  $R "V-ctest-$b" "ctest $b" "validate/ctest-$b" -- ctest --test-dir $b --output-on-failure -j2
done
$R V-ctest-build-msan "ctest MSan (clang-18, libc++, SIMD off)" validate/ctest-build-msan -- env MSAN_OPTIONS=print_stacktrace=1:halt_on_error=1:abort_on_error=1 ctest --test-dir build-msan --output-on-failure -j2
$R V-ctest-build-tsan "ctest TSan" validate/ctest-build-tsan -- env TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 ctest --test-dir build-tsan --output-on-failure -j2
for b in build-arm build-arm-nocrypto; do
  $R "V-ctest-$b" "ctest $b (AArch64 cross, qemu-user)" "validate/ctest-$b" -- ctest --test-dir $b --output-on-failure -j2
done
for vq in 1 2 4 8 16; do
  $R "V-ctest-sve2-vq$vq" "ctest AArch64 SVE2 at VL=$((vq*128)) (QEMU_CPU=max,sve-max-vq=$vq)" "validate/ctest-sve2-vq$vq" -- env QEMU_CPU=max,sve-max-vq=$vq ctest --test-dir build-arm-sve2 --output-on-failure -j2
done
# VL 1024 and 2048 need the default-VL cap lifted (qemu 8.2 caps the default at 512 bits otherwise).
for vq in 8 16; do
  $R "V-ctest-sve2-vq$vq-defaultvl" "ctest AArch64 SVE2 at VL=$((vq*128)) with sve-default-vector-length=-1 (the dispatcher sees the full VL)" "validate/ctest-sve2-vq$vq-defaultvl" -- env QEMU_CPU=max,sve-max-vq=$vq,sve-default-vector-length=-1 ctest --test-dir build-arm-sve2 --output-on-failure -j2
done

# ---- Strict-warning builds and the frozen allowlist (static-analysis.yml) --
for cc in gcc clang; do
  rm -rf build-strict-$cc build-strict-release-$cc
  $R "V-strict-$cc-configure" "strict warnings ($cc, CMAKE_BUILD_TYPE=None)" "validate/strict-$cc-configure" -- cmake -B build-strict-$cc -DCMAKE_BUILD_TYPE=None -DCMAKE_C_COMPILER=$cc "-DCMAKE_C_FLAGS=$STRICT" -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_LTO=OFF
  cmake --build build-strict-$cc -j$NPROC -- -Otarget > build-warnings-$cc.log 2>&1; echo "build exit $?" >> build-warnings-$cc.log
  $R "V-strict-release-$cc-configure" "strict warnings ($cc, Release, LTO on)" "validate/strict-release-$cc-configure" -- cmake -B build-strict-release-$cc -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=$cc "-DCMAKE_C_FLAGS=$STRICT" -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON -DAMA_BUILD_EXAMPLES=OFF -DAMA_ENABLE_NATIVE_ARCH=OFF -DAMA_ENABLE_LTO=ON
  cmake --build build-strict-release-$cc -j$NPROC -- -Otarget > build-warnings-release-$cc.log 2>&1; echo "build exit $?" >> build-warnings-release-$cc.log
  $R "V-gate-check_compiler_warnings-$cc" "frozen warning allowlist ($cc: None + Release logs)" "validate/gate-compiler-warnings-$cc" -- python tools/check_compiler_warnings.py build-warnings-$cc.log build-warnings-release-$cc.log
done
rm -rf build-strict-arm-sve2
$R V-strict-arm-sve2-configure "strict warnings (AArch64 cross, NEON + SVE2)" validate/strict-arm-sve2-configure -- cmake -S . -B build-strict-arm-sve2 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake -DCMAKE_BUILD_TYPE=Release "-DCMAKE_C_FLAGS=$STRICT" -DAMA_USE_NATIVE_PQC=ON -DAMA_AES_CONSTTIME=ON -DAMA_ENABLE_SVE2=ON -DAMA_BUILD_TESTS=ON -DAMA_BUILD_EXAMPLES=OFF -DAMA_BUILD_FUZZ=OFF -DAMA_ENABLE_NATIVE_ARCH=OFF -DAMA_ENABLE_LTO=OFF
LC_ALL=C cmake --build build-strict-arm-sve2 -j$NPROC > build-warnings-arm-sve2.log 2>&1; echo "build exit $?" >> build-warnings-arm-sve2.log
$R V-gate-check_compiler_warnings-arm "frozen warning allowlist (AArch64 SVE2 log)" validate/gate-compiler-warnings-arm -- python tools/check_compiler_warnings.py build-warnings-arm-sve2.log

# ---- Ed25519 backend parity (ci.yml) --------------------------------------
rm -rf build-donna build-fe51
$R V-parity-build-donna "donna backend build" validate/parity-build-donna -- sh -c "cmake -S . -B build-donna -DAMA_ED25519_ASSEMBLY=ON -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release -DAMA_BUILD_TESTS=ON -DAMA_BUILD_EXAMPLES=OFF && cmake --build build-donna -j$NPROC"
$R V-parity-build-fe51 "fe51 backend build" validate/parity-build-fe51 -- sh -c "cmake -S . -B build-fe51 -DAMA_ED25519_ASSEMBLY=OFF -DAMA_USE_NATIVE_PQC=ON -DCMAKE_BUILD_TYPE=Release -DAMA_BUILD_TESTS=ON -DAMA_BUILD_EXAMPLES=OFF && cmake --build build-fe51 -j$NPROC"
$R V-ctest-build-fe51 "ctest against the fe51 backend" validate/ctest-build-fe51 -- ctest --test-dir build-fe51 --output-on-failure -j2
$R V-gate-check_ed25519_backend_parity "donna vs fe51 differential" validate/gate-ed25519-parity -- python tools/check_ed25519_backend_parity.py --donna build-donna/lib/libama_cryptography.so --fe51 build-fe51/lib/libama_cryptography.so

# ---- callgrind instruction-count gates (dudect.yml) -----------------------
rm -rf build-callgrind
$R V-callgrind-build "Release, LTO off, test archive for the callgrind gates" validate/callgrind-build -- sh -c "cmake -B build-callgrind -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON -DAMA_ENABLE_LTO=OFF && cmake --build build-callgrind -j$NPROC --target ama_cryptography_test"
for t in aead-verify agent-binding ascon-encrypt ascon-hash consttime consttime-copy consttime-lookup consttime-swap ecdsa ed25519-sign ghash kyber-decaps nistp-ecdsa secp256k1-scalarmult secure-memzero sha3-256 x25519 x25519-batch; do
  $R "V-gate-ghash-$t" "callgrind instruction-count invariance: $t" "validate/gate-callgrind-$t" -- python tools/check_ghash_constant_time.py --lib build-callgrind/lib/libama_cryptography_test.a --target $t
done

# ---- Release tag preflight on the current (untagged) head ------------------
$R V-gate-check_release_tag "release tag preflight against v5.0.0 (expected to refuse: no such tag)" validate/gate-release-tag -- python tools/check_release_tag.py v5.0.0
echo "VALIDATE_DONE $(date -u +%FT%TZ)"
