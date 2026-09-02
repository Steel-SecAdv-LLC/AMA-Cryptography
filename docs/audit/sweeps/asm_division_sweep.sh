#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# PR #394 readiness falsification, Phase E: KyberSlash-class assembly sweep.
# Every C source of the library is compiled to assembly with each compiler
# the CI matrix uses, at -O0, -O1, -O2, -O3 and -Os, with the build's own
# defines and per-file ISA flags, and every integer division instruction is
# reported with the function it landed in.  KyberSlash was a `/ KYBER_Q` on
# secret data that the source-level rule missed and only the compiler made
# visible; an assembly-level census at every optimisation level is the check
# that does not depend on the source spelling.  A file that fails to compile
# is a row, not a silence.
#
# Usage: docs/audit/sweeps/asm_division_sweep.sh <out.tsv> <status.tsv> <log-dir>
set -u
out="$1"; status="$2"; logdir="$3"
mkdir -p "$logdir"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"
printf 'compiler\tarch\topt\tfile\tfunction\tmnemonic\tcount\n' > "$out"
printf 'compiler\tarch\topt\tfile\tstatus\tdivisions\tlog\n' > "$status"

defines_of() { grep -E "^C_DEFINES" "$1" | sed 's/^C_DEFINES = //; s/\\"/"/g'; }
custom_of()  { grep -A1 -F "$2.o_FLAGS" "$1" | grep -oE '= .*$' | sed 's/^= //' | head -1; }
base_of()    { grep -E '^C_FLAGS' "$1" | sed 's/^C_FLAGS = //; s/-O[0-3s]//g; s/-g\b//g; s/-flto[^ ]*//g; s/-f\(no-\)\?fat-lto-objects//g; s/-DNDEBUG//g'; }

X86_FM="build-release/CMakeFiles/ama_cryptography_static.dir/flags.make"
ARM_FM="build-arm-sve2/CMakeFiles/ama_cryptography_static.dir/flags.make"
INC="-Iinclude -Isrc/c"

common=$(ls src/c/*.c src/c/internal/*.c src/c/dispatch/*.c)
x86_only=$(ls src/c/x86/*.c src/c/avx2/*.c src/c/avx512/*.c)
arm_only=$(ls src/c/neon/*.c src/c/sve2/*.c)
vendor=$(find src/c/vendor -name '*.c' | sort)

sweep() {  # compiler arch flags.make regex files...
  local cc="$1" arch="$2" fm="$3" re="$4"; shift 4
  local defs base
  defs="$(defines_of "$fm")"; base="$(base_of "$fm")"
  for lvl in 0 1 2 3 s; do
    for f in "$@"; do
      local custom asm log rc
      custom="$(custom_of "$fm" "$f")"
      asm="$logdir/$(echo "$cc-$arch-O$lvl-$f" | tr '/ ' '__').s"
      log="$asm.log"
      # shellcheck disable=SC2086
      $cc $base -O$lvl $defs $INC $custom -w -S -o "$asm" "$f" > "$log" 2>&1
      rc=$?
      if [ $rc -ne 0 ]; then
        printf '%s\t%s\tO%s\t%s\tcompile_error\tn/a\t%s\n' "$cc" "$arch" "$lvl" "$f" "$log" >> "$status"
        continue
      fi
      # Function labels are `name:` at column 0 (not `.L` locals); a division
      # is attributed to the last label seen before it.
      awk -v cc="$cc" -v arch="$arch" -v lvl="O$lvl" -v file="$f" -v re="$re" '
        /^[A-Za-z_][A-Za-z0-9_.$@]*:/ {fn=$1; sub(/:$/, "", fn)}
        $0 ~ re {m=$1; key=fn "\t" m; n[key]++}
        END {for (k in n) printf "%s\t%s\t%s\t%s\t%s\t%d\n", cc, arch, lvl, file, k, n[k]}' "$asm" | sort >> "$out"
      total=$(awk -v re="$re" '$0 ~ re {c++} END {print c+0}' "$asm")
      printf '%s\t%s\tO%s\t%s\tok\t%s\t%s\n' "$cc" "$arch" "$lvl" "$f" "$total" "$log" >> "$status"
      rm -f "$asm"
    done
  done
}

X86_RE='^[[:space:]]+(div|idiv)[bwlq]?[[:space:]]'
ARM_RE='^[[:space:]]+(udiv|sdiv)[[:space:]]'
# shellcheck disable=SC2086
sweep gcc   x86_64  "$X86_FM" "$X86_RE" $common $x86_only $vendor
# shellcheck disable=SC2086
sweep clang x86_64  "$X86_FM" "$X86_RE" $common $x86_only $vendor
# shellcheck disable=SC2086
sweep aarch64-linux-gnu-gcc aarch64 "$ARM_FM" "$ARM_RE" $common $arm_only $vendor
echo "DONE $(date -u +%FT%TZ)" >> "$out.done"
