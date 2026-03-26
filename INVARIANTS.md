# AMA Cryptography — Library Invariants

> **See also:** [`.github/INVARIANTS.md`](.github/INVARIANTS.md) for the
> complete set of architectural invariants (INVARIANT-1 through INVARIANT-4)
> enforced on every PR. This document provides detailed rationale and vendoring
> policy for the invariants defined there.

This document defines invariants that must hold true across all changes to the
AMA Cryptography library. Violations of any invariant must be resolved before
code is merged.

---

1. **INVARIANT-1: Zero External Crypto Dependencies.** All cryptographic
   primitives implemented in this library must map to a non-deprecated entry in
   CSRC_STANDARDS.md. Adding any new algorithm requires updating
   CSRC_STANDARDS.md with its governing standard, parameter set, status, and
   source URL before implementation is permitted. Algorithms whose governing
   standard has been deprecated or withdrawn must be removed from the library
   or explicitly documented with a migration timeline. No pre-built external
   cryptographic libraries (libsodium, OpenSSL, liboqs, etc.) may be linked.
   Vendoring public-domain source into `src/c/vendor/` and compiling it as part
   of AMA's own build system is permitted — vendored source is included in-tree
   and compiled as part of AMA's build system; its original license (documented
   per component) is unaffected by vendoring.

---

2. **INVARIANT-2: Thread-Safe CPU Dispatch via Platform Once-Primitive.** All
   one-time initialization in `ama_cpuid.c` (CPU feature detection, AEAD
   backend selection) must use a platform once-primitive that guarantees
   exactly-once execution with full memory visibility across threads.  The
   approved primitives are:
   - **POSIX** (Linux, macOS, BSDs): `pthread_once` (IEEE Std 1003.1)
   - **Windows** (MSVC): `InitOnceExecuteOnce` (synchapi.h, Vista+)

   Lockless flag + plain-variable patterns (e.g., `volatile int done` guarding
   a non-atomic shared variable) are **prohibited** — they constitute data
   races on weakly-ordered architectures and are undefined behavior under the
   C11 memory model.

   C11 `<threads.h>` (`call_once`) is not used because it is unavailable on
   macOS (Apple SDK has never shipped `<threads.h>`) and unreliable on MSVC
   (partially shipped starting VS 17.8, still buggy).  CMakeLists.txt uses
   `find_package(Threads REQUIRED)` and links `Threads::Threads` to all
   library targets.

---

## Vendored Dependencies

### ed25519-donna

- **Source:** https://github.com/floodyberry/ed25519-donna
- **License:** Public domain (Andrew Moon)
- **Location:** `src/c/vendor/ed25519-donna/`
- **CMake flag:** `AMA_ED25519_ASSEMBLY` (default OFF)
- **Purpose:** Optimized x86-64 Ed25519 scalar multiplication with inline
  assembly for constant-time Niels basepoint table selection. Provides ~3x
  keygen/sign speedup and ~2.5x verify speedup over AMA's fe51 C
  implementation on x86-64.
- **INVARIANT-1 compliance:** The vendored source is public domain, compiled
  from source as part of AMA's build system, and never linked as a pre-built
  binary. It satisfies INVARIANT-1 under the vendoring policy: vendored
  public-domain source is included in-tree and compiled as part of AMA's build
  system; its original public-domain license is unaffected by vendoring.
- **MSVC ARM64 limitation:** The donna backend provides x86-64 assembly only.
  The fe51 backend requires `__uint128_t`, which MSVC does not provide on any
  architecture. Therefore MSVC on ARM64 (Windows on ARM) has no working
  Ed25519 path. CMakeLists.txt emits `FATAL_ERROR` at configure time for this
  combination. To build on ARM64 Windows, use GCC or Clang (e.g., via MSYS2
  or clang-cl) which provide `__uint128_t` and enable the fe51 backend.
