# AMA Cryptography — Library Invariants

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
