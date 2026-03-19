# AMA Cryptography — Library Invariants

This document defines invariants that must hold true across all changes to the
AMA Cryptography library. Violations of any invariant must be resolved before
code is merged.

---

1. All cryptographic primitives implemented in this library must map to a
   non-deprecated entry in CSRC_STANDARDS.md. Adding any new algorithm requires
   updating CSRC_STANDARDS.md with its governing standard, parameter set,
   status, and source URL before implementation is permitted. Algorithms whose
   governing standard has been deprecated or withdrawn must be removed from the
   library or explicitly documented with a migration timeline.
