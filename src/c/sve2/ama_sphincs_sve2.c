/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_sphincs_sve2.c
 * @brief ARM SVE2 SLH-DSA / SPHINCS+ placeholder TU (no kernels currently wired)
 *
 * SVE2 SLH-DSA (FIPS 205 / SPHINCS+) acceleration is not currently
 * shipped.  SLH-DSA on SVE2-capable ARM systems runs the one SLH-DSA
 * implementation in the tree, `src/c/ama_slhdsa.c` (the former standalone
 * `ama_sphincs.c`, whose signer was byte-identical to it, has been
 * removed), with no algorithm-level SIMD.  Its Keccak permutation is
 * accelerated through the dispatch table's `keccak_f1600` slot, which on
 * SVE2 hosts routes to `ama_keccak_f1600_sve2` (wired by
 * `dispatch_init_internal` in `src/c/dispatch/ama_dispatch.c`).  Indirect
 * SHAKE acceleration via the Keccak slot is the production path on every
 * shipped AArch64 host.
 *
 * The previous content of this file was scalar `ama_sha256_compress_sve2`
 * and `ama_sphincs_wots_chain_sve2` helpers that — by design — were
 * never reachable from any dispatch table entry.  The dispatch table
 * (`include/ama_dispatch.h`) intentionally exposes no SPHINCS+ /
 * SLH-DSA function-pointer slots: the SLH-DSA hot loop is the FORS /
 * Merkle hash tree, and acceleration there comes from the
 * `keccak_f1600` slot (for SHAKE families) or, for SHA-2 families, from
 * the runtime-selected SHA-256 compress in `src/c/ama_sha256.c` (ARMv8
 * SHA2 instructions on AArch64 hosts that have them, SHA-NI on x86-64),
 * not from algorithm-level dispatch.  A compiled-but-unreachable kernel is
 * pre-installed attack surface (any future wiring line would route SLH-DSA
 * through a code path that was never KAT-validated against FIPS 205
 * vectors), so the helpers have been removed.
 *
 * A future SVE2 SLH-DSA acceleration must (a) target the FORS /
 * Merkle / WOTS+ hash chains through a properly declared dispatch
 * surface — not a private symbol consumed by ad-hoc include — and
 * (b) land alongside an SVE-aware CI lane that exercises the
 * SLH-DSA-SHAKE-128s / SHA2-256f ACVP sigGen vectors end-to-end on
 * the SVE2 path.  Until then, SVE2 hosts use the scalar SLH-DSA inner
 * loop with the SVE2 Keccak permutation underneath — which is already
 * a strict upgrade over the previous "generic Keccak" state.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>

typedef int ama_sphincs_sve2_not_available;
