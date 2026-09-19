/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_sphincs_avx2.c
 * @brief x86-64 AVX2 SLH-DSA / SPHINCS+ placeholder TU (no kernels wired)
 *
 * AVX2 SLH-DSA (FIPS 205 / SPHINCS+) acceleration is not currently shipped.
 * SLH-DSA on x86-64 uses the same scalar SHA-256 / SHAKE inner loop as the
 * rest of the family (`src/c/ama_slhdsa.c`, `src/c/ama_sphincs.c`), with the
 * underlying Keccak permutation accelerated through the dispatch table's
 * `keccak_f1600` slot — which is what gives the SHAKE-128s parameter sets
 * their speed-up.  The SHA2-256f path is scalar end to end.
 *
 * WHAT THIS FILE USED TO CONTAIN, AND WHY IT IS GONE
 *
 * A header advertising "8-way parallel SHA-256 compression", "vectorized
 * WOTS+ chain computation", "parallel FORS tree leaf generation" and
 * "vectorized Merkle tree hash computation", above:
 *
 *   - `ama_sha256_compress_x8_avx2` and `..._x4_avx2`, both `static` with no
 *     caller, eliminated from every shipped artifact;
 *   - `ama_sphincs_wots_chain_avx2`, the one exported symbol, which was
 *     plain scalar C — a hand-rolled single unpadded SHA-256 compression per
 *     step that ignored `pub_seed`, emitted no compressed ADRS and no
 *     `toByte(0, 64 - n)` padding, so it did not compute FIPS 205 `F` at all
 *     — and which `slh_wots_chain` never dispatched to.
 *
 * Its "SIMD equivalence" test compared that function against a verbatim
 * transcription of the same non-spec algorithm, so the gate could not detect
 * a regression and executed zero vector instructions.  A kernel that is
 * compiled, exported, unreachable and untested is pre-installed attack
 * surface with a gate that certifies nothing: a later "wiring" commit could
 * have routed WOTS+ through a function that is not `F` while the equivalence
 * test stayed green.
 *
 * This is the same disposition, and the same reasoning, applied to
 * `src/c/sve2/ama_sphincs_sve2.c` in an earlier pass.
 *
 * A future AVX2 SLH-DSA acceleration must (a) compute the real FIPS 205 `F`
 * / `PRF` (PK.seed || toByte(0, 32) || ADRSc || M, correctly padded),
 * (b) reach the FORS / Merkle / WOTS+ chains through a declared dispatch
 * surface rather than a private symbol, and (c) land with a lane that pins
 * it against `ama_sha256` on the same inputs and runs the SLH-DSA ACVP
 * sigGen vectors end to end on the vector path.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>

typedef int ama_sphincs_avx2_not_available;
