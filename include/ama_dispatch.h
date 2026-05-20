/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dispatch.h
 * @brief Runtime SIMD dispatch declarations
 *
 * Function pointer table for routing cryptographic inner loops to
 * SIMD-optimized implementations based on CPU feature detection.
 * Thread-safe initialization via platform once-primitives (INVARIANT-15).
 */

#ifndef AMA_DISPATCH_H
#define AMA_DISPATCH_H

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Dispatch implementation level selected at runtime. */
typedef enum {
    AMA_IMPL_GENERIC = 0,  /**< Portable scalar C reference implementation. */
    AMA_IMPL_AVX2    = 1,  /**< x86-64 AVX2 (256-bit SIMD). */
    AMA_IMPL_AVX512  = 2,  /**< x86-64 AVX-512 (512-bit SIMD; where enabled). */
    AMA_IMPL_NEON    = 3,  /**< ARM64 NEON / AdvSIMD. */
    AMA_IMPL_SVE2    = 4,  /**< ARM64 SVE2 (scalable vectors). */
} ama_impl_level_t;

/** Dispatch info populated by ama_dispatch_init() (read-only after init).
 *
 * ABI policy: append-only.  New fields land *after* `arch_name` so
 * binaries linked against older copies of this header still see the
 * same offset for every field they know about.  Reordering or
 * inserting fields earlier would silently break consumers compiled
 * against a previous release. */
typedef struct {
    ama_impl_level_t sha3;              /**< Selected SHA3 / Keccak-f[1600] path. */
    ama_impl_level_t kyber;             /**< Selected Kyber NTT / pointwise path. */
    ama_impl_level_t dilithium;         /**< Selected Dilithium NTT / pointwise path. */
    ama_impl_level_t sphincs;           /**< Selected SPHINCS+ path. */
    ama_impl_level_t aes_gcm;           /**< Selected AES-256-GCM path (AES-NI, etc.). */
    ama_impl_level_t ed25519;           /**< Selected Ed25519 field-element path. */
    ama_impl_level_t chacha20poly1305;  /**< Selected ChaCha20-Poly1305 path. */
    ama_impl_level_t argon2;            /**< Selected Argon2 G compression path. */
    const char *arch_name;              /**< Human-readable architecture label (for diagnostics). */
    ama_impl_level_t x25519;            /**< Selected X25519 4-way ladder path (batch API only; single-shot stays scalar). 3.0.0+. */
} ama_dispatch_info_t;

/* ============================================================================
 * Function pointer types for dispatchable operations
 * ============================================================================ */

/** Keccak-f[1600] permutation (24 rounds on 25 x uint64_t state) */
typedef void (*ama_keccak_f1600_fn)(uint64_t state[25]);

/** 4-way Keccak-f[1600] permutation on four independent states.
 *  Generic fallback invokes the single-state keccak_f1600 four times;
 *  AVX2 path permutes the four states interleaved in YMM registers,
 *  amortizing theta/rho/pi/chi/iota across all four lanes. */
typedef void (*ama_keccak_f1600_x4_fn)(uint64_t states[4][25]);

/** SHA3-256: full hash (input, len) -> output[32] */
typedef ama_error_t (*ama_sha3_256_fn)(const uint8_t *input, size_t input_len,
                                        uint8_t output[32]);

/** Kyber NTT forward transform */
typedef void (*ama_kyber_ntt_fn)(int16_t poly[256], const int16_t zetas[128]);

/** Kyber polynomial pointwise multiply (basemul in Z_q[X]/(X^2-zeta)) */
typedef void (*ama_kyber_pointwise_fn)(int16_t r[256],
                                       const int16_t a[256],
                                       const int16_t b[256],
                                       const int16_t zetas[128]);

/** Kyber polynomial add: r = a + b (coefficient-wise int16_t add).
 *  Output range is [-2(q-1), 2(q-1)]; callers that need canonical
 *  reduction must follow with `kyber_poly_reduce`. */
typedef void (*ama_kyber_poly_add_fn)(int16_t r[256],
                                       const int16_t a[256],
                                       const int16_t b[256]);

/** Kyber polynomial sub: r = a - b (coefficient-wise int16_t sub).
 *  Output range is [-2(q-1), 2(q-1)]; callers that need canonical
 *  reduction must follow with `kyber_poly_reduce`. */
typedef void (*ama_kyber_poly_sub_fn)(int16_t r[256],
                                       const int16_t a[256],
                                       const int16_t b[256]);

/** Kyber polynomial Barrett reduction in place.
 *
 *  Post-condition: each output coefficient is congruent to its input
 *  modulo q (= 3329) and small enough to feed back into further mod-q
 *  int16 arithmetic without overflow.  The actual representative is
 *  implementation-defined within roughly [-q, q]: the production
 *  scalar barrett_reduce() in src/c/ama_kyber.c can return +q (or -q)
 *  for some inputs at the extremes of its input range (e.g., a == -q
 *  yields t == (v*-q)>>26 == -2 via arithmetic right shift, producing
 *  a - t*q == +q), and the SVE2 kernel's *centered* Barrett (with the
 *  `+ (1 << 25)` rounding term) can pick a representative differing
 *  by exactly q from the scalar result.  Both are cryptographically
 *  correct because every downstream consumer re-reduces before bit
 *  extraction.  Callers needing a strict canonical form must follow
 *  with the FIPS 203 csubq / freeze step. */
typedef void (*ama_kyber_poly_reduce_fn)(int16_t poly[256]);

/** Kyber CBD2 noise sampler: 128-byte uniform stream -> 256 coefficients
 *  in {-2, -1, 0, 1, 2} per FIPS 203 §4.2.2 (ML-KEM eta=2). */
typedef void (*ama_kyber_cbd2_fn)(int16_t poly[256], const uint8_t buf[128]);

/** Dilithium NTT forward transform */
typedef void (*ama_dilithium_ntt_fn)(int32_t poly[256],
                                     const int32_t zetas[256]);

/** Dilithium inverse NTT */
typedef void (*ama_dilithium_invntt_fn)(int32_t poly[256],
                                        const int32_t zetas[256]);

/** Dilithium polynomial pointwise multiply */
typedef void (*ama_dilithium_pointwise_fn)(int32_t r[256],
                                           const int32_t a[256],
                                           const int32_t b[256]);

/** Dilithium rejection-uniform sampler: consumes a SHAKE128 byte stream,
 * writes up to `outlen` accepted 23-bit coefficients < q into `out`, and
 * returns the number of accepted samples.  Byte-identical to the
 * 3-byte-at-a-time scalar loop; the AVX2 variant batches 8 candidates
 * per 24-byte chunk. */
typedef int (*ama_dilithium_rej_uniform_fn)(int32_t *out, size_t outlen,
                                             const uint8_t *buf, size_t buflen);

/** AES-256-GCM encrypt (AVX2/AES-NI accelerated) */
typedef void (*ama_aes_gcm_encrypt_fn)(const uint8_t *plaintext, size_t plaintext_len,
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t key[32], const uint8_t nonce[12],
                                        uint8_t *ciphertext, uint8_t tag[16]);

/** AES-256-GCM decrypt (AVX2/AES-NI accelerated) */
typedef ama_error_t (*ama_aes_gcm_decrypt_fn)(const uint8_t *ciphertext, size_t ciphertext_len,
                                               const uint8_t *aad, size_t aad_len,
                                               const uint8_t key[32], const uint8_t nonce[12],
                                               const uint8_t tag[16], uint8_t *plaintext);

/** ChaCha20 8-way block function: emits 8 * 64 = 512 bytes of keystream
 * for blocks [counter, counter+7]. Byte-identical to scalar chacha20_block
 * on little-endian hosts (x86-64 is always LE). */
typedef void (*ama_chacha20_block_x8_fn)(const uint8_t key[32],
                                          const uint8_t nonce[12],
                                          uint32_t counter,
                                          uint8_t out[512]);

/** Argon2 G compression on a 1024-byte block (128 uint64_t).
 * out = R XOR Z where R = X XOR Y and Z = P-permutation(R).
 * Must be byte-identical to the scalar argon2_G (RFC 9106 Section 3.5). */
typedef void (*ama_argon2_g_fn)(uint64_t out[128],
                                const uint64_t x[128],
                                const uint64_t y[128]);

/** X25519 4-way Montgomery ladder.  Computes four independent
 *  scalarmult(scalar[k], point[k]) -> out[k] in parallel.  Each
 *  scalar is clamped per RFC 7748 §5 inside the kernel.  Output is
 *  byte-identical to four sequential calls of the scalar single-shot
 *  ladder (verified across both fe51 and fe64 paths by
 *  tests/c/test_x25519.c).  Wired only when AVX2 is detected AND
 *  `AMA_DISPATCH_USE_X25519_AVX2=1` is explicitly set in the
 *  environment (the kernel is opt-in by default — see
 *  `src/c/dispatch/ama_dispatch.c` for the rationale); otherwise the
 *  pointer may remain NULL even on AVX2-capable hosts.  Callers MUST
 *  NULL-check before invoking. */
typedef void (*ama_x25519_scalarmult_x4_fn)(uint8_t out[4][32],
                                             const uint8_t scalar[4][32],
                                             const uint8_t point[4][32]);

/* ============================================================================
 * Dispatch function table (global, set once at init)
 *
 * After ama_dispatch_init(), function pointers are either:
 *   - Non-NULL: points to the optimal implementation (SIMD or generic).
 *     Guaranteed non-NULL: keccak_f1600, keccak_f1600_x4.  The x4
 *     pointer always resolves — either to the AVX2 interleaved
 *     kernel or to ama_keccak_f1600_x4_generic, which invokes the
 *     single-state keccak four times.
 *     Wired when SIMD detected: sha3_256, kyber_ntt, kyber_invntt,
 *     kyber_pointwise, dilithium_ntt, dilithium_invntt,
 *     dilithium_pointwise (AVX2 and NEON; SVE2 wires keccak_f1600,
 *     kyber_*, and dilithium_* but not sha3_256).  kyber_cbd2 is
 *     AVX2-only today — it remains NULL on NEON and SVE2 tiers
 *     until a corresponding implementation is wired.
 *   - NULL: no dispatch available; caller must use its own inline generic
 *     implementation.
 *
 * Callers MUST NULL-check before calling any field except keccak_f1600
 * and keccak_f1600_x4 (both always non-NULL after init).
 * ============================================================================ */

typedef struct {
    ama_keccak_f1600_fn       keccak_f1600;        /**< Always non-NULL after init */
    ama_keccak_f1600_x4_fn    keccak_f1600_x4;     /**< Always non-NULL after init; 4-way batched permutation */
    ama_sha3_256_fn           sha3_256;             /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_ntt_fn          kyber_ntt;            /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_ntt_fn          kyber_invntt;         /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_pointwise_fn    kyber_pointwise;      /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_cbd2_fn         kyber_cbd2;           /**< Non-NULL when AVX2 detected (AVX2-only today; NEON/SVE2 wiring TBD); callers MUST NULL-check */
    ama_dilithium_ntt_fn      dilithium_ntt;        /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_dilithium_invntt_fn   dilithium_invntt;     /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_dilithium_pointwise_fn dilithium_pointwise; /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_dilithium_rej_uniform_fn dilithium_rej_uniform; /**< Non-NULL when AVX2 detected; callers MUST NULL-check */
    ama_aes_gcm_encrypt_fn    aes_gcm_encrypt;       /**< Non-NULL when AES-NI+PCLMULQDQ detected; callers MUST NULL-check */
    ama_aes_gcm_decrypt_fn    aes_gcm_decrypt;       /**< Non-NULL when AES-NI+PCLMULQDQ detected; callers MUST NULL-check */
    ama_chacha20_block_x8_fn  chacha20_block_x8;     /**< Non-NULL when AVX2 ChaCha20 detected; emits 8 blocks / 512 B */
    ama_argon2_g_fn           argon2_g;              /**< Non-NULL when AVX2 Argon2 G detected; 1024 B compression */
    ama_x25519_scalarmult_x4_fn x25519_x4;           /**< Non-NULL when AVX2 X25519 4-way ladder detected; callers MUST NULL-check */
    /* --- Appended slots (ABI rule: append-only at the end of this
     *     struct).  ama_dispatch.h is installed as a PUBLIC_HEADER, so
     *     inserting fields in the middle would shift every later
     *     field's offset and break any consumer compiled against an
     *     older header.  New slots go here. ------------------------ */
    ama_kyber_poly_add_fn     kyber_poly_add;       /**< Appended 2026-05 (SVE2 wiring PR).  Non-NULL when SVE2 detected (today: SVE2 only — AVX2/NEON paths let the compiler auto-vectorise the trivial int16 add loop); callers MUST NULL-check */
    ama_kyber_poly_sub_fn     kyber_poly_sub;       /**< Appended 2026-05.  Non-NULL when SVE2 detected (today: SVE2 only — see kyber_poly_add); callers MUST NULL-check */
    ama_kyber_poly_reduce_fn  kyber_poly_reduce;    /**< Appended 2026-05.  Non-NULL when SVE2 detected (today: SVE2 only — see kyber_poly_add); callers MUST NULL-check */
} ama_dispatch_table_t;

/* ============================================================================
 * Public API
 * ============================================================================ */

/** Initialize dispatch (thread-safe, idempotent). */
AMA_API void ama_dispatch_init(void);

/** Get dispatch info (detection results). */
AMA_API const ama_dispatch_info_t *ama_get_dispatch_info(void);

/** Get the dispatch function table. Calls ama_dispatch_init() if needed. */
AMA_API const ama_dispatch_table_t *ama_get_dispatch_table(void);

/** Print dispatch info to stderr (diagnostics). */
AMA_API void ama_print_dispatch_info(void);

/** Implementation level name string. */
AMA_API const char *ama_impl_level_name(ama_impl_level_t level);

/* ============================================================================
 * AES-GCM backend introspection (audit Issue 5 / INVARIANT-20)
 * ============================================================================
 *
 * Identifies which AES-GCM kernel the runtime dispatcher actually
 * selected on the current host.  Returned strings are constant and
 * NUL-terminated.  Consumers (downstream packagers, integration
 * tests, hardening verifiers) can assert at startup that they did
 * not end up on a cache-timing-unsafe path.
 *
 * Possible values:
 *   "aes-ni-pclmul"        — x86-64 AES-NI + PCLMULQDQ (CT by HW spec)
 *   "vaes-avx2"            — x86-64 VAES + VPCLMULQDQ (CT by HW spec)
 *   "arm-aes-pmull"        — ARMv8 crypto extension AES + PMULL (CT by HW spec)
 *   "bitsliced-software"   — algebraic constant-time S-box (cache-timing safe)
 *   "table-insecure"       — table-lookup S-box (NOT cache-timing safe;
 *                            only present when the build was explicitly
 *                            opted in via -DAMA_AES_TABLE_INSECURE=ON)
 *
 * A "table-insecure" return is the audit-trail evidence that the
 * deployment is running on a host with no hardware AES support AND
 * was built without the bitsliced fallback.  Callers should refuse
 * to proceed in shared-tenant deployments under that condition.
 */
AMA_API const char *ama_aes_gcm_active_backend(void);

/* ============================================================================
 * Cross-process auto-tune cache (opt-in)
 * ============================================================================
 *
 * `AMA_DISPATCH_CACHE_FILE=<path>` — when set in the environment before
 * the first `ama_dispatch_init()` call, the per-slot auto-tune
 * microbench writes its regressed/kept verdict for each SIMD slot to
 * <path>, and subsequent processes with the same env var (and matching
 * CPU-feature fingerprint) skip the microbench entirely and apply the
 * cached verdict.  Removes the ~10K-Keccak-iteration startup latency
 * on warm hosts without sacrificing the per-host accuracy of the
 * regression heuristic.
 *
 * Cache key — a deterministic string built from `arch_name` plus the
 * runtime CPU-feature probe results (`avx2`, `avx512f`,
 * `avx512_keccak_bundle`, `aes_ni`, `pclmulqdq`, `vaes_aesgcm_bundle`,
 * `arm_aes`, `arm_pmull`).  A kernel upgrade or microcode change that
 * shifts any flag invalidates the cache automatically — no manual
 * flush.  Mismatched fingerprints are treated as a cache miss; the
 * bench runs and rewrites the file.
 *
 * Default (env unset) — no file I/O on this code path, strictly opt-in.
 * Distribution packagers can ship a pre-warmed cache in /etc or under
 * `$XDG_CACHE_HOME/ama-cryptography/` and have downstream processes
 * pick it up by exporting `AMA_DISPATCH_CACHE_FILE` in their service
 * wrappers.  See `src/c/dispatch/ama_dispatch.c::dispatch_cache_save`
 * for the (text, one key=value per line) file format and forward-
 * compatibility behaviour.
 *
 * The cache is bypassed when `AMA_DISPATCH_NO_AUTOTUNE=1` is set — the
 * opt-out env var takes precedence and the bench is skipped without
 * any cache read or write.
 */

/* ============================================================================
 * Per-slot dispatch isolation (audit Issue 3 close-out / INVARIANT-12)
 * ============================================================================
 *
 * `AMA_DISPATCH_ONLY=<slot>` (read at `ama_dispatch_init()` time) leaves
 * every dispatch kernel pointer at its scalar fallback EXCEPT the named
 * slot, which is forced active if and only if the host supports it.
 * Lets the dudect SIMD sweep attribute a per-slot t-value to a single
 * kernel without interference from the rest of the dispatch table.
 *
 * Recognised slot names (must match the CHANGELOG inventory verbatim):
 *
 *   "sha3-avx512x4"        — keccak_f1600_x4 -> AVX-512 (vprolq + vpternlogq)
 *   "kyber-ntt-avx2"       — kyber_ntt / invntt / pointwise / cbd2 -> AVX2
 *   "dilithium-ntt-avx2"   — dilithium_ntt / invntt / pointwise / rej_uniform -> AVX2
 *   "chacha20-avx2x8"      — chacha20_block_x8 -> AVX2 8-way
 *   "argon2-g-avx2"        — argon2_g -> AVX2 BlaMka
 *   "aes-gcm-neon"         — aes_gcm_encrypt / decrypt -> ARMv8 AES + PMULL
 *   "chacha20-neon"        — chacha20_block_x8 -> NEON
 *   "sha3-neon"            — keccak_f1600 / sha3_256 -> NEON
 *   "kyber-sve2"           — kyber_ntt / invntt / pointwise / poly_{add,sub,reduce} -> SVE2
 *   "sha3-sve2"            — keccak_f1600 / sha3_256 -> SVE2
 *   "x25519-avx2"          — x25519_x4 -> AVX2 4-way ladder
 *                            (requires AMA_DISPATCH_USE_X25519_AVX2=1 also set)
 *
 * `ama_dispatch_active_slot()` returns the resolved slot label on a
 * host that honored `AMA_DISPATCH_ONLY`, or the literal string
 * `"all-default-dispatch"` on a host where `AMA_DISPATCH_ONLY` was
 * unset OR set to a slot the host could not satisfy.  The returned
 * pointer is a string literal with static storage duration; do not
 * free it.
 *
 * A failing `AMA_DISPATCH_ONLY` request emits exactly one
 * unconditional `[AMA Dispatch] ERROR:` line on stderr (NOT gated
 * on `AMA_DISPATCH_VERBOSE`) and leaves every kernel pointer at
 * scalar fallback.  Two distinct error messages cover the two
 * failure modes:
 *
 *   UNRECOGNISED — the slot name is not in the inventory above.
 *                  The error line enumerates the known slot names
 *                  so an operator who fat-fingered the env var
 *                  sees the right spelling.
 *   UNSUPPORTED  — the slot name is known, but the host's CPU does
 *                  not satisfy it (or the build did not compile
 *                  the kernel).  The error line names the slot
 *                  and the cause class.
 *
 * `ama_dispatch_active_slot()` reports the `"all-default-dispatch"`
 * sentinel in either case, which the dudect test harness in
 * `tests/c/test_dispatch_only_env.c` interprets as a CTest skip
 * (exit code 77).
 */
AMA_API const char *ama_dispatch_active_slot(void);

#ifdef __cplusplus
}
#endif

#endif /* AMA_DISPATCH_H */
