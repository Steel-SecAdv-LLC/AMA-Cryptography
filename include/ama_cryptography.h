/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_cryptography.h
 * @brief AMA Cryptography - Core C API for Post-Quantum Cryptography
 * @version 3.1.0
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-25
 *
 * High-performance C implementation of quantum-resistant cryptographic primitives.
 */

#ifndef AMA_CRYPTOGRAPHY_H
#define AMA_CRYPTOGRAPHY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* DLL export/import macro for Windows.
 *
 * When compiling the library itself (shared or static), AMA_API is either
 * __declspec(dllexport) or empty.  Only external consumers of the shared
 * DLL get __declspec(dllimport). */
#if defined(_WIN32) || defined(_WIN64)
  #ifdef AMA_BUILDING_SHARED
    #define AMA_API __declspec(dllexport)
  #elif defined(AMA_BUILDING_STATIC) || defined(AMA_TESTING_MODE)
    #define AMA_API  /* static library or test build — no dllimport */
  #else
    #define AMA_API __declspec(dllimport)
  #endif
#else
  #define AMA_API
#endif

/* ============================================================================
 * VERSION INFORMATION
 * ============================================================================ */

#define AMA_CRYPTOGRAPHY_VERSION_MAJOR 3
#define AMA_CRYPTOGRAPHY_VERSION_MINOR 1
#define AMA_CRYPTOGRAPHY_VERSION_PATCH 0
#define AMA_CRYPTOGRAPHY_VERSION_STRING "3.1.0"

/* ============================================================================
 * ALGORITHM IDENTIFIERS
 * ============================================================================ */

typedef enum {
    AMA_ALG_ML_DSA_65 = 0,    /**< CRYSTALS-Dilithium (ML-DSA-65) */
    AMA_ALG_KYBER_1024 = 1,   /**< CRYSTALS-Kyber (Kyber-1024) */
    AMA_ALG_SPHINCS_256F = 2, /**< SPHINCS+-256f */
    AMA_ALG_ED25519 = 3,      /**< Ed25519 (classical) */
    AMA_ALG_HYBRID = 4        /**< Hybrid mode (classical + PQC) */
} ama_algorithm_t;

/* ============================================================================
 * ERROR CODES
 * ============================================================================ */

typedef enum {
    AMA_SUCCESS = 0,
    AMA_ERROR_INVALID_PARAM = -1,
    AMA_ERROR_MEMORY = -2,
    AMA_ERROR_CRYPTO = -3,
    AMA_ERROR_VERIFY_FAILED = -4,
    AMA_ERROR_NOT_IMPLEMENTED = -5,
    AMA_ERROR_TIMING_ATTACK = -6,
    AMA_ERROR_SIDE_CHANNEL = -7,
    AMA_ERROR_OVERFLOW = -8
} ama_error_t;

/* ============================================================================
 * KEY SIZES (bytes)
 * ============================================================================ */

/* ML-DSA-65 (Dilithium3) - FIPS 204 */
#define AMA_ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define AMA_ML_DSA_65_SECRET_KEY_BYTES 4032
#define AMA_ML_DSA_65_SIGNATURE_BYTES 3309

/* Kyber-1024 */
#define AMA_KYBER_1024_PUBLIC_KEY_BYTES 1568
#define AMA_KYBER_1024_SECRET_KEY_BYTES 3168
#define AMA_KYBER_1024_CIPHERTEXT_BYTES 1568
#define AMA_KYBER_1024_SHARED_SECRET_BYTES 32

/* SPHINCS+-256f (legacy aliases for SLH-DSA-SHA2-256f-simple) */
#define AMA_SPHINCS_256F_PUBLIC_KEY_BYTES 64
#define AMA_SPHINCS_256F_SECRET_KEY_BYTES 128
#define AMA_SPHINCS_256F_SIGNATURE_BYTES 49856

/* SLH-DSA parameter set sizes (FIPS 205 Table 2) */
#define AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES 64
#define AMA_SLHDSA_SHA2_256F_SECRET_KEY_BYTES 128
#define AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES  49856

#define AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES 32
#define AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES 64
#define AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES  7856

/**
 * @brief FIPS 205 SLH-DSA parameter set selector.
 *
 * Numeric values are stable and form part of the AMA ABI.
 */
typedef enum {
    AMA_SLHDSA_SHA2_256F  = 0,  /**< SLH-DSA-SHA2-256f-simple, NIST L5 */
    AMA_SLHDSA_SHAKE_128S = 1   /**< SLH-DSA-SHAKE-128s,        NIST L1 */
} ama_slhdsa_param_set_t;

/* Ed25519 */
#define AMA_ED25519_PUBLIC_KEY_BYTES 32
#define AMA_ED25519_SECRET_KEY_BYTES 64
#define AMA_ED25519_SIGNATURE_BYTES 64

/* ============================================================================
 * OPAQUE TYPES
 * ============================================================================ */

typedef struct ama_context_t ama_context_t;
typedef struct ama_keypair_t ama_keypair_t;
typedef struct ama_signature_t ama_signature_t;

/* ============================================================================
 * CONTEXT MANAGEMENT
 * ============================================================================ */

/**
 * @brief Initialize AMA Cryptography context
 * @param algorithm Algorithm to use
 * @return Opaque context pointer, NULL on failure
 */
AMA_API ama_context_t* ama_context_init(ama_algorithm_t algorithm);

/**
 * @brief Free AMA Cryptography context and scrub memory
 * @param ctx Context to free
 */
AMA_API void ama_context_free(ama_context_t* ctx);

/* ============================================================================
 * KEY GENERATION
 * ============================================================================ */

/**
 * @brief Generate a new keypair (constant-time)
 *
 * Generates a cryptographic keypair for the algorithm specified in the context.
 * Supports ML-DSA-65, Kyber-1024, SPHINCS+-256f, Ed25519, and hybrid modes.
 * All algorithms use native implementations (no external PQC dependencies).
 *
 * @param ctx Initialized context
 * @param public_key Output buffer for public key
 * @param public_key_len Length of public key buffer
 * @param secret_key Output buffer for secret key
 * @param secret_key_len Length of secret key buffer
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_keypair_generate(
    ama_context_t* ctx,
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
);

/* ============================================================================
 * SIGNATURE OPERATIONS
 * ============================================================================ */

/**
 * @brief Sign a message (constant-time)
 *
 * Signs a message using the algorithm specified in the context.
 * Supports ML-DSA-65, SPHINCS+-256f, and Ed25519 natively.
 *
 * @param ctx Initialized context
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Secret key
 * @param secret_key_len Length of secret key
 * @param signature Output buffer for signature
 * @param signature_len Pointer to signature length (in/out)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sign(
    ama_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* signature,
    size_t* signature_len
);

/**
 * @brief Verify a signature (constant-time)
 *
 * Verifies a signature using the algorithm specified in the context.
 * Supports ML-DSA-65, SPHINCS+-256f, and Ed25519 natively.
 *
 * @param ctx Initialized context
 * @param message Message to verify
 * @param message_len Length of message
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param public_key Public key
 * @param public_key_len Length of public key
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_verify(
    ama_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
);

/* ============================================================================
 * KEY ENCAPSULATION (Kyber-1024)
 * ============================================================================ */

/**
 * @brief Encapsulate a shared secret
 *
 * Performs KEM encapsulation using Kyber-1024 (ML-KEM-1024).
 * Generates a random shared secret and ciphertext using the recipient's public key.
 * Uses native implementation (FIPS 203 compliant).
 *
 * @param ctx Initialized context (must be Kyber-1024)
 * @param public_key Recipient's public key
 * @param public_key_len Length of public key
 * @param ciphertext Output buffer for ciphertext
 * @param ciphertext_len Pointer to ciphertext length (in/out)
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Length of shared secret buffer
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kem_encapsulate(
    ama_context_t* ctx,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
);

/**
 * @brief Decapsulate a shared secret
 *
 * Performs KEM decapsulation using Kyber-1024 (ML-KEM-1024).
 * Recovers the shared secret from ciphertext using the recipient's secret key.
 * Uses implicit rejection for IND-CCA2 security (FIPS 203 compliant).
 *
 * @param ctx Initialized context (must be Kyber-1024)
 * @param ciphertext Ciphertext to decapsulate
 * @param ciphertext_len Length of ciphertext
 * @param secret_key Recipient's secret key
 * @param secret_key_len Length of secret key
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Length of shared secret buffer
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kem_decapsulate(
    ama_context_t* ctx,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
);

/* ============================================================================
 * CONSTANT-TIME UTILITIES
 * ============================================================================ */

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise (timing-safe)
 */
AMA_API int ama_consttime_memcmp(const void* a, const void* b, size_t len);

/**
 * @brief Secure memory scrubbing
 * @param ptr Memory to scrub
 * @param len Length to scrub
 */
AMA_API void ama_secure_memzero(void* ptr, size_t len);

/**
 * @brief Lock memory pages to prevent swapping to disk.
 * @param ptr Pointer to memory region
 * @param len Length of memory region
 * @return AMA_SUCCESS or AMA_ERROR_MEMORY
 */
AMA_API ama_error_t ama_secure_mlock(void* ptr, size_t len);

/**
 * @brief Unlock previously locked memory pages.
 * @param ptr Pointer to memory region
 * @param len Length of memory region
 * @return AMA_SUCCESS or AMA_ERROR_MEMORY
 */
AMA_API ama_error_t ama_secure_munlock(void* ptr, size_t len);

/**
 * @brief Allocate a secure buffer with mlock and DONTDUMP.
 * @param size Number of bytes to allocate
 * @return Pointer to locked, zeroed memory, or NULL on failure
 */
AMA_API void* ama_secure_alloc(size_t size);

/**
 * @brief Free a secure buffer with guaranteed zeroization and munlock.
 * @param ptr Pointer from ama_secure_alloc
 * @param size Size of the allocation
 */
AMA_API void ama_secure_free(void* ptr, size_t size);

/**
 * @brief Constant-time conditional swap
 * @param condition Swap if non-zero
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to swap
 */
AMA_API void ama_consttime_swap(int condition, void* a, void* b, size_t len);

/**
 * @brief Constant-time table lookup
 * @param table Table to lookup from
 * @param table_len Number of elements in table
 * @param elem_size Size of each element in bytes
 * @param index Index to lookup (may be secret)
 * @param output Output buffer for selected element
 */
AMA_API void ama_consttime_lookup(
    const void* table,
    size_t table_len,
    size_t elem_size,
    size_t index,
    void* output
);

/**
 * @brief Constant-time conditional copy
 * @param condition Copy if non-zero
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Length to copy
 */
AMA_API void ama_consttime_copy(int condition, void* dst, const void* src, size_t len);

/* ============================================================================
 * HASHING AND KEY DERIVATION
 * ============================================================================ */

/**
 * @brief SHA3-256 hash (FIPS 202)
 *
 * Computes the SHA3-256 cryptographic hash of the input data.
 * Uses the Keccak-f[1600] sponge construction with rate 136 and capacity 64.
 *
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer (32 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_256(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief SHA3-512 hash (FIPS 202)
 *
 * Computes the SHA3-512 cryptographic hash of the input data.
 * Uses the Keccak-f[1600] sponge construction with rate 72 and capacity 128.
 * Required by FIPS 203 (ML-KEM) as the G function.
 *
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer (64 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_512(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/* ============================================================================
 * STREAMING SHA3-256 API (init/update/final)
 * Enables hashing of large data streams without loading everything into memory
 * ============================================================================ */

/**
 * @brief SHA3-256 streaming context
 */
typedef struct {
    uint64_t state[25];     /**< Keccak state (1600 bits) */
    uint8_t buffer[168];    /**< Rate buffer (168 bytes max for SHAKE128; 136 for SHA3-256/SHAKE256) */
    size_t buffer_len;      /**< Current bytes in buffer */
    int finalized;          /**< Set to 1 after final() called */
} ama_sha3_ctx;

/**
 * @brief Initialize SHA3-256 streaming context
 *
 * @param ctx Context to initialize
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_init(ama_sha3_ctx* ctx);

/**
 * @brief Update SHA3-256 with additional data
 *
 * Can be called multiple times to process data in chunks.
 *
 * @param ctx Initialized context
 * @param data Data to absorb
 * @param len Length of data in bytes
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_update(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA3-256 and output digest
 *
 * After calling this, the context cannot be used again without re-initializing.
 *
 * @param ctx Context to finalize
 * @param output Output buffer (32 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_final(ama_sha3_ctx* ctx, uint8_t* output);

/* ============================================================================
 * STREAMING SHA3-512 API (init/update/final)
 * Enables incremental hashing of large data streams with SHA3-512
 * Reuses ama_sha3_ctx; rate = 72 bytes fits inside the 168-byte buffer
 * ============================================================================ */

/**
 * @brief Initialize SHA3-512 streaming context
 *
 * @param ctx Context to initialize
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_512_init(ama_sha3_ctx* ctx);

/**
 * @brief Update SHA3-512 with additional data
 *
 * Can be called multiple times to process data in chunks.
 *
 * @param ctx Initialized context
 * @param data Data to absorb
 * @param len Length of data in bytes
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_512_update(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA3-512 and output digest
 *
 * After calling this, the context cannot be used again without re-initializing.
 *
 * @param ctx Context to finalize
 * @param output Output buffer (64 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_512_final(ama_sha3_ctx* ctx, uint8_t* output);

/* ============================================================================
 * STREAMING SHAKE256 API (init/absorb/finalize/squeeze)
 * Enables incremental absorb and multi-block squeeze for SHAKE256 (XOF)
 * Reuses ama_sha3_ctx since SHAKE256 rate = 136 = SHA3-256 rate
 * ============================================================================ */

/**
 * @brief Initialize SHAKE256 incremental context
 */
AMA_API ama_error_t ama_shake256_inc_init(ama_sha3_ctx* ctx);

/**
 * @brief Absorb data into SHAKE256 incremental context
 */
AMA_API ama_error_t ama_shake256_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHAKE256 absorption (apply padding). Must be called before squeeze.
 */
AMA_API ama_error_t ama_shake256_inc_finalize(ama_sha3_ctx* ctx);

/**
 * @brief Squeeze output bytes from finalized SHAKE256 context. Can be called multiple times.
 */
AMA_API ama_error_t ama_shake256_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);

/* ============================================================================
 * STREAMING SHAKE128 API (init/absorb/finalize/squeeze)
 * Enables incremental absorb and multi-block squeeze for SHAKE128 (XOF)
 * SHAKE128 rate = 168 bytes
 * ============================================================================ */

/**
 * @brief Initialize SHAKE128 incremental context
 */
AMA_API ama_error_t ama_shake128_inc_init(ama_sha3_ctx* ctx);

/**
 * @brief Absorb data into SHAKE128 incremental context
 */
AMA_API ama_error_t ama_shake128_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize SHAKE128 absorption (apply padding). Must be called before squeeze.
 */
AMA_API ama_error_t ama_shake128_inc_finalize(ama_sha3_ctx* ctx);

/**
 * @brief Squeeze output bytes from finalized SHAKE128 context. Can be called multiple times.
 */
AMA_API ama_error_t ama_shake128_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);

/**
 * @brief HMAC-SHA3-256 per RFC 2104 using AMA's native SHA3-256 implementation.
 *
 * @param key       Pointer to key bytes
 * @param key_len   Key length in bytes (any length; keys >136 bytes are hashed)
 * @param msg       Pointer to message bytes
 * @param msg_len   Message length in bytes
 * @param out       Output buffer, must be at least 32 bytes
 * @return          AMA_SUCCESS on success, AMA_ERROR_MEMORY on allocation failure
 *
 * INVARIANT-1 compliant: uses only ama_sha3.c — zero external crypto dependencies.
 * Constant-time: output comparison must use ama_consttime_memcmp, not memcmp.
 */
AMA_API ama_error_t ama_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]
);

/**
 * @brief HMAC-SHA-512 (RFC 2104)
 *
 * Computes HMAC using SHA-512 for BIP32 key derivation and general-purpose
 * keyed authentication.
 *
 * @param key       HMAC key
 * @param key_len   Length of key in bytes
 * @param msg       Message to authenticate
 * @param msg_len   Length of message in bytes
 * @param out       Output buffer (must be at least 64 bytes)
 * @return          AMA_SUCCESS on success, AMA_ERROR_INVALID_PARAM if key or out
 *                  is NULL (or msg is NULL with msg_len > 0),
 *                  AMA_ERROR_MEMORY on allocation failure
 *
 * INVARIANT-1 compliant: uses only ama_sha2.h — zero external crypto dependencies.
 */
AMA_API ama_error_t ama_hmac_sha512(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[64]
);

/**
 * @brief HKDF key derivation (RFC 5869)
 *
 * Derives key material using HKDF with HMAC-SHA3-256.
 * Implements Extract-then-Expand paradigm for secure key derivation.
 * Maximum output length: 255 * 32 = 8160 bytes.
 *
 * @param salt Salt value (can be NULL for zero-length salt)
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of IKM
 * @param info Context information (can be NULL)
 * @param info_len Length of info
 * @param okm Output key material
 * @param okm_len Desired length of OKM
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_hkdf(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
);

/* ============================================================================
 * ED25519 STANDALONE API
 * ============================================================================ */

/**
 * @brief Generate Ed25519 keypair
 *
 * Generates an Ed25519 keypair. The caller must provide 32 bytes of random
 * seed data in secret_key[0..31] before calling. The function will compute
 * the public key and store it in both public_key and secret_key[32..63].
 *
 * @param public_key Output: 32-byte public key
 * @param secret_key Input/Output: 64-byte buffer (seed in, seed||pk out)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]);

/**
 * @brief Sign a message with Ed25519
 *
 * Creates an Ed25519 signature for a message using the secret key.
 * Implements RFC 8032 Ed25519 (pure EdDSA).
 *
 * @param signature Output: 64-byte signature
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key 64-byte secret key (seed || public_key)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[64]
);

/**
 * @brief Verify an Ed25519 signature
 *
 * Verifies an Ed25519 signature on a message.
 * Implements RFC 8032 Ed25519 verification.
 *
 * @param signature 64-byte signature
 * @param message Message to verify
 * @param message_len Length of message
 * @param public_key 32-byte public key
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
);

/**
 * @brief Entry for Ed25519 batch verification
 *
 * Each entry contains a message, signature, and public key to verify.
 */
typedef struct {
    const uint8_t *message;     /**< Message bytes */
    size_t         message_len; /**< Length of message */
    const uint8_t *signature;   /**< 64-byte Ed25519 signature */
    const uint8_t *public_key;  /**< 32-byte Ed25519 public key */
} ama_ed25519_batch_entry;

/**
 * @brief Batch verify multiple Ed25519 signatures
 *
 * Verifies multiple Ed25519 signatures independently. Each entry's result
 * is written to the results array: 1 if valid, 0 if invalid.
 *
 * This is intentionally non-constant-time (vartime) because verification
 * scalars are public. This is safe and documented.
 *
 * @param entries   Array of batch entries to verify
 * @param count     Number of entries
 * @param results   Output: array of int (1=valid, 0=invalid), must be >= count
 * @return AMA_SUCCESS if all verified, AMA_ERROR_VERIFY_FAILED if any failed,
 *         AMA_ERROR_INVALID_PARAM if entries or results is NULL
 */
AMA_API ama_error_t ama_ed25519_batch_verify(
    const ama_ed25519_batch_entry *entries,
    size_t count,
    int *results
);

/* ----------------------------------------------------------------------------
 * Ed25519 Group Primitives (for FROST / Threshold Signatures)
 * ---------------------------------------------------------------------------- */

/** Raw scalar-basepoint multiply: point = scalar * G (no hash/clamp). */
AMA_API void ama_ed25519_point_from_scalar(uint8_t point[32], const uint8_t scalar[32]);

/** Point addition: result = P + Q (compressed Ed25519 points). */
AMA_API ama_error_t ama_ed25519_point_add(uint8_t result[32],
    const uint8_t p[32], const uint8_t q[32]);

/**
 * Variable-time scalar-point multiplication: result = public_scalar * P.
 *
 * SECURITY: This function is NOT constant-time.  The scalar MUST be
 * PUBLIC data (e.g., FROST binding factors, verification challenges).
 * Using a secret scalar leaks it via timing side-channels.
 *
 * For secret-scalar × basepoint, use ama_ed25519_point_from_scalar().
 *
 * Renamed from ama_ed25519_scalar_mult (audit finding C7) to make the
 * public-only constraint impossible to miss.
 */
AMA_API ama_error_t ama_ed25519_scalarmult_public(uint8_t result[32],
    const uint8_t public_scalar[32], const uint8_t point[32]);

/* Backwards-compatible macro — deprecated, use ama_ed25519_scalarmult_public */
#define ama_ed25519_scalar_mult(r, s, p) ama_ed25519_scalarmult_public((r), (s), (p))

/**
 * Joint variable-time double-base scalar multiplication:
 *   result = [s1]P1 + [s2]P2  (one interleaved Shamir/Straus pass).
 *
 * SECURITY: NOT constant-time — both scalars MUST be PUBLIC data
 * (Ed25519 verify, FROST verifier, batch verify).  See the in-tree
 * implementation block comment in src/c/ama_ed25519.c for the full
 * security contract.
 *
 * Exposed as a regression / equivalence-test surface and a
 * micro-benchmark target for tuning the wNAF window default.
 */
AMA_API ama_error_t ama_ed25519_double_scalarmult_public(
    uint8_t result[32],
    const uint8_t s1[32], const uint8_t P1[32],
    const uint8_t s2[32], const uint8_t P2[32]);

/** Reduce 64-byte scalar mod l (Ed25519 group order). Result in s[0..31]. */
AMA_API void ama_ed25519_sc_reduce(uint8_t s[64]);

/** SHA-512 hash (for FROST challenge computation, matching Ed25519 verify). */
AMA_API void ama_ed25519_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/** Scalar multiply-add: s = (a + b * c) mod l. All 32-byte LE scalars. */
AMA_API void ama_ed25519_sc_muladd(uint8_t s[32], const uint8_t a[32],
    const uint8_t b[32], const uint8_t c[32]);

/* ============================================================================
 * FROST THRESHOLD ED25519 SIGNATURES (RFC 9591)
 * ============================================================================ */

#define AMA_FROST_SHARE_BYTES       64  /* 32 secret + 32 public */
#define AMA_FROST_NONCE_BYTES       64  /* 32 hiding + 32 binding */
#define AMA_FROST_COMMITMENT_BYTES  64  /* 32 hiding_point + 32 binding_point */
#define AMA_FROST_SIG_SHARE_BYTES   32
#define AMA_FROST_MAX_PARTICIPANTS  255

/**
 * @brief Trusted dealer key generation via Shamir secret sharing.
 *
 * @param threshold         Minimum signers required (t >= 2)
 * @param num_participants  Total participants (n >= t)
 * @param group_public_key  Output: 32 bytes
 * @param participant_shares Output: n * 64 bytes (secret || public)
 * @param secret_key        Optional input: 32-byte secret (NULL = random)
 */
AMA_API ama_error_t ama_frost_keygen_trusted_dealer(
    uint8_t threshold, uint8_t num_participants,
    uint8_t *group_public_key, uint8_t *participant_shares,
    const uint8_t *secret_key);

/**
 * @brief Round 1: Generate nonce commitment.
 *
 * @param nonce_pair         Output: 64 bytes (SECRET — must be kept until round 2)
 * @param commitment         Output: 64 bytes (PUBLIC — sent to coordinator)
 * @param participant_share  Input:  64-byte participant share
 */
AMA_API ama_error_t ama_frost_round1_commit(
    uint8_t *nonce_pair, uint8_t *commitment,
    const uint8_t *participant_share);

/**
 * @brief Round 2: Generate signature share.
 *
 * @param sig_share          Output: 32 bytes
 * @param message            Message to sign
 * @param message_len        Message length
 * @param participant_share  64-byte participant share
 * @param participant_index  1-based participant index
 * @param nonce_pair         64-byte nonce pair from round 1
 * @param commitments        num_signers * 64 bytes of commitments.
 *                           MUST be ordered to match signer_indices:
 *                           commitments[i*64..(i+1)*64] is the commitment
 *                           from participant signer_indices[i].
 * @param signer_indices     num_signers participant indices (1-based, unique)
 * @param num_signers        Number of signers in this session
 * @param group_public_key   32-byte group public key
 */
AMA_API ama_error_t ama_frost_round2_sign(
    uint8_t *sig_share,
    const uint8_t *message, size_t message_len,
    const uint8_t *participant_share, uint8_t participant_index,
    const uint8_t *nonce_pair,
    const uint8_t *commitments, const uint8_t *signer_indices,
    uint8_t num_signers, const uint8_t *group_public_key);

/**
 * @brief Aggregate signature shares into a standard Ed25519 signature.
 *
 * @param signature         Output: 64-byte Ed25519-compatible signature
 * @param sig_shares        num_signers * 32 bytes
 * @param commitments       num_signers * 64 bytes
 * @param signer_indices    num_signers participant indices (1-based)
 * @param num_signers       Number of signers
 * @param message           Message that was signed
 * @param message_len       Message length
 * @param group_public_key  32-byte group public key
 */
AMA_API ama_error_t ama_frost_aggregate(
    uint8_t *signature,
    const uint8_t *sig_shares, const uint8_t *commitments,
    const uint8_t *signer_indices, uint8_t num_signers,
    const uint8_t *message, size_t message_len,
    const uint8_t *group_public_key);

/* ============================================================================
 * AES-256-GCM AUTHENTICATED ENCRYPTION (NIST SP 800-38D)
 * ============================================================================ */

#define AMA_AES256_KEY_BYTES   32
#define AMA_AES256_GCM_NONCE_BYTES 12
#define AMA_AES256_GCM_TAG_BYTES   16

/**
 * @brief AES-256-GCM authenticated encryption
 *
 * Encrypts plaintext and produces ciphertext + 16-byte authentication tag.
 * Conforms to NIST SP 800-38D.
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte nonce (IV)
 * @param plaintext  Plaintext to encrypt (can be NULL if pt_len == 0)
 * @param pt_len     Length of plaintext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param ciphertext Output: ciphertext (same length as plaintext)
 * @param tag        Output: 16-byte authentication tag
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_aes256_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext,
    size_t pt_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

/**
 * @brief AES-256-GCM authenticated decryption
 *
 * Verifies authentication tag and decrypts ciphertext.
 * Returns AMA_ERROR_VERIFY_FAILED if tag mismatch.
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte nonce (IV)
 * @param ciphertext Ciphertext to decrypt
 * @param ct_len     Length of ciphertext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output: decrypted plaintext (same length as ciphertext)
 * @return AMA_SUCCESS or AMA_ERROR_VERIFY_FAILED
 */
AMA_API ama_error_t ama_aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext,
    size_t ct_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

/* ============================================================================
 * SECP256K1 ELLIPTIC CURVE (BIP32 HD KEY DERIVATION)
 * ============================================================================ */

#define AMA_SECP256K1_PRIVKEY_BYTES  32
#define AMA_SECP256K1_PUBKEY_BYTES   33  /* SEC1 compressed */

/**
 * @brief Scalar multiplication on secp256k1
 *
 * Computes out = scalar * (point_x, point_y) using a constant-time Montgomery ladder.
 *
 * @param scalar    32-byte big-endian scalar
 * @param point_x   32-byte big-endian X coordinate of input point
 * @param point_y   32-byte big-endian Y coordinate of input point
 * @param out_x     Output: 32-byte big-endian X coordinate of result
 * @param out_y     Output: 32-byte big-endian Y coordinate of result
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_secp256k1_point_mul(
    const uint8_t scalar[32],
    const uint8_t point_x[32],
    const uint8_t point_y[32],
    uint8_t out_x[32],
    uint8_t out_y[32]
);

/**
 * @brief Compute compressed SEC1 public key from private key
 *
 * Performs constant-time Montgomery ladder scalar multiplication on secp256k1.
 * Output is 33 bytes: 0x02 or 0x03 prefix + 32-byte X coordinate.
 *
 * @param privkey 32-byte private key (must be in [1, N-1])
 * @param compressed_pubkey Output: 33-byte compressed public key
 * @return AMA_SUCCESS or AMA_ERROR_INVALID_PARAM
 */
AMA_API ama_error_t ama_secp256k1_pubkey_from_privkey(
    const uint8_t privkey[32],
    uint8_t compressed_pubkey[33]
);

/* ============================================================================
 * X25519 KEY EXCHANGE (RFC 7748)
 * ============================================================================ */

#define AMA_X25519_KEY_BYTES 32

/**
 * @brief Generate X25519 keypair
 *
 * Generates a random secret key (clamped per RFC 7748) and computes
 * the corresponding public key via scalar multiplication with base point 9.
 *
 * @param public_key Output: 32-byte public key
 * @param secret_key Output: 32-byte secret key (clamped)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_x25519_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]
);

/**
 * @brief X25519 Diffie-Hellman key exchange
 *
 * Computes shared_secret = X25519(our_secret_key, their_public_key).
 * Returns AMA_ERROR_CRYPTO if result is all-zero (low-order point rejection).
 *
 * @param shared_secret Output: 32-byte shared secret
 * @param our_secret_key Our 32-byte secret key
 * @param their_public_key Their 32-byte public key
 * @return AMA_SUCCESS or AMA_ERROR_CRYPTO
 */
AMA_API ama_error_t ama_x25519_key_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]
);

/**
 * @brief Batched X25519 Diffie-Hellman key exchange.
 *
 * Computes `out[k] = X25519(scalars[k], points[k])` for k in [0, count).
 *
 * On x86-64 hosts where the AVX2 4-way Montgomery-ladder kernel is
 * **opted in** via `AMA_DISPATCH_USE_X25519_AVX2=1`, batches with at
 * least one full 4-lane chunk (N >= 4) dispatch those full chunks to
 * a SIMD path that runs four ladders in parallel; any tail (N % 4)
 * is processed via the scalar single-shot path.  Batches with N of
 * 1, 2, or 3 use the scalar fe64 / fe51 / gf16 path entirely — the
 * batch wrapper never pads short calls up to four lanes.  The 4-way
 * kernel is opt-in because on hosts with the scalar fe64 (MULX/ADX)
 * field path, four sequential scalar ladders are faster than four
 * AVX2 lanes of the donna-32bit ladder; the kernel is provided for
 * the future AVX-512 IFMA port and for CI/test coverage of the SIMD
 * path.  Single-element batches (N == 1) bypass the 4-way kernel
 * entirely so callers do not pay the 3-lane zero-fill cost on the
 * hot path of `ama_x25519_key_exchange`.
 *
 * Output is byte-identical to N sequential `ama_x25519_key_exchange`
 * calls (verified by `tests/c/test_x25519.c` across both code paths).
 *
 * Low-order rejection is aggregated across the batch: if ANY lane's
 * shared secret is all-zero (RFC 7748 §6.1 low-order point), the
 * function returns `AMA_ERROR_CRYPTO` and ALL outputs are zeroed
 * before return — preventing accidental use of a partially-failing
 * batch result.
 *
 * Standards reference: RFC 7748 §5 (clamp + scalar mult) and §6.1
 * (low-order rejection).
 *
 * @param out      Output: count × 32-byte shared-secret slots
 * @param scalars  Input:  count × 32-byte secret keys (pre-clamping)
 * @param points   Input:  count × 32-byte u-coordinates
 * @param count    Number of independent X25519 operations (0 returns AMA_SUCCESS)
 * @return AMA_SUCCESS on success, AMA_ERROR_INVALID_PARAM if any pointer
 *         is NULL with `count > 0`, or AMA_ERROR_CRYPTO on low-order
 *         rejection (with all outputs zeroed).
 */
AMA_API ama_error_t ama_x25519_scalarmult_batch(
    uint8_t out[][32],
    const uint8_t scalars[][32],
    const uint8_t points[][32],
    size_t count
);

/**
 * @brief Return the X25519 field-arithmetic path selected at compile time.
 *
 * Returns one of the string literals "fe64" (radix 2^64, 4 limbs — x86-64
 * GCC/Clang default), "fe51" (radix 2^51, 5 limbs — non-x86-64 64-bit
 * GCC/Clang fallback), or "gf16" (radix 2^16, 16 limbs — MSVC and 32-bit
 * portable fallback). By default the selection is determined by the
 * compiler and target architecture, but builds may also explicitly
 * force the 64-bit or 51-bit field path via `-DAMA_X25519_FORCE_FE64`
 * or `-DAMA_X25519_FORCE_FE51` at compile time (used by
 * `tests/c/test_x25519_field_equiv.c` to compile both paths into one
 * test binary for byte-equivalence checks). The selection is otherwise
 * deterministic and stable for a given toolchain.
 *
 * Used by the path-pinning regression test
 * (`tests/c/test_x25519_path.c`) to assert that a future build-flag
 * change cannot silently regress the compiled-in path.
 */
AMA_API const char *ama_x25519_field_path(void);

/* ============================================================================
 * ARGON2ID KEY DERIVATION (RFC 9106)
 * ============================================================================ */

#define AMA_ARGON2_SALT_BYTES  16
#define AMA_ARGON2_TAG_BYTES   32

/**
 * @brief Upper bound on Argon2id output/tag length accepted by the public API.
 *
 * RFC 9106 §3.2 permits out_len up to 2^32 - 1 bytes, but every real-world
 * deployment uses 16–64 bytes; sizes above ~128 are cryptographically
 * indistinguishable from 64 and only waste compute / memory.  A 1024-byte
 * cap (32× the default tag length) is the application-sane ceiling we
 * enforce at every public entry point to bound worst-case CPU time and
 * prevent a caller-controlled ``tag_len`` from becoming a
 * memory-exhaustion / DoS vector in ``ama_argon2id_legacy_verify`` (which
 * heap-allocates ``computed[tag_len]`` to hold the freshly-derived tag).
 */
#define AMA_ARGON2ID_MAX_TAG_LEN  1024u

/**
 * @brief Argon2id password hashing / key derivation (RFC 9106)
 *
 * Memory-hard KDF with resistance to GPU/ASIC attacks.
 * Single-threaded execution (parallelism affects block layout only).
 *
 * @param password    Password bytes
 * @param pwd_len     Password length
 * @param salt        Salt (16+ bytes recommended)
 * @param salt_len    Salt length
 * @param t_cost      Time cost (iterations, >= 1)
 * @param m_cost      Memory cost in KiB (>= 8 * parallelism)
 * @param parallelism Degree of parallelism (lanes)
 * @param output      Output tag buffer
 * @param out_len     Desired output length (>= 4)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_argon2id(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len
);

/**
 * @brief Argon2id with the pre-2.1.5 buggy ``blake2b_long`` loop termination.
 *
 * Reproduces the non-spec derivation shipped in AMA ≤ 2.1.5. **Do not** use
 * this for new password hashes — it is retained **only** so existing
 * deployments can verify stored hashes during the migration window
 * documented in ``CHANGELOG.md`` [Unreleased] § BREAKING. New derivations
 * must use :c:func:`ama_argon2id`.
 *
 * Typical migration flow:
 *   1. On next successful login, call :c:func:`ama_argon2id_legacy_verify`
 *      with the stored tag.
 *   2. On match, re-derive with :c:func:`ama_argon2id` and overwrite the
 *      stored hash.
 *   3. Retire the legacy path once all active accounts have rotated.
 *
 * Parameters and return codes are identical to :c:func:`ama_argon2id`.
 */
AMA_API ama_error_t ama_argon2id_legacy(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len
);

/**
 * @brief Constant-time verify of a pre-2.1.5 Argon2id tag.
 *
 * Computes the legacy Argon2id derivation for the supplied inputs and
 * compares against @p expected_tag with :c:func:`ama_consttime_memcmp`.
 *
 * @param password      Password bytes
 * @param pwd_len       Password length
 * @param salt          Salt
 * @param salt_len      Salt length
 * @param t_cost        Time cost (iterations)
 * @param m_cost        Memory cost (KiB)
 * @param parallelism   Degree of parallelism
 * @param expected_tag  Stored tag to compare against (pre-2.1.5 format)
 * @param tag_len       Length of expected_tag (>= 4)
 * @return ``AMA_SUCCESS`` on constant-time match,
 *         ``AMA_ERROR_VERIFY_FAILED`` on mismatch, or another error code
 *         on parameter / allocation failure.
 */
AMA_API ama_error_t ama_argon2id_legacy_verify(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const uint8_t *expected_tag, size_t tag_len
);

/* ============================================================================
 * CHACHA20-POLY1305 AEAD (RFC 8439)
 * ============================================================================ */

#define AMA_CHACHA20_KEY_BYTES    32
#define AMA_CHACHA20_NONCE_BYTES  12
#define AMA_POLY1305_TAG_BYTES    16

/**
 * @brief ChaCha20-Poly1305 AEAD encryption (RFC 8439)
 *
 * Encrypts plaintext and produces ciphertext + 16-byte authentication tag.
 *
 * @param key        32-byte key
 * @param nonce      12-byte nonce
 * @param plaintext  Plaintext to encrypt (can be NULL if pt_len == 0)
 * @param pt_len     Length of plaintext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param ciphertext Output: ciphertext (same length as plaintext)
 * @param tag        Output: 16-byte authentication tag
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

/**
 * @brief ChaCha20-Poly1305 AEAD decryption (RFC 8439)
 *
 * Verifies tag and decrypts. Fail-closed: zeros plaintext on tag mismatch.
 *
 * @param key        32-byte key
 * @param nonce      12-byte nonce
 * @param ciphertext Ciphertext to decrypt
 * @param ct_len     Length of ciphertext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output: decrypted plaintext (same length as ciphertext)
 * @return AMA_SUCCESS or AMA_ERROR_VERIFY_FAILED
 */
AMA_API ama_error_t ama_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

/* ============================================================================
 * DIRECT PQC ALGORITHM ACCESS
 * ============================================================================ */

/**
 * @brief Generate ML-DSA-65 (Dilithium) keypair
 *
 * @param public_key Output: public key (1952 bytes)
 * @param secret_key Output: secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair(
    uint8_t *public_key, uint8_t *secret_key
);

/**
 * @brief Sign message with ML-DSA-65 (Dilithium)
 *
 * @param signature     Output: signature buffer
 * @param signature_len Output: actual signature length
 * @param message       Message to sign
 * @param message_len   Length of message
 * @param secret_key    Secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key
);

/**
 * @brief Sign message with ML-DSA-65 (Dilithium) using FIPS 204 §5.2 binding context
 *
 * Applies domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * before delegating to ama_dilithium_sign(). This is the symmetric
 * counterpart of ama_dilithium_verify_ctx() — identical wrapper, so
 * sign/verify round-trip with the same ctx always succeeds.
 *
 * Per FIPS 204 §5.2 line 4, ctx_len > 255 is rejected with a non-zero error.
 *
 * @param signature     Output: signature buffer
 * @param signature_len Output: actual signature length (in/out)
 * @param message       Raw message to sign
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes)
 * @param ctx_len       Length of context (must be <= 255)
 * @param secret_key    Secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_sign_ctx(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *secret_key
);

/**
 * @brief Verify ML-DSA-65 (Dilithium) signature
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param signature     Signature to verify
 * @param signature_len Length of signature
 * @param public_key    Public key (1952 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_dilithium_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/**
 * @brief Verify ML-DSA-65 signature with context (FIPS 204 external/pure)
 *
 * Applies domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * before delegating to ama_dilithium_verify().
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes)
 * @param ctx_len       Length of context (must be <= 255)
 * @param signature     Signature to verify (3309 bytes)
 * @param signature_len Length of signature
 * @param public_key    Public key (1952 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_dilithium_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/**
 * @brief Generate Kyber-1024 keypair
 *
 * @param pk     Output: public key buffer
 * @param pk_len Public key buffer length
 * @param sk     Output: secret key buffer
 * @param sk_len Secret key buffer length
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_keypair(
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
);

/**
 * @brief Kyber-1024 key encapsulation
 *
 * @param pk     Public key
 * @param pk_len Public key length
 * @param ct     Output: ciphertext buffer
 * @param ct_len Output: ciphertext length
 * @param ss     Output: shared secret buffer
 * @param ss_len Shared secret buffer length
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_encapsulate(
    const uint8_t *pk, size_t pk_len,
    uint8_t *ct, size_t *ct_len,
    uint8_t *ss, size_t ss_len
);

/**
 * @brief Kyber-1024 key decapsulation
 *
 * @param ct     Ciphertext
 * @param ct_len Ciphertext length
 * @param sk     Secret key
 * @param sk_len Secret key length
 * @param ss     Output: shared secret buffer
 * @param ss_len Shared secret buffer length
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_decapsulate(
    const uint8_t *ct, size_t ct_len,
    const uint8_t *sk, size_t sk_len,
    uint8_t *ss, size_t ss_len
);

/**
 * @brief Generate SPHINCS+-256f keypair
 *
 * @param public_key Output: public key (64 bytes)
 * @param secret_key Output: secret key (128 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sphincs_keypair(
    uint8_t *public_key, uint8_t *secret_key
);

/**
 * @brief Sign message with SPHINCS+-256f
 *
 * @param signature     Output: signature buffer
 * @param signature_len Output: actual signature length
 * @param message       Message to sign
 * @param message_len   Length of message
 * @param secret_key    Secret key (128 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sphincs_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key
);

/**
 * @brief Verify SPHINCS+-256f signature
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param signature     Signature to verify
 * @param signature_len Length of signature
 * @param public_key    Public key (64 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_sphincs_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/**
 * @brief Verify SPHINCS+-256f signature with context (FIPS 205 external/pure)
 *
 * Applies domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * before delegating to ama_sphincs_verify().
 *
 * @param message       Message to verify
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes)
 * @param ctx_len       Length of context (must be <= 255)
 * @param signature     Signature to verify (49856 bytes)
 * @param signature_len Length of signature
 * @param public_key    Public key (64 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_sphincs_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key
);

/* ============================================================================
 * SLH-DSA (FIPS 205) — parameter-driven public API
 *
 * Supports SLH-DSA-SHA2-256f-simple (AMA_SLHDSA_SHA2_256F, NIST L5) and
 * SLH-DSA-SHAKE-128s (AMA_SLHDSA_SHAKE_128S, NIST L1). The legacy
 * ama_sphincs_* surface above is preserved as a thin wrapper around the
 * SHA2-256f variant; new code should use ama_slhdsa_*.
 * ============================================================================ */

/**
 * @brief Generate an SLH-DSA keypair.
 *
 * @param ps  Parameter set selector.
 * @param pk  Output buffer of `2n` bytes (32 for SHAKE-128s, 64 for SHA2-256f).
 * @param sk  Output buffer of `4n` bytes (64 for SHAKE-128s, 128 for SHA2-256f).
 * @return AMA_SUCCESS or error code.
 */
AMA_API ama_error_t ama_slhdsa_keygen(ama_slhdsa_param_set_t ps,
                                      uint8_t *pk, uint8_t *sk);

/**
 * @brief Deterministic SLH-DSA keypair from explicit (sk_seed, sk_prf, pk_seed).
 *
 * Exposed for KAT validation and re-seeding flows; bypasses RNG.
 * Each seed is `n` bytes (16 for SHAKE-128s, 32 for SHA2-256f).
 */
AMA_API ama_error_t ama_slhdsa_keygen_from_seed(ama_slhdsa_param_set_t ps,
                                                const uint8_t *sk_seed,
                                                const uint8_t *sk_prf,
                                                const uint8_t *pk_seed,
                                                uint8_t *pk, uint8_t *sk);

/**
 * @brief SLH-DSA signing with FIPS 205 §10.2 external/pure context wrapper.
 *
 * Applies M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M and signs M' with
 * a fresh randomizer (hedged variant). Pass `ctx = NULL`, `ctx_len = 0` for
 * the empty-context form. Rejects `ctx_len > 255`.
 *
 * @param ps             Parameter set selector.
 * @param signature      Output buffer of at least `sig_bytes`.
 * @param signature_len  In: capacity; Out: bytes written.
 */
AMA_API ama_error_t ama_slhdsa_sign(ama_slhdsa_param_set_t ps,
                                    uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *ctx, size_t ctx_len,
                                    const uint8_t *sk);

/**
 * @brief SLH-DSA verification with FIPS 205 §10.2 external/pure context wrapper.
 */
AMA_API ama_error_t ama_slhdsa_verify(ama_slhdsa_param_set_t ps,
                                      const uint8_t *signature,
                                      size_t signature_len,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *ctx, size_t ctx_len,
                                      const uint8_t *pk);

/**
 * @brief Deterministic SLH-DSA signing (FIPS 205 §10.2, addrnd = PK.seed).
 *
 * Exposed for ACVP byte-exact KAT validation against NIST's deterministic
 * sigGen vectors. Production code should call ama_slhdsa_sign() (hedged).
 */
AMA_API ama_error_t ama_slhdsa_sign_deterministic(ama_slhdsa_param_set_t ps,
                                                  uint8_t *signature,
                                                  size_t *signature_len,
                                                  const uint8_t *message,
                                                  size_t message_len,
                                                  const uint8_t *ctx,
                                                  size_t ctx_len,
                                                  const uint8_t *sk);

/**
 * @brief SLH-DSA "internal interface" signing with explicit `addrnd`.
 *
 * Skips the §10.2 context wrapper and signs `message` directly. Exposed for
 * ACVP `signatureInterface == "internal"` KAT validation.
 */
AMA_API ama_error_t ama_slhdsa_sign_internal(ama_slhdsa_param_set_t ps,
                                             uint8_t *signature,
                                             size_t *signature_len,
                                             const uint8_t *message,
                                             size_t message_len,
                                             const uint8_t *addrnd,
                                             const uint8_t *sk);

/* ============================================================================
 * DETERMINISTIC KEYGEN FROM SEED (KAT TESTING)
 * ============================================================================ */

/**
 * @brief Deterministic Kyber-1024 keypair from seed
 *
 * Generates keypair from provided seeds, bypassing RNG.
 * Used for NIST KAT validation.
 *
 * @param d   32-byte seed for key generation
 * @param z   32-byte seed for implicit rejection
 * @param pk  Output: public key (1568 bytes)
 * @param sk  Output: secret key (3168 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_keypair_from_seed(
    const uint8_t d[32], const uint8_t z[32],
    uint8_t *pk, uint8_t *sk
);

/**
 * @brief Deterministic ML-DSA-65 keypair from seed
 *
 * Generates keypair from provided seed, bypassing RNG.
 * Used for NIST KAT validation.
 *
 * @param xi          32-byte seed
 * @param public_key  Output: public key (1952 bytes)
 * @param secret_key  Output: secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair_from_seed(
    const uint8_t xi[32],
    uint8_t *public_key, uint8_t *secret_key
);

/* ============================================================================
 * CONSTANT-TIME AES S-BOX (bitsliced / algebraic decomposition)
 * ============================================================================ */

/**
 * @brief Constant-time AES S-box substitution
 *
 * Computes the AES SubBytes transformation using algebraic decomposition
 * in GF((2^4)^2) tower field arithmetic. No lookup tables are used —
 * all operations are bitwise, eliminating cache-timing side channels.
 *
 * When AMA_AES_CONSTTIME is defined, the AES-GCM implementation uses
 * this function instead of the standard 256-byte S-box table.
 *
 * @param x Input byte
 * @return S-box output byte
 */
AMA_API uint8_t ama_aes_sbox_consttime(uint8_t x);

/**
 * @brief AES-256 key expansion using constant-time S-box
 */
AMA_API void ama_aes256_key_expansion_consttime(
    const uint8_t key[32], uint8_t round_keys[240]);

/**
 * @brief AES-256 block encryption using constant-time S-box
 */
AMA_API void ama_aes256_encrypt_block_consttime(
    const uint8_t round_keys[240], const uint8_t in[16], uint8_t out[16]);

/* ============================================================================
 * VERSIONING
 * ============================================================================ */

/**
 * @brief Get library version string
 * @return Version string (e.g., "1.0.0")
 */
AMA_API const char* ama_version_string(void);

/**
 * @brief Get library version number
 * @param major Output for major version
 * @param minor Output for minor version
 * @param patch Output for patch version
 */
AMA_API void ama_version_number(int* major, int* minor, int* patch);

#ifdef __cplusplus
}
#endif

#endif /* AMA_CRYPTOGRAPHY_H */
