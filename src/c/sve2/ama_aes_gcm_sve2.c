/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_aes_gcm_sve2.c
 * @brief ARM SVE2 AES-GCM — placeholder for future integration
 *
 * SVE2 does not provide AES instructions directly; those come from the
 * ARMv8 Crypto Extensions (FEAT_AES / FEAT_PMULL). AES-GCM on AArch64
 * is handled by the NEON path (ama_aes_gcm_neon.c) which uses AES/PMULL
 * intrinsics directly.
 *
 * This file is intentionally empty. SVE2 cannot accelerate AES rounds
 * (no SVE2 AES instructions exist), and GHASH acceleration via PMULL
 * is already provided by the NEON backend. A future SVE2 contribution
 * would need to provide a full encrypt/decrypt implementation wired
 * into the dispatch table — not standalone helper functions.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

/* Compiled only when AMA_ENABLE_SVE2=ON on AArch64.
 * No symbols exported — AES-GCM dispatch uses NEON or generic. */
typedef int ama_aes_gcm_sve2_reserved;
