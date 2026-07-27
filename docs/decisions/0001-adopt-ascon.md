# Decision 0001 — Adopt Ascon-AEAD128 and Ascon-Hash256

**Status:** Accepted
**Date:** 2026-07-27
**Applies to:** `3.4.0`
**Rule invoked:** *Preserve and evolve primitives* — a primitive addition,
replacement, or removal requires a decision log recording the compatibility
impact, security rationale, and measured evidence.
**Supersedes:** the interim position in `docs/AUDIT_DIRECTIVE.md` §3.1, which
recorded Ascon as recommended-but-deferred.

---

## 1. Decision

Add two functions from **NIST SP 800-232** to the shipped primitive set:

| Function | Standard | Parameters |
|---|---|---|
| **Ascon-AEAD128** | SP 800-232 §4, Algorithms 3–4 | 128-bit key, 128-bit nonce, 128-bit tag, rate 128 bits, capacity 192 bits |
| **Ascon-Hash256** | SP 800-232 §5.1, Algorithm 5 | 256-bit digest, rate 64 bits, capacity 256 bits |

**Nothing is replaced or removed.** AES-256-GCM and ChaCha20-Poly1305 remain
the default AEADs, SHA3-256 remains the default hash, and no existing
algorithm, parameter set, dispatch path, or API changes. This is purely
additive.

**Explicitly out of scope:** Ascon-XOF128 and Ascon-CXOF128, specified in the
same document. They share the permutation already added here, so adding them
later is incremental rather than foundational; nothing in the tree needs an XOF
that SHA3/SHAKE does not already serve. Revisit when a caller needs one.

---

## 2. Why — security and standing rationale

**It is a NIST standard, not a candidate.** SP 800-232, *Ascon-Based
Lightweight Cryptography Standards for Constrained Devices*, was finalized
2025-08-13 after the multi-round NIST Lightweight Cryptography process. This
library's entire identity is native implementations of NIST standards —
FIPS 202/203/204/205, SP 800-56C, SP 800-90A — and Ascon is the **only**
NIST-standardized lightweight AEAD. It belongs in `CSRC_STANDARDS.md` on the
same footing as the rest.

**It closes a gap the project had already committed to.** `AUDIT_DIRECTIVE.md`
§5.2 names Cortex-M as a benchmark tier while the library shipped only
AES-256-GCM and ChaCha20-Poly1305 — both designed for application processors.
AES-GCM without AES-NI needs either large tables (a cache-timing surface) or
the bitsliced path in `ama_aes_bitsliced.c` (constant-time, but slower and
larger); ChaCha20-Poly1305 needs a 512-bit state plus a separate
128-bit-multiply authenticator. Ascon needs a 320-bit state and one
permutation for both confidentiality and authentication. The inconsistency
between the platforms claimed and the primitives offered is now resolved at
the root rather than annotated.

**Its side-channel posture is structural, not engineered.** There are no
lookup tables anywhere in Ascon — the 5-bit S-box is evaluated bitsliced
across the five 64-bit state words, 64 applications in parallel, in 22 boolean
operations. There is no cache-timing surface to remove. AES had to be
*rewritten* bitsliced to reach the same property (INVARIANT-20 makes the
constant-time path the default precisely because the table-driven one is
unsafe); Ascon starts there.

**It reuses a review model already in the tree.** Ascon is a sponge over a
round-based permutation, structurally the same shape as `ama_sha3.c`. No code
is shared and none should be, but the KAT harness pattern, the constant-time
argument, and the fuzz-property design transfer directly — which is why this
landed with full verification rather than a partial first cut.

---

## 3. Why not — the honest case against, and what it costs

**It is not faster, and this is not a performance change.** On any host with
AES-NI or ARMv8 crypto extensions, AES-256-GCM wins decisively. On 64-bit
hosts without them, ChaCha20-Poly1305 generally still wins: it moves 512 bits
of state through cheap 32-bit adds and XORs, while Ascon's rate is 128 bits
per 8-round permutation. Ascon's advantage appears where state size, code
size, and absence of tables dominate — 8/16/32-bit microcontrollers — not on
the machines most callers of this library use. Any claim that adding Ascon
made anything faster would be false.

**It is not an interoperability win.** No mainstream TLS deployment negotiates
Ascon. Its interoperability value is with other SP 800-232 implementations on
constrained devices, which is a real but narrow population.

**It is new attack surface.** ~500 lines of new cryptographic C in a library
whose value proposition is "zero external crypto dependencies, community
tested, not externally audited." That cost is mitigated but not eliminated by
the verification in §5.

**It carries a specific interoperability trap.** See §4.

**Accepted on balance** because the standing and platform-coverage arguments
are structural and the cost is bounded and verified, not because Ascon
outperforms an incumbent. It does not.

---

## 4. Compatibility impact

**No breaking change.** New functions, new symbols, new Python module. No
existing signature, error code, ABI offset, or wire format is touched.
`ama_error_t` gains no new value — Ascon uses `AMA_ERROR_VERIFY_FAILED`, the
same code AES-GCM and ChaCha20-Poly1305 return for a bad tag.

**Available in both build configurations.** `src/c/ama_ascon.c` references no
other primitive in this library and no PQC symbol, so it sits in the
unconditional `AMA_SOURCES` list and is present under
`AMA_USE_NATIVE_PQC=OFF` as well as the default build. This is deliberate:
the constrained targets Ascon exists for are the ones most likely to build
without native post-quantum support, and an Ascon that vanished in that
configuration would miss its own use case.

**The one trap, recorded prominently.** SP 800-232 is **not byte-compatible
with Ascon v1.2 / the CAESAR submission.** Three differences:

1. **Rate.** Ascon-AEAD128 absorbs 128 bits per permutation call; v1.2's
   Ascon-128 absorbed 64.
2. **IV.** `0x00001000808c0001`, not v1.2's `0x80400c0600000000`.
3. **Bit ordering.** SP 800-232 numbers a bitstring from its *least*
   significant bit (Appendix A.1), so the domain-separation constant
   `0^319 || 1` is the integer `0x8000000000000000` (Appendix A.2) — **not**
   `1`. A v1.2-derived implementation writes `S4 ^= 1` and produces a
   non-standard tag on every message that carries associated data, while
   round-tripping perfectly against itself.

A peer running v1.2 will not interoperate, and the failure presents as a tag
mismatch rather than a version error. This is stated in the header of
`src/c/ama_ascon.c`, in `include/ama_cryptography.h`, and in the
`ama_cryptography.ascon` module docstring, because it is the defect most
likely to be introduced by a future contributor porting reference code.

**Nonce discipline is a caller obligation.** Ascon-AEAD128 has no
nonce-misuse resistance. The leak under `(key, nonce)` reuse is narrower than
a stream cipher's — because the sponge absorbs plaintext into the rate before
permuting, only the **first 16-byte block** XORs to the plaintext XOR, and the
states diverge thereafter — but it is still a leak, and repeated reuse gives
an attacker leverage on the state. Narrower is not safe. Both halves of that
property are asserted in the test suites so the documentation cannot drift
into either overstating or understating it.

---

## 5. Measured evidence

Verification is layered, because a mode-level KAT alone cannot distinguish
"the permutation is correct" from "two errors cancelled."

| Layer | What it checks | Result |
|---|---|---|
| Substitution layer | Bitsliced S-box expression vs the Table 6 lookup representation, all 32 inputs | 32/32 |
| Permutation | `Ascon-p[12]` vs the precomputed Ascon-Hash256 initialization state published in Appendix A.3 — a value from the standard, not from this implementation | exact match, all 5 words |
| Ascon-Hash256 | Full published KAT corpus | **1025 / 1025** |
| Ascon-AEAD128 | Full published KAT corpus, encrypt **and** decrypt round-trip | **1089 / 1089** |
| Python surface | Same two corpora driven through the ctypes boundary | 1025 / 1025 and 1089 / 1089 |
| C suite | `tests/c/test_ascon.c`, including all 128 single-bit tag forgeries and the fail-closed contract | 246 checks, 0 failures |
| Build configurations | Full C suite, `AMA_USE_NATIVE_PQC=OFF` and `=ON` | 27/27 and 55/55 |
| Compiler | `-Wall -Wextra -Wpedantic` | 0 warnings from `ama_ascon.c` |

The KAT corpus covers every plaintext length 0..32 crossed with every
associated-data length 0..32, which exercises the empty-input, sub-rate,
exact-rate, and rate-plus-one boundaries in both the rate-128 AEAD and the
rate-64 hash — the four places a sponge implementation actually breaks.
Provenance is recorded in `tests/kat/ascon/README.md`.

Constant-time and fuzzing evidence is recorded in `CHANGELOG.md` for `3.4.0`
alongside the numbers produced by `tools/run_dudect.sh` and
`fuzz/fuzz_ascon.c`.

---

## 6. What would reverse this decision

Recorded so the decision is falsifiable rather than permanent by default:

- A cryptanalytic result reducing Ascon's security margin below its claimed
  128-bit strength, or NIST withdrawing or amending SP 800-232.
- Discovery that the constrained-target use case does not materialise — if no
  consumer builds for a device where Ascon is the right choice within a year,
  it is carrying maintenance cost for no benefit and should be reconsidered.
- A measured constant-time regression that cannot be fixed without a table.

---

Copyright (C) 2025-2026 Steel Security Advisors LLC
