# Hybrid Cryptography

Documentation for AMA Cryptography's hybrid classical + post-quantum cryptographic constructions, including the hybrid KEM combiner and hybrid signature scheme.

---

## Motivation

**Why hybrid?**

1. **Defense-in-depth:** If either the classical or PQC component is compromised, the hybrid scheme retains the security of the other.
2. **Migration:** Systems can verify with classical keys today and add PQC verification as it becomes standard.
3. **Regulatory compliance:** Some standards require classical algorithms; others mandate PQC. Hybrid satisfies both.
4. **Conservative posture:** The security of ML-KEM and ML-DSA rests on lattice hardness assumptions. SPHINCS+-based hybrids add a second assumption based only on hash functions.

---

## Hybrid KEM Combiner

The `HybridCombiner` class implements a binding construction combining X25519 (classical ECDH) and ML-KEM-1024 (post-quantum), following the dual-PRF HKDF approach of Bindel et al. (PQCrypto 2019).

### Security Guarantee

> **IND-CCA2 hybrid security:** The combined shared secret is indistinguishable from random as long as at least one of the two component KEMs is IND-CCA2 secure. An adversary must break **both** X25519 and ML-KEM-1024 simultaneously to compromise the combined secret.

### Construction

```
combined_ss = HKDF-SHA3-256(
    ikm  = u8(2)                     ||                # component count
           u32be(|ct_c|) || ct_c     ||                # classical ciphertext
           u32be(|ct_p|) || ct_p     ||                # pqc ciphertext
           ss_c || ss_p,                               # concatenated shared secrets
    salt = u32be(|pk_c|) || pk_c || u32be(|pk_p|) || pk_p,
    info = b"ama-hybrid-kem-v1",
)
```

All variable-length fields use fixed-size length prefixes (`u32be`) so
concatenation is unambiguous — the component-stripping attack reported in
audit finding C6 is prevented by the `u8(count)` header together with the
`u32be(len)` prefixes (PR #224, v2.1.5).

### `HybridCombiner` API

`HybridCombiner` is KEM-agnostic: you pass in the `encapsulate` /
`decapsulate` callables for each half, so the same class drives
X25519 ∥ ML-KEM-1024, ECDH ∥ ML-KEM, or any pairing. The
`AmaCryptography(AlgorithmType.HYBRID_KEM)` entry point wires this up
for the default X25519 + ML-KEM-1024 pair.

```python
from ama_cryptography.hybrid_combiner import HybridCombiner, HybridEncapsulation
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType, KyberProvider

# ---- Option A: the algorithm-agnostic dispatcher (recommended)
hybrid = AmaCryptography(algorithm=AlgorithmType.HYBRID_KEM)
recipient = hybrid.generate_keypair()
enc = hybrid.encapsulate(recipient.public_key)                # EncapsulatedSecret
shared = hybrid.decapsulate(enc.ciphertext, recipient.secret_key)
assert shared == enc.shared_secret

# ---- Option B: drive the combiner directly with explicit providers
from ama_cryptography.pqc_backends import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

# HybridCombiner expects bare-tuple callables:
#   encapsulate_fn(pk) -> (ciphertext: bytes, shared_secret: bytes)
#   decapsulate_fn(ct, sk) -> shared_secret: bytes
#
# AMA's Kyber API returns dataclasses, so wrap to expose the tuple shape:
def _kyber_encaps(pk: bytes):
    enc = kyber_encapsulate(pk)                 # KyberEncapsulation
    return enc.ciphertext, enc.shared_secret    # (bytes, bytes)

# kyber_decapsulate already returns bytes, so no adapter is needed.

combiner = HybridCombiner()

classical_pk, classical_sk = b"...", b"..."     # X25519 keypair (your wrapper)
pqc_kp   = generate_kyber_keypair()             # KyberKeyPair dataclass
pqc_pk   = pqc_kp.public_key
pqc_sk   = pqc_kp.secret_key

encapsulation: HybridEncapsulation = combiner.encapsulate_hybrid(
    classical_encapsulate=my_x25519_encapsulate,   # (pk) -> (ct, ss)
    pqc_encapsulate=_kyber_encaps,                 # dataclass adapter above
    classical_pk=classical_pk,
    pqc_pk=pqc_pk,
)

recovered = combiner.decapsulate_hybrid(
    classical_decapsulate=my_x25519_decapsulate,   # (ct, sk) -> ss
    pqc_decapsulate=kyber_decapsulate,             # (ct, sk) -> ss (already bytes)
    classical_ct=encapsulation.classical_ciphertext,
    pqc_ct=encapsulation.pqc_ciphertext,
    classical_sk=classical_sk,
    pqc_sk=pqc_sk,
    classical_pk=classical_pk,
    pqc_pk=pqc_pk,
)
assert recovered == encapsulation.combined_secret
```

### `HybridEncapsulation` Object

```python
@dataclass
class HybridEncapsulation:
    combined_secret: bytes          # 32 bytes — derived by HKDF
    classical_ciphertext: bytes     # X25519 ephemeral public key
    pqc_ciphertext: bytes           # ML-KEM-1024 ciphertext (1568 bytes)
    classical_shared_secret: bytes  # X25519 shared secret (32 bytes)
    pqc_shared_secret: bytes        # Kyber shared secret (32 bytes)
```

---

## Hybrid Signature Scheme

The Ed25519 + ML-DSA-65 dual-signature scheme is the recommended
production default. It is exposed through the unified
`AmaCryptography` entry point (`AlgorithmType.HYBRID_SIG`) and backed by
`HybridSignatureProvider` in `ama_cryptography.crypto_api`.

### Security Guarantee

> **Dual-signature security:** Both Ed25519 and ML-DSA-65 signatures must independently verify for the package to be accepted. An attacker must forge **both** simultaneously — one classical forgery (2^128 classical operations) and one quantum-resistant forgery (2^190 quantum operations).

### Hybrid signing API

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)

kp = crypto.generate_keypair()     # KeyPair.public_key  = Ed25519_pk || ML-DSA_pk
                                   # KeyPair.secret_key  = Ed25519_sk || ML-DSA_sk

message = b"Data requiring quantum-resistant protection"
sig     = crypto.sign(message, kp.secret_key)        # Signature.signature = Ed25519_sig || ML-DSA_sig
valid   = crypto.verify(message, sig, kp.public_key) # True only if BOTH verify
```

The `KeyPair.public_key` / `KeyPair.secret_key` fields are fixed-size
concatenations (32 + 1952 bytes public, 32 + 4032 bytes secret) and the
`Signature.signature` is a 64 + 3309 byte concatenation. If you need to
drive the two layers independently, construct `Ed25519Provider` and
`MLDSAProvider` directly — they share the same `CryptoProvider` contract
as the hybrid.

---

## Using the Multi-Layer Package (Full Hybrid)

The legacy orchestrator still exposes the historical codes+helix package
flow — which internally uses hybrid Ed25519 + ML-DSA-65 signatures at
layer 3. It lives in `ama_cryptography.legacy_compat` (new code should
prefer `AmaCryptography(AlgorithmType.HYBRID_SIG)` above):

```python
from ama_cryptography.legacy_compat import (
    generate_key_management_system,
    create_crypto_package,
    verify_crypto_package,
)

kms = generate_key_management_system("MyOrg")
package = create_crypto_package(codes, helix_params, kms)

results = verify_crypto_package(codes, helix_params, package, kms.hmac_key)

# Check both classical and quantum signatures
print(f"Ed25519 valid: {results['ed25519']}")
print(f"ML-DSA-65 valid: {results['dilithium']}")
```

---

## Algorithm Selection

```python
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType

# Classical only (Ed25519)
crypto = AmaCryptography(algorithm=AlgorithmType.ED25519)

# Quantum-resistant only (ML-DSA-65)
crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)

# Hybrid (Ed25519 + ML-DSA-65) — recommended for production
crypto = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
```

---

## Thread Safety and Serialization

`HybridCombiner` and the `HybridSignatureProvider` behind
`AlgorithmType.HYBRID_SIG` are stateless — all state is local to each
method call, so they are safe to use concurrently from multiple threads.

`HybridEncapsulation` objects are serializable (can be converted to/from `bytes` or JSON for transmission).

---

## Integration with Adaptive Posture

The [Adaptive Posture](Adaptive-Posture) system can automatically switch
between algorithm choices based on threat level — e.g., elevating from
`HYBRID_SIG` to `ML_DSA_65` when timing anomalies signal potential
classical compromise:

```python
from ama_cryptography.adaptive_posture import (
    CryptoPostureController,
    PostureEvaluator,
    PostureAction,
    ThreatLevel,
)
from ama_cryptography.crypto_api import AmaCryptography, AlgorithmType
from ama_cryptography.key_management import KeyRotationManager
from ama_cryptography_monitor import AmaCryptographyMonitor

# The controller wires monitor → evaluator → response internally.
# It exposes `evaluate_and_respond()` (no public `execute_action`).
monitor    = AmaCryptographyMonitor(enabled=True)
controller = CryptoPostureController(monitor=monitor)
crypto     = AmaCryptography(algorithm=AlgorithmType.HYBRID_SIG)
key_mgr    = KeyRotationManager()

evaluation = controller.evaluate_and_respond()  # returns PostureEvaluation

# PostureEvaluation.action is the applied action (NOT `.recommended_action`).
# Direct use of PostureEvaluator is only needed when you want to evaluate a
# raw monitor_report dict without driving the controller:
#     evaluator = PostureEvaluator()
#     evaluation = evaluator.evaluate(monitor_report)   # positional arg
if evaluation.action != PostureAction.NONE:
    # Surface the action in your application logs / alerting. The controller
    # has already updated the crypto stance by the time this returns.
    ...
```

---

## References

- Bindel, N., Brendel, J., Fischlin, M., Goncalves, B., Stebila, D. (2019). *Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange.* PQCrypto 2019.
- NIST SP 800-56C Rev. 2 — Recommendation for Key-Derivation Methods in Key-Establishment Schemes
- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard

---

*See [Post-Quantum Cryptography](Post-Quantum-Cryptography) for PQC algorithm details, or [Adaptive Posture](Adaptive-Posture) for runtime algorithm switching.*
