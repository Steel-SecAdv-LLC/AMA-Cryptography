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
    salt = classical_ciphertext || pqc_ciphertext,   # Ciphertext binding
    ikm  = classical_shared_secret || pqc_shared_secret,  # Key material
    info = "ama-hybrid-kem-v1" || classical_pk || pqc_pk  # Context binding
)
```

The ciphertext binding in the `salt` parameter ensures that the combined secret is bound to the specific ciphertexts used, preventing ciphertext substitution attacks.

### `HybridCombiner` API

```python
from ama_cryptography.hybrid_combiner import HybridCombiner, HybridEncapsulation
from ama_cryptography.pqc_backends import generate_kyber_keypair
from ama_cryptography.crypto_api import AsymmetricCryptoAlgorithm

combiner = HybridCombiner()
classical_algo = AsymmetricCryptoAlgorithm()

# === Sender Setup ===
# Generate recipient key pairs (done once; public keys are distributed)
classical_pk, classical_sk = classical_algo.generate_keypair()
pqc_pk, pqc_sk = generate_kyber_keypair()

# === Sender: Encapsulate ===
# Encapsulate generates ciphertexts and the combined shared secret
encapsulation: HybridEncapsulation = combiner.encapsulate(classical_pk, pqc_pk)

# The combined secret is derived from both component secrets
print(f"Combined secret: {encapsulation.combined_secret.hex()}")  # 32 bytes
print(f"Classical ciphertext: {len(encapsulation.classical_ciphertext)} bytes")
print(f"PQC ciphertext: {len(encapsulation.pqc_ciphertext)} bytes")

# Sender transmits: encapsulation.classical_ciphertext + encapsulation.pqc_ciphertext

# === Receiver: Decapsulate ===
recovered_secret = combiner.decapsulate(encapsulation, classical_sk, pqc_sk)

assert recovered_secret == encapsulation.combined_secret
print("Hybrid KEM key agreement successful!")
print(f"Both parties share: {recovered_secret.hex()[:16]}...")
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

AMA Cryptography's multi-layer defense architecture natively incorporates a hybrid signature in layers 3 and 4 (Ed25519 + ML-DSA-65). The `HybridSigner` class provides direct access to this scheme.

### Security Guarantee

> **Dual-signature security:** Both Ed25519 and ML-DSA-65 signatures must independently verify for the package to be accepted. An attacker must forge **both** simultaneously — one classical forgery (2^128 classical operations) and one quantum-resistant forgery (2^190 quantum operations).

### `HybridSigner` API

```python
from ama_cryptography.crypto_api import HybridSigner, CryptoMode

signer = HybridSigner(mode=CryptoMode.HYBRID)

# Generate both classical and PQC key pairs
classical_pk, classical_sk = signer.generate_classical_keypair()
pqc_pk, pqc_sk = signer.generate_pqc_keypair()

message = b"Data requiring quantum-resistant protection"

# Sign with both algorithms
combined_signature = signer.combine_signatures(
    ed25519_sig=signer.sign_classical(message, classical_sk),
    ml_dsa_sig=signer.sign_pqc(message, pqc_sk),
)

# Verify both signatures
is_valid = signer.verify_hybrid(
    message,
    combined_signature,
    classical_pk,
    pqc_pk,
)
print(f"Hybrid signature valid: {is_valid}")
```

---

## Using the Multi-Layer Package (Full Hybrid)

The highest-level API (`code_guardian_secure.py`) automatically uses hybrid signatures (Ed25519 + ML-DSA-65) as layers 3 and 4:

```python
from code_guardian_secure import (
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

## Hybrid Mode Selection

```python
from ama_cryptography.crypto_api import CryptoMode

# Classical only (Ed25519)
mode = CryptoMode.CLASSICAL

# Quantum-resistant only (ML-DSA-65)
mode = CryptoMode.QUANTUM_RESISTANT

# Hybrid (Ed25519 + ML-DSA-65)
mode = CryptoMode.HYBRID  # Recommended for production
```

---

## Thread Safety and Serialization

`HybridCombiner` and `HybridSigner` are stateless — all state is local to each method call. They are safe to use concurrently from multiple threads.

`HybridEncapsulation` objects are serializable (can be converted to/from `bytes` or JSON for transmission).

---

## Integration with Adaptive Posture

The [Adaptive Posture](Adaptive-Posture) system can automatically switch between hybrid modes based on threat level:

```python
from ama_cryptography.adaptive_posture import (
    CryptoPostureController,
    ThreatLevel,
)

controller = CryptoPostureController()

# On elevated threat: switch to strict quantum-resistant-only mode
controller.execute_action(
    evaluation=PostureEvaluation(threat_level=ThreatLevel.HIGH),
    crypto_api=signer,
    key_manager=manager,
)
```

---

## References

- Bindel, N., Brendel, J., Fischlin, M., Goncalves, B., Stebila, D. (2019). *Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange.* PQCrypto 2019.
- NIST SP 800-56C Rev. 2 — Recommendation for Key-Derivation Methods in Key-Establishment Schemes
- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard

---

*See [Post-Quantum Cryptography](Post-Quantum-Cryptography) for PQC algorithm details, or [Adaptive Posture](Adaptive-Posture) for runtime algorithm switching.*
