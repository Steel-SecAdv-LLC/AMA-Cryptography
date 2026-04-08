"""NTRU tower solver and Babai signing for FALCON-512.

Computes the NTRU complement polynomials (F, G) given short polynomials
(f, g) such that f*G - g*F = q mod (x^n + 1).

The algorithm uses a recursive field-norm tower:
  1. Base case (n=1): extended GCD to find F0, G0 with f0*G0 - g0*F0 = q
  2. Recursive case: project via field norm to half-size, solve, lift back
  3. Babai reduction at each level to keep coefficients small

Also provides Babai nearest-plane signing using the splitting-tower FFT
that diagonalizes Z[x]/(x^n+1), enabling per-slot Gram-Schmidt reduction.

Uses bit-shifting for precision management in the Babai reduction:
f, g are shifted down to ~53-bit precision once; F, G are re-shifted each
iteration. The subtraction compensates with a left-shift.

Based on: tprest/falcon.py (Thomas Prest's reference implementation)
"""

from __future__ import annotations

import cmath
import hashlib
import os

FALCON_Q = 12289
FALCON_N = 512

# ---------------------------------------------------------------------------
# Negacyclic NTT mod q = 12289 for exact polynomial multiplication
# in Z_q[x]/(x^n+1).  q-1 = 12288 = 2^12 * 3, so Z_q has primitive
# 2^12-th roots of unity.
# ---------------------------------------------------------------------------
_NTT_PSI = 10302  # primitive 2n-th root: psi^(2n) = 1, psi^n = -1
_NTT_PSI_INV = pow(_NTT_PSI, FALCON_Q - 2, FALCON_Q)
_NTT_OMEGA = pow(_NTT_PSI, 2, FALCON_Q)  # primitive n-th root
_NTT_OMEGA_INV = pow(_NTT_OMEGA, FALCON_Q - 2, FALCON_Q)
_NTT_N_INV = pow(FALCON_N, FALCON_Q - 2, FALCON_Q)
_NTT_LOGN = 9  # log2(512)


def _bit_rev(x: int, bits: int) -> int:
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def _ntt_forward(a: list[int]) -> list[int]:
    """Forward negacyclic NTT: pre-twist by psi, Cooley-Tukey DIT."""
    q = FALCON_Q
    nn = len(a)
    a = [(x % q) for x in a]
    # Pre-twist: a[i] *= psi^i
    pw = 1
    for i in range(nn):
        a[i] = (a[i] * pw) % q
        pw = (pw * _NTT_PSI) % q
    # Bit-reversal permutation
    for i in range(nn):
        j = _bit_rev(i, _NTT_LOGN)
        if i < j:
            a[i], a[j] = a[j], a[i]
    # Cooley-Tukey butterflies
    m = 1
    while m < nn:
        wm = pow(_NTT_OMEGA, nn // (2 * m), q)
        for k in range(0, nn, 2 * m):
            w = 1
            for j in range(m):
                t = (w * a[k + j + m]) % q
                u = a[k + j]
                a[k + j] = (u + t) % q
                a[k + j + m] = (u - t) % q
                w = (w * wm) % q
        m *= 2
    return a


def _ntt_inverse(a: list[int]) -> list[int]:
    """Inverse negacyclic NTT: Gentleman-Sande DIF, post-untwist."""
    q = FALCON_Q
    nn = len(a)
    a = list(a)
    # Gentleman-Sande DIF butterflies
    m = nn // 2
    while m >= 1:
        wm = pow(_NTT_OMEGA_INV, nn // (2 * m), q)
        for k in range(0, nn, 2 * m):
            w = 1
            for j in range(m):
                u = a[k + j]
                v = a[k + j + m]
                a[k + j] = (u + v) % q
                a[k + j + m] = ((u - v) * w) % q
                w = (w * wm) % q
        m //= 2
    # Bit-reversal permutation
    for i in range(nn):
        j = _bit_rev(i, _NTT_LOGN)
        if i < j:
            a[i], a[j] = a[j], a[i]
    # Post-untwist: a[i] *= n_inv * psi_inv^i
    pw = _NTT_N_INV
    for i in range(nn):
        a[i] = (a[i] * pw) % q
        pw = (pw * _NTT_PSI_INV) % q
    return a


def _poly_mul_ntt(a: list[int], b: list[int]) -> list[int]:
    """Multiply polynomials mod (x^n+1) mod q using negacyclic NTT."""
    a_hat = _ntt_forward(a)
    b_hat = _ntt_forward(b)
    c_hat = [(ai * bi) % FALCON_Q for ai, bi in zip(a_hat, b_hat)]
    return _ntt_inverse(c_hat)


# ---------------------------------------------------------------------------
# Splitting-tower FFT (matching the reference implementation exactly)
# ---------------------------------------------------------------------------

_roots_cache: dict[int, list[complex]] = {}


def _gen_roots(n: int) -> list[complex]:
    """Generate FFT roots for x^n+1 in splitting-tower order."""
    if n in _roots_cache:
        return _roots_cache[n]
    if n == 2:
        roots = [1j, -1j]
    else:
        half_roots = _gen_roots(n // 2)
        roots = [complex(0)] * n
        for i in range(n // 2):
            r = cmath.sqrt(half_roots[i])
            roots[2 * i] = r
            roots[2 * i + 1] = -r
    _roots_cache[n] = roots
    return roots


def _split(f: list) -> tuple[list, list]:
    n = len(f)
    return [f[2 * i] for i in range(n // 2)], [f[2 * i + 1] for i in range(n // 2)]


def _merge(f0: list, f1: list) -> list:
    n = 2 * len(f0)
    f = [None] * n
    for i in range(n // 2):
        f[2 * i] = f0[i]
        f[2 * i + 1] = f1[i]
    return f


def _fft(f: list, n: int) -> list[complex]:
    """FFT: coefficient representation -> FFT representation."""
    if n == 2:
        return [complex(f[0], f[1]), complex(f[0], -f[1])]
    w = _gen_roots(n)
    f0, f1 = _split(f)
    f0_fft = _fft(f0, n // 2)
    f1_fft = _fft(f1, n // 2)
    result = [complex(0)] * n
    for i in range(n // 2):
        result[2 * i] = f0_fft[i] + w[2 * i] * f1_fft[i]
        result[2 * i + 1] = f0_fft[i] - w[2 * i] * f1_fft[i]
    return result


def _ifft(f_fft: list[complex], n: int) -> list:
    """Inverse FFT: FFT representation -> coefficient representation."""
    if n == 2:
        return [f_fft[0].real, f_fft[0].imag]
    w = _gen_roots(n)
    f0_fft = [complex(0)] * (n // 2)
    f1_fft = [complex(0)] * (n // 2)
    for i in range(n // 2):
        f0_fft[i] = 0.5 * (f_fft[2 * i] + f_fft[2 * i + 1])
        f1_fft[i] = 0.5 * (f_fft[2 * i] - f_fft[2 * i + 1]) * w[2 * i].conjugate()
    f0 = _ifft(f0_fft, n // 2)
    f1 = _ifft(f1_fft, n // 2)
    return _merge(f0, f1)


def _mul_fft(a: list[complex], b: list[complex]) -> list[complex]:
    return [a[i] * b[i] for i in range(len(a))]


def _add_fft(a: list[complex], b: list[complex]) -> list[complex]:
    return [a[i] + b[i] for i in range(len(a))]


def _adj_fft(a: list[complex]) -> list[complex]:
    return [x.conjugate() for x in a]


def _div_fft(a: list[complex], b: list[complex]) -> list[complex]:
    return [a[i] / b[i] for i in range(len(a))]


# ---------------------------------------------------------------------------
# Polynomial arithmetic in Z[x]/(x^n + 1)
# ---------------------------------------------------------------------------


def _xgcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended GCD (iterative): returns (g, u, v) such that a*u + b*v = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def _karatsuba(a: list[int], b: list[int], n: int) -> list[int]:
    """Karatsuba multiplication of two polynomials."""
    if n == 1:
        return [a[0] * b[0], 0]
    n2 = n // 2
    a0, a1 = a[:n2], a[n2:]
    b0, b1 = b[:n2], b[n2:]
    ax = [a0[i] + a1[i] for i in range(n2)]
    bx = [b0[i] + b1[i] for i in range(n2)]
    a0b0 = _karatsuba(a0, b0, n2)
    a1b1 = _karatsuba(a1, b1, n2)
    axbx = _karatsuba(ax, bx, n2)
    for i in range(n):
        axbx[i] -= a0b0[i] + a1b1[i]
    ab = [0] * (2 * n)
    for i in range(n):
        ab[i] += a0b0[i]
        ab[i + n] += a1b1[i]
        ab[i + n2] += axbx[i]
    return ab


def _karamul(a: list[int], b: list[int]) -> list[int]:
    """Karatsuba multiplication mod (x^n + 1)."""
    n = len(a)
    ab = _karatsuba(a, b, n)
    return [ab[i] - ab[i + n] for i in range(n)]


def _field_norm(f: list[int], n: int) -> list[int]:
    """Compute field norm N(f): Z[x]/(x^n+1) -> Z[x]/(x^(n/2)+1)."""
    half = n // 2
    fe = [f[2 * i] for i in range(half)]
    fo = [f[2 * i + 1] for i in range(half)]
    fe_sq = _karamul(fe, fe)
    fo_sq = _karamul(fo, fo)
    result = list(fe_sq)
    for i in range(half - 1):
        result[i + 1] -= fo_sq[i]
    result[0] += fo_sq[half - 1]
    return result


def _galois_conjugate(f: list[int]) -> list[int]:
    """Galois conjugate: f(x) -> f(-x)."""
    return [f[i] if i % 2 == 0 else -f[i] for i in range(len(f))]


def _lift(fp: list[int]) -> list[int]:
    """Lift from Z[x]/(x^(n/2)+1) to Z[x]/(x^n+1): fp(y) -> fp(x^2)."""
    n2 = len(fp)
    result = [0] * (2 * n2)
    for i in range(n2):
        result[2 * i] = fp[i]
    return result


def _bitsize(a: int) -> int:
    """Bitsize of integer (rounded to next multiple of 8)."""
    val = abs(a)
    res = 0
    while val:
        res += 8
        val >>= 8
    return res


def _reduce(f: list[int], g: list[int], F: list[int], G: list[int]) -> tuple[list[int], list[int]]:
    """Babai reduction of (F, G) w.r.t. (f, g) in Z[x]/(x^n+1).

    Algorithm 7 (Reduce) from Falcon's specification.
    """
    n = len(f)
    size = max(53, max(_bitsize(c) for c in f), max(_bitsize(c) for c in g))

    f_adjust = [c >> (size - 53) for c in f]
    g_adjust = [c >> (size - 53) for c in g]
    fa_fft = _fft(f_adjust, n)
    ga_fft = _fft(g_adjust, n)

    for _ in range(100):
        Size = max(53, max(_bitsize(c) for c in F), max(_bitsize(c) for c in G))
        if Size < size:
            break

        F_adjust = [c >> (Size - 53) for c in F]
        G_adjust = [c >> (Size - 53) for c in G]
        Fa_fft = _fft(F_adjust, n)
        Ga_fft = _fft(G_adjust, n)

        den_fft = _add_fft(_mul_fft(fa_fft, _adj_fft(fa_fft)), _mul_fft(ga_fft, _adj_fft(ga_fft)))
        num_fft = _add_fft(_mul_fft(Fa_fft, _adj_fft(fa_fft)), _mul_fft(Ga_fft, _adj_fft(ga_fft)))
        k_fft = _div_fft(num_fft, den_fft)
        k = _ifft(k_fft, n)
        k = [round(c) for c in k]

        if all(c == 0 for c in k):
            break

        fk = _karamul(f, k)
        gk = _karamul(g, k)
        shift_comp = Size - size
        for i in range(n):
            F[i] -= fk[i] << shift_comp
            G[i] -= gk[i] << shift_comp

    return F, G


# ---------------------------------------------------------------------------
# Main solver
# ---------------------------------------------------------------------------


def ntru_solve(
    f: list[int], g: list[int], n: int = FALCON_N, q: int = FALCON_Q
) -> tuple[list[int], list[int]]:
    """Solve the NTRU equation: find F, G such that f*G - g*F = q mod (x^n+1).

    Uses the recursive field-norm tower algorithm (NTRUSolve).

    Args:
        f: First short polynomial (length n)
        g: Second short polynomial (length n)
        n: Ring dimension (power of 2)
        q: Modulus

    Returns:
        (F, G) such that f*G - g*F = q in Z[x]/(x^n+1)

    Raises:
        ValueError: If no solution exists
    """
    if n == 1:
        f0, g0 = f[0], g[0]
        d, u, v = _xgcd(f0, g0)
        if d != 1:
            raise ValueError(f"NTRU equation has no solution: gcd({f0}, {g0}) = {d} != 1")
        return [-q * v], [q * u]

    half = n // 2
    fn = _field_norm(f, n)
    gn = _field_norm(g, n)

    Fp, Gp = ntru_solve(fn, gn, half, q)

    F = _karamul(_lift(Fp), _galois_conjugate(g))
    G = _karamul(_lift(Gp), _galois_conjugate(f))

    F, G = _reduce(f, g, F, G)
    return F, G


def verify_ntru(
    f: list[int], g: list[int], F: list[int], G: list[int], n: int = FALCON_N, q: int = FALCON_Q
) -> bool:
    """Verify that f*G - g*F = q mod (x^n+1)."""
    fG = _karamul(f, G)
    gF = _karamul(g, F)
    result = [fG[i] - gF[i] for i in range(n)]
    if result[0] != q:
        return False
    return all(result[i] == 0 for i in range(1, n))


# ---------------------------------------------------------------------------
# Babai nearest-plane signing
# ---------------------------------------------------------------------------

FALCON_NONCE_LEN = 40
FALCON_SIG_BOUND = 350000000


def _hash_to_point(nonce: bytes, message: bytes, n: int = FALCON_N, q: int = FALCON_Q) -> list[int]:
    """Hash (nonce || message) to a polynomial in Z_q^n using SHAKE-256.

    Matches the C ``hash_to_point`` exactly: incremental SHAKE-256
    squeeze, 2 bytes per sample, 14-bit mask (``buf[1] & 0x3F``),
    accept when ``val < q``.
    """
    # SHAKE-256 is an XOF; Python's hashlib exposes .digest(length)
    # which returns the first `length` bytes of the XOF output.  We
    # request a generous buffer and consume it 2 bytes at a time,
    # exactly matching the C incremental-squeeze loop.
    buf = hashlib.shake_256(nonce + message).digest(2 * n + 512)
    c: list[int] = []
    pos = 0
    while len(c) < n:
        if pos + 2 > len(buf):
            # Extend buffer (extremely unlikely to be needed)
            buf = hashlib.shake_256(nonce + message).digest(len(buf) * 2)
        val = buf[pos] | ((buf[pos + 1] & 0x3F) << 8)  # 14-bit
        pos += 2
        if val < q:
            c.append(val)
    return c


def babai_sign(
    f: list[int],
    g: list[int],
    F: list[int],
    G: list[int],
    c: list[int],
    n: int = FALCON_N,
) -> tuple[list[int], list[int]]:
    """Babai nearest-plane reduction using the full NTRU basis.

    Basis (as rows of polynomials in Z[x]/(x^n+1)):
      b1 = (g, -f)
      b2 = (G, -F)

    Target: t = (c_centered, 0) where c_centered is c shifted to (-q/2, q/2].

    Algorithm:
      1. Use FFT-domain Gram-Schmidt to find approximate real z1, z2.
      2. IFFT z1, z2 back to coefficient domain and round to integers.
      3. Compute the residual s = t - z*B using exact polynomial arithmetic
         so the algebraic relation s1 + s2*h ≡ c (mod q) holds exactly.

    Returns (s1, s2) in coefficient domain.
    """
    q = FALCON_Q
    # Center c around 0
    c_centered = [float(ci - q) if ci > q // 2 else float(ci) for ci in c]

    # FFT of all basis polynomials
    f_fft = _fft([float(x) for x in f], n)
    g_fft = _fft([float(x) for x in g], n)
    F_fft = _fft([float(x) for x in F], n)
    G_fft = _fft([float(x) for x in G], n)

    # FFT of target: t = (c_centered, 0)
    t0_fft = _fft(c_centered, n)
    t1_fft = [complex(0)] * n

    # Collect z1, z2 in FFT domain
    z1_fft = [complex(0)] * n
    z2_fft = [complex(0)] * n

    for k in range(n):
        gk = g_fft[k]
        fk = f_fft[k]
        Gk = G_fft[k]
        Fk = F_fft[k]

        # Gram matrix entries
        g11 = abs(gk) ** 2 + abs(fk) ** 2
        g12 = gk * Gk.conjugate() + fk * Fk.conjugate()
        g22 = abs(Gk) ** 2 + abs(Fk) ** 2

        # Gram-Schmidt: |b2*|^2
        b2star_sq = g22 - abs(g12) ** 2 / g11

        # <t, b1> = t0*conj(g) - t1*conj(f)
        t_b1 = t0_fft[k] * gk.conjugate() - t1_fft[k] * fk.conjugate()

        # <t, b2> = t0*conj(G) - t1*conj(F)
        t_b2 = t0_fft[k] * Gk.conjugate() - t1_fft[k] * Fk.conjugate()

        # <t, b2*> = <t, b2> - (g12/g11) * <t, b1>
        t_b2star = t_b2 - (g12 / g11) * t_b1

        # z2 = round(<t, b2*> / |b2*|^2)
        z2_c = t_b2star / b2star_sq
        z2 = complex(round(z2_c.real), round(z2_c.imag))
        z2_fft[k] = z2

        # z1 = round((<t, b1> - z2 * conj(g12)) / g11)
        z1_c = (t_b1 - z2 * g12.conjugate()) / g11
        z1 = complex(round(z1_c.real), round(z1_c.imag))
        z1_fft[k] = z1

    # IFFT z1, z2 to coefficient domain and round to integers.
    # Per-slot rounding in FFT domain may not produce valid integer
    # polynomials, so we must round after IFFT to get true integers.
    z1_real = _ifft(z1_fft, n)
    z2_real = _ifft(z2_fft, n)
    z1_int = [round(x) for x in z1_real]
    z2_int = [round(x) for x in z2_real]

    # Compute the lattice point v = z1*b1 + z2*b2 using exact NTT mul.
    # b1 = (g, -f), b2 = (G, -F)
    # v1 = z1*g + z2*G,  v2 = z1*f + z2*F  (note: s2 = v2, not -v2)
    z1g = _poly_mul_ntt(z1_int, g)
    z2G = _poly_mul_ntt(z2_int, G)
    z1f = _poly_mul_ntt(z1_int, f)
    z2F = _poly_mul_ntt(z2_int, F)

    # v1 = z1*g + z2*G mod q
    v1 = [(z1g[i] + z2G[i]) % q for i in range(n)]
    # v2 = z1*f + z2*F mod q
    v2 = [(z1f[i] + z2F[i]) % q for i in range(n)]

    # Residual: s1 = c - v1,  s2 = 0 - (-(z1*f + z2*F)) = v2
    # Center around 0
    s1 = [(c[i] - v1[i]) % q for i in range(n)]
    s1 = [v - q if v > q // 2 else v for v in s1]
    s2 = [v2[i] if v2[i] <= q // 2 else v2[i] - q for i in range(n)]
    return s1, s2


def _poly_mul_mod_q(a: list[int], b: list[int], n: int = FALCON_N, q: int = FALCON_Q) -> list[int]:
    """Multiply polynomials mod (x^n+1) mod q using negacyclic NTT."""
    return _poly_mul_ntt(a, b)


def falcon_sign(
    f: list[int],
    g: list[int],
    F: list[int],
    G: list[int],
    h: list[int],
    message: bytes,
    n: int = FALCON_N,
    max_attempts: int = 100,
) -> tuple[bytes, list[int], list[int]] | None:
    """Sign a message using the full NTRU basis with Babai reduction.

    The Babai nearest-plane algorithm produces a short ``s2``.  We then
    compute ``s1 = c - s2*h mod q`` algebraically so that the
    verification relation ``s1 + s2*h ≡ c (mod q)`` holds exactly.

    Args:
        f, g, F, G: NTRU basis polynomials (secret key).
        h: Public key polynomial in Z_q^n (needed to derive s1).
        message: Message bytes to sign.
        n: Ring dimension.
        max_attempts: Max rejection-sampling attempts.

    Returns:
        (nonce, s1, s2) on success, or None if all attempts exceeded the
        norm bound.
    """
    q = FALCON_Q
    for _ in range(max_attempts):
        nonce = os.urandom(FALCON_NONCE_LEN)
        c = _hash_to_point(nonce, message, n)
        _s1_babai, s2 = babai_sign(f, g, F, G, c, n)

        # Derive s1 algebraically: s1 = c - s2*h mod q, centered
        s2h = _poly_mul_mod_q(s2, h, n, q)
        s1 = [(c[i] - s2h[i]) % q for i in range(n)]
        s1 = [v - q if v > q // 2 else v for v in s1]

        norm_sq = sum(x * x for x in s1) + sum(x * x for x in s2)
        if norm_sq <= FALCON_SIG_BOUND:
            return nonce, s1, s2
    return None


def falcon_verify(
    h: list[int],
    nonce: bytes,
    s2: list[int],
    message: bytes,
    n: int = FALCON_N,
    q: int = FALCON_Q,
) -> bool:
    """Verify a FALCON-512 signature given the public key polynomial h.

    Recomputes c = H(nonce || message), then s1 = c - s2*h mod q,
    and checks that ||(s1, s2)||^2 <= FALCON_SIG_BOUND.

    Args:
        h: Public key polynomial in Z_q^n (coefficient form).
        nonce: 40-byte nonce from the signature.
        s2: Second signature polynomial (decoded from signature).
        message: Original message bytes.
        n: Ring dimension.
        q: Modulus.

    Returns:
        True if signature is valid, False otherwise.
    """
    c = _hash_to_point(nonce, message, n, q)

    # Compute s2 * h mod q using exact negacyclic NTT
    prod = _poly_mul_ntt(s2, h)

    # s1 = c - s2*h mod q, centered in (-q/2, q/2]
    s1: list[int] = []
    for i in range(n):
        v = (c[i] - prod[i]) % q
        if v > q // 2:
            v -= q
        s1.append(v)

    norm_sq = sum(x * x for x in s1) + sum(x * x for x in s2)
    return norm_sq <= FALCON_SIG_BOUND
