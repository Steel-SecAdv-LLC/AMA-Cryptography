# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""Interval model of the fe51 lazy-reduction contract in src/c/internal/ama_ed25519_ge.h.

The fe51 instantiation of the group law subtracts without carrying
(``fe51_sub_2p`` / ``fe51_sub_8p`` in ``src/c/fe51.h``) and lets the next
multiplication absorb the wider limbs.  That is sound only while every
subtrahend stays under the bias the subtraction adds and every multiplication
input stays under the bound ``fe51_mul`` tolerates (each column below 2^115
and the ``19 * c4`` fold below 2^64).  The comments in ``fe51.h`` state those
bounds and the margin at the tightest site; this module derives them
mechanically so the numbers in the comments are checked rather than asserted.

The model walks every group operation with inputs at their structural bounds
(a ``fe51_mul`` output on every projective coordinate), tracks a per-limb
``[lo, hi]`` interval through each add / biased-sub / mul, and records the
largest ``19 * c4`` fold and the largest column any site reaches.  It is a
model of the formulas in ``ama_ed25519_ge.h`` (ge_dbl, ge_nielsadd/sub,
ge_pnielsadd/sub, ge_add, the p1p1 -> p3 conversion and the negations the
verifier uses), so a change to those formulas or to the biases in ``fe51.h``
must be mirrored here — the pinned numbers below will say so.

Reproduces the figures cited in ``src/c/fe51.h``: zero precondition
violations, and a worst-case fold of ``0xF0780000000164B2`` at ge_dbl's
``X = E * F`` (6.5% below 2^64).
"""

from __future__ import annotations

import dataclasses
from typing import Optional

import pytest

#: One field element as five per-limb ``(lo, hi)`` bounds -- the model's only
#: value type.  Every helper below consumes and produces this shape.
Bounds = list[tuple[int, int]]
#: An extended point ``(X, Y, Z, T)`` and a niels/pniels tuple.
Point = tuple[Bounds, Bounds, Bounds, Bounds]
P1P1 = tuple[Bounds, Bounds, Bounds, Bounds]


@dataclasses.dataclass
class Worst:
    """The extreme values the walk reached, and where."""

    c4x19: int = 0
    col: int = 0
    site: Optional[str] = None

    def reset(self) -> None:
        self.c4x19 = 0
        self.col = 0
        self.site = None


M51 = 2**51
bias2 = [2**52 - 38, 2**52 - 2, 2**52 - 2, 2**52 - 2, 2**52 - 2]
bias8 = [2**54 - 152, 2**54 - 8, 2**54 - 8, 2**54 - 8, 2**54 - 8]
bias4 = [2**53 - 76, 2**53 - 4, 2**53 - 4, 2**53 - 4, 2**53 - 4]  # fe51_sub (carried)
worst = Worst()
viol: list[tuple[str, str]] = []


def mul_out_bound(f: Bounds, g: Bounds, site: str) -> Bounds:
    """f, g: lists of (lo, hi).  Returns output interval and checks."""
    cols = []
    for k in range(5):
        s = 0
        for i in range(5):
            j = k - i
            if j < 0:
                j += 5
                s += 19 * f[i][1] * g[j][1]
            else:
                s += f[i][1] * g[j][1]
        cols.append(s)
    # carries: c_k = (col_k + c_{k-1}) >> 51
    c = 0
    for k in range(5):
        tot = cols[k] + c
        if tot >= 2**115:
            viol.append((site, f"column {k} = 2^{tot.bit_length()-1}+ exceeds 2^115"))
        c = tot >> 51
    c4 = c
    if 19 * c4 + M51 >= 2**64:
        viol.append((site, f"19*c4 = {19*c4:#x} overflows uint64"))
    if 19 * c4 > worst.c4x19:
        worst.c4x19 = 19 * c4
        worst.site = site
    worst.col = max(worst.col, max(cols))
    r0 = (M51 - 1) + 19 * c4
    c2 = r0 >> 51
    return [(0, M51 - 1), (0, M51 - 1 + c2), (0, M51 - 1), (0, M51 - 1), (0, M51 - 1)]


def add(f: Bounds, g: Bounds) -> Bounds:
    return [(f[i][0] + g[i][0], f[i][1] + g[i][1]) for i in range(5)]


def sub_bias(f: Bounds, g: Bounds, bias: list[int], name: str, site: str) -> Bounds:
    out = []
    for i in range(5):
        if g[i][1] > bias[i]:
            viol.append(
                (
                    site,
                    f"{name} limb {i}: subtrahend max {g[i][1]:#x} > "
                    f"bias {bias[i]:#x} (underflow possible)",
                )
            )
        out.append((f[i][0] + bias[i] - g[i][1], f[i][1] + bias[i] - g[i][0]))
    return out


def sub2(f: Bounds, g: Bounds, site: str) -> Bounds:
    return sub_bias(f, g, bias2, "sub_2p", site)


def sub8(f: Bounds, g: Bounds, site: str) -> Bounds:
    return sub_bias(f, g, bias8, "sub_8p", site)


def sub_exact(f: Bounds, g: Bounds, site: str) -> Bounds:
    sub_bias(f, g, bias4, "fe51_sub(4p)", site)
    return [(0, M51 - 1 + (60 if i == 0 else 0)) for i in range(5)]  # carried; limb0 + 19*c


def neg(f: Bounds, site: str) -> Bounds:
    return sub_exact(zero(), f, site)


def zero() -> Bounds:
    return [(0, 0)] * 5


def one() -> Bounds:
    return [(1, 1), (0, 0), (0, 0), (0, 0), (0, 0)]


def reduced() -> Bounds:
    return [(0, M51 - 1)] * 5  # table entries, constants, frombytes


# A generic mul output (worst-case: inputs at the largest bounds reached anywhere).
# Start with the fixpoint: p3 coordinates are mul outputs.
M = [(0, M51 - 1), (0, M51 + 2**13), (0, M51 - 1), (0, M51 - 1), (0, M51 - 1)]


def p1p1_to_p3(E: Bounds, H: Bounds, G: Bounds, F: Bounds, site: str) -> Point:
    X = mul_out_bound(E, F, site + "/X=E*F")
    Y = mul_out_bound(H, G, site + "/Y=H*G")
    Z = mul_out_bound(G, F, site + "/Z=G*F")
    T = mul_out_bound(E, H, site + "/T=E*H")
    return X, Y, Z, T


def ge_dbl(X: Bounds, Y: Bounds, Z: Bounds, site: str = "ge_dbl") -> P1P1:
    A = mul_out_bound(X, X, site + "/A")
    Bq = mul_out_bound(Y, Y, site + "/B")
    C = mul_out_bound(Z, Z, site + "/C")
    C = add(C, C)
    XY = add(X, Y)
    t0 = mul_out_bound(XY, XY, site + "/(X+Y)^2")
    H = add(Bq, A)
    G = sub2(Bq, A, site + "/G=B-A")
    E = sub8(t0, H, site + "/E=t0-H")
    F = sub8(C, G, site + "/F=C-G")
    return E, H, G, F


def ge_nielsadd(
    X: Bounds,
    Y: Bounds,
    Z: Bounds,
    T: Bounds,
    q_ypx: Bounds,
    q_ymx: Bounds,
    q_t2d: Bounds,
    site: str = "ge_nielsadd",
    sub: bool = False,
) -> P1P1:
    A = sub2(Y, X, site + "/A=Y-X")
    A = mul_out_bound(A, q_ypx if sub else q_ymx, site + "/A*")
    Bq = add(Y, X)
    Bq = mul_out_bound(Bq, q_ymx if sub else q_ypx, site + "/B*")
    C = mul_out_bound(T, q_t2d, site + "/C")
    D = add(Z, Z)
    E = sub2(Bq, A, site + "/E=B-A")
    H = add(Bq, A)
    if not sub:
        G = add(D, C)
        F = sub2(D, C, site + "/F=D-C")
    else:
        G = sub2(D, C, site + "/G=D-C")
        F = add(D, C)
    return E, H, G, F


def ge_pnielsadd(
    X: Bounds,
    Y: Bounds,
    Z: Bounds,
    T: Bounds,
    q_ypx: Bounds,
    q_ymx: Bounds,
    q_z: Bounds,
    q_t2d: Bounds,
    site: str = "ge_pnielsadd",
    sub: bool = False,
) -> P1P1:
    A = sub2(Y, X, site + "/A=Y-X")
    A = mul_out_bound(A, q_ypx if sub else q_ymx, site + "/A*")
    Bq = add(Y, X)
    Bq = mul_out_bound(Bq, q_ymx if sub else q_ypx, site + "/B*")
    C = mul_out_bound(T, q_t2d, site + "/C")
    D = mul_out_bound(Z, q_z, site + "/D")
    D = add(D, D)
    E = sub2(Bq, A, site + "/E=B-A")
    H = add(Bq, A)
    if not sub:
        G = add(D, C)
        F = sub2(D, C, site + "/F=D-C")
    else:
        G = sub2(D, C, site + "/G=D-C")
        F = add(D, C)
    return E, H, G, F


def ge_add(P: Point, Q: Point, site: str = "ge_add") -> P1P1:
    A = sub2(P[1], P[0], site + "/A")
    Bq = sub2(Q[1], Q[0], site + "/B")
    A = mul_out_bound(A, Bq, site + "/A*B")
    Bq = add(P[1], P[0])
    C = add(Q[1], Q[0])
    Bq = mul_out_bound(Bq, C, site + "/B*C")
    C = mul_out_bound(P[3], Q[3], site + "/T1T2")
    C = mul_out_bound(C, reduced(), site + "/C*2d")
    D = mul_out_bound(P[2], Q[2], site + "/Z1Z2")
    D = add(D, D)
    E = sub2(Bq, A, site + "/E")
    H = add(Bq, A)
    G = add(D, C)
    F = sub2(D, C, site + "/F")
    return E, H, G, F


# p3 inputs: worst = all coordinates mul outputs (also covers identity 0/1 and frombytes)
P3 = (M, M, M, M)
# also a p3 after decode: X may be fe51_neg output (carried, limb0 <= 2^51+57), T = mul
# niels table entry: reduced.  pniels: (Y+X, Y-X via sub2, Z, T*2d)
niels = (reduced(), reduced(), reduced())
pn_ypx = add(M, M)
pn_ymx = sub2(M, M, "ge_p3_to_pniels/ymx")
pn_z = M
pn_t2d = mul_out_bound(M, reduced(), "ge_p3_to_pniels/t2d")


def walk_every_site() -> None:
    """Walk every group-law site once; results land in ``viol`` / ``worst``."""
    E, H, G, F = ge_dbl(M, M, M)
    p1p1_to_p3(E, H, G, F, "ge_dbl->p3")
    E, H, G, F = ge_nielsadd(M, M, M, M, *niels)
    p1p1_to_p3(E, H, G, F, "ge_nielsadd->p3")
    E, H, G, F = ge_nielsadd(M, M, M, M, *niels, site="ge_nielssub", sub=True)
    p1p1_to_p3(E, H, G, F, "ge_nielssub->p3")
    E, H, G, F = ge_pnielsadd(M, M, M, M, pn_ypx, pn_ymx, pn_z, pn_t2d)
    p1p1_to_p3(E, H, G, F, "ge_pnielsadd->p3")
    E, H, G, F = ge_pnielsadd(
        M, M, M, M, pn_ypx, pn_ymx, pn_z, pn_t2d, site="ge_pnielssub", sub=True
    )
    p1p1_to_p3(E, H, G, F, "ge_pnielssub->p3")
    E, H, G, F = ge_add(P3, P3)
    p1p1_to_p3(E, H, G, F, "ge_add->p3")
    # ge_niels_select: neg_t2d = fe51_neg(t2d) with t2d reduced  -> fine
    neg(reduced(), "ge_niels_select/neg_t2d")
    # verify_half: GE_FE_NEG on decoded X, T (mul outputs)
    neg(M, "verify_half/neg X")
    neg(M, "verify_half/neg T")
    # ge_half_sum_is_identity: GE_FE_SUB(d, Y, Z) exact with Y,Z mul outputs
    sub_exact(M, M, "half_sum/Y-Z")
    # decode: u = y^2 - 1 (exact sub), v = d*y^2 + 1 ; etc. -- exact ops, fine
    # table-entry test path uses exact sub


def _run_model() -> tuple[list[tuple[str, str]], Worst]:
    """Return (violations, worst) for a fresh walk of every site."""
    viol.clear()
    worst.reset()
    walk_every_site()
    return list(viol), dataclasses.replace(worst)


def test_no_lazy_reduction_precondition_is_violated() -> None:
    violations, _ = _run_model()
    assert violations == [], violations


def test_worst_fold_matches_the_fe51_comment() -> None:
    """Pins the margin quoted in src/c/fe51.h (6.5%, at ge_dbl's E*F)."""
    _, w = _run_model()
    assert w.site == "ge_dbl->p3/X=E*F"
    assert w.c4x19 == 0xF0780000000164B2
    margin = 2**64 / w.c4x19
    assert 1.06 < margin < 1.07


def test_every_column_stays_below_the_128_bit_shift_width() -> None:
    _, w = _run_model()
    assert w.col < 2**115


@pytest.mark.parametrize("limb", range(5))
def test_sum_of_two_products_exceeds_the_sub_2p_bias(limb: int) -> None:
    """The precondition fe51.h now states: a fe51_add of two mul outputs is
    NOT a valid fe51_sub_2p subtrahend (limb 0 reaches 2^52 - 2 > 2^52 - 38;
    limb 1 reaches 2^52 + 2^14), so such subtrahends must use sub_8p."""
    two = add(M, M)
    if limb in (0, 1):
        assert two[limb][1] > bias2[limb]
    assert two[limb][1] <= bias8[limb]
