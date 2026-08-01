# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""``numpy.ndarray`` interoperability for the analytics math layer.

What broke, and where
---------------------
``AmaEquationEngine.converge()`` accepted only ``ama_cryptography._numeric``
types, and failed on anything else four frames below the public call::

    >>> engine.converge(numpy.random.randn(100) * 0.5)
    ValueError: matmul: Input operand 0 does not have enough dimensions
    (has 0, gufunc core with signature (n?,k),(k,m?)->(n?,m?) requires 1)

raised from ``_term_ethical_gradient``'s ``self.ethical_matrix @ state``.  The
root cause was not in the engine: ``Mat`` implemented ``__getitem__`` but not
``__len__``, so ``numpy`` could not see it as a sequence, classified it as a
0-dimensional object scalar, and refused the ``matmul``.  The shipped
``examples/python/complete_demo.py`` builds its initial state with
``numpy.random.randn``, so that example could not run at all.

What this module pins
---------------------
Three layers, because a fix at only one of them would leave the other two able
to regress silently:

* ``Mat``/``Vec`` convert to correctly shaped ``numpy`` arrays (the root
  cause).
* :func:`asvec` / :func:`asmat` accept every array-like the engine advertises
  and reject the rest with a message that names the shape or type.
* ``converge``/``step`` and the public ``equations`` entry points produce
  **bit-identical** results on the ndarray path and the ``Vec`` path — the
  property that makes "accepts ndarray" mean something more than "does not
  raise".

The ``asvec``/``asmat`` layer is also tested through a stub that mimics the
``shape``/``tolist()`` protocol, so the coercion contract stays covered on
installs without ``numpy`` — which is every default install, since the library
has no runtime dependencies.
"""

from __future__ import annotations

from typing import Any

import pytest

from ama_cryptography._numeric import Mat, Vec, asmat, asvec, eye, norm
from ama_cryptography.double_helix_engine import AmaEquationEngine
from ama_cryptography.equations import (
    calculate_sigma_quadratic,
    enforce_sigma_quadratic_threshold,
    lyapunov_function,
)

try:
    import numpy as _numpy

    numpy: Any = _numpy
    HAVE_NUMPY = True
except ImportError:  # pragma: no cover - exercised on installs without numpy
    numpy = None
    HAVE_NUMPY = False

requires_numpy = pytest.mark.skipif(not HAVE_NUMPY, reason="numpy is not installed")


class _ArrayLike:
    """Minimal stand-in for an ndarray: ``shape`` plus ``tolist()``.

    Exists so the coercion contract is covered without ``numpy``.  ``asvec``
    and ``asmat`` are duck-typed on exactly these two attributes precisely so
    that the library never has to import an array package, and a test that can
    only run when ``numpy`` happens to be installed would not be checking that
    property — it would be checking ``numpy``.
    """

    def __init__(self, data: Any, shape: tuple[int, ...]) -> None:
        self._data = data
        self.shape = shape

    def tolist(self) -> Any:
        return self._data


# ---------------------------------------------------------------------------
# The root cause: Mat must be a sequence, so numpy can see its dimensions
# ---------------------------------------------------------------------------


class TestMatIsASequence:
    def test_len_is_the_row_count(self) -> None:
        assert len(Mat([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])) == 2

    def test_iteration_yields_rows(self) -> None:
        rows = list(Mat([[1.0, 2.0], [3.0, 4.0]]))
        assert rows == [[1.0, 2.0], [3.0, 4.0]]

    def test_tolist_is_a_copy(self) -> None:
        m = Mat([[1.0, 2.0], [3.0, 4.0]])
        copied = m.tolist()
        copied[0][0] = 99.0
        assert m[0, 0] == 1.0

    def test_empty_matrix_has_zero_rows(self) -> None:
        assert len(Mat([])) == 0

    @requires_numpy
    def test_numpy_sees_a_2d_float_array(self) -> None:
        """The regression itself: without ``__len__`` this was a 0-D object."""
        arr = numpy.asarray(eye(4))
        assert arr.shape == (4, 4)
        assert arr.dtype == numpy.float64
        assert numpy.array_equal(arr, numpy.eye(4))

    @requires_numpy
    def test_numpy_sees_vec_as_a_1d_float_array(self) -> None:
        arr = numpy.asarray(Vec([1.0, 2.0, 3.0]))
        assert arr.shape == (3,)
        assert arr.dtype == numpy.float64

    @requires_numpy
    def test_mat_matmul_ndarray_no_longer_raises(self) -> None:
        """The exact expression from ``_term_ethical_gradient``.

        This is the assertion that fails on the unfixed tree, with the
        ``matmul: Input operand 0 does not have enough dimensions`` message
        quoted in this module's docstring.
        """
        product = numpy.asarray(eye(3)) @ numpy.array([1.0, 2.0, 3.0])
        assert numpy.allclose(product, [1.0, 2.0, 3.0])


# ---------------------------------------------------------------------------
# asvec / asmat: what is accepted, and how the rest is refused
# ---------------------------------------------------------------------------


class TestAsvecAccepts:
    def test_vec_round_trips(self) -> None:
        v = Vec([1.0, 2.0])
        assert asvec(v).tolist() == [1.0, 2.0]

    def test_vec_is_copied_by_default(self) -> None:
        v = Vec([1.0, 2.0])
        out = asvec(v)
        out[0] = 99.0
        assert v[0] == 1.0

    def test_vec_is_passed_through_when_copy_is_false(self) -> None:
        v = Vec([1.0, 2.0])
        assert asvec(v, copy=False) is v

    @pytest.mark.parametrize(
        "value",
        [[1, 2, 3], (1.0, 2.0, 3.0), range(1, 4), iter([1, 2, 3])],
        ids=["list", "tuple", "range", "iterator"],
    )
    def test_plain_sequences(self, value: Any) -> None:
        assert asvec(value).tolist() == [1.0, 2.0, 3.0]

    def test_empty_sequence(self) -> None:
        assert asvec([]).tolist() == []

    def test_array_like_protocol_without_numpy(self) -> None:
        stub = _ArrayLike([1.0, 2.0, 3.0], (3,))
        assert asvec(stub).tolist() == [1.0, 2.0, 3.0]

    def test_integers_and_bools_widen_to_float(self) -> None:
        assert asvec([1, True, 0]).tolist() == [1.0, 1.0, 0.0]

    @requires_numpy
    def test_numpy_1d(self) -> None:
        assert asvec(numpy.array([1.0, 2.0, 3.0])).tolist() == [1.0, 2.0, 3.0]

    @requires_numpy
    @pytest.mark.parametrize("dtype", ["float32", "float64", "int32", "int64"])
    def test_numpy_dtypes(self, dtype: str) -> None:
        assert asvec(numpy.array([1, 2, 3], dtype=dtype)).tolist() == [1.0, 2.0, 3.0]


class TestAsvecRefuses:
    def test_mat_names_its_shape(self) -> None:
        with pytest.raises(ValueError, match=r"2-D Mat with shape \(2, 2\)"):
            asvec(eye(2))

    def test_nested_sequences(self) -> None:
        with pytest.raises(ValueError, match="nested sequences"):
            asvec([[1.0], [2.0]])

    @pytest.mark.parametrize("value", [b"abc", "abc", bytearray(b"abc")])
    def test_byte_and_text_sequences(self, value: Any) -> None:
        with pytest.raises(TypeError, match="not numeric vectors"):
            asvec(value)

    def test_non_iterable(self) -> None:
        with pytest.raises(TypeError, match="neither a Vec"):
            asvec(object())

    def test_non_numeric_element_is_named(self) -> None:
        with pytest.raises(TypeError, match=r"got str \('a'\)"):
            asvec([1.0, "a"])

    def test_complex_element_is_refused(self) -> None:
        with pytest.raises(TypeError, match="must be real numbers"):
            asvec([1 + 2j])

    def test_two_dimensional_array_like_points_at_asmat(self) -> None:
        stub = _ArrayLike([[1.0, 2.0], [3.0, 4.0]], (2, 2))
        with pytest.raises(ValueError, match=r"shape \(2, 2\).*asmat"):
            asvec(stub)

    def test_zero_dimensional_array_like(self) -> None:
        stub = _ArrayLike(3.0, ())
        with pytest.raises(ValueError, match="0-D scalar"):
            asvec(stub)

    @requires_numpy
    def test_numpy_2d(self) -> None:
        with pytest.raises(ValueError, match=r"shape \(2, 2\)"):
            asvec(numpy.zeros((2, 2)))

    @requires_numpy
    def test_numpy_scalar(self) -> None:
        with pytest.raises(ValueError, match="0-D scalar"):
            asvec(numpy.float64(3.0))


class TestAsmat:
    def test_mat_is_copied_by_default(self) -> None:
        m = eye(2)
        out = asmat(m)
        out[0, 0] = 99.0
        assert m[0, 0] == 1.0

    def test_mat_is_passed_through_when_copy_is_false(self) -> None:
        m = eye(2)
        assert asmat(m, copy=False) is m

    def test_nested_lists(self) -> None:
        m = asmat([[1, 2], [3, 4]])
        assert (m.rows, m.cols) == (2, 2)
        assert m[1, 0] == 3.0

    def test_array_like_protocol_without_numpy(self) -> None:
        stub = _ArrayLike([[1.0, 2.0], [3.0, 4.0]], (2, 2))
        assert asmat(stub).tolist() == [[1.0, 2.0], [3.0, 4.0]]

    def test_empty(self) -> None:
        m = asmat([])
        assert (m.rows, m.cols) == (0, 0)

    def test_vec_points_at_asvec(self) -> None:
        with pytest.raises(ValueError, match="1-D Vec of length 2"):
            asmat(Vec([1.0, 2.0]))

    def test_ragged_rows_name_the_offending_row(self) -> None:
        with pytest.raises(ValueError, match="row 0 has 2 columns but row 1 has 1"):
            asmat([[1, 2], [3]])

    def test_scalar_row(self) -> None:
        with pytest.raises(ValueError, match="row 1 is int"):
            asmat([[1, 2], 3])

    @requires_numpy
    def test_numpy_2d(self) -> None:
        assert asmat(numpy.eye(2)).tolist() == [[1.0, 0.0], [0.0, 1.0]]

    @requires_numpy
    def test_numpy_1d_points_at_asvec(self) -> None:
        with pytest.raises(ValueError, match=r"shape \(3,\).*asvec"):
            asmat(numpy.zeros(3))


# ---------------------------------------------------------------------------
# The engine: both paths accepted, and they agree exactly
# ---------------------------------------------------------------------------

DIM = 12
SEED = 42


def _initial_values() -> list[float]:
    """A fixed start, so the ndarray and Vec runs are comparable."""
    return [((i * 37) % 23) / 10.0 - 1.1 for i in range(DIM)]


def _engine() -> AmaEquationEngine:
    return AmaEquationEngine(state_dim=DIM, random_seed=SEED)


class TestConvergeAcceptsBothPaths:
    def test_vec_path(self) -> None:
        final, history = _engine().converge(Vec(_initial_values()), max_steps=8)
        assert isinstance(final, Vec)
        assert len(final) == DIM
        assert 0 < len(history) <= 8

    def test_list_path(self) -> None:
        final, _history = _engine().converge(_initial_values(), max_steps=8)
        assert isinstance(final, Vec)
        assert len(final) == DIM

    def test_array_like_path_without_numpy(self) -> None:
        stub = _ArrayLike(_initial_values(), (DIM,))
        final, _ = _engine().converge(stub, max_steps=8)
        assert isinstance(final, Vec)
        assert len(final) == DIM

    @requires_numpy
    def test_ndarray_path(self) -> None:
        """The reproducer from the bug report, as an assertion."""
        final, history = _engine().converge(numpy.array(_initial_values()), max_steps=8)
        assert isinstance(final, Vec)
        assert len(final) == DIM
        assert len(history) > 0

    @requires_numpy
    def test_ndarray_and_vec_agree_bit_for_bit(self) -> None:
        """Accepting an ndarray is only a fix if it computes the same thing.

        Both engines are seeded identically and the same numbers go in, so
        every float on both paths must match exactly — not approximately.  A
        coercion that silently rounded, reordered or truncated would pass a
        "does not raise" test and fail this one.
        """
        vec_final, vec_history = _engine().converge(Vec(_initial_values()), max_steps=8)
        arr_final, arr_history = _engine().converge(numpy.array(_initial_values()), max_steps=8)
        assert arr_final.tolist() == vec_final.tolist()
        assert arr_history == vec_history

    @requires_numpy
    def test_result_converts_back_to_ndarray(self) -> None:
        final, _ = _engine().converge(numpy.array(_initial_values()), max_steps=4)
        arr = numpy.asarray(final)
        assert arr.shape == (DIM,)
        assert arr.dtype == numpy.float64

    @requires_numpy
    def test_the_callers_array_is_not_modified(self) -> None:
        start = numpy.array(_initial_values())
        untouched = start.copy()
        _engine().converge(start, max_steps=6)
        assert numpy.array_equal(start, untouched)

    def test_none_still_draws_a_random_start(self) -> None:
        final, history = _engine().converge(None, max_steps=4)
        assert len(final) == DIM
        assert len(history) > 0


class TestStepAcceptsBothPaths:
    def test_vec_path(self) -> None:
        assert isinstance(_engine().step(Vec(_initial_values())), Vec)

    def test_list_path(self) -> None:
        assert isinstance(_engine().step(_initial_values()), Vec)

    @requires_numpy
    def test_ndarray_path(self) -> None:
        assert isinstance(_engine().step(numpy.array(_initial_values())), Vec)

    @requires_numpy
    def test_iterated_stepping_matches_the_vec_path(self) -> None:
        """``complete_demo.demo_performance`` drives ``step`` in a loop.

        The two runs are sequential, not interleaved: ``_numeric.random`` is a
        module singleton that ``AmaEquationEngine.__init__`` reseeds, so
        alternating steps between two engines would have them draw from one
        shared stream and diverge for a reason that has nothing to do with the
        input type.
        """

        def _run(start: Any) -> list[float]:
            engine = _engine()
            state: Vec = engine.step(start, 0)
            for i in range(1, 5):
                state = engine.step(state, i)
            return state.tolist()

        assert _run(numpy.array(_initial_values())) == _run(Vec(_initial_values()))


class TestEngineRejectsBadStates:
    def test_wrong_length_names_both_numbers(self) -> None:
        with pytest.raises(ValueError, match=r"has 5 elements but this engine .*state_dim=12"):
            _engine().converge([0.0] * 5, max_steps=1)

    def test_error_names_the_argument(self) -> None:
        with pytest.raises(ValueError, match=r"converge\(initial_state=\.\.\.\)"):
            _engine().converge([0.0] * 5, max_steps=1)

    def test_step_error_names_its_own_argument(self) -> None:
        with pytest.raises(ValueError, match=r"step\(state=\.\.\.\)"):
            _engine().step([0.0] * 5)

    def test_non_numeric(self) -> None:
        with pytest.raises(TypeError):
            _engine().converge("not a state", max_steps=1)

    def test_negative_max_steps(self) -> None:
        with pytest.raises(ValueError, match="max_steps must be >= 0"):
            _engine().converge([0.0] * DIM, max_steps=-1)

    def test_negative_tolerance(self) -> None:
        with pytest.raises(ValueError, match="tolerance must be >= 0"):
            _engine().converge([0.0] * DIM, tolerance=-1.0)

    def test_zero_max_steps_returns_the_input(self) -> None:
        values = _initial_values()
        final, history = _engine().converge(values, max_steps=0)
        assert history == []
        assert final.tolist() == values

    @requires_numpy
    def test_two_dimensional_ndarray(self) -> None:
        with pytest.raises(ValueError, match=r"shape \(2, 12\)"):
            _engine().converge(numpy.zeros((2, DIM)), max_steps=1)


class TestConvergeInstabilityRollback:
    """The rollback used to be unreachable, and nothing noticed.

    ``converge`` tested ``lyapunov_derivative(V) > 0``.  That function returns
    the analytic model ``V̇ = -2λV`` with ``λ = 0.18``, and ``V = ||x - x*||²``
    is non-negative by construction, so the expression is ``<= 0`` for every
    input it can be given: the branch, its rollback and its comment could
    never execute.  The only test that named the mechanism asserted that
    ``converge`` returned something not-None, which it did either way.
    """

    def test_the_analytic_derivative_can_never_be_positive(self) -> None:
        """Why the old condition was dead, asserted rather than argued."""
        from ama_cryptography.equations import lyapunov_derivative

        for V in (0.0, 1e-12, 1.0, 1e6, 1e300):
            assert lyapunov_derivative(V) <= 0.0

    @pytest.mark.parametrize("seed", [42, 7, 2026])
    def test_history_is_non_increasing_after_the_warm_up(self, seed: int) -> None:
        """What the guard is for: no retained step raises V past the warm-up.

        This is the assertion that fails on the unfixed tree, and it fails
        loudly: with the default weights V rises monotonically for the whole
        run, so ``converge`` retained 7 to 12 increasing steps depending on the
        seed.  Three seeds, so the result is a property of the guard and not of
        one lucky draw.
        """
        _, history = AmaEquationEngine(state_dim=DIM, random_seed=seed).converge(
            _initial_values(), max_steps=50
        )
        rises = [i for i in range(6, len(history)) if history[i] > history[i - 1]]
        assert not rises, f"steps {rises} raised V and were kept"

    @pytest.mark.parametrize("seed", [42, 7, 2026])
    def test_stops_while_the_trajectory_is_still_moving(self, seed: int) -> None:
        """Non-vacuity, from the other side: *which* exit ended the loop.

        ``len(history) < max_steps`` alone proves nothing — the unfixed
        ``converge`` also stopped early, on the convergence test, once the
        state had ground to a halt.  The two exits are distinguishable by what
        the trajectory is doing at the moment of the stop: after a convergence
        exit one more step moves the state by less than ``tolerance`` (measured
        on the unfixed tree: exactly 0.0, for every seed), while the guard
        stops mid-flight.
        """
        engine = AmaEquationEngine(state_dim=DIM, random_seed=seed)
        final, history = engine.converge(_initial_values(), max_steps=50)
        assert len(history) < 50, "converge ran to max_steps"
        moved = norm(engine.step(final, len(history)) - final)
        assert moved > 1e-4, (
            "the loop exited on the convergence test, not the instability "
            f"guard: one more step moves the state by {moved}"
        )

    @pytest.mark.parametrize("seed", [42, 7, 2026])
    def test_history_ends_on_the_returned_state(self, seed: int) -> None:
        """``history[-1]`` must be ``V(final_state)``, including after a rollback.

        Exact equality, not a tolerance: the same float was computed once and
        stored, so anything but an exact match means the wrong entry was kept.
        The rollback branch discards the rejected step's value for this reason;
        keeping it would have left a caller plotting ``history`` against
        ``final_state`` reading one step past the answer.  This pins the new
        path rather than reproducing an old failure: while the branch was dead
        the mismatch was unreachable, so driving the *unfixed* ``converge``
        with a ``Vec`` satisfies this property as well.
        """
        engine = AmaEquationEngine(state_dim=DIM, random_seed=seed)
        final, history = engine.converge(_initial_values(), max_steps=50)
        assert history
        assert history[-1] == lyapunov_function(final, engine.target_state)


# ---------------------------------------------------------------------------
# equations.py: the same coercion on the public math entry points
# ---------------------------------------------------------------------------


class TestEquationsAcceptArrayLikes:
    def test_lyapunov_function_on_lists(self) -> None:
        assert lyapunov_function([1.0, 2.0], [0.0, 0.0]) == pytest.approx(5.0)

    def test_lyapunov_function_length_mismatch(self) -> None:
        with pytest.raises(ValueError, match="state has 2 elements but target has 3"):
            lyapunov_function([1.0, 2.0], [0.0, 0.0, 0.0])

    def test_sigma_quadratic_on_lists(self) -> None:
        assert calculate_sigma_quadratic([1.0, 0.0], [[2.0, 0.0], [0.0, 2.0]]) == pytest.approx(2.0)

    def test_sigma_quadratic_zero_state(self) -> None:
        assert calculate_sigma_quadratic([0.0, 0.0], eye(2)) == 0.0

    def test_sigma_quadratic_rejects_a_mismatched_matrix(self) -> None:
        with pytest.raises(ValueError, match=r"E has shape \(3, 3\).*side 2"):
            calculate_sigma_quadratic([1.0, 2.0], eye(3))

    def test_enforce_returns_a_vec_on_the_pass_branch(self) -> None:
        ok, corrected = enforce_sigma_quadratic_threshold([1.0, 0.0], eye(2) * 2.0)
        assert ok is True
        assert isinstance(corrected, Vec)

    def test_enforce_returns_a_vec_on_the_correction_branch(self) -> None:
        ok, corrected = enforce_sigma_quadratic_threshold([1.0, 0.0], eye(2) * 0.5)
        assert ok is False
        assert isinstance(corrected, Vec)

    def test_enforce_never_aliases_the_caller_s_vec(self) -> None:
        """Both branches return a new ``Vec``.

        The pass branch used to hand back the caller's own object while the
        correction branch built a new one, so whether the result aliased the
        input depended on the data.
        """
        original = Vec([1.0, 0.0])
        _, corrected = enforce_sigma_quadratic_threshold(original, eye(2) * 2.0)
        assert corrected is not original

    @requires_numpy
    def test_sigma_quadratic_with_ndarray_operands(self) -> None:
        """``Mat @ ndarray`` was the original ``matmul`` failure."""
        state = numpy.array([1.0, 0.0, 0.0])
        assert calculate_sigma_quadratic(state, numpy.eye(3) * 3.0) == pytest.approx(3.0)
        assert calculate_sigma_quadratic(state, eye(3) * 3.0) == pytest.approx(3.0)

    @requires_numpy
    def test_lyapunov_function_with_ndarray_operands(self) -> None:
        assert lyapunov_function(numpy.array([3.0, 4.0]), numpy.zeros(2)) == pytest.approx(25.0)
