
import pytest

from qguards.quantum.algorithm import calculate_quantum_score


def test_all_zero_outcomes_score_zero():
    assert calculate_quantum_score({"00": 1.0}) == 0.0


def test_all_one_outcomes_score_one():
    assert calculate_quantum_score({"11": 1.0}) == 1.0


def test_mixed_outcomes_score():
    assert calculate_quantum_score({"00": 0.25, "01": 0.25, "10": 0.25, "11": 0.25}) == 0.75


def test_empty_probabilities_rejected():
    with pytest.raises(ValueError):
        calculate_quantum_score({})


def test_probabilities_not_summing_to_one_rejected():
    with pytest.raises(ValueError):
        calculate_quantum_score({"00": 0.4, "11": 0.4})


def test_invalid_measurement_key_rejected():
    with pytest.raises(ValueError):
        calculate_quantum_score({"02": 1.0})
