
import pytest
from qiskit import QuantumCircuit

from qguards.quantum.circuit_builder import build_security_circuit


def test_builds_two_qubit_circuit():
    circuit = build_security_circuit([0.2, 0.4], [0.1, 0.3])

    assert isinstance(circuit, QuantumCircuit)
    assert circuit.num_qubits == 2
    assert circuit.num_clbits == 2


def test_circuit_contains_measurements():
    circuit = build_security_circuit([0.2, 0.4], [0.1, 0.3])

    assert circuit.num_clbits == 2
    assert circuit.count_ops()["measure"] == 2


def test_circuit_contains_entangling_gates():
    circuit = build_security_circuit([0.2, 0.4], [0.1, 0.3])

    assert circuit.count_ops()["cx"] == 2


@pytest.mark.parametrize(
    "features, parameters",
    [
        ([0.1], [0.2, 0.3]),
        ([0.1, 0.2], [0.3]),
    ],
)
def test_rejects_wrong_input_lengths(features, parameters):
    with pytest.raises(ValueError, match="Exactly two"):
        build_security_circuit(features, parameters)


def test_rejects_non_finite_angle():
    with pytest.raises(ValueError, match="finite"):
        build_security_circuit([float("nan"), 0.2], [0.1, 0.3])


def test_rejects_string_angle():
    with pytest.raises(ValueError, match="finite"):
        build_security_circuit(["invalid", 0.2], [0.1, 0.3])


from qguards.quantum.simulator import run_security_circuit


def test_simulation_returns_requested_number_of_shots():
    result = run_security_circuit(
        features=[0.2, 0.8],
        parameters=[0.4, 0.6],
        shots=256,
        seed=42,
    )
    assert result["shots"] == 256
    assert sum(result["counts"].values()) == 256


def test_simulation_probabilities_sum_to_one():
    result = run_security_circuit(
        features=[0.2, 0.8],
        parameters=[0.4, 0.6],
        shots=256,
        seed=42,
    )
    assert abs(sum(result["probabilities"].values()) - 1.0) < 1e-9


def test_simulation_returns_valid_bitstrings():
    result = run_security_circuit(
        features=[0.2, 0.8],
        parameters=[0.4, 0.6],
        shots=128,
        seed=42,
    )
    assert set(result["counts"]).issubset({"00", "01", "10", "11"})


def test_simulation_returns_circuit_metrics():
    result = run_security_circuit(
        features=[0.2, 0.8],
        parameters=[0.4, 0.6],
        shots=128,
        seed=42,
    )
    assert result["circuit_depth"] > 0
    assert result["operation_counts"]


def test_simulation_rejects_invalid_shots():
    import pytest

    with pytest.raises(ValueError):
        run_security_circuit([0.2, 0.8], [0.4, 0.6], shots=0)


def test_simulation_rejects_invalid_seed():
    import pytest

    with pytest.raises(ValueError):
        run_security_circuit([0.2, 0.8], [0.4, 0.6], seed=-1)
