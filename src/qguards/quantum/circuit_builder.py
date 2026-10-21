
"""Build a small parameterized Qiskit circuit for security-event experiments."""

import math

from qiskit import QuantumCircuit


def build_security_circuit(features, parameters):
    """Build a measured two-qubit circuit.

    Args:
        features: Two finite rotation angles in radians.
        parameters: Two finite trainable rotation angles in radians.

    Returns:
        A QuantumCircuit with two qubits and two classical measurement bits.
    """
    if len(features) != 2 or len(parameters) != 2:
        raise ValueError("Exactly two features and two parameters are required")

    values = list(features) + list(parameters)
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for value in values
    ):
        raise ValueError("All angles must be finite numbers")

    circuit = QuantumCircuit(2, 2)

    # Encode the two input features.
    circuit.ry(float(features[0]), 0)
    circuit.ry(float(features[1]), 1)

    # Couple the qubits and apply trainable rotations.
    circuit.cx(0, 1)
    circuit.ry(float(parameters[0]), 0)
    circuit.ry(float(parameters[1]), 1)
    circuit.cx(0, 1)

    # Measure both qubits.
    circuit.measure([0, 1], [0, 1])

    return circuit
