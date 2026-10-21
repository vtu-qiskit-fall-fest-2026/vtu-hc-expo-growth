
"""Run Q Guards quantum circuits using the local Qiskit Aer simulator."""

from qiskit import transpile
from qiskit_aer import AerSimulator

from qguards.quantum.circuit_builder import build_security_circuit


def run_security_circuit(features, parameters, shots=1024, seed=42):
    """Simulate the circuit and return reproducible measurement statistics.

    Args:
        features: Two finite rotation angles in radians.
        parameters: Two finite circuit parameters in radians.
        shots: Positive number of circuit executions.
        seed: Non-negative integer used for simulator reproducibility.

    Returns:
        Dictionary containing counts, probabilities, and circuit metrics.
    """
    if isinstance(shots, bool) or not isinstance(shots, int) or shots < 1:
        raise ValueError("shots must be a positive integer")

    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")

    circuit = build_security_circuit(features, parameters)

    simulator = AerSimulator()
    compiled_circuit = transpile(circuit, simulator, seed_transpiler=seed)

    result = simulator.run(
        compiled_circuit,
        shots=shots,
        seed_simulator=seed,
    ).result()

    counts = result.get_counts(compiled_circuit)
    total_shots = sum(counts.values())

    probabilities = {
        bitstring: count / total_shots
        for bitstring, count in counts.items()
    }

    return {
        "counts": counts,
        "probabilities": probabilities,
        "shots": total_shots,
        "circuit_depth": compiled_circuit.depth(),
        "operation_counts": {
            str(operation): int(count)
            for operation, count in compiled_circuit.count_ops().items()
        },
    }
