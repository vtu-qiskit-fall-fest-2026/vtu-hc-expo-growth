
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator


def main():
    # Create a one-qubit circuit with one classical bit.
    circuit = QuantumCircuit(1, 1)

    # Put the qubit into an equal superposition.
    circuit.h(0)

    # Measure the qubit.
    circuit.measure(0, 0)

    simulator = AerSimulator()
    compiled_circuit = transpile(circuit, simulator)

    # Run 1,000 independent circuit shots.
    result = simulator.run(
        compiled_circuit,
        shots=1000,
        seed_simulator=42,
    ).result()

    counts = result.get_counts()

    print("Q GUARDS - QISKIT SMOKE TEST")
    print("Circuit:")
    print(circuit.draw(output="text"))
    print("Measurement counts:", counts)
    print("Total shots:", sum(counts.values()))

    assert sum(counts.values()) == 1000
    assert set(counts).issubset({"0", "1"})

    print("TEST PASSED: Qiskit circuit executed successfully.")


if __name__ == "__main__":
    main()
