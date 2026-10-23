
"""Educational BB84 simulation using Qiskit Aer."""

import random
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator


def _circuit(prepared_bit, prepared_basis, measurement_basis):
    circuit = QuantumCircuit(1, 1)

    if prepared_bit:
        circuit.x(0)
    if prepared_basis == "X":
        circuit.h(0)
    if measurement_basis == "X":
        circuit.h(0)

    circuit.measure(0, 0)
    return circuit


def _measure(simulator, circuits, seed):
    if not circuits:
        return []

    compiled = transpile(circuits, simulator)
    result = simulator.run(
        compiled, shots=1, seed_simulator=seed
    ).result()

    return [
        int(result.get_counts(i).most_frequent())
        for i in range(len(circuits))
    ]


def run_bb84(n_bits=128, eavesdropper=False, seed=7):
    if not isinstance(n_bits, int) or isinstance(n_bits, bool) or n_bits <= 0:
        raise ValueError("n_bits must be a positive integer")
    if not isinstance(eavesdropper, bool):
        raise ValueError("eavesdropper must be a boolean")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")

    rng = random.Random(seed)
    simulator = AerSimulator()

    alice_bits = [rng.randint(0, 1) for _ in range(n_bits)]
    alice_bases = [rng.choice(("Z", "X")) for _ in range(n_bits)]
    bob_bases = [rng.choice(("Z", "X")) for _ in range(n_bits)]

    if eavesdropper:
        eve_bases = [rng.choice(("Z", "X")) for _ in range(n_bits)]
        eve_circuits = [
            _circuit(bit, a_basis, e_basis)
            for bit, a_basis, e_basis in zip(
                alice_bits, alice_bases, eve_bases
            )
        ]
        eve_bits = _measure(simulator, eve_circuits, seed + 1)

        bob_circuits = [
            _circuit(bit, e_basis, b_basis)
            for bit, e_basis, b_basis in zip(
                eve_bits, eve_bases, bob_bases
            )
        ]
        bob_bits = _measure(simulator, bob_circuits, seed + 2)
    else:
        circuits = [
            _circuit(bit, a_basis, b_basis)
            for bit, a_basis, b_basis in zip(
                alice_bits, alice_bases, bob_bases
            )
        ]
        bob_bits = _measure(simulator, circuits, seed + 1)

    positions = [
        i for i in range(n_bits)
        if alice_bases[i] == bob_bases[i]
    ]
    alice_key = [alice_bits[i] for i in positions]
    bob_key = [bob_bits[i] for i in positions]

    errors = sum(a != b for a, b in zip(alice_key, bob_key))
    qber = errors / len(positions) if positions else 0.0

    return {
        "n_bits_sent": n_bits,
        "eavesdropper": eavesdropper,
        "sifted_bits": len(positions),
        "errors": errors,
        "qber": qber,
        "qber_percent": round(qber * 100, 2),
        "alice_sifted_key": "".join(map(str, alice_key)),
        "bob_sifted_key": "".join(map(str, bob_key)),
        "key_matches": alice_key == bob_key,
        "seed": seed,
        "simulation_only": True,
    }


if __name__ == "__main__":
    for attack in (False, True):
        result = run_bb84(n_bits=256, eavesdropper=attack, seed=42)
        print("\n--- BB84 experiment ---")
        print("Eavesdropper:", result["eavesdropper"])
        print("Bits sent:", result["n_bits_sent"])
        print("Sifted bits:", result["sifted_bits"])
        print("Errors:", result["errors"])
        print("QBER:", str(result["qber_percent"]) + "%")
        print("Keys match:", result["key_matches"])
        print("Simulation only:", result["simulation_only"])
