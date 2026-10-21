
"""Summarize Qiskit measurement outcomes for security experiments."""


def calculate_quantum_score(probabilities: dict) -> float:
    """Return the probability of observing a non-zero measurement.

    This is an experimental circuit statistic, not a security verdict.
    """
    if not isinstance(probabilities, dict) or not probabilities:
        raise ValueError("probabilities must be a non-empty dictionary")

    total = 0.0

    for bitstring, probability in probabilities.items():
        if not isinstance(bitstring, str) or not bitstring:
            raise ValueError("Measurement keys must be non-empty strings")

        if any(bit not in "01" for bit in bitstring):
            raise ValueError("Measurement keys must contain only 0 and 1")

        if (
            isinstance(probability, bool)
            or not isinstance(probability, (int, float))
            or not 0.0 <= probability <= 1.0
        ):
            raise ValueError("Probabilities must be between 0 and 1")

        total += probability

    if abs(total - 1.0) > 1e-6:
        raise ValueError("Probabilities must sum to 1")

    return sum(
        probability
        for bitstring, probability in probabilities.items()
        if "1" in bitstring
    )
