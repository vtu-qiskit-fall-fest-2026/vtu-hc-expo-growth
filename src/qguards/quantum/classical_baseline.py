
"""Transparent rule-based baseline for Q Guards security events."""

FEATURE_WEIGHTS = {
    "failed_auth": 0.4,
    "replay_detected": 0.3,
    "tampering_detected": 0.3,
}


def calculate_classical_score(features: dict) -> float:
    """Calculate a weighted security-event score between 0 and 1."""
    if not isinstance(features, dict):
        raise ValueError("features must be a dictionary")

    if set(features) != set(FEATURE_WEIGHTS):
        raise ValueError(
            f"features must contain exactly: {', '.join(FEATURE_WEIGHTS)}"
        )

    for name, value in features.items():
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be a Boolean")

    return round(
        sum(
            FEATURE_WEIGHTS[name]
            for name, detected in features.items()
            if detected
        ),
        2,
    )


def classify_classical_event(features: dict) -> dict:
    """Return the baseline score and a transparent heuristic verdict."""
    score = calculate_classical_score(features)

    return {
        "score": score,
        "verdict": "suspicious" if score > 0.0 else "no_signal",
        "method": "rule_based_baseline",
    }
