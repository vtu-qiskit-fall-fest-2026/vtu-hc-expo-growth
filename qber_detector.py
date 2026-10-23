
"""QBER classification for the Q Guards BB84 demonstration."""

from dataclasses import dataclass


@dataclass(frozen=True)
class QBERAssessment:
    qber: float
    threshold: float
    status: str
    alert: bool
    message: str


def assess_qber(qber: float, threshold: float = 0.11) -> QBERAssessment:
    """Classify an observed QBER using a configurable demo threshold.

    qber and threshold must be fractions between 0.0 and 1.0.
    This classification alone cannot establish that a key is secure.
    """
    if isinstance(qber, bool) or not isinstance(qber, (int, float)):
        raise ValueError("qber must be a number")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("threshold must be a number")

    if not 0.0 <= qber <= 1.0:
        raise ValueError("qber must be between 0.0 and 1.0")
    if not 0.0 < threshold < 1.0:
        raise ValueError("threshold must be greater than 0.0 and less than 1.0")

    if qber > threshold:
        return QBERAssessment(
            qber=float(qber),
            threshold=float(threshold),
            status="HIGH_ERROR_RATE",
            alert=True,
            message=(
                "Observed QBER exceeds the configured demo threshold. "
                "Flag this session for rejection or investigation."
            ),
        )

    return QBERAssessment(
        qber=float(qber),
        threshold=float(threshold),
        status="BELOW_THRESHOLD",
        alert=False,
        message=(
            "Observed QBER is within the configured demo threshold. "
            "This does not prove the session or key is secure."
        ),
    )


if __name__ == "__main__":
    for observed in (0.00, 0.04, 0.11, 0.25):
        assessment = assess_qber(observed)
        print(
            f"QBER={assessment.qber:.1%} | "
            f"status={assessment.status} | "
            f"alert={assessment.alert}"
        )
