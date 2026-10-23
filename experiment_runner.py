
"""Top-level integration for the Q Guards BB84 demonstration."""

from bb84_protocol import run_bb84
from qber_detector import assess_qber


def run_experiment(
    n_bits: int = 256,
    eavesdropper: bool = False,
    seed: int = 42,
    threshold: float = 0.11,
) -> dict:
    """Run BB84, assess QBER, and return an integrated demo report."""

    quantum_result = run_bb84(
        n_bits=n_bits,
        eavesdropper=eavesdropper,
        seed=seed,
    )

    assessment = assess_qber(
        quantum_result["qber"],
        threshold=threshold,
    )

    # This is a demonstration decision, not a production security verdict.
    if assessment.alert:
        decision = "REJECT_DEMO_SESSION"
    else:
        decision = "BELOW_THRESHOLD_DEMO_ONLY"

    return {
        "project": "Q Guards",
        "simulation_only": True,
        "bits_sent": quantum_result["n_bits_sent"],
        "sifted_bits": quantum_result["sifted_bits"],
        "observed_errors": quantum_result["errors"],
        "qber": quantum_result["qber"],
        "qber_percent": quantum_result["qber_percent"],
        "threshold": assessment.threshold,
        "alert": assessment.alert,
        "status": assessment.status,
        "decision": decision,
        "keys_match_in_simulation": quantum_result["key_matches"],
        "production_security_established": False,
    }


def print_report(report: dict) -> None:
    """Print a readable report without exposing the simulated key bits."""
    print("\n========== Q GUARDS EXPERIMENT ==========")
    print("Simulation only:", report["simulation_only"])
    print("Bits sent:", report["bits_sent"])
    print("Sifted bits:", report["sifted_bits"])
    print("Observed errors:", report["observed_errors"])
    print(f"Measured QBER: {report['qber_percent']:.2f}%")
    print(f"Demo threshold: {report['threshold']:.2%}")
    print("Alert:", report["alert"])
    print("Status:", report["status"])
    print("Demo decision:", report["decision"])
    print("Keys match in simulation:", report["keys_match_in_simulation"])
    print(
        "Production security established:",
        report["production_security_established"],
    )
    print("=========================================\n")


if __name__ == "__main__":
    for attack in (False, True):
        report = run_experiment(
            n_bits=256,
            eavesdropper=attack,
            seed=42,
        )
        print("Eavesdropper enabled:", attack)
        print_report(report)
