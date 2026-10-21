
"""Q Guards attack demonstration runner.

Exercises the existing gateway validator against valid and malicious
telemetry. This is a software simulation, not a live IoT deployment.
"""

import json
from datetime import datetime, timezone

from qguards.telemetry.packet import serialize_packet
from qguards.security.encryption import generate_key, encrypt
from qguards.security.authentication import generate_auth_key, create_tag
from qguards.gateway.validator import GatewayValidator
from qguards.gateway.alert_manager import create_alert
from qguards.monitoring.event_logger import EventLogger
from qguards.monitoring.metrics import Metrics


def build_packet(encryption_key, auth_key, sensor_id="sensor-001"):
    """Build one encrypted and authenticated telemetry packet."""
    reading = {
        "sensor_id": sensor_id,
        "sequence_number": 1,
        "temperature_c": 28.5,
        "humidity_percent": 55.0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    plaintext = serialize_packet(reading)
    packet = encrypt(encryption_key, plaintext)
    tag = create_tag(auth_key, packet["nonce"] + packet["ciphertext"])
    return packet, tag


def run_attack_demo():
    encryption_key = generate_key()
    auth_key = generate_auth_key()
    trusted_keys = {"sensor-001": auth_key}

    metrics = Metrics()
    event_logger = EventLogger()
    results = []

    scenarios = [
        "valid",
        "tampered_ciphertext",
        "invalid_hmac",
        "unauthorized_sensor",
        "replay",
        "malformed_packet",
    ]

    for scenario in scenarios:
        validator = GatewayValidator(encryption_key, trusted_keys)
        packet, tag = build_packet(
            encryption_key,
            auth_key,
            "rogue-999" if scenario == "unauthorized_sensor" else "sensor-001",
        )

        if scenario == "tampered_ciphertext":
            modified = bytearray(packet["ciphertext"])
            modified[0] ^= 1
            packet["ciphertext"] = bytes(modified)

        elif scenario == "invalid_hmac":
            tag = bytes(32)

        elif scenario == "malformed_packet":
            packet = {"nonce": "not-bytes", "ciphertext": b"invalid"}

        metrics.record_received()

        # For replay, accept the original packet first, then submit it again.
        if scenario == "replay":
            validator.validate(packet, tag)
            metrics.record_accepted()
            event_logger.log(
                "telemetry_accepted", "Initial packet accepted before replay"
            )
            metrics.record_received()

        try:
            reading = validator.validate(packet, tag)
            accepted = True
            reason = "Packet accepted"
        except (ValueError, TypeError, KeyError) as exc:
            accepted = False
            reason = str(exc)

        expected_acceptance = scenario == "valid"
        passed = accepted == expected_acceptance

        if accepted:
            metrics.record_accepted()
            event_logger.log(
                "telemetry_accepted",
                f"Accepted telemetry from {reading['sensor_id']}",
            )
        else:
            if scenario == "tampered_ciphertext":
                event_type = "tampering_detected"
                metrics.record_tampering()
            elif scenario == "invalid_hmac":
                event_type = "authentication_failure"
                metrics.record_authentication_failure()
            elif scenario == "unauthorized_sensor":
                event_type = "unauthorized_sender"
                metrics.record_unauthorized_sender()
            elif scenario == "replay":
                event_type = "replay_detected"
                metrics.record_replay_attack()
            else:
                event_type = "invalid_packet"
                metrics.record_rejected()

            alert = create_alert(
                event_type,
                f"{scenario}: {reason}",
                severity="HIGH",
            )
            event_logger.log("telemetry_rejected", alert["message"])

        results.append({
            "scenario": scenario,
            "expected": "accept" if expected_acceptance else "reject",
            "actual": "accept" if accepted else "reject",
            "result": "PASS" if passed else "FAIL",
            "reason": reason,
        })

    return {
        "scenario_results": results,
        "all_scenarios_passed": all(
            item["result"] == "PASS" for item in results
        ),
        "metrics": metrics.snapshot(),
        "events": event_logger.get_events(),
    }


if __name__ == "__main__":
    print(json.dumps(run_attack_demo(), indent=2))
