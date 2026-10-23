
"""Q Guards: ML-KEM-secured IoT telemetry demonstration."""

import json
import logging

from qguards.telemetry.sensor_simulator import SensorSimulator
from qguards.telemetry.packet import serialize_packet
from qguards.security.encryption import encrypt
from qguards.security.key_exchange import (
    establish_gateway_keypair,
    establish_sender_session_key,
    establish_receiver_session_key,
)
from qguards.security.authentication import generate_auth_key, create_tag
from qguards.gateway.validator import GatewayValidator
from qguards.gateway.alert_manager import create_alert
from qguards.monitoring.event_logger import EventLogger
from qguards.monitoring.metrics import Metrics

logger = logging.getLogger("qguards")


def run_demo() -> dict:
    """Run one ML-KEM key-establishment and secure telemetry exchange."""

    # Simulated sensor and gateway.
    sensor = SensorSimulator(sensor_id="sensor-001", seed=42)

    # The gateway generates its ML-KEM-768 key pair.
    gateway_private_key, gateway_public_key = establish_gateway_keypair()

    # The sender encapsulates to the gateway's public key.
    kem_ciphertext, kem_salt, sender_encryption_key = (
        establish_sender_session_key(gateway_public_key)
    )

    # The gateway decapsulates and derives the same session key.
    gateway_encryption_key = establish_receiver_session_key(
        gateway_private_key,
        kem_ciphertext,
        kem_salt,
    )

    if sender_encryption_key != gateway_encryption_key:
        raise RuntimeError("ML-KEM session key agreement failed")

    # Separate sensor authentication key; ML-KEM does not authenticate identity.
    auth_key = generate_auth_key()

    validator = GatewayValidator(
        encryption_key=gateway_encryption_key,
        sensor_auth_keys={"sensor-001": auth_key},
    )

    event_logger = EventLogger()
    metrics = Metrics()

    # Generate and serialize a sensor reading.
    reading = sensor.generate_reading()
    plaintext = serialize_packet(reading)

    # Encrypt using the sender's ML-KEM-derived AES-256 key.
    encrypted_packet = encrypt(sender_encryption_key, plaintext)

    # Authenticate the encrypted packet with the existing sensor HMAC key.
    authenticated_bytes = (
        encrypted_packet["nonce"] + encrypted_packet["ciphertext"]
    )
    auth_tag = create_tag(auth_key, authenticated_bytes)

    metrics.record_received()

    try:
        accepted_reading = validator.validate(
            encrypted_packet,
            auth_tag,
        )

        metrics.record_accepted()
        event_logger.log(
            "telemetry_accepted",
            f"Accepted telemetry from {accepted_reading['sensor_id']}",
        )

        outcome = {
            "status": "accepted",
            "reading": accepted_reading,
            "key_establishment": "ML-KEM-768",
            "encryption": "AES-256-GCM",
            "sender_authentication": "HMAC",
        }

    except (ValueError, TypeError, KeyError) as exc:
        metrics.record_rejected()

        error_text = str(exc).lower()

        if "replay" in error_text or "sequence number" in error_text:
            event_type = "replay_detected"
        elif "authentication" in error_text or "tag" in error_text:
            event_type = "authentication_failure"
        elif "unauthorized" in error_text:
            event_type = "unauthorized_sender"
        else:
            event_type = "invalid_packet"

        alert = create_alert(
            event_type,
            f"Gateway rejected telemetry: {exc}",
            severity="HIGH",
        )
        event_logger.log("telemetry_rejected", alert["message"])

        outcome = {
            "status": "rejected",
            "reason": str(exc),
            "alert": alert,
        }

    return {
        "outcome": outcome,
        "metrics": metrics.snapshot(),
        "events": event_logger.get_events(),
    }


def main() -> None:
    """Run the demo and print its JSON report."""
    logging.basicConfig(level=logging.INFO)
    report = run_demo()
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
