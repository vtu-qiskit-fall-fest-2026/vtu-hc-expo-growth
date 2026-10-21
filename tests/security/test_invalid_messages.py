
"""Security tests for malformed messages and invalid senders."""

import pytest

from qguards.gateway.validator import GatewayValidator
from qguards.security.authentication import create_tag, generate_auth_key
from qguards.security.encryption import encrypt, generate_key
from qguards.telemetry.packet import serialize_packet


@pytest.fixture
def secure_setup():
    encryption_key = generate_key()
    sensor_key = generate_auth_key()
    gateway = GatewayValidator(
        encryption_key,
        {"sensor-001": sensor_key},
    )
    return encryption_key, sensor_key, gateway


def make_envelope(reading, encryption_key, sensor_key):
    encrypted = encrypt(encryption_key, serialize_packet(reading))
    tag = create_tag(
        sensor_key,
        encrypted["nonce"] + encrypted["ciphertext"],
    )
    return encrypted, tag


def valid_reading():
    return {
        "sensor_id": "sensor-001",
        "sequence_number": 1,
        "timestamp": "2026-10-21T12:00:00+00:00",
        "temperature_c": 25.0,
        "humidity_percent": 50.0,
    }


def test_invalid_authentication_tag_is_rejected(secure_setup):
    encryption_key, sensor_key, gateway = secure_setup
    encrypted, _ = make_envelope(
        valid_reading(), encryption_key, sensor_key
    )

    with pytest.raises(ValueError, match="Sender authentication failed"):
        gateway.validate(encrypted, b"\x00" * 32)


def test_unauthorized_sensor_is_rejected(secure_setup):
    encryption_key, sensor_key, gateway = secure_setup
    reading = valid_reading()
    reading["sensor_id"] = "unknown-sensor"
    encrypted, tag = make_envelope(
        reading, encryption_key, sensor_key
    )

    with pytest.raises(ValueError, match="Unauthorized sensor"):
        gateway.validate(encrypted, tag)


@pytest.mark.parametrize(
    "malformed_packet",
    [
        None,
        "not a packet",
        {},
        {"nonce": "not bytes", "ciphertext": b"data"},
        {"nonce": b"nonce", "ciphertext": None},
    ],
)
def test_malformed_envelope_is_rejected(secure_setup, malformed_packet):
    _, _, gateway = secure_setup

    with pytest.raises(ValueError):
        gateway.validate(malformed_packet, b"\x00" * 32)


def test_wrong_encryption_key_is_rejected(secure_setup):
    encryption_key, sensor_key, _ = secure_setup
    encrypted, tag = make_envelope(
        valid_reading(), encryption_key, sensor_key
    )

    wrong_key_gateway = GatewayValidator(
        generate_key(),
        {"sensor-001": sensor_key},
    )

    with pytest.raises(ValueError):
        wrong_key_gateway.validate(encrypted, tag)
