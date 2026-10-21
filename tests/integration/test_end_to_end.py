
import pytest

from qguards.gateway.validator import GatewayValidator
from qguards.security.authentication import create_tag, generate_auth_key
from qguards.security.encryption import encrypt, generate_key
from qguards.telemetry.packet import serialize_packet


@pytest.fixture
def setup_gateway():
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


def make_reading(sequence_number):
    return {
        "sensor_id": "sensor-001",
        "sequence_number": sequence_number,
        "timestamp": "2026-10-21T12:00:00+00:00",
        "temperature_c": 25.0,
        "humidity_percent": 50.0,
    }


def test_valid_packet_is_accepted(setup_gateway):
    encryption_key, sensor_key, gateway = setup_gateway
    encrypted, tag = make_envelope(
        make_reading(1), encryption_key, sensor_key
    )

    accepted = gateway.validate(encrypted, tag)
    assert accepted["sequence_number"] == 1


def test_replayed_packet_is_rejected(setup_gateway):
    encryption_key, sensor_key, gateway = setup_gateway
    encrypted, tag = make_envelope(
        make_reading(1), encryption_key, sensor_key
    )

    gateway.validate(encrypted, tag)
    with pytest.raises(ValueError, match="Replay detected"):
        gateway.validate(encrypted, tag)


def test_invalid_tag_is_rejected(setup_gateway):
    encryption_key, _, gateway = setup_gateway
    encrypted, _ = make_envelope(
        make_reading(1), encryption_key, generate_auth_key()
    )

    with pytest.raises(ValueError, match="Sender authentication failed"):
        gateway.validate(encrypted, b"\x00" * 32)


def test_unauthorized_sensor_is_rejected(setup_gateway):
    encryption_key, sensor_key, gateway = setup_gateway
    reading = make_reading(1)
    reading["sensor_id"] = "unknown-sensor"
    encrypted, tag = make_envelope(reading, encryption_key, sensor_key)

    with pytest.raises(ValueError, match="Unauthorized sensor"):
        gateway.validate(encrypted, tag)


def test_modified_ciphertext_is_rejected(setup_gateway):
    encryption_key, sensor_key, gateway = setup_gateway
    encrypted, tag = make_envelope(
        make_reading(1), encryption_key, sensor_key
    )
    modified = bytearray(encrypted["ciphertext"])
    modified[0] ^= 1
    encrypted["ciphertext"] = bytes(modified)

    with pytest.raises(ValueError, match="Authentication failed"):
        gateway.validate(encrypted, tag)
