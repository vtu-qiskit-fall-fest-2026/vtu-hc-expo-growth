
"""Security tests for replayed and out-of-order telemetry."""

import pytest

from qguards.gateway.validator import GatewayValidator
from qguards.security.authentication import create_tag, generate_auth_key
from qguards.security.encryption import encrypt, generate_key
from qguards.telemetry.packet import serialize_packet


@pytest.fixture
def secure_gateway():
    encryption_key = generate_key()
    sensor_key = generate_auth_key()
    gateway = GatewayValidator(
        encryption_key,
        {"sensor-001": sensor_key},
    )
    return encryption_key, sensor_key, gateway


def make_envelope(sequence_number, encryption_key, sensor_key):
    reading = {
        "sensor_id": "sensor-001",
        "sequence_number": sequence_number,
        "timestamp": "2026-10-21T12:00:00+00:00",
        "temperature_c": 25.0,
        "humidity_percent": 50.0,
    }
    encrypted = encrypt(encryption_key, serialize_packet(reading))
    tag = create_tag(
        sensor_key,
        encrypted["nonce"] + encrypted["ciphertext"],
    )
    return encrypted, tag


def test_duplicate_packet_is_rejected(secure_gateway):
    encryption_key, sensor_key, gateway = secure_gateway
    envelope = make_envelope(1, encryption_key, sensor_key)

    gateway.validate(*envelope)

    with pytest.raises(ValueError, match="Replay detected"):
        gateway.validate(*envelope)


def test_out_of_order_sequence_is_rejected(secure_gateway):
    encryption_key, sensor_key, gateway = secure_gateway
    packet_1 = make_envelope(1, encryption_key, sensor_key)
    packet_2 = make_envelope(2, encryption_key, sensor_key)

    assert gateway.validate(*packet_2)["sequence_number"] == 2

    with pytest.raises(ValueError, match="Replay detected"):
        gateway.validate(*packet_1)


def test_rejected_replay_does_not_block_next_valid_sequence(secure_gateway):
    encryption_key, sensor_key, gateway = secure_gateway
    packet_1 = make_envelope(1, encryption_key, sensor_key)
    packet_2 = make_envelope(2, encryption_key, sensor_key)

    gateway.validate(*packet_1)

    with pytest.raises(ValueError, match="Replay detected"):
        gateway.validate(*packet_1)

    assert gateway.validate(*packet_2)["sequence_number"] == 2
