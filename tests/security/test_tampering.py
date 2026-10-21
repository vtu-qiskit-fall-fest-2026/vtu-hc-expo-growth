
"""Security tests for encrypted telemetry tampering."""

import pytest

from qguards.gateway.validator import GatewayValidator
from qguards.security.authentication import create_tag, generate_auth_key
from qguards.security.encryption import encrypt, generate_key
from qguards.telemetry.packet import serialize_packet


def make_valid_envelope():
    encryption_key = generate_key()
    sensor_key = generate_auth_key()
    gateway = GatewayValidator(
        encryption_key,
        {"sensor-001": sensor_key},
    )
    reading = {
        "sensor_id": "sensor-001",
        "sequence_number": 1,
        "timestamp": "2026-10-21T12:00:00+00:00",
        "temperature_c": 25.0,
        "humidity_percent": 50.0,
    }
    encrypted = encrypt(encryption_key, serialize_packet(reading))
    tag = create_tag(
        sensor_key,
        encrypted["nonce"] + encrypted["ciphertext"],
    )
    return gateway, encrypted, tag


def test_modified_ciphertext_is_rejected():
    gateway, encrypted, tag = make_valid_envelope()

    modified = encrypted.copy()
    ciphertext = bytearray(modified["ciphertext"])
    ciphertext[0] ^= 1
    modified["ciphertext"] = bytes(ciphertext)

    with pytest.raises(ValueError):
        gateway.validate(modified, tag)


def test_modified_nonce_is_rejected():
    gateway, encrypted, tag = make_valid_envelope()

    modified = encrypted.copy()
    nonce = bytearray(modified["nonce"])
    nonce[0] ^= 1
    modified["nonce"] = bytes(nonce)

    with pytest.raises(ValueError):
        gateway.validate(modified, tag)


def test_non_byte_ciphertext_is_rejected():
    gateway, encrypted, tag = make_valid_envelope()

    malformed = encrypted.copy()
    malformed["ciphertext"] = "not bytes"

    with pytest.raises(ValueError, match="byte nonce and ciphertext"):
        gateway.validate(malformed, tag)
