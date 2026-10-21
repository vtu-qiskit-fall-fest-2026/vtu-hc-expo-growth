
import pytest

from qguards.security.encryption import decrypt, encrypt, generate_key


def test_encrypt_decrypt_round_trip():
    key = generate_key()
    plaintext = b"Q Guards telemetry"
    packet = encrypt(key, plaintext)

    assert decrypt(key, packet["nonce"], packet["ciphertext"]) == plaintext


def test_each_encryption_uses_a_new_nonce():
    key = generate_key()
    first = encrypt(key, b"message")
    second = encrypt(key, b"message")

    assert first["nonce"] != second["nonce"]


def test_modified_ciphertext_is_rejected():
    key = generate_key()
    packet = encrypt(key, b"telemetry")
    modified = bytearray(packet["ciphertext"])
    modified[0] ^= 1

    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt(key, packet["nonce"], bytes(modified))


def test_wrong_key_is_rejected():
    packet = encrypt(generate_key(), b"telemetry")

    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt(generate_key(), packet["nonce"], packet["ciphertext"])


def test_modified_associated_data_is_rejected():
    key = generate_key()
    packet = encrypt(key, b"telemetry", b"sensor-001")

    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt(key, packet["nonce"], packet["ciphertext"], b"sensor-002")


def test_invalid_key_length_is_rejected():
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt(b"short", b"telemetry")


def test_invalid_nonce_length_is_rejected():
    with pytest.raises(ValueError, match="12 bytes"):
        decrypt(generate_key(), b"short", b"ciphertext")
