
"""AES-256-GCM authenticated encryption for Q Guards telemetry."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH = 32
NONCE_LENGTH = 12


def generate_key() -> bytes:
    """Generate a cryptographically random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes | None = None,
) -> dict:
    """Encrypt bytes and return the nonce and authenticated ciphertext."""
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise ValueError("Key must be exactly 32 bytes")

    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes")

    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("Associated data must be bytes or None")

    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)

    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate; reject modified data or an incorrect key."""
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise ValueError("Key must be exactly 32 bytes")

    if not isinstance(nonce, bytes) or len(nonce) != NONCE_LENGTH:
        raise ValueError("Nonce must be exactly 12 bytes")

    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes")

    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("Associated data must be bytes or None")

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise ValueError(
            "Authentication failed: incorrect key or modified data"
        ) from exc
