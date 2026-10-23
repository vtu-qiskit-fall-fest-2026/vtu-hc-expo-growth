
"""ML-KEM-768 key establishment for Q Guards telemetry."""

import os

from qguards.security.pq_kem import (
    decapsulate,
    derive_aes256_key,
    encapsulate,
    generate_keypair,
)


def establish_gateway_keypair():
    """Generate the gateway's ML-KEM-768 key pair."""
    return generate_keypair()


def establish_sender_session_key(gateway_public_key):
    """Encapsulate to the gateway and derive the sender's AES key.

    Returns:
        ciphertext: ML-KEM encapsulation ciphertext to send to gateway.
        salt: Public HKDF salt to send with the session setup.
        aes_key: Derived 32-byte AES key for sender-side encryption.
    """
    ciphertext, shared_secret = encapsulate(gateway_public_key)
    salt = os.urandom(16)
    aes_key = derive_aes256_key(shared_secret, salt)

    return ciphertext, salt, aes_key


def establish_receiver_session_key(gateway_private_key, ciphertext, salt):
    """Decapsulate and derive the matching 32-byte gateway AES key."""
    shared_secret = decapsulate(gateway_private_key, ciphertext)
    return derive_aes256_key(shared_secret, salt)
