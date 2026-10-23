"""ML-KEM-768 key establishment for the Q Guards prototype.

ML-KEM establishes a shared secret. It does not authenticate
the peer's identity or encrypt application messages by itself.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_keypair():
    """Generate an ML-KEM-768 private key and its public key."""
    private_key = mlkem.MLKEM768PrivateKey.generate()
    return private_key, private_key.public_key()


def encapsulate(public_key) -> tuple[bytes, bytes]:
    """Return (ciphertext, shared_secret) for the sender."""
    shared_secret, ciphertext = public_key.encapsulate()
    return ciphertext, shared_secret


def decapsulate(private_key, ciphertext: bytes) -> bytes:
    """Recover the recipient's shared secret."""
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    return private_key.decapsulate(ciphertext)


def derive_aes256_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte AES-256 key using HKDF-SHA256."""
    if not isinstance(shared_secret, bytes) or not shared_secret:
        raise ValueError("shared_secret must be non-empty bytes")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("salt must be bytes of at least 16 bytes")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"Q-Guards telemetry AES-256-GCM v1",
    ).derive(shared_secret)