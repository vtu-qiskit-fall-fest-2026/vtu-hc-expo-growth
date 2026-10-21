
"""HMAC-SHA-256 sender authentication for Q Guards."""

import hashlib
import hmac


TAG_LENGTH = hashlib.sha256().digest_size


def generate_auth_key() -> bytes:
    """Generate a cryptographically random 256-bit HMAC key."""
    import secrets
    return secrets.token_bytes(32)


def create_tag(key: bytes, message: bytes) -> bytes:
    """Create an authentication tag for a byte message."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("Authentication key must be at least 32 bytes")

    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")

    return hmac.new(key, message, hashlib.sha256).digest()


def verify_tag(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify a tag using a constant-time comparison."""
    if not isinstance(tag, bytes) or len(tag) != TAG_LENGTH:
        return False

    expected = create_tag(key, message)
    return hmac.compare_digest(expected, tag)
