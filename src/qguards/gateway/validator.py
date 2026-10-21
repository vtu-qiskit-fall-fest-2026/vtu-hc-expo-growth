
"""Secure telemetry gateway validation pipeline."""

from qguards.security.encryption import decrypt
from qguards.security.authentication import verify_tag
from qguards.security.replay_protection import ReplayProtection
from qguards.telemetry.packet import deserialize_packet


class GatewayValidator:
    """Validate encrypted sensor telemetry before accepting it."""

    def __init__(self, encryption_key: bytes, sensor_auth_keys: dict[str, bytes]):
        if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes")

        if not isinstance(sensor_auth_keys, dict) or not sensor_auth_keys:
            raise ValueError("At least one trusted sensor authentication key is required")

        for sensor_id, key in sensor_auth_keys.items():
            if not isinstance(sensor_id, str) or not sensor_id.strip():
                raise ValueError("Trusted sensor IDs must be non-empty strings")
            if not isinstance(key, bytes) or len(key) < 32:
                raise ValueError("Each sensor authentication key must be at least 32 bytes")

        self._encryption_key = encryption_key
        self._sensor_auth_keys = sensor_auth_keys.copy()
        self._replay_guard = ReplayProtection()

    def validate(self, encrypted_packet: dict, auth_tag: bytes) -> dict:
        """Return the accepted reading or raise ValueError on rejection."""
        if not isinstance(encrypted_packet, dict):
            raise ValueError("Encrypted packet must be a dictionary")

        nonce = encrypted_packet.get("nonce")
        ciphertext = encrypted_packet.get("ciphertext")

        if not isinstance(nonce, bytes) or not isinstance(ciphertext, bytes):
            raise ValueError("Packet must contain byte nonce and ciphertext")

        # AES-GCM checks ciphertext integrity before returning plaintext.
        plaintext = decrypt(self._encryption_key, nonce, ciphertext)

        # Decode and validate the telemetry schema.
        reading = deserialize_packet(plaintext)
        sensor_id = reading["sensor_id"]

        # Select the trusted key from local configuration, never from the packet.
        auth_key = self._sensor_auth_keys.get(sensor_id)
        if auth_key is None:
            raise ValueError("Unauthorized sensor")

        # Bind the HMAC to the encrypted packet, including its nonce.
        authenticated_bytes = nonce + ciphertext
        if not verify_tag(auth_key, authenticated_bytes, auth_tag):
            raise ValueError("Sender authentication failed")

        # Replay state changes only after integrity and identity checks succeed.
        sequence_number = reading["sequence_number"]
        if not self._replay_guard.accept(sensor_id, sequence_number):
            raise ValueError("Replay detected or sequence number out of order")

        return reading
