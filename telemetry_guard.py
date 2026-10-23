
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TelemetryMessage:
    sensor_id: str
    sequence: int
    payload: dict[str, Any]
    tag: str


class TelemetryGuard:
    """Prototype telemetry authentication and replay protection."""

    def __init__(self, sensor_keys: dict[str, bytes]):
        if not sensor_keys:
            raise ValueError("At least one sensor key is required")

        if any(not key for key in sensor_keys):
            raise ValueError("Sensor IDs must not be empty")

        if any(len(key) < 16 for key in sensor_keys.values()):
            raise ValueError("Each sensor key must be at least 16 bytes")

        self._sensor_keys = dict(sensor_keys)
        self._last_sequence: dict[str, int] = {}

    @staticmethod
    def _canonical_bytes(
        sensor_id: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> bytes:
        body = {
            "sensor_id": sensor_id,
            "sequence": sequence,
            "payload": payload,
        }
        return json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def create_message(
        self,
        sensor_id: str,
        sequence: int,
        payload: dict[str, Any],
    ) -> TelemetryMessage:
        if sensor_id not in self._sensor_keys:
            raise ValueError("Unknown sensor")

        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise ValueError("Sequence must be an integer")

        if sequence < 0:
            raise ValueError("Sequence must be non-negative")

        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary")

        data = self._canonical_bytes(sensor_id, sequence, payload)
        tag = hmac.new(
            self._sensor_keys[sensor_id],
            data,
            hashlib.sha256,
        ).hexdigest()

        return TelemetryMessage(sensor_id, sequence, payload, tag)

    def verify_message(self, message: TelemetryMessage) -> tuple[bool, str]:
        if not isinstance(message, TelemetryMessage):
            return False, "MALFORMED_MESSAGE"

        if message.sensor_id not in self._sensor_keys:
            return False, "UNKNOWN_SENSOR"

        if (
            not isinstance(message.sequence, int)
            or isinstance(message.sequence, bool)
            or message.sequence < 0
            or not isinstance(message.payload, dict)
            or not isinstance(message.tag, str)
        ):
            return False, "MALFORMED_MESSAGE"

        try:
            data = self._canonical_bytes(
                message.sensor_id,
                message.sequence,
                message.payload,
            )
        except (TypeError, ValueError, OverflowError):
            return False, "MALFORMED_PAYLOAD"

        expected_tag = hmac.new(
            self._sensor_keys[message.sensor_id],
            data,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_tag, message.tag):
            return False, "AUTHENTICATION_FAILED"

        last = self._last_sequence.get(message.sensor_id, -1)

        if message.sequence <= last:
            return False, "REPLAY_OR_OUT_OF_ORDER"

        # Update state only after authentication and sequence validation.
        self._last_sequence[message.sensor_id] = message.sequence
        return True, "ACCEPTED"
