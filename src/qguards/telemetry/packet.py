
"""Validated telemetry packet serialization."""

import json


REQUIRED_FIELDS = {
    "sensor_id",
    "sequence_number",
    "timestamp",
    "temperature_c",
    "humidity_percent",
}


def serialize_packet(reading: dict) -> bytes:
    """Validate a sensor reading and serialize it to deterministic JSON."""
    if not isinstance(reading, dict):
        raise ValueError("Reading must be a dictionary")

    missing = REQUIRED_FIELDS - reading.keys()
    if missing:
        raise ValueError(f"Missing fields: {', '.join(sorted(missing))}")

    if not isinstance(reading["sensor_id"], str) or not reading["sensor_id"].strip():
        raise ValueError("Invalid sensor_id")

    sequence = reading["sequence_number"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("sequence_number must be a positive integer")

    for field in ("temperature_c", "humidity_percent"):
        value = reading[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{field} must be numeric")

    humidity = reading["humidity_percent"]
    if not 0 <= humidity <= 100:
        raise ValueError("humidity_percent must be between 0 and 100")

    try:
        return json.dumps(
            reading,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Reading contains invalid JSON values") from exc


def deserialize_packet(payload: bytes) -> dict:
    """Decode JSON bytes and validate the resulting telemetry packet."""
    if not isinstance(payload, bytes):
        raise ValueError("Payload must be bytes")

    try:
        reading = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON payload") from exc

    # Reuse the serializer's schema and field validation.
    serialize_packet(reading)
    return reading
