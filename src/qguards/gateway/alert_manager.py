
"""Create and validate structured security alerts for Q Guards."""

from datetime import datetime, timezone


ALLOWED_SEVERITIES = {"INFO", "WARNING", "HIGH", "CRITICAL"}

ALLOWED_EVENT_TYPES = {
    "authentication_failure",
    "replay_detected",
    "tampering_detected",
    "unauthorized_sender",
    "invalid_packet",
    "sensor_disconnected",
}


def create_alert(event_type: str, message: str, severity: str = "WARNING") -> dict:
    """Create a structured security alert with a UTC timestamp."""

    if not isinstance(event_type, str) or event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError("Unsupported security event type")

    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")

    if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
        raise ValueError("Unsupported severity")

    return {
        "event_type": event_type,
        "message": message.strip(),
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
