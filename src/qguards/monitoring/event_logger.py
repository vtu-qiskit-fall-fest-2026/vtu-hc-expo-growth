
"""Record structured events for Q Guards monitoring."""

from datetime import datetime, timezone


ALLOWED_EVENT_TYPES = {
    "telemetry_accepted",
    "telemetry_rejected",
    "authentication_failure",
    "replay_detected",
    "tampering_detected",
    "unauthorized_sender",
    "invalid_packet",
    "sensor_disconnected",
}


def create_event(event_type: str, message: str) -> dict:
    """Create a validated monitoring event."""
    if not isinstance(event_type, str) or event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError("Unsupported event type")

    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")

    return {
        "event_type": event_type,
        "message": message.strip(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class EventLogger:
    """Maintain an in-memory history of monitoring events."""

    def __init__(self):
        self._events = []

    def log(self, event_type: str, message: str) -> dict:
        event = create_event(event_type, message)
        self._events.append(event)
        return event.copy()

    def get_events(self) -> list:
        """Return a copy so callers cannot modify the internal history."""
        return [event.copy() for event in self._events]

    def clear(self) -> None:
        """Clear the in-memory event history."""
        self._events.clear()
