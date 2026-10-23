
"""Q Guards monitoring gateway for authenticated IoT telemetry."""

from datetime import datetime, timezone
from typing import Any

from telemetry_guard import TelemetryGuard, TelemetryMessage


class TelemetryGateway:
    """Verify incoming telemetry and record security events."""

    def __init__(self, guard: TelemetryGuard):
        if not isinstance(guard, TelemetryGuard):
            raise TypeError("guard must be a TelemetryGuard instance")

        self.guard = guard
        self.events: list[dict[str, Any]] = []

    def process_message(self, message: Any) -> dict[str, Any]:
        """Process one message and return a structured gateway result."""

        accepted, reason = self.guard.verify_message(message)

        sensor_id = (
            message.sensor_id
            if isinstance(message, TelemetryMessage)
            and isinstance(message.sensor_id, str)
            else "unknown"
        )

        sequence = (
            message.sequence
            if isinstance(message, TelemetryMessage)
            and isinstance(message.sequence, int)
            and not isinstance(message.sequence, bool)
            else None
        )

        alert = not accepted

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sensor_id": sensor_id,
            "sequence": sequence,
            "accepted": accepted,
            "reason": reason,
            "alert": alert,
        }

        # Store metadata only; do not log payloads or authentication tags.
        self.events.append(event)

        result = dict(event)

        # Only accepted messages expose their payload to the application.
        if accepted:
            result["payload"] = message.payload

        return result

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return a copy of all rejected-message events."""
        return [dict(event) for event in self.events if event["alert"]]


if __name__ == "__main__":
    demo_key = b"qguards-demo-key-32-bytes-long!!"
    guard = TelemetryGuard({"sensor-01": demo_key})
    gateway = TelemetryGateway(guard)

    message = guard.create_message(
        sensor_id="sensor-01",
        sequence=1,
        payload={"temperature_c": 26.5, "humidity_pct": 58},
    )

    print("Valid message:")
    print(gateway.process_message(message))

    print("\nReplay attempt:")
    print(gateway.process_message(message))

    print("\nSecurity alerts:")
    for alert in gateway.get_alerts():
        print(alert)
