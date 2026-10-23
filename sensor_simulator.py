
"""Simulated IoT sensor for the Q Guards prototype."""

import random
from typing import Any

from telemetry_guard import TelemetryGuard, TelemetryMessage


class SensorSimulator:
    """Generate readings and authenticate outgoing sensor messages."""

    def __init__(
        self,
        sensor_id: str,
        guard: TelemetryGuard,
        seed: int = 42,
    ):
        if not isinstance(sensor_id, str) or not sensor_id.strip():
            raise ValueError("sensor_id must be a non-empty string")

        if not isinstance(guard, TelemetryGuard):
            raise TypeError("guard must be a TelemetryGuard instance")

        if not isinstance(seed, int) or isinstance(seed, bool):
            raise ValueError("seed must be an integer")

        self.sensor_id = sensor_id
        self.guard = guard
        self.sequence = 0
        self.rng = random.Random(seed)

    def read_sensor(self) -> dict[str, Any]:
        """Generate simulated temperature and humidity readings."""
        return {
            "temperature_c": round(self.rng.uniform(18.0, 38.0), 2),
            "humidity_pct": round(self.rng.uniform(25.0, 85.0), 2),
        }

    def create_telemetry(self) -> TelemetryMessage:
        """Create an authenticated message with a fresh sequence number."""
        payload = self.read_sensor()

        message = self.guard.create_message(
            sensor_id=self.sensor_id,
            sequence=self.sequence,
            payload=payload,
        )

        self.sequence += 1
        return message
