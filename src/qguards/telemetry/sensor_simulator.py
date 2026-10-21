
"""Simulate temperature and humidity telemetry for Q Guards."""

from datetime import datetime, timezone
import random


class SensorSimulator:
    """Generate validated, reproducible simulated sensor readings."""

    def __init__(
        self,
        sensor_id="sensor-001",
        temperature_min=20.0,
        temperature_max=40.0,
        humidity_min=30.0,
        humidity_max=80.0,
        seed=None,
    ):
        if not sensor_id or not sensor_id.strip():
            raise ValueError("sensor_id must not be empty")

        if temperature_min > temperature_max:
            raise ValueError("Invalid temperature range")

        if humidity_min > humidity_max:
            raise ValueError("Invalid humidity range")

        if humidity_min < 0 or humidity_max > 100:
            raise ValueError("Humidity bounds must be between 0 and 100")

        self.sensor_id = sensor_id
        self.temperature_min = temperature_min
        self.temperature_max = temperature_max
        self.humidity_min = humidity_min
        self.humidity_max = humidity_max
        self._random = random.Random(seed)
        self._sequence_number = 0

    def generate_reading(self):
        """Return the next simulated telemetry reading as a dictionary."""
        self._sequence_number += 1

        return {
            "sensor_id": self.sensor_id,
            "sequence_number": self._sequence_number,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "temperature_c": round(
                self._random.uniform(
                    self.temperature_min, self.temperature_max
                ),
                2,
            ),
            "humidity_percent": round(
                self._random.uniform(
                    self.humidity_min, self.humidity_max
                ),
                2,
            ),
        }
