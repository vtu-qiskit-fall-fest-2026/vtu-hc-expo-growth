
"""Per-sensor replay protection using monotonically increasing sequence numbers."""


class ReplayProtection:
    """Reject duplicate and out-of-order telemetry sequence numbers."""

    def __init__(self):
        self._last_sequence = {}

    def accept(self, sensor_id: str, sequence_number: int) -> bool:
        """Accept only a sequence number greater than the last accepted one."""
        if not isinstance(sensor_id, str) or not sensor_id.strip():
            return False

        if (
            isinstance(sequence_number, bool)
            or not isinstance(sequence_number, int)
            or sequence_number < 1
        ):
            return False

        last = self._last_sequence.get(sensor_id, 0)

        if sequence_number <= last:
            return False

        self._last_sequence[sensor_id] = sequence_number
        return True

    def reset_sensor(self, sensor_id: str) -> None:
        """Reset replay state for a sensor; use only during trusted reinitialization."""
        self._last_sequence.pop(sensor_id, None)

    def last_accepted(self, sensor_id: str) -> int:
        """Return the last accepted sequence number, or zero if unseen."""
        return self._last_sequence.get(sensor_id, 0)
