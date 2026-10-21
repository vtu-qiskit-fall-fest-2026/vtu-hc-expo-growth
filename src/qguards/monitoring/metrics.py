
"""Track telemetry and security metrics for Q Guards."""


class Metrics:
    """Maintain counters for gateway processing and security events."""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Reset all metric counters."""
        self.messages_received = 0
        self.messages_accepted = 0
        self.messages_rejected = 0
        self.replay_attacks_detected = 0
        self.tampering_detected = 0
        self.authentication_failures = 0
        self.unauthorized_senders = 0

    def record_received(self) -> None:
        self.messages_received += 1

    def record_accepted(self) -> None:
        self.messages_accepted += 1

    def record_rejected(self) -> None:
        self.messages_rejected += 1

    def record_replay_attack(self) -> None:
        self.replay_attacks_detected += 1
        self.record_rejected()

    def record_tampering(self) -> None:
        self.tampering_detected += 1
        self.record_rejected()

    def record_authentication_failure(self) -> None:
        self.authentication_failures += 1
        self.record_rejected()

    def record_unauthorized_sender(self) -> None:
        self.unauthorized_senders += 1
        self.record_rejected()

    @property
    def acceptance_rate(self) -> float:
        """Accepted messages as a percentage of received messages."""
        if self.messages_received == 0:
            return 0.0
        return round(
            self.messages_accepted / self.messages_received * 100, 2
        )

    @property
    def rejection_rate(self) -> float:
        """Rejected messages as a percentage of received messages."""
        if self.messages_received == 0:
            return 0.0
        return round(
            self.messages_rejected / self.messages_received * 100, 2
        )

    def snapshot(self) -> dict:
        """Return a consistent snapshot of current metrics."""
        return {
            "messages_received": self.messages_received,
            "messages_accepted": self.messages_accepted,
            "messages_rejected": self.messages_rejected,
            "replay_attacks_detected": self.replay_attacks_detected,
            "tampering_detected": self.tampering_detected,
            "authentication_failures": self.authentication_failures,
            "unauthorized_senders": self.unauthorized_senders,
            "acceptance_rate": self.acceptance_rate,
            "rejection_rate": self.rejection_rate,
        }
