
"""End-to-end in-process Q Guards telemetry demonstration."""

from telemetry_guard import TelemetryGuard
from gateway import TelemetryGateway
from sensor_simulator import SensorSimulator


def main():
    keys = {
        "sensor-01": b"qguards-demo-key-32-bytes-long!!",
    }

    guard = TelemetryGuard(keys)
    gateway = TelemetryGateway(guard)
    sensor = SensorSimulator("sensor-01", guard, seed=42)

    print("Q GUARDS — SENSOR TO GATEWAY DEMO")

    for _ in range(5):
        message = sensor.create_telemetry()
        result = gateway.process_message(message)

        print(
            f"Sensor={result['sensor_id']} "
            f"Seq={result['sequence']} "
            f"Accepted={result['accepted']} "
            f"Reason={result['reason']} "
            f"Payload={result.get('payload', {})}"
        )

    print("\nReplaying the first message...")
    replay = guard.create_message(
        "sensor-01",
        sequence=0,
        payload={"temperature_c": 20.0, "humidity_pct": 50.0},
    )

    # This message has a valid tag, but its sequence number is stale.
    replay_result = gateway.process_message(replay)
    print(replay_result)

    print("\nTotal security alerts:", len(gateway.get_alerts()))


if __name__ == "__main__":
    main()
