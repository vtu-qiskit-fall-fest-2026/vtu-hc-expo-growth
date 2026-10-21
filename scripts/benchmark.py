
"""Benchmark the Q Guards sensor-to-gateway security pipeline.

Measures simulated telemetry generation, serialization, AES-GCM encryption,
HMAC generation, and gateway validation. Results are machine-dependent.
"""

import argparse
import json
import math
import statistics
import time

from qguards.telemetry.sensor_simulator import SensorSimulator
from qguards.telemetry.packet import serialize_packet
from qguards.security.encryption import generate_key, encrypt
from qguards.security.authentication import generate_auth_key, create_tag
from qguards.gateway.validator import GatewayValidator


def percentile(values, percent):
    """Return a nearest-rank percentile."""
    ordered = sorted(values)
    index = max(0, math.ceil(percent / 100 * len(ordered)) - 1)
    return ordered[index]


def send_telemetry(sensor, encryption_key, auth_key, validator):
    """Run one complete sensor-to-gateway telemetry exchange."""
    reading = sensor.generate_reading()
    plaintext = serialize_packet(reading)

    encrypted_packet = encrypt(encryption_key, plaintext)

    authenticated_bytes = (
        encrypted_packet["nonce"] + encrypted_packet["ciphertext"]
    )
    auth_tag = create_tag(auth_key, authenticated_bytes)

    accepted_reading = validator.validate(encrypted_packet, auth_tag)

    if accepted_reading["sensor_id"] != reading["sensor_id"]:
        raise RuntimeError("Gateway returned an unexpected sensor ID")

    return accepted_reading


def run_benchmark(messages=1000, warmup=50):
    """Benchmark valid telemetry exchanges and return measured statistics."""
    if isinstance(messages, bool) or not isinstance(messages, int) or messages < 1:
        raise ValueError("messages must be a positive integer")

    if isinstance(warmup, bool) or not isinstance(warmup, int) or warmup < 0:
        raise ValueError("warmup must be a non-negative integer")

    sensor = SensorSimulator(sensor_id="sensor-001", seed=42)
    encryption_key = generate_key()
    auth_key = generate_auth_key()

    validator = GatewayValidator(
        encryption_key=encryption_key,
        sensor_auth_keys={"sensor-001": auth_key},
    )

    # Warm up the pipeline; these messages are excluded from the metrics.
    for _ in range(warmup):
        send_telemetry(sensor, encryption_key, auth_key, validator)

    latencies_ms = []
    accepted = 0

    overall_start = time.perf_counter()

    for _ in range(messages):
        start = time.perf_counter()

        send_telemetry(sensor, encryption_key, auth_key, validator)

        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies_ms.append(elapsed_ms)
        accepted += 1

    total_seconds = time.perf_counter() - overall_start

    return {
        "benchmark": "Q Guards sensor-to-gateway pipeline",
        "messages_requested": messages,
        "messages_accepted": accepted,
        "messages_rejected": messages - accepted,
        "acceptance_rate_percent": round(100 * accepted / messages, 2),
        "total_elapsed_seconds": round(total_seconds, 6),
        "latency_ms": {
            "mean": round(statistics.mean(latencies_ms), 4),
            "median_p50": round(percentile(latencies_ms, 50), 4),
            "p95": round(percentile(latencies_ms, 95), 4),
            "p99": round(percentile(latencies_ms, 99), 4),
            "minimum": round(min(latencies_ms), 4),
            "maximum": round(max(latencies_ms), 4),
        },
        "throughput_messages_per_second": round(
            messages / total_seconds, 2
        ),
        "warmup_messages_excluded": warmup,
        "timed_stages": [
            "sensor reading generation",
            "packet serialization",
            "AES-GCM encryption",
            "HMAC generation",
            "gateway validation",
        ],
        "limitations": [
            "Software simulation; no physical sensors or network transport.",
            "Performance depends on the computer and runtime environment.",
            "Does not benchmark the Qiskit circuit.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark the Q Guards security pipeline."
    )
    parser.add_argument(
        "--messages",
        type=int,
        default=1000,
        help="Number of timed telemetry messages (default: 1000)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=50,
        help="Warmup messages excluded from measurements (default: 50)",
    )
    args = parser.parse_args()

    try:
        results = run_benchmark(args.messages, args.warmup)
    except (ValueError, TypeError, KeyError, RuntimeError) as exc:
        parser.error(str(exc))

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
