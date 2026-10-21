
"""Q Guards automated self-check runner.

Runs pytest, telemetry security scenarios, and Qiskit simulation.
Only reports PASS when the observed behavior matches expectations.
"""

import subprocess
import sys
import traceback

RESULTS = []


def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append((name, bool(passed), detail))
    print(f"[{status}] {name}")
    if detail:
        print(f"       {detail}")


def run_pytest():
    print("\n=== 1. EXISTING PYTHON TEST SUITE ===")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        print(output[-5000:] if output else "(pytest produced no output)")
        record(
            "Existing pytest suite",
            result.returncode == 0,
            f"pytest exit code: {result.returncode}",
        )
    except Exception as exc:
        record("Existing pytest suite", False, repr(exc))


def run_security_checks():
    print("\n=== 2. TELEMETRY SECURITY SCENARIOS ===")

    try:
        from qguards.security.encryption import generate_key, encrypt
        from qguards.security.authentication import (
            generate_auth_key,
            create_tag,
        )
        from qguards.telemetry.packet import serialize_packet
        from qguards.gateway.validator import GatewayValidator

        encryption_key = generate_key()
        auth_key = generate_auth_key()
        trusted_id = "sensor-01"

        gateway = GatewayValidator(
            encryption_key,
            {trusted_id: auth_key},
        )

        sequence = 0

        def make_message(sensor_id=trusted_id):
            nonlocal sequence
            sequence += 1

            # These fields match the packet serializer's required schema.
            packet = {
                "sensor_id": sensor_id,
                "sequence_number": sequence,
                "temperature_c": 24.5,
                "humidity_percent": 50.0,
                "timestamp": "2026-10-21T12:00:00Z",
            }

            plaintext = serialize_packet(packet)
            encrypted = encrypt(encryption_key, plaintext)
            tag = create_tag(
                auth_key,
                encrypted["nonce"] + encrypted["ciphertext"],
            )
            return encrypted, tag

        def must_accept(name, encrypted, tag):
            try:
                gateway.validate(encrypted, tag)
                record(name, True, "Gateway accepted the packet.")
            except Exception as exc:
                record(
                    name,
                    False,
                    f"Unexpected rejection: {type(exc).__name__}: {exc}",
                )

        def must_reject(name, encrypted, tag):
            try:
                gateway.validate(encrypted, tag)
                record(
                    name,
                    False,
                    "Gateway accepted a packet that should be rejected.",
                )
            except (ValueError, TypeError, KeyError) as exc:
                record(name, True, f"Gateway rejected packet: {exc}")
            except Exception as exc:
                record(
                    name,
                    False,
                    f"Unexpected exception: {type(exc).__name__}: {exc}",
                )

        # 1. Valid telemetry must be accepted.
        valid_packet, valid_tag = make_message()
        must_accept(
            "Valid telemetry accepted",
            valid_packet,
            valid_tag,
        )

        # 2. Ciphertext modification must fail authenticated decryption.
        tampered = dict(valid_packet)
        ciphertext = bytearray(tampered["ciphertext"])

        if not ciphertext:
            record(
                "Tampered ciphertext rejected",
                False,
                "Ciphertext is empty; tampering test cannot run.",
            )
        else:
            ciphertext[0] ^= 1
            tampered["ciphertext"] = bytes(ciphertext)
            must_reject(
                "Tampered ciphertext rejected",
                tampered,
                valid_tag,
            )

        # 3. A wrong HMAC must be rejected.
        packet, tag = make_message()
        if not isinstance(tag, bytes):
            record(
                "Invalid HMAC rejected",
                False,
                f"Expected bytes HMAC, got {type(tag).__name__}.",
            )
        else:
            bad_tag = bytes(len(tag))
            must_reject("Invalid HMAC rejected", packet, bad_tag)

        # 4. An untrusted sensor must be rejected.
        rogue_packet, rogue_tag = make_message("rogue-sensor")
        must_reject(
            "Unauthorized sender rejected",
            rogue_packet,
            rogue_tag,
        )

        # 5. The first copy must be accepted; its duplicate rejected.
        replay_packet, replay_tag = make_message()
        try:
            gateway.validate(replay_packet, replay_tag)
        except Exception as exc:
            record(
                "Replay rejected",
                False,
                f"Initial packet failed unexpectedly: {exc!r}",
            )
        else:
            try:
                gateway.validate(replay_packet, replay_tag)
                record(
                    "Replay rejected",
                    False,
                    "Gateway accepted the duplicate packet.",
                )
            except (ValueError, TypeError, KeyError) as exc:
                record("Replay rejected", True, f"Duplicate rejected: {exc}")
            except Exception as exc:
                record(
                    "Replay rejected",
                    False,
                    f"Unexpected exception: {type(exc).__name__}: {exc}",
                )

        # 6. Malformed nonce and ciphertext must be rejected.
        malformed = {
            "nonce": "not-bytes",
            "ciphertext": b"invalid",
        }
        must_reject(
            "Malformed packet rejected",
            malformed,
            b"invalid-tag",
        )

    except Exception as exc:
        record(
            "Security scenario setup",
            False,
            f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
        )


def run_quantum_check():
    print("\n=== 3. QISKIT SIMULATION ===")
    try:
        from qguards.quantum.simulator import run_security_circuit

        result = run_security_circuit(
            [0.5, 1.0],
            [0.2, 0.3],
            shots=1024,
            seed=42,
        )

        counts = result["counts"]
        probabilities = result["probabilities"]
        total_shots = sum(counts.values())

        print("Counts:", counts)
        print("Probabilities:", probabilities)
        print("Shots:", result["shots"])
        print("Circuit depth:", result["circuit_depth"])
        print("Operations:", result["operation_counts"])

        valid = (
            total_shots == 1024
            and result["shots"] == 1024
            and set(counts).issubset({"00", "01", "10", "11"})
            and abs(sum(probabilities.values()) - 1.0) < 1e-9
        )

        record(
            "Qiskit circuit simulation",
            valid,
            f"Observed {total_shots} measurement shots.",
        )

    except Exception as exc:
        record(
            "Qiskit circuit simulation",
            False,
            f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
        )


def main():
    print("=" * 58)
    print("Q GUARDS - AUTOMATED SELF-CHECK")
    print("=" * 58)
    print("Results reflect actual execution.")

    run_pytest()
    run_security_checks()
    run_quantum_check()

    print("\n=== 4. FINAL SUMMARY ===")
    passed = sum(ok for _, ok, _ in RESULTS)
    failed = len(RESULTS) - passed

    for name, ok, _ in RESULTS:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")

    print(f"\nTotal checks: {len(RESULTS)}")
    print(f"Passed:       {passed}")
    print(f"Failed:       {failed}")

    if failed:
        print("SELF-CHECK RESULT: FAIL - inspect failures above.")
        return 1

    print("SELF-CHECK RESULT: PASS - all executed checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
