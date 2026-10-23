
import unittest
from dataclasses import replace

from telemetry_guard import TelemetryGuard


class TelemetryGuardTests(unittest.TestCase):

    def setUp(self):
        self.guard = TelemetryGuard({
            "sensor-01": b"A" * 32,
        })

    def test_valid_message(self):
        message = self.guard.create_message(
            "sensor-01", 1, {"temperature": 25.5}
        )
        self.assertEqual(
            self.guard.verify_message(message),
            (True, "ACCEPTED"),
        )

    def test_tampered_payload(self):
        message = self.guard.create_message(
            "sensor-01", 1, {"temperature": 25.5}
        )
        tampered = replace(
            message,
            payload={"temperature": 99.9},
        )
        self.assertEqual(
            self.guard.verify_message(tampered),
            (False, "AUTHENTICATION_FAILED"),
        )

    def test_replay(self):
        message = self.guard.create_message(
            "sensor-01", 1, {"temperature": 25.5}
        )
        self.assertTrue(self.guard.verify_message(message)[0])
        self.assertEqual(
            self.guard.verify_message(message),
            (False, "REPLAY_OR_OUT_OF_ORDER"),
        )

    def test_out_of_order_message(self):
        first = self.guard.create_message(
            "sensor-01", 2, {"temperature": 25}
        )
        older = self.guard.create_message(
            "sensor-01", 1, {"temperature": 24}
        )
        self.assertTrue(self.guard.verify_message(first)[0])
        self.assertEqual(
            self.guard.verify_message(older),
            (False, "REPLAY_OR_OUT_OF_ORDER"),
        )

    def test_unknown_sensor(self):
        message = self.guard.create_message(
            "sensor-01", 1, {"temperature": 25}
        )
        forged = replace(message, sensor_id="sensor-99")
        self.assertEqual(
            self.guard.verify_message(forged),
            (False, "UNKNOWN_SENSOR"),
        )

    def test_bad_tag_does_not_consume_sequence(self):
        message = self.guard.create_message(
            "sensor-01", 1, {"temperature": 25}
        )
        bad_tag = replace(message, tag="0" * 64)

        self.assertEqual(
            self.guard.verify_message(bad_tag),
            (False, "AUTHENTICATION_FAILED"),
        )
        self.assertEqual(
            self.guard.verify_message(message),
            (True, "ACCEPTED"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
