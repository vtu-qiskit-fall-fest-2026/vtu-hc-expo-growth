
import unittest

from telemetry_guard import TelemetryGuard
from sensor_simulator import SensorSimulator


class TestSensorSimulator(unittest.TestCase):

    def setUp(self):
        self.guard = TelemetryGuard({
            "sensor-01": b"qguards-test-key-32-bytes-long!!"
        })
        self.sensor = SensorSimulator("sensor-01", self.guard, seed=7)

    def test_generates_expected_payload_fields(self):
        payload = self.sensor.read_sensor()

        self.assertIn("temperature_c", payload)
        self.assertIn("humidity_pct", payload)
        self.assertGreaterEqual(payload["temperature_c"], 18.0)
        self.assertLessEqual(payload["temperature_c"], 38.0)
        self.assertGreaterEqual(payload["humidity_pct"], 25.0)
        self.assertLessEqual(payload["humidity_pct"], 85.0)

    def test_messages_have_increasing_sequences(self):
        first = self.sensor.create_telemetry()
        second = self.sensor.create_telemetry()

        self.assertEqual(first.sequence, 0)
        self.assertEqual(second.sequence, 1)

    def test_generated_message_authenticates(self):
        message = self.sensor.create_telemetry()

        accepted, reason = self.guard.verify_message(message)

        self.assertTrue(accepted)
        self.assertEqual(reason, "ACCEPTED")

    def test_rejects_empty_sensor_id(self):
        with self.assertRaises(ValueError):
            SensorSimulator("", self.guard)

    def test_rejects_invalid_seed(self):
        with self.assertRaises(ValueError):
            SensorSimulator("sensor-01", self.guard, seed=True)


if __name__ == "__main__":
    unittest.main()
