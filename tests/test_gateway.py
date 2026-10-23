
import unittest

from telemetry_guard import TelemetryGuard, TelemetryMessage
from gateway import TelemetryGateway


class TestTelemetryGateway(unittest.TestCase):

    def setUp(self):
        self.key = b"qguards-test-key-32-bytes-long!!"
        self.guard = TelemetryGuard({"sensor-01": self.key})
        self.gateway = TelemetryGateway(self.guard)

    def make_message(self, sequence=1):
        return self.guard.create_message(
            "sensor-01",
            sequence,
            {"temperature_c": 25.0},
        )

    def test_accepts_valid_message(self):
        result = self.gateway.process_message(self.make_message())

        self.assertTrue(result["accepted"])
        self.assertEqual(result["reason"], "ACCEPTED")
        self.assertFalse(result["alert"])
        self.assertEqual(result["payload"]["temperature_c"], 25.0)

    def test_rejects_replay(self):
        message = self.make_message()

        first = self.gateway.process_message(message)
        second = self.gateway.process_message(message)

        self.assertTrue(first["accepted"])
        self.assertFalse(second["accepted"])
        self.assertEqual(second["reason"], "REPLAY_OR_OUT_OF_ORDER")
        self.assertTrue(second["alert"])
        self.assertNotIn("payload", second)

    def test_rejects_tampered_payload(self):
        message = self.make_message()
        message.payload["temperature_c"] = 99.0

        result = self.gateway.process_message(message)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "AUTHENTICATION_FAILED")
        self.assertTrue(result["alert"])
        self.assertNotIn("payload", result)

    def test_rejects_unknown_sensor(self):
        message = TelemetryMessage(
            sensor_id="unknown-sensor",
            sequence=1,
            payload={"temperature_c": 25.0},
            tag="0" * 64,
        )

        result = self.gateway.process_message(message)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "UNKNOWN_SENSOR")
        self.assertTrue(result["alert"])

    def test_rejects_malformed_message(self):
        result = self.gateway.process_message(None)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "MALFORMED_MESSAGE")
        self.assertTrue(result["alert"])

    def test_alert_history_contains_rejections_only(self):
        self.gateway.process_message(self.make_message(1))
        self.gateway.process_message(self.make_message(1))

        alerts = self.gateway.get_alerts()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["reason"], "REPLAY_OR_OUT_OF_ORDER")

    def test_event_log_does_not_store_payload(self):
        self.gateway.process_message(self.make_message())

        event = self.gateway.events[0]

        self.assertNotIn("payload", event)
        self.assertNotIn("tag", event)


if __name__ == "__main__":
    unittest.main()
