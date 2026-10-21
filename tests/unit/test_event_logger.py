
import pytest

from qguards.monitoring.event_logger import EventLogger, create_event


def test_create_event_has_expected_fields():
    event = create_event("telemetry_accepted", "Sensor data accepted")
    assert event["event_type"] == "telemetry_accepted"
    assert event["message"] == "Sensor data accepted"
    assert event["timestamp"].endswith("+00:00")


def test_empty_message_is_rejected():
    with pytest.raises(ValueError):
        create_event("invalid_packet", "  ")


def test_unknown_event_type_is_rejected():
    with pytest.raises(ValueError):
        create_event("unknown", "Test")


def test_logger_stores_events():
    logger = EventLogger()
    logger.log("replay_detected", "Duplicate sequence number")
    assert len(logger.get_events()) == 1


def test_logger_returns_copies():
    logger = EventLogger()
    logger.log("telemetry_accepted", "Accepted")
    events = logger.get_events()
    events.clear()
    assert len(logger.get_events()) == 1


def test_logger_clear():
    logger = EventLogger()
    logger.log("invalid_packet", "Malformed packet")
    logger.clear()
    assert logger.get_events() == []
