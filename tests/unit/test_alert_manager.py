import pytest

from qguards.gateway.alert_manager import create_alert


def test_create_alert_returns_expected_fields():
    alert = create_alert(
        "replay_detected",
        "Duplicate sequence number received",
        "HIGH",
    )

    assert alert["event_type"] == "replay_detected"
    assert alert["message"] == "Duplicate sequence number received"
    assert alert["severity"] == "HIGH"
    assert alert["timestamp"].endswith("+00:00")


def test_message_whitespace_is_removed():
    alert = create_alert("authentication_failure", "  Invalid tag  ")
    assert alert["message"] == "Invalid tag"


def test_default_severity_is_warning():
    alert = create_alert("invalid_packet", "Malformed packet")
    assert alert["severity"] == "WARNING"


def test_invalid_event_type_is_rejected():
    with pytest.raises(ValueError):
        create_alert("unknown_event", "Unexpected event")


def test_empty_message_is_rejected():
    with pytest.raises(ValueError):
        create_alert("replay_detected", "  ")


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        create_alert("tampering_detected", "Payload changed", "LOW")