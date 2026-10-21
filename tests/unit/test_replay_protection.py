
import pytest

from qguards.security.replay_protection import ReplayProtection


def test_first_sequence_is_accepted():
    guard = ReplayProtection()
    assert guard.accept("sensor-001", 1)


def test_duplicate_sequence_is_rejected():
    guard = ReplayProtection()
    assert guard.accept("sensor-001", 1)
    assert not guard.accept("sensor-001", 1)


def test_older_sequence_is_rejected():
    guard = ReplayProtection()
    assert guard.accept("sensor-001", 5)
    assert not guard.accept("sensor-001", 4)


def test_newer_sequence_is_accepted():
    guard = ReplayProtection()
    assert guard.accept("sensor-001", 1)
    assert guard.accept("sensor-001", 2)
    assert guard.last_accepted("sensor-001") == 2


def test_sensor_states_are_independent():
    guard = ReplayProtection()
    assert guard.accept("sensor-A", 1)
    assert guard.accept("sensor-B", 1)


@pytest.mark.parametrize("sequence", [0, -1, True, 1.5, "2", None])
def test_invalid_sequence_is_rejected(sequence):
    guard = ReplayProtection()
    assert not guard.accept("sensor-001", sequence)


def test_empty_sensor_id_is_rejected():
    assert not ReplayProtection().accept("", 1)


def test_reset_sensor_clears_state():
    guard = ReplayProtection()
    assert guard.accept("sensor-001", 3)
    guard.reset_sensor("sensor-001")
    assert guard.accept("sensor-001", 1)
