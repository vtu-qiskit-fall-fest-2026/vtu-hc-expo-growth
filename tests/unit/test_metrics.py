
from qguards.monitoring.metrics import Metrics


def test_initial_metrics_are_zero():
    metrics = Metrics()
    assert metrics.messages_received == 0
    assert metrics.acceptance_rate == 0.0
    assert metrics.rejection_rate == 0.0


def test_acceptance_rate():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_accepted()
    metrics.record_received()
    metrics.record_rejected()
    assert metrics.acceptance_rate == 50.0
    assert metrics.rejection_rate == 50.0


def test_replay_attack_increments_rejection():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_replay_attack()
    assert metrics.replay_attacks_detected == 1
    assert metrics.messages_rejected == 1


def test_tampering_increments_rejection():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_tampering()
    assert metrics.tampering_detected == 1
    assert metrics.messages_rejected == 1


def test_authentication_failure_increments_rejection():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_authentication_failure()
    assert metrics.authentication_failures == 1
    assert metrics.messages_rejected == 1


def test_unauthorized_sender_increments_rejection():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_unauthorized_sender()
    assert metrics.unauthorized_senders == 1
    assert metrics.messages_rejected == 1


def test_snapshot_contains_metrics():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_accepted()
    snapshot = metrics.snapshot()
    assert snapshot["messages_received"] == 1
    assert snapshot["messages_accepted"] == 1
    assert snapshot["acceptance_rate"] == 100.0


def test_reset_clears_metrics():
    metrics = Metrics()
    metrics.record_received()
    metrics.record_accepted()
    metrics.reset()
    assert metrics.messages_received == 0
    assert metrics.messages_accepted == 0
