
import pytest

from qguards.quantum.classical_baseline import (
    calculate_classical_score,
    classify_classical_event,
)


def test_no_security_signals_score_zero():
    features = {
        "failed_auth": False,
        "replay_detected": False,
        "tampering_detected": False,
    }
    assert calculate_classical_score(features) == 0.0


def test_all_security_signals_score_one():
    features = {
        "failed_auth": True,
        "replay_detected": True,
        "tampering_detected": True,
    }
    assert calculate_classical_score(features) == 1.0


def test_failed_authentication_weight():
    features = {
        "failed_auth": True,
        "replay_detected": False,
        "tampering_detected": False,
    }
    assert calculate_classical_score(features) == 0.4


def test_suspicious_verdict_when_signal_exists():
    features = {
        "failed_auth": False,
        "replay_detected": True,
        "tampering_detected": False,
    }
    result = classify_classical_event(features)
    assert result["verdict"] == "suspicious"
    assert result["method"] == "rule_based_baseline"


def test_no_signal_verdict():
    features = {
        "failed_auth": False,
        "replay_detected": False,
        "tampering_detected": False,
    }
    result = classify_classical_event(features)
    assert result["verdict"] == "no_signal"


def test_missing_feature_rejected():
    with pytest.raises(ValueError):
        calculate_classical_score({"failed_auth": True})


def test_non_boolean_feature_rejected():
    features = {
        "failed_auth": 1,
        "replay_detected": False,
        "tampering_detected": False,
    }
    with pytest.raises(ValueError):
        calculate_classical_score(features)


def test_unexpected_feature_rejected():
    features = {
        "failed_auth": False,
        "replay_detected": False,
        "tampering_detected": False,
        "unknown": True,
    }
    with pytest.raises(ValueError):
        calculate_classical_score(features)
