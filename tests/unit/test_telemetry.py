
import pytest

from qguards.telemetry.sensor_simulator import SensorSimulator


def test_reading_contains_required_fields():
    sensor = SensorSimulator(seed=42)
    reading = sensor.generate_reading()

    assert reading["sensor_id"] == "sensor-001"
    assert reading["sequence_number"] == 1
    assert "timestamp" in reading
    assert "temperature_c" in reading
    assert "humidity_percent" in reading


def test_readings_stay_within_configured_ranges():
    sensor = SensorSimulator(seed=42)

    for _ in range(100):
        reading = sensor.generate_reading()
        assert 20.0 <= reading["temperature_c"] <= 40.0
        assert 30.0 <= reading["humidity_percent"] <= 80.0


def test_sequence_numbers_increase():
    sensor = SensorSimulator(seed=42)

    assert sensor.generate_reading()["sequence_number"] == 1
    assert sensor.generate_reading()["sequence_number"] == 2
    assert sensor.generate_reading()["sequence_number"] == 3


def test_seed_reproduces_measurements():
    first = SensorSimulator(seed=123).generate_reading()
    second = SensorSimulator(seed=123).generate_reading()

    assert first["temperature_c"] == second["temperature_c"]
    assert first["humidity_percent"] == second["humidity_percent"]


def test_invalid_temperature_range_is_rejected():
    with pytest.raises(ValueError, match="Invalid temperature range"):
        SensorSimulator(temperature_min=40, temperature_max=20)


def test_invalid_humidity_range_is_rejected():
    with pytest.raises(ValueError, match="Humidity bounds"):
        SensorSimulator(humidity_min=-1, humidity_max=80)


def test_empty_sensor_id_is_rejected():
    with pytest.raises(ValueError, match="sensor_id"):
        SensorSimulator(sensor_id="")
