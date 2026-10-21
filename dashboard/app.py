
"""Q Guards: local IoT security monitoring dashboard."""

from datetime import datetime, timezone
import json

import streamlit as st

from qguards.telemetry.packet import serialize_packet
from qguards.security.encryption import generate_key, encrypt
from qguards.security.authentication import generate_auth_key, create_tag
from qguards.gateway.validator import GatewayValidator
from qguards.gateway.alert_manager import create_alert
from qguards.quantum.simulator import run_security_circuit
from qguards.quantum.algorithm import calculate_quantum_score
from qguards.quantum.classical_baseline import classify_classical_event


st.set_page_config(
    page_title="Q Guards | Security Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Q Guards")
st.caption(
    "Secure IoT Telemetry Monitoring | Local simulation and security testing"
)

# Keep cryptographic keys and replay-protection state consistent across reruns.
if "qg_initialized" not in st.session_state:
    st.session_state.encryption_key = generate_key()
    st.session_state.auth_key = generate_auth_key()
    st.session_state.trusted_keys = {
        "sensor-001": st.session_state.auth_key
    }
    st.session_state.validator = GatewayValidator(
        st.session_state.encryption_key,
        st.session_state.trusted_keys,
    )
    st.session_state.next_sequence = 1
    st.session_state.last_accepted = None
    st.session_state.events = []
    st.session_state.readings = []
    st.session_state.metrics_data = {
        "received": 0,
        "accepted": 0,
        "rejected": 0,
        "tampering": 0,
        "authentication_failures": 0,
        "unauthorized_senders": 0,
        "replay_attacks": 0,
        "invalid_packets": 0,
    }
    st.session_state.qg_initialized = True


def build_packet(sensor_id="sensor-001"):
    """Create and protect one simulated telemetry message."""
    sequence = st.session_state.next_sequence
    st.session_state.next_sequence += 1

    reading = {
        "sensor_id": sensor_id,
        "sequence_number": sequence,
        "temperature_c": round(20 + __import__("random").random() * 20, 2),
        "humidity_percent": round(30 + __import__("random").random() * 50, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    plaintext = serialize_packet(reading)
    packet = encrypt(st.session_state.encryption_key, plaintext)

    # A rogue sensor uses a different key and is not in the trusted registry.
    if sensor_id == "rogue-999":
        signing_key = generate_auth_key()
    else:
        signing_key = st.session_state.auth_key

    tag = create_tag(signing_key, packet["nonce"] + packet["ciphertext"])
    return packet, tag


def record_event(event_type, message, severity):
    alert = create_alert(event_type, message, severity=severity)
    st.session_state.events.insert(0, alert)
    st.session_state.events = st.session_state.events[:100]


def submit_packet(scenario):
    """Run a scenario through the real gateway validator."""
    metrics = st.session_state.metrics_data
    metrics["received"] += 1

    if scenario == "Replay previous packet":
        previous = st.session_state.last_accepted
        if previous is None:
            st.warning("Accept a valid packet before testing replay protection.")
            return
        packet, tag = previous
    elif scenario == "Malformed packet":
        packet = {"nonce": "invalid", "ciphertext": b"invalid"}
        tag = b"\x00" * 32
    else:
        sensor_id = (
            "rogue-999" if scenario == "Unauthorized sender"
            else "sensor-001"
        )
        packet, tag = build_packet(sensor_id)

        if scenario == "Tampered ciphertext":
            damaged = bytearray(packet["ciphertext"])
            damaged[0] ^= 1
            packet["ciphertext"] = bytes(damaged)

        elif scenario == "Invalid HMAC":
            tag = b"\x00" * 32

    try:
        reading = st.session_state.validator.validate(packet, tag)
        metrics["accepted"] += 1
        st.session_state.readings.insert(0, reading)
        st.session_state.readings = st.session_state.readings[:100]

        st.session_state.last_accepted = (packet, tag)

        record_event(
            "telemetry_accepted",
            f"Accepted telemetry from {reading['sensor_id']}, "
            f"sequence {reading['sequence_number']}",
            "INFO",
        )
        st.session_state.last_result = {
            "accepted": True,
            "scenario": scenario,
            "message": "Packet authenticated and accepted.",
        }

    except Exception as exc:
        metrics["rejected"] += 1
        reason = str(exc) or type(exc).__name__

        if scenario == "Tampered ciphertext":
            event_type = "tampering_detected"
            metrics["tampering"] += 1
        elif scenario == "Invalid HMAC":
            event_type = "authentication_failure"
            metrics["authentication_failures"] += 1
        elif scenario == "Unauthorized sender":
            event_type = "unauthorized_sender"
            metrics["unauthorized_senders"] += 1
        elif scenario == "Replay previous packet":
            event_type = "replay_detected"
            metrics["replay_attacks"] += 1
        else:
            event_type = "invalid_packet"
            metrics["invalid_packets"] += 1

        record_event(
            event_type,
            f"{scenario}: {reason}",
            "HIGH",
        )
        st.session_state.last_result = {
            "accepted": False,
            "scenario": scenario,
            "message": reason,
        }


# Top-level security metrics.
m = st.session_state.metrics_data
total = m["accepted"] + m["rejected"]
acceptance_rate = (100 * m["accepted"] / total) if total else 0

columns = st.columns(5)
columns[0].metric("Messages received", m["received"])
columns[1].metric("Accepted", m["accepted"])
columns[2].metric("Rejected", m["rejected"])
columns[3].metric("Attacks detected", (
    m["tampering"] + m["authentication_failures"]
    + m["unauthorized_senders"] + m["replay_attacks"]
))
columns[4].metric("Acceptance rate", f"{acceptance_rate:.1f}%")

st.divider()

monitor_tab, attack_tab, quantum_tab, events_tab = st.tabs(
    ["📡 Telemetry", "🧪 Attack Lab", "⚛️ Quantum Experiment", "🚨 Security Events"]
)

with monitor_tab:
    st.subheader("Sensor telemetry")

    if st.button("Generate and validate telemetry", type="primary"):
        submit_packet("Valid telemetry")

    if st.session_state.readings:
        st.dataframe(
            st.session_state.readings,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No accepted telemetry yet. Generate a valid message to begin.")

    st.caption(
        "Sensor values are randomly simulated. This is not a physical sensor feed."
    )

with attack_tab:
    st.subheader("Controlled security tests")
    st.write(
        "Send simulated packets through the gateway. Each test uses the "
        "configured encryption, authentication, and replay checks."
    )

    scenario = st.selectbox(
        "Select test scenario",
        [
            "Valid telemetry",
            "Tampered ciphertext",
            "Invalid HMAC",
            "Unauthorized sender",
            "Replay previous packet",
            "Malformed packet",
        ],
    )

    if st.button("Run security test", type="primary"):
        submit_packet(scenario)

    if "last_result" in st.session_state:
        result = st.session_state.last_result
        if result["accepted"]:
            st.success(
                f"{result['scenario']}: {result['message']}"
            )
        else:
            st.error(
                f"{result['scenario']}: rejected — {result['message']}"
            )

    st.subheader("Attack detection counters")
    attack_cols = st.columns(4)
    attack_cols[0].metric("Tampering", m["tampering"])
    attack_cols[1].metric("Authentication failures", m["authentication_failures"])
    attack_cols[2].metric("Unauthorized senders", m["unauthorized_senders"])
    attack_cols[3].metric("Replay attempts", m["replay_attacks"])

with quantum_tab:
    st.subheader("Qiskit circuit experiment")
    st.warning(
        "This quantum circuit is an experimental measurement demo. "
        "Its score is not used to accept or reject telemetry and does not "
        "demonstrate quantum-secured communication."
    )

    if st.button("Run quantum circuit simulation"):
        try:
            result = run_security_circuit(
                features=[0.5, 1.0],
                parameters=[0.2, 0.3],
                shots=1024,
                seed=42,
            )
            score = calculate_quantum_score(result["probabilities"])

            st.write("Measurement counts")
            st.json(result["counts"])
            q1, q2, q3 = st.columns(3)
            q1.metric("Shots", result["shots"])
            q2.metric("Circuit depth", result["circuit_depth"])
            q3.metric("Experimental score", f"{score:.4f}")
            st.write("Operation counts")
            st.json(result["operation_counts"])
        except Exception as exc:
            st.error(f"Quantum simulation failed: {exc}")

    st.subheader("Classical rule-based baseline")
    st.caption("Example score only; this is not a trained detection model.")

    failed_auth = st.checkbox("Simulate failed authentication")
    replay_detected = st.checkbox("Simulate replay detection")
    tampering_detected = st.checkbox("Simulate tampering detection")

    if st.button("Evaluate classical baseline"):
        try:
            baseline = classify_classical_event({
                "failed_auth": failed_auth,
                "replay_detected": replay_detected,
                "tampering_detected": tampering_detected,
            })
            st.json(baseline)
        except Exception as exc:
            st.error(f"Baseline evaluation failed: {exc}")

with events_tab:
    st.subheader("Recent security events")

    if st.session_state.events:
        st.dataframe(
            st.session_state.events,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No events recorded yet.")

    if st.button("Clear dashboard history"):
        st.session_state.events = []
        st.session_state.readings = []
        st.session_state.metrics_data = {
            key: 0 for key in st.session_state.metrics_data
        }
        st.session_state.last_accepted = None
        st.session_state.pop("last_result", None)
        st.rerun()

with st.sidebar:
    st.header("System status")
    st.success("Dashboard running")
    st.write("**Mode:** Local simulation")
    st.write("**Encryption:** AES-256-GCM")
    st.write("**Sender authentication:** HMAC-SHA256")
    st.write("**Replay protection:** Sequence-based")
    st.write("**Quantum backend:** Qiskit Aer")
    st.divider()
    st.caption(
        "Demo keys are generated in memory for this session. "
        "Do not use this dashboard as a production security gateway."
    )
