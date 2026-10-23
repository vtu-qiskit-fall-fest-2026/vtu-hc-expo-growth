import streamlit as st
import pandas as pd

from telemetry_guard import TelemetryGuard
from gateway import TelemetryGateway
from sensor_simulator import SensorSimulator


# ============================================================
# CONFIGURATION
# ============================================================

DEMO_SENSOR_ID = "sensor-01"
DEMO_SENSOR_KEY = b"qguards-demo-key-32-bytes-long!!"


# ============================================================
# DEMO PIPELINE
# ============================================================

def run_demo(
    message_count=5,
    replay=True,
    tamper=True,
    unknown_sensor=True,
):
    """
    Run a complete telemetry security demonstration.

    All dashboard metrics are calculated from the exact event
    records returned by the gateway during this run.
    """

    sensor_keys = {
        DEMO_SENSOR_ID: DEMO_SENSOR_KEY,
    }

    guard = TelemetryGuard(sensor_keys)
    gateway = TelemetryGateway(guard)

    sensor = SensorSimulator(
        sensor_id=DEMO_SENSOR_ID,
        guard=guard,
        seed=42,
    )

    # Collect every event returned by the gateway.
    results = []

    # --------------------------------------------------------
    # 1. Valid telemetry
    # --------------------------------------------------------

    for _ in range(message_count):
        message = sensor.create_telemetry()
        event = gateway.process_message(message)
        results.append(event)

    # --------------------------------------------------------
    # 2. Replay attack
    # --------------------------------------------------------

    if replay:
        replay_message = guard.create_message(
            DEMO_SENSOR_ID,
            0,
            {
                "temperature_c": 25.0,
                "humidity_pct": 50.0,
            },
        )

        event = gateway.process_message(replay_message)
        results.append(event)

    # --------------------------------------------------------
    # 3. Payload-tampering attack
    # --------------------------------------------------------

    if tamper:
        tampered_message = guard.create_message(
            DEMO_SENSOR_ID,
            message_count,
            {
                "temperature_c": 99.9,
                "humidity_pct": 10.0,
            },
        )

        # Modify the payload without recomputing its HMAC.
        tampered_message.payload["temperature_c"] = -99.0

        event = gateway.process_message(tampered_message)
        results.append(event)

    # --------------------------------------------------------
    # 4. Unknown-sensor attack
    # --------------------------------------------------------

    if unknown_sensor:
        rogue_guard = TelemetryGuard({
            "rogue-sensor": b"rogue-demo-key-not-authorized",
        })

        rogue_message = rogue_guard.create_message(
            "rogue-sensor",
            0,
            {
                "temperature_c": 30.0,
                "humidity_pct": 40.0,
            },
        )

        # The main gateway does not trust rogue-sensor.
        event = gateway.process_message(rogue_message)
        results.append(event)

    # --------------------------------------------------------
    # 5. Reconcile metrics from one event list
    # --------------------------------------------------------

    accepted_events = [
        event for event in results
        if event.get("accepted") is True
    ]

    rejected_events = [
        event for event in results
        if event.get("accepted") is False
    ]

    alert_events = [
        event for event in results
        if bool(event.get("alert"))
    ]

    return {
        "results": results,
        "accepted_events": accepted_events,
        "rejected_events": rejected_events,
        "alerts": alert_events,
        "accepted": len(accepted_events),
        "rejected": len(rejected_events),
        "alert_count": len(alert_events),
        "total_events": len(results),
        "settings": {
            "message_count": message_count,
            "replay": replay,
            "tamper": tamper,
            "unknown_sensor": unknown_sensor,
        },
    }


# ============================================================
# STREAMLIT PAGE
# ============================================================

st.set_page_config(
    page_title="Q Guards | Secure IoT Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Q Guards")
st.subheader("Secure Real-Time IoT Telemetry Monitoring")

st.caption(
    "Educational security demonstration. "
    "BB84, if used elsewhere in the project, is a simulation; "
    "this dashboard does not establish a live quantum link "
    "or certify production-grade security."
)


# ============================================================
# SIDEBAR CONTROLS
# ============================================================

st.sidebar.header("Experiment Configuration")

message_count = st.sidebar.slider(
    "Valid sensor messages",
    min_value=1,
    max_value=20,
    value=5,
    step=1,
)

replay_enabled = st.sidebar.checkbox(
    "Enable replay attack",
    value=True,
)

tamper_enabled = st.sidebar.checkbox(
    "Enable payload-tampering attack",
    value=True,
)

unknown_sensor_enabled = st.sidebar.checkbox(
    "Enable unknown-sensor attack",
    value=True,
)

st.sidebar.divider()

run_clicked = st.sidebar.button(
    "▶ Run Security Demo",
    use_container_width=True,
    type="primary",
)

clear_clicked = st.sidebar.button(
    "Clear Displayed Results",
    use_container_width=True,
)

if clear_clicked:
    st.session_state.pop("qguards_results", None)

if run_clicked:
    try:
        st.session_state["qguards_results"] = run_demo(
            message_count=message_count,
            replay=replay_enabled,
            tamper=tamper_enabled,
            unknown_sensor=unknown_sensor_enabled,
        )
        st.session_state.pop("qguards_error", None)

    except Exception as exc:
        st.session_state["qguards_error"] = (
            f"{type(exc).__name__}: {exc}"
        )

if st.session_state.get("qguards_error"):
    st.error(st.session_state["qguards_error"])

data = st.session_state.get("qguards_results")


# ============================================================
# DASHBOARD CONTENT
# ============================================================

if data is None:
    st.info(
        "Configure the experiment in the sidebar, then click "
        "'Run Security Demo' to generate telemetry and attack events."
    )

    st.markdown("### Demonstration workflow")
    st.markdown(
        """
        1. Generate telemetry from an authorized sensor.
        2. Authenticate each message at the gateway.
        3. Attempt replay, payload tampering, and unauthorized-sensor injection.
        4. Display accepted messages, rejected messages, and security alerts.
        """
    )

else:
    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    st.markdown("### Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Accepted",
            value=data["accepted"],
        )

    with col2:
        st.metric(
            label="Rejected",
            value=data["rejected"],
        )

    with col3:
        st.metric(
            label="Security Alerts",
            value=data["alert_count"],
        )

    with col4:
        st.metric(
            label="Total Events",
            value=data["total_events"],
        )

    # --------------------------------------------------------
    # Metric consistency checks
    # --------------------------------------------------------

    metrics_consistent = (
        data["accepted"] + data["rejected"]
        == data["total_events"]
        and data["alert_count"] == len(data["alerts"])
        and data["total_events"] == len(data["results"])
    )

    if metrics_consistent:
        st.success(
            "Metric reconciliation passed: the displayed "
            "counts match the recorded event list."
        )
    else:
        st.error(
            "Metric reconciliation failed. Inspect the gateway "
            "event records and alert-generation logic."
        )

    # --------------------------------------------------------
    # Telemetry and alert tables
    # --------------------------------------------------------

    left, right = st.columns(2)

    with left:
        st.markdown("### Telemetry Events")

        if data["results"]:
            telemetry_df = pd.DataFrame(data["results"])
            st.dataframe(
                telemetry_df,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No telemetry events recorded.")

    with right:
        st.markdown("### Security Alerts")

        if data["alerts"]:
            alerts_df = pd.DataFrame(data["alerts"])
            st.dataframe(
                alerts_df,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "No events with the gateway's alert flag were recorded."
            )

    # --------------------------------------------------------
    # Rejected events
    # --------------------------------------------------------

    st.markdown("### Rejected Messages")

    if data["rejected_events"]:
        rejected_df = pd.DataFrame(data["rejected_events"])
        st.dataframe(
            rejected_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No messages were rejected.")

    # --------------------------------------------------------
    # Experiment configuration
    # --------------------------------------------------------

    with st.expander("Experiment Settings and Expected Counts"):
        st.json(data["settings"])

        expected_rejections = sum([
            int(data["settings"]["replay"]),
            int(data["settings"]["tamper"]),
            int(data["settings"]["unknown_sensor"]),
        ])

        st.write(
            f"Expected valid messages: "
            f"{data['settings']['message_count']}"
        )

        st.write(
            f"Expected attack attempts: {expected_rejections}"
        )

        st.write(
            f"Recorded events: {data['total_events']}"
        )

    # --------------------------------------------------------
    # Security limitations
    # --------------------------------------------------------

    with st.expander("Security Scope and Limitations"):
        st.markdown(
            """
            - HMAC-SHA256 authenticates telemetry using a shared secret.
            - Replay protection depends on the gateway's sequence tracking.
            - Payload-tampering detection depends on verifying the
              authentication tag against the received payload.
            - Unknown-sensor rejection depends on the configured
              sensor-key registry.
            - This demo uses simulated telemetry and locally generated
              attack cases.
            - HMAC is symmetric authentication; it is not a digital
              signature or post-quantum key-establishment algorithm.
            - A BB84 simulation does not demonstrate actual quantum
              communication.
            - Successful demonstration tests do not establish
              production-grade security.
            """
        )

st.divider()
st.caption("Q Guards | IoT telemetry security prototype")