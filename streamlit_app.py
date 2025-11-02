# streamlit_app.py
import os
import time
import requests
import pandas as pd
import streamlit as st

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
PAGE_REFRESH_SEC = int(os.getenv("PAGE_REFRESH_SEC", "30"))

st.set_page_config(page_title="AI-Powered SOC – Alerts", layout="wide")
st.title("AI-Powered SOC - Alerts Dashboard")
st.caption(f"Backend: {API_BASE}")

# ---------------- auto-refresh every 30s (no secrets required) ----------------  
if "next_refresh" not in st.session_state:
    st.session_state.next_refresh = time.time() + PAGE_REFRESH_SEC

# Initialize refresh timestamp on first run
if "refresh_timestamp" not in st.session_state:
    st.session_state.refresh_timestamp = time.time()

# Calculate time until next refresh (use refresh_timestamp to get accurate countdown)
current_time = time.time()
time_elapsed = current_time - st.session_state.refresh_timestamp
time_remaining = max(0, PAGE_REFRESH_SEC - int(time_elapsed))
st.sidebar.write(f"Auto-refresh: {PAGE_REFRESH_SEC}s  |  Next in {time_remaining}s")

# Controls
st.sidebar.header("Controls")
order_opt = st.sidebar.selectbox("Order table by", ["Newest first", "Oldest first"])
if st.sidebar.button("Reset session stats"):
    st.session_state.pop("last_seen_row_id", None)
    st.success("Session stats reset. The table will recompute on next refresh.")

# ---------------- data fetch helpers ----------------
def fetch_json(path: str, params=None):
    try:
        r = requests.get(f"{API_BASE}{path}", params=params, timeout=10)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)

def fetch_alerts(limit: int) -> pd.DataFrame:
    url = f"{API_BASE}/alerts/live"
    r = requests.get(url, params={"since_id": -1, "limit": limit}, timeout=10)
    r.raise_for_status()
    return pd.DataFrame(r.json())  # backend returns a list


# Alerts
data, err = fetch_json("/alerts", params={"limit": 500})
if err:
    st.error(f"Failed to fetch alerts: {err}")
    alerts = []
    df = pd.DataFrame()
else:
    alerts = data.get("alerts", [])
    df = pd.DataFrame(alerts)

# Format mitre_tags for better display (convert list to readable string)
if not df.empty and "mitre_tags" in df.columns:
    df["mitre_tags"] = df["mitre_tags"].apply(
        lambda x: ", ".join(x) if isinstance(x, list) else (str(x) if pd.notna(x) else "")
    )

col1, col2, col3 = st.columns(3)
col1.metric("Total alerts loaded", value=len(df))
col2.metric("Last row_id", value=data.get("last_row_id", 0))
col3.metric("Last refresh (local time)", value=time.strftime("%H:%M:%S"))

# Determine "new since last refresh"
last_seen = st.session_state.get("last_seen_row_id", 0)
if not df.empty:
    newest_row = int(df["row_id"].max())
else:
    newest_row = last_seen

new_df = df[df["row_id"] > last_seen].sort_values("row_id")
st.subheader("New alerts this refresh")
st.dataframe(new_df, use_container_width=True, height=220)

# Main table
st.subheader("All alerts")
if order_opt == "Newest first" and not df.empty:
    df_show = df.sort_values("row_id", ascending=False)
else:
    df_show = df.sort_values("row_id", ascending=True)
st.dataframe(
    df_show[
        [
            c for c in [
                "row_id", "src_ip", "dst_ip", "dst_port", "protocol",
                "approx_packets_per_s", "approx_bytes_per_s", "y_prob", "mitre_tags"
            ] if c in df_show.columns
        ]
    ],
    use_container_width=True,
    height=520,
)

# Update "last seen" AFTER rendering
st.session_state["last_seen_row_id"] = max(last_seen, newest_row)

# Summary (heuristic or Gemini, depending on backend)
st.subheader("Analyst summary")
sum_json, sum_err = fetch_json("/summary")
if sum_err:
    st.warning(f"Summary unavailable: {sum_err}")
else:
    st.info(sum_json.get("summary", ""))

# Auto-refresh mechanism - use JavaScript to reliably refresh every 30 seconds
# This ensures the page refreshes automatically without requiring user interaction
st.markdown(
    f"""
    <meta http-equiv="refresh" content="{PAGE_REFRESH_SEC}">
    <script>
        setTimeout(function() {{
            window.location.reload();
        }}, {PAGE_REFRESH_SEC * 1000});
    </script>
    """,
    unsafe_allow_html=True
)

# Also check Python timer as backup
current_time_check = time.time()
time_since_last_refresh = current_time_check - st.session_state.refresh_timestamp

# Reset refresh timestamp if 30 seconds have passed (helps keep countdown accurate)
if time_since_last_refresh >= PAGE_REFRESH_SEC:
    st.session_state.refresh_timestamp = current_time_check
