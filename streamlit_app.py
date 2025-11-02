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

# Calculate time until next refresh
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

# SOC Assistant Chat
st.sidebar.divider()
st.sidebar.header("🤖 SOC Assistant")
st.sidebar.caption("Ask questions about alerts, analyze patterns, or get insights")

# Initialize chat history
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# Display chat history
with st.sidebar.expander("💬 Chat", expanded=False):
    chat_container = st.container()
    with chat_container:
        # Show chat messages
        for msg in st.session_state.chat_history:
            if msg["role"] == "user":
                st.chat_message("user").write(msg["content"])
            elif msg["role"] == "assistant":
                st.chat_message("assistant").write(msg["content"])

        # Chat input
        user_query = st.text_input(
            "Ask a question...",
            key="chat_input",
            placeholder='e.g., "Show alerts from Russia" or "Why is port 22 risky?"'
        )

        if user_query:
            # Add user message to history
            st.session_state.chat_history.append({"role": "user", "content": user_query})

            # Show user message immediately
            st.chat_message("user").write(user_query)

            # Get assistant response from backend
            with st.spinner("🤖 Thinking..."):
                try:
                    chat_data = {
                        "query": user_query,
                        "history": st.session_state.chat_history[:-1]
                    }

                    # Call POST endpoint
                    response_obj = requests.post(
                        f"{API_BASE}/chat/query",
                        json=chat_data,
                        timeout=15
                    )

                    if response_obj.status_code == 200:
                        response_data = response_obj.json()
                        response = response_data.get("response", "I'm processing your query...")
                        relevant_alerts = response_data.get("relevant_alerts", [])
                    else:
                        response = f"⚠️ Error: Backend returned status {response_obj.status_code}. Chat functionality may be unavailable."
                        relevant_alerts = []

                    st.session_state.chat_history.append({"role": "assistant", "content": response})
                    st.chat_message("assistant").write(response)

                    # Show relevant alerts if any
                    if relevant_alerts:
                        with st.expander(f"📋 Related Alerts ({len(relevant_alerts)})"):
                            alerts_df = pd.DataFrame(relevant_alerts)
                            if not alerts_df.empty:
                                display_cols = ["row_id", "src_ip", "dst_port", "protocol", "y_prob", "mitre_tags"]
                                display_cols = [c for c in display_cols if c in alerts_df.columns]
                                st.dataframe(alerts_df[display_cols], use_container_width=True)

                except Exception as e:
                    error_msg = f"⚠️ Error: {str(e)}. Chat functionality is still being set up."
                    st.session_state.chat_history.append({"role": "assistant", "content": error_msg})
                    st.chat_message("assistant").write(error_msg)

                st.rerun()

        # Clear chat button
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()


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

# Format mitre_tags for better display
if not df.empty and "mitre_tags" in df.columns:
    df["mitre_tags"] = df["mitre_tags"].apply(
        lambda x: ", ".join(x) if isinstance(x, list) else (str(x) if pd.notna(x) else "")
    )

col1, col2, col3 = st.columns(3)
col1.metric("Total alerts loaded", value=len(df))
col2.metric("Last row_id", value=data.get("last_row_id", 0) if not err else 0)
col3.metric("Last refresh (local time)", value=time.strftime("%H:%M:%S"))

# Determine "new since last refresh"
last_seen = st.session_state.get("last_seen_row_id", 0)
if not df.empty and "row_id" in df.columns:
    newest_row = int(df["row_id"].max())
else:
    newest_row = last_seen

# Filter new alerts only
if not df.empty and "row_id" in df.columns:
    new_df = df[df["row_id"] > last_seen].sort_values("row_id")
else:
    new_df = pd.DataFrame()

st.subheader("New alerts this refresh")
if not new_df.empty:
    st.dataframe(new_df, use_container_width=True, height=220)
else:
    st.info("No new alerts this refresh.")

# Main table
st.subheader("All alerts")
if not df.empty and "row_id" in df.columns:
    if order_opt == "Newest first":
        df_show = df.sort_values("row_id", ascending=False)
    else:
        df_show = df.sort_values("row_id", ascending=True)
else:
    df_show = df

st.dataframe(
    df_show[
        [
            c
            for c in [
                "row_id",
                "src_ip",
                "dst_ip",
                "dst_port",
                "protocol",
                "approx_packets_per_s",
                "approx_bytes_per_s",
                "y_prob",
                "mitre_tags",
            ]
            if c in df_show.columns
        ]
    ],
    use_container_width=True,
    height=520,
)

# Update "last seen"
if not df.empty and "row_id" in df.columns:
    st.session_state["last_seen_row_id"] = max(last_seen, newest_row)

# Summary (AI-powered LLM summaries)
st.subheader("AI-Powered Analyst Summary")
sum_json, sum_err = fetch_json("/summary", params={"use_llm": True})
if sum_err:
    st.warning(f"Summary unavailable: {sum_err}")
else:
    summary_text = sum_json.get("summary", "")
    if sum_json.get("llm_enhanced"):
        st.success("🤖 AI-Enhanced Summary")
    st.info(summary_text)

# AI-Powered Insights Section
st.divider()
st.subheader("🔍 AI-Powered Insights")

tab1, tab2, tab3 = st.tabs(["Prioritized Alerts", "Clustered Alerts", "Detailed Analysis"])

with tab1:
    st.markdown("### Top Priority Alerts (AI-Scored)")
    priority_data, priority_err = fetch_json("/alerts/prioritized", params={"limit": 20, "min_priority": 0.3})
    if priority_err:
        st.warning(f"Priority scoring unavailable: {priority_err}")
    elif priority_data and priority_data.get("alerts"):
        priority_df = pd.DataFrame(priority_data["alerts"])
        if "ai_priority_score" in priority_df.columns:
            display_cols = [
                "row_id",
                "src_ip",
                "dst_ip",
                "dst_port",
                "protocol",
                "ai_priority_score",
                "y_prob",
                "mitre_tags",
            ]
            display_cols = [c for c in display_cols if c in priority_df.columns]
            st.dataframe(
                priority_df[display_cols].sort_values("ai_priority_score", ascending=False),
                use_container_width=True,
                height=400,
            )
            st.caption(f"Showing top {priority_data.get('returned', 0)} alerts by AI priority score")
    else:
        st.info("No high-priority alerts found.")

with tab2:
    st.markdown("### Alert Clusters & Root Cause Analysis")
    cluster_data, cluster_err = fetch_json("/alerts/clustered", params={"min_cluster_size": 2})
    if cluster_err:
        st.warning(f"Clustering unavailable: {cluster_err}")
    elif cluster_data and cluster_data.get("clusters"):
        clusters = cluster_data["clusters"]
        st.success(f"Found {cluster_data.get('total_clusters', 0)} alert clusters")

        for cluster_id, cluster_info in clusters.items():
            with st.expander(
                f"Cluster {cluster_id} ({cluster_info['count']} alerts) - {cluster_info.get('root_cause_hypothesis', 'No hypothesis')}"
            ):
                cluster_df = pd.DataFrame(cluster_info["alerts"])
                if not cluster_df.empty:
                    st.dataframe(
                        cluster_df[
                            ["row_id", "src_ip", "dst_ip", "dst_port", "protocol", "mitre_tags", "y_prob"]
                        ],
                        use_container_width=True,
                    )
                    st.markdown(
                        f"**Root Cause Hypothesis:** {cluster_info.get('root_cause_hypothesis', 'Analysis in progress')}"
                    )
    else:
        st.info("No alert clusters found. Try increasing minimum cluster size or wait for more alerts.")

with tab3:
    st.markdown("### Alert Explanation Tool")
    alert_id_to_explain = st.number_input("Enter Alert ID to explain", min_value=0, value=0, step=1)
    if alert_id_to_explain > 0:
        explain_data, explain_err = fetch_json(f"/alerts/{int(alert_id_to_explain)}/explain")
        if explain_err:
            st.error(f"Could not explain alert: {explain_err}")
        elif explain_data:
            col1, col2 = st.columns(2)
            with col1:
                st.metric("AI Priority Score", f"{explain_data.get('ai_priority_score', 0):.2%}")
            with col2:
                st.metric("Threat Probability", f"{explain_data.get('alert', {}).get('y_prob', 0):.2%}")

            st.markdown("#### Why was this flagged?")
            st.info(explain_data.get("explanation", "No explanation available"))

            if explain_data.get("alert"):
                st.markdown("#### Alert Details")
                alert_df = pd.DataFrame([explain_data["alert"]])
                st.dataframe(
                    alert_df[
                        ["row_id", "src_ip", "dst_ip", "dst_port", "protocol", "mitre_tags", "y_prob"]
                    ],
                    use_container_width=True,
                )

            # SHAP-like Feature Importance
            st.markdown("---")
            st.markdown("#### 🔍 Feature Importance (SHAP-like Explanation)")
            feature_data, feature_err = fetch_json(f"/alerts/{int(alert_id_to_explain)}/explain-features")
            if feature_err:
                st.warning(f"Feature explanation unavailable: {feature_err}")
            elif feature_data:
                # Display feature importance as bars
                if feature_data.get("features"):
                    features = feature_data["features"]

                    # Create a DataFrame for visualization
                    feature_list = []
                    for feat_name, feat_info in features.items():
                        feature_list.append({
                            "Feature": feat_name.replace("_", " ").title(),
                            "Importance": feat_info.get("importance", 0),
                            "Value": str(feat_info.get("value", "")),
                            "Impact": feat_info.get("impact", "neutral")
                        })

                    if feature_list:
                        feat_df = pd.DataFrame(feature_list)
                        feat_df = feat_df.sort_values("Importance", ascending=True)

                        # Show as horizontal bar chart
                        st.bar_chart(feat_df.set_index("Feature")[["Importance"]])

                        # Show detailed explanations
                        if feature_data.get("explanations"):
                            st.markdown("**Detailed Explanations:**")
                            for explanation in feature_data["explanations"]:
                                st.write(f"- {explanation}")

                        st.caption(
                            f"Total explainable: {feature_data.get('total_feature_importance', 0):.1%} | "
                            f"Base threat probability: {feature_data.get('y_prob', 0):.1%}"
                        )


# Daily SOC Summary Report Section
st.divider()
st.subheader("📋 Daily SOC Summary Report")

# Daily Summary Report
summary_date = st.date_input("Report Date", value=None, help="Select date for report (defaults to today)")
if summary_date:
    date_str = summary_date.strftime("%Y-%m-%d")
else:
    date_str = None

summary_report_data, summary_report_err = fetch_json(
    "/reports/daily-summary",
    params={"date": date_str, "limit": 2000}
)

if summary_report_err:
    st.warning(f"Daily summary unavailable: {summary_report_err}")
elif summary_report_data:
    # Show LLM-enhanced indicator
    if summary_report_data.get("llm_enhanced"):
        st.success("🤖 AI-Generated Daily Summary Report")

    # Display natural language report
    st.markdown("### 📝 Executive Summary")
    report_text = summary_report_data.get("report", "")
    st.markdown(report_text)

    # Show statistics
    stats = summary_report_data.get("statistics", {})
    if stats:
        st.markdown("### 📊 Key Statistics")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Alerts", stats.get("total_alerts", 0))
        with col2:
            st.metric("High-Risk Alerts", stats.get("high_risk_alerts", 0))
        with col3:
            st.metric("Unique Source IPs", stats.get("unique_source_ips", 0))
        with col4:
            st.metric("Unique Ports", stats.get("unique_destination_ports", 0))

    # Show embedded charts
    charts = summary_report_data.get("charts", {})
    if charts:
        st.markdown("### 📈 Visual Analytics")

        chart_tab1, chart_tab2, chart_tab3 = st.tabs(["Top Patterns", "Geographic", "Time Distribution"])

        with chart_tab1:
            # Top IPs
            if charts.get("top_source_ips"):
                st.markdown("#### Top Source IPs")
                ips_df = pd.DataFrame(charts["top_source_ips"])
                ips_df = ips_df.set_index("ip")
                st.bar_chart(ips_df[["count"]])

            # Top Ports
            if charts.get("top_destination_ports"):
                st.markdown("#### Top Destination Ports")
                ports_df = pd.DataFrame(charts["top_destination_ports"])
                ports_df = ports_df.set_index("port")
                st.bar_chart(ports_df[["count"]])

            # MITRE Techniques
            if charts.get("mitre_techniques"):
                st.markdown("#### MITRE Techniques Distribution")
                mitre_df = pd.DataFrame(charts["mitre_techniques"])
                mitre_df = mitre_df.set_index("technique")
                st.bar_chart(mitre_df[["count"]])

        with chart_tab2:
            # Geographic distribution
            if charts.get("geographic_distribution"):
                st.markdown("#### Attack Origins by Country")
                geo_df = pd.DataFrame(charts["geographic_distribution"])
                geo_df = geo_df.set_index("country")
                st.bar_chart(geo_df[["count"]])
            else:
                st.info("Geographic data not available. Enable threat intelligence enrichment for country data.")

        with chart_tab3:
            # Hourly distribution
            if charts.get("hourly_distribution"):
                st.markdown("#### Attack Frequency by Hour")
                hourly_df = pd.DataFrame(charts["hourly_distribution"])
                hourly_df = hourly_df.set_index("hour")
                st.line_chart(hourly_df[["count"]])
            else:
                st.info("Hourly distribution data not available.")

    st.caption(
        f"Report Date: {summary_report_data.get('date', 'N/A')} | "
        f"Alerts Analyzed: {summary_report_data.get('alerts_analyzed', 0)}"
    )
else:
    st.info("Daily summary report unavailable. Ensure there are enough alerts for analysis.")

# Attack Replay Simulation Section
st.divider()
st.subheader("🎬 Attack Replay Simulation")

st.markdown("### 🔍 Simulate Unprotected Port Scenario")
st.caption("See what would happen if a specific port wasn't protected - based on historical attack patterns")

col1, col2 = st.columns(2)
with col1:
    sim_port = st.number_input(
        "Port to Simulate",
        min_value=1,
        max_value=65535,
        value=22,
        step=1,
        help="Port number to simulate as unprotected"
    )
with col2:
    sim_duration = st.number_input(
        "Simulation Duration (hours)",
        min_value=1,
        max_value=168,
        value=24,
        step=1
    )

if st.button("🚀 Run Simulation", type="primary", use_container_width=True):
    with st.spinner("Running attack replay simulation..."):
        sim_data, sim_err = fetch_json(
            "/simulation/replay",
            params={"port": sim_port, "duration_hours": sim_duration, "limit": 1000}
        )

        if sim_err:
            st.error(f"Simulation failed: {sim_err}")
        elif sim_data:
            st.session_state["simulation_result"] = sim_data
            st.rerun()

# Display simulation results
if "simulation_result" in st.session_state:
    sim_data = st.session_state["simulation_result"]

    # Risk Assessment
    risk_assessment = sim_data.get("risk_assessment", {})
    risk_level = risk_assessment.get("risk_level", "unknown")

    if risk_level == "critical":
        st.error(f"🚨 **CRITICAL RISK** - Port {sim_data.get('port', 'N/A')}")
    elif risk_level == "high":
        st.warning(f"⚠️ **HIGH RISK** - Port {sim_data.get('port', 'N/A')}")
    elif risk_level == "medium":
        st.warning(f"⚠️ **MEDIUM RISK** - Port {sim_data.get('port', 'N/A')}")
    else:
        st.info(f"ℹ️ **LOW RISK** - Port {sim_data.get('port', 'N/A')}")

    st.markdown(f"**Risk Score:** {risk_assessment.get('risk_score', 0):.2%}")
    st.info(risk_assessment.get("recommendation", "No recommendation available"))

    # Impact Analysis
    impact = sim_data.get("impact_analysis", {})
    if impact:
        st.markdown("### 📊 Impact Analysis")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Historical Attacks", impact.get("historical_attacks", 0))
        with col2:
            st.metric("Projected Attacks", impact.get("projected_attacks", 0), delta=f"over {sim_data.get('duration_hours', 24)}h")
        with col3:
            st.metric("Projected Data Exfil", f"{impact.get('projected_data_exfil_gb', 0)} GB")
        with col4:
            st.metric("Unique Attackers", impact.get("unique_attackers", 0))

        # Show top attackers
        if impact.get("top_attackers"):
            st.markdown("#### Top Attackers (if port unprotected)")
            attackers_df = pd.DataFrame(impact["top_attackers"])
            attackers_df = attackers_df.set_index("ip")
            st.bar_chart(attackers_df[["count"]])

        # Show MITRE techniques
        if impact.get("mitre_techniques"):
            st.markdown("#### MITRE Techniques Expected")
            mitre_list = []
            for tech in impact["mitre_techniques"]:
                mitre_list.append({
                    "Technique": tech.get("technique", "N/A"),
                    "Expected Occurrences": tech.get("count", 0)
                })
            if mitre_list:
                mitre_df = pd.DataFrame(mitre_list)
                st.dataframe(mitre_df, use_container_width=True)

    # Simulated Attacks
    simulated_attacks = sim_data.get("simulated_attacks", [])
    if simulated_attacks:
        st.markdown("### 🎯 Simulated Attack Examples")
        st.caption(f"Examples of what could happen if port {sim_data.get('port', 'N/A')} was unprotected")

        sim_list = []
        for attack in simulated_attacks[:20]:
            sim_list.append({
                "Alert ID": attack.get("row_id", "N/A"),
                "Source IP": attack.get("src_ip", "N/A"),
                "Protocol": attack.get("protocol", "N/A"),
                "Threat Prob": f"{attack.get('threat_probability', 0):.1%}",
                "Impact": attack.get("simulated_impact", "Unknown"),
                "Packets/s": f"{attack.get('packets_per_sec', 0):.0f}",
                "Bytes/s": f"{attack.get('bytes_per_sec', 0):.0f}",
                "MITRE": ", ".join(attack.get("mitre_tags", []))
            })

        if sim_list:
            sim_df = pd.DataFrame(sim_list)
            st.dataframe(sim_df, use_container_width=True, height=400)

    st.caption(sim_data.get("message", "Simulation complete"))


# Top MITRE Techniques
st.markdown("### 🎯 Top 5 MITRE Techniques Observed Today")
mitre_analytics, mitre_analytics_err = fetch_json("/analytics/mitre-techniques", params={"limit": 500})
if mitre_analytics_err:
    st.warning(f"MITRE analytics unavailable: {mitre_analytics_err}")
elif mitre_analytics and mitre_analytics.get("techniques"):
    techniques = mitre_analytics["techniques"]
    if techniques:
        # Create two columns for better layout
        cols = st.columns(len(techniques) if len(techniques) <= 5 else 5)
        
        for idx, tech in enumerate(techniques):
            with cols[idx % len(cols)]:
                st.metric(
                    label=tech.get("technique_id", "Unknown"),
                    value=f"{tech.get('percentage', 0)}%",
                    delta=f"{tech.get('count', 0)} occurrences"
                )
        
        # Also show as a bar chart
        if len(techniques) > 0:
            tech_df = pd.DataFrame(techniques)
            tech_df = tech_df.set_index("technique_id")
            st.bar_chart(tech_df[["percentage"]])
            st.caption(f"Analyzed {mitre_analytics.get('analyzed_alerts', 0)} alerts | Total occurrences: {mitre_analytics.get('total_technique_occurrences', 0)}")
    else:
        st.info("No MITRE techniques found in recent alerts.")
else:
    st.info("No MITRE analytics available yet.")

# Time-Series Plots
st.markdown("### 📈 Time-Series Analytics")
ts_interval = st.selectbox("Time Interval", [5, 10, 15, 30], index=0, help="Group alerts by time intervals")
ts_data, ts_err = fetch_json("/analytics/timeseries", params={"interval_minutes": ts_interval, "limit": 500})

if ts_err:
    st.warning(f"Time-series data unavailable: {ts_err}")
elif ts_data:
    # Alert Frequency Over Time
    if ts_data.get("frequency"):
        freq_df = pd.DataFrame(ts_data["frequency"])
        if not freq_df.empty:
            st.markdown("#### Alert Frequency Over Time")
            freq_chart = freq_df[["time", "count"]].copy()
            freq_chart = freq_chart.set_index("time")
            st.line_chart(freq_chart)
            st.caption(f"Alert count per {ts_interval}-minute interval")
    
    # Ports Over Time
    if ts_data.get("ports"):
        st.markdown("#### Top Destination Ports Over Time")
        ports_df = pd.DataFrame(ts_data["ports"])
        if not ports_df.empty:
            # Flatten the ports data for visualization
            ports_flat = []
            for _, row in ports_df.iterrows():
                time_val = row["time"]
                for port_info in row["ports"]:
                    ports_flat.append({
                        "time": time_val,
                        "port": port_info["port"],
                        "count": port_info["count"]
                    })
            
            if ports_flat:
                ports_flat_df = pd.DataFrame(ports_flat)
                ports_pivot = ports_flat_df.pivot(index="time", columns="port", values="count").fillna(0)
                st.line_chart(ports_pivot)
                st.caption(f"Port activity per {ts_interval}-minute interval")
    
    # IPs Over Time
    if ts_data.get("ips"):
        st.markdown("#### Top Source IPs Over Time")
        ips_df = pd.DataFrame(ts_data["ips"])
        if not ips_df.empty:
            # Flatten the IPs data for visualization
            ips_flat = []
            for _, row in ips_df.iterrows():
                time_val = row["time"]
                for ip_info in row["ips"]:
                    ips_flat.append({
                        "time": time_val,
                        "ip": ip_info["ip"],
                        "count": ip_info["count"]
                    })
            
            if ips_flat:
                ips_flat_df = pd.DataFrame(ips_flat)
                # Show top 5 IPs to avoid clutter
                top_ips = ips_flat_df.groupby("ip")["count"].sum().nlargest(5).index.tolist()
                ips_filtered = ips_flat_df[ips_flat_df["ip"].isin(top_ips)]
                if not ips_filtered.empty:
                    ips_pivot = ips_filtered.pivot(index="time", columns="ip", values="count").fillna(0)
                    st.line_chart(ips_pivot)
                    st.caption(f"Top source IPs activity per {ts_interval}-minute interval")
else:
    st.info("No time-series data available yet.")

# Threat Intelligence Section
st.divider()
st.subheader("🌍 Threat Intelligence & Geographic Analysis")

# Tabs for threat intelligence features
ti_tab1, ti_tab2, ti_tab3 = st.tabs(["IP Reputation", "Geographic Map", "MITRE Techniques"])

# --- IP Reputation ---
with ti_tab1:
    st.markdown("### IP Reputation Check")

    if "ip_lookup_result" not in st.session_state:
        st.session_state.ip_lookup_result = None
        st.session_state.ip_lookup_error = None

    ip_to_check = st.text_input("Enter IP address to check", placeholder="e.g., 8.8.8.8", key="ip_input")

    # Private IP check
    is_private = False
    if ip_to_check:
        try:
            parts = ip_to_check.strip().split(".")
            if len(parts) == 4:
                parts = [int(p) for p in parts]
                if parts[0] == 10:
                    is_private = True
                elif parts[0] == 172 and 16 <= parts[1] <= 31:
                    is_private = True
                elif parts[0] == 192 and parts[1] == 168:
                    is_private = True
                elif parts[0] == 127:
                    is_private = True
                elif parts[0] == 0 or parts[0] >= 224:
                    is_private = True
        except (ValueError, IndexError):
            pass

        if is_private:
            st.warning("⚠️ Private IP address detected. Threat intelligence lookups may not work for private IPs.")

    col_btn1, col_btn2 = st.columns([1, 5])
    with col_btn1:
        check_button = st.button("🔍 Check IP", type="primary", use_container_width=True)
    with col_btn2:
        if st.button("Clear", use_container_width=True):
            st.session_state.ip_lookup_result = None
            st.session_state.ip_lookup_error = None
            st.rerun()

    if check_button:
        if ip_to_check and ip_to_check.strip():
            with st.spinner("Fetching threat intelligence data..."):
                intel_data, intel_err = fetch_json(f"/threat-intel/ip/{ip_to_check.strip()}")
                st.session_state.ip_lookup_result = intel_data
                st.session_state.ip_lookup_error = intel_err
        else:
            st.warning("Please enter an IP address to check.")

    # Display results
    if st.session_state.ip_lookup_result is not None or st.session_state.ip_lookup_error is not None:
        if st.session_state.ip_lookup_error:
            st.error(f"Threat intelligence lookup failed: {st.session_state.ip_lookup_error}")
        elif st.session_state.ip_lookup_result:
            intel_data = st.session_state.ip_lookup_result
            is_private_from_api = intel_data.get("is_private", False)

            if is_private_from_api or is_private:
                st.info(
                    "ℹ️ **This is a private IP address.** External threat intelligence services (AbuseIPDB, GeoIP, WHOIS) cannot look up private IPs as they are not routable on the public internet."
                )

            col1, col2, col3 = st.columns(3)

            # AbuseIPDB
            if intel_data.get("abuseipdb"):
                abuse = intel_data["abuseipdb"]
                with col1:
                    reputation_score = abuse.get("ip_reputation", 0)
                    st.metric("Abuse Score", f"{reputation_score}%")
                    st.caption(f"Reports: {abuse.get('total_reports', 0)}")
                    st.info(f"ISP: {abuse.get('isp', 'unknown')}")
            else:
                with col1:
                    if is_private_from_api or is_private:
                        st.warning("⚠️ **Private IP**\nExternal lookup not possible")
                    else:
                        st.info(
                            "ℹ️ **AbuseIPDB data not available**\n\nSet ABUSEIPDB_API_KEY environment variable for IP reputation checks."
                        )

            # GeoIP
            if intel_data.get("geoip"):
                geo = intel_data["geoip"]
                with col2:
                    country = geo.get("country_name", "unknown")
                    st.metric("Country", country)
                    city = geo.get("city", "unknown")
                    st.caption(f"City: {city}")
                    if geo.get("latitude") and geo.get("longitude"):
                        st.info(f"📍 {geo.get('latitude')}, {geo.get('longitude')}")
            else:
                with col2:
                    if is_private_from_api or is_private:
                        st.warning("⚠️ **Private IP**\nNo geographic data available")
                    else:
                        st.info("ℹ️ **GeoIP data unavailable**")

            # WHOIS
            if intel_data.get("whois"):
                whois = intel_data["whois"]
                with col3:
                    st.metric("ASN", str(whois.get("asn", "unknown")))
                    st.caption(f"Network: {whois.get('network', 'unknown')}")
                    st.info(f"ISP: {whois.get('asn_description', 'unknown')}")
            else:
                with col3:
                    if is_private_from_api or is_private:
                        st.warning("⚠️ **Private IP**\nNo network info available")
                    else:
                        st.info("ℹ️ **WHOIS data unavailable**")

# --- Geo Map ---
with ti_tab2:
    st.markdown("### Attack Origin World Map")
    geo_summary_data, geo_err = fetch_json("/alerts/geo-summary")
    if geo_err:
        st.warning(f"Geographic analysis unavailable: {geo_err}")
    elif geo_summary_data and geo_summary_data.get("countries"):
        countries = geo_summary_data["countries"]
        st.success(f"📊 Alerts from {geo_summary_data.get('total_countries', 0)} countries")

        country_data = []
        for country_code, stats in countries.items():
            country_data.append(
                {
                    "Country": stats.get("name", country_code),
                    "Code": country_code,
                    "Alert Count": stats.get("alert_count", 0),
                    "Unique IPs": stats.get("unique_ips", 0),
                    "Top MITRE": ", ".join([k for k, v in stats.get("top_mitre_techniques", {}).items()]),
                }
            )

        country_df = pd.DataFrame(country_data)
        if not country_df.empty:
            country_df = country_df.sort_values("Alert Count", ascending=False)
            st.dataframe(country_df, use_container_width=True, height=400)

            st.markdown("#### Country Distribution")
            top_countries = country_df.head(10)
            st.bar_chart(top_countries.set_index("Country")[["Alert Count"]])
            
            # Geo-heatmap using plotly
            try:
                import plotly.express as px
                
                # Prepare data for map
                map_data = []
                for country_code, stats in countries.items():
                    map_data.append({
                        "country": stats.get("name", country_code),
                        "code": country_code,
                        "alert_count": stats.get("alert_count", 0),
                        "unique_ips": stats.get("unique_ips", 0)
                    })
                
                if map_data:
                    map_df = pd.DataFrame(map_data)
                    
                    # Create choropleth map
                    fig = px.choropleth(
                        map_df,
                        locations="code",
                        color="alert_count",
                        hover_name="country",
                        hover_data={"alert_count": True, "unique_ips": True, "code": False},
                        color_continuous_scale="Reds",
                        title="🌍 Attack Source Heatmap - Alert Count by Country",
                        labels={"alert_count": "Alert Count", "code": "Country Code"}
                    )
                    fig.update_geos(projection_type="natural earth")
                    fig.update_layout(height=500)
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.info("💡 Hover over countries to see alert counts and unique IPs")
            except ImportError:
                st.info("💡 For an interactive world map, install plotly: `pip install plotly`")
        else:
            st.info("No geographic data available yet.")
    else:
        st.info("No geographic data available.")

# --- MITRE Techniques ---
with ti_tab3:
    st.markdown("### MITRE ATT&CK Technique Information")
    technique_input = st.text_input("Enter MITRE Technique ID", placeholder="e.g., T1110")
    if technique_input:
        mitre_data, mitre_err = fetch_json(f"/threat-intel/mitre/{technique_input}")
        if mitre_err:
            st.error(f"MITRE lookup failed: {mitre_err}")
        elif mitre_data:
            st.markdown(f"#### {mitre_data.get('id', 'Unknown')}: {mitre_data.get('name', 'Unknown Technique')}")
            st.info(f"**Description:** {mitre_data.get('description', 'No description available')}")

            col1, col2 = st.columns(2)
            with col1:
                if mitre_data.get("tactics"):
                    st.markdown("**Tactics:**")
                    for tactic in mitre_data["tactics"]:
                        st.write(f"- {tactic}")

            with col2:
                if mitre_data.get("platforms"):
                    st.markdown("**Platforms:**")
                    for platform in mitre_data["platforms"]:
                        st.write(f"- {platform}")

            if mitre_data.get("url"):
                st.markdown(f"[🔗 View on MITRE ATT&CK]({mitre_data['url']})")

# --- Enriched Alerts ---
st.divider()
st.subheader("🎯 Threat Intelligence Enriched Alerts")

enriched_data, enriched_err = fetch_json("/alerts/enriched", params={"limit": 20, "enrich": True})
if enriched_err:
    st.warning(f"Enriched alerts unavailable: {enriched_err}")
elif enriched_data and enriched_data.get("alerts"):
    enriched_df = pd.DataFrame(enriched_data["alerts"])

    display_cols = [
        "row_id",
        "src_ip",
        "src_ip_country",
        "src_ip_reputation",
        "dst_port",
        "protocol",
        "mitre_tags",
        "ai_priority_score",
    ]
    display_cols = [c for c in display_cols if c in enriched_df.columns]

    st.dataframe(
        enriched_df[display_cols].sort_values("ai_priority_score", ascending=False),
        use_container_width=True,
        height=400,
    )

    st.caption(f"Showing {enriched_data.get('total', 0)} alerts enriched with threat intelligence data")

    if "src_ip_reputation" in enriched_df.columns:
        high_risk = enriched_df[enriched_df["src_ip_reputation"] > 50]
        if not high_risk.empty:
            st.warning(f"⚠️ {len(high_risk)} alerts from IPs with reputation score > 50%")
else:
    st.info("No enriched alerts available yet.")

# --- Auto-refresh ---
st.markdown(
    f"""
    <meta http-equiv="refresh" content="{PAGE_REFRESH_SEC}">
    <script>
        setTimeout(function() {{
            window.location.reload();
        }}, {PAGE_REFRESH_SEC * 1000});
    </script>
    """,
    unsafe_allow_html=True,
)

current_time_check = time.time()
time_since_last_refresh = current_time_check - st.session_state.refresh_timestamp
if time_since_last_refresh >= PAGE_REFRESH_SEC:
    st.session_state.refresh_timestamp = current_time_check
