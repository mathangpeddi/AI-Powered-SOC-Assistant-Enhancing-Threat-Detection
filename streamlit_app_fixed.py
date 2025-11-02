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
col2.metric("Last row_id", value=data.get("last_row_id", 0) if not err else 0)
col3.metric("Last refresh (local time)", value=time.strftime("%H:%M:%S"))

# Determine "new since last refresh"
last_seen = st.session_state.get("last_seen_row_id", 0)
if not df.empty and "row_id" in df.columns:
    newest_row = int(df["row_id"].max())
else:
    newest_row = last_seen

# Filter new alerts only if DataFrame has row_id column
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

# Tabs for different AI features
tab1, tab2, tab3 = st.tabs(["Prioritized Alerts", "Clustered Alerts", "Detailed Analysis"])

with tab1:
    st.markdown("### Top Priority Alerts (AI-Scored)")
    priority_data, priority_err = fetch_json("/alerts/prioritized", params={"limit": 20, "min_priority": 0.3})
    if priority_err:
        st.warning(f"Priority scoring unavailable: {priority_err}")
    elif priority_data and priority_data.get("alerts"):
        priority_df = pd.DataFrame(priority_data["alerts"])
        if "ai_priority_score" in priority_df.columns:
            # Show key columns with priority score
            display_cols = ["row_id", "src_ip", "dst_ip", "dst_port", "protocol", "ai_priority_score", "y_prob", "mitre_tags"]
            display_cols = [c for c in display_cols if c in priority_df.columns]
            st.dataframe(
                priority_df[display_cols].sort_values("ai_priority_score", ascending=False),
                use_container_width=True,
                height=400
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
            with st.expander(f"Cluster {cluster_id} ({cluster_info['count']} alerts) - {cluster_info.get('root_cause_hypothesis', 'No hypothesis')}"):
                cluster_df = pd.DataFrame(cluster_info["alerts"])
                if not cluster_df.empty:
                    st.dataframe(cluster_df[["row_id", "src_ip", "dst_ip", "dst_port", "protocol", "mitre_tags", "y_prob"]], use_container_width=True)
                    st.markdown(f"**Root Cause Hypothesis:** {cluster_info.get('root_cause_hypothesis', 'Analysis in progress')}")
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
                st.dataframe(alert_df[["row_id", "src_ip", "dst_ip", "dst_port", "protocol", "mitre_tags", "y_prob"]], use_container_width=True)

# Threat Intelligence Section
st.divider()
st.subheader("🌍 Threat Intelligence & Geographic Analysis")

# Tabs for threat intelligence features
ti_tab1, ti_tab2, ti_tab3 = st.tabs(["IP Reputation", "Geographic Map", "MITRE Techniques"])

with ti_tab1:
    st.markdown("### IP Reputation Check")
    
    # Use session state to persist lookup results
    if "ip_lookup_result" not in st.session_state:
        st.session_state.ip_lookup_result = None
        st.session_state.ip_lookup_error = None
    
    ip_to_check = st.text_input("Enter IP address to check", placeholder="e.g., 8.8.8.8", key="ip_input")
    
    # Check if it's a private IP (properly check ranges)
    is_private = False
    if ip_to_check:
        try:
            # Parse IP address
            parts = ip_to_check.strip().split('.')
            if len(parts) == 4:
                parts = [int(p) for p in parts]
                # Check private IP ranges:
                # 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
                # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
                # 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
                if parts[0] == 10:
                    is_private = True
                elif parts[0] == 172 and 16 <= parts[1] <= 31:
                    is_private = True
                elif parts[0] == 192 and parts[1] == 168:
                    is_private = True
                elif parts[0] == 127:
                    is_private = True  # Loopback
                elif parts[0] == 0 or parts[0] >= 224:
                    is_private = True  # Reserved/multicast
        except (ValueError, IndexError):
            # Invalid IP format, will be handled by backend
            pass
        
        if is_private:
            st.warning("⚠️ Private IP address detected. Threat intelligence lookups may not work for private IPs.")
    
    # Button to trigger lookup
    col_btn1, col_btn2 = st.columns([1, 5])
    with col_btn1:
        check_button = st.button("🔍 Check IP", type="primary", use_container_width=True)
    with col_btn2:
        if st.button("Clear", use_container_width=True):
            st.session_state.ip_lookup_result = None
            st.session_state.ip_lookup_error = None
            st.rerun()
    
    # Trigger lookup on button click
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
            
            # Show clear message for private IPs
            if is_private_from_api or is_private:
                st.info("ℹ️ **This is a private IP address.** External threat intelligence services (AbuseIPDB, GeoIP, WHOIS) cannot look up private IPs as they are not routable on the public internet. This is expected behavior.")
            
            col1, col2, col3 = st.columns(3)
            
            # AbuseIPDB data
            if intel_data.get("abuseipdb"):
                abuse = intel_data["abuseipdb"]
                with col1:
                    reputation_score = abuse.get('ip_reputation', 0)
                    st.metric("Abuse Score", f"{reputation_score}%")
                    st.caption(f"Reports: {abuse.get('total_reports', 0)}")
                    if abuse.get('isp'):
                        st.info(f"ISP: {abuse.get('isp')}")
                    else:
                        st.info("ISP: unknown")
            else:
                with col1:
                    if is_private_from_api or is_private:
                        st.warning("⚠️ **Private IP**\nExternal lookup not possible")
                    else:
                        st.info("ℹ️ **AbuseIPDB data not available**\n\nSet ABUSEIPDB_API_KEY environment variable for IP reputation checks.\n\nGet free API key: https://www.abuseipdb.com/")
            
            # GeoIP data
            if intel_data.get("geoip"):
                geo = intel_data["geoip"]
                with col2:
                    country = geo.get("country_name", "unknown")
                    st.metric("Country", country)
                    city = geo.get("city", "unknown")
                    if city != "unknown":
                        st.caption(f"City: {city}")
                    else:
                        st.caption("City: unknown")
                    if geo.get("latitude") and geo.get("longitude"):
                        st.info(f"📍 {geo.get('latitude')}, {geo.get('longitude')}")
            else:
                with col2:
                    if is_private_from_api or is_private:
                        st.warning("⚠️ **Private IP**\nNo geographic data available")
                    else:
                        st.info("ℹ️ **GeoIP data unavailable**\n\nTrying to fetch location data...")
            
            # WHOIS data
            if intel_data.get("whois"):
                whois = intel_data["whois"]
                with col3:
                    asn = whois.get("asn", "unknown")
                    st.metric("ASN", str(asn) if asn != "unknown" else "unknown")
                    network = whois.get("network", "unknown")
                    st.caption(f"Network: {network}")
                    isp = whois.get("asn_description", "unknown")
                    if isp != "unknown":
                        st.info(f"ISP: {isp}")
            else:
                with col3:
                    if is_private_from_api or is_private:
                        st.warning("⚠️ **Private IP**\nNo network info available")
                    else:
                        st.info("ℹ️ **WHOIS data unavailable**\n\nMay require ipwhois library installation")

with ti_tab2:
    st.markdown("### Attack Origin World Map")
    geo_summary_data, geo_err = fetch_json("/alerts/geo-summary")
    if geo_err:
        st.warning(f"Geographic analysis unavailable: {geo_err}")
    elif geo_summary_data and geo_summary_data.get("countries"):
        countries = geo_summary_data["countries"]
        st.success(f"📊 Alerts from {geo_summary_data.get('total_countries', 0)} countries")
        
        # Create country stats table
        country_data = []
        for country_code, stats in countries.items():
            country_data.append({
                "Country": stats.get("name", country_code),
                "Code": country_code,
                "Alert Count": stats.get("alert_count", 0),
                "Unique IPs": stats.get("unique_ips", 0),
                "Top MITRE": ", ".join([k for k, v in stats.get("top_mitre_techniques", {}).items()])
            })
        
        country_df = pd.DataFrame(country_data)
        if not country_df.empty:
            country_df = country_df.sort_values("Alert Count", ascending=False)
            st.dataframe(country_df, use_container_width=True, height=400)
            
            # Simple visualization using country codes
            st.markdown("#### Country Distribution")
            top_countries = country_df.head(10)
            st.bar_chart(top_countries.set_index("Country")[["Alert Count"]])
            
            # Note: For actual world map, would need folium/plotly
            st.info("💡 Note: For interactive world map visualization, install plotly or folium")
        else:
            st.info("No geographic data available yet. Wait for more alerts with public IPs.")
    else:
        st.info("No geographic data available. Ensure alerts contain public IP addresses.")

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

# Enriched Alerts Section
st.divider()
st.subheader("🎯 Threat Intelligence Enriched Alerts")

enriched_data, enriched_err = fetch_json("/alerts/enriched", params={"limit": 20, "enrich": True})
if enriched_err:
    st.warning(f"Enriched alerts unavailable: {enriched_err}")
elif enriched_data and enriched_data.get("alerts"):
    enriched_df = pd.DataFrame(enriched_data["alerts"])
    
    # Show key columns including threat intel data
    display_cols = ["row_id", "src_ip", "src_ip_country", "src_ip_reputation", "dst_port", "protocol", "mitre_tags", "ai_priority_score"]
    display_cols = [c for c in display_cols if c in enriched_df.columns]
    
    st.dataframe(
        enriched_df[display_cols].sort_values("ai_priority_score", ascending=False),
        use_container_width=True,
        height=400
    )
    
    st.caption(f"Showing {enriched_data.get('total', 0)} alerts enriched with threat intelligence data")
    
    # Show IPs with high reputation scores
    if "src_ip_reputation" in enriched_df.columns:
        high_risk = enriched_df[enriched_df["src_ip_reputation"] > 50]
        if not high_risk.empty:
            st.warning(f"⚠️ {len(high_risk)} alerts from IPs with reputation score > 50%")
else:
    st.info("No enriched alerts available yet.")

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

