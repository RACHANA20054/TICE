import streamlit as st
import requests
import pandas as pd
import os
import datetime

# --- PAGE SETUP ---
st.set_page_config(page_title="TICE Dashboard", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR ELEGANCE ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    div[data-testid="stMetricValue"] { font-size: 28px; color: #00d4ff; }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] {
        height: 50px; background-color: #161b22; border-radius: 5px; color: white;
    }
    .status-card {
        padding: 20px; border-radius: 10px; border: 1px solid #30363d;
        background-color: #161b22; margin-bottom: 15px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HISTORY SYSTEM ---
HISTORY_FILE = "frontend/ip_history.csv"

def save_search(item, score, verdict, type="IP"):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    new_entry = pd.DataFrame([[now, item, verdict, score, type]],
                             columns=["Time", "Target", "Verdict", "Score", "Type"])
    new_entry.to_csv(HISTORY_FILE, mode='a', header=not os.path.exists(HISTORY_FILE), index=False)

# --- SIDEBAR HISTORY ---
with st.sidebar:
    st.title("📡 TICE CORE")
    st.markdown("---")
    st.header("Recent Scans")
    if os.path.exists(HISTORY_FILE):
        try:
            history_data = pd.read_csv(HISTORY_FILE)
            st.dataframe(history_data.tail(8), use_container_width=True, hide_index=True)
        except:
            st.write("Telemetry log ready.")

# --- MAIN INTERFACE ---
st.title("🛡️ Threat Intelligence Correlation Engine")
st.caption("Synchronized Cross-Platform Security Analysis")

tab_ip, tab_url = st.tabs(["🔍 IP REPUTATION", "🔗 URL SIMULATOR"])

# --- TAB 1: IP REPUTATION ---
with tab_ip:
    target_ip = st.text_input("Enter IP Address", placeholder="e.g. 8.8.8.8", key="ip_input")
    if st.button("Analyze IP", type="primary"):
        if target_ip:
            with st.spinner(f"Intercepting signals for {target_ip}..."):
                try:
                    response = requests.get(f"http://127.0.0.1:8000/analyze/ip/{target_ip}")
                    if response.status_code == 200:
                        res = response.json()
                        corr = res.get("correlation", {})
                        score, verdict = corr.get("risk_score", 0), corr.get("verdict", "UNKNOWN")
                        
                        # Results Header
                        c1, c2, c3 = st.columns([1, 1, 2])
                        c1.metric("Risk Score", f"{score}/100")
                        c2.metric("Verdict", verdict)
                        
                        st.progress(score / 100)
                        
                        if verdict == "MALICIOUS": st.error(f"🚨 CRITICAL THREAT: {target_ip}")
                        elif verdict == "SUSPICIOUS": st.warning(f"⚠️ SUSPICIOUS ACTIVITY: {target_ip}")
                        else: st.success(f"✅ CLEAN SIGNAL: {target_ip}")

                        # Details Tabs
                        t1, t2, t3 = st.tabs(["AbuseIPDB", "Shodan", "VirusTotal"])
                        t1.json(res.get("abuseipdb", {}))
                        t2.json(res.get("shodan", {}))
                        t3.json(res.get("virustotal", {}))
                        
                        save_search(target_ip, score, verdict, "IP")
                    else: st.error(f"Backend Error: {response.status_code}")
                except Exception as e: st.error(f"Connection Failed: {e}")

# --- TAB 2: URL SIMULATOR ---
with tab_url:
    st.subheader("Link Analysis & Simulation")
    url_input = st.text_input("Enter URL for deep analysis", placeholder="https://suspicious-site.net/login")
    
    if st.button("EXECUTE URL SCAN", type="primary"):
        if url_input:
            with st.spinner("Analyzing URL Security DNA..."):
                try:
                    response = requests.get(f"http://127.0.0.1:8000/analyze-url?url={url_input}")
                    if response.status_code == 200:
                        url_res = response.json()
                        m, s, h = url_res.get("malicious", 0), url_res.get("suspicious", 0), url_res.get("harmless", 0)
                        status = url_res.get("status")

                        # Elegant Metric Row
                        col1, col2, col3 = st.columns(3)
                        
                        # Logic for Verdict
                        if m > 0: v_text, v_col = "❌ MALICIOUS", "red"
                        elif s > 0: v_text, v_col = "⚠️ SUSPICIOUS", "orange"
                        else: v_text, v_col = "✅ CLEAN", "green"

                        col1.markdown(f"**Verdict**\n### :{v_col}[{v_text}]")
                        col2.metric("Detections", f"{m} Engines")
                        col3.metric("Analysis", status)

                        # Visual breakdown
                        st.markdown("---")
                        c_info, c_chart = st.columns([2, 1])
                        with c_info:
                            st.info(f"Summary: Found **{m}** malicious and **{s}** suspicious indicators across **{m+s+h}** security scanners.")
                            st.progress(min((m * 20), 100) / 100) # Simple visual risk gauge
                        
                        with c_chart:
                            st.bar_chart(pd.DataFrame({'Hits': [m, s, h]}, index=['Malicious', 'Suspicious', 'Harmless']))

                        with st.expander("🔬 View Raw JSON Response"):
                            st.json(url_res)
                            
                        save_search(url_input, m, v_text, "URL")
                except Exception as e: st.error(f"URL Service Unreachable: {e}")