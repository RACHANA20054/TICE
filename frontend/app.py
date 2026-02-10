import streamlit as st
import requests
import pandas as pd
import os
import datetime

# --- 1. PAGE SETUP & PATHS ---
st.set_page_config(page_title="TICE Dashboard", page_icon="🛡️", layout="wide")

current_dir = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(current_dir, "ip_history.csv")

# --- 2. CUSTOM CSS ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    div[data-testid="stMetricValue"] { font-size: 28px; color: #00d4ff; }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] {
        height: 50px; background-color: #161b22; border-radius: 5px; color: white;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. CORE SYSTEMS: HISTORY ---
def save_search(item, score, verdict, scan_type="IP"):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    new_entry = pd.DataFrame([[now, item, verdict, score, scan_type]],
                             columns=["Time", "Target", "Verdict", "Score", "Type"])
    file_exists = os.path.isfile(HISTORY_FILE)
    new_entry.to_csv(HISTORY_FILE, mode='a', header=not file_exists, index=False)

# --- 4. SIDEBAR: TELEMETRY LOGS ---
with st.sidebar:
    st.title("📡 TICE CORE")
    st.markdown("---")
    st.header("Recent Scans")
    
    if os.path.exists(HISTORY_FILE):
        try:
            history_df = pd.read_csv(HISTORY_FILE)
            if not history_df.empty:
                st.dataframe(history_df.tail(10).iloc[::-1], width="stretch", hide_index=True)
                if st.button("🗑️ Clear All Logs"):
                    os.remove(HISTORY_FILE)
                    st.session_state.clear() # Clear results too
                    st.rerun()
            else:
                st.info("No scans recorded.")
        except Exception:
            os.remove(HISTORY_FILE)
            st.rerun()
    else:
        st.info("Logs will appear here after a scan.")

# --- 5. MAIN INTERFACE ---
st.title("🛡️ Threat Intelligence Engine")
st.caption("Synchronized Cross-Platform Security Analysis")

tab_ip, tab_url = st.tabs(["🔍 IP REPUTATION", "🔗 URL SIMULATOR"])

# --- TAB: IP ANALYSIS ---
with tab_ip:
    target_ip = st.text_input("Enter IP Address", placeholder="e.g. 1.1.1.1", key="ip_input_field")
    
    if st.button("Analyze IP", type="primary"):
        if target_ip:
            with st.spinner("Intercepting signals..."):
                try:
                    response = requests.get(f"http://127.0.0.1:8000/analyze/ip/{target_ip}")
                    if response.status_code == 200:
                        # Store result in session state so it doesn't "blink" away
                        st.session_state.last_ip_result = response.json()
                        st.session_state.last_ip_target = target_ip
                        
                        res = st.session_state.last_ip_result
                        corr = res.get("correlation", {})
                        save_search(target_ip, corr.get("risk_score", 0), corr.get("verdict", "UNKNOWN"), "IP")
                        st.rerun() # Refresh history
                    else:
                        st.error(f"Backend Error: {response.status_code}")
                except Exception as e:
                    st.error("Backend unreachable. Is FastAPI running?")

    # Persistent Report Display
    if "last_ip_result" in st.session_state:
        res = st.session_state.last_ip_result
        target = st.session_state.last_ip_target
        corr = res.get("correlation", {})
        score, verdict = corr.get("risk_score", 0), corr.get("verdict", "UNKNOWN")

        st.markdown("---")
        c1, c2, c3 = st.columns([1, 1, 2])
        c1.metric("Risk Score", f"{score}/100")
        c2.metric("Verdict", verdict)
        st.progress(score / 100)
        
        if verdict == "MALICIOUS": st.error(f"🚨 CRITICAL THREAT: {target}")
        elif verdict == "SUSPICIOUS": st.warning(f"⚠️ SUSPICIOUS ACTIVITY: {target}")
        else: st.success(f"✅ CLEAN SIGNAL: {target}")

        t1, t2, t3 = st.tabs(["AbuseIPDB", "Shodan", "VirusTotal"])
        with t1: st.json(res.get("abuseipdb", {}))
        with t2: st.json(res.get("shodan", {}))
        with t3: st.json(res.get("virustotal", {}))

# --- TAB: URL SIMULATOR ---
with tab_url:
    st.subheader("Link Analysis & Simulation")
    url_input = st.text_input("Enter URL", placeholder="https://suspicious.com", key="url_input_final")
    
    if st.button("EXECUTE URL SCAN", type="primary"):
        if url_input:
            with st.spinner("Searching for Backend Route..."):
                import urllib.parse
                safe_url = urllib.parse.quote_plus(url_input)
                
                # List of possible routes based on common backend structures
                possible_endpoints = [
                    f"http://127.0.0.1:8000/analyze/url?url={url_input}",
                    f"http://127.0.0.1:8000/scan?url={url_input}",
                    f"http://127.0.0.1:8000/url-analysis?url={url_input}"
                ]
                
                success = False
                for api_url in possible_endpoints:
                    try:
                        response = requests.get(api_url)
                        if response.status_code == 200:
                            st.session_state.last_url_result = response.json()
                            st.session_state.last_url_target = url_input
                            
                            url_res = st.session_state.last_url_result
                            # Extract stats safely
                            stats = url_res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                            m = url_res.get("malicious", stats.get("malicious", 0))
                            
                            save_search(url_input, m, "MALICIOUS" if m > 0 else "CLEAN", "URL")
                            success = True
                            st.rerun()
                            break 
                    except Exception:
                        continue
                
                if not success:
                    st.error("Backend Route Not Found (404).")
                    st.info("Check your backend/main.py for the @app.get('/...') route name.")

   # --- PERSISTENT URL DISPLAY (Fixed for your specific JSON) ---
    if "last_url_result" in st.session_state:
        url_res = st.session_state.last_url_result
        
        # 🛡️ FIX: Your backend puts these inside the "virustotal" key
        vt_data = url_res.get("virustotal", {})
        corr_data = url_res.get("correlation", {})

        # Extract counts from the "virustotal" block
        m = vt_data.get("malicious", 0)
        s = vt_data.get("suspicious", 0)
        h = vt_data.get("harmless", 0)
        
        # Extract verdict from the "correlation" block
        verdict = corr_data.get("verdict", "UNKNOWN")

        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        # Dynamic coloring based on the actual verdict
        v_col = "red" if verdict == "MALICIOUS" else "green"
        
        col1.markdown(f"**Verdict**\n### :{v_col}[{verdict}]")
        col2.metric("Engine Hits", f"{m} Detections")
        col3.metric("Clean Checks", h)
        
        # Visual Summary
        if verdict == "MALICIOUS":
            st.error(f"🚨 This URL has been flagged by {m} security engines!")
        
        chart_df = pd.DataFrame({'Count': [m, s, h]}, index=['Malicious', 'Suspicious', 'Harmless'])
        st.bar_chart(chart_df, width="stretch")
        
        with st.expander("🔬 View Full Telemetry Data"):
            st.json(url_res)

        

   