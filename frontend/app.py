import streamlit as st
import requests
import pandas as pd
import os
import datetime
import joblib
import numpy as np

# --- 1. PAGE SETUP & PATHS ---
st.set_page_config(page_title="TICE Dashboard", page_icon="🛡️", layout="wide")

current_dir = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.abspath(os.path.join(current_dir, "..", "backend", "tice_brain.joblib"))
HISTORY_FILE = os.path.join(current_dir, "ip_history.csv")

# --- 2. TOR CHECK FUNCTION (Official Method) ---
def is_tor_exit_node(ip):
    try:
        # Fetch the official list of active exit nodes
        response = requests.get("https://check.torproject.org/exit-addresses", timeout=5)
        if ip in response.text:
            return True
        return False
    except Exception:
        return False

# --- 3. LOAD AI BRAIN ---
@st.cache_resource
def load_ai_model():
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            return None
    return None

brain = load_ai_model()

# --- 4. CUSTOM CSS ---
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

# --- 5. HISTORY LOGGING ---
def save_search(item, score, verdict, scan_type="IP"):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    new_entry = pd.DataFrame([[now, item, verdict, score, scan_type]],
                             columns=["Time", "Target", "Verdict", "Score", "Type"])
    file_exists = os.path.isfile(HISTORY_FILE)
    new_entry.to_csv(HISTORY_FILE, mode='a', header=not file_exists, index=False)

# --- 6. SIDEBAR: TELEMETRY LOGS ---
with st.sidebar:
    st.title("📡 TICE CORE")
    
    try:
        status_check = requests.get("http://127.0.0.1:8000/", timeout=1)
        if status_check.status_code == 200:
            st.success("✅ Backend Online")
        else:
            st.warning("⚠️ Backend Error")
    except:
        st.error("❌ Backend Offline (Run main.py!)")

    st.markdown("---")
    st.header("Recent Activity")
    
    if os.path.exists(HISTORY_FILE):
        try:
            history_df = pd.read_csv(HISTORY_FILE)
            if not history_df.empty:
                st.dataframe(history_df.tail(10).iloc[::-1], width="stretch", hide_index=True)
                if st.button("🗑️ Clear Logs"):
                    os.remove(HISTORY_FILE)
                    st.rerun()
            else:
                st.info("No logs found.")
        except:
            if os.path.exists(HISTORY_FILE): os.remove(HISTORY_FILE)
            st.rerun()
    else:
        st.info("Logs will appear here.")

# --- 7. MAIN INTERFACE ---
st.title("🛡️ Threat Intelligence Engine")
st.caption("Synchronized API Analysis & Machine Learning Auditor")

tab_ip, tab_url = st.tabs(["🔍 IP REPUTATION", "🔗 URL SIMULATOR"])

# --- TAB: IP ANALYSIS ---
with tab_ip:
    target_ip = st.text_input("Enter IP Address", placeholder="e.g. 8.8.8.8", key="ip_input")
    
    if st.button("Analyze IP", type="primary"):
        if target_ip:
            with st.spinner("Querying API..."):
                try:
                    response = requests.get(f"http://127.0.0.1:8000/analyze/ip/{target_ip}")
                    if response.status_code == 200:
                        data = response.json()
                        st.session_state.last_ip_result = data
                        st.session_state.last_ip_target = target_ip
                        corr = data.get("correlation", {})
                        save_search(target_ip, corr.get("risk_score", 0), corr.get("verdict", "UNKNOWN"), "IP")
                        st.rerun()
                    else:
                        st.error(f"Backend Error: {response.status_code}")
                except Exception as e:
                    st.error(f"Backend unreachable: {e}")

    if "last_ip_result" in st.session_state:
        res = st.session_state.last_ip_result
        target_ip = st.session_state.last_ip_target
        corr = res.get("correlation", {})
        score = corr.get("risk_score", 0)
        verdict = corr.get("verdict", "UNKNOWN")
        
        # --- NEW TOR CHECK INTEGRATION ---
        is_tor = is_tor_exit_node(target_ip)

        st.markdown("---")
        c1, c2, c3 = st.columns([1, 1, 2])
        c1.metric("Risk Score", f"{score}/100")
        c2.metric("Verdict", verdict)
        
        st.progress(max(0.0, min(1.0, score / 100)))

        if is_tor:
            st.error(f"🕵️ **Tor Detection: {target_ip} is an active Tor Exit Node.**")
            st.warning("Note: Traffic from Tor nodes is often used for anonymization and carries higher risk.")
        
        t1, t2, t3 = st.tabs(["AbuseIPDB", "Shodan", "VirusTotal"])
        with t1: st.json(res.get("abuseipdb", {}))
        with t2: st.json(res.get("shodan", {}))
        with t3: st.json(res.get("virustotal", {}))

# --- TAB: URL SIMULATOR ---
with tab_url:
    st.subheader("Link DNA Analysis")
    url_input = st.text_input("Enter URL", placeholder="https://example.com", key="url_input")
    
    if st.button("EXECUTE URL SCAN", type="primary"):
        if url_input:
            with st.spinner("Fetching Threat Data..."):
                try:
                    api_url = f"http://127.0.0.1:8000/analyze/url"
                    response = requests.get(api_url, params={"url": url_input})
                    
                    if response.status_code == 200:
                        data = response.json()
                        st.session_state.last_url_result = data
                        st.session_state.last_url_target = url_input
                        st.rerun()
                    else:
                        st.error(f"Backend API Error: {response.status_code}")
                except Exception:
                    st.error(f"Connection Failed: Ensure the backend is running.")

    if "last_url_result" in st.session_state:
        url_res = st.session_state.last_url_result
        target_url = st.session_state.last_url_target
        vt_data = url_res.get("virustotal", {})
        
        st.markdown("---")
        st.subheader("🤖 TICE AI Auditor")
        
        prob = 0.0
        if brain:
            danger_words = ['login', 'secure', 'verify', 'update', 'banking', 'account', 'signin', 'ebay', 'paypal', 'office365']
            found_danger = any(word in target_url.lower() for word in danger_words)
            
            dna_features = [[
                len(target_url), 
                target_url.count('.'), 
                target_url.count('-'), 
                sum(c.isdigit() for c in target_url), 
                1 if '@' in target_url else 0,
                1 if target_url.startswith('http://') else 0
            ]]
            
            prob = brain.predict_proba(dna_features)[0][1] * 100
            
            if found_danger:
                prob = max(prob, 65.0)
                prob = min(98.0, prob + 20.0)
            
            a1, a2 = st.columns([1, 2])
            a1.metric("AI Suspicion Level", f"{prob:.1f}%")
            with a2:
                st.progress(max(0.0, min(1.0, prob / 100)))
                if prob > 60:
                    st.error("🚨 AI Insight: Phishing keywords or high-risk structural DNA detected!")
                elif prob > 30:
                    st.warning("⚠️ AI Insight: Unusual URL characteristics observed.")
                else:
                    st.success("✅ AI Insight: URL structure appears legitimate.")
        
        # --- Unified Verdict Logic (Stabilized) ---
        st.markdown("---")
        st.subheader("🛡️ Unified Threat Intelligence Result")

        api_hits = vt_data.get("malicious", 0)
        
        if api_hits > 0 or prob > 75.0:
            final_verdict = "MALICIOUS"
            v_color = "red"
        elif prob > 45.0:
            final_verdict = "SUSPICIOUS"
            v_color = "orange"
        else:
            final_verdict = "CLEAN"
            v_color = "green"

        # Use MAX to avoid 280/100 error
        consolidated_score = max(prob, min(100.0, api_hits * 10))
        
        f1, f2 = st.columns([1, 2])
        f1.markdown(f"**Final Consolidated Verdict**\n### :{v_color}[{final_verdict}]")
        with f2:
            st.write(f"**Max Risk Score: {consolidated_score:.1f}/100**")
            st.progress(max(0.0, min(1.0, consolidated_score / 100)))
            st.info("Combined analysis of AI structural patterns and global threat databases.")

        with st.expander("🔭 View Raw API Response"):
            st.json(url_res)