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

# --- 2. LOAD AI BRAIN ---
@st.cache_resource
def load_ai_model():
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            return None
    return None

brain = load_ai_model()

# --- 3. CUSTOM CSS ---
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

# --- 4. HISTORY LOGGING ---
def save_search(item, score, verdict, scan_type="IP"):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    new_entry = pd.DataFrame([[now, item, verdict, score, scan_type]],
                             columns=["Time", "Target", "Verdict", "Score", "Type"])
    file_exists = os.path.isfile(HISTORY_FILE)
    new_entry.to_csv(HISTORY_FILE, mode='a', header=not file_exists, index=False)

# --- 5. SIDEBAR: TELEMETRY LOGS ---
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
            os.remove(HISTORY_FILE)
            st.rerun()
    else:
        st.info("Logs will appear here.")

# --- 6. MAIN INTERFACE ---
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
                    # FIX: Correct request logic inside the button block
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
        corr = res.get("correlation", {})
        score = corr.get("risk_score", 0)
        verdict = corr.get("verdict", "UNKNOWN")

        st.markdown("---")
        c1, c2, c3 = st.columns([1, 1, 2])
        c1.metric("Risk Score", f"{score}/100")
        c2.metric("Verdict", verdict)
        st.progress(score / 100)
        
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
                        corr = data.get("correlation", {})
                        save_search(url_input, corr.get("risk_score", 0), corr.get("verdict", "UNKNOWN"), "URL")
                        st.rerun()
                    else:
                        st.error(f"Backend API Error: {response.status_code}")
                except Exception:
                    st.error(f"Connection Failed: Ensure the backend is running.")

    if "last_url_result" in st.session_state:
        url_res = st.session_state.last_url_result
        target_url = st.session_state.last_url_target
        vt_data = url_res.get("virustotal", {})
        corr_data = url_res.get("correlation", {})

        m, s, h = vt_data.get("malicious", 0), vt_data.get("suspicious", 0), vt_data.get("harmless", 0)
        verdict = corr_data.get("verdict", "UNKNOWN")

        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        v_col = "red" if verdict == "MALICIOUS" else "green"
        col1.markdown(f"**API Verdict**\n### :{v_col}[{verdict}]")
        col2.metric("Engine Hits", f"{m} Detections")
        col3.metric("Clean Checks", h)
        # --- 🤖 TICE AI Auditor (Enhanced Logic) ---
        st.markdown("---")
        st.subheader("🤖 TICE AI Auditor")
        
        if brain:
            # 1. KEYWORD WEIGHTING (Detects Deception)
            # Add words common in phishing but rare in simple structural scans
            danger_words = ['login', 'secure', 'verify', 'update', 'banking', 'account', 'signin', 'ebay', 'paypal', 'office365']
            found_danger = any(word in target_url.lower() for word in danger_words)
            
            # 2. FEATURE EXTRACTION
            dna_features = [[
                len(target_url), 
                target_url.count('.'), 
                target_url.count('-'), 
                sum(c.isdigit() for c in target_url), 
                1 if '@' in target_url else 0,
                1 if target_url.startswith('http://') else 0  # http is a risk factor over https
            ]]
            
            # 3. PREDICTION
            # Base probability from your joblib model
            prob = brain.predict_proba(dna_features)[0][1] * 100
            
            # 4. OVERRIDE/PENALTY SYSTEM
            # If "secure" or "login" is found, we boost the score to prevent the "15% trap"
            if found_danger:
                prob = max(prob, 65.0)  # Minimum 65% suspicion if keywords are present
                prob = min(98.0, prob + 20.0) # Add 20% on top of existing suspicion
            
            # 5. UI DISPLAY
            a1, a2 = st.columns([1, 2])
            a1.metric("AI Suspicion Level", f"{prob:.1f}%")
            with a2:
                st.progress(prob / 100)
                if prob > 60:
                    st.error("🚨 AI Insight: Phishing keywords or high-risk structural DNA detected!")
                elif prob > 30:
                    st.warning("⚠️ AI Insight: Unusual URL characteristics observed.")
                else:
                    st.success("✅ AI Insight: URL structure appears legitimate.")
        else:
            st.warning(f"AI Brain is offline. Expected at: {MODEL_PATH}")
        with st.expander("🔭 View Raw API Response"):
            st.json(url_res)
    # --- 🛡️ Unified Verdict & Combined Risk Score ---
       # --- 🛡️ Updated Unified Verdict (Logical "OR" Strategy) ---
        st.markdown("---")
        st.subheader("🛡️ Unified Threat Intelligence Result")

        # 1. Gather individual signals
        api_hits = vt_data.get("malicious", 0)
        ai_is_suspicious = prob > 50.0  # Threshold for your AI Auditor
        
        # 2. Logic: If EITHER flags it, update the final status
        if api_hits > 0 or prob > 75.0:
            final_verdict = "MALICIOUS"
            v_color = "red"
            reason = f"Detected by {'API' if api_hits > 0 else 'AI Auditor'} (Confidence: {max(api_hits*10, prob):.1f}%)"
        elif ai_is_suspicious or api_hits == 0 and prob > 40:
            final_verdict = "SUSPICIOUS"
            v_color = "orange"
            reason = "AI Auditor detects high-risk structural patterns (API reports clean)."
        else:
            final_verdict = "CLEAN"
            v_color = "green"
            reason = "Both API and AI Auditor consider this URL safe."

        # 3. Calculate a truly consolidated score
        # We take the HIGHEST risk value found, not the average
        consolidated_score = max(prob, (api_hits * 20)) 

        # 4. UI Display
        f1, f2 = st.columns([1, 2])
        f1.markdown(f"**Final Consolidated Verdict**\n### :{v_color}[{final_verdict}]")
        with f2:
            st.write(f"**Max Risk Score Detected: {consolidated_score:.1f}/100**")
            st.progress(consolidated_score / 100)
            st.info(f"**Analysis Insight:** {reason}")