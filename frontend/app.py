import streamlit as st
import requests
import pandas as pd
import os
import datetime

# --- PAGE SETUP ---
st.set_page_config(page_title="TICE Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ TICE: Threat Intelligence Correlation Engine")
st.markdown("---")

# --- HISTORY SYSTEM ---
HISTORY_FILE = "frontend/ip_history.csv"

def save_search(ip, score, verdict):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    new_entry = pd.DataFrame([[now, ip, verdict, score]],
                             columns=["Time", "IP", "Verdict", "Score"])
    if not os.path.exists(HISTORY_FILE):
        new_entry.to_csv(HISTORY_FILE, index=False)
    else:
        new_entry.to_csv(HISTORY_FILE, mode='a', header=False, index=False)

# Sidebar History
st.sidebar.header("Recent Scans")
if os.path.exists(HISTORY_FILE):
    try:
        history_data = pd.read_csv(HISTORY_FILE)
        st.sidebar.dataframe(history_data.tail(5), use_container_width=True)
    except:
        st.sidebar.write("History log started.")

# --- MAIN INTERFACE ---
target_ip = st.text_input("Search IP Address", placeholder="e.g. 8.8.8.8")

if st.button("Analyze Threat"):
    if target_ip:
        with st.spinner(f"Analyzing {target_ip}..."):
            try:
                # ✅ FIXED ENDPOINT
                response = requests.get(
                    f"http://127.0.0.1:8000/analyze/ip/{target_ip}"
                )

                if response.status_code == 200:
                    res = response.json()

                    corr = res.get("correlation", {})
                    score = corr.get("risk_score", 0)
                    verdict = corr.get("verdict", "UNKNOWN")
                    reasons = corr.get("reasons", [])

                    # --- DISPLAY RESULT ---
                    st.subheader("Correlation Result")
                    c1, c2 = st.columns([1, 3])

                    c1.metric("Risk Score", f"{score}/100")

                    if verdict == "MALICIOUS":
                        c2.error(f"Verdict: {verdict}")
                    elif verdict == "SUSPICIOUS":
                        c2.warning(f"Verdict: {verdict}")
                    else:
                        c2.success(f"Verdict: {verdict}")

                    st.progress(score / 100)

                    # --- REASONS DISPLAY ---
                    if reasons:
                        st.markdown("### 🚨 Detection Reasons")
                        for r in reasons:
                            st.write(f"- {r}")
                    else:
                        st.info("No strong indicators detected.")

                    # Save history
                    save_search(target_ip, score, verdict)

                    # --- DETAILS ---
                    st.markdown("---")
                    t1, t2, t3 = st.tabs(["AbuseIPDB", "Shodan", "VirusTotal"])
                    with t1:
                        st.json(res.get("abuseipdb", {}))
                    with t2:
                        st.json(res.get("shodan", {}))
                    with t3:
                        st.json(res.get("virustotal", {}))

                else:
                    st.error(f"Backend Error: {response.status_code}")

            except Exception as e:
                st.error(f"Backend not reachable: {e}")
    else:
        st.warning("Please enter an IP address.")