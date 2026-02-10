import streamlit as st
import requests

# ---------------- CONFIG ----------------
BACKEND_URL = "http://127.0.0.1:8000/analyze/url"

st.set_page_config(
    page_title="URL Threat Analysis",
    layout="wide"
)

st.title("🔗 URL Threat Intelligence")
st.caption("Powered by VirusTotal")

# ---------------- INPUT ----------------
url = st.text_input(
    "Enter URL to analyze",
    placeholder="https://example.com"
)

scan = st.button("🚨 Scan URL")

# ---------------- PROCESS ----------------
if scan:
    if not url:
        st.warning("Please enter a URL")
    else:
        with st.spinner("Analyzing URL threat intelligence..."):
            try:
                response = requests.get(
                    BACKEND_URL,
                    params={"url": url},
                    timeout=15
                )
                data = response.json()
            except Exception as e:
                st.error(f"Backend connection failed: {e}")
                st.stop()

        # ---------------- RESULTS ----------------
        malicious = data.get("malicious", 0)
        suspicious = data.get("suspicious", 0)
        harmless = data.get("harmless", 0)
        undetected = data.get("undetected", 0)
        status = data.get("status", "UNKNOWN")

        total_engines = malicious + suspicious + harmless + undetected
        risk_score = round(((malicious * 1.0 + suspicious * 0.5) / max(total_engines, 1)) * 100, 2)

        # ---------------- METRICS ----------------
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("🚫 Malicious", malicious)
        col2.metric("⚠️ Suspicious", suspicious)
        col3.metric("✅ Harmless", harmless)
        col4.metric("🎯 Risk Score", f"{risk_score}%")

        # ---------------- VERDICT ----------------
        if risk_score >= 60:
            st.error("🔥 MALICIOUS URL")
        elif risk_score >= 25:
            st.warning("⚠️ SUSPICIOUS URL")
        else:
            st.success("✅ CLEAN URL")

        # ---------------- RAW DATA ----------------
        with st.expander("📄 Raw VirusTotal Response"):
            st.json(data)
