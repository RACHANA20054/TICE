import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import os

# ------------------ PAGE CONFIG ------------------
st.set_page_config(
    page_title="TICE Cyber Dashboard",
    layout="wide"
)

# ------------------ DARK THEME CSS ------------------
st.markdown("""
<style>
body {
    background-color: #000000;
    color: #ffffff;
}
.block-container {
    padding-top: 1rem;
}
</style>
""", unsafe_allow_html=True)

# ------------------ HEADER ------------------
st.markdown(
    "<h1 style='text-align:center; color:#00ffcc;'>🔐 Threat Intelligence Correlation Engine</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align:center;'>Cyber Threat Intelligence Dashboard</p>",
    unsafe_allow_html=True
)

st.divider()

# ------------------ HISTORY FILE ------------------
HISTORY_FILE = "frontend/ip_history.csv"

if not os.path.exists(HISTORY_FILE):
    df = pd.DataFrame(columns=["Time", "IP", "Verdict", "Score"])
    df.to_csv(HISTORY_FILE, index=False)

# ------------------ LAYOUT ------------------
left, right = st.columns([1, 2])

# ------------------ INPUT PANEL ------------------
with left:
    st.subheader("🔎 IP Analysis")
    ip_address = st.text_input("Target IP", placeholder="8.8.8.8")
    analyze_btn = st.button("🚀 Analyze IP")

    st.info("Correlates multiple CTI feeds into a unified threat verdict.")

# ------------------ BACKEND ------------------
BACKEND_URL = "http://127.0.0.1:8000/analyze"

# ------------------ RESULT PANEL ------------------
with right:
    if analyze_btn and ip_address:
        with st.spinner("Collecting threat intelligence..."):
            try:
                res = requests.post(BACKEND_URL, json={"ip": ip_address}, timeout=20)
                data = res.json()

                verdict = data.get("verdict", "Unknown")
                score = data.get("malicious_score", 0)

                # ------------------ VERDICT ------------------
                if verdict == "Malicious":
                    st.error("🚨 MALICIOUS IP DETECTED")
                elif verdict == "Suspicious":
                    st.warning("⚠️ SUSPICIOUS IP")
                else:
                    st.success("✅ IP IS BENIGN")

                st.subheader("📊 Threat Risk Score")
                st.progress(min(score, 100))
                st.caption(f"Score: {score}/100")

                # ------------------ SAVE HISTORY ------------------
                new_row = {
                    "Time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "IP": ip_address,
                    "Verdict": verdict,
                    "Score": score
                }

                hist_df = pd.read_csv(HISTORY_FILE)
                hist_df = pd.concat([hist_df, pd.DataFrame([new_row])])
                hist_df.to_csv(HISTORY_FILE, index=False)

                # ------------------ META ------------------
                c1, c2 = st.columns(2)
                c1.metric("🌍 Country", data.get("geo_location", "N/A"))
                c2.metric("🏢 ASN", data.get("asn", "N/A"))

                # ------------------ CATEGORIES ------------------
                st.subheader("🧠 Threat Categories")
                cats = data.get("threat_categories", [])
                if cats:
                    st.write(", ".join(cats))
                else:
                    st.write("None detected")

                # ------------------ SOURCES ------------------
                st.subheader("📡 Intelligence Sources")
                for src in data.get("sources", []):
                    with st.expander(src["source"]):
                        st.json(src)

            except Exception as e:
                st.error(f"Backend error: {e}")

    elif analyze_btn:
        st.warning("Enter an IP address")

    else:
        st.info("👈 Enter an IP address to begin analysis")

# ------------------ HISTORY DASHBOARD ------------------
st.divider()
st.subheader("📜 IP Analysis History")

hist_df = pd.read_csv(HISTORY_FILE)

if not hist_df.empty:
    st.dataframe(hist_df, use_container_width=True)

    # ------------------ CHARTS ------------------
    st.subheader("📈 Threat Analytics")

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("**Verdict Distribution**")
        verdict_counts = hist_df["Verdict"].value_counts()
        st.bar_chart(verdict_counts)

    with c2:
        st.markdown("**Average Risk Score**")
        avg_score = hist_df.groupby("Verdict")["Score"].mean()
        st.bar_chart(avg_score)

else:
    st.info("No history available yet.")

