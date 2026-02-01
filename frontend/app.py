import streamlit as st
import requests

# ------------------ PAGE CONFIG ------------------
st.set_page_config(
    page_title="TICE Dashboard",
    layout="wide"
)

# ------------------ HEADER ------------------
st.markdown(
    "<h1 style='text-align:center;'>🔐 Threat Intelligence Correlation Engine</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align:center;'>Multi-source IP threat analysis dashboard</p>",
    unsafe_allow_html=True
)

st.divider()

# ------------------ LAYOUT ------------------
left, right = st.columns([1, 2])

# ------------------ INPUT PANEL ------------------
with left:
    st.subheader("🔎 IP Analysis")
    ip_address = st.text_input(
        "Target IP Address",
        placeholder="8.8.8.8"
    )
    analyze_btn = st.button("🚀 Analyze")

    st.info(
        "This engine correlates multiple CTI feeds "
        "to generate a unified threat verdict."
    )

# ------------------ BACKEND ------------------
BACKEND_URL = "http://127.0.0.1:8000/analyze"

# ------------------ RESULT PANEL ------------------
with right:
    if analyze_btn:
        if not ip_address:
            st.warning("Please enter a valid IP address.")
        else:
            with st.spinner("Collecting threat intelligence..."):
                try:
                    response = requests.post(
                        BACKEND_URL,
                        json={"ip": ip_address},
                        timeout=20
                    )

                    if response.status_code == 200:
                        data = response.json()

                        verdict = data.get("verdict", "Unknown")
                        score = data.get("malicious_score", 0)

                        # ------------------ VERDICT CARD ------------------
                        if verdict == "Malicious":
                            st.error("🚨 MALICIOUS IP DETECTED")
                        elif verdict == "Suspicious":
                            st.warning("⚠️ SUSPICIOUS ACTIVITY")
                        else:
                            st.success("✅ IP IS BENIGN")

                        # ------------------ SCORE ------------------
                        st.subheader("📊 Threat Risk Score")
                        st.progress(min(score, 100))
                        st.caption(f"Risk Level: {score}/100")

                        # ------------------ META INFO ------------------
                        c1, c2 = st.columns(2)
                        with c1:
                            st.metric("🌍 Country", data.get("geo_location", "N/A"))
                        with c2:
                            st.metric("🏢 ASN", data.get("asn", "N/A"))

                        # ------------------ CATEGORIES ------------------
                        st.subheader("🧠 Threat Categories")
                        cats = data.get("threat_categories", [])
                        if cats:
                            for cat in cats:
                                st.markdown(f"- **{cat}**")
                        else:
                            st.write("No threat categories identified.")

                        # ------------------ SOURCES ------------------
                        st.subheader("📡 Intelligence Sources")
                        sources = data.get("sources", [])

                        if sources:
                            for src in sources:
                                with st.expander(f"🔍 {src['source']}"):
                                    st.json(src)
                        else:
                            st.info("No source data available.")

                    else:
                        st.error("Backend failed to analyze IP.")

                except Exception as e:
                    st.error(f"Could not connect to backend: {e}")

    else:
        st.info("👈 Enter an IP address to start analysis.")
