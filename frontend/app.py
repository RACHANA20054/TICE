import streamlit as st
import requests

# ------------------ PAGE CONFIG ------------------
st.set_page_config(
    page_title="TICE – Threat Intelligence Dashboard",
    layout="wide"
)

# ------------------ TITLE ------------------
st.title("🔐 Threat Intelligence Correlation Engine (TICE)")
st.markdown("Analyze IP addresses using multiple threat intelligence sources.")

# ------------------ INPUT ------------------
ip_address = st.text_input("Enter IP Address", placeholder="8.8.8.8")

analyze_btn = st.button("Analyze IP")

# ------------------ BACKEND URL ------------------
BACKEND_URL = "http://127.0.0.1:8000/analyze"

# ------------------ ANALYSIS ------------------
if analyze_btn:
    if not ip_address:
        st.warning("Please enter an IP address")
    else:
        with st.spinner("Analyzing threat intelligence..."):
            try:
                response = requests.post(
                    BACKEND_URL,
                    json={"ip": ip_address},
                    timeout=20
                )

                if response.status_code == 200:
                    data = response.json()

                    # Verdict
                    verdict = data.get("verdict", "Unknown")
                    score = data.get("malicious_score", 0)

                    # Verdict Badge
                    if verdict == "Malicious":
                        st.error(f"🚨 Verdict: {verdict}")
                    elif verdict == "Suspicious":
                        st.warning(f"⚠️ Verdict: {verdict}")
                    else:
                        st.success(f"✅ Verdict: {verdict}")

                    # Score
                    st.metric("Threat Score", score)

                    # Categories
                    st.subheader("Threat Categories")
                    st.write(data.get("threat_categories", []))

                    # Geo Info
                    st.subheader("Geolocation & ASN")
                    st.json({
                        "Country": data.get("geo_location"),
                        "ASN": data.get("asn")
                    })

                    # Sources
                    st.subheader("Source Intelligence")
                    for src in data.get("sources", []):
                        with st.expander(src["source"]):
                            st.json(src)

                else:
                    st.error("Backend error while analyzing IP")

            except Exception as e:
                st.error(f"Connection error: {e}")
