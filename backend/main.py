from fastapi import FastAPI, Query
from dotenv import load_dotenv
import os

# 1️⃣ Load environment variables
load_dotenv()

# 2️⃣ Import IP services (FIXED IMPORTS)
from services.abuseipdb_service import check_ip_abuseipdb
from services.shodan_service import check_ip_shodan
from services.virustotal_service import check_ip_virustotal

# 3️⃣ Import URL service
from services.virustotal_url_service import check_url_virustotal

# 4️⃣ Import normalization + correlation logic
from core.normalizer import (
    normalize_abuseipdb,
    normalize_shodan,
    normalize_virustotal
)
from core.correlator import correlate, correlate_url

# 5️⃣ FastAPI app
app = FastAPI(
    title="AI-Driven Threat Intelligence Correlation Engine (TICE)",
    description="Threat intelligence analysis for IP addresses and URLs",
    version="1.0"
)

# ---------------- ROOT ----------------
@app.get("/")
def root():
    return {
        "message": "TICE Backend is running successfully 🚀"
    }

# ---------------- ANALYZE IP ----------------
@app.get("/analyze/ip/{ip}")
def analyze_ip(ip: str):
    # Raw data
    abuse = check_ip_abuseipdb(ip)
    shodan = check_ip_shodan(ip)
    vt = check_ip_virustotal(ip)

    # Normalize
    abuse_n = normalize_abuseipdb(abuse)
    shodan_n = normalize_shodan(shodan)
    vt_n = normalize_virustotal(vt)

    # Correlate
    correlation = correlate(abuse_n, shodan_n, vt_n)

    return {
        "ip": ip,
        "abuseipdb": abuse_n,
        "shodan": shodan_n,
        "virustotal": vt_n,
        "correlation": correlation
    }

# ---------------- ANALYZE URL ----------------
@app.get("/analyze/url")
def analyze_url(url: str = Query(..., description="URL to analyze")):
    vt_data = check_url_virustotal(url)
    correlation = correlate_url(vt_data)

    return {
        "url": url,
        "virustotal": vt_data,
        "correlation": correlation
    }

# ---------------- DEBUG ENV ----------------
@app.get("/debug/env")
def debug_env():
    return {
        "abuseipdb_key_loaded": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "shodan_key_loaded": bool(os.getenv("SHODAN_API_KEY")),
        "virustotal_key_loaded": bool(os.getenv("VT_API_KEY")),
    }
