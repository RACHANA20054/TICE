from fastapi import FastAPI
from dotenv import load_dotenv
import os

# 1️⃣ Load environment variables (.env)
load_dotenv()

# 2️⃣ Import services
from services.abuseipdb_service import check_ip_abuseipdb
from services.shodan_service import check_ip_shodan
from services.virustotal_service import check_ip_virustotal

# 3️⃣ Import correlation logic
from core.normalizer import (
    normalize_abuseipdb,
    normalize_shodan,
    normalize_virustotal
)
from core.correlator import correlate

# 4️⃣ FastAPI app
app = FastAPI(
    title="AI-Driven Threat Intelligence Correlation Engine",
    description="Consolidated threat intelligence analysis for IP addresses",
    version="1.0"
)

# ---------------- ROOT ----------------
@app.get("/")
def root():
    return {
        "message": "TICE Backend is running successfully 🚀"
    }

# ---------------- ANALYZE IP ----------------
@app.get("/analyze/{ip}")
def analyze_ip(ip: str):
    # Raw data from APIs
    abuse = check_ip_abuseipdb(ip)
    shodan = check_ip_shodan(ip)
    vt = check_ip_virustotal(ip)

    # Normalize data
    abuse_n = normalize_abuseipdb(abuse)
    shodan_n = normalize_shodan(shodan)
    vt_n = normalize_virustotal(vt)

    # Correlate
    correlation = correlate(abuse_n, shodan_n, vt_n)

    return {
        "ip": ip,
        "abuseipdb": abuse,
        "shodan": shodan,
        "virustotal": vt,
        "correlation": correlation
    }

# ---------------- DEBUG ENV ----------------
@app.get("/debug/env")
def debug_env():
    return {
        "abuseipdb_key_loaded": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "shodan_key_loaded": bool(os.getenv("SHODAN_API_KEY")),
        "virustotal_key_loaded": bool(os.getenv("VIRUSTOTAL_API_KEY")),
    }
