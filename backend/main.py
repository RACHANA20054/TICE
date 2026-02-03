from services.abuseipdb_service import check_ip_abuseipdb
from fastapi import FastAPI


app = FastAPI(
    title="AI-Driven Threat Intelligence Correlation Engine",
    description="Consolidated threat intelligence analysis for IP addresses",
    version="1.0"
)

@app.get("/")
def root():
    return {
        "message": "TICE Backend is running successfully 🚀"
    }

@app.get("/analyze/{ip}")
def analyze_ip(ip: str):
    abuseipdb_result = check_ip_abuseipdb(ip)

    return {
        "ip": ip,
        "abuseipdb": abuseipdb_result
    }

