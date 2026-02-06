import os
import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_abuseipdb(ip: str):
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=10
    )

    if response.status_code != 200:
        return {
            "error": "AbuseIPDB API failed",
            "status_code": response.status_code,
            "message": response.text
        }

    data = response.json().get("data", {})

    return {
        "source": "AbuseIPDB",
        "abuse_score": data.get("abuseConfidenceScore"),
        "is_public": data.get("isPublic"),
        "country": data.get("countryName"),
        "usage_type": data.get("usageType"),
        "last_reported": data.get("lastReportedAt")
    }
