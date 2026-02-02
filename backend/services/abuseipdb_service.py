import requests

ABUSEIPDB_API_KEY = "ebaa1a6e315ac934de3ea7800cb5693867ae70bd154dad5c3452f89cfbaec977699c1af7232faeb3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_abuseipdb(ip: str):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)

    if response.status_code != 200:
        return {"error": "AbuseIPDB API failed"}

    data = response.json()["data"]

    return {
        "source": "AbuseIPDB",
        "abuse_score": data["abuseConfidenceScore"],
        "is_public": data["isPublic"],
        "country": data["countryName"],
        "usage_type": data["usageType"],
        "last_reported": data["lastReportedAt"]
    }
