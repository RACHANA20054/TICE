import base64
import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

def check_url_virustotal(url: str):
    # 1️⃣ Handle missing API key explicitly
    if not VT_API_KEY:
        return {
            "error": "VirusTotal API key missing",
            "malicious": 0,
            "suspicious": 0,
            "status": "NO_API_KEY"
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    # 2️⃣ Encode URL as required by VirusTotal
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    try:
        response = requests.get(vt_url, headers=headers, timeout=10)
    except requests.RequestException as e:
        return {
            "error": f"VirusTotal request failed: {str(e)}",
            "malicious": 0,
            "suspicious": 0,
            "status": "REQUEST_FAILED"
        }

    # 3️⃣ URL not analyzed yet
    if response.status_code == 404:
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "NOT_ANALYZED"
        }

    # 4️⃣ Any other API error
    if response.status_code != 200:
        return {
            "error": f"VirusTotal API error {response.status_code}",
            "malicious": 0,
            "suspicious": 0,
            "status": "API_ERROR"
        }

    # 5️⃣ Successful response
    data = response.json()
    stats = (
        data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
    )

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "status": "ANALYZED"
    }
