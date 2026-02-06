import os
import requests

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_virustotal(ip: str):
    if not VT_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code != 200:
        return {
            "error": "VirusTotal API failed",
            "status": response.status_code
        }

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]

    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }
