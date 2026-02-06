def normalize_abuseipdb(data):
    return {
        "abuse_score": data.get("abuse_score", 0),
        "is_public": data.get("is_public", False)
    }


def normalize_shodan(data):
    return {
        "open_ports_count": len(data.get("open_ports", [])),
        "has_vulns": len(data.get("vulns", [])) > 0
    }


def normalize_virustotal(data):
    stats = data.get("stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0)
    }
