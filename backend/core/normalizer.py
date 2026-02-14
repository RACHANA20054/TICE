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

def normalize_shodan(data):
    if not isinstance(data, dict):
        return {}

    org = data.get("org", "")
    isp = data.get("isp", "")

    hosting_keywords = [
        "amazon", "aws", "google", "azure",
        "digitalocean", "ovh", "hetzner", "linode"
    ]

    is_vpn = any(k in (org + isp).lower() for k in hosting_keywords)

    return {
        "open_ports": data.get("ports", []),
        "vulns": list(data.get("vulns", [])),
        "is_vpn": is_vpn,
        "org": org
    }

