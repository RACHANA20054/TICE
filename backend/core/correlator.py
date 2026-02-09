# =========================
# IP CORRELATION LOGIC
# =========================
def correlate(abuse_data, shodan_data, vt_data):
    score = 0
    reasons = []

    # 1. AbuseIPDB
    abuse_score = abuse_data.get("abuse_score", 0)
    if abuse_score >= 50:
        score += 50
        reasons.append(f"High AbuseIPDB score ({abuse_score})")
    elif abuse_score >= 20:
        score += 20
        reasons.append(f"Moderate AbuseIPDB score ({abuse_score})")

    # 2. Shodan
    open_ports = shodan_data.get("open_ports", [])
    if open_ports:
        score += 15
        reasons.append(f"Open ports exposed: {open_ports}")

    vulns = shodan_data.get("vulns", [])
    if vulns:
        score += 25
        reasons.append("Known vulnerabilities detected")

    # 3. VirusTotal (IP)
    if vt_data.get("malicious", 0) > 0:
        score += 40
        reasons.append("VirusTotal reports malicious detections")

    if vt_data.get("suspicious", 0) > 0:
        score += 20
        reasons.append("VirusTotal reports suspicious detections")

    # Final verdict
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "risk_score": min(score, 100),
        "verdict": verdict,
        "reasons": reasons
    }


# =========================
# URL CORRELATION LOGIC
# =========================
def correlate_url(vt_data):
    score = 0
    reasons = []

    if vt_data.get("malicious", 0) > 0:
        score += 70
        reasons.append("VirusTotal reports malicious URL detections")

    if vt_data.get("suspicious", 0) > 0:
        score += 30
        reasons.append("VirusTotal reports suspicious URL behavior")

    if vt_data.get("status") == "NOT_ANALYZED":
        reasons.append("URL not yet analyzed by VirusTotal")

    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "risk_score": min(score, 100),
        "verdict": verdict,
        "reasons": reasons
    }
