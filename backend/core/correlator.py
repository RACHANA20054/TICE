def correlate(abuse, shodan, vt):
    risk_score = 0
    reasons = []

    # -------- AbuseIPDB --------
    if abuse.get("abuse_score", 0) > 50:
        risk_score += 3
        reasons.append("High abuse score reported by AbuseIPDB")
    else:
        reasons.append("No significant abuse reports in AbuseIPDB")

    # -------- Shodan --------
    open_ports = shodan.get("open_ports", [])
    dangerous_ports = {22, 23, 3389, 445}

    if any(port in dangerous_ports for port in open_ports):
        risk_score += 2
        reasons.append("Potentially dangerous open ports detected by Shodan")
    else:
        reasons.append("Only common service ports detected by Shodan")

    # -------- VirusTotal --------
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)

    if malicious > 0 or suspicious > 0:
        risk_score += 3
        reasons.append("VirusTotal reports malicious or suspicious activity")
    else:
        reasons.append("VirusTotal engines classify IP as harmless")

    # -------- Verdict --------
    if risk_score >= 5:
        verdict = "HIGH RISK"
    elif risk_score >= 3:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons
    }
