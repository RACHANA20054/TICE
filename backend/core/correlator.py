# =========================
# IP CORRELATION LOGIC (WITH EXPLAINABLE AI)
# =========================
def correlate(abuse_data, shodan_data, vt_data, tor_data=None):
    score = 0
    reasons = []
    feature_importance = {}

    # -------------------------
    # 1️⃣ AbuseIPDB
    # -------------------------
    abuse_score = abuse_data.get("abuse_score", 0)

    if abuse_score >= 50:
        contribution = 50
        score += contribution
        reasons.append(f"High AbuseIPDB score ({abuse_score})")
        feature_importance["abuseipdb"] = contribution

    elif abuse_score >= 20:
        contribution = 20
        score += contribution
        reasons.append(f"Moderate AbuseIPDB score ({abuse_score})")
        feature_importance["abuseipdb"] = contribution


    # -------------------------
    # 2️⃣ Tor Detection
    # -------------------------
    if tor_data and tor_data.get("is_tor"):
        contribution = 40
        score += contribution
        reasons.append("IP is a Tor exit node")
        feature_importance["tor_network"] = contribution


    # -------------------------
    # 3️⃣ VPN / Hosting Detection
    # -------------------------
    if shodan_data.get("is_vpn"):
        contribution = 25
        score += contribution
        reasons.append("IP belongs to VPN / hosting provider")
        feature_importance["vpn_hosting"] = contribution


    # -------------------------
    # 4️⃣ Shodan Exposure
    # -------------------------
    open_ports = shodan_data.get("open_ports", [])
    if open_ports:
        contribution = 15
        score += contribution
        reasons.append(f"Open ports exposed: {open_ports}")
        feature_importance["open_ports"] = contribution

    vulns = shodan_data.get("vulns", [])
    if vulns:
        contribution = 25
        score += contribution
        reasons.append("Known vulnerabilities detected")
        feature_importance["vulnerabilities"] = contribution


    # -------------------------
    # 5️⃣ VirusTotal
    # -------------------------
    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)

    if malicious > 0:
        contribution = 40
        score += contribution
        reasons.append(f"VirusTotal malicious detections ({malicious})")
        feature_importance["virustotal_malicious"] = contribution

    elif suspicious > 0:
        contribution = 20
        score += contribution
        reasons.append(f"VirusTotal suspicious detections ({suspicious})")
        feature_importance["virustotal_suspicious"] = contribution


    # -------------------------
    # 6️⃣ Final Verdict
    # -------------------------
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    if not reasons:
        reasons.append("No significant threat indicators found")

    dominant_factor = (
        max(feature_importance, key=feature_importance.get)
        if feature_importance else "none"
    )

    return {
        "risk_score": min(score, 100),
        "verdict": verdict,
        "reasons": reasons,
        "explainability": {
            "feature_importance": feature_importance,
            "dominant_factor": dominant_factor
        }
    }


# =========================
# URL CORRELATION LOGIC (WITH EXPLAINABLE AI)
# =========================
def correlate_url(vt_data):
    score = 0
    reasons = []
    feature_importance = {}

    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)

    if malicious > 0:
        contribution = 70
        score += contribution
        reasons.append(
            f"VirusTotal reports malicious URL detections ({malicious})"
        )
        feature_importance["virustotal_malicious"] = contribution

    elif suspicious > 0:
        contribution = 30
        score += contribution
        reasons.append(
            f"VirusTotal reports suspicious URL behavior ({suspicious})"
        )
        feature_importance["virustotal_suspicious"] = contribution

    if vt_data.get("status") == "NOT_ANALYZED":
        reasons.append("URL not yet analyzed by VirusTotal")

    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    if not reasons:
        reasons.append("No malicious indicators detected")

    dominant_factor = (
        max(feature_importance, key=feature_importance.get)
        if feature_importance else "none"
    )

    return {
        "risk_score": min(score, 100),
        "verdict": verdict,
        "reasons": reasons,
        "explainability": {
            "feature_importance": feature_importance,
            "dominant_factor": dominant_factor
        }
    }
