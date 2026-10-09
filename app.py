"""Local, offline threat-intelligence triage using transparent demo rules."""
from __future__ import annotations
import ipaddress, re
from urllib.parse import urlparse

SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")

def classify_indicator(value: str) -> dict:
    raw = value.strip()
    if not raw:
        raise ValueError("Indicator cannot be empty")
    kind, normalized, score, reasons = "unknown", raw, 0, []
    try:
        normalized = str(ipaddress.ip_address(raw))
        kind = "ip"
        if ipaddress.ip_address(normalized).is_private:
            reasons.append("private address: validate context before escalation")
        else:
            score += 20
    except ValueError:
        if SHA256.fullmatch(raw):
            kind, normalized, score = "sha256", raw.lower(), 10
        elif raw.lower().startswith(("http://", "https://")):
            parsed = urlparse(raw)
            if not parsed.hostname:
                raise ValueError("URL must include a hostname")
            kind, normalized = "url", raw
            if parsed.scheme == "http":
                score += 15; reasons.append("unencrypted HTTP scheme")
            if "@" in parsed.netloc:
                score += 20; reasons.append("URL user-info may be deceptive")
        elif DOMAIN.fullmatch(raw):
            kind, normalized = "domain", raw.lower()
            if normalized.startswith("xn--"):
                score += 10; reasons.append("internationalized domain: inspect for lookalikes")
        else:
            raise ValueError("Unsupported indicator; use IP, domain, URL, or SHA-256")
    score = min(score, 100)
    severity = "high" if score >= 60 else "medium" if score >= 25 else "low"
    return {"indicator": normalized, "type": kind, "score": score, "severity": severity, "reasons": reasons}

if __name__ == "__main__":
    for item in ["203.0.113.10", "example.org", "https://example.org/login"]:
        print(classify_indicator(item))