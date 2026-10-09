"""Offline indicator triage with validation and explainable scoring."""
from __future__ import annotations
import ipaddress, re
from urllib.parse import urlparse

_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\Z")
_SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")

def classify_indicator(value: str) -> dict:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Indicator must be a non-empty string")
    raw = value.strip()
    score, reasons = 0, []
    try:
        ip = ipaddress.ip_address(raw)
        return {"indicator": str(ip), "type": "ip", "score": 0, "severity": "informational", "reasons": []}
    except ValueError:
        pass
    if _SHA256.fullmatch(raw):
        return {"indicator": raw.lower(), "type": "sha256", "score": 0, "severity": "informational", "reasons": []}
    if raw.lower().startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL must have a hostname and must not embed credentials")
        if parsed.scheme == "http":
            score += 20
            reasons.append("URL uses unencrypted HTTP")
        host = parsed.hostname.lower()
        if host.startswith("xn--") or ".xn--" in host:
            score += 10
            reasons.append("Internationalized hostname may require lookalike review")
        kind, normalized = "url", raw
    elif _DOMAIN.fullmatch(raw):
        kind, normalized = "domain", raw.lower()
        if normalized.startswith("xn--") or ".xn--" in normalized:
            score += 10
            reasons.append("Internationalized domain may require lookalike review")
    else:
        raise ValueError("Unsupported indicator: provide an IP, domain, HTTP(S) URL, or SHA-256")
    severity = "high" if score >= 60 else "medium" if score >= 25 else "low" if score else "informational"
    return {"indicator": normalized, "type": kind, "score": score, "severity": severity, "reasons": reasons}

if __name__ == "__main__":
    for sample in ("203.0.113.10", "example.org", "http://example.org/login"):
        print(classify_indicator(sample))
