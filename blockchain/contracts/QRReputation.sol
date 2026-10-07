import re
from urllib.parse import urlparse, urlunparse

COMMON_BRANDS = {
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "netflix",
    "dropbox",
    "github",
    "bankofamerica",
    "chase",
    "wellsfargo",
}

SUSPICIOUS_TLDS = {"xyz", "top", "club", "loan", "bid", "click", "tk", "ga", "ml"}
COMMON_PHISHING_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "password",
    "update",
    "confirm",
    "bank",
    "payment",
    "security",
    "urgent",
    "alert",
    "invoice",
    "session",
}


def normalize_url(raw_url: str) -> str:
    if not raw_url:
        raise ValueError("URL is empty")

    url = raw_url.strip()
    if not url:
        raise ValueError("URL is empty after trimming")

    if not re.match(r"^[a-zA-Z]+://", url):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https are supported")

    hostname = parsed.hostname.lower() if parsed.hostname else ""
    if not hostname:
        raise ValueError("Hostname could not be parsed")

    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            "",
            parsed.query,
            parsed.fragment,
        )
    )
    return normalized


def likely_typo_squatted(domain: str) -> bool:
    if not domain:
        return False

    domain = domain.lower().split(":")[0]
    base = domain.split(".")[0]
    if not base:
        return False

    for brand in COMMON_BRANDS:
        if brand in base and base != brand:
            return True

    if domain.endswith(".co") and not domain.startswith("co."):
        return True

    return False


def similarity_to_brand(domain: str) -> bool:
    hostname = domain.lower().replace("www.", "")
    for brand in COMMON_BRANDS:
        if hostname.startswith(brand) or hostname.endswith(brand):
            return True
    return False


def classify_url(url: str, threat_feeds: list[dict] | None = None) -> dict:
    threat_feeds = threat_feeds or []

    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    path = parsed.path.lower()
    risk_score = 0
    reasons = []

    if not hostname:
        return {
            "url": url,
            "normalized_url": normalized_url,
            "risk_level": "malicious",
            "risk_score": 100,
            "reasons": ["URL has no valid hostname"],
            "suspicious": True,
        }

    if parsed.scheme.lower() not in {"http", "https"}:
        reasons.append("unsupported scheme")
        risk_score += 25

    if hostname.endswith(tuple(f".{tld}" for tld in SUSPICIOUS_TLDS)):
        reasons.append("domain uses a high-risk or spam-heavy TLD")
        risk_score += 25

    if likely_typo_squatted(hostname):
        reasons.append("domain resembles a known brand but is slightly altered")
        risk_score += 35

    if similarity_to_brand(hostname):
        reasons.append("hostname overlaps with a major brand name")
        risk_score += 15

    if any(keyword in path for keyword in COMMON_PHISHING_KEYWORDS):
        reasons.append("URL path contains phishing-related keywords")
        risk_score += 20

    if "@" in parsed.netloc:
        reasons.append("URL contains userinfo ambiguity")
        risk_score += 10

    if "//" in path or path.count("/") > 5:
        reasons.append("URL path is unusually complex or obfuscated")
        risk_score += 10

    for feed in threat_feeds:
        if feed.get("match"):
            reasons.append(f"matched known threat feed: {feed.get('source', 'unknown')}")
            risk_score += int(feed.get("weight", 30))

    if risk_score >= 70:
        risk_level = "malicious"
    elif risk_score >= 35:
        risk_level = "suspicious"
    else:
        risk_level = "low"

    if not reasons:
        reasons = ["domain not in known threat feeds"]

    return {
        "url": url,
        "normalized_url": normalized_url,
        "risk_level": risk_level,
        "risk_score": min(risk_score, 100),
        "reasons": reasons,
        "suspicious": risk_level in {"suspicious", "malicious"},
    }
