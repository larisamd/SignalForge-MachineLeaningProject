"""
url_features.py
----------------
Shared lexical/structural feature-extraction logic for the phishing /
malicious-URL detection module (Module B).

Using the SAME function at training time and at inference time guarantees
the feature vector the model was trained on matches exactly what the live
app builds when a user submits a URL.
"""

import re
import math
from urllib.parse import urlparse

# A small list of TLDs that are disproportionately abused for phishing /
# malware distribution in the wild (commonly cited in phishing-detection
# literature). Not exhaustive — just a useful signal, not a hard rule.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan",
    "men", "gdn", "kim", "cricket", "science", "party", "review", "download",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "bl.ink", "rebrand.ly",
}

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update", "secure", "bank", "confirm",
    "signin", "security", "webscr", "password", "ebayisapi", "paypal",
    "suspend", "urgent", "click", "invoice", "billing", "wallet",
]

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_underscore", "num_slash",
    "num_question", "num_equal", "num_at", "num_and", "num_digits",
    "num_percent", "digit_ratio", "has_ip", "num_subdomains",
    "suspicious_tld", "suspicious_word_count", "has_shortener",
    "path_length", "num_www", "has_https_token_in_path", "hostname_length",
    "url_entropy",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_url_features(raw_url: str) -> dict:
    """Extract a fixed-order dict of lexical/structural features from a URL string.

    Handles URLs that are missing a scheme (e.g. 'example.com/path') by
    assuming http:// for parsing purposes, since the training dataset
    contains many scheme-less entries.
    """
    url = (raw_url or "").strip()
    if not url:
        url = "http://"

    parse_target = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(parse_target)
    except ValueError:
        parsed = urlparse("http://")

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    domain_parts = hostname.split(".") if hostname else []
    num_subdomains = max(len(domain_parts) - 2, 0)

    tld = domain_parts[-1].lower() if len(domain_parts) >= 2 else ""
    registrable_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname

    digits = sum(c.isdigit() for c in url)

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscore": url.count("_"),
        "num_slash": url.count("/"),
        "num_question": url.count("?"),
        "num_equal": url.count("="),
        "num_at": url.count("@"),
        "num_and": url.count("&"),
        "num_digits": digits,
        "num_percent": url.count("%"),
        "digit_ratio": digits / len(url) if len(url) > 0 else 0.0,
        "has_ip": 1 if IP_PATTERN.match(hostname) else 0,
        "num_subdomains": num_subdomains,
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
        "has_shortener": 1 if registrable_domain.lower() in URL_SHORTENERS else 0,
        "path_length": len(path),
        "num_www": url.lower().count("www"),
        "has_https_token_in_path": 1 if "https" in (path + (parsed.query or "")).lower() else 0,
        "hostname_length": len(hostname),
        "url_entropy": _shannon_entropy(url),
    }
    return features


def features_to_vector(raw_url: str):
    """Return the feature values in the fixed FEATURE_NAMES order (list of floats)."""
    feats = extract_url_features(raw_url)
    return [feats[name] for name in FEATURE_NAMES]
