import re
import math
import socket
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_WORDS = ["secure", "account", "verify", "login", "signin", "update",
                     "confirm", "bank", "wallet", "password", "ebay", "paypal"]

BRAND_NAMES = ["paypal", "google", "facebook", "apple", "microsoft", "amazon",
               "netflix", "bankofamerica", "chase", "wellsfargo", "instagram",
               "whatsapp", "ebay", "linkedin", "dropbox"]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                   "buff.ly", "adf.ly", "shorte.st"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def min_brand_distance(domain: str) -> int:
    if not domain:
        return 99
    return min(levenshtein(domain, b) for b in BRAND_NAMES)


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    domain = ext.domain or ""
    full_domain = ".".join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p)
    host = parsed.netloc or full_domain

    path_and_query = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_subdomains": max(len(ext.subdomain.split(".")), 1) if ext.subdomain else 0,
        "has_ip_host": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "is_shortener": 1 if full_domain in URL_SHORTENERS else 0,
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
        "brand_edit_distance": min_brand_distance(domain.lower()),
        "suspicious_tld": 1 if ext.suffix in {"xyz", "top", "tk", "club", "info", "online", "site"} else 0,
        "domain_entropy": shannon_entropy(domain),
        "path_length": len(path_and_query),
        "uses_https": 1 if parsed.scheme == "https" else 0,
    }
    return features


def extract_domain_age_days(url: str) -> int:
    """Best-effort WHOIS lookup. Returns -1 if lookup fails (treated as unknown)."""
    try:
        import whois
        ext = tldextract.extract(url)
        full_domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
        w = whois.whois(full_domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return -1
        import datetime
        delta = datetime.datetime.now() - created.replace(tzinfo=None)
        return max(delta.days, 0)
    except Exception:
        return -1
