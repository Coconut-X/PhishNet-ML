import hashlib
import requests
import tldextract
from urllib.parse import urlparse, urljoin

HEADERS = {"User-Agent": "Mozilla/5.0 (phishing-detector-mvp research tool)"}
TIMEOUT = 6


def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return ".".join(p for p in [ext.domain, ext.suffix] if p)


def fetch_content_features(url: str) -> dict:
    """Best-effort content fetch. Returns neutral defaults on any failure
    (dead link, timeout, blocked) so the pipeline never crashes on bad input.
    This performs a direct HTTP GET; it is NOT the isolated sandbox described
    in the proposal and should only be pointed at URLs you intend to inspect."""
    defaults = {
        "form_action_mismatch": 0,
        "favicon_present": 0,
        "external_resource_ratio": 0.0,
        "has_password_field": 0,
        "fetch_ok": 0,
    }
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        html = resp.text
        page_domain = _registered_domain(resp.url)
    except Exception:
        return defaults

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return defaults

    forms = soup.find_all("form")
    mismatch = 0
    has_pw = 0
    for form in forms:
        action = form.get("action") or ""
        if action.startswith("http"):
            action_domain = _registered_domain(action)
            if action_domain and action_domain != page_domain:
                mismatch = 1
        if form.find("input", {"type": "password"}):
            has_pw = 1

    tags = soup.find_all(["script", "img", "link"])
    total = len(tags)
    external = 0
    for tag in tags:
        src = tag.get("src") or tag.get("href") or ""
        if src.startswith("http"):
            src_domain = _registered_domain(src)
            if src_domain and src_domain != page_domain:
                external += 1
    ratio = (external / total) if total else 0.0

    favicon = 1 if soup.find("link", rel=lambda v: v and "icon" in v.lower()) else 0

    return {
        "form_action_mismatch": mismatch,
        "favicon_present": favicon,
        "external_resource_ratio": round(ratio, 3),
        "has_password_field": has_pw,
        "fetch_ok": 1,
    }
