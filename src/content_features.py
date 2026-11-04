import requests
import tldextract

HEADERS = {"User-Agent": "Mozilla/5.0 (phishing-detector-mvp research tool)"}
TIMEOUT = 6


def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return ".".join(p for p in [ext.domain, ext.suffix] if p)


def fetch_content_features(url: str) -> dict:
    #heads up, this uses a plain requests.get, not a sandboxed headless browser
    #so it's fine for quick manual checks but not safe to run on a big batch of
    #real phishing urls yet, that sandboxing is planned for a later iteration
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
        #dead link, timeout, blocked request, whatever, just return neutral defaults
        #instead of crashing the whole pipeline over one bad url
        return defaults

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return defaults

    #the actual strongest phishing signal, does the form send data somewhere
    #other than the domain it's pretending to be
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

    #how much of the page's css/js/images come from somewhere else
    #phishing clones often borrow the real site's assets while hosting the shell elsewhere
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

    #just checks a favicon tag exists, doesn't compare it against a real brand's
    #favicon yet, that hash comparison is planned for a later iteration
    favicon = 1 if soup.find("link", rel=lambda v: v and "icon" in v.lower()) else 0

    return {
        "form_action_mismatch": mismatch,
        "favicon_present": favicon,
        "external_resource_ratio": round(ratio, 3),
        "has_password_field": has_pw,
        "fetch_ok": 1,
    }
