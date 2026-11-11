import re
import os
import json
import math
import datetime
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import tldextract

#words that show up a lot in phishing urls trying to sound official
SUSPICIOUS_WORDS = ["secure", "account", "verify", "login", "signin", "update",
                     "confirm", "bank", "wallet", "password", "ebay", "paypal"]

#common targets for typosquatting, used to catch stuff like paypa1.com
BRAND_NAMES = ["paypal", "google", "facebook", "apple", "microsoft", "amazon",
               "netflix", "bankofamerica", "chase", "wellsfargo", "instagram",
               "whatsapp", "ebay", "linkedin", "dropbox"]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                   "buff.ly", "adf.ly", "shorte.st"}


def shannon_entropy(s: str) -> float:
    #measures how "random" a string looks. a word like facebook reuses letters
    #in a structured way and scores low, a generated domain like xk4j9qz scores high
    #formula is -sum(p(c) * log2(p(c))) over every unique character c
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def levenshtein(a: str, b: str) -> int:
    #classic edit distance, minimum inserts/deletes/substitutions to turn a into b
    #using the standard dp table approach, only keeping the previous row to save memory
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
            #three options at each cell: substitute, insert, delete. take the cheapest
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def min_brand_distance(domain: str) -> int:
    #closest a domain gets to a known brand name, small number means likely typosquat
    if not domain:
        return 99
    return min(levenshtein(domain, b) for b in BRAND_NAMES)


def extract_url_features(url: str) -> dict:
    #a browser always sends https://site.com/ with the slash, the tranco urls in the
    #dataset had none, so the model learned "has a / path = phishing". treat a lone
    #trailing slash as no path so both spellings give the same features
    if url.endswith("/") and urlparse(url if "://" in url else "http://" + url).path == "/" \
            and "?" not in url and "#" not in url:
        url = url[:-1]
    #urlparse needs a scheme to work right, so add one if it's missing
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
        #ip used instead of a real domain name is a big red flag, legit sites basically never do this
        "has_ip_host": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]) else 0,
        #old browser trick, everything before @ in a url gets ignored, used to hide the real host
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


#-- domain age (whois) ------------------------------------------------------
#whois is slow (a network round trip per domain) and flaky, so every answer is cached
#in a json file. the cache stores the creation DATE, not the age in days, because an
#age stored today would be wrong tomorrow, the age is worked out fresh on every read
WHOIS_CACHE_PATH = "data/whois_cache.json"
_whois_cache = None
_cache_lock = threading.Lock()


def registered_domain(url: str) -> str:
    #paypal.com for https://secure.login.paypal.com/x, this is what whois is asked about
    ext = tldextract.extract(url)
    return ".".join(p for p in [ext.domain, ext.suffix] if p)


def _load_whois_cache() -> dict:
    global _whois_cache
    if _whois_cache is None:
        try:
            with open(WHOIS_CACHE_PATH) as f:
                _whois_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _whois_cache = {}
    return _whois_cache


def _save_whois_cache():
    #write to a temp file then rename, so a crash mid-write can't leave a half written cache
    os.makedirs(os.path.dirname(WHOIS_CACHE_PATH), exist_ok=True)
    tmp = WHOIS_CACHE_PATH + ".tmp"
    with _cache_lock, open(tmp, "w") as f:
        json.dump(_whois_cache, f, indent=1, sort_keys=True)
    os.replace(tmp, WHOIS_CACHE_PATH)


def _query_creation_date(domain: str):
    #returns (status, iso_date or None). "ok", "no_date" (record exists but the registrar
    #hides the date) and "not_found" (domain isnt registered) are real answers and get
    #cached. "error" (timeout, rate limit, parse failure) is transient so it is NOT cached,
    #otherwise one bad moment would poison that domain forever
    try:
        import whois
        from whois.exceptions import WhoisDomainNotFoundError, UnknownTldError
    except Exception:
        return "error", None
    try:
        w = whois.whois(domain)
    except WhoisDomainNotFoundError:
        return "not_found", None
    except UnknownTldError:
        return "no_date", None
    except Exception:
        return "error", None
    created = w.get("creation_date")
    if not isinstance(created, list):
        created = [created]
    #some registrars return several dates, take the earliest. drop tzinfo so naive and
    #aware datetimes can be compared, day precision is all we need
    dates = [c.replace(tzinfo=None) for c in created if isinstance(c, datetime.datetime)]
    if not dates:
        return "no_date", None
    return "ok", min(dates).date().isoformat()


def _lookup_and_cache(domain: str) -> str:
    cache = _load_whois_cache()
    status, created = _query_creation_date(domain)
    if status != "error":
        with _cache_lock:
            cache[domain] = {"status": status, "created": created}
    return status


def extract_domain_age_days(url: str) -> int:
    #age of the registered domain in days, or -1 if unknown (not registered, hidden date,
    #lookup failed). -1 instead of raising so one bad domain cant crash the whole pipeline
    domain = registered_domain(url)
    if not domain:
        return -1
    cache = _load_whois_cache()
    if domain not in cache:
        if _lookup_and_cache(domain) == "error":
            return -1
        _save_whois_cache()
    created = cache.get(domain, {}).get("created")
    if created is None:
        return -1
    age = datetime.date.today() - datetime.date.fromisoformat(created)
    return max(age.days, 0)


def prefetch_domain_ages(urls, workers: int = 6) -> Counter:
    #looks up every not-yet-cached domain in parallel before the build loop runs.
    #lookups are mostly waiting on the network so threads help a lot (600 lookups at ~2s
    #each is 20 min one by one). kept to a few workers so the whois servers dont throttle us
    cache = _load_whois_cache()
    todo = sorted({d for d in map(registered_domain, urls) if d and d not in cache})
    print(f"whois: {len(todo)} domains to look up ({len(cache)} already cached)")
    results = Counter()
    if todo:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for n, status in enumerate(ex.map(_lookup_and_cache, todo), 1):
                results[status] += 1
                if n % 50 == 0:
                    print(f"  {n}/{len(todo)} done")
                    _save_whois_cache()
        _save_whois_cache()
    return results
