import base64
import ipaddress
import json
import os
import socket
import subprocess
import threading
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from features import registered_domain
import brand_favicons

IMAGE = "phish-sandbox"
SANDBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
CACHE_PATH = "data/content_cache.json"

#every restriction the container runs with. kept in one place so the isolation tests use
#exactly the same flags as the real fetch
SANDBOX_FLAGS = [
    #root only for the few seconds the entrypoint needs to set the firewall
    "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
    "--security-opt", "no-new-privileges",
    "--read-only", "--tmpfs", "/tmp:rw,size=256m", "-e", "HOME=/tmp",
    "--memory", "1g", "--pids-limit", "300", "--cpus", "1", "--shm-size", "512m",
    "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
]

#what a url gets when the page couldnt be loaded. fetch_ok = 0 tells the two cases apart
#and train.py leaves those rows out, otherwise "dead page" would just become a shortcut
#for "phishing" (most dead pages are takedowns)
NO_CONTENT = {
    "form_action_mismatch": 0,
    "favicon_brand_match": 0,
    "external_resource_ratio": 0.0,
    "has_password_field": 0,
    "fetch_ok": 0,
}

_cache = None
_lock = threading.Lock()


def build_image():
    subprocess.run(["docker", "build", "-t", IMAGE, SANDBOX_DIR], check=True)


def resolve(host, allow_private=False):
    #look the host up here on the host machine, the container gets no dns at all.
    #only public ipv4 addresses are allowed: a phishing url pointing at 192.168.x.x or
    #127.0.0.1 would otherwise let the sandbox poke around our own network
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
    except socket.gaierror:
        return []
    ips = sorted({i[4][0] for i in infos})
    if not allow_private:
        ips = [ip for ip in ips if ipaddress.ip_address(ip).is_global]
    return ips


def run_sandbox(url, allow_private=False):
    #loads the url in the container and returns what the page script printed.
    #always returns a dict. "infra": True means docker itself failed (not the page), so
    #the result must not be cached
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"ok": False, "error": "bad url"}
    #the host itself plus its www/non-www twin, because apex -> www is by far the most
    #common redirect and blocking it would make a lot of normal sites fail. any other
    #redirect stays blocked
    host = parsed.hostname
    twin = host[4:] if host.startswith("www.") else "www." + host
    hostmap = {}
    for h in (host, twin):
        found = resolve(h, allow_private)
        if found:
            hostmap[h] = found
    if host not in hostmap:
        return {"ok": False, "error": "no public ip"}
    ips = sorted({ip for found in hostmap.values() for ip in found})
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    name = "sandbox-" + uuid.uuid4().hex[:12]
    cmd = ["docker", "run", "--rm", "--name", name] + SANDBOX_FLAGS + [
        "-e", f"TARGET_URL={url}", "-e", f"TARGET_IPS={','.join(ips)}",
        "-e", "TARGET_HOSTMAP=" + ",".join(f"{h}={f[0]}" for h, f in hostmap.items()),
        "-e", f"TARGET_PORT={port}", IMAGE,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True)
        return {"ok": False, "error": "timeout"}
    except FileNotFoundError:
        return {"ok": False, "error": "docker not found", "infra": True}

    #the container output is untrusted, it came from a page we dont control
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"ok": False, "error": "docker failed: " + proc.stderr[-200:], "infra": True}


def favicon_match(page_domain, data):
    #1 if the favicon is a known brand's but the page is not that brand
    db = brand_favicons.load_db()

    #icon loaded straight from a brand's own domain
    icon_domain = registered_domain(str(data.get("favicon_url", "")))
    for entry in db.values():
        if icon_domain in entry["domains"] and page_domain not in entry["domains"]:
            return 1

    #icon copied onto the phishing host, compare the picture itself
    try:
        raw = base64.b64decode(data.get("favicon_b64") or "")
    except Exception:
        raw = b""
    h = brand_favicons.image_hash(raw) if raw else None
    if h is not None and db:
        brand, dist = brand_favicons.closest_brand(h, db)
        if dist <= brand_favicons.MATCH_DISTANCE and page_domain not in db[brand]["domains"]:
            return 1
    return 0


def features_from_page(url, data):
    page_domain = registered_domain(str(data.get("final_url") or url))

    #the strongest signal: a form that sends data to a different site than the page
    forms = [f for f in data.get("forms", []) if isinstance(f, str) and f.startswith("http")]
    mismatch = any(registered_domain(f) not in ("", page_domain) for f in forms)

    #share of the page's scripts/images/stylesheets that come from another site
    res = [r for r in data.get("resources", []) if isinstance(r, str) and r.startswith("http")]
    external = sum(1 for r in res if registered_domain(r) not in ("", page_domain))

    return {
        "form_action_mismatch": int(mismatch),
        "favicon_brand_match": favicon_match(page_domain, data),
        "external_resource_ratio": round(external / len(res), 3) if res else 0.0,
        "has_password_field": int(bool(data.get("has_password"))),
        "fetch_ok": 1,
    }


def _load_cache():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_PATH) as f:
                _cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _cache = {}
    return _cache


def _save_cache():
    tmp = CACHE_PATH + ".tmp"
    with _lock, open(tmp, "w") as f:
        json.dump(_cache, f, indent=1, sort_keys=True)
    os.replace(tmp, CACHE_PATH)


def _fetch(url, allow_private=False):
    data = run_sandbox(url, allow_private)
    feats = features_from_page(url, data) if data.get("ok") else dict(NO_CONTENT)
    return feats, data


def _fetch_and_cache(url, allow_private=False):
    cache = _load_cache()
    feats, data = _fetch(url, allow_private)
    #docker failing says nothing about the page, so dont remember that
    if not data.get("infra"):
        with _lock:
            cache[url] = {"features": feats, "error": data.get("error", "")}
    return feats


def fetch_content_features(url, allow_private=False, use_cache=True):
    #use_cache=False is for classify.py, so checking a random url doesnt end up in the
    #dataset cache
    if not use_cache:
        return _fetch(url, allow_private)[0]
    cache = _load_cache()
    if url not in cache:
        feats = _fetch_and_cache(url, allow_private)
        _save_cache()
        return feats
    return cache[url]["features"]


def prefetch_content(urls, workers=4):
    #same idea as the whois prefetch, run the slow part in parallel and cache it. each
    #lookup is its own container so they dont share anything
    cache = _load_cache()
    todo = [u for u in dict.fromkeys(urls) if u not in cache]
    print(f"sandbox: {len(todo)} urls to fetch ({len(cache)} already cached)")
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for _ in ex.map(_fetch_and_cache, todo):
            done += 1
            if done % 25 == 0:
                print(f"  {done}/{len(todo)} done")
                _save_cache()
    if todo:
        _save_cache()
    return Counter(cache[u]["features"]["fetch_ok"] for u in urls if u in cache)


if __name__ == "__main__":
    import sys
    print(fetch_content_features(sys.argv[1]))
