import io
import json
import requests
import imagehash
from bs4 import BeautifulSoup
from PIL import Image
from urllib.parse import urljoin

DB_PATH = "data/brand_favicons.json"

#how many of the 64 hash bits can differ and still count as "the same icon"
MATCH_DISTANCE = 8

#common phishing targets. name -> the domains that really belong to that brand, a favicon
#that looks like the brand but sits on any other domain is the suspicious case
BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gstatic.com", "youtube.com", "android.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "media-amazon.com", "amazon.ca", "amazon.co.jp", "amazon.co.uk",
               "amazon.de", "amazon.fr", "amazon.es", "amazon.it", "amazon.in",
               "amazon.com.au", "amazon.com.br", "amazon.com.mx"],
    "facebook": ["facebook.com", "fbcdn.net"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "ebay": ["ebay.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "dhl": ["dhl.com"],
    "whatsapp": ["whatsapp.com"],
    "adobe": ["adobe.com"],
    "yahoo": ["yahoo.com"],
    "roblox": ["roblox.com"],
    "discord": ["discord.com"],
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
}

HEADERS = {"User-Agent": "Mozilla/5.0 (phishing-detector class project)"}


def image_hash(raw: bytes):
    #perceptual hash of an image, None if it isnt an image we can read
    try:
        img = Image.open(io.BytesIO(raw))
        #icons are often transparent, put them on a white background first
        #otherwise the transparent part turns black and changes the hash
        img = img.convert("RGBA")
        bg = Image.new("RGBA", img.size, "white")
        bg.alpha_composite(img)
        return imagehash.phash(bg.convert("RGB"))
    except Exception:
        return None


def closest_brand(h, db):
    #(brand, hamming distance) of the brand whose icon is nearest to hash h
    best = None
    for name, entry in db.items():
        d = h - imagehash.hex_to_hash(entry["hash"])
        if best is None or d < best[1]:
            best = (name, d)
    return best


_db = None


def load_db():
    global _db
    if _db is None:
        try:
            with open(DB_PATH) as f:
                _db = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _db = {}
    return _db


def download_icon(domain):
    #these are the real brand sites, so a normal requests call from the host is fine here
    base = f"https://www.{domain}/"
    candidates = []
    try:
        page = requests.get(base, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(page.text, "html.parser")
        link = soup.find("link", rel=lambda v: v and "icon" in " ".join(v).lower())
        if link and link.get("href"):
            candidates.append(urljoin(page.url, link["href"]))
    except Exception:
        pass
    candidates.append(urljoin(base, "/favicon.ico"))
    for url in candidates:
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            if r.ok and image_hash(r.content) is not None:
                return r.content
        except Exception:
            continue
    return None


def main():
    #run this once to (re)build the reference hashes: python src/brand_favicons.py
    db = {}
    for name, domains in BRANDS.items():
        raw = download_icon(domains[0])
        h = image_hash(raw) if raw else None
        if h is None:
            print(f"  {name:15s} FAILED")
            continue
        db[name] = {"domains": domains, "hash": str(h)}
        print(f"  {name:15s} {h}")
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=1, sort_keys=True)
    print(f"saved {len(db)}/{len(BRANDS)} brands to {DB_PATH}")

    #how far apart different brands are from each other, the match distance has to be
    #well below this or two different brands would count as the same icon
    names = sorted(db)
    dists = [(imagehash.hex_to_hash(db[a]["hash"]) - imagehash.hex_to_hash(db[b]["hash"]), a, b)
             for i, a in enumerate(names) for b in names[i + 1:]]
    dists.sort()
    print("closest brand pairs:", [(int(d), a, b) for d, a, b in dists[:5]])


if __name__ == "__main__":
    main()
