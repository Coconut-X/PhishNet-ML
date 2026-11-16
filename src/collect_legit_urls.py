import csv
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import requests
from features import registered_domain

DATA_DIR = "data"
UA = "Mozilla/5.0 (X11; Linux x86_64) research-crawler for a class project"
LINKS_PER_SITE = 3


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)


def crawl_site(domain):
    #the homepage url exactly as a browser ends up on it (www, trailing slash, redirects)
    #plus a few real links from that page that stay on the same site and have a path
    try:
        r = requests.get(f"https://{domain}/", headers={"User-Agent": UA}, timeout=8)
    except requests.RequestException:
        return []
    if r.status_code != 200 or "html" not in r.headers.get("content-type", ""):
        return []
    home = r.url
    #only keep it if we stayed on the same registered domain, redirects can go anywhere
    if registered_domain(home) != registered_domain(f"https://{domain}"):
        return []
    parser = LinkParser()
    try:
        parser.feed(r.text[:400000])
    except Exception:
        pass
    seen, links = set(), []
    for href in parser.links:
        u = urljoin(home, href).split("#")[0]
        p = urlparse(u)
        if p.scheme not in ("http", "https") or registered_domain(u) != registered_domain(home):
            continue
        if p.path in ("", "/") and not p.query:
            continue
        if u not in seen and len(u) < 300:
            seen.add(u)
            links.append(u)
    random.Random(domain).shuffle(links)
    return [home] + links[:LINKS_PER_SITE]


def domains_in_rank(lo, hi):
    out = []
    with open(f"{DATA_DIR}/top-1m.csv") as f:
        for rank, d in csv.reader(f):
            if lo <= int(rank) <= hi:
                out.append(d)
            if int(rank) > hi:
                break
    return out


def collect(name, lo, hi, n_domains, exclude=()):
    #train urls come from ranks 1-1999 and validation from 2000-20000 so they never share a site
    pool = [d for d in domains_in_rank(lo, hi) if registered_domain(d) not in exclude]
    random.Random(11).shuffle(pool)
    pool = pool[:n_domains]
    with ThreadPoolExecutor(16) as ex:
        results = list(ex.map(crawl_site, pool))
    urls = [u for r in results for u in r]
    ok = sum(1 for r in results if r)
    with open(f"{DATA_DIR}/legit_crawled_{name}.txt", "w") as f:
        f.write("\n".join(urls) + "\n")
    print(f"{name}: {ok} of {len(pool)} sites answered, {len(urls)} urls")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    if which in ("train", "both"):
        collect("train", 1, 1999, 450)
    if which in ("val", "both"):
        collect("val", 2000, 20000, 450)
