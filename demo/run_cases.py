import json
import urllib.request

API = "http://127.0.0.1:5000/scan/fast"

for line in open("demo/cases.txt"):
    url = line.strip()
    if not url or url.startswith("#"):
        continue
    req = urllib.request.Request(API, json.dumps({"url": url}).encode(), {"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req))
    top = ", ".join(f"{e['feature']} {e['shap']:+.2f}" for e in r["explanation"][:3])
    print(f"{r['verdict']:10s} {r['phishing_probability']:.2f}  {url}\n           why: {top}")
