import os
import sys
from urllib.parse import urlparse
from flask import Flask, jsonify, request

#classify.py lives in src/ and uses paths like data/model.joblib, so run from the project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.chdir(ROOT)

from classify import classify

#big well known sites are not run through the model. a url model that flags google searches is
#useless in a browser. shared hosting platforms are left out of the list, anyone can put a
#phishing page on those, so they always go through the model
TOP_N = 2000
SHARED_HOSTS = {"blogspot.com", "github.io", "pages.dev", "vercel.app", "workers.dev", "netlify.app",
                "herokuapp.com", "duckdns.org", "weebly.com", "wixsite.com", "web.app", "firebaseapp.com",
                "glitch.me", "000webhostapp.com", "sites.google.com", "googleusercontent.com",
                "amazonaws.com", "azurewebsites.net", "wordpress.com", "r2.dev", "repl.co", "onrender.com"}


def load_allowlist():
    from features import registered_domain
    allow = set()
    try:
        with open("data/top-1m.csv") as f:
            for line in f:
                rank, domain = line.strip().split(",")
                if int(rank) > TOP_N:
                    break
                rd = registered_domain("https://" + domain)
                if rd not in SHARED_HOSTS and domain not in SHARED_HOSTS:
                    allow.add(rd)
    except OSError:
        pass
    return allow


ALLOWLIST = load_allowlist()


def allowlisted(url):
    from features import registered_domain
    return registered_domain(url) in ALLOWLIST


app = Flask(__name__)
MAX_URL_LEN = 2048


def get_url():
    #accepts {"url": "..."} as json, returns (url, None) or (None, error response)
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return None, (jsonify(error="send json like {\"url\": \"https://...\"}"), 400)
    url = url.strip()
    if len(url) > MAX_URL_LEN:
        return None, (jsonify(error="url too long"), 400)
    #only web urls, we never want to feed file:// or chrome:// things into the pipeline
    if urlparse(url).scheme not in ("http", "https"):
        return None, (jsonify(error="only http and https urls"), 400)
    return url, None


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/scan/fast")
def scan_fast():
    #url features only, never opens the page
    url, err = get_url()
    if err:
        return err
    if allowlisted(url):
        return jsonify(url=url, model="allowlist", verdict="LEGITIMATE", confidence=1.0,
                       phishing_probability=0.0, baseline=0.0, explanation=[], other_features=0.0,
                       note="top 2000 site, not run through the model")
    return jsonify(classify(url, deep=False))


@app.post("/scan/deep")
def scan_deep():
    #also loads the page in the docker sandbox, takes several seconds
    #falls back to the fast model if the sandbox or the page is unavailable
    url, err = get_url()
    if err:
        return err
    return jsonify(classify(url, deep=True))


if __name__ == "__main__":
    #127.0.0.1 only, this is not meant to be reachable from other machines
    app.run(host="127.0.0.1", port=5000)
