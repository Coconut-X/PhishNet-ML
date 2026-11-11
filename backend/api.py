import os
import sys
from urllib.parse import urlparse
from flask import Flask, jsonify, request

#classify.py lives in src/ and uses paths like data/model.joblib, so run from the project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.chdir(ROOT)

from classify import classify

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
