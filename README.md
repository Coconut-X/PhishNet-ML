# ML-Based Phishing Page Detector

Classifies a URL as phishing or legitimate with a Random Forest, and explains the verdict with SHAP.
Course project for CS3002 Information Security (Fall 2026).

## Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Page-content features need Docker (the page is opened in an isolated, firewalled container):

```bash
docker build -t phish-sandbox src/sandbox
```

## Run the pipeline end to end

```bash
# data (not stored in git)
curl -sL "https://openphish.com/feed.txt" -o data/openphish.txt
curl -sL "https://tranco-list.eu/top-1m.csv.zip" -o data/tranco.csv.zip && unzip data/tranco.csv.zip -d data/

python src/brand_favicons.py     # favicon hash database (needs internet)
python src/build_dataset.py      # features for every URL, takes a while (WHOIS + sandbox fetches)
python src/train.py              # trains data/model.joblib (fast) and data/model_deep.joblib
python src/validate_holdout.py   # optional: test on a fresh feed (download it as data/openphish_fresh.txt)
```

## Classify a URL

```bash
python src/classify.py https://example.com            # fast model, URL features only, no network
python src/classify.py https://example.com --deep     # also loads the page in the sandbox
```

Output: verdict, confidence, and the features that pushed the decision (SHAP).

## Optional: backend and Chrome extension

```bash
pip install -r backend/requirements.txt
python backend/api.py            # http://127.0.0.1:5000, endpoints /scan/fast and /scan/deep
```
Load `extension/` as an unpacked extension in `chrome://extensions` (developer mode).

## Layout

`src/` pipeline code, `src/sandbox/` the Docker sandbox and its isolation tests, `backend/` Flask API,
`extension/` Chrome extension, `data/` generated data and models.

## Safety note

Never open phishing URLs from the feed in a normal browser. This project only fetches pages inside the sandbox.
