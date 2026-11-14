# Architecture

How the pieces fit together. Everything is in `phishing_detector/`.

## Data flow

```
 OpenPhish feed ─┐
 Tranco top sites ├─► build_dataset.py ─► data/dataset.csv ─► train.py ─► data/model.joblib       (13 URL features)
 curated logins ──┘        │                                          └─► data/model_deep.joblib  (17 features)
                           │
        features.py  ◄─────┤   URL features + WHOIS age (age no longer used by the models)
        content_features.py ◄ ┘  page features, via the Docker sandbox

 classify.py <url> [--deep] ─► features ─► model ─► verdict + SHAP "why"
```

## Files

| File | Job |
|---|---|
| `src/features.py` | 13 URL features (length, dots, hyphens, entropy, brand edit distance, ...). Also the WHOIS age lookup with a cache. |
| `src/content_features.py` | Runs a page fetch in the sandbox and turns the result into 4 content features. Host side: DNS, SSRF guard, caching. |
| `src/sandbox/` | `Dockerfile`, `entrypoint.sh` (firewall, drop privileges), `fetch.py` (Playwright), `test_isolation.py` (10 checks). |
| `src/brand_favicons.py` | Builds the brand favicon hash database used by `favicon_brand_match`. |
| `src/curated_legit_urls.py` | 51 real login-page URLs added to the legit class (added to fix a dataset bias, see `security-analysis.md`). |
| `src/build_dataset.py` | Loads the sources, computes every feature, writes `data/dataset.csv`. |
| `src/train.py` | Trains the fast and deep Random Forests, prints plain and grouped CV, test report, SHAP ranking. |
| `src/classify.py` | CLI. Fast model by default, deep model with `--deep`. Prints the verdict and the top SHAP reasons. |
| `src/ablation.py` | Measurement script: with/without a feature, plain vs grouped CV. |
| `src/evaluate.py` | Evaluation demo: metrics, ROC and confusion matrix, SHAP charts and per-URL reasons, saved to `reports/`. |
| `src/validate_holdout.py` | Tests the fast model on a fresh feed and on Tranco domains outside the training sample. |
| `backend/api.py` | Flask service (`/scan/fast`, `/scan/deep`) wrapping `classify()`, localhost only. |
| `extension/` | Chrome Manifest V3 extension that checks each navigation through the backend. See `extension-workflow.md`. |

## Two models

- **Fast** (default): 13 URL-string features, trained on all 600 rows. Needs no network, answers in milliseconds.
- **Deep** (`--deep`): the 13 plus 4 content features, trained only on the 208 rows whose page loaded.
  If the sandbox is down or the page does not load, `classify.py` says so and falls back to the fast model.

`fetch_ok` is never a feature. It is only used to pick the rows for the deep model.

## Trust boundaries

1. Everything from the feed or the user (the URL) is untrusted text.
2. The host resolves DNS itself and keeps only public IPv4 addresses (SSRF guard).
3. The page is opened only inside the container, behind its own firewall and without privileges.
4. The container's output is untrusted JSON; the host parses it and only reads known fields.

Details and the reasoning are in `security-analysis.md`.

