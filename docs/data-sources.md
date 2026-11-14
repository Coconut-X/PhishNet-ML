# Data Sources

Quick reference for where every URL in `data/dataset.csv` actually comes from. Nothing in this
dataset is synthetic, every URL is real, just collected a few different ways depending on which
class it belongs to.

## Phishing URLs (300)

Source: **OpenPhish** free feed, a public list of currently active phishing URLs reported by the
security community. It's a plain text file, one URL per line, no signup needed.

```bash
curl -sL "https://openphish.com/feed.txt" -o data/openphish.txt
```

File: `data/openphish.txt`

## Legitimate URLs (300 total, two sources mixed together)

### 1. Tranco top sites list (~249 of them)

Source: **Tranco**, a public, research-grade ranking of the most popular websites on the internet
by real traffic. A random sample of domains was taken from near the top of this list
(`google.com`, `cloudflare.com`, `facebook.com`, etc) and used as bare homepage URLs.

```bash
curl -sL "https://tranco-list.eu/top-1m.csv.zip" -o data/tranco.csv.zip
unzip data/tranco.csv.zip -d data/
```

File: `data/top-1m.csv`

### 2. Curated real login pages (51 of them)

Source: hand picked by hand, not scraped. These are actual, real login page URLs for well known
sites (`accounts.google.com/signin/...`, `www.amazon.com/ap/signin`, `my.chase.com/`, etc).

Why these were added: Tranco only gives bare homepages like `google.com`, while every phishing
URL from OpenPhish has a path like `/login.php`. Without these curated login URLs, the model was
just learning "does this URL have a path" as a shortcut for phishing, instead of real phishing
signal. See `security-analysis.md` for the full
story on why this was needed.

File: `src/curated_legit_urls.py`

## Putting it together

Running `src/build_dataset.py` pulls from all three sources above and writes the combined,
labeled dataset to `data/dataset.csv`: 300 phishing rows (label 1) + 300 legit rows (label 0,
51 curated login pages + 249 Tranco homepages).
