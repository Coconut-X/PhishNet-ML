# Security Analysis

Covers the metrics, the errors, why the sandbox is built the way it is, and the limits. All numbers are
from `python src/train.py` on the current `dataset.csv` (300 phishing, 300 legit).

## 1. Evaluation metrics

Fast model (13 URL features):

| Metric | Value |
|---|---|
| Held-out test (150 rows) accuracy | 0.97 |
| Precision / recall, phishing | 0.95 / 1.00 |
| Precision / recall, legit | 1.00 / 0.95 |
| ROC-AUC | 0.996 |
| 5-fold CV F1, plain | 0.937 (+/- 0.118) |
| 5-fold CV F1, **grouped by domain** | **0.975 (+/- 0.013)** |

Deep model (17 features, 208 rows): test accuracy 0.96, grouped CV F1 0.983 (+/- 0.023).

**Which number to trust.** The held-out test split shares registered domains with the training split
(300 phishing rows sit on only 94 domains), so it is optimistic. The grouped CV keeps a domain on one
side only, and is the number I would quote. The plain CV has one unexplained bad fold (0.702), which
is why its spread is so large. A test on fresh data (`src/validate_holdout.py`): 98% accuracy (1 false positive, 9 phishing missed), but the legit set was bare homepages; a login-path stress test flagged up to 100% of legit domains.

## 2. False positives and false negatives

Confusion matrix on the test set: 72 true legit, **3 false positives**, **2 false negatives**, 73 true phishing.

**False positives (legit flagged as phishing)**: `booking.com/sign-in.html`, `outlook.live.com/owa/` and
`hbomax.com/sign-in`. They are real login pages. Their URLs are long and deep, which is what the model learned
as phishing, and nothing in the URL says they are real. This is the costly error for a user: a blocked login.

**False negatives (phishing let through)**: `in-echallan.fun/` and `duck2store.com/`. Both are short, bare-domain
URLs with nothing suspicious in the string. On the fresh feed the model missed 9 of 300, nearly all of the same
kind: `https://btctrz.com/`, `https://otbtaw.cn/`, `https://webtrz.com/` (scores near 0). A URL-only model cannot
see these. Only the page content could, and that did not work well enough (the content-features experiment).

Other reasons it will miss in practice:
- Phishing on short, clean URLs (a hacked small site, `evil.com/a`) looks like legit to a model that
  leans on `path_length` and `url_length`.
- The dataset has no phishing that mimics the curated legit login pages closely.
- The test set is the same distribution as training; the fresh feed (`validate_holdout.py`) is the better guide.

## 3. Shortcuts the model learned

Found with SHAP. `path_length` and `url_length` are the top two features by a large margin.
`suspicious_word_count` points the wrong way (more login words means legit) because the curated legit
pages are login pages and most phishing URLs have no such words. The legit class is old and famous by
construction (Tranco). These are properties of how the data was collected, not of phishing.

**Worked example, the first model:** the first model scored 1.0 on everything. The legit URLs were bare
domains (`google.com`) and the phishing URLs were long paths, so the model only learned "has a path".
Mixing in real login pages broke the shortcut and the score dropped to 0.937. A perfect
score on an easy dataset is a warning, not a result. It happened again in a smaller form later: a
trailing `/` (browsers always send it, the Tranco rows had none) was read as phishing, and removing it cost
about 2 points of grouped F1.

`domain_age_days` was dropped for the same kind of reason (it separated the classes through the way the
data was sampled, with no gain on unseen domains).

## 4. Why the sandbox is built this way

Opening a phishing page is the dangerous part of the project. The page can run JavaScript, try to
download files, probe the local network, or be pointed at internal addresses.

| Threat | Control |
|---|---|
| URL points at `127.0.0.1`, LAN or cloud metadata (SSRF) | Host resolves DNS and keeps only `is_global` IPv4; if none, the container never starts. |
| Page talks to other hosts | Container iptables allows only the target IPs on ports 80/443/URL port, rejects the rest. IPv6 disabled. |
| Code escapes or escalates | Runs as `pwuser` via `setpriv` with no capabilities and no-new-privs; read-only filesystem; tmpfs for scratch. |
| Resource exhaustion | Memory, pids and CPU limits; 60 s timeout then `docker kill`. |
| Malicious download | Downloads blocked. |
| Container lies in its output | Output is treated as untrusted JSON, only known fields are read. |

`src/sandbox/test_isolation.py` checks these 10 behaviours and all pass. They were written to need an
explicit "blocked" marker, because the first version passed falsely when Docker failed to start.

## 5. Known limitations

- Only 208 of 600 pages load (dead phishing pages, bot blocking). The content features rarely fire and
  did not improve the grouped CV, so the deep model is mostly a research result.
- Cloaking: a phishing page can show a harmless page to a headless browser. Not tested.
- `brand_edit_distance` compares the whole domain label, so `paypa1-secure-login` is not seen as close to `paypal`.
- `external_resource_ratio` penalises sites that use CDNs.
- Dropbox and Discord are missing from the favicon database.
- The content cache stores computed features, not raw page data.
- The Docker sandbox is not a hardened VM. A container escape would still reach the host, and the Docker
  daemon is trusted.
- The phishing sample is one feed (OpenPhish) from a short window, and heavily clustered on a few hosts.
- A model trained on URL strings can be evaded by an attacker who knows the features (short clean URLs).
