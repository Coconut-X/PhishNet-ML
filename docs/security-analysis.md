# Security Analysis

Covers the metrics, the errors, why the sandbox is built the way it is, and the limits. All numbers are
from `python src/train.py` on the current `dataset.csv` (300 phishing, 300 legit).

## 1. Evaluation metrics

Training data: 300 phishing URLs (OpenPhish) and 451 legit URLs: 51 curated login pages, about 300 real URLs
crawled from top sites (homepage as a browser lands on it, plus real internal links with paths and queries),
and 100 bare Tranco homepages. Training uses `class_weight="balanced"`.

Fast model (13 URL features):

| Metric | Value |
|---|---|
| Held-out test (188 rows) accuracy | 0.91 |
| Precision / recall / F1, phishing | 0.86 / 0.92 / 0.89 |
| ROC-AUC | 0.963 |
| 5-fold CV F1, plain | 0.878 (+/- 0.048) |
| 5-fold CV F1, **grouped by domain** | **0.815 (+/- 0.044)** |

Deep model (17 features, 290 rows): test accuracy 0.95 (73 rows, noisy), grouped CV F1 0.796 (+/- 0.136).

**Which number to trust.** The grouped CV (a domain never in both train and test) is the honest one: about 0.82
F1. The held-out split shares domains with training and is optimistic.

**Fresh data** (`src/validate_holdout.py`): a new OpenPhish feed (300 URLs, none in training) and 723 real legit
URLs crawled from sites ranked 2000 and below, which share no site with training. Fast model:

| Threshold | Phishing caught | Real legit pages flagged |
|---|---|---|
| 0.5 | 86% (259 of 300) | 9.8% (71 of 723) |
| 0.7 (used for warnings) | 77% (230 of 300) | 3.3% (24 of 723) |

182 of the 300 fresh phishing URLs sit on domains already seen in training (`pages.dev` and similar), so the
catch rate is flattering. On unseen phishing domains only, accuracy is lower.

**Earlier, much better numbers were not real.** The first versions scored 0.97 to 1.0 because the legit class
was only bare domains (`https://google.com`) while phishing URLs were longer, had `www.`, subdomains, paths and
queries. The model learned "looks like a normal browser URL = phishing". It was found when the Chrome extension
flagged everything a person browsed: a Google search for "can cats drink milk" (152 characters because of its
query string) was flagged as phishing, and so was an ordinary `www.` homepage of a new, harmless site. Fixes:
treat a lone trailing `/` and a leading `www.` as nothing, leave the query string out of the length, dots and
path features, and add real crawled legit URLs. The scores dropped to what they are now, which is the honest
level of a URL-only model.

## 2. False positives and false negatives

Test set confusion matrix: 102 legit right, **11 false positives**, **6 false negatives**, 69 phishing caught.

**False positives** are mostly real login or account pages with deep paths: `my.chase.com/`,
`outlook.live.com/owa/`, `login.epicgames.com/`, `login.opendns.com/?return_to=...`,
`cloud.digitalocean.com/registrations/new`. These look like phishing by URL shape, and nothing in the string
says they are real. A blocked login is the costly error for a user.

**False negatives** are phishing on short, clean-looking URLs, for example `https://www.weqweqw.com/` and
`https://sarkariresult.com.cm/`. On the fresh feed the model also misses `https://otbtaw.cn/`,
`https://califlaw.vip/` and `https://280082365756.com/`. A URL-only model cannot see these. Only the page could,
and the content features did not help enough in the experiment.

**How the product handles this.** The verdict has three levels: LEGITIMATE below 0.5, SUSPICIOUS from 0.5 to 0.7
(shown in the popup, page not blocked), PHISHING at 0.7 and up (warning page). The 0.7 cut-off was chosen from
grouped CV on training data, not from the fresh set. The backend also skips the model for the 20000 most popular
sites (shared hosting platforms such as `github.io`, `pages.dev` and `blogspot.com`, and any domain that appears
in the phishing feeds, are excluded, so they are always scored), since a URL model that flags a Google search is unusable in a browser. This is a pragmatic layer,
and it hides model errors on big sites, so the model numbers above are measured without it.

**Not a new-domain detector.** Domain age is not used by the model (it was dropped), so a recently registered
domain is not flagged for being new. A new harmless site can still be scored as suspicious if its URL shape looks
like the phishing training examples. The model never reads the page unless the deep scan is used.

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
