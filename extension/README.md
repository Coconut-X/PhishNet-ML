# Chrome extension and demo

Optional extension from the extended proposal. It only asks the local backend for a verdict, it never loads
or renders untrusted content itself. Page fetching happens in the Docker sandbox on the backend.

## Run the demo

```bash
python backend/api.py          # terminal 1, http://127.0.0.1:5000
python demo/serve.py           # terminal 2, harmless clone page on http://localhost:8000/login.html
python demo/run_cases.py       # optional: scores demo/cases.txt from the command line
```
Chrome: `chrome://extensions`, Developer mode, Load unpacked, pick `extension/`.

- The popup shows the fast verdict, confidence and top SHAP reasons as soon as it opens, and has a Deep scan button.
- Phishing samples in `demo/cases.txt` are only scored as text. Do not open them in a browser.
- Note: the model currently flags `http://localhost:8000/login.html` (about 0.68). That is a false positive on a
  harmless page and is useful to show the warning page and Proceed anyway. It happens because the model was trained
  on public sites, and plain `http` with a login path looks like phishing to it.

## Fast check vs deep scan (trade-off)

| | Fast (`/scan/fast`) | Deep (`/scan/deep`) |
|---|---|---|
| Input | URL string only | URL plus the page, loaded in the sandbox |
| Time | about 0.15 s | about 6.7 s in one test |
| Opens the page | never | yes, inside the firewalled container |
| Training data | all 600 rows | only the 208 rows whose page loaded |
| Grouped CV F1 | 0.951 | 0.977 (+/- 0.022, small sample) |
| Failure | none | falls back to fast if Docker or the page is unavailable |

The deep model scores a little higher on paper, but it trained on a third of the data and only 208 of 600 pages
load, so I would not claim it is better. Its content features rarely fire (see Iteration 3). The fast path is
the one that suits real-time use, which is why the extension checks every navigation with it and keeps deep
scan as a manual button.

## Limits

`onBeforeNavigate` cannot block a navigation, it can only redirect shortly after the page starts loading.
Untested in a real browser so far. More in `docs/iteration-08-chrome-extension.md`.
