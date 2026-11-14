# Chrome extension: workflow and user story

The extension protects someone while they browse. It only asks the local backend for a verdict. It never
loads or renders untrusted content itself, and any page fetching for a deep scan happens in the Docker
sandbox on the backend.

## Parts

```
 Chrome ── navigation ──► background.js ── POST /scan/fast ──► backend/api.py ──► classify() (model + SHAP)
    ▲                          │                                      │
    │                          ◄──────────── verdict + reasons ───────┘
    └── warning.html (redirect)   popup.html ── POST /scan/deep ──► backend ──► Docker sandbox ──► page
```

## Story 1: a normal, safe page

1. Sam types `https://github.com/` into the address bar and presses Enter.
2. Chrome fires `webNavigation.onBeforeNavigate`. The background script sends the URL to `/scan/fast`
   (URL features only, about 0.15 s).
3. Verdict LEGITIMATE. The extension does nothing. The page loads normally. Sam notices nothing, the
   toolbar badge stays empty.

## Story 2: a phishing link

1. Sam gets an email and clicks a link to `http://paypal-secure-login.verify-account.pages.dev/login.php`.
2. The extension catches the navigation and asks the backend. The verdict is PHISHING (probability 0.79).
3. The tab is redirected to the extension's own **warning page**. Sam sees:
   - a red heading "This page may be a phishing site"
   - the URL that was flagged
   - the phishing probability (79%)
   - the top reasons, for example `+0.134 uses_https = 0`, `+0.124 url_length = 61`, `+0.068 num_dots = 4`
     (positive numbers pushed towards phishing, negative towards legit)
   - two buttons: **Go back** and **Proceed anyway**
4. **If Sam clicks Go back**, they return to the previous page and the phishing site is never used.
5. **If Sam clicks Proceed anyway**, the choice is remembered for this browser session and the browser
   goes to the original URL. The extension does not warn again for that URL until Chrome is closed.

## Story 3: a legit page that gets flagged (false positive)

Same as story 2, but the page is real, for example a bank login with a long path. Sam sees the warning and
the reasons (long URL, odd path), decides it is fine and clicks **Proceed anyway**. The page loads as normal.
This is why there is an override at all: the model is not perfect (see `security-analysis.md`).

## Story 4: a closer look (deep scan)

1. Sam is on a page that feels off and clicks the extension icon.
2. The popup opens and immediately shows the **fast** result: verdict, confidence, probability and the top
   SHAP reasons.
3. Sam clicks **Deep scan this page**. The backend loads the page inside the sandbox (firewalled Docker
   container), computes the content features (does the form submit to another domain, does the favicon match
   a known brand, how much is loaded from third parties) and scores it with the deep model. This takes
   several seconds. The popup shows the new verdict and reasons.
4. If the page cannot be loaded or Docker is down, the popup says the fast model was used instead.

## Story 5: the backend is not running

The page loads normally (the extension fails open so browsing never breaks) and the toolbar icon shows a
`?` badge, so the failure is visible and not silent.

## What the extension never does

- It never fetches or renders a suspicious page itself.
- It never scans the backend's own address or non-web URLs (`chrome://`, `file://`).
- The URL shown on the warning page is inserted as plain text, so a crafted URL cannot run script.

## Limits

- `onBeforeNavigate` cannot block a navigation. The browser starts loading while the check runs (about
  0.15 s), then the tab is redirected. This is a warning tool, not a firewall.
- Only top-level navigations are checked, not frames inside a page.
- The backend must be running locally, with no authentication (localhost only).

## Setup and registering it in Chrome

1. Start the backend from the project root: `python backend/api.py`.
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, select the `extension/` folder.
   The extension appears with its toolbar icon (pin it from the puzzle-piece menu).
3. To demo in a clean browser instead, run `bash demo/launch_chromium.sh`, which starts Chromium with the
   extension already loaded.
There is no need to publish it to the Chrome Web Store.
