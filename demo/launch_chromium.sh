#!/bin/bash
#opens a fresh chromium profile with the extension already loaded, for the demo
#needs the backend running: python backend/api.py
cd "$(dirname "$0")/.." || exit 1
BROWSER=$(command -v google-chrome || command -v chromium || command -v chromium-browser)
[ -z "$BROWSER" ] && { echo "no chrome or chromium found"; exit 1; }
exec "$BROWSER" --user-data-dir=/tmp/phish-demo-profile \
  --disable-extensions-except="$PWD/extension" --load-extension="$PWD/extension" \
  http://paypal-secure-login.verify-account.localhost:8000/login.html
