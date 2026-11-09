import base64
import json
import os
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

#this runs INSIDE the container. it loads the page in a real browser (so javascript runs),
#pulls out the raw bits we care about and prints one json line. all the actual feature
#logic happens on the host, so this stays small

URL = os.environ["TARGET_URL"]
#"host=ip,host2=ip2", already resolved on the host
HOSTMAP = [pair.split("=") for pair in os.environ["TARGET_HOSTMAP"].split(",")]
RULES = ", ".join(f"MAP {h} {ip}" for h, ip in HOSTMAP)

PAGE_INFO_JS = """() => {
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch (e) { return ""; } };
  const icon = document.querySelector("link[rel~=icon]");
  return {
    forms: [...document.forms].map(f => abs(f.getAttribute("action") || "")).slice(0, 50),
    has_password: !!document.querySelector("input[type=password]"),
    resources: [...document.querySelectorAll("script[src], img[src], link[href]")]
      .map(e => abs(e.getAttribute("src") || e.getAttribute("href"))).slice(0, 500),
    icon: icon ? abs(icon.getAttribute("href")) : "",
  };
}"""

#fetch the favicon from inside the page so it goes through chromium's network stack
FAVICON_JS = """async (url) => {
  const r = await fetch(url);
  if (!r.ok) return "";
  const buf = new Uint8Array(await r.arrayBuffer());
  if (buf.length > 200000) return "";
  let s = "";
  for (const b of buf) s += String.fromCharCode(b);
  return btoa(s);
}"""


def main():
    out = {"ok": False, "error": ""}
    try:
        with sync_playwright() as p:
            #--no-sandbox because chromium's own sandbox doesnt work in a locked down
            #container, the container is the sandbox here
            #host-resolver-rules makes the browser use the ips we already resolved, so it
            #never needs dns (which is blocked)
            browser = p.chromium.launch(args=[
                "--no-sandbox", "--disable-gpu",
                f"--host-resolver-rules={RULES}",
            ])
            #accept_downloads=False cancels any download, ignore_https_errors because
            #phishing sites often have broken certs and we only want to read them
            ctx = browser.new_context(accept_downloads=False, service_workers="block",
                                      ignore_https_errors=True)
            page = ctx.new_page()
            resp = page.goto(URL, timeout=20000, wait_until="load")
            #small wait so pages that build their form with js have time to do it
            page.wait_for_timeout(1500)

            info = page.evaluate(PAGE_INFO_JS)
            out.update(info)
            out["status"] = resp.status if resp else 0
            out["final_url"] = page.url
            out["ok"] = bool(resp) and resp.status < 400

            #only try the favicon if it lives on the same host, anything else is blocked
            #by the firewall anyway. the host checks the url of external ones
            icon = info["icon"] or f"{urlparse(page.url).scheme}://{urlparse(page.url).netloc}/favicon.ico"
            out["favicon_url"] = icon
            if urlparse(icon).hostname == urlparse(page.url).hostname:
                try:
                    out["favicon_b64"] = page.evaluate(FAVICON_JS, icon)
                except Exception:
                    out["favicon_b64"] = ""
            browser.close()
    except Exception as e:
        out["error"] = str(e)[:200]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
