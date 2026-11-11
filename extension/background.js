const API = "http://127.0.0.1:5000";
const FAST_TIMEOUT_MS = 3000;

//asks the backend for a fast scan, gives up after a few seconds
async function scanFast(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FAST_TIMEOUT_MS);
  try {
    const res = await fetch(API + "/scan/fast", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function isAllowed(url) {
  const { allow = [] } = await chrome.storage.session.get("allow");
  return allow.includes(url);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  //top frame only, and only normal web pages
  if (details.frameId !== 0) return;
  if (!/^https?:\/\//.test(details.url)) return;
  //never scan the backend itself
  if (details.url.startsWith(API)) return;
  if (await isAllowed(details.url)) return;

  const result = await scanFast(details.url);
  if (!result) {
    //backend is down, let the page load but show it on the icon so it isnt silent
    chrome.action.setBadgeText({ tabId: details.tabId, text: "?" });
    return;
  }
  if (result.verdict !== "PHISHING") {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
    return;
  }

  //keep the result for the warning page to show
  await chrome.storage.session.set({ ["r:" + details.url]: result });
  const warn = chrome.runtime.getURL("warning.html") + "?u=" + encodeURIComponent(details.url);
  chrome.tabs.update(details.tabId, { url: warn });
});
