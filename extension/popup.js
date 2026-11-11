const API = "http://127.0.0.1:5000";
const verdictEl = document.getElementById("verdict");

document.getElementById("deep").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  document.getElementById("url").textContent = url || "";
  if (!url || !/^https?:\/\//.test(url)) {
    verdictEl.textContent = "Only http and https pages can be scanned.";
    return;
  }
  verdictEl.textContent = "Scanning, this can take several seconds...";
  document.getElementById("why").replaceChildren();
  try {
    const res = await fetch(API + "/scan/deep", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const r = await res.json();
    if (!res.ok) throw new Error(r.error || res.status);
    verdictEl.textContent = r.verdict + " (" + Math.round(r.phishing_probability * 100) +
      "% phishing, model: " + r.model + ")";
    for (const e of r.explanation) {
      const li = document.createElement("li");
      li.textContent = (e.shap >= 0 ? "+" : "") + e.shap.toFixed(3) + "  " + e.feature + " = " + e.value;
      document.getElementById("why").appendChild(li);
    }
  } catch (e) {
    verdictEl.textContent = "Could not reach the backend. Is backend/api.py running?";
  }
};
