const API = "http://127.0.0.1:5000";
const verdictEl = document.getElementById("verdict");
const whyEl = document.getElementById("why");

async function scan(kind, url) {
  const res = await fetch(API + "/scan/" + kind, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const r = await res.json();
  if (!res.ok) throw new Error(r.error || res.status);
  return r;
}

//everything from the page or the backend goes in with textContent
function show(r) {
  verdictEl.textContent = r.verdict + " (" + Math.round(r.confidence * 100) +
    "% confident, phishing probability " + Math.round(r.phishing_probability * 100) +
    "%, model: " + r.model + ")";
  whyEl.replaceChildren();
  for (const e of r.explanation) {
    const li = document.createElement("li");
    li.textContent = (e.shap >= 0 ? "+" : "") + e.shap.toFixed(3) + "  " + e.feature + " = " + e.value;
    whyEl.appendChild(li);
  }
}

async function activeUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  document.getElementById("url").textContent = url || "";
  return url && /^https?:\/\//.test(url) ? url : null;
}

async function run(kind) {
  const url = await activeUrl();
  if (!url) {
    verdictEl.textContent = "Only http and https pages can be scanned.";
    return;
  }
  verdictEl.textContent = kind === "deep" ? "Deep scan, this can take several seconds..." : "Checking...";
  try {
    show(await scan(kind, url));
  } catch (e) {
    verdictEl.textContent = "Could not reach the backend. Is backend/api.py running?";
  }
}

document.getElementById("deep").onclick = () => run("deep");
//fast result shows as soon as the popup opens
run("fast");
