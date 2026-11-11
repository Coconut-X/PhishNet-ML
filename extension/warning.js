//the url comes from the web so it only ever goes in with textContent, never innerHTML
const url = new URLSearchParams(location.search).get("u") || "";
document.getElementById("url").textContent = url;

chrome.storage.session.get("r:" + url).then((data) => {
  const r = data["r:" + url];
  if (!r) return;
  document.getElementById("prob").textContent =
    "Phishing probability: " + Math.round(r.phishing_probability * 100) + "%";
  const list = document.getElementById("why");
  for (const e of r.explanation) {
    const li = document.createElement("li");
    li.textContent = (e.shap >= 0 ? "+" : "") + e.shap.toFixed(3) + "  " + e.feature + " = " + e.value;
    list.appendChild(li);
  }
});

document.getElementById("back").onclick = () => {
  //the warning page replaced the page in this tab, so going back is just history back
  if (history.length > 1) history.back();
  else window.close();
};

document.getElementById("proceed").onclick = async () => {
  //remember the choice for this browser session so it doesnt warn again in a loop
  const { allow = [] } = await chrome.storage.session.get("allow");
  allow.push(url);
  await chrome.storage.session.set({ allow });
  location.href = url;
};
