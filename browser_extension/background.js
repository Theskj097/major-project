// Auto-scan URLs and show badge on extension icon
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (changeInfo.status === "complete" && /^https?/.test(tab.url)) {
    scanAndSetBadge(tabId, tab.url);
  }
});

function scanAndSetBadge(tabId, url) {
  fetch("http://localhost:5000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.prediction === 1 || data.risk_level === "high") {
        // Phishing detected
        chrome.action.setBadgeText({ tabId: tabId, text: "!" });
        chrome.action.setBadgeBackgroundColor({
          tabId: tabId,
          color: "#ef4444",
        });
      } else if (data.risk_level === "medium" || data.risk_level === "low") {
        // Suspicious
        chrome.action.setBadgeText({ tabId: tabId, text: "?" });
        chrome.action.setBadgeBackgroundColor({
          tabId: tabId,
          color: "#f59e0b",
        });
      } else {
        // Safe
        chrome.action.setBadgeText({ tabId: tabId, text: "✓" });
        chrome.action.setBadgeBackgroundColor({
          tabId: tabId,
          color: "#10b981",
        });
      }
    })
    .catch((err) => {
      console.error("Background scan error:", err);
    });
}
