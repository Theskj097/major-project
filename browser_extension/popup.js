document.addEventListener("DOMContentLoaded", function () {
  // Auto-scan when popup opens
  scanCurrentTab();

  // Manual rescan button
  document.getElementById("scanBtn").onclick = function () {
    scanCurrentTab();
  };
});

function scanCurrentTab() {
  setLoading(true);
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    let url = tabs[0].url;

    // Don't scan chrome:// or extension pages
    if (!url.startsWith("http")) {
      setLoading(false);
      showError("Cannot scan this page type");
      return;
    }

    fetch("http://localhost:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    })
      .then((r) => r.json())
      .then((data) => {
        setLoading(false);
        showResult(data);
      })
      .catch((err) => {
        setLoading(false);
        showError("Failed to scan: " + err.message);
      });
  });
}

function setLoading(isLoading) {
  document.getElementById("loading").style.display = isLoading
    ? "block"
    : "none";
  document.getElementById("resultSection").style.display = "none";
  document.getElementById("error").style.display = "none";
  document.getElementById("status").style.display = isLoading
    ? "none"
    : "block";
}

function showResult(data) {
  document.getElementById("resultSection").style.display = "block";
  document.getElementById("status").style.display = "none";

  const verdictEl = document.getElementById("verdict");
  const verdictContainer = document.querySelector(".verdict-container");

  verdictEl.textContent = data.result;
  document.getElementById("confidence").textContent =
    data.confidence + "% confidence";

  // Style based on risk
  verdictContainer.classList.remove(
    "verdict-safe",
    "verdict-danger",
    "verdict-warning"
  );
  if (data.risk_level === "safe") {
    verdictContainer.classList.add("verdict-safe");
    verdictEl.textContent = "✓ " + data.result;
  } else if (data.risk_level === "high") {
    verdictContainer.classList.add("verdict-danger");
    verdictEl.textContent = "⚠ " + data.result;
  } else {
    verdictContainer.classList.add("verdict-warning");
    verdictEl.textContent = "⚡ " + data.result;
  }

  // Explanation
  let explanation = "";
  if (data.prediction === 1) {
    explanation = "<strong>Why this might be phishing:</strong><br>";
    explanation += buildExplanation(data);
  } else {
    explanation =
      "<strong>✓ This site appears legitimate.</strong> No major phishing indicators detected.";
  }
  document.getElementById("explanation").innerHTML = explanation;

  // Risk factors
  if (data.top_risk_factors && data.top_risk_factors.length > 0) {
    let riskHTML =
      "<strong>Key Risk Factors:</strong><ul style='margin:8px 0 0 20px;'>";
    data.top_risk_factors.slice(0, 3).forEach((factor) => {
      if (factor.impact === "increases risk") {
        riskHTML += `<li>${factor.feature}: ${factor.value}</li>`;
      }
    });
    riskHTML += "</ul>";
    document.getElementById("riskFactors").innerHTML = riskHTML;
    document.getElementById("riskFactors").style.display =
      data.prediction === 1 ? "block" : "none";
  }
}

function buildExplanation(data) {
  let parts = [];
  if (data.all_features) {
    if (data.all_features.has_login) parts.push("Contains 'login' keyword");
    if (data.all_features.has_ip)
      parts.push("Uses IP address instead of domain");
    if (data.all_features.domain_age_days < 30)
      parts.push("Very new domain (less than 30 days old)");
    if (data.all_features.is_shortened) parts.push("Uses URL shortener");
    if (data.all_features.hyphen_count > 2)
      parts.push("Multiple hyphens in domain");
  }
  return parts.length > 0
    ? parts.join(", ") + "."
    : "Multiple suspicious indicators detected.";
}

function showError(message) {
  document.getElementById("error").style.display = "block";
  document.getElementById("error").textContent = "⚠️ " + message;
  document.getElementById("status").style.display = "none";
}
