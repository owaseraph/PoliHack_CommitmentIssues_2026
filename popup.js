"use strict";

// ── DOM refs ──────────────────────────────────────────────────────────────
const planChip    = document.getElementById("plan-chip");
const ringArc     = document.getElementById("ring-arc");
const ringNum     = document.getElementById("ring-num");
const scoreNum    = document.getElementById("score-num");
const scoreVerdict= document.getElementById("score-verdict");
const scoreUrl    = document.getElementById("score-url");
const descText    = document.getElementById("desc-text");
const threatChip  = document.getElementById("threat-chip");
const dLinks      = document.getElementById("d-links");
const dMode       = document.getElementById("d-mode");
const dSource     = document.getElementById("d-source");
const dTs         = document.getElementById("d-ts");
const btnFree     = document.getElementById("btn-free");
const btnPremium  = document.getElementById("btn-premium");
const rescanBtn   = document.getElementById("rescan-btn");
const askBtn      = document.getElementById("ask-btn");

const CIRC = 2 * Math.PI * 24; // r=24 → ≈150.8

// ── Helpers ───────────────────────────────────────────────────────────────
function getLevel(score) {
  if (score == null) return "unknown";
  if (score >= 75)   return "safe";
  if (score >= 45)   return "warn";
  return "danger";
}

const LEVEL_COLOR = {
  safe:    "var(--green)",
  warn:    "var(--amber)",
  danger:  "var(--red)",
  unknown: "var(--muted)",
};

const LEVEL_LABEL = {
  safe:    "Verified Safe",
  warn:    "Use Caution",
  danger:  "Threat Detected",
  unknown: "No scan yet",
};

function relTime(ts) {
  if (!ts) return "—";
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 5)  return "just now";
  if (s < 60) return `${s}s ago`;
  return `${Math.round(s/60)}m ago`;
}

// ── Render ────────────────────────────────────────────────────────────────
function renderScore(score) {
  const level = getLevel(score);
  const color = LEVEL_COLOR[level];
  const dash  = score != null ? (score / 100) * CIRC : 0;

  ringArc.style.strokeDasharray = `${dash.toFixed(1)} ${CIRC.toFixed(1)}`;
  ringArc.setAttribute("stroke", color.replace("var(", "").replace(")", "")); // fallback
  ringArc.style.stroke = color;
  ringNum.setAttribute("fill", color.replace("var(", "").replace(")", ""));
  ringNum.style.fill   = color;
  ringNum.textContent  = score != null ? score : "—";

  scoreNum.className      = `score-num c-${level}`;
  scoreNum.textContent    = score != null ? score : "—";
  scoreVerdict.className  = `score-verdict c-${level}`;
  scoreVerdict.textContent= LEVEL_LABEL[level];
}

function renderResult(result, diag) {
  if (!result) return;

  renderScore(result.trust_score);
  descText.textContent = result.description || "—";

  // Threat chip
  if (result.threat_type && result.threat_type !== "none") {
    threatChip.textContent = result.threat_type.replace(/_/g, " ");
    threatChip.style.display = "inline-block";
  } else {
    threatChip.style.display = "none";
  }

  // Diagnostics
  if (diag) {
    dLinks.textContent  = diag.links_found ?? "—";
    dMode.textContent   = diag.mode        ?? "—";
    dSource.textContent = diag.source      ?? "—";
  }
}

function renderDiagnostic(diag) {
  if (!diag) return;
  dLinks.textContent  = diag.links_found ?? "—";
  dMode.textContent   = diag.mode        ?? "—";
  dSource.textContent = diag.source      ?? "—";
  dTs.textContent     = relTime(diag.ts);

  // Refresh URL
  if (diag.url) {
    try {
      scoreUrl.textContent = new URL(diag.url).hostname;
    } catch { scoreUrl.textContent = diag.url.slice(0, 30); }
  }
}

function setPlan(plan) {
  const isPrem = plan === "premium_user";
  btnFree.className    = "plan-btn" + (isPrem ? "" : " active-free");
  btnPremium.className = "plan-btn" + (isPrem ? " active-premium" : "");
  planChip.textContent = isPrem ? "PREMIUM" : "FREE";
  planChip.className   = "header-status" + (isPrem ? " premium" : "");
  askBtn.className     = "ask-btn" + (isPrem ? " visible" : "");
}

// ── Load saved state ──────────────────────────────────────────────────────
chrome.storage.local.get(["user_id", "last_result", "last_diagnostics", "last_diagnostic"], (res) => {
  setPlan(res.user_id || "free_user");

  if (res.last_result) {
    renderResult(res.last_result, res.last_diagnostics);
    renderScore(res.last_result.trust_score);
  }

  if (res.last_diagnostic) {
    renderDiagnostic(res.last_diagnostic);
  }

  // Refresh the relative timestamp every second
  setInterval(() => {
    chrome.storage.local.get(["last_diagnostic"], r => {
      if (r.last_diagnostic?.ts) dTs.textContent = relTime(r.last_diagnostic.ts);
    });
  }, 1000);
});

// ── Plan buttons ──────────────────────────────────────────────────────────
btnFree.onclick = () => {
  chrome.storage.local.set({ user_id: "free_user" });
  setPlan("free_user");
};

btnPremium.onclick = () => {
  chrome.storage.local.set({ user_id: "premium_user" });
  setPlan("premium_user");
};

// ── Rescan ────────────────────────────────────────────────────────────────
rescanBtn.onclick = () => {
  rescanBtn.textContent = "↺ Scanning…";
  rescanBtn.disabled    = true;
  scoreNum.classList.add("scanning");

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]?.id) return;
    chrome.tabs.sendMessage(tabs[0].id, { type: "FORCE_SCAN" }, () => {
      setTimeout(() => {
        rescanBtn.textContent = "↺ Rescan";
        rescanBtn.disabled    = false;
        scoreNum.classList.remove("scanning");
      }, 2500);
    });
  });
};

// ── Ask AI (premium only) ─────────────────────────────────────────────────
askBtn.onclick = () => {
  askBtn.disabled    = true;
  askBtn.textContent = "⚡ Analyzing…";

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]?.id) return;
    chrome.tabs.sendMessage(tabs[0].id, { type: "FORCE_SCAN" });
  });

  // Re-enable after cooldown window
  setTimeout(() => {
    askBtn.disabled    = false;
    askBtn.textContent = "⚡ Ask AI";
  }, 5000);
};

// ── Live updates from storage ─────────────────────────────────────────────
chrome.storage.onChanged.addListener((changes) => {
  if (changes.last_result) {
    const r = changes.last_result.newValue;
    renderScore(r.trust_score);
    descText.textContent = r.description || "—";
    if (r.threat_type && r.threat_type !== "none") {
      threatChip.textContent   = r.threat_type.replace(/_/g, " ");
      threatChip.style.display = "inline-block";
    } else {
      threatChip.style.display = "none";
    }
  }
  if (changes.last_diagnostics) {
    renderDiagnostic(changes.last_diagnostics.newValue);
  }
  if (changes.last_diagnostic) {
    renderDiagnostic(changes.last_diagnostic.newValue);
  }
});