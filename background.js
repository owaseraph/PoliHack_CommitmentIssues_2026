"use strict";

const API_BASE = "https://polihackcommitmentissues2026-production-019d.up.railway.app";

// Per-tab LLM timestamps — prevent hammering Gemini on rapid navigation
const tabLlmTs = {};
const LLM_COOLDOWN_MS = 30_000;

function canCallLlm(tabId) {
  return Date.now() - (tabLlmTs[tabId] || 0) >= LLM_COOLDOWN_MS;
}

async function apiFetch(path, body) {
  const r = await fetch(`${API_BASE}${path}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function sendToTab(tabId, msg) {
  chrome.tabs.sendMessage(tabId, msg).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (msg.type === "ANALYZE") {
    if (!tabId) return;
    sendToTab(tabId, { type: "LOADING" });

    apiFetch("/analyze", msg.payload)
      .then(data => {
        if (msg.payload.user_id === "premium_user" && data.source === "llm") {
          tabLlmTs[tabId] = Date.now();
        }
        sendToTab(tabId, { type: "RESULT", payload: data });
        chrome.storage.local.set({ last_result: data });
      })
      .catch(() => {
        sendToTab(tabId, {
          type: "RESULT",
          payload: { trust_score: null, description: "Could not reach PhishGuard server.", error: true },
        });
      });
    return true;
  }

  if (msg.type === "ASK_AI") {
    apiFetch("/ask", msg.payload)
      .then(data => {
        if (tabId) tabLlmTs[tabId] = Date.now();
        sendResponse(data);
        chrome.storage.local.set({ last_result: data });
      })
      .catch(() => sendResponse({ error: true }));
    return true;
  }

  if (msg.type === "DIAGNOSTIC") {
    chrome.storage.local.set({ last_diagnostic: msg.payload });
    return false;
  }
});

chrome.tabs.onRemoved.addListener(tabId => delete tabLlmTs[tabId]);