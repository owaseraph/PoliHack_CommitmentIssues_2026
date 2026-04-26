(() => {
  "use strict";

  // ── Skip on PhishGuard's own domain ──────────────────────────────────────
  const SAFE_HOSTS = [
    // PhishGuard's own domains
    "polihackcommitmentissues2026-production.up.railway.app",
    "polihackcommitmentissues2026-production-019d.up.railway.app",
    // Google auth — never flag these, they are legitimate OAuth flows
    "accounts.google.com",
    "oauth2.googleapis.com",
    "apis.google.com",
  ];
  if (SAFE_HOSTS.some(h => location.hostname === h)) return;

  const VERDICT_URL   = "https://polihackcommitmentissues2026-production.up.railway.app/login";
  const SCAN_DELAY_MS = 1200;
  const BADGE_ID      = "pg-badge";
  const PANEL_ID      = "pg-panel";
  const OVERLAY_ID    = "pg-overlay";
  const STYLE_ID      = "pg-styles";

  // ── State ─────────────────────────────────────────────────────────────────
  let badgeEl             = null;
  let panelEl             = null;
  let overlayEl           = null;
  let lastResult          = null;
  let highlightedEls      = [];
  let scanTimer           = null;
  let changeTimer         = null;
  let lastLinkSet         = "";
  let overlaySnoozedUntil = 0;   // ms epoch — don't show overlay until after this
  let llmResult           = null; // last result from LLM (source: "llm" or "llm-cached")
  let dbResult            = null; // last result from DB (source: "db")
  let overlayShownForScore = null; // score when overlay last shown — re-show only if score gets worse

  // ── Extraction ────────────────────────────────────────────────────────────
  const RE_URL   = /https?:\/\/[^\s"'<>()\[\]]+/g;
  const RE_EMAIL = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  const NO_REPLY_RE = /^(noreply|no-reply|donotreply|mailer-daemon|postmaster|bounce)$/i;

  function ownUI(el) {
    return el.closest(`#${BADGE_ID},#${PANEL_ID},#${OVERLAY_ID}`);
  }

  function cloneWithoutUI() {
    const clone = document.body.cloneNode(true);
    clone.querySelectorAll("script,style,noscript,svg,img").forEach(e => e.remove());
    [`#${BADGE_ID}`,`#${PANEL_ID}`,`#${OVERLAY_ID}`].forEach(id => clone.querySelector(id)?.remove());
    return clone;
  }

  function isActionableHref(h) {
    if (!h) return false;
    if (h.startsWith("mailto:")) {
      const local = h.replace("mailto:","").split("@")[0];
      if (NO_REPLY_RE.test(local)) return false;
      return true;
    }
    if (/^https?:\/\//.test(h)) {
      try {
        const host = new URL(h).hostname;
        return !SAFE_HOSTS.includes(host);
      } catch { return false; }
    }
    return false;
  }

  function extractAll() {
    const seen  = new Set();
    const links = [];

    const add = raw => {
      const h = raw.trim().replace(/[.,;:!?)>]+$/, "");
      if (!h || seen.has(h)) return;
      if (!isActionableHref(h)) return;
      seen.add(h);
      links.push(h);
    };

    // Resolved anchor hrefs (most reliable — browser has already resolved relative URLs)
    document.querySelectorAll("a[href]").forEach(a => {
      if (ownUI(a)) return;
      add(a.href);
    });

    // Raw text — catches bare URLs/emails not wrapped in <a>
    const clone = cloneWithoutUI();
    const raw   = (clone.innerText || clone.textContent || "").replace(/\s+/g, " ");
    for (const m of raw.matchAll(RE_URL))   add(m[0]);
    for (const m of raw.matchAll(RE_EMAIL)) add("mailto:" + m[0].toLowerCase());

    return {
      text : raw.slice(0, 4000),
      links: links.slice(0, 80),
    };
  }

  function linkFingerprint() {
    const hrefs = new Set();
    document.querySelectorAll("a[href]").forEach(a => {
      if (ownUI(a)) return;
      if (isActionableHref(a.href)) hrefs.add(a.href);
    });
    return [...hrefs].sort().join("|");
  }

  function buildPayload(userId) {
    const { text, links } = extractAll();
    return { user_id: userId || "free_user", data: text, links, url: location.href };
  }

  // ── Scoring ───────────────────────────────────────────────────────────────
  function getLevel(score) {
    if (score == null) return "unknown";
    if (score >= 75)   return "safe";
    if (score >= 45)   return "warn";
    return "danger";
  }

  const META = {
    safe:    { color: "#22c55e", label: "Safe",            icon: "✓" },
    warn:    { color: "#f59e0b", label: "Caution",         icon: "⚠" },
    danger:  { color: "#ef4444", label: "Threat Detected", icon: "✕" },
    unknown: { color: "#6b7280", label: "Scanning…",       icon: "·" },
    loading: { color: "#3b82f6", label: "Scanning…",       icon: "↻" },
  };

  // ── Styles ────────────────────────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement("style");
    s.id = STYLE_ID;
    s.textContent = `
      #${BADGE_ID} {
        all: initial;
        position: fixed; bottom: 20px; right: 20px; z-index: 2147483647;
        display: flex; align-items: center; gap: 6px;
        padding: 6px 13px 6px 9px; border-radius: 999px;
        font-family: 'SF Mono','Fira Code',monospace;
        font-size: 12px; font-weight: 700; cursor: pointer;
        border: 1px solid transparent; backdrop-filter: blur(14px);
        box-shadow: 0 4px 20px rgba(0,0,0,.45);
        transition: opacity .4s ease, transform .4s ease;
        user-select: none; letter-spacing: .02em; white-space: nowrap;
      }
      #${BADGE_ID}.pg-safe    { background:rgba(5,46,22,.93);  border-color:#22c55e44; color:#22c55e; }
      #${BADGE_ID}.pg-warn    { background:rgba(28,20,0,.93);  border-color:#f59e0b55; color:#f59e0b; }
      #${BADGE_ID}.pg-danger  { background:rgba(28,0,0,.96);   border-color:#ef444466; color:#ef4444;
                                 animation:pg-pulse 2s ease-in-out infinite; }
      #${BADGE_ID}.pg-loading,
      #${BADGE_ID}.pg-unknown { background:rgba(12,18,34,.93); border-color:#3b82f644; color:#3b82f6; }
      #${BADGE_ID}.pg-gone    { opacity:0; pointer-events:none; transform:translateY(8px); }
      .pg-spin { display:inline-block; animation:pg-spin 1s linear infinite; }
      @keyframes pg-pulse {
        0%,100%{ box-shadow:0 4px 20px rgba(239,68,68,.2); }
        50%    { box-shadow:0 4px 36px rgba(239,68,68,.6); }
      }
      @keyframes pg-spin { to{ transform:rotate(360deg); } }

      #${PANEL_ID} {
        all: initial;
        position: fixed; bottom: 68px; right: 20px; z-index: 2147483646;
        width: 288px; background: #080d1a; border: 1px solid #1a2540;
        border-radius: 14px; padding: 16px;
        font-family: 'SF Mono','Fira Code',monospace; color: #e2e8f0; font-size: 12px;
        box-shadow: 0 24px 64px rgba(0,0,0,.7); backdrop-filter: blur(20px);
        transform-origin: bottom right;
        transition: opacity .22s cubic-bezier(.4,0,.2,1), transform .22s cubic-bezier(.4,0,.2,1);
      }
      #${PANEL_ID}.pg-hidden { opacity:0; pointer-events:none; transform:scale(.93) translateY(8px); }
      .pg-ph  { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
      .pg-pt  { font-size:11px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; color:#7a8fa6; }
      .pg-px  { all:initial; color:#7a8fa6; cursor:pointer; font-size:15px; line-height:1; font-family:monospace; transition:color .15s; }
      .pg-px:hover { color:#e2e8f0; }
      .pg-sr  { display:flex; align-items:center; gap:12px; margin-bottom:12px; }
      .pg-sn  { font-size:26px; font-weight:700; line-height:1; }
      .pg-ss  { font-size:10px; color:#8fa3b8; margin-top:3px; letter-spacing:.07em; text-transform:uppercase; }
      .pg-tc  { display:inline-block; margin-top:6px; padding:2px 8px; border-radius:999px;
                font-size:9px; font-weight:700; letter-spacing:.1em; text-transform:uppercase;
                background:#1c0000; color:#ef4444; border:1px solid #ef444433; }
      .pg-desc { font-size:12px; color:#c8d8e8; line-height:1.65; padding:10px 12px; background:#0c1120;
                 border-radius:8px; margin-bottom:10px; border:1px solid #1a2540; font-family:system-ui,sans-serif; }
      .pg-flagged { font-size:10px; color:#7a8fa6; margin-bottom:10px;
                    white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .pg-flagged b { color:#ef444488; }
      .pg-ab  { all:initial; display:block; width:100%; box-sizing:border-box; padding:8px;
                border-radius:8px; border:1px solid #3b82f633; background:#0c1829; color:#3b82f6;
                font-family:'SF Mono',monospace; font-size:11px; font-weight:700; cursor:pointer;
                letter-spacing:.05em; transition:all .15s; margin-bottom:8px; text-align:center; }
      .pg-ab:hover:not(:disabled) { background:#1e3a5f; border-color:#3b82f688; }
      .pg-ab:disabled { opacity:.4; cursor:default; }
      .pg-rl  { all:initial; display:block; text-align:center; font-size:10px; color:#5a7a9a;
                letter-spacing:.05em; cursor:pointer; transition:color .15s; font-family:monospace; }
      .pg-rl:hover { color:#8fa3b8; }

      /* Danger overlay */
      #${OVERLAY_ID} {
        all: initial;
        position: fixed; inset: 0; z-index: 2147483640;
        display: flex; align-items: center; justify-content: center;
        background: rgba(6,0,0,.88); backdrop-filter: blur(7px);
        animation: pg-fin .28s ease;
      }
      @keyframes pg-fin { from{opacity:0} to{opacity:1} }
      .pg-wb {
        background: #0e0000; border: 1px solid rgba(239,68,68,.28);
        border-radius: 16px; padding: 32px 28px; max-width: 440px; width: 90%;
        text-align: center; box-shadow: 0 0 80px rgba(239,68,68,.15);
        font-family: system-ui,sans-serif; color: #fca5a5;
      }
      .pg-wi  { font-size:46px; line-height:1; margin-bottom:14px; display:block; }
      .pg-wt  { font-size:20px; font-weight:800; color:#ef4444; margin-bottom:10px; }
      .pg-wd  { font-size:13px; line-height:1.75; margin-bottom:24px; }
      .pg-wa  { display:flex; gap:10px; justify-content:center; flex-wrap:wrap; }
      .pg-bleave   { padding:10px 22px; border-radius:8px; background:#ef4444; color:#fff;
                     border:none; font-weight:700; font-size:13px; cursor:pointer; font-family:system-ui; }
      .pg-bleave:hover { background:#dc2626; }
      .pg-bproceed { padding:10px 22px; border-radius:8px; background:transparent; color:#6b7280;
                     border:1px solid #374151; font-weight:700; font-size:13px; cursor:pointer; font-family:system-ui; }
      .pg-bproceed:hover { color:#9ca3af; border-color:#4b5563; }
      .pg-breport  { padding:10px 22px; border-radius:8px; background:transparent; color:#3b82f6;
                     border:1px solid rgba(59,130,246,.3); font-weight:700; font-size:13px;
                     cursor:pointer; text-decoration:none; font-family:system-ui; display:inline-block; }
      .pg-breport:hover { background:#0c1829; }

      /* Link highlights — underline style, no blur on the element itself */
      .pg-hl-danger {
        border-bottom: 2px solid #ef4444 !important;
        text-decoration: none !important;
        color: #ef4444 !important;
        cursor: not-allowed !important;
        position: relative !important;
      }
      .pg-hl-warn {
        border-bottom: 2px solid #f59e0b !important;
        text-decoration: none !important;
        color: #f59e0b !important;
        position: relative !important;
      }
      /* Tooltip — sits above the link, never inherits blur */
      .pg-tip {
        position: fixed;
        background: #0e0000; color: #fca5a5;
        font-family: 'SF Mono',monospace; font-size: 10px; font-weight: 700;
        padding: 5px 11px; border-radius: 7px;
        border: 1px solid rgba(239,68,68,.4); white-space: nowrap;
        pointer-events: none; z-index: 2147483645;
        box-shadow: 0 4px 20px rgba(239,68,68,.3);
        animation: pg-tip-in .15s ease;
        transform: translateX(-50%);
      }
      @keyframes pg-tip-in { from{opacity:0;margin-top:4px} to{opacity:1;margin-top:0} }
    `;
    document.head.appendChild(s);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function getDomain(url) {
    try { return new URL(url).hostname.replace(/^www\./,""); } catch { return ""; }
  }

  function makeSvgRing(score, color) {
    const r = 20, circ = +(2*Math.PI*r).toFixed(1);
    const dash = score != null ? +((score/100)*circ).toFixed(1) : 0;
    return `<svg width="48" height="48" viewBox="0 0 48 48">
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="#1a2540" stroke-width="4"/>
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="${color}" stroke-width="4"
        stroke-dasharray="${dash} ${circ}" stroke-linecap="round" transform="rotate(-90 24 24)"/>
      <text x="24" y="29" text-anchor="middle" font-size="12"
        fill="${color}" font-family="SF Mono,monospace" font-weight="700">${score ?? "?"}</text>
    </svg>`;
  }

  // ── Badge ─────────────────────────────────────────────────────────────────
  function ensureBadge() {
    if (badgeEl) return badgeEl;
    badgeEl = document.createElement("div");
    badgeEl.id = BADGE_ID;
    badgeEl.addEventListener("click", togglePanel);
    document.body.appendChild(badgeEl);
    return badgeEl;
  }

  function showLoading() {
    const b = ensureBadge();
    b.className = "pg-loading"; b.id = BADGE_ID;
    b.classList.remove("pg-gone");
    b.innerHTML = `<span class="pg-spin">↻</span><span>PhishGuard…</span>`;
  }

  function renderBadge(result) {
    const b     = ensureBadge();
    const level = getLevel(result?.trust_score);
    b.className = `pg-${level}`; b.id = BADGE_ID;
    b.innerHTML = `<span>${META[level].icon}</span><span>PhishGuard · ${result?.trust_score ?? "?"}</span>`;
    if (level === "safe") setTimeout(() => b.classList.add("pg-gone"), 4000);
    else b.classList.remove("pg-gone");
  }

  // ── Panel ─────────────────────────────────────────────────────────────────
  function ensurePanel() {
    if (panelEl) return panelEl;
    panelEl = document.createElement("div");
    panelEl.id = PANEL_ID; panelEl.className = "pg-hidden";
    document.body.appendChild(panelEl);
    return panelEl;
  }

  function togglePanel() { ensurePanel().classList.toggle("pg-hidden"); }

  function renderPanel(result, diag) {
    const p      = ensurePanel();
    const level  = getLevel(result?.trust_score);
    const color  = META[level].color;
    const score  = result?.trust_score;
    const isPrem = diag?.user_id === "premium_user";

    const tc = result?.threat_type && result.threat_type !== "none"
      ? `<div class="pg-tc">${result.threat_type.replace(/_/g," ")}</div>` : "";

    const flaggedRow = diag?.worst_link
      ? `<div class="pg-flagged"><b>⚠</b> ${diag?.worst_link?.slice(0,55)}</div>` : "";

    const askBtn = isPrem
      ? `<button class="pg-ab" id="pg-ask">⚡ Ask AI — Force Analysis</button>` : "";

    p.innerHTML = `
      <div class="pg-ph">
        <span class="pg-pt">PhishGuard</span>
        <button class="pg-px" id="pg-close">✕</button>
      </div>
      <div class="pg-sr">
        ${makeSvgRing(score, color)}
        <div>
          <div class="pg-sn" style="color:${color}">${score ?? "?"}</div>
          <div class="pg-ss">${META[level].label}</div>${tc}
        </div>
      </div>
      <div class="pg-desc">${result?.description || "Analyzing…"}</div>
      ${flaggedRow}
      ${askBtn}
      <a class="pg-rl" href="${VERDICT_URL}" target="_blank" rel="noopener">View full report ↗</a>`;

    p.querySelector("#pg-close")?.addEventListener("click", togglePanel);
    p.querySelector("#pg-ask")?.addEventListener("click", handleAskAI);
  }

  // ── Overlay ───────────────────────────────────────────────────────────────
  function showOverlay(result) {
    if (Date.now() < overlaySnoozedUntil) return;
    // Re-show if score got worse since last time we showed it (e.g. LLM downgraded)
    const score = result?.trust_score ?? 100;
    if (overlayShownForScore !== null && score >= overlayShownForScore) return;
    overlayShownForScore = score;
    removeOverlay();

    const desc   = result?.description || "This page contains dangerous content.";
    const threat = result?.threat_type && result.threat_type !== "none"
      ? `<br><br><b>Threat type:</b> ${result.threat_type.replace(/_/g," ")}` : "";

    overlayEl = document.createElement("div");
    overlayEl.id = OVERLAY_ID;
    overlayEl.innerHTML = `
      <div class="pg-wb">
        <span class="pg-wi">🛡️</span>
        <div class="pg-wt">PhishGuard — Threat Detected</div>
        <div class="pg-wd">${desc}${threat}</div>
        <div class="pg-wa">
          <button class="pg-bleave" id="pg-leave">← Go Back</button>
          <a class="pg-breport" href="${VERDICT_URL}" target="_blank" rel="noopener">View Report ↗</a>
          <button class="pg-bproceed" id="pg-proceed">I understand the risk</button>
        </div>
      </div>`;
    document.body.appendChild(overlayEl);

    overlayEl.querySelector("#pg-leave")?.addEventListener("click", () => history.back());
    overlayEl.querySelector("#pg-proceed")?.addEventListener("click", () => {
      overlaySnoozedUntil  = Date.now() + 5 * 60_000;  // 5 min snooze
      overlayShownForScore = null;  // reset so a genuinely worse score can still show
      removeOverlay();
      highlightedEls.forEach(({ el }) => el.classList.remove("pg-hl-danger"));
    });
  }

  function removeOverlay() {
    overlayEl?.remove();
    overlayEl = null;
  }

  // ── Highlighting ──────────────────────────────────────────────────────────
  function clearHighlights() {
    highlightedEls.forEach(({ el, cls, listener, tip }) => {
      el.classList.remove(cls);
      if (listener) el.removeEventListener("click", listener, true);
      tip?.remove();
    });
    highlightedEls = [];
  }

  // Tooltip using fixed position to avoid inheriting any parent filter/blur
  function showTip(a) {
    const tip = document.createElement("div");
    tip.className = "pg-tip";
    tip.textContent = "⚠ PhishGuard — blocked";
    document.body.appendChild(tip);

    const place = () => {
      const r = a.getBoundingClientRect();
      tip.style.left = (r.left + r.width / 2) + "px";
      tip.style.top  = (r.top - tip.offsetHeight - 8) + "px";
    };

    a.addEventListener("mouseenter", place);
    a.addEventListener("mouseleave", () => tip.style.display = "none");
    a.addEventListener("mouseenter", () => tip.style.display = "block");
    tip.style.display = "none";
    return tip;
  }

  function highlightLinks(result) {
    clearHighlights();
    // Use the worst combined verdict for the page-level decision
    const display = worstResult();
    const level   = getLevel(display?.trust_score);
    if (level === "safe" || level === "unknown") return;

    // DB result is always fetched — it tells us which specific domains are confirmed bad.
    // Collect ALL domains the DB flagged as dangerous (score < 45).
    const badDomains = new Set();
    if (dbResult?.worst_link) {
      const w = dbResult.worst_link;
      const d = w.startsWith("mailto:") ? w.replace("mailto:","").split("@")[1] || "" : getDomain(w);
      if (d && dbResult.trust_score < 45) badDomains.add(d);
    }

    document.querySelectorAll("a[href]").forEach(a => {
      if (ownUI(a)) return;
      const href = a.href || "";
      if (!isActionableHref(href)) return;

      const isMailto   = href.startsWith("mailto:");
      const linkDomain = isMailto
        ? href.replace("mailto:","").split("@")[1] || ""
        : getDomain(href);

      if (badDomains.has(linkDomain)) {
        // DB confirmed this domain is bad → red + block
        a.classList.add("pg-hl-danger");
        const tip = showTip(a);
        const listener = e => {
          e.preventDefault(); e.stopImmediatePropagation();
          ensurePanel().classList.remove("pg-hidden");
        };
        a.addEventListener("click", listener, true);
        highlightedEls.push({ el: a, cls: "pg-hl-danger", listener, tip });
      } else if (level === "danger" || level === "warn") {
        // Page is flagged but this link isn't confirmed bad by DB → amber only
        a.classList.add("pg-hl-warn");
        highlightedEls.push({ el: a, cls: "pg-hl-warn" });
      }
    });
  }

  // ── Ask AI ────────────────────────────────────────────────────────────────
  function handleAskAI() {
    const btn = panelEl?.querySelector("#pg-ask");
    if (btn) { btn.disabled = true; btn.textContent = "⚡ Analyzing…"; }

    chrome.storage.local.get(["user_id"], res => {
      const userId  = res.user_id || "free_user";
      const payload = buildPayload(userId);
      chrome.runtime.sendMessage({ type: "ASK_AI", payload }, result => {
        if (result && !result.error) {
          lastResult = result;
          chrome.storage.local.set({ last_result: result });
          applyResult(result, userId);
        }
        const b2 = panelEl?.querySelector("#pg-ask");
        if (b2) { b2.disabled = false; b2.textContent = "⚡ Ask AI — Force Analysis"; }
      });
    });
  }

  // ── Apply result ──────────────────────────────────────────────────────────
  function worstResult() {
    if (!llmResult && !dbResult) return null;
    if (!llmResult) return dbResult;
    if (!dbResult)  return llmResult;

    const db  = dbResult.trust_score  ?? 100;
    const llm = llmResult.trust_score ?? 100;

    // Mirror server merge_scores: if either alarmed (<70) take min, if both calm take max.
    // This prevents DB's unknown-default-70 from dragging down safe sites the LLM scored high.
    const finalScore = (db < 70 || llm < 70) ? Math.min(db, llm) : Math.max(db, llm);
    const base = llm <= db ? llmResult : dbResult;
    return { ...base, trust_score: finalScore };
  }

  function applyResult(result, userId, showPopup = true) {
    // Store by source so we always have both verdicts available
    const source = result?.source || "db";
    if (source === "llm" || source === "llm-cached" || source === "llm-forced") {
      llmResult = result;
    } else {
      dbResult = result;
    }

    // Display the worst verdict out of both sources
    const display = worstResult();
    if (!display) return;
    lastResult = display;
    const level = getLevel(display.trust_score);

    const diag = { user_id: userId, worst_link: display.worst_link, source: display.source };
    renderBadge(display);
    renderPanel(display, diag);
    highlightLinks(display);

    if (level === "danger") {
      ensurePanel().classList.remove("pg-hidden");
      if (showPopup) showOverlay(display);
    } else if (level === "warn") {
      ensurePanel().classList.remove("pg-hidden");
    }

    chrome.storage.local.set({ last_result: display, last_diagnostics: diag });
  }

  // ── Scan ──────────────────────────────────────────────────────────────────
  function doScan(showPopup = true) {
    chrome.storage.local.get(["user_id"], res => {
      const userId  = res.user_id || "free_user";
      const payload = buildPayload(userId);

      // For free users: DB only (server decides).
      // For premium: server always calls LLM + DB and returns the merged worst score.
      // We also always fire a separate free/DB-only call so we have worst_link
      // for link highlighting regardless of what the premium response contains.
      if (userId === "premium_user") {
        // DB call for link data (worst_link, blocking)
        chrome.runtime.sendMessage({ type: "ANALYZE", payload: { ...payload, user_id: "free_user" } }, dbRes => {
          if (dbRes) applyResult(dbRes, userId, false);
        });
        // Premium call — server merges DB + LLM score and always calls Gemini
        chrome.runtime.sendMessage({ type: "ANALYZE", payload }, result => {
          if (result) applyResult(result, userId, showPopup);
        });
      } else {
        chrome.runtime.sendMessage({ type: "ANALYZE", payload }, result => {
          if (result) applyResult(result, userId, showPopup);
        });
      }
    });
  }

  // ── Messages ──────────────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === "LOADING") {
      showLoading(); clearHighlights(); removeOverlay();
    }
    if (msg.type === "RESULT") {
      chrome.storage.local.get(["user_id"], res => {
        applyResult(msg.payload, res.user_id || "free_user");
      });
    }
    if (msg.type === "FORCE_SCAN") {
      llmResult = null; dbResult = null;  // user explicitly rescanning — start fresh
      showLoading(); clearHighlights(); removeOverlay();
      clearTimeout(scanTimer);
      scanTimer = setTimeout(() => doScan(true), 200);
    }
  });

  // ── Init ──────────────────────────────────────────────────────────────────
  injectStyles();
  ensureBadge();
  ensurePanel();
  showLoading();
  // Clear any cached result from a previous tab so it never bleeds into this page
  chrome.storage.local.remove(["last_result", "last_diagnostics"]);
  scanTimer = setTimeout(() => doScan(true), SCAN_DELAY_MS);

  // MutationObserver — only fires when link set changes
  const mo = new MutationObserver(() => {
    clearTimeout(changeTimer);
    changeTimer = setTimeout(() => {
      const fp = linkFingerprint();
      if (fp === lastLinkSet) return;
      lastLinkSet = fp;
      doScan(true);   // new links appeared — always show popup if dangerous
    }, 800);
  });
  mo.observe(document.body, { childList: true, subtree: true });

  // 30s periodic rescan — silent (no overlay), just refreshes highlights + badge
  setInterval(() => doScan(false), 30_000);  // periodic: silent, server handles LLM

})();