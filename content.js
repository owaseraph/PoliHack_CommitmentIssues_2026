/* -----------------------------
   VERDICT PAGE GUARD
------------------------------*/
const isVerdictPage = window.location.href.includes("/verdict");

if (isVerdictPage) {
    console.log("[TrustExt] 🚫 Verdict page detected — disabling extension UI");
    throw new Error("TrustExt disabled on verdict page");
}

/* -----------------------------
   STATE
------------------------------*/
let lastSignature = "";
let lastScanQueued = false;
let lastScanTime = 0;
const SCAN_COOLDOWN = 800; // prevents flood

/* -----------------------------
   GET RAW PAGE TEXT
------------------------------*/
function getPageText() {
    return document.body.innerText || "";
}

/* -----------------------------
   EXTRACT LINKS FROM TEXT (REGEX)
------------------------------*/
function extractLinks(text) {
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;

    const matches = text.match(urlRegex) || [];

    const cleaned = matches.map(url => {
        try {
            const u = new URL(url);
            return u.origin + u.pathname;
        } catch {
            return null;
        }
    }).filter(Boolean);

    return [...new Set(cleaned)];
}

/* -----------------------------
   PAGE DATA
------------------------------*/
function getPageData() {
    const text = getPageText();
    const links = extractLinks(text);

    return { text, links };
}

/* -----------------------------
   LOGGING (separate as requested)
------------------------------*/
function logUserId(user_id) {
    console.log("[TrustExt] 👤 USER ID:", user_id);
}

function logLinks(links) {
    console.log("[TrustExt] 🔗 LINKS:", links);
}

function logPayload(payload) {
    console.log("[TrustExt] 📦 FULL PAYLOAD:");
    console.log(JSON.stringify(payload, null, 2));
}

/* -----------------------------
   SEND DATA
------------------------------*/
function sendData(reason = "manual") {
    chrome.storage.local.get(["user_id"], (res) => {
        const user_id = res.user_id || "free_user";

        const { text, links } = getPageData();

        logUserId(user_id);
        logLinks(links);

        const payload = {
            user_id,
            data: text,
            links
        };

        logPayload(payload);

        chrome.runtime.sendMessage({
            type: "ANALYZE",
            payload
        });
    });
}

/* -----------------------------
   SAFE CHANGE DETECTION
------------------------------*/
function computeSignature(text, links) {
    // IMPORTANT: stable hash (order-independent)
    const sortedLinks = [...links].sort().join("|");
    return text.length + "|" + sortedLinks;
}

/* -----------------------------
   SCAN CONTROLLER (ANTI-SPAM)
------------------------------*/
function checkForChanges(reason) {
    const now = Date.now();

    if (now - lastScanTime < SCAN_COOLDOWN) return;

    const { text, links } = getPageData();
    const signature = computeSignature(text, links);

    if (signature === lastSignature) return;

    lastSignature = signature;
    lastScanTime = now;

    console.log("[TrustExt] 🔄 CHANGE DETECTED:", reason);

    sendData(reason);
}

/* -----------------------------
   MUTATION OBSERVER (IGNORES POPUP)
------------------------------*/
let mutationTimeout = null;

const observer = new MutationObserver((mutations) => {

    // 🚨 IGNORE ANYTHING INSIDE EXTENSION POPUP
    for (const m of mutations) {
        if (m.target.closest?.("#trust-popup")) return;
    }

    clearTimeout(mutationTimeout);

    mutationTimeout = setTimeout(() => {
        checkForChanges("dom change");
    }, 200);
});

observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
    attributes: true
});

/* -----------------------------
   POPUP UI (SAFE - NO FEEDBACK LOOP)
------------------------------*/
function renderPopup(result) {
    const old = document.getElementById("trust-popup");
    if (old) old.remove();

    const div = document.createElement("div");
    div.id = "trust-popup";

    const isSafe = result.trust_score >= 70;
    const verdictUrl =
        result.verdict_url || "http://localhost:5000/verdict/free_user";

    if (isSafe) {
        div.style.cssText = `
            position:fixed;
            bottom:20px;
            right:20px;
            padding:6px 10px;
            border-radius:20px;
            background:#e8f8f5;
            color:#2ecc71;
            font-family:Arial;
            font-size:12px;
            font-weight:600;
            z-index:999999;
            border:1px solid rgba(46,204,113,0.3);
        `;
        div.innerHTML = "✔ Verified";

    } else {
        div.style.cssText = `
            position:fixed;
            bottom:20px;
            right:20px;
            width:340px;
            padding:16px;
            background:white;
            border-left:6px solid #e74c3c;
            font-family:Arial;
            z-index:999999;
            box-shadow:0 8px 24px rgba(0,0,0,0.25);
        `;

        div.innerHTML = `
            <div style="display:flex;justify-content:space-between;">
                <strong style="color:#e74c3c;">⚠ Suspicious Page</strong>
                <span style="font-weight:bold;color:#e74c3c;">
                    ${result.trust_score}
                </span>
            </div>

            <p style="font-size:13px;margin:10px 0;">
                ${result.description || "No description available"}
            </p>

            <a href="${verdictUrl}" target="_blank"
               style="font-size:12px;color:#3498db;">
                See full verdict →
            </a>
        `;
    }

    document.body.appendChild(div);
}

/* -----------------------------
   RESULT HANDLER
------------------------------*/
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "RESULT") return;

    console.log("[TrustExt] 📥 RESULT RECEIVED:", msg.payload);

    renderPopup(msg.payload);
});

/* -----------------------------
   INITIAL SCAN
------------------------------*/
console.log("[TrustExt] 🚀 Initial scan");
checkForChanges("initial");