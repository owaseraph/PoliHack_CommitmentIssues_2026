const isVerdictPage = window.location.href.includes("/verdict");

if (isVerdictPage) {
    console.log("[TrustExt] 🚫 Verdict page detected — disabling extension UI");

    // stop entire script early
    throw new Error("TrustExt disabled on verdict page");
}

let lastScanTime = 0;
const SCAN_INTERVAL = 5000; // 5 seconds

let lastResult = null;
let lastRenderTime = 0;

const SIGNIFICANT_CHANGE = 0.2;

/* -----------------------------
   PAGE DATA EXTRACTION
------------------------------*/
function getPageData() {
    const text = document.body.innerText || "";

    const links = Array.from(document.querySelectorAll("a"))
        .map(a => a.href)
        .filter(Boolean);

    return { text, links };
}

/* -----------------------------
   SEND DATA TO BACKEND
------------------------------*/
function sendData(reason = "manual") {
    chrome.storage.local.get(["user_id"], (res) => {
        const user_id = res.user_id || "free_user";

        const { text, links } = getPageData();

        const payload = {
            user_id,
            data: text,
            links
        };

        console.log("[TrustExt] 📤 Sending request:", {
            reason,
            user_id,
            text_length: text,
            links_count: links
        });

        chrome.runtime.sendMessage({
            type: "ANALYZE",
            payload
        });
    });
}

/* -----------------------------
   SCAN CONTROLLER (15s limit)
------------------------------*/
function tryScan(reason) {
    const now = Date.now();

    if (now - lastScanTime < SCAN_INTERVAL) {
        console.log("[TrustExt] ⏱ Scan blocked (cooldown):", reason);
        return;
    }

    lastScanTime = now;

    console.log("[TrustExt] 🚀 Scan allowed:", reason);
    sendData(reason);
}

/* -----------------------------
   POPUP RENDERER
------------------------------*/
function renderPopup(result) {
    console.log("[TrustExt] 🧩 Rendering popup:", result);

    const old = document.getElementById("trust-popup");
    if (old) old.remove();

    const isSafe = result.trust_score >= 0.5;

    const verdictUrl =
        result.verdict_url || "http://localhost:5000/verdict/free_user";

    const div = document.createElement("div");
    div.id = "trust-popup";

    /* -------------------------
       SAFE: small badge (NO SCORE)
    --------------------------*/
    if (isSafe) {
        div.style.position = "fixed";
        div.style.bottom = "20px";
        div.style.right = "20px";
        div.style.padding = "6px 10px";
        div.style.borderRadius = "20px";
        div.style.boxShadow = "0 2px 8px rgba(0,0,0,0.15)";
        div.style.fontFamily = "Arial, sans-serif";
        div.style.zIndex = 999999;
        div.style.background = "#e8f8f5";
        div.style.color = "#2ecc71";
        div.style.fontSize = "12px";
        div.style.fontWeight = "600";
        div.style.border = "1px solid rgba(46, 204, 113, 0.3)";

        div.innerHTML = `✔ Verified`;

    /* -------------------------
       UNSAFE: big warning (WITH SCORE)
    --------------------------*/
    } else {
        div.style.position = "fixed";
        div.style.bottom = "20px";
        div.style.right = "20px";
        div.style.width = "340px";
        div.style.padding = "16px";
        div.style.borderRadius = "12px";
        div.style.boxShadow = "0 8px 24px rgba(0,0,0,0.25)";
        div.style.fontFamily = "Arial, sans-serif";
        div.style.zIndex = 999999;
        div.style.background = "#fff";
        div.style.borderLeft = "6px solid #e74c3c";
        div.style.color = "#111";

        div.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong style="color:#e74c3c; font-size:15px;">
                    ⚠ Suspicious Page
                </strong>

                <span style="
                    font-size:12px;
                    font-weight:600;
                    color:#e74c3c;
                    background:rgba(231,76,60,0.1);
                    padding:2px 6px;
                    border-radius:6px;
                ">
                    ${result.trust_score}
                </span>
            </div>

            <p style="
                margin:10px 0;
                font-size:13px;
                color:#222;
                line-height:1.4;
            ">
                ${result.description || "No description available"}
            </p>

            <a href="${verdictUrl}" target="_blank"
               style="
                font-size:12px;
                color:#3498db;
                text-decoration:none;
                font-weight:500;
            ">
                See full verdict →
            </a>
        `;
    }

    document.body.appendChild(div);
}

/* -----------------------------
   MESSAGE HANDLER (STABLE UI)
------------------------------*/
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "RESULT") return;

    const newResult = msg.payload;

    console.log("[TrustExt] 📥 Result received:", newResult);

    // first render
    if (!lastResult) {
        lastResult = newResult;
        lastRenderTime = Date.now();
        renderPopup(newResult);
        return;
    }

    const scoreDiff = Math.abs(newResult.trust_score - lastResult.trust_score);

    const stateChanged =
        (newResult.trust_score >= 0.5) !== (lastResult.trust_score >= 0.5);

    console.log("[TrustExt] 📊 Compare:", {
        scoreDiff,
        stateChanged
    });

    // ignore tiny fluctuations
    if (!stateChanged && scoreDiff < SIGNIFICANT_CHANGE) {
        console.log("[TrustExt] ⏱ Ignored minor update");
        return;
    }

    lastResult = newResult;
    lastRenderTime = Date.now();
    renderPopup(newResult);
});

/* -----------------------------
   INITIAL SCAN
------------------------------*/
console.log("[TrustExt] 🚀 Initial scan");
tryScan("initial");

/* -----------------------------
   SCROLL TRIGGER
------------------------------*/
window.addEventListener("scroll", () => {
    tryScan("scroll");
});

/* -----------------------------
   DOM CHANGES (NO SPAM)
------------------------------*/
const observer = new MutationObserver(() => {
    tryScan("dom change");
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});