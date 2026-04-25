chrome.runtime.onMessage.addListener((msg, sender) => {
    if (msg.type === "ANALYZE") {

        console.log("[TrustExt BG] 📤 Request received");

        fetch("http://localhost:5000/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(msg.payload)
        })
        .then(res => res.json())
        .then(data => {

            console.log("[TrustExt BG] 📥 Response:", data);

            // 🧠 forward full response including verdict_url
            chrome.tabs.sendMessage(sender.tab.id, {
                type: "RESULT",
                payload: data
            });
        })
        .catch(err => {
            console.error("[TrustExt BG] ❌ API error:", err);
        });
    }
});