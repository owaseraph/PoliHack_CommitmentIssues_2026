const freeBtn = document.getElementById("free");
const premiumBtn = document.getElementById("premium");
const status = document.getElementById("status");

function setSelected(plan) {
    freeBtn.classList.remove("selected");
    premiumBtn.classList.remove("selected");

    if (plan === "free_user") {
        freeBtn.classList.add("selected");
        status.innerText = "Selected: Free Plan";
    }

    if (plan === "premium_user") {
        premiumBtn.classList.add("selected");
        status.innerText = "Selected: Premium Plan";
    }
}

// Load saved state
chrome.storage.local.get(["user_id"], (res) => {
    const user = res.user_id || null;

    if (user) setSelected(user);
});

// Free
freeBtn.onclick = () => {
    chrome.storage.local.set({ user_id: "free_user" }, () => {
        setSelected("free_user");
        console.log("[TrustExt] Plan set: FREE");
    });
};

// Premium
premiumBtn.onclick = () => {
    chrome.storage.local.set({ user_id: "premium_user" }, () => {
        setSelected("premium_user");
        console.log("[TrustExt] Plan set: PREMIUM");
    });
};