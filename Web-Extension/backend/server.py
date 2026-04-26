from flask import Flask, request, jsonify
import random

app = Flask(__name__)

# simple in-memory session store
sessions = {}

def get_user_plan(user_id):
    if user_id == "premium_user":
        return "premium"
    return "free"


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json or {}

    user_id = data.get("user_id", "free_user")
    text = data.get("data", "")
    links = data.get("links", [])

    plan = get_user_plan(user_id)

    print("\n[API] Incoming request")
    print("User:", user_id)
    print("Plan:", plan)
    print("Text length:", len(text))
    print("Links:", len(links))

    # different behavior per user
    if plan == "premium":
        trust_score = round(random.uniform(0.2, 1.0), 2)
        descriptions = [
            "Premium analysis: sources cross-verified.",
            "High confidence content with strong signals.",
            "Low risk detected across linked sources."
        ]
    else:
        trust_score = round(random.uniform(0.0, 0.75), 2)
        descriptions = [
            "Free analysis: limited verification.",
            "Some sources may be unreliable.",
            "Upgrade for deeper link analysis."
        ]

    response = {
        "trust_score": trust_score,
        "description": random.choice(descriptions),
        "verdict_url": f"http://localhost:5000/verdict/{user_id}"
    }

    print("[API] Response:", response)

    return jsonify(response)


# 🔥 USER-SPECIFIC VERDICT PAGE
@app.route("/verdict/<user_id>")
def verdict(user_id):

    plan = get_user_plan(user_id)

    if plan == "premium":
        return f"""
        <h1>🔵 Premium Verdict</h1>
        <p>User: {user_id}</p>
        <p>Detailed AI analysis enabled.</p>
        <ul>
            <li>Cross-source verification active</li>
            <li>Link reputation scoring enabled</li>
            <li>Deep content analysis enabled</li>
        </ul>
        """
    else:
        return f"""
        <h1>🟡 Free Verdict</h1>
        <p>User: {user_id}</p>
        <p>Basic analysis only.</p>
        <ul>
            <li>Limited source checking</li>
            <li>No deep link validation</li>
        </ul>
        <p>Upgrade to premium for full report.</p>
        """


# optional debug endpoint
@app.route("/session/<user_id>")
def session(user_id):
    return jsonify({
        "user_id": user_id,
        "plan": get_user_plan(user_id)
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)