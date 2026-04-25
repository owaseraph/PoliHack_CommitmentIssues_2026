from flask import Flask, request, jsonify
from services.link_analyzer import analyze_links
from services.llm_service import analyze_text
from services.scoring import get_description, compute_trust_score
from models.db import init_db
import time

app = Flask(__name__)

VERDICT_URL = "https://polihackcommitmentissues2026-production.up.railway.app/"

_last_llm_time   = 0
_last_llm_desc   = ""
_last_llm_score  = 50
_last_llm_threat = "none"
LLM_COOLDOWN     = 5


def build_response(trust_score, description, threat_type="none"):
    return {
        "trust_score": trust_score,
        "description": description,
        "threat_type": threat_type,
        "verdict_url": VERDICT_URL,
    }


def run_llm(text, links, force=False):
    global _last_llm_time, _last_llm_desc, _last_llm_score, _last_llm_threat
    now = time.time()
    if force or now - _last_llm_time >= LLM_COOLDOWN:
        print("[LLM] Calling Gemini…")
        desc, score, threat = analyze_text(text, links)
        _last_llm_time   = now
        _last_llm_desc   = desc
        _last_llm_score  = score
        _last_llm_threat = threat
    else:
        print("[LLM] Cooldown — returning cached")
        desc, score, threat = _last_llm_desc, _last_llm_score, _last_llm_threat
    return desc, score, threat


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data    = request.json or {}
    user_id = data.get("user_id", "free_user")
    text    = data.get("data", "")
    links   = data.get("links", [])

    print(f"\n[REQUEST] user={user_id}  links={len(links)}")
    worst_score, cleaned_links, worst_link, all_known = analyze_links(links)

    # Free tier — DB only, no LLM ever
    if user_id != "premium_user":
        score = compute_trust_score(worst_score)
        desc  = get_description(worst_link, worst_score)
        print(f"[FREE] score={score}  worst={worst_link}")
        return jsonify(build_response(score, desc))

    # Premium: all links in DB → return DB score immediately
    if cleaned_links and all_known:
        score = compute_trust_score(worst_score)
        desc  = get_description(worst_link, worst_score)
        print(f"[PREMIUM/DB] score={score}  worst={worst_link}")
        return jsonify(build_response(score, desc))

    # Premium: at least one unknown link, or no links at all → LLM
    print("[PREMIUM/LLM] Triggering Gemini…")
    desc, score, threat = run_llm(text, cleaned_links)
    print(f"[PREMIUM/LLM] score={score}  threat={threat}")
    return jsonify(build_response(score, desc, threat))


@app.route("/ask", methods=["POST"])
def ask():
    """
    Premium-only. Called when user clicks 'Ask AI' in the extension panel.
    Always forces a fresh LLM call — bypasses cooldown and DB cache.
    """
    data    = request.json or {}
    user_id = data.get("user_id", "free_user")
    text    = data.get("data", "")
    links   = data.get("links", [])

    if user_id != "premium_user":
        return jsonify({"error": "premium only", "description": None, "trust_score": None}), 403

    print(f"\n[ASK_AI] Forced Gemini for user={user_id}  links={len(links)}")
    _, cleaned_links, _, _ = analyze_links(links)
    desc, score, threat = run_llm(text, cleaned_links, force=True)
    return jsonify(build_response(score, desc, threat))


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
    app.run(debug=True)