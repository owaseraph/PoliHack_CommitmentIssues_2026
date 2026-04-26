from flask import Flask, request, jsonify
from services.link_analyzer import analyze_links
from services.llm_service import analyze_text
from services.scoring import get_description, compute_trust_score
from models.db import init_db
import time

app = Flask(__name__)

VERDICT_URL  = "https://polihackcommitmentissues2026-production-019d.up.railway.app"

# ── Global LLM cooldown (server-side safety net, 30 s) ───────────────────
_last_llm_time   = 0
_last_llm_desc   = ""
_last_llm_score  = 50
_last_llm_threat = "none"
LLM_COOLDOWN     = 30      # seconds — generous, client enforces too


def build_response(trust_score, description, threat_type="none",
                   source="db", worst_link=None):
    return {
        "trust_score" : trust_score,
        "description" : description,
        "threat_type" : threat_type,
        "verdict_url" : VERDICT_URL,
        "source"      : source,          # "db" | "llm" | "llm-cached"
        "worst_link"  : worst_link,      # for extension diagnostics
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
        return desc, score, threat, "llm"
    else:
        print("[LLM] Cooldown — returning cached result")
        return _last_llm_desc, _last_llm_score, _last_llm_threat, "llm-cached"


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

    # ── Free tier: DB only, never LLM ────────────────────────────────────
    if user_id != "premium_user":
        score = compute_trust_score(worst_score)
        desc  = get_description(worst_link, worst_score)
        print(f"[FREE] score={score}  worst={worst_link}")
        return jsonify(build_response(score, desc, source="db", worst_link=worst_link))

    # ── Premium: all links known in DB → return immediately ──────────────
    if cleaned_links and all_known:
        score = compute_trust_score(worst_score)
        desc  = get_description(worst_link, worst_score)
        print(f"[PREMIUM/DB] score={score}  worst={worst_link}")
        return jsonify(build_response(score, desc, source="db", worst_link=worst_link))

    # ── Premium: unknown link(s) or no links → LLM ───────────────────────
    print("[PREMIUM/LLM] Triggering Gemini…")
    desc, score, threat, source = run_llm(text, cleaned_links)
    print(f"[PREMIUM/LLM] score={score}  threat={threat}  source={source}")
    return jsonify(build_response(score, desc, threat, source=source, worst_link=worst_link))


@app.route("/ask", methods=["POST"])
def ask():
    """
    Premium-only forced LLM call (Ask AI button).
    Always bypasses cooldown — used sparingly by the client.
    """
    data    = request.json or {}
    user_id = data.get("user_id", "free_user")
    text    = data.get("data", "")
    links   = data.get("links", [])

    if user_id != "premium_user":
        return jsonify({"error": "premium only", "description": None, "trust_score": None}), 403

    print(f"\n[ASK_AI] Forced Gemini for user={user_id}  links={len(links)}")
    _, cleaned_links, worst_link, _ = analyze_links(links)
    desc, score, threat, _ = run_llm(text, cleaned_links, force=True)
    return jsonify(build_response(score, desc, threat, source="llm", worst_link=worst_link))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)