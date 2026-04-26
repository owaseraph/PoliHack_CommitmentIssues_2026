import os
import time
from flask import Flask, request, jsonify
from services.link_analyzer import analyze_links
from services.llm_service import analyze_text
from services.scoring import get_description, compute_trust_score
from models.db import init_db

app = Flask(__name__)

# ── LLM cooldown (server-side, 30 s) ─────────────────────────────────────
_last_llm_time   = 0
_last_llm_desc   = ""
_last_llm_score  = 50
_last_llm_threat = "none"
LLM_COOLDOWN     = 30


def build_response(trust_score, description, threat_type="none", source="db", worst_link=None):
    return {
        "trust_score": trust_score,
        "description": description,
        "threat_type": threat_type,
        "source":      source,
        "worst_link":  worst_link,
    }


def run_llm(text, links, force=False):
    global _last_llm_time, _last_llm_desc, _last_llm_score, _last_llm_threat
    now = time.time()
    if force or now - _last_llm_time >= LLM_COOLDOWN:
        print("[LLM] Calling Gemini…")
        desc, score, threat = analyze_text(text, links)
        _last_llm_time, _last_llm_desc, _last_llm_score, _last_llm_threat = now, desc, score, threat
        return desc, score, threat, "llm"
    print("[LLM] Cooldown — cached")
    return _last_llm_desc, _last_llm_score, _last_llm_threat, "llm-cached"



def merge_scores(db_score, llm_score, llm_desc, llm_threat, worst_link, worst_score):
    # If either source is alarmed (<70): take minimum — something is wrong.
    # If both are calm (>=70): take maximum — DB unknown default (70) should not
    # drag down a site the LLM correctly identifies as safe (e.g. proton.me).
    if db_score < 70 or llm_score < 70:
        final_score = min(db_score, llm_score)
    else:
        final_score = max(db_score, llm_score)

    # Description comes from whichever source is more alarmed
    if llm_score <= db_score:
        return final_score, llm_desc, llm_threat
    return final_score, get_description(worst_link, worst_score), "none"


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
    db_score = compute_trust_score(worst_score)

    # ── Free tier: DB only, never LLM ────────────────────────────────────
    if user_id != "premium_user":
        desc = get_description(worst_link, worst_score)
        print(f"[FREE] score={db_score}  worst={worst_link}")
        return jsonify(build_response(db_score, desc, source="db", worst_link=worst_link))

    # ── Premium: always call LLM for the page score ───────────────────────
    # DB gives us the link reputation (worst_link, db_score).
    # LLM scores the page content independently.
    # Final score = min(db_score, llm_score) so either can flag the page.
    print("[PREMIUM/LLM] Triggering Gemini…")
    llm_desc, llm_score, llm_threat, source = run_llm(text, cleaned_links)
    final_score, desc, threat = merge_scores(db_score, llm_score, llm_desc, llm_threat, worst_link, worst_score)

    print(f"[PREMIUM] db={db_score}  llm={llm_score}  final={final_score}  threat={threat}")
    return jsonify(build_response(final_score, desc, threat, source=source, worst_link=worst_link))


@app.route("/ask", methods=["POST"])
def ask():
    """Premium-only forced LLM call — always fresh, bypasses cooldown."""
    data    = request.json or {}
    user_id = data.get("user_id", "free_user")
    text    = data.get("data", "")
    links   = data.get("links", [])

    if user_id != "premium_user":
        return jsonify({"error": "premium only", "description": None, "trust_score": None}), 403

    print(f"\n[ASK_AI] Forced Gemini for user={user_id}  links={len(links)}")
    worst_score, cleaned_links, worst_link, _ = analyze_links(links)
    db_score = compute_trust_score(worst_score)

    llm_desc, llm_score, llm_threat, _ = run_llm(text, cleaned_links, force=True)
    final_score, desc, threat = merge_scores(db_score, llm_score, llm_desc, llm_threat, worst_link, worst_score)

    return jsonify(build_response(final_score, desc, threat, source="llm", worst_link=worst_link))


if __name__ == "__main__":
    print("init db")
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)