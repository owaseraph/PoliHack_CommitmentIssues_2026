from flask import Flask, request, jsonify
from services.link_analyzer import analyze_links, unknown_link
from services.llm_service import analyze_text
from services.scoring import compute_trust_score, get_free_description
import time

app = Flask(__name__)

# Store the time of the last LLM call and the last LLM description for caching
last_llm_timestamp = 0
llm_cooldown = 5  # Time in seconds for LLM cooldown
last_llm_description = ""  # Cache the LLM description
last_llm_trust_score = 100  # Default trust score if LLM is triggered

@app.route("/analyze", methods=["POST"])
def analyze():
    global last_llm_timestamp, last_llm_description, last_llm_trust_score

    data = request.json
    user_id = data.get("user_id")
    text = data.get("data", "")
    links = data.get("links", [])

    # Analyze links first
    link_score, cleaned_links, worst_link = analyze_links(links)

    print(f"unknown_link: {unknown_link}")  # Debugging print

    # 🔥 FREE TIER (SMART LOGIC)
    if user_id != "premium_user":
        trust_score = compute_trust_score(link_score)

        description = get_free_description(
            worst_link=worst_link,
            worst_score=link_score
        )

        response = {
            "trust_score": trust_score,
            "description": description,
            "verdict_url": "https://polihackcommitmentissues2026-production.up.railway.app/"
        }

        print("[FREE] score:", trust_score)
        print("[FREE] worst link:", worst_link)

        return jsonify(response)

    # 🔥 PREMIUM TIER (Optimized LLM Calls)
    # If links are detected and no unknown links, skip LLM analysis
    if cleaned_links and not unknown_link:
        print("[PREMIUM] Links detected, skipping LLM analysis.")
        trust_score = compute_trust_score(link_score)
        description = get_free_description(
            worst_link=worst_link,
            worst_score=link_score
        )

        response = {
            "trust_score": trust_score,
            "description": description,
            "verdict_url": "https://polihackcommitmentissues2026-production.up.railway.app/"
        }

        print("[PREMIUM] score:", trust_score)
        print("[PREMIUM] worst link:", worst_link)

        return jsonify(response)

    # 🔥 If the link score is unknown (defaults to 60) or no links, use LLM analysis
    if unknown_link or not cleaned_links:
        print("[PREMIUM] Unknown link detected or no links found, triggering LLM analysis.")

        # LLM cooldown logic
        current_time = time.time()
        if current_time - last_llm_timestamp >= llm_cooldown:
            print("[PREMIUM] Using LLM analysis.")
            llm_description, llm_trust_score = analyze_text(text)

            # Update the last LLM timestamp and store the description and trust score
            last_llm_timestamp = current_time
            last_llm_description = llm_description
            last_llm_trust_score = llm_trust_score

            response = {
                "trust_score": llm_trust_score,
                "description": llm_description,
                "verdict_url": "https://polihackcommitmentissues2026-production.up.railway.app/"
            }

            print("[PREMIUM] LLM score:", llm_trust_score)
            print("[PREMIUM] LLM description:", llm_description)
        else:
            # If LLM is not needed, use cached description
            print("[PREMIUM] LLM not needed, using cached description.")
            response = {
                "trust_score": last_llm_trust_score,
                "description": last_llm_description or get_free_description(
                    worst_link=worst_link,
                    worst_score=link_score
                ),
                "verdict_url": "https://polihackcommitmentissues2026-production.up.railway.app/"
            }

            print("[PREMIUM] Using cached LLM description:", last_llm_description)
            print("[PREMIUM] Cached LLM score:", last_llm_trust_score)

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)