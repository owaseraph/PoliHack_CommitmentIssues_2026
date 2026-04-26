import re
import google.generativeai as genai
from config import Config

genai.configure(api_key=Config.GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

# Phrases that are strong scam/phishing signals worth extracting
SIGNAL_PHRASES = [
    r"verify.{0,20}account",
    r"confirm.{0,20}identity",
    r"suspended.{0,20}account",
    r"urgent.{0,20}action",
    r"click.{0,20}immediately",
    r"password.{0,20}expire",
    r"unusual.{0,20}activit",
    r"limited.{0,20}time",
    r"claim.{0,20}reward",
    r"you.{0,10}won",
    r"gift.{0,10}card",
    r"bitcoin|crypto.{0,20}payment",
    r"wire.{0,10}transfer",
    r"social security",
    r"irs.{0,20}refund",
    r"inheritance",
    r"nigerian prince",
    r"lottery.{0,20}winner",
]
_SIGNAL_RE = re.compile("|".join(SIGNAL_PHRASES), re.IGNORECASE)


def extract_signals(text, links):
    """
    Rather than sending the full page to Gemini, extract only what matters:
    - All links/emails
    - Suspicious phrase snippets (50 chars of context around each match)
    - Page title
    - First 300 chars (above-the-fold context)
    """
    signals = []

    # Suspicious phrase snippets
    for m in _SIGNAL_RE.finditer(text):
        start = max(0, m.start() - 40)
        end   = min(len(text), m.end() + 40)
        snippet = text[start:end].replace("\n", " ").strip()
        signals.append(f'"{snippet}"')

    # Deduplicate
    signals = list(dict.fromkeys(signals))[:12]

    page_title = ""
    try:
        # Can't import from Flask context, but text usually starts with title
        page_title = text[:120].split("\n")[0].strip()
    except Exception:
        pass

    context = {
        "page_intro": text[:300].replace("\n", " ").strip(),
        "suspicious_phrases": signals,
        "links_and_emails": links[:30],
    }
    return context


def analyze_text(text, links=None):
    """
    Analyze page content for phishing/scam signals.
    Returns (description, trust_score).
    trust_score: 0 = high risk, 100 = safe.
    """
    links = links or []
    ctx = extract_signals(text, links)

    prompt = f"""You are TrustGuard, a security analysis system that detects phishing, scams, and misleading web content.

Analyze the following extracted page signals and determine the threat level.

PAGE INTRO (first 300 chars):
{ctx['page_intro']}

SUSPICIOUS PHRASE MATCHES:
{chr(10).join(ctx['suspicious_phrases']) if ctx['suspicious_phrases'] else 'None detected'}

LINKS AND EMAILS ON PAGE:
{chr(10).join(ctx['links_and_emails']) if ctx['links_and_emails'] else 'None'}

TASK:
1. Determine if this page is: safe / suspicious / phishing / scam
2. Identify the PRIMARY threat (if any): phishing_link | credential_harvest | fake_reward | impersonation | malware | none
3. Write ONE clear sentence explaining what you found (be specific, mention actual URLs or phrases if suspicious)
4. Assign a trust score: 0 = confirmed threat, 100 = fully safe

Respond in EXACTLY this format, nothing else:
summary: [your one sentence finding]
threat_type: [phishing_link | credential_harvest | fake_reward | impersonation | malware | none]
trust_score: [0-100]
"""

    try:
        response = model.generate_content(prompt)
        cleaned  = response.text.strip()

        result = {}
        for line in cleaned.splitlines():
            ll = line.lower()
            if ll.startswith("summary:"):
                result["summary"] = line[len("summary:"):].strip()
            elif ll.startswith("threat_type:"):
                result["threat_type"] = line[len("threat_type:"):].strip()
            elif ll.startswith("trust_score:"):
                raw = line[len("trust_score:"):].strip()
                try:
                    result["trust_score"] = max(0, min(100, int(raw)))
                except ValueError:
                    result["trust_score"] = 50

        if "summary" in result and "trust_score" in result:
            print(f"[LLM] score={result['trust_score']} threat={result.get('threat_type','?')}")
            return result["summary"], result["trust_score"], result.get("threat_type", "none")

        print(f"[LLM] Unexpected format: {cleaned}")
        return cleaned[:200], 50, "none"

    except Exception as e:
        print(f"[LLM] Error: {e}")
        return "Unable to analyze content.", 50, "none"
