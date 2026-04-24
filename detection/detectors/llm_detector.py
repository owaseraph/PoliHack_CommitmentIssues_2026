import json
from google import genai
from google.genai import types
from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal
from config import GEMINI_API_KEY

SYSTEM_PROMPT = """
You are a cybersecurity expert specializing in phishing email detection.
Analyze the email and return ONLY a valid JSON object — no markdown, no explanation.
Schema:
{
  "score": <float 0.0-1.0>,
  "verdict": "phishing" | "suspicious" | "safe",
  "reasons": [<string>, ...]
}
""".strip()

class LLMDetector(BaseDetector):
    """
    Uses Gemini to analyze email content for phishing signals:
    urgency, impersonation, suspicion requests, manipulative language, etc.
    """

    name="llm_analysis"

    def __init__(self):
        self.client = genai.Client(api_key=GEMINI_API_KEY)

    def analyze(self, email: EmailData) -> DetectionSignal:
        try:
            raw = self._call_llm(email)
            result = json.loads(raw)

            score = float(result.get("score", 0.0))
            verdict = result.get("verdict", "safe")
            reasons = result.get("reasons", [])

            flags = [f"llm:{r}" for r in reasons]
            flags.insert(0,f"llm_verdict:{verdict}")

            return DetectionSignal(name=self.name, score=score, flags=flags)
        except Exception as e:
            print(f"[LLM Detector] Error: {e}")
            return DetectionSignal(name=self.name, score=0.0)

    # Helpers
    def _call_llm(self, email:EmailData) -> str:
        prompt = (
            f"Subject: {email.subject}\n"
            f"From: {email.from_}\n"
            f"Reply-to: {email.reply_to}\n"
            f"Links: {email.links}\n\n"
            f"Body:\n {email.body_text[:2000]}"
        )
        # Low temperature for more deterministic/analytical results
        response = self.client.models.generate_content(
            model="gemini-2.5-flash", 
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                temperature=0.1, 
            )
        )

        return response.text