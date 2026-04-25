# app/detection/detectors/llm_detector.py

import json
from google import genai
from google.genai import types
from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal
from config import GEMINI_API_KEY

SYSTEM_PROMPT = """
You are a cybersecurity expert specializing in phishing email detection.

You will receive an email along with pre-computed signals from other detectors.
Use ALL available information — email content AND detector signals — to make your assessment.

Rules:
- Empty bodies on notification emails (GitHub, Google, etc.) are NORMAL
- Weight pre-computed signals heavily — they are from trusted rule-based systems
- Only flag actual phishing signals: urgency, credential requests, spoofed domains, manipulation
- If pre-computed signals show SPF/DKIM/DMARC failures, treat that as strong evidence

Return ONLY valid JSON:
{
  "score": <float 0.0-1.0>,
  "verdict": "phishing" | "suspicious" | "safe",
  "reasons": [<string>, ...]
}
""".strip()


class LLMDetector(BaseDetector):

    name = "llm_analysis"

    def __init__(self):
        self._client = None  # lazy — instantiated on first use to avoid import-time crash

    @property
    def client(self):
        if self._client is None:
            import os
            api_key = os.environ.get("GEMINI_API_KEY", GEMINI_API_KEY)
            if not api_key:
                raise ValueError("GEMINI_API_KEY is not set")
            self._client = genai.Client(api_key=api_key)
        return self._client

    def analyze(self, email: EmailData, pre_signals: list[DetectionSignal] | None = None) -> DetectionSignal:
        try:
            raw    = self._call_llm(email, pre_signals or [])
            result = json.loads(raw)

            score   = float(result.get("score", 0.0))
            verdict = result.get("verdict", "safe")
            reasons = result.get("reasons", [])

            flags = [f"llm_verdict:{verdict}"] + [f"llm:{r}" for r in reasons]

            return DetectionSignal(name=self.name, score=score, flags=flags)

        except Exception as e:
            self._client = None  # reset so next request retries with fresh key
            print(f"[LLMDetector] Error: {e}")
            return DetectionSignal(name=self.name, score=0.0)

    def _call_llm(self, email: EmailData, pre_signals: list[DetectionSignal]) -> str:

        # Summarise what other detectors already found
        signal_summary = ""
        if pre_signals:
            lines = []
            for s in pre_signals:
                if s.flags:
                    lines.append(f"- {s.name} (score={s.score:.2f}): {', '.join(s.flags)}")
            if lines:
                signal_summary = "Pre-computed detector signals:\n" + "\n".join(lines) + "\n\n"

        prompt = (
            f"{signal_summary}"
            f"Subject:  {email.subject}\n"
            f"From:     {email.from_}\n"
            f"Reply-To: {email.reply_to}\n"
            f"Links:    {email.links}\n\n"
            f"Body:\n{email.body_text[:2000]}"
        )

        response = self.client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                temperature=0.1,
            )
        )

        return response.text