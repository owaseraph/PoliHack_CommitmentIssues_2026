import os
import pytest
from detection.detectors.llm_detector import LLMDetector
from detection.models import EmailData
from config import GEMINI_API_KEY

pytestmark = pytest.mark.skipif(
    not GEMINI_API_KEY or "your_api_key_here" in GEMINI_API_KEY,
    reason="Live Gemini API key not configured"
)


def test_llm_detector_live():
    """Live integration test against the Gemini API."""
    email = EmailData(
        id="live_001",
        subject="Important account notice",
        from_="security@service.com",
        to="user@example.com",
        date="2024-01-01",
        reply_to="security@service.com",
        body_text="Your account has unusual activity. Please verify your login at https://service.com/verify.",
        body_html="<p>Your account has unusual activity. Please verify your login <a href=\"https://service.com/verify\">here</a>.</p>",
        links=["https://service.com/verify"],
        attachments=[],
        headers={"authentication-results": "spf=pass dkim=pass dmarc=pass"},
    )

    detector = LLMDetector()
    signal = detector.analyze(email)

    assert signal.name == "llm_analysis"
    assert 0.0 <= signal.score <= 1.0
    assert signal.flags, "LLM detector should return at least one flag"
    assert signal.flags[0].startswith("llm_verdict:"), "First flag should be the LLM verdict"
    assert any(flag.startswith("llm:") for flag in signal.flags[1:])


if __name__ == "__main__":
    if not GEMINI_API_KEY or "your_api_key_here" in GEMINI_API_KEY:
        raise SystemExit("Set GEMINI_API_KEY in config.py before running this live test.")

    test_llm_detector_live()
    print("Live Gemini integration test passed.")