from detection.detectors.llm_detector import LLMDetector
from detection.detectors.link_detector import LinkDetector
from detection.models import EmailData
from config import GEMINI_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY


def main():
    if not GEMINI_API_KEY or "your_api_key_here" in GEMINI_API_KEY:
        raise SystemExit("Set GEMINI_API_KEY in config.py before running this demo.")
    if not GOOGLE_SAFE_BROWSING_API_KEY or "your_api_key_here" in GOOGLE_SAFE_BROWSING_API_KEY:
        raise SystemExit("Set GOOGLE_SAFE_BROWSING_API_KEY in config.py before running this demo.")

    email = EmailData(
        id="demo_001",
        subject="Security alert: verify your account",
        from_="security@service.com",
        to="user@example.com",
        date="2024-01-01",
        reply_to="security@service.com",
        body_text="Your account may be compromised. Please verify your identity here: http://testsafebrowsing.appspot.com/s/malware.html",
        body_html='<p>Your account may be compromised. Please verify your identity <a href="http://testsafebrowsing.appspot.com/s/malware.html">here</a>.</p>',
        links=["http://testsafebrowsing.appspot.com/s/malware.html"],
        attachments=[],
        headers={"authentication-results": "spf=pass dkim=pass dmarc=pass"},
    )

    print("=== Running Gemini LLM Detector ===")
    llm_detector = LLMDetector()
    llm_signal = llm_detector.analyze(email)
    print("LLM Signal:", llm_signal)
    print("LLM Flags:", llm_signal.flags)
    print("LLM score:", llm_signal.score)
    print()

    print("=== Running Google Safe Browsing Detector ===")
    link_detector = LinkDetector()
    link_signal = link_detector.analyze(email)
    print("Safe Browsing Signal:", link_signal)
    print("Safe Browsing Flags:", link_signal.flags)
    print("Safe Browsing score:", link_signal.score)


if __name__ == "__main__":
    main()