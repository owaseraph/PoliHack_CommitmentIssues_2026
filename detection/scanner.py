from detection.models import EmailData, DetectionSignal, ScanResult
from detection.base import BaseDetector
from detection.detectors.header_detector import HeaderDetector
from detection.detectors.link_detector import LinkDetector
from detection.detectors.llm_detector import LLMDetector
from config import PHISHING_SCORE_THRESHOLD

# Registry of detectors
DETECTORS: list[BaseDetector] = [
    HeaderDetector(),
    LinkDetector(),
    LLMDetector(),
]

TRUSTED_DOMAINS = {
    "github.com", "gitlab.com", "google.com", "microsoft.com",
    "apple.com", "amazon.com", "paypal.com", "linkedin.com",
    "stackoverflow.com", "atlassian.com", "slack.com", "notion.so"
}

# Public API
def scan(raw_email: dict) -> ScanResult:
    """
    Entry point for the detection pipeline.
    Accepts raw parser output, returns a ScanResult.
    """

    email = EmailData.from_dict(raw_email)
    if _is_trusted_sender(email):
        return ScanResult(
            email_id=email.id,
            subject=email.subject,
            from_=email.from_,
            final_score=0.0,
            is_phishing=False,
            signals=[DetectionSignal(name="trusted_sender", score=0.0, flags=["domain_whitelisted"])]
        )

    signals = _run_detectors(email)
    final_score = _aggregate(signals)

    return ScanResult(
        email_id = email.id,
        subject = email.subject,
        from_ = email.from_,
        final_score = final_score,
        is_phishing = final_score >= PHISHING_SCORE_THRESHOLD,
        signals = signals,
    )




# Helpers

def _run_detectors(email: EmailData) -> list[DetectionSignal]:
    signals = []
    for detector in DETECTORS:
        try:
            signals.append(detector.analyze(email))
        
        except Exception as e:
            print(f"[Scanner] Detector '{detector.name}' failed: {e}")
    
    return signals

def _aggregate(signals: list[DetectionSignal]) -> float:
    """
    Takes the worst scores across all detectors.
    """
    return max((s.score for s in signals), default=0.0)

def _is_trusted_sender(email: EmailData) -> bool:
    domain = email.from_.split("@")[-1].strip(">").lower()
    return domain in TRUSTED_DOMAINS