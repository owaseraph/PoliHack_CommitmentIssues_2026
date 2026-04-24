import pytest
from detection.detectors.link_detector import LinkDetector
from detection.models import EmailData
from config import GOOGLE_SAFE_BROWSING_API_KEY

pytestmark = pytest.mark.skipif(
    not GOOGLE_SAFE_BROWSING_API_KEY or "your_api_key_here" in GOOGLE_SAFE_BROWSING_API_KEY,
    reason="Live Google Safe Browsing API key not configured"
)


def test_safe_browsing_detector_live():
    """Live integration test against the Google Safe Browsing API."""
    email = EmailData(
        id="safe_001",
        subject="Check this suspicious site",
        from_="security@service.com",
        to="user@example.com",
        date="2024-01-01",
        reply_to="security@service.com",
        body_text="This link is unsafe: http://testsafebrowsing.appspot.com/s/malware.html",
        body_html='<p>This link is unsafe: <a href="http://testsafebrowsing.appspot.com/s/malware.html">malware test</a></p>',
        links=["http://testsafebrowsing.appspot.com/s/malware.html"],
        attachments=[],
        headers={"authentication-results": "spf=pass dkim=pass dmarc=pass"},
    )

    detector = LinkDetector()
    signal = detector.analyze(email)

    assert signal.name == "link_analysis"
    assert 0.0 <= signal.score <= 1.0
    assert isinstance(signal.flags, list)
    assert all(flag.startswith("malicious_url:") for flag in signal.flags)
    assert signal.score in (0.0, 1.0)


if __name__ == "__main__":
    if not GOOGLE_SAFE_BROWSING_API_KEY or "your_api_key_here" in GOOGLE_SAFE_BROWSING_API_KEY:
        raise SystemExit("Set GOOGLE_SAFE_BROWSING_API_KEY in config.py before running this live test.")

    test_safe_browsing_detector_live()
    print("Live Safe Browsing integration test passed.")