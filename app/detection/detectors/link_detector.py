# app/detection/detectors/link_detector.py

import re
import requests
from urllib.parse import urlparse
from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal
from config import GOOGLE_SAFE_BROWSING_API_KEY

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# TLDs heavily abused in phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".icu",
    ".buzz", ".gq", ".tk", ".ml", ".cf", ".ga"
}

# URL shorteners that hide real destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "cutt.ly", "rebrand.ly"
}


class LinkDetector(BaseDetector):

    name = "link_analysis"

    def analyze(self, email: EmailData) -> DetectionSignal:
        if not email.links:
            return DetectionSignal(name=self.name, score=0.0)

        flags  = []
        score  = 0.0

        # 1. Google Safe Browsing (known threats)
        malicious = self._check_safe_browsing(email.links)
        if malicious:
            flags += [f"malicious_url:{url}" for url in malicious]
            score = 1.0   # known malicious = immediate max score

        # 2. Heuristic analysis on ALL links (catches unknown threats)
        for url in email.links:
            url_flags, url_score = self._analyze_url(url)
            flags += url_flags
            score = max(score, url_score)

        return DetectionSignal(name=self.name, score=min(score, 1.0), flags=flags)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _analyze_url(self, url: str) -> tuple[list[str], float]:
        """
        Heuristic checks on a single URL.
        Returns (flags, score).
        """
        flags = []
        score = 0.0

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path   = parsed.path.lower()
        except Exception:
            return ["unparseable_url"], 0.3

        # IP address as host — no legitimate service uses raw IPs in emails
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            flags.append("ip_address_url")
            score = max(score, 0.8)

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(f"suspicious_tld:{tld}")
                score = max(score, 0.4)
                break

        # URL shortener — hides real destination
        apex = ".".join(domain.split(".")[-2:])
        if apex in URL_SHORTENERS:
            flags.append(f"url_shortener:{apex}")
            score = max(score, 0.35)

        # Excessive subdomains (e.g. login.secure.paypal.verify.evil.com)
        if domain.count(".") >= 4:
            flags.append("excessive_subdomains_in_url")
            score = max(score, 0.45)

        # Sensitive keywords in path (credential harvesting)
        sensitive_keywords = ["login", "signin", "verify", "secure",
                              "account", "update", "confirm", "banking",
                              "password", "credential", "authenticate"]
        found = [kw for kw in sensitive_keywords if kw in path]
        if found:
            flags.append(f"sensitive_path_keywords:{','.join(found)}")
            score = max(score, 0.3)

        # HTTP (not HTTPS) — no legitimate bank or service uses plain HTTP
        if url.startswith("http://"):
            flags.append("insecure_http")
            score = max(score, 0.25)

        # Misleading URL: brand name in path but not in domain
        # e.g. evil.com/paypal-login
        for brand in ["paypal", "amazon", "google", "microsoft",
                      "apple", "netflix", "facebook"]:
            if brand in path and brand not in domain:
                flags.append(f"brand_in_path_not_domain:{brand}")
                score = max(score, 0.55)
                break

        return flags, score

    def _check_safe_browsing(self, links: list[str]) -> list[str]:
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return []

        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "PHISHING"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": u} for u in links],
            },
        }

        try:
            resp = requests.post(
                SAFE_BROWSING_URL,
                params={"key": GOOGLE_SAFE_BROWSING_API_KEY},
                json=payload,
                timeout=5,
            )
            return [m["threat"]["url"] for m in resp.json().get("matches", [])]
        except Exception as e:
            print(f"[LinkDetector] Safe Browsing error: {e}")
            return []