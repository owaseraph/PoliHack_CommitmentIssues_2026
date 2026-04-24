import requests
from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal
from config import GOOGLE_SAFE_BROWSING_API_KEY

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

class LinkDetector(BaseDetector):
    """
    Checks all detected links against Google Safe Browsing API.
    """
    
    name = "link_analysis"

    def analyze(self, email: EmailData) -> DetectionSignal:
        if not email.links:
            return DetectionSignal(name=self.name, score=0.0)
        
        malicious = self._check_safe_browsing(email.links)

        flags = [f"malicious_url:{url}" for url in malicious]
        score = 1.0 if malicious else 0.0

        return DetectionSignal(name=self.name, score=score, flags=flags)
    
    # Helpers
    def _check_safe_browsing(self, links: list[str]) -> list[str]:
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return []
        
        payload = {
            "client":{"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo":{
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in links] 
            },
        }

        try:
            resp = requests.post(
                SAFE_BROWSING_URL,
                params={"key": GOOGLE_SAFE_BROWSING_API_KEY},
                json=payload,
                timeout=5,
            )
            matches = resp.json().get("matches",[])
            return [m["threat"]["url"] for m in matches]
        except Exception as e:
            print(f"[Link Detector] Safe Browsing error: {e}")
            return []