import re
from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal

class HeaderDetector(BaseDetector):
    """
    Detects spoofing signals in email headers:
        - Reply-To email mismatch
        - SPF / DKIM / DMARC failures
    """

    name = "header_analysis"

    def analyze(self, email: EmailData) -> DetectionSignal:
        flags = []
        headers = {k.lower(): v for k, v in email.headers.items()}

        if self._reply_to_mismatch(email.from_, email.reply_to):
            flags.append("reply_to_domain_mismatch")

        flags += self._check_auth_results(headers.get("authentication-results",""))

        #score is 0.3 per flag, capped at 1.0
        score = min(len(flags)*0.3,1.0)

        return DetectionSignal(name=self.name, score=score, flags=flags)
    
    # Helpers
    def _reply_to_mismatch(self, from_: str, reply_to:str) -> bool:
        if not reply_to:
            return False
        
        return self._domain(from_) != self._domain(reply_to)

    def _check_auth_results(self, auth_header:str) -> list[str]:
        flags = []
        lower = auth_header.lower()

        if "spf=fail" in lower: flags.append("spf_fail")
        if "dkim=fail" in lower: flags.append("dkim_fail")
        if "dmarc=fail" in lower: flags.append("dmarc_fail")

        return flags

    @staticmethod
    def _domain(address: str) -> str:
        match = re.search(r"@([\w.-]+)", address)
        return match.group(1).lower() if match else ""