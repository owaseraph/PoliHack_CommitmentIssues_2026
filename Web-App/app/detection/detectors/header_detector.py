# app/detection/detectors/header_detector.py

import re
from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal

# Well-known brands that attackers commonly impersonate
IMPERSONATION_TARGETS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "twitter": "twitter.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
}


class HeaderDetector(BaseDetector):

    name = "header_analysis"

    def analyze(self, email: EmailData) -> DetectionSignal:
        flags = []
        headers = {k.lower(): v for k, v in email.headers.items()}

        # 1. Reply-To domain mismatch
        if self._reply_to_mismatch(email.from_, email.reply_to):
            flags.append("reply_to_domain_mismatch")

        # 2. SPF / DKIM / DMARC failures
        flags += self._check_auth_results(headers.get("authentication-results", ""))

        # 3. Lookalike / homoglyph domain detection (NEW)
        lookalike = self._check_lookalike_domain(email.from_, email.subject)
        if lookalike:
            flags.append(f"lookalike_domain:{lookalike}")

        # 4. Display name spoofing (NEW)
        # e.g. "PayPal Security <attacker@evil.com>"
        if self._display_name_spoofing(email.from_):
            flags.append("display_name_spoofing")

        # 5. Suspicious sender patterns (NEW)
        flags += self._check_sender_patterns(email.from_)

        # Weighted scoring — not all flags are equal
        FLAG_WEIGHTS = {
            "reply_to_domain_mismatch": 0.3,
            "spf_fail":                 0.25,
            "dkim_fail":                0.25,
            "dmarc_fail":               0.3,
            "display_name_spoofing":    0.5,  # very strong signal
        }

        score = 0.0
        for flag in flags:
            if flag.startswith("lookalike_domain:"):
                score += 0.6   # lookalike is a very strong signal
            else:
                score += FLAG_WEIGHTS.get(flag, 0.2)

        return DetectionSignal(
            name=self.name,
            score=min(score, 1.0),
            flags=flags
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _reply_to_mismatch(self, from_: str, reply_to: str) -> bool:
        if not reply_to:
            return False
        return self._domain(from_) != self._domain(reply_to)

    def _check_auth_results(self, auth_header: str) -> list[str]:
        flags = []
        lower = auth_header.lower()
        if "spf=fail"   in lower: flags.append("spf_fail")
        if "dkim=fail"  in lower: flags.append("dkim_fail")
        if "dmarc=fail" in lower: flags.append("dmarc_fail")
        return flags

    def _check_lookalike_domain(self, from_: str, subject: str) -> str | None:
        """
        Detects domains that look like known brands but aren't.
        Checks:
        - Digit substitution: paypa1.com, amaz0n.com
        - Hyphen insertion:   pay-pal.com, micro-soft.com
        - Extra subdomain:    paypal.support.com, secure.paypal.phish.com
        - Brand in subdomain: paypal.evil.com
        """
        sender_domain = self._domain(from_)
        if not sender_domain:
            return None

        for brand, legit_domain in IMPERSONATION_TARGETS.items():
            # Skip if it IS the legitimate domain
            if sender_domain == legit_domain:
                continue

            # Digit substitution: replace 0→o, 1→l/i, 3→e, etc.
            normalized = (sender_domain
                .replace("0", "o").replace("1", "l")
                .replace("3", "e").replace("4", "a")
                .replace("5", "s").replace("@", "a"))

            if brand in normalized:
                return legit_domain

            # Hyphen: pay-pal.com → paypal
            dehyphenated = sender_domain.replace("-", "")
            if brand in dehyphenated and sender_domain != legit_domain:
                return legit_domain

            # Brand appears in subject but sender domain doesn't match
            # e.g. subject says "PayPal" but sent from random-mailer.com
            if brand in subject.lower() and brand not in sender_domain:
                return legit_domain

        return None

    def _display_name_spoofing(self, from_: str) -> bool:
        """
        Detects "PayPal <attacker@evil.com>" style spoofing.
        Extracts the display name and checks if it matches a known brand
        while the actual sending domain does not.
        """
        # Extract display name: "PayPal Security <user@evil.com>" → "PayPal Security"
        name_match = re.match(r'^"?([^<"]+)"?\s*<', from_)
        if not name_match:
            return False

        display_name = name_match.group(1).lower().strip()
        sender_domain = self._domain(from_)

        for brand, legit_domain in IMPERSONATION_TARGETS.items():
            if brand in display_name and sender_domain != legit_domain:
                return True

        return False

    def _check_sender_patterns(self, from_: str) -> list[str]:
        """Flags structurally suspicious sender patterns."""
        flags = []
        domain = self._domain(from_)

        if not domain:
            return flags

        # Excessive subdomains: a.b.c.d.evil.com
        if domain.count(".") >= 4:
            flags.append("excessive_subdomains")

        # Random-looking domain: 8+ char alphanumeric with no vowels
        apex = domain.split(".")[-2] if "." in domain else domain
        if len(apex) >= 8 and not re.search(r"[aeiou]", apex):
            flags.append("random_looking_domain")

        return flags

    @staticmethod
    def _domain(address: str) -> str:
        match = re.search(r"@([\w.-]+)>?\s*$", address)
        return match.group(1).lower() if match else ""