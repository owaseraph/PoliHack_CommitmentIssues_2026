# app/detection/detectors/plugin_detector.py
"""
Runs all enabled plugins installed by a specific user.

Plugin types:
  blacklist   — flags email if sender matches any entry
  keyword     — flags email if body/subject contains any keyword
  regex       — flags email if body/subject matches any pattern
  domain_list — treats matched senders as trusted (reduces score)
"""
import re

from detection.base import BaseDetector
from detection.models import EmailData, DetectionSignal


class PluginDetector(BaseDetector):
    """
    Dynamically applies a single installed plugin to an email.
    One PluginDetector instance is created per enabled user plugin at scan time.
    """

    def __init__(self, plugin_id: int, plugin_name: str, plugin_type: str, rules: list[str]):
        self._plugin_id   = plugin_id
        self._plugin_name = plugin_name
        self._plugin_type = plugin_type
        self._rules       = rules

    @property
    def name(self) -> str:
        return f"plugin:{self._plugin_id}:{self._plugin_name}"

    def analyze(self, email: EmailData, pre_signals=None) -> DetectionSignal:
        ptype = self._plugin_type
        if ptype == "blacklist":
            return self._run_blacklist(email)
        elif ptype == "keyword":
            return self._run_keyword(email)
        elif ptype == "regex":
            return self._run_regex(email)
        elif ptype == "domain_list":
            return self._run_domain_list(email)
        return DetectionSignal(name=self.name, score=0.0)

    # ── Type implementations ──────────────────────────────────────────────────

    def _run_blacklist(self, email: EmailData) -> DetectionSignal:
        sender = email.from_.lower()
        for entry in self._rules:
            entry = entry.lower()
            if entry in sender:
                return DetectionSignal(
                    name=self.name,
                    score=0.95,
                    flags=[f"blacklisted_sender:{entry}"],
                )
        return DetectionSignal(name=self.name, score=0.0)

    def _run_keyword(self, email: EmailData) -> DetectionSignal:
        haystack = (email.subject + " " + email.body_text).lower()
        matched  = []
        for kw in self._rules:
            if kw.lower() in haystack:
                matched.append(kw)
        if matched:
            score = min(0.4 + 0.1 * len(matched), 0.85)
            return DetectionSignal(
                name=self.name,
                score=score,
                flags=[f"keyword_match:{kw}" for kw in matched],
            )
        return DetectionSignal(name=self.name, score=0.0)

    def _run_regex(self, email: EmailData) -> DetectionSignal:
        haystack = email.subject + "\n" + email.body_text
        matched  = []
        for pattern in self._rules:
            try:
                if re.search(pattern, haystack, re.IGNORECASE):
                    matched.append(pattern)
            except re.error:
                pass  # skip invalid regex
        if matched:
            score = min(0.5 + 0.1 * len(matched), 0.9)
            return DetectionSignal(
                name=self.name,
                score=score,
                flags=[f"regex_match:{p}" for p in matched],
            )
        return DetectionSignal(name=self.name, score=0.0)

    def _run_domain_list(self, email: EmailData) -> DetectionSignal:
        """Trusted domain list — lowers score if sender is in the list."""
        sender = email.from_.lower()
        for domain in self._rules:
            if domain.lower() in sender:
                return DetectionSignal(
                    name=self.name,
                    score=0.0,
                    flags=[f"plugin_trusted_domain:{domain}"],
                )
        return DetectionSignal(name=self.name, score=0.0)
