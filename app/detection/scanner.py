from detection.models import EmailData, DetectionSignal, ScanResult
from detection.base import BaseDetector
from detection.detectors.header_detector import HeaderDetector
from detection.detectors.link_detector import LinkDetector
from detection.detectors.llm_detector import LLMDetector
from detection.detectors.plugin_detector import PluginDetector
from config import PHISHING_SCORE_THRESHOLD
import re


# Registry of built-in detectors (always run for every user)
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
def scan(raw_email: dict, user_id: str | None = None) -> ScanResult:
    """
    Entry point for the detection pipeline.
    Accepts raw parser output and an optional user_id to load installed plugins.
    Returns a ScanResult.
    """

    email = EmailData.from_dict(raw_email)

    # Check trusted-domain list (built-in) — but only if no plugins override it
    user_plugins = _load_user_plugins(user_id) if user_id else []

    # If a plugin_domain_list trusts this sender, skip full scan
    if _is_trusted_sender(email) and not _plugin_overrides_trust(email, user_plugins):
        return ScanResult(
            email_id=email.id,
            subject=email.subject,
            from_=email.from_,
            final_score=0.0,
            is_phishing=False,
            signals=[DetectionSignal(name="trusted_sender", score=0.0, flags=["domain_whitelisted"])]
        )

    signals = _run_detectors(email, user_plugins)
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

def _load_user_plugins(user_id: str) -> list[PluginDetector]:
    """Load all enabled plugins installed by this user from the DB."""
    try:
        from core.models import UserPlugin
        installs = (
            UserPlugin.objects
            .filter(user_id=user_id, enabled=True)
            .select_related("plugin")
        )
        detectors = []
        for install in installs:
            p = install.plugin
            if p.is_published:
                detectors.append(PluginDetector(
                    plugin_id=p.pk,
                    plugin_name=p.name,
                    plugin_type=p.plugin_type,
                    rules=p.get_rules_list(),
                ))
        return detectors
    except Exception as e:
        print(f"[Scanner] Failed to load user plugins for {user_id}: {e}")
        return []


def _plugin_overrides_trust(email: EmailData, plugins: list[PluginDetector]) -> bool:
    """
    Returns True if any blacklist plugin flags this email,
    meaning we should NOT skip it even if domain is in built-in trusted list.
    """
    for plugin in plugins:
        if plugin._plugin_type == "blacklist":
            signal = plugin.analyze(email)
            if signal.score > 0:
                return True
    return False


def _run_detectors(email: EmailData, user_plugins: list[PluginDetector] | None = None) -> list[DetectionSignal]:
    signals = []
    all_detectors = list(DETECTORS) + (user_plugins or [])
    for detector in all_detectors:
        try:
            if detector.name == "llm_analysis":
                signals.append(detector.analyze(email, pre_signals=signals))
            else:
                signals.append(detector.analyze(email))
        except Exception as e:
            print(f"[Scanner] Detector '{detector.name}' failed: {e}")
    return signals


def _aggregate(signals: list[DetectionSignal]) -> float:
    """
    Weighted aggregation across all detectors.

    Instead of just taking max(), we combine:
    - A weighted average (each detector contributes proportionally)
    - A "panic" override: if ANY single detector is very confident (>= 0.9),
      that alone can push the score high
    - A "corroboration" bonus: if multiple detectors agree, score is boosted

    This means:
    - One detector mildly suspicious = low score (probably safe)
    - One detector very confident    = high score (override)
    - Multiple detectors agreeing    = boosted score (corroboration)
    """

    if not signals:
        return 0.0

    # Weights reflect how reliable each detector is
    WEIGHTS = {
        "header_analysis": 0.25,   # rule-based, fast, but limited signal
        "link_analysis":   0.40,   # very reliable when it fires — Safe Browsing is authoritative
        "llm_analysis":    0.35,   # powerful but can hallucinate
        "trusted_sender":  0.00,   # bypass signal — handled before aggregation
    }

    weighted_sum = 0.0
    total_weight = 0.0

    for signal in signals:
        # User plugin signals use a lower default weight (user-defined rules)
        if signal.name.startswith("plugin:"):
            weight = WEIGHTS.get(signal.name, 0.3)
        else:
            weight = WEIGHTS.get(signal.name, 0.2)
        weighted_sum += signal.score * weight
        total_weight += weight

    weighted_avg = weighted_sum / total_weight if total_weight > 0 else 0.0

    # Panic override: one very confident detector is enough
    max_score = max(s.score for s in signals)
    if max_score >= 0.6:
        # Blend: 70% from the confident detector, 30% from weighted avg
        final = 0.7 * max_score + 0.3 * weighted_avg
    else:
        final = weighted_avg

    # Corroboration bonus: multiple detectors firing together
    firing = sum(1 for s in signals if s.score >= 0.4)
    if firing >= 2:
        final = min(final * 1.15, 1.0)  # +15% boost, capped at 1.0

    return round(final, 4)


def _is_trusted_sender(email: EmailData) -> bool:
    # Extract domain from "Display Name <user@domain.com>" format
    match = re.search(r"@([\w.-]+)>?\s*$", email.from_)
    if not match:
        return False
    domain = match.group(1).lower()
    return domain in TRUSTED_DOMAINS