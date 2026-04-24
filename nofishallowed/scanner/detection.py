import re
from .models import PhishingKeyword, FlaggedSender, CommunityFlag


def _extract_domain(email: str) -> str:
    if '@' in email:
        return email.split('@')[-1].lower().strip()
    return ''


def _build_sender_blocklist():
    """
    Combine FlaggedSender (admin-verified) and approved CommunityFlag rows
    into a single list of (type, value) tuples for sender checking.
    """
    entries = []
    for fs in FlaggedSender.objects.filter(is_active=True):
        entries.append((fs.type, fs.value.lower()))
    for cf in CommunityFlag.objects.filter(status='approved'):
        entries.append((cf.type, cf.value.lower()))
    return entries


def analyse_email(subject: str, body: str, sender: str = '') -> dict:
    text = f'{subject} {body}'.lower()

    # Layer 1: keyword matching
    keywords = list(
        PhishingKeyword.objects.filter(is_active=True).values_list('keyword', flat=True)
    )
    matched_keywords = [kw for kw in keywords if re.search(re.escape(kw.lower()), text)]

    # Layer 2: sender / domain blocklist (admin + community)
    flagged_sender = False
    if sender:
        sender_lower = sender.lower().strip()
        domain = _extract_domain(sender_lower)
        for entry_type, entry_value in _build_sender_blocklist():
            if entry_type == 'email' and entry_value == sender_lower:
                flagged_sender = True
                break
            if entry_type == 'domain' and domain and entry_value == domain:
                flagged_sender = True
                break

    is_phishing = bool(matched_keywords) or flagged_sender

    return {
        'risk': 'phishing' if is_phishing else 'safe',
        'matched_keywords': matched_keywords,
        'flagged_sender': flagged_sender,
    }