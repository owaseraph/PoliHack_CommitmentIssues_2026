def compute_trust_score(link_score):
    return max(0, min(100, int(link_score)))


def get_description(worst_link=None, worst_score=50, threat_type=None):
    """
    Generate a human-readable description based on the worst link score
    and optional threat type from LLM analysis.
    """
    if not worst_link:
        return "No links or emails detected on this page."

    is_email = worst_link.startswith("mailto:")
    display  = worst_link.replace("mailto:", "") if is_email else worst_link
    kind     = "email address" if is_email else "link"

    if worst_score < 20:
        return (
            f"Known malicious {kind} detected: {display}. "
            "This page is likely a phishing attempt or scam. Do not enter any credentials."
        )

    if worst_score < 40:
        return (
            f"High-risk {kind} detected: {display}. "
            "This domain has been flagged for suspicious activity. Proceed with extreme caution."
        )

    if worst_score < 60:
        return (
            f"Suspicious {kind} detected: {display}. "
            "This may not be the legitimate site it claims to be."
        )

    if worst_score < 75:
        return f"Some unverified content found. The {kind} {display} is not in our trusted database."

    return "All links and emails on this page appear trustworthy."


# Keep old name for compatibility
def get_free_description(worst_link=None, worst_score=50):
    return get_description(worst_link=worst_link, worst_score=worst_score)
