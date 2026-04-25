import random

FREE_DESCRIPTIONS = [
    "This content has a moderate trust level.",
    "Be cautious with this content.",
    "Some elements may not be reliable."
]

def compute_trust_score(link_score, text_bonus=0):
    return min(100, int(link_score))


def get_free_description(worst_link=None, worst_score=50):
    if not worst_link:
        return "This content has a moderate trust level."

    if worst_score < 30:
        return f"High-risk link detected: {worst_link}. This may be a phishing or malicious website."

    if worst_score < 60:
        return f"Suspicious link detected: {worst_link}. Exercise caution before interacting."

    return "Some elements may not be fully trusted."