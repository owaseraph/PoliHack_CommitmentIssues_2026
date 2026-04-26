from models.db import get_connection
from urllib.parse import urlparse


def normalize_url(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme.startswith("http"):
            return None
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return clean.rstrip("/")
    except Exception:
        return None


def normalize_email(email):
    if not email:
        return None
    email = email.strip().lower()
    if "@" not in email:
        return None
    return email


def check_link_reputation(url):
    """
    Returns (score, found).
    found=False → not in DB, caller should trigger LLM.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    if url.startswith("mailto:"):
        email = url[len("mailto:"):]
        cursor.execute("SELECT reputation FROM emails WHERE email = ?", (email,))
    else:
        cursor.execute("SELECT reputation FROM links WHERE url = ?", (url,))

    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0], True

    return 75, False


def analyze_links(links):
    """
    Returns (worst_score, cleaned_links, worst_link, all_known).

    all_known=True  → every link hit the DB → skip LLM
    all_known=False → at least one unknown  → trigger LLM
    """
    if not links:
        return 80, [], None, False

    cleaned = []
    for link in links:
        if link.startswith("mailto:"):
            norm = normalize_email(link[len("mailto:"):])
            if norm:
                cleaned.append("mailto:" + norm)
        else:
            norm = normalize_url(link)
            if norm:
                cleaned.append(norm)

    cleaned = list(set(cleaned))

    if not cleaned:
        return 70, [], None, False

    detailed    = []
    any_unknown = False

    for link in cleaned:
        score, found = check_link_reputation(link)
        if not found:
            any_unknown = True
            print(f"[ANALYZER] Unknown: {link}")
        detailed.append((link, score))

    worst_link, worst_score = min(detailed, key=lambda x: x[1])
    return worst_score, cleaned, worst_link, not any_unknown
