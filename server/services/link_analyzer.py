from models.db import get_connection
from urllib.parse import urlparse

unknown_link = False

def check_link_reputation(url):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT reputation FROM links WHERE url = ?", (url,))
    result = cursor.fetchone()
    conn.close()

    if result:
        unknown_link = False
        return result[0]

    # unknown links are slightly suspicious
  
    unknown_link = True
    print("BAAAAAAAAAAAAAAAAAAAAAAAAAA" + unknown_link)
    return 60


def normalize_url(url):
    try:
        parsed = urlparse(url)

        if not parsed.scheme.startswith("http"):
            return None

        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return clean.rstrip("/")

    except:
        return None

def normalize_email(email):
    if not email:
        return None

    email = email.strip().lower()

    if "@" not in email:
        return None

    return email
    
def analyze_links(links):
    """
    PURE FUNCTION:
    - no memory
    - no persistence
    - only current request matters
    """

    if not links:
        return 70, [], None

    cleaned = []

    for link in links:
        norm = normalize_url(link)
        if norm:
            cleaned.append(norm)

    cleaned = list(set(cleaned))

    if not cleaned:
        return 70, [], None

    detailed = []

    for link in cleaned:
        score = check_link_reputation(link)
        detailed.append((link, score))

    # worst link dominates CURRENT snapshot only
    worst_link, worst_score = min(detailed, key=lambda x: x[1])

    return worst_score, cleaned, worst_link