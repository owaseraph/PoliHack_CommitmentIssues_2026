import re
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

#Public API
def parser_raw_email(email_id:bytes, raw:bytes) -> dict:
        """
        Entry point. Takes raw RFC822 bytes, returns a clean structured dict ready to be passed to the detection pipeline.
        """

        msg = BytesParser(policy=policy.default).parsebytes(raw)

        body_text, body_html, attachments = _extract_parts(msg)

        return {
        "id":          email_id.decode(),
        "subject":     _clean(msg["subject"]),
        "from":        _clean(msg["from"]),
        "to":          _clean(msg["to"]),
        "date":        _clean(msg["date"]),
        "reply_to":    _clean(msg["reply-to"]),
        "body_text":   body_text,
        "body_html":   body_html,
        "links":       _extract_links(body_text, body_html),
        "attachments": attachments,
        "headers":     dict(msg.items()),
    }

#Helpers
def _clean(value) -> str:
        """Safely coerce any header value to a stripped string."""
        return str(value or "").strip()

def _extract_parts(msg) -> tuple[str,str,list[dict]]:
        """Walk the MIME tree and extract the body text, HTML and attachments."""
        body_text = ""
        body_html = ""
        attachments = []

        for part in msg.walk():
                content_type = part.get_content_type()
                disposition = part.get_content_disposition()

                if disposition == "attachment":
                        attachments.append(_parse_attachment(part))
                
                elif content_type == "text/plain" and not body_text:
                        body_text = part.get_content()
                
                elif content_type == "text/html" and not body_html:
                        body_html = part.get_content()
        
        return body_text,body_html,attachments

def _parse_attachment(part) -> dict:
        payload = part.get_payload(decode=True) or b""
        return{
                "filename": part.get_filename() or "unknown",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload)
        }

def _extract_links(text: str, html: str)->list[str]:
        """Extract all unique URLs from both plain text and HTML body."""
        links = set()

        if html:
                soup = BeautifulSoup(html, "html.parser")
                links.update(
                        a["href"]
                        for a in soup.find_all("a", href=True)
                        if a["href"].startswith("http")
                )
        
        if text:
                links.update(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text))
        return list(links)