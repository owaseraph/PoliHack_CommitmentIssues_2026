"""
Basic testing setup for the phishing detection system.
Run with: python -m pytest tests/ -v
"""

import pytest
from detection.models import EmailData, DetectionSignal
from detection.scanner import scan
from mail.parser import parser_raw_email

# Sample test emails
def test_parser_basic():
    """Test basic email parsing functionality."""
    raw_email = b"""From: sender@example.com
To: recipient@example.com
Subject: Test Email

This is a test email body."""

    result = parser_raw_email(b"test_id", raw_email)

    assert result["id"] == "test_id"
    assert result["subject"] == "Test Email"
    assert result["from"] == "sender@example.com"
    assert result["body_text"] == "This is a test email body."
    assert isinstance(result["links"], list)
    assert isinstance(result["attachments"], list)

def test_scanner_with_safe_email():
    """Test scanner with a clearly safe email."""
    email_data = {
        "id": "safe_001",
        "subject": "Meeting Reminder",
        "from": "boss@company.com",
        "to": "employee@company.com",
        "date": "2024-01-01",
        "reply_to": "boss@company.com",
        "body_text": "Don't forget our meeting tomorrow at 10 AM.",
        "body_html": "<p>Don't forget our meeting tomorrow at 10 AM.</p>",
        "links": [],
        "attachments": [],
        "headers": {"authentication-results": "spf=pass dkim=pass dmarc=pass"}
    }

    result = scan(email_data)

    assert result.email_id == "safe_001"
    assert result.final_score < 0.5  # Should be safe
    assert not result.is_phishing
    assert len(result.signals) >= 2  # At least header and link detectors should run

def test_scanner_with_suspicious_email():
    """Test scanner with a suspicious email."""
    email_data = {
        "id": "phish_001",
        "subject": "URGENT: Account Suspension Notice",
        "from": "support@bank.com",
        "to": "victim@example.com",
        "date": "2024-01-01",
        "reply_to": "evil@badguy.com",  # Mismatched reply-to
        "body_text": "Your account will be suspended! Click here: http://fake-bank.com/login",
        "body_html": '<p>Your account will be suspended! <a href="http://fake-bank.com/login">Click here</a></p>',
        "links": ["http://fake-bank.com/login"],
        "attachments": [],
        "headers": {"authentication-results": "spf=fail dkim=fail dmarc=fail"}
    }

    result = scan(email_data)

    assert result.email_id == "phish_001"
    assert result.final_score > 0.5  # Should be flagged
    assert result.is_phishing
    assert len(result.signals) >= 2  # At least header and link detectors should run

if __name__ == "__main__":
    # Run basic tests manually
    test_parser_basic()
    test_scanner_with_safe_email()
    test_scanner_with_suspicious_email()
    print("All basic tests passed!")