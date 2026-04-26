from django.core.management.base import BaseCommand
from core.models import Plugin

DUMMY_AUTHOR_ID    = "seed_bot_000"
DUMMY_AUTHOR_EMAIL = "community@phishguard.dev"


PLUGINS = [

    # ── Blacklists ────────────────────────────────────────────────────────────
    {
        "name":        "Known Phishing Senders",
        "description": "A curated blacklist of sender domains and addresses "
                       "repeatedly used in phishing campaigns targeting EU users. "
                       "Updated weekly by the PhishGuard community.",
        "plugin_type": "blacklist",
        "installs":    312,
        "upvotes":     87,
        "rules": """\
# High-confidence phishing sender domains — do not remove without evidence
noreply@secure-paypal-alert.com
support@account-verification-google.net
billing@netflix-suspend-notice.com
security@apple-id-locked.info
admin@microsofft-365-login.com
update@amazon-prime-renewal-alert.net
no-reply@dhl-parcel-notification.xyz
verify@steam-community-support.ru
alert@bankofamerica-secure-login.pw
team@linkedln-notification.com
# Typosquatting variants of common brands
noreply@paypa1.com
support@g00gle-account.com
help@amaz0n-orders.net
""",
    },
    {
        "name":        "Crypto Scam Senders",
        "description": "Blocks emails from domains and addresses associated with "
                       "cryptocurrency investment scams, fake exchange alerts, and "
                       "wallet-draining phishing attempts.",
        "plugin_type": "blacklist",
        "installs":    198,
        "upvotes":     54,
        "rules": """\
# Fake exchange / wallet alerts
security@binance-withdrawal-alert.net
noreply@coinbase-account-hold.info
alert@metamask-security-notice.xyz
support@crypto-wallet-verify.com
team@ethereum-airdrop-claim.net
admin@bitcoin-prize-winner.com
no-reply@trust-wallet-alert.org
verify@ledger-device-confirm.info
""",
    },

    # ── Keyword filters ───────────────────────────────────────────────────────
    {
        "name":        "Urgency & Scare Tactics",
        "description": "Flags emails using high-pressure language designed to "
                       "panic recipients into clicking links or revealing "
                       "credentials. Targets the most common social-engineering "
                       "patterns seen in phishing.",
        "plugin_type": "keyword",
        "installs":    445,
        "upvotes":     130,
        "rules": """\
# Urgency triggers
your account has been suspended
immediate action required
your account will be closed
verify your identity within 24 hours
unusual sign-in activity detected
we have detected suspicious activity
your password has been compromised
action needed: secure your account
final warning
limited time to respond
# Fear triggers
unauthorized access
your account is at risk
security breach detected
you have been selected for verification
confirm your information to avoid suspension
""",
    },
    {
        "name":        "Prize & Lottery Scams",
        "description": "Catches advance-fee fraud and prize scam emails that "
                       "promise winnings, inheritances, or grants in exchange "
                       "for upfront payments or personal details.",
        "plugin_type": "keyword",
        "installs":    271,
        "upvotes":     61,
        "rules": """\
you have been selected as a winner
claim your prize
you have won
lottery jackpot
unclaimed funds
inheritance transfer
bank transfer of funds
I am the son of a deceased
confidential business proposal
I need your assistance to transfer
percentage of the total sum
you are the beneficiary
western union transfer
advance fee
""",
    },
    {
        "name":        "Credential Harvesting Keywords",
        "description": "Detects language specifically designed to extract "
                       "usernames, passwords, credit card numbers, or "
                       "social security numbers from recipients.",
        "plugin_type": "keyword",
        "installs":    389,
        "upvotes":     102,
        "rules": """\
enter your password
confirm your credit card
provide your social security number
re-enter your banking details
update your payment method
your card ending in
billing information required
enter your pin
full card number
cvv security code
mother's maiden name
date of birth for verification
provide your national ID
""",
    },

    # ── Regex patterns ────────────────────────────────────────────────────────
    {
        "name":        "Suspicious URL Patterns",
        "description": "Regex rules that catch obfuscated, typosquatted, and "
                       "redirect-based phishing URLs embedded in email bodies. "
                       "Covers common tricks like IP addresses as hosts, "
                       "excessive subdomains, and misleading paths.",
        "plugin_type": "regex",
        "installs":    502,
        "upvotes":     148,
        "rules": """\
# IP address used directly as host (no domain name)
https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}
# Excessive subdomains (4+) — classic phishing redirect trick
https?://([a-z0-9-]+\\.){4,}[a-z]{2,}
# URL contains a legitimate brand name but the real domain is different
https?://[^/]*(paypal|google|apple|amazon|microsoft|netflix)[^/]*\\.[^/]{3,}/
# Base64-looking path segments — used to hide destination
https?://[^/]+/[A-Za-z0-9+/]{30,}={0,2}
# Shortened URL services commonly abused in phishing
https?://(bit\\.ly|tinyurl\\.com|t\\.co|ow\\.ly|goo\\.gl|cutt\\.ly)/
# Redirect parameters pointing elsewhere
https?://[^?]+\\?.*url=https?://
https?://[^?]+\\?.*redirect=https?://
""",
    },
    {
        "name":        "Fake Invoice & Payment Regex",
        "description": "Matches patterns found in fake invoice emails: "
                       "fabricated invoice numbers, payment amounts formatted "
                       "to look legitimate, and urgency phrases combined with "
                       "financial figures.",
        "plugin_type": "regex",
        "installs":    167,
        "upvotes":     43,
        "rules": """\
# Invoice number patterns (INV- or # followed by digits)
\\bINV-?\\d{4,8}\\b
# Currency amounts in suspicious context
\\$[\\d,]+\\.\\d{2}\\s*(is\\s+)?due
payment\\s+of\\s+\\$[\\d,]+
# Overdue / final notice language next to a number
(overdue|past due|final notice).{0,40}\\$[\\d,]+
# Wire transfer instructions
(wire|bank).{0,20}transfer.{0,40}account\\s+number
routing\\s+number\\s*:?\\s*\\d{9}
""",
    },

    # ── Trusted domain lists ──────────────────────────────────────────────────
    {
        "name":        "Major Tech & Cloud Providers",
        "description": "Whitelist of legitimate sending domains for the most "
                       "common tech companies. Reduces false positives for "
                       "emails from Google, Microsoft, Apple, Amazon, and "
                       "similar services.",
        "plugin_type": "domain_list",
        "installs":    634,
        "upvotes":     201,
        "rules": """\
# Google
google.com
accounts.google.com
gmail.com
googlemail.com
# Microsoft
microsoft.com
microsoftonline.com
office.com
outlook.com
live.com
hotmail.com
# Apple
apple.com
icloud.com
# Amazon / AWS
amazon.com
amazonaws.com
aws.amazon.com
# Meta
meta.com
facebook.com
instagram.com
# GitHub / Atlassian / developer tools
github.com
atlassian.com
slack.com
notion.so
""",
    },
    {
        "name":        "Romanian University & Gov Domains",
        "description": "Trusted domain list covering Romanian public universities, "
                       "government institutions, and research networks. Useful for "
                       "students and staff to avoid false positives on official "
                       "institutional emails.",
        "plugin_type": "domain_list",
        "installs":    88,
        "upvotes":     29,
        "rules": """\
# Universities
utcluj.ro
ubbcluj.ro
upt.ro
unibuc.ro
ase.ro
tuiasi.ro
umfcluj.ro
# Government & public institutions
gov.ro
mai.gov.ro
edu.ro
anaf.ro
# Research networks
ro.net
roedunet.ro
""",
    },
]


class Command(BaseCommand):
    help = "Seed the plugin marketplace with realistic dummy plugins."

    def add_arguments(self, parser):
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Delete all existing seed plugins before re-seeding.",
        )

    def handle(self, *args, **options):
        if options["clear"]:
            deleted, _ = Plugin.objects.filter(author_id=DUMMY_AUTHOR_ID).delete()
            self.stdout.write(self.style.WARNING(f"Cleared {deleted} existing seed plugins."))

        created = 0
        skipped = 0

        for data in PLUGINS:
            _, was_created = Plugin.objects.get_or_create(
                name=data["name"],
                author_id=DUMMY_AUTHOR_ID,
                defaults={
                    "description":  data["description"],
                    "plugin_type":  data["plugin_type"],
                    "rules":        data["rules"],
                    "author_email": DUMMY_AUTHOR_EMAIL,
                    "is_published": True,
                    "installs":     data["installs"],
                    "upvotes":      data["upvotes"],
                },
            )
            if was_created:
                created += 1
                self.stdout.write(f"  ✓ Created: {data['name']}")
            else:
                skipped += 1
                self.stdout.write(f"  – Skipped (already exists): {data['name']}")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone. {created} plugin(s) created, {skipped} skipped."
            )
        )