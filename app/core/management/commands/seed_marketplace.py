"""
Management command: seed_marketplace

Populates the marketplace with a curated set of demo plugins so there is
something to browse even on a fresh database.  Idempotent — skips any plugin
whose name already exists, so it is safe to run on every deploy.
"""

from django.core.management.base import BaseCommand
from core.models import Plugin

SEED_AUTHOR_ID    = "system"
SEED_AUTHOR_EMAIL = "phishguard@system"

PLUGINS = [
    # ── Sender Blacklists ────────────────────────────────────────────────
    {
        "name":        "Common Phishing Domains",
        "description": "A curated list of domains frequently used in phishing campaigns impersonating banks, payment providers, and tech giants.",
        "plugin_type": Plugin.TYPE_BLACKLIST,
        "installs":    142,
        "upvotes":     38,
        "rules": """\
# Known phishing domains
paypa1.com
micros0ft.com
amazoon.com
apple-id-verify.net
netflix-billing-update.com
secure-bankofamerica.xyz
irs-refund-portal.net
google-accounts-alert.info
support-apple.com
icloud-unlock.net
""",
    },
    {
        "name":        "Crypto Scam Senders",
        "description": "Blocks emails from addresses associated with cryptocurrency giveaway and investment scams.",
        "plugin_type": Plugin.TYPE_BLACKLIST,
        "installs":    89,
        "upvotes":     21,
        "rules": """\
# Crypto scam senders
noreply@bitcoin-rewards.com
support@elon-crypto-giveaway.com
admin@btc-doubler.net
invest@crypto-profits-daily.xyz
airdrop@eth-giveaway.io
claim@binance-promo.net
""",
    },
    # ── Keyword Filters ──────────────────────────────────────────────────
    {
        "name":        "Urgency & Fear Tactics",
        "description": "Flags emails using classic urgency and fear manipulation language to pressure users into hasty action.",
        "plugin_type": Plugin.TYPE_KEYWORD,
        "installs":    203,
        "upvotes":     61,
        "rules": """\
# Urgency triggers
your account has been suspended
act immediately
verify your identity now
unusual sign-in activity
your password will expire
click here to avoid suspension
limited time offer
confirm within 24 hours
your account will be terminated
action required
""",
    },
    {
        "name":        "Financial Bait Keywords",
        "description": "Detects emails baiting users with fake prizes, refunds, and lottery wins.",
        "plugin_type": Plugin.TYPE_KEYWORD,
        "installs":    115,
        "upvotes":     29,
        "rules": """\
# Financial bait
you have won
claim your prize
unclaimed refund
congratulations you have been selected
wire transfer required
inheritance funds
send your bank details
lottery winner
free gift card
exclusive reward
""",
    },
    {
        "name":        "HR & Payroll Impersonation",
        "description": "Catches internal-impersonation phishing pretending to be HR or payroll departments.",
        "plugin_type": Plugin.TYPE_KEYWORD,
        "installs":    77,
        "upvotes":     19,
        "rules": """\
# HR / payroll impersonation
update your direct deposit
payroll verification required
w-2 form available
benefits enrollment deadline
new employee onboarding link
hr policy update required
salary adjustment notice
""",
    },
    # ── Regex Patterns ───────────────────────────────────────────────────
    {
        "name":        "Fake Invoice Detector",
        "description": "Regular expressions to catch fake invoice and billing scam emails.",
        "plugin_type": Plugin.TYPE_REGEX,
        "installs":    134,
        "upvotes":     44,
        "rules": """\
# Fake invoice patterns
invoice\\s*#?\\s*\\d{4,}
payment\\s+of\\s+\\$[\\d,]+\\.\\d{2}\\s+is\\s+(due|overdue|pending)
your\\s+(account|subscription)\\s+will\\s+be\\s+charged
unpaid\\s+(invoice|balance|amount)
\\bINV-\\d{4,}\\b
""",
    },
    {
        "name":        "Suspicious URL Patterns",
        "description": "Regex rules targeting URLs with IP addresses, unusual ports, or lookalike domains embedded in email bodies.",
        "plugin_type": Plugin.TYPE_REGEX,
        "installs":    98,
        "upvotes":     33,
        "rules": """\
# Suspicious URL patterns
https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}
https?://[^/]+:\\d{4,5}/
paypal\\.[a-z]{3,}\\.com
verify[-.]account\\.[a-z]{2,}
login[-.]secure[-.]\\w+\\.com
""",
    },
    # ── Trusted Domain Lists ─────────────────────────────────────────────
    {
        "name":        "Developer Tools & Services",
        "description": "Marks well-known developer services as always safe, reducing false positives on transactional emails from these platforms.",
        "plugin_type": Plugin.TYPE_DOMAIN_LIST,
        "installs":    187,
        "upvotes":     52,
        "rules": """\
# Developer services
github.com
gitlab.com
npmjs.com
pypi.org
stackoverflow.com
vercel.com
netlify.com
railway.app
cloudflare.com
fly.io
render.com
digitalocean.com
""",
    },
    {
        "name":        "Major Productivity Suites",
        "description": "Trusts emails from Google Workspace, Microsoft 365, Notion, Slack, and similar productivity platforms.",
        "plugin_type": Plugin.TYPE_DOMAIN_LIST,
        "installs":    221,
        "upvotes":     67,
        "rules": """\
# Productivity suites
google.com
microsoft.com
office365.com
outlook.com
slack.com
notion.so
linear.app
atlassian.com
jira.com
confluence.com
zoom.us
""",
    },
]


class Command(BaseCommand):
    help = "Seed the marketplace with demo plugins (idempotent)."

    def handle(self, *args, **options):
        created = 0
        skipped = 0
        for spec in PLUGINS:
            name = spec["name"]
            if Plugin.objects.filter(name=name).exists():
                skipped += 1
                continue
            Plugin.objects.create(
                name=spec["name"],
                description=spec["description"],
                plugin_type=spec["plugin_type"],
                rules=spec["rules"].strip(),
                author_id=SEED_AUTHOR_ID,
                author_email=SEED_AUTHOR_EMAIL,
                is_published=True,
                installs=spec.get("installs", 0),
                upvotes=spec.get("upvotes", 0),
            )
            created += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"seed_marketplace: {created} plugin(s) created, {skipped} already existed."
            )
        )
