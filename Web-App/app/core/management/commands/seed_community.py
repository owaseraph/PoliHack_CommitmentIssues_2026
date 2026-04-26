from django.core.management.base import BaseCommand
from core.models import CommunityReport

REPORTS = [
    {
        "title":        "Fake DHL parcel notification stealing credentials",
        "sender_email": "noreply@dhl-parcel-notification.xyz",
        "description":  "Received an email claiming a parcel is on hold due to unpaid customs fees. "
                        "Links to a convincing DHL lookalike page that asks for full card details. "
                        "Sender domain registered 3 days ago. SPF and DKIM both fail.",
        "reported_by":  "alert@phishguard.dev",
        "upvotes":      34,
    },
    {
        "title":        "Netflix account suspension phishing wave",
        "sender_email": "billing@netflix-suspend-notice.com",
        "description":  "Mass campaign impersonating Netflix billing. Email says your subscription "
                        "was cancelled due to a failed payment and urges you to update card info "
                        "within 24 hours. The linked page captures card number, CVV and billing address. "
                        "Over a dozen reports of this in the past week.",
        "reported_by":  "security@phishguard.dev",
        "upvotes":      61,
    },
    {
        "title":        "Google Workspace admin takeover attempt",
        "sender_email": "admin@google-workspace-alert.net",
        "description":  "Targets small business Google Workspace admins. Claims unusual admin activity "
                        "was detected and asks you to verify your identity via a fake Google sign-in page. "
                        "The page harvests your Google credentials and 2FA backup codes. "
                        "Real sender IP traced to Eastern Europe.",
        "reported_by":  "team@phishguard.dev",
        "upvotes":      48,
    },
    {
        "title":        "Romanian tax authority (ANAF) impersonation",
        "sender_email": "noreply@anaf-rambursare.ro.info",
        "description":  "Email written in Romanian claiming you are owed a tax refund from ANAF. "
                        "Asks you to log in via a spoofed ANAF portal to claim it. "
                        "The real anaf.ro domain is anaf.ro — this sender uses a subdomain trick. "
                        "Targeting Romanian users specifically, likely scraped from public business registries.",
        "reported_by":  "community@phishguard.dev",
        "upvotes":      29,
    },
    {
        "title":        "Steam account phishing via fake trade offer",
        "sender_email": "verify@steam-community-support.ru",
        "description":  "Fake Steam email notifying of a pending trade offer worth over $200. "
                        "Links to a pixel-perfect Steam login clone at a .ru domain. "
                        "After entering credentials it asks for your Steam Guard code, "
                        "completing a full account takeover in real time.",
        "reported_by":  "gamer@phishguard.dev",
        "upvotes":      22,
    },
    {
        "title":        "Fake invoice from spoofed accounting software",
        "sender_email": "invoices@quickbooks-billing-notice.com",
        "description":  "Impersonates QuickBooks sending an overdue invoice for $349. "
                        "PDF attachment contains a QR code pointing to a credential harvesting page. "
                        "Targeting small business owners and freelancers. "
                        "The PDF looks identical to a real QuickBooks invoice export.",
        "reported_by":  "finance@phishguard.dev",
        "upvotes":      17,
    },
]


class Command(BaseCommand):
    help = "Seed the community reports page with realistic dummy phishing reports."

    def add_arguments(self, parser):
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Delete all existing seeded reports before re-seeding.",
        )

    def handle(self, *args, **options):
        if options["clear"]:
            deleted, _ = CommunityReport.objects.filter(
                reported_by__endswith="@phishguard.dev"
            ).delete()
            self.stdout.write(self.style.WARNING(f"Cleared {deleted} existing seed reports."))

        created = 0
        skipped = 0

        for data in REPORTS:
            _, was_created = CommunityReport.objects.get_or_create(
                title=data["title"],
                reported_by=data["reported_by"],
                defaults={
                    "sender_email": data["sender_email"],
                    "description":  data["description"],
                    "upvotes":      data["upvotes"],
                },
            )
            if was_created:
                created += 1
                self.stdout.write(f"  ✓ Created: {data['title']}")
            else:
                skipped += 1
                self.stdout.write(f"  – Skipped (already exists): {data['title']}")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone. {created} report(s) created, {skipped} skipped."
            )
        )