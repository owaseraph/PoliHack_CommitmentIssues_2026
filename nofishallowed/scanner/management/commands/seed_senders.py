from django.core.management.base import BaseCommand
from scanner.models import FlaggedSender

FLAGGED_DOMAINS = [
    # Known phishing / disposable / malicious domains
    ('mailinator.com', 'Disposable email service'),
    ('guerrillamail.com', 'Disposable email service'),
    ('trashmail.com', 'Disposable email service'),
    ('tempmail.com', 'Disposable email service'),
    ('10minutemail.com', 'Disposable email service'),
    ('yopmail.com', 'Disposable email service'),
    ('sharklasers.com', 'Disposable email service'),
    ('throwam.com', 'Disposable email service'),
    ('maildrop.cc', 'Disposable email service'),
    ('dispostable.com', 'Disposable email service'),
    # Typosquatted brands
    ('paypa1.com', 'PayPal typosquat'),
    ('paypal-security.com', 'PayPal impersonation'),
    ('apple-id-verify.com', 'Apple impersonation'),
    ('microsoft-alert.com', 'Microsoft impersonation'),
    ('amazon-security-alert.com', 'Amazon impersonation'),
    ('netflix-billing.com', 'Netflix impersonation'),
    ('google-account-verify.com', 'Google impersonation'),
    ('secure-bankofamerica.com', 'Bank impersonation'),
    ('irs-refund.com', 'IRS impersonation'),
    ('dhl-delivery-notice.com', 'DHL impersonation'),
]

FLAGGED_EMAILS = [
    ('noreply@paypa1.com', 'PayPal typosquat'),
    ('support@apple-id-verify.com', 'Apple impersonation'),
    ('security@microsoft-alert.com', 'Microsoft impersonation'),
]


class Command(BaseCommand):
    help = 'Seed the database with flagged sender domains and emails'

    def handle(self, *args, **options):
        created = skipped = 0

        for domain, reason in FLAGGED_DOMAINS:
            _, was_created = FlaggedSender.objects.get_or_create(
                value=domain,
                defaults={'type': 'domain', 'reason': reason},
            )
            if was_created:
                created += 1
            else:
                skipped += 1

        for email, reason in FLAGGED_EMAILS:
            _, was_created = FlaggedSender.objects.get_or_create(
                value=email,
                defaults={'type': 'email', 'reason': reason},
            )
            if was_created:
                created += 1
            else:
                skipped += 1

        self.stdout.write(self.style.SUCCESS(
            f'Done. {created} senders added, {skipped} already existed.'
        ))