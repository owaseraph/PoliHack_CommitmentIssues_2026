from django.core.management.base import BaseCommand
from scanner.models import PhishingKeyword

KEYWORDS = [
    # Urgency
    'act now',
    'immediate action required',
    'urgent',
    'respond immediately',
    'within 24 hours',
    'account will be suspended',
    'limited time',
    'expires today',
    'don\'t delay',
    'last chance',

    # Credential harvesting
    'verify your account',
    'confirm your identity',
    'update your password',
    'your password has expired',
    'enter your credentials',
    'sign in to verify',
    'validate your email',
    'account verification required',
    'unusual sign-in activity',
    'suspicious login detected',

    # Financial
    'bank account',
    'wire transfer',
    'send money',
    'bitcoin',
    'crypto payment',
    'your invoice is attached',
    'payment required',
    'billing information',
    'credit card details',
    'refund pending',

    # Rewards / prizes
    'you have won',
    'congratulations',
    'claim your prize',
    'free gift',
    'selected as a winner',
    'lottery',
    '$1000',
    'cash reward',
    'gift card',
    'exclusive offer',

    # Threats
    'your account has been compromised',
    'we detected a virus',
    'legal action will be taken',
    'law enforcement',
    'arrest warrant',
    'your computer has been hacked',
    'malware detected',
    'unauthorized access',

    # Impersonation
    'microsoft account team',
    'apple support',
    'paypal security',
    'irs notice',
    'hmrc',
    'amazon security alert',
    'google account alert',
    'facebook security',
    'it department',
    'helpdesk',

    # Generic phishing
    'click here',
    'click the link below',
    'download the attachment',
    'open the attached file',
    'do not ignore this email',
    'this is not spam',
    'kindly provide',
    'dear valued customer',
    'dear user',
    'your account is at risk',
]


class Command(BaseCommand):
    help = 'Seed the database with default phishing keywords'

    def handle(self, *args, **options):
        created = 0
        skipped = 0
        for kw in KEYWORDS:
            _, was_created = PhishingKeyword.objects.get_or_create(keyword=kw)
            if was_created:
                created += 1
            else:
                skipped += 1

        self.stdout.write(self.style.SUCCESS(
            f'Done. {created} keywords added, {skipped} already existed.'
        ))