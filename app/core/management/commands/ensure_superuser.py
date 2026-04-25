"""
Management command: ensure_superuser

Creates a Django superuser from environment variables if one doesn't exist.
Safe to run on every deploy — skips creation if the username already exists.

Required env vars:
  DJANGO_SUPERUSER_USERNAME  (default: admin)
  DJANGO_SUPERUSER_EMAIL     (default: admin@example.com)
  DJANGO_SUPERUSER_PASSWORD  (required — command is skipped if not set)
"""
import os
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create a superuser from env vars if one does not exist."

    def handle(self, *args, **options):
        User = get_user_model()

        username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "admin")
        email    = os.environ.get("DJANGO_SUPERUSER_EMAIL", "admin@example.com")
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")

        if not password:
            self.stdout.write(
                "DJANGO_SUPERUSER_PASSWORD not set — skipping superuser creation."
            )
            return

        if User.objects.filter(username=username).exists():
            self.stdout.write(f"Superuser '{username}' already exists — skipping.")
            return

        User.objects.create_superuser(username=username, email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"Superuser '{username}' created."))
