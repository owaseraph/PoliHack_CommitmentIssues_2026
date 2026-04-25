import json
import os
import base64

from django.db import models
from django.utils import timezone
from datetime import timedelta
from google.oauth2.credentials import Credentials


# ── Credential helpers ────────────────────────────────────────────────────────

def _load_client_secrets() -> tuple[str, str]:
    """
    Read client_id and client_secret from credentials.json.

    On Railway the file doesn't exist on disk — instead the whole JSON is
    base64-encoded in the GOOGLE_CREDENTIALS_JSON env var.
    This function handles both cases transparently.
    """
    env_creds = os.environ.get("GOOGLE_CREDENTIALS_JSON")

    if env_creds:
        data = json.loads(base64.b64decode(env_creds).decode())
    else:
        creds_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "credentials.json"
        )
        with open(creds_path) as f:
            data = json.load(f)

    # Google wraps secrets under "web" (server apps) or "installed" (desktop apps)
    section = data.get("web") or data.get("installed", {})
    return section["client_id"], section["client_secret"]


# ── Models ────────────────────────────────────────────────────────────────────

class UserToken(models.Model):
    """
    Stores per-user OAuth tokens.

    client_id and client_secret are intentionally NOT stored here —
    they are app-level secrets that belong in credentials.json only.
    Storing them in the DB would mean a DB leak compromises the entire
    OAuth app for all users, not just one user's token.
    """

    user_id       = models.CharField(max_length=255, primary_key=True)
    token         = models.TextField()
    refresh_token = models.TextField(blank=True, null=True)
    token_uri     = models.TextField()
    scopes        = models.TextField()  # JSON-encoded list

    class Meta:
        db_table = "user_tokens"

    def to_credentials(self) -> Credentials:
        """Reconstruct a Google Credentials object from this DB record."""
        client_id, client_secret = _load_client_secrets()
        return Credentials(
            token=self.token,
            refresh_token=self.refresh_token,
            token_uri=self.token_uri,
            client_id=client_id,      # loaded from file, not DB
            client_secret=client_secret,  # loaded from file, not DB
            scopes=json.loads(self.scopes),
        )

    @classmethod
    def save_credentials(cls, user_id: str, creds: Credentials) -> None:
        """Upsert a user's OAuth tokens. Never saves client secrets."""
        record, _ = cls.objects.get_or_create(user_id=user_id)
        record.token         = creds.token
        record.refresh_token = creds.refresh_token
        record.token_uri     = creds.token_uri
        record.scopes        = json.dumps(list(creds.scopes or []))
        record.save()

    @classmethod
    def load_credentials(cls, user_id: str) -> Credentials | None:
        """Load a user's credentials, or None if not found."""
        try:
            return cls.objects.get(user_id=user_id).to_credentials()
        except cls.DoesNotExist:
            return None

    @classmethod
    def delete_credentials(cls, user_id: str) -> None:
        """Remove a user's tokens — called on logout."""
        cls.objects.filter(user_id=user_id).delete()


class CommunityReport(models.Model):
    """A user-submitted phishing report visible to the community."""

    title        = models.CharField(max_length=500)
    sender_email = models.CharField(max_length=500, blank=True)
    description  = models.TextField()
    reported_by  = models.CharField(max_length=255, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)
    upvotes      = models.IntegerField(default=0)

    class Meta:
        db_table = "community_reports"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.title

    @classmethod
    def is_duplicate(cls, title: str, reported_by: str, window_minutes: int = 10) -> bool:
        """
        Returns True if the same user submitted the same title within
        the last `window_minutes`. Used to prevent accidental double-submits
        and basic spam.
        """
        since = timezone.now() - timedelta(minutes=window_minutes)
        return cls.objects.filter(
            title=title,
            reported_by=reported_by,
            created_at__gte=since,
        ).exists()