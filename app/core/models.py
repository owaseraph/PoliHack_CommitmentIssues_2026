import json

from django.db import models
from google.oauth2.credentials import Credentials


class UserToken(models.Model):
    user_id = models.CharField(max_length=255, primary_key=True)
    token = models.TextField()
    refresh_token = models.TextField(blank=True, null=True)
    token_uri = models.TextField()
    client_id = models.TextField()
    client_secret = models.TextField()
    scopes = models.TextField()  # JSON-encoded list

    class Meta:
        db_table = "user_tokens"

    def to_credentials(self) -> Credentials:
        return Credentials(
            token=self.token,
            refresh_token=self.refresh_token,
            token_uri=self.token_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            scopes=json.loads(self.scopes),
        )

    @classmethod
    def save_credentials(cls, user_id: str, creds: Credentials) -> None:
        record, _ = cls.objects.get_or_create(user_id=user_id)
        record.token = creds.token
        record.refresh_token = creds.refresh_token
        record.token_uri = creds.token_uri
        record.client_id = creds.client_id
        record.client_secret = creds.client_secret
        record.scopes = json.dumps(list(creds.scopes or []))
        record.save()

    @classmethod
    def load_credentials(cls, user_id: str):
        try:
            return cls.objects.get(user_id=user_id).to_credentials()
        except cls.DoesNotExist:
            return None

    @classmethod
    def delete_credentials(cls, user_id: str) -> None:
        cls.objects.filter(user_id=user_id).delete()


class CommunityReport(models.Model):
    title = models.CharField(max_length=500)
    sender_email = models.CharField(max_length=500, blank=True)
    description = models.TextField()
    reported_by = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    upvotes = models.IntegerField(default=0)

    class Meta:
        db_table = "community_reports"
        ordering = ["-created_at"]

    def __str__(self):
        return self.title
