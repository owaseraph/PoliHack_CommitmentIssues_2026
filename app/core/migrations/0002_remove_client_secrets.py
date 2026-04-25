"""
Remove client_id and client_secret from user_tokens.

These are app-level secrets that belong in credentials.json only.
Storing them per-user in the DB means a DB leak compromises the entire
OAuth application, not just a single user's token.

After running this migration, client_id and client_secret are read
from credentials.json (or GOOGLE_CREDENTIALS_JSON env var) at runtime
inside UserToken.to_credentials().
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="usertoken",
            name="client_id",
        ),
        migrations.RemoveField(
            model_name="usertoken",
            name="client_secret",
        ),
    ]