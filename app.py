import os
import json
from flask import Flask, redirect, url_for, session, request, render_template_string
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import base64
import requests

app = Flask(__name__)
app.secret_key = "super_secret_key_change_me"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # only for local dev

CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

HTML_PAGE = """
<h2>Last 10 Emails (JSON)</h2>
<pre>{{ emails }}</pre>
<a href="/logout">Logout</a>
"""

REDIRECT_URI = "http://localhost:5000/oauth2callback"


@app.route("/")
def index():
    if "credentials" not in session:
        return '<a href="/login">Login with Google</a>'

    creds = Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me",
        maxResults=10
    ).execute()

    messages = results.get("messages", [])

    emails_data = []

    def extract_body(payload):
        """Recursively find plain text body"""
        if "parts" in payload:
            for part in payload["parts"]:
                mime = part.get("mimeType", "")
                body = part.get("body", {}).get("data")

                if mime == "text/plain" and body:
                    return base64.urlsafe_b64decode(body).decode("utf-8", errors="ignore")

                # recurse into nested parts
                if "parts" in part:
                    result = extract_body(part)
                    if result:
                        return result

        # fallback: single-part message
        body = payload.get("body", {}).get("data")
        if body:
            return base64.urlsafe_b64decode(body).decode("utf-8", errors="ignore")

        return None

    for msg in messages:
        msg_detail = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        headers = msg_detail["payload"].get("headers", [])

        subject = next((h["value"] for h in headers if h["name"] == "Subject"), None)
        sender = next((h["value"] for h in headers if h["name"] == "From"), None)
        date = next((h["value"] for h in headers if h["name"] == "Date"), None)

        body = extract_body(msg_detail["payload"])

        emails_data.append({
            "id": msg["id"],
            "subject": subject,
            "from": sender,
            "date": date,
            "body": body
        })

    session["credentials"] = creds_to_dict(creds)

    return render_template_string(
        HTML_PAGE,
        emails=json.dumps(emails_data, indent=2)
    )

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )

    session["state"] = state
    session["code_verifier"] = flow.code_verifier

    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session["state"],
        redirect_uri=REDIRECT_URI
    )

    flow.code_verifier = session.get("code_verifier")

    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session["credentials"] = creds_to_dict(creds)

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    creds = session.get("credentials")

    if creds:
        token = creds.get("token")
        if token:
            requests.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": token},
                headers={"content-type": "application/x-www-form-urlencoded"}
            )

    session.clear()
    return redirect(url_for("index"))

def creds_to_dict(creds):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }


if __name__ == "__main__":
    app.run(debug=True)