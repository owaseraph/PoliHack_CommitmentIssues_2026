import os
import json
import base64
import requests

from flask import Flask, redirect, url_for, session, request, render_template_string
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from mail.parser import parser_raw_email
from detection.scanner import scan

# your DB helpers
from database import save_credentials, load_credentials, delete_credentials

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_fallback_change_me")
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# ⚠️ REMOVE THIS IN PRODUCTION
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Fallback storage for PKCE code verifiers keyed by OAuth state.
# This helps recover the verifier when the browser session cookie is lost or not sent.
oauth2_state_verifiers = {}

CLIENT_SECRETS_FILE = "credentials.json"

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

REDIRECT_URI = "http://localhost:5000/oauth2callback"

HTML_PAGE = """
<h2>Last 10 Emails with Phishing Analysis</h2>
{% for email in emails %}
<div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
    <h3>{{ email.subject }}</h3>
    <p><strong>From:</strong> {{ email.from }}</p>
    <p><strong>Score:</strong> {{ email.phishing_score }} 
       {% if email.is_phishing %}
           <span style="color: red;">⚠️ PHISHING DETECTED</span>
       {% else %}
           <span style="color: green;">✅ SAFE</span>
       {% endif %}
    </p>
    <p><strong>Detection Signals:</strong></p>
    <ul>
    {% for signal in email.detection_signals %}
        <li>{{ signal.name }}: {{ signal.score }} - {{ signal.flags|join(', ') }}</li>
    {% endfor %}
    </ul>
</div>
{% endfor %}
<a href="/logout">Logout</a>
"""


@app.route("/")
def index():
    if "user_id" not in session:
        return '<a href="/login">Login with Google</a>'

    creds = load_credentials(session["user_id"])
    if not creds:
        return redirect("/login")

    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me",
        maxResults=10
    ).execute()

    messages = results.get("messages", [])
    emails_data = []

    def extract_body(payload):
        if "parts" in payload:
            for part in payload["parts"]:
                mime = part.get("mimeType", "")
                body = part.get("body", {}).get("data")

                if mime == "text/plain" and body:
                    return base64.urlsafe_b64decode(body).decode("utf-8", errors="ignore")

                if "parts" in part:
                    result = extract_body(part)
                    if result:
                        return result

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

        # Run phishing detection
        try:
            parsed_email = parser_raw_email(
                msg["id"].encode(),
                json.dumps({"headers": dict((h["name"], h["value"]) for h in headers), "body": body}).encode()
            )
            scan_result = scan(parsed_email)
        except Exception as e:
            print(f"[Integration] Error scanning email {msg['id']}: {e}")
            scan_result = None

        email_entry = {
            "id": msg["id"],
            "subject": subject,
            "from": sender,
            "date": date,
            "body": body,
        }

        if scan_result:
            email_entry["phishing_score"] = scan_result.final_score
            email_entry["is_phishing"] = scan_result.is_phishing
            email_entry["detection_signals"] = [
                {
                    "name": s.name,
                    "score": s.score,
                    "flags": s.flags
                }
                for s in scan_result.signals
            ]
        else:
            email_entry["phishing_score"] = 0.0
            email_entry["is_phishing"] = False
            email_entry["detection_signals"] = []

        emails_data.append(email_entry)

    return render_template_string(
        HTML_PAGE,
        emails=emails_data
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
        include_granted_scopes="true",
        prompt="consent"
    )

    session["state"] = state
    session["code_verifier"] = flow.code_verifier
    oauth2_state_verifiers[state] = flow.code_verifier

    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    callback_state = request.args.get("state") or session.get("state")
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=callback_state,
        redirect_uri=REDIRECT_URI
    )

    code_verifier = session.get("code_verifier") or oauth2_state_verifiers.pop(callback_state, None)
    if not code_verifier:
        return "Missing code verifier. Please retry login.", 400

    flow.code_verifier = code_verifier
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials

    # 🔐 Get user identity safely via Google userinfo API
    resp = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {creds.token}"}
    )

    if resp.status_code != 200:
        return "Failed to fetch user info", 400

    userinfo = resp.json()
    user_id = userinfo.get("id")

    if not user_id:
        return "Invalid user info response", 400

    # store session reference only
    session["user_id"] = user_id

    # store tokens server-side
    save_credentials(user_id, creds)
    
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    user_id = session.get("user_id")

    if user_id:
        creds = load_credentials(user_id)

        if creds and creds.token:
            requests.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": creds.token},
                headers={"content-type": "application/x-www-form-urlencoded"}
            )

        delete_credentials(user_id)

    session.clear()
    return redirect(url_for("index"))

@app.route("/debug-session")
def debug_session():
    return dict(session)
    
if __name__ == "__main__":
    app.run(debug=True)