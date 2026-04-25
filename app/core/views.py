import os
import json
import base64
import tempfile

import requests as http_requests

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from mail.parser import parser_raw_email
from detection.scanner import scan

from .models import UserToken, CommunityReport


# ── Environment setup ─────────────────────────────────────────────────────────

# ✅ Safe default: only allow insecure transport in explicit local dev mode
if os.environ.get("DEBUG", "False") == "True":
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

_BASE = os.path.dirname(os.path.dirname(__file__))

# On Railway, credentials.json doesn't exist on disk.
# Instead, the JSON is base64-encoded in GOOGLE_CREDENTIALS_JSON env var.
_CREDS_ENV = os.environ.get("GOOGLE_CREDENTIALS_JSON")
if _CREDS_ENV:
    _tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    _tmp.write(base64.b64decode(_CREDS_ENV).decode())
    _tmp.close()
    CLIENT_SECRETS_FILE = _tmp.name
else:
    CLIENT_SECRETS_FILE = os.path.join(_BASE, "credentials.json")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_redirect_uri(request) -> str:
    """
    Build the OAuth redirect URI.
    Uses SITE_URL env var override for Railway/ngrok deployments.
    """
    from django.conf import settings
    site_url = getattr(settings, "SITE_URL", "").rstrip("/")
    if site_url:
        return site_url + "/oauth2callback"
    return request.build_absolute_uri("/oauth2callback")


def _get_valid_credentials(user_id: str) -> Credentials | None:
    """
    Load a user's credentials and silently refresh them if expired.

    Returns None if credentials don't exist or can't be refreshed
    (e.g. user revoked access), so the caller can redirect to login.

    Without this, users get an empty dashboard ~1 hour after logging in
    because Google access tokens expire after 3600 seconds.
    """
    creds = UserToken.load_credentials(user_id)

    if not creds:
        return None

    if not creds.scopes or GMAIL_SCOPE not in creds.scopes:
        return None

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            UserToken.save_credentials(user_id, creds)  # persist the new token
        except Exception as e:
            print(f"[Auth] Token refresh failed for {user_id}: {e}")
            return None  # force re-login

    return creds


# ── Email helpers ─────────────────────────────────────────────────────────────

def _extract_body(payload) -> str | None:
    """Recursively extract plain-text body from a Gmail message payload."""
    if "parts" in payload:
        for part in payload["parts"]:
            mime = part.get("mimeType", "")
            body = part.get("body", {}).get("data")
            if mime == "text/plain" and body:
                return base64.urlsafe_b64decode(body).decode("utf-8", errors="ignore")
            if "parts" in part:
                result = _extract_body(part)
                if result:
                    return result

    body = payload.get("body", {}).get("data")
    if body:
        return base64.urlsafe_b64decode(body).decode("utf-8", errors="ignore")

    return None


def _enrich_email(email_entry: dict) -> dict:
    """
    Add computed display fields to a raw email dict.
    Separates verdict logic from the template so templates stay clean.
    """
    score       = email_entry.get("phishing_score", 0.0)
    pct         = round(score * 100)
    is_phishing = email_entry.get("is_phishing", False)

    if is_phishing:
        verdict, label, bar_color = "phishing",   "PHISHING",   "#ff4d4d"
    elif score > 0.5:
        verdict, label, bar_color = "suspicious", "SUSPICIOUS", "#f0a500"
    else:
        verdict, label, bar_color = "safe",       "SAFE",       "#3dd68c"

    all_flags, bad_links, llm_reasons = [], [], []

    for sig in email_entry.get("detection_signals", []):
        for flag in sig.get("flags", []):
            if "malicious_url:" in flag:
                bad_links.append(flag.replace("malicious_url:", ""))
            elif flag.startswith("llm:"):
                llm_reasons.append(flag.replace("llm:", ""))
            elif flag.startswith("llm_verdict:"):
                llm_reasons.append("verdict: " + flag.replace("llm_verdict:", ""))
            elif flag:
                all_flags.append({
                    "text":   flag.replace("_", " "),
                    "danger": "fail" in flag or "mismatch" in flag,
                })

    email_entry.update(
        verdict=verdict,
        label=label,
        bar_color=bar_color,
        pct=pct,
        all_flags=all_flags,
        bad_links=bad_links,
        llm_reasons=llm_reasons,
        has_analysis=verdict != "safe" and bool(llm_reasons or bad_links),
    )
    return email_entry


def _fetch_and_scan_emails(service, max_results: int = 10) -> list[dict]:
    """Fetch emails from Gmail API and run phishing detection on each."""
    results  = service.users().messages().list(userId="me", maxResults=max_results).execute()
    emails_data = []

    for msg in results.get("messages", []):
        msg_detail = service.users().messages().get(
            userId="me", id=msg["id"], format="full"
        ).execute()

        headers = msg_detail["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), None)
        sender  = next((h["value"] for h in headers if h["name"] == "From"), None)
        date    = next((h["value"] for h in headers if h["name"] == "Date"), None)
        body    = _extract_body(msg_detail["payload"])

        try:
            parsed_email = parser_raw_email(
                msg["id"].encode(),
                json.dumps({
                    "headers": {h["name"]: h["value"] for h in headers},
                    "body":    body,
                }).encode(),
            )
            scan_result = scan(parsed_email)
        except Exception as exc:
            print(f"[scan] error on {msg['id']}: {exc}")
            scan_result = None

        entry = {
            "id":             msg["id"],
            "subject":        subject,
            "sender":         sender,
            "date":           date,
            "body":           body,
            "phishing_score": scan_result.final_score  if scan_result else 0.0,
            "is_phishing":    scan_result.is_phishing  if scan_result else False,
            "detection_signals": [
                {
                    "name":      s.name,
                    "score":     s.score,
                    "score_fmt": f"{s.score:.2f}",
                    "flags":     s.flags,
                }
                for s in scan_result.signals
            ] if scan_result else [],
        }
        emails_data.append(_enrich_email(entry))

    return emails_data


# ── Views ─────────────────────────────────────────────────────────────────────

def home(request):
    stats = {
        "community_reports": CommunityReport.objects.count(),
        "users_protected":   UserToken.objects.count(),
    }
    return render(request, "home.html", {
        "stats":        stats,
        "is_logged_in": bool(request.session.get("user_id")),
    })


def login_view(request):
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=_get_redirect_uri(request),
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    # Store verifier in the session only — no in-memory dict.
    # Django's DB-backed sessions survive across multiple gunicorn workers,
    # which an in-memory dict does NOT (causes random login failures in prod).
    request.session["oauth_state"]    = state
    request.session["code_verifier"]  = flow.code_verifier
    request.session.save()

    return redirect(authorization_url)


def oauth2callback(request):
    state         = request.GET.get("state") or request.session.get("oauth_state")
    code_verifier = request.session.get("code_verifier")

    if not code_verifier:
        # Session was lost — ask user to try again
        return HttpResponseBadRequest(
            "Your session expired during login. Please try again."
        )

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=_get_redirect_uri(request),
    )
    flow.code_verifier = code_verifier

    callback_url = request.build_absolute_uri()
    # In local dev Django sees http:// even if the browser sent https://
    if callback_url.startswith("https://") and not os.environ.get("HTTPS"):
        callback_url = "http://" + callback_url[len("https://"):]

    flow.fetch_token(authorization_response=callback_url)
    creds = flow.credentials

    resp = http_requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {creds.token}"},
    )
    if resp.status_code != 200:
        return HttpResponseBadRequest("Failed to fetch user info from Google.")

    userinfo = resp.json()
    user_id  = userinfo.get("id")
    if not user_id:
        return HttpResponseBadRequest("Invalid user info response from Google.")

    request.session["user_id"]      = user_id
    request.session["user_name"]    = userinfo.get("name", "")
    request.session["user_email"]   = userinfo.get("email", "")
    request.session["user_picture"] = userinfo.get("picture", "")

    UserToken.save_credentials(user_id, creds)

    return redirect(reverse("dashboard"))


def dashboard(request):
    if not request.session.get("user_id"):
        return render(request, "login.html")

    user_id = request.session["user_id"]

    # _get_valid_credentials handles expiry + refresh transparently
    creds = _get_valid_credentials(user_id)
    if not creds:
        UserToken.delete_credentials(user_id)
        request.session.flush()
        return redirect(reverse("login"))

    service     = build("gmail", "v1", credentials=creds)
    emails_data = _fetch_and_scan_emails(service)

    phishing_count   = sum(1 for e in emails_data if e.get("is_phishing"))
    suspicious_count = sum(
        1 for e in emails_data
        if e.get("phishing_score", 0) > 0.5 and not e.get("is_phishing")
    )

    return render(request, "dashboard.html", {
        "emails":           emails_data,
        "phishing_count":   phishing_count,
        "suspicious_count": suspicious_count,
        "user_name":        request.session.get("user_name", ""),
        "user_email":       request.session.get("user_email", ""),
        "user_picture":     request.session.get("user_picture", ""),
    })


def logout_view(request):
    user_id = request.session.get("user_id")
    if user_id:
        creds = UserToken.load_credentials(user_id)
        if creds and creds.token:
            # Revoke the token on Google's side so it can't be reused
            http_requests.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": creds.token},
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        UserToken.delete_credentials(user_id)
    request.session.flush()
    return redirect(reverse("home"))


def community(request):
    if request.method == "POST":
        if not request.session.get("user_id"):
            return redirect(reverse("login"))

        title        = request.POST.get("title",        "").strip()
        sender_email = request.POST.get("sender_email", "").strip()
        description  = request.POST.get("description",  "").strip()
        reported_by  = request.session.get("user_email", "anonymous")

        if title and description:
            # ✅ Prevent duplicate submissions within 10 minutes
            if not CommunityReport.is_duplicate(title, reported_by):
                CommunityReport.objects.create(
                    title=title,
                    sender_email=sender_email,
                    description=description,
                    reported_by=reported_by,
                )

        return redirect(reverse("community"))

    reports = CommunityReport.objects.all()[:50]
    return render(request, "community.html", {
        "reports":      reports,
        "is_logged_in": bool(request.session.get("user_id")),
        "user_name":    request.session.get("user_name", ""),
    })


@require_POST
def upvote_report(request, report_id):
    """
    Upvote a community report.
    Session-based tracking prevents the same browser from voting twice.
    """
    upvoted = set(request.session.get("upvoted_reports", []))

    if report_id in upvoted:
        report = get_object_or_404(CommunityReport, id=report_id)
        return JsonResponse({"upvotes": report.upvotes, "already_voted": True})

    report          = get_object_or_404(CommunityReport, id=report_id)
    report.upvotes += 1
    report.save()

    upvoted.add(report_id)
    request.session["upvoted_reports"] = list(upvoted)

    return JsonResponse({"upvotes": report.upvotes, "already_voted": False})


def download(request):
    return render(request, "download.html", {
        "is_logged_in": bool(request.session.get("user_id")),
        "user_name":    request.session.get("user_name", ""),
    })


@csrf_exempt
def api_scan(request):
    """
    JSON endpoint for external callers (future browser extension, etc).
    Protected by a static API key — set EXTENSION_API_KEY in Railway env vars.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    # ✅ Require API key so this endpoint can't be abused to drain Gemini quota
    expected_key = os.environ.get("EXTENSION_API_KEY", "")
    provided_key = request.headers.get("X-API-Key", "")
    if not expected_key or provided_key != expected_key:
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    email_id    = str(data.get("id", "api-scan")).encode()
    raw_content = json.dumps(data).encode()

    try:
        parsed = parser_raw_email(email_id, raw_content)
        result = scan(parsed)
        return JsonResponse({
            "email_id":    result.email_id,
            "final_score": result.final_score,
            "is_phishing": result.is_phishing,
            "signals": [
                {"name": s.name, "score": s.score, "flags": s.flags}
                for s in result.signals
            ],
        })
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)