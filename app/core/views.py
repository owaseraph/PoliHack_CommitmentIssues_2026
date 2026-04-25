import os
import json
import base64

import requests as http_requests

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.urls import reverse

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from mail.parser import parser_raw_email
from detection.scanner import scan

from .models import UserToken, CommunityReport

# Allow HTTP for local development only
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
# Don't raise an exception if Google returns a subset of requested scopes
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

# Fallback store in case the session is lost between login and callback
_code_verifiers: dict[str, str] = {}

_BASE = os.path.dirname(os.path.dirname(__file__))
CLIENT_SECRETS_FILE = os.path.join(_BASE, "credentials.json")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

def _get_redirect_uri(request):
    """Build the OAuth redirect URI, using SITE_URL override if configured."""
    from django.conf import settings
    site_url = getattr(settings, "SITE_URL", "").rstrip("/")
    if site_url:
        return site_url + "/oauth2callback"
    return request.build_absolute_uri("/oauth2callback")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_body(payload):
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


def _enrich_email(email_entry):
    """Add computed display fields to an email dict (verdict, pct, flags…)."""
    score = email_entry.get("phishing_score", 0.0)
    pct = round(score * 100)
    is_phishing = email_entry.get("is_phishing", False)

    if is_phishing:
        verdict, label, bar_color = "phishing", "PHISHING", "#ff4d4d"
    elif score > 0.5:
        verdict, label, bar_color = "suspicious", "SUSPICIOUS", "#f0a500"
    else:
        verdict, label, bar_color = "safe", "SAFE", "#3dd68c"

    all_flags, bad_links, llm_reasons = [], [], []
    for sig in email_entry.get("detection_signals", []):
        for flag in sig.get("flags", []):
            if "malicious_url:" in flag:
                bad_links.append(flag.replace("malicious_url:", ""))
            elif "llm:" in flag:
                llm_reasons.append(
                    flag.replace("llm:", "").replace("llm_verdict:", "verdict: ")
                )
            elif flag:
                all_flags.append(
                    {"text": flag.replace("_", " "), "danger": "fail" in flag or "mismatch" in flag}
                )

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


def _fetch_and_scan_emails(service, max_results=10):
    results = service.users().messages().list(userId="me", maxResults=max_results).execute()
    emails_data = []

    for msg in results.get("messages", []):
        msg_detail = service.users().messages().get(
            userId="me", id=msg["id"], format="full"
        ).execute()

        headers = msg_detail["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), None)
        sender = next((h["value"] for h in headers if h["name"] == "From"), None)
        date = next((h["value"] for h in headers if h["name"] == "Date"), None)
        body = _extract_body(msg_detail["payload"])

        try:
            parsed_email = parser_raw_email(
                msg["id"].encode(),
                json.dumps({"headers": {h["name"]: h["value"] for h in headers}, "body": body}).encode(),
            )
            scan_result = scan(parsed_email)
        except Exception as exc:
            print(f"[scan] error on {msg['id']}: {exc}")
            scan_result = None

        entry = {
            "id": msg["id"],
            "subject": subject,
            "sender": sender,
            "date": date,
            "body": body,
            "phishing_score": scan_result.final_score if scan_result else 0.0,
            "is_phishing": scan_result.is_phishing if scan_result else False,
            "detection_signals": [
                {
                    "name": s.name,
                    "score": s.score,
                    "score_fmt": f"{s.score:.2f}",
                    "flags": s.flags,
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
        "users_protected": UserToken.objects.count(),
    }
    return render(request, "home.html", {
        "stats": stats,
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
    request.session["oauth_state"] = state
    request.session["code_verifier"] = flow.code_verifier
    request.session.save()  # ensure session is persisted before redirect
    _code_verifiers[state] = flow.code_verifier  # fallback in case session is lost
    return redirect(authorization_url)


def oauth2callback(request):
    state = request.GET.get("state") or request.session.get("oauth_state")
    code_verifier = request.session.get("code_verifier") or _code_verifiers.pop(state, None)

    if not code_verifier:
        return HttpResponseBadRequest("Missing code verifier — please retry login.")

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=_get_redirect_uri(request),
    )
    flow.code_verifier = code_verifier

    # Build the full callback URL as Django sees it
    callback_url = request.build_absolute_uri()
    # Ensure scheme matches what Google expects (http for local dev)
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
    user_id = userinfo.get("id")
    if not user_id:
        return HttpResponseBadRequest("Invalid user info response from Google.")

    request.session["user_id"] = user_id
    request.session["user_name"] = userinfo.get("name", "")
    request.session["user_email"] = userinfo.get("email", "")
    request.session["user_picture"] = userinfo.get("picture", "")
    UserToken.save_credentials(user_id, creds)

    return redirect(reverse("dashboard"))


def dashboard(request):
    if not request.session.get("user_id"):
        return render(request, "login.html")

    user_id = request.session["user_id"]
    creds = UserToken.load_credentials(user_id)
    if not creds:
        return redirect(reverse("login"))

    service = build("gmail", "v1", credentials=creds)
    emails_data = _fetch_and_scan_emails(service)

    phishing_count = sum(1 for e in emails_data if e.get("is_phishing"))
    suspicious_count = sum(
        1 for e in emails_data if e.get("phishing_score", 0) > 0.5 and not e.get("is_phishing")
    )

    return render(request, "dashboard.html", {
        "emails": emails_data,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "user_name": request.session.get("user_name", ""),
        "user_email": request.session.get("user_email", ""),
        "user_picture": request.session.get("user_picture", ""),
    })


def logout_view(request):
    user_id = request.session.get("user_id")
    if user_id:
        creds = UserToken.load_credentials(user_id)
        if creds and creds.token:
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

        title = request.POST.get("title", "").strip()
        sender_email = request.POST.get("sender_email", "").strip()
        description = request.POST.get("description", "").strip()

        if title and description:
            CommunityReport.objects.create(
                title=title,
                sender_email=sender_email,
                description=description,
                reported_by=request.session.get("user_email", "anonymous"),
            )
        return redirect(reverse("community"))

    reports = CommunityReport.objects.all()[:50]
    return render(request, "community.html", {
        "reports": reports,
        "is_logged_in": bool(request.session.get("user_id")),
        "user_name": request.session.get("user_name", ""),
    })


@require_POST
def upvote_report(request, report_id):
    report = get_object_or_404(CommunityReport, id=report_id)
    report.upvotes += 1
    report.save()
    return JsonResponse({"upvotes": report.upvotes})


def download(request):
    return render(request, "download.html", {
        "is_logged_in": bool(request.session.get("user_id")),
        "user_name": request.session.get("user_name", ""),
    })


@csrf_exempt
def api_scan(request):
    """JSON endpoint for the browser extension — scans a single email."""
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    email_id = str(data.get("id", "ext-scan")).encode()
    raw_content = json.dumps(data).encode()

    try:
        parsed = parser_raw_email(email_id, raw_content)
        result = scan(parsed)
        return JsonResponse({
            "email_id": result.email_id,
            "final_score": result.final_score,
            "is_phishing": result.is_phishing,
            "signals": [
                {"name": s.name, "score": s.score, "flags": s.flags}
                for s in result.signals
            ],
        })
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)
