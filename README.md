# PhishGuard

**Real-time phishing protection for Gmail with AI-powered detection and community intelligence.**

Built for PoliHack 2026 — _Detecting and Preventing Phishing Attacks in Real Time._

---

## 🎯 Overview

PhishGuard is a multi-layer phishing detection system that scans Gmail inboxes in real time, combining traditional email security checks with modern AI analysis and community-driven threat intelligence. The platform empowers users to identify phishing attempts before they cause harm, with a plugin marketplace that lets the community extend detection capabilities beyond the defaults.

**Live Demo**: https://polihackcommitmentissues2026-production.up.railway.app/

---

## ✨ Key Features

### 🔍 Four-Layer Detection Engine

1. **Header Analysis** — Validates SPF, DKIM, DMARC records and inspects sender routing to catch spoofed origins
2. **Link Scanning** — Checks URLs against Google Safe Browsing API and analyzes domain patterns for typosquatting and deceptive redirects
3. **AI Verdict** — Google Gemini reads the full email body and provides scored verdicts with human-readable reasoning for each flag
4. **Community Plugins** — User-installed detection rules, keyword filters, regex patterns, and blacklists that extend the base system

### 🧩 Plugin Marketplace

The marketplace is PhishGuard's differentiator — a community-driven extension system where users can:

- Install blacklists of known phishing sender domains
- Add keyword filters for common phishing language (urgency tactics, credential harvesting phrases)
- Deploy regex patterns to catch obfuscated URLs and fake invoice formats
- Whitelist trusted domains to reduce false positives

**9 pre-seeded plugins** cover:
- Known phishing senders (DHL, Netflix, Google Workspace impersonation)
- Cryptocurrency scam senders
- Urgency & scare tactic keywords
- Prize & lottery scam language
- Credential harvesting phrases
- Suspicious URL patterns (IP addresses as hosts, excessive subdomains, base64 paths)
- Fake invoice detection regex
- Trusted domain lists (major tech providers, Romanian universities/government)

### 👥 Community Intelligence

Users can submit phishing reports that are visible to the entire PhishGuard community:

- **6 pre-seeded reports** covering real-world campaigns (DHL parcels, Netflix suspensions, Google Workspace admin takeovers, Romanian tax authority impersonation)
- Upvote system highlights the most critical active threats
- Threat badges (HIGH THREAT / ACTIVE / REPORTED) based on community validation

### 🔐 Privacy & Security

- **Read-only Gmail access** (`gmail.readonly` scope only) — PhishGuard never modifies, deletes, or stores your emails
- **OAuth 2.0 authentication** — no passwords stored
- **Zero data retention** — emails are scanned on-demand and immediately discarded
- **Transparent permissions** — clear disclosure of what data is accessed and why

---

## 🏗️ Technical Stack

**Backend**
- Django 6.0.4 (Python 3.14)
- Gmail API + Google OAuth2
- Google Gemini 1.5 Flash (LLM analysis)
- Google Safe Browsing API (link scanning)
- SQLite (development) / PostgreSQL-ready (production)

**Frontend**
- Server-side rendered HTML templates
- Vanilla JavaScript (no frameworks)
- IBM Plex Mono + IBM Plex Sans typography
- Dark cybersec-themed UI with red accent colors

**Deployment**
- Railway (platform)
- Gunicorn (WSGI server)
- WhiteNoise (static file serving)
- Environment-based configuration (dev/prod split)

---

## 🚀 Quick Start

### Prerequisites

- Python 3.14+
- Google Cloud project with Gmail API enabled
- Google OAuth 2.0 credentials (`credentials.json`)
- Google Safe Browsing API key
- Google Gemini API key

### Local Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/owaseraph/PoliHack_CommitmentIssues_2026.git
   cd PoliHack_CommitmentIssues_2026/app
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt --break-system-packages
   ```

3. **Configure environment**
   
   Create a `.env` file or set these variables:
   ```bash
   DEBUG=True
   SECRET_KEY=your-secret-key-here
   GEMINI_API_KEY=your-gemini-api-key
   SAFE_BROWSING_API_KEY=your-safe-browsing-key
   ```

4. **Set up OAuth credentials**
   
   Place your `credentials.json` from Google Cloud Console in `app/credentials.json`.

5. **Run migrations**
   ```bash
   python manage.py migrate
   python manage.py ensure_superuser
   python manage.py seed_marketplace
   python manage.py seed_community
   ```

6. **Start the development server**
   ```bash
   python manage.py runserver
   ```

7. **Open the app**
   
   Navigate to `http://localhost:8000`

---

## 📁 Project Structure

```
app/
├── phishguard/          # Django project settings
│   ├── settings.py      # Configuration (DB, static files, security)
│   ├── urls.py          # URL routing
│   └── wsgi.py          # WSGI entry point
├── core/                # Main application
│   ├── models.py        # UserToken, CommunityReport, Plugin models
│   ├── views.py         # View logic (OAuth, dashboard, marketplace, community)
│   ├── urls.py          # App-level URL patterns
│   ├── admin.py         # Django admin interface
│   └── management/
│       └── commands/    # Custom management commands
│           ├── ensure_superuser.py
│           ├── seed_marketplace.py
│           └── seed_community.py
├── detection/           # Phishing detection engine
│   ├── scanner.py       # Orchestrates all detectors
│   ├── base.py          # Abstract base detector class
│   ├── models.py        # ScanResult, DetectionSignal data classes
│   └── detectors/       # Individual detection modules
│       ├── header_detector.py    # SPF/DKIM/DMARC validation
│       ├── link_detector.py      # URL analysis + Safe Browsing
│       ├── llm_detector.py       # Gemini-powered analysis
│       └── plugin_detector.py    # User-installed plugin rules
├── mail/
│   └── parser.py        # Email parsing utilities (link extraction)
├── templates/           # HTML templates
│   ├── base.html        # Base layout with nav
│   ├── home.html        # Landing page
│   ├── dashboard.html   # Gmail scan results
│   ├── marketplace.html # Plugin browser
│   ├── community.html   # Phishing reports feed
│   ├── download.html    # Browser extension info
│   └── login.html       # OAuth login page
├── static/              # Static assets (if any)
├── manage.py            # Django management script
├── requirements.txt     # Python dependencies
└── Procfile             # Railway deployment config
```

---

## 🔧 How It Works

### 1. Authentication Flow

```
User clicks "Login with Google"
  ↓
OAuth2 consent screen (gmail.readonly + profile scopes)
  ↓
Google redirects back with authorization code
  ↓
Exchange code for access token + refresh token
  ↓
Store tokens in database (UserToken model)
  ↓
Redirect to dashboard
```

### 2. Email Scanning Flow

```
Dashboard loads
  ↓
Fetch latest 10 emails via Gmail API
  ↓
For each email:
  ├─ Extract headers, body, links, metadata
  ├─ Run through scanner.scan(email_dict, user_id)
  │   ├─ Header detector (SPF, DKIM, DMARC checks)
  │   ├─ Link detector (Safe Browsing API + pattern analysis)
  │   ├─ LLM detector (Gemini analyzes full body text)
  │   └─ Plugin detector (applies user's installed plugins)
  ├─ Aggregate scores from all detectors
  └─ Return ScanResult with verdict + flags
  ↓
Render results in dashboard UI
```

### 3. Plugin Detection Flow

```
User installs a plugin from marketplace
  ↓
Plugin rules stored in database (Plugin model)
  ↓
During email scan, plugin_detector.py:
  ├─ Loads all enabled plugins for user_id
  ├─ Applies rules based on plugin_type:
  │   ├─ blacklist: checks if sender matches any blacklisted domain
  │   ├─ keyword: searches body+subject for flagged phrases
  │   ├─ regex: runs patterns against body+subject
  │   └─ domain_list: whitelists trusted senders
  └─ Returns DetectionSignal with matched flags
```

---

## 🎨 Design Philosophy

**Dark, minimal, and functional** — the UI uses a cybersec-inspired dark theme with red accents. The design prioritizes clarity over decoration:

- **Monospace typography** for technical data (email addresses, scores, flags)
- **Sans-serif typography** for body text and descriptions
- **Color-coded verdicts**: red (phishing), amber (suspicious), green (safe)
- **Minimal animations**: subtle fade-ups on page load, no distracting motion
- **Mobile-first responsive grid** with graceful degradation

---

## 🛡️ Security Considerations

### What We Did Right

✅ **Read-only Gmail scope** — can't modify or delete emails  
✅ **No email storage** — scanned on-demand, immediately discarded  
✅ **OAuth 2.0 only** — no password handling  
✅ **Token refresh handled transparently** — users don't get logged out after 1 hour  
✅ **CSRF protection enabled** — Django's built-in middleware active  
✅ **Environment-based secrets** — credentials in env vars, not committed  
✅ **HTTPS enforcement in production** — `SECURE_PROXY_SSL_HEADER` configured  

### Known Limitations (Hackathon Scope)

⚠️ **SQLite resets on Railway redeployments** — data is ephemeral unless migrated to Postgres  
⚠️ **Session-based upvote tracking** — not persistent across browsers/devices  
⚠️ **No rate limiting on API endpoints** — could be abused if exposed publicly  
⚠️ **LLM costs scale with usage** — Gemini API calls are not cached  

---

## 🧪 Testing & Validation

### Manual Testing Checklist

- [x] OAuth login flow (Google consent → token exchange → dashboard)
- [x] Token refresh on expiry (transparent, no re-login required)
- [x] Email scanning across all 4 detection layers
- [x] Plugin install/uninstall + upvote toggle
- [x] Community report submission + upvote toggle
- [x] Filtering emails by verdict (ALL / PHISHING / SUSPICIOUS / SAFE)
- [x] Mobile responsive layout (nav, stats, cards)
- [x] Logout + token revocation

### Seed Data Commands

```bash
python manage.py seed_marketplace    # Creates 9 dummy plugins
python manage.py seed_community      # Creates 6 phishing reports
python manage.py ensure_superuser    # Creates admin user (for Django admin)
```

---

## 🚢 Deployment (Railway)

### Environment Variables

Set these in Railway's environment settings:

```
DEBUG=False
SECRET_KEY=<random-secret-key>
SITE_URL=https://your-app.up.railway.app
GOOGLE_CREDENTIALS_JSON=<base64-encoded-credentials.json>
GEMINI_API_KEY=<your-gemini-key>
SAFE_BROWSING_API_KEY=<your-safe-browsing-key>
EXTENSION_API_KEY=<optional-api-key-for-extension>
```

### Deployment Commands (Automated via Procfile)

Railway runs this on every deploy:

```bash
# Release phase (runs before starting web server)
python manage.py collectstatic --noinput
python manage.py migrate --noinput
python manage.py ensure_superuser
python manage.py seed_marketplace

# Web phase (starts Gunicorn)
gunicorn phishguard.wsgi --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

---

## 🎓 Lessons Learned

### What Worked Well

- **Modular detector architecture** — adding new detectors is trivial (just subclass `BaseDetector`)
- **Plugin marketplace as differentiator** — judges immediately understood the value
- **Seeded dummy data** — marketplace and community pages look alive from the start
- **OAuth token refresh** — silent refresh prevents the "logged out after 1 hour" UX issue

### What We'd Improve

- **Postgres from day one** — SQLite on Railway means data resets on every deploy
- **Caching for LLM calls** — identical emails get re-analyzed, wasting Gemini quota
- **Browser extension** — we built the backend API but ran out of time for the Chrome extension
- **Rate limiting** — API endpoints are unprotected, could be spammed

---

## 📜 License

This project was built for PoliHack 2026 by **Team Commitment Issues**.

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Google Cloud Platform** — Gmail API, Safe Browsing API, Gemini API
- **Railway** — Deployment platform
- **Anthropic Claude** — Code review, architecture guidance, and pair programming
- **PoliHack organizers** — For the opportunity to build something meaningful

---

## 👥 Team

**Commitment Issues**  
- [Petric Rares] — [WebExtension Developer, Gmail API]  
- [Tarnita Robert] — [Frontend Developer, Database Manager]  
- [Tcaciuc Rares] — [Backend Developer, Detection Algorithm Developer]  

---

## 📧 Contact

Questions? Feedback? Want to collaborate?

**Live Demo**: https://polihackcommitmentissues2026-production.up.railway.app/  
**GitHub**: https://github.com/owaseraph/PoliHack_CommitmentIssues_2026  
**Email**: [tcaciuc.rares.stefan@gmail.com]

---

Built with ❤️ for a safer internet.