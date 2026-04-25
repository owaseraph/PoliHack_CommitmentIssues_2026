import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-in-production")

# ✅ Safe default: False. Explicitly set DEBUG=True in local .env only.
# If this were True by default and you forgot to set it on Railway,
# Django would serve full tracebacks to anyone on the internet.
DEBUG = os.environ.get("DEBUG", "False") == "True"

ALLOWED_HOSTS = ["*"]

# Trust Railway/ngrok proxy headers so build_absolute_uri() returns the public URL
USE_X_FORWARDED_HOST    = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Set this to your public URL in Railway env vars (no trailing slash)
# e.g. SITE_URL=https://phishguard.up.railway.app
_railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
SITE_URL = os.environ.get("SITE_URL", "") or (f"https://{_railway_domain}" if _railway_domain else "")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "phishguard.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "phishguard.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "phishguard.db",
    }
}

# DB-backed sessions survive across multiple gunicorn workers.
# This is critical — an in-memory or cookie session would cause
# random OAuth login failures when gunicorn routes requests to
# different workers mid-flow.
SESSION_ENGINE      = "django.contrib.sessions.backends.db"
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE   = not DEBUG  # HTTPS-only cookies in production

# CSRF trusted origins — required for Railway/ngrok (non-localhost) deployments
_SITE_URL = SITE_URL.rstrip("/")
CSRF_TRUSTED_ORIGINS = [_SITE_URL] if _SITE_URL else []

LANGUAGE_CODE = "en-us"
TIME_ZONE     = "UTC"
USE_I18N      = True
USE_TZ        = True

STATIC_URL      = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT     = BASE_DIR / "staticfiles"
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"