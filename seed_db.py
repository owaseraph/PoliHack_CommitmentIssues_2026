"""
TrustGuard — comprehensive DB seed
Run from project root: python seed_db.py
Uses INSERT OR IGNORE so safe to re-run.
"""
import sqlite3, os
from config import Config

os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
conn = sqlite3.connect(Config.DB_PATH)
c = conn.cursor()

c.execute("CREATE TABLE IF NOT EXISTS links (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE, reputation INTEGER)")
c.execute("CREATE TABLE IF NOT EXISTS emails (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, reputation INTEGER)")

LINKS = [
    # ── Trusted (85-98) ──────────────────────────────────────────────────────
    ("https://google.com",          98),
    ("https://youtube.com",         96),
    ("https://github.com",          97),
    ("https://wikipedia.org",       97),
    ("https://mozilla.org",         95),
    ("https://anthropic.com",       98),
    ("https://openai.com",          96),
    ("https://microsoft.com",       95),
    ("https://apple.com",           96),
    ("https://amazon.com",          90),
    ("https://netflix.com",         92),
    ("https://spotify.com",         93),
    ("https://twitter.com",         88),
    ("https://linkedin.com",        91),
    ("https://reddit.com",          85),
    ("https://stackoverflow.com",   95),
    ("https://medium.com",          80),
    ("https://stripe.com",          96),
    ("https://notion.so",           90),
    ("https://cloudflare.com",      97),
    ("https://paypal.com",          93),
    ("https://chase.com",           94),
    ("https://bankofamerica.com",   94),
    ("https://wellsfargo.com",      92),
    ("https://irs.gov",             98),
    ("https://usa.gov",             98),
    ("https://cdc.gov",             97),
    ("https://nhs.uk",              97),
    ("https://bbc.com",             94),
    ("https://nytimes.com",         91),
    ("https://reuters.com",         93),
    # ── Suspicious / low-quality (35-55) ─────────────────────────────────────
    ("https://bit.ly",              45),
    ("https://tinyurl.com",         45),
    ("https://cutt.ly",             40),
    ("https://rebrand.ly",          42),
    ("https://t.co",                55),  # twitter shortener, semi-trusted
    # ── Known malicious (0-25) ───────────────────────────────────────────────
    ("https://login-paypal-secure.xyz",            5),
    ("https://free-iphone-winner.biz",             8),
    ("https://track-package-now.ru",               7),
    ("https://verify-account-update.com",          6),
    ("https://free-money-now.com",                 4),
    ("https://login-paypal-security.ru",           5),
    ("https://appleid-locked-verify.com",          6),
    ("https://amazon-prize-claim.net",             5),
    ("https://irs-gov-portal.net",                 8),
    ("https://secure-refund-verify.co",            7),
    ("https://tax-return-2026.info",               9),
    ("https://bankofamerica-alert.net",            6),
    ("https://chase-secure-login.biz",             5),
    ("https://microsoft-helpdesk.ru",              7),
    ("https://steam-trade-confirm.xyz",            8),
    ("https://netflix-payment-failed.com",         6),
    ("https://crypto-rewards-now.biz",            10),
    ("https://click-earn-daily.com",               8),
    ("https://login-facebook-verify.ru",           5),
    ("https://wellsfargo-secure-access.com",       6),
    ("https://dmv-online-renew.net",              12),
    ("https://covid-relief-fund.biz",              7),
    ("https://usps-delivery-confirm.info",         9),
]

EMAILS = [
    # ── Trusted (85-98) ──────────────────────────────────────────────────────
    ("noreply@google.com",          98),
    ("support@github.com",          97),
    ("hello@wikipedia.org",         97),
    ("noreply@twitter.com",         92),
    ("support@stripe.com",          97),
    ("no-reply@amazon.com",         91),
    ("info@anthropic.com",          98),
    ("hello@mozilla.org",           95),
    ("noreply@netflix.com",         92),
    ("support@paypal.com",          93),
    ("no-reply@apple.com",          96),
    ("alerts@chase.com",            94),
    ("service@bankofamerica.com",   93),
    ("contact@irs.gov",             98),
    ("noreply@linkedin.com",        92),
    ("hello@notion.so",             90),
    # ── Known malicious (0-20) ───────────────────────────────────────────────
    ("security@paypal-secure-login.xyz",           5),
    ("winner@free-prize-claim.biz",                4),
    ("admin@login-verify-account.ru",              6),
    ("noreply@appleid-locked.net",                 7),
    ("security@amazon-account-alert.tk",           5),
    ("billing@netflix-payment-failed.com",         6),
    ("alert@chase-secure-login.biz",               5),
    ("info@irs-tax-refund-pending.com",            4),
    ("refunds@irs-gov-portal.net",                 6),
    ("support@microsoft-helpdesk.ru",              7),
    ("no-reply@steam-trade-confirm.xyz",           8),
    ("support@paypal-secure-login.xyz",            5),
    ("offers@discount-meds.biz",                  12),
    ("verify@bankofamerica-alert.net",             6),
    ("contact@free-trials-now.com",               15),
    ("team@dropbox-storage-upgrade.tk",            8),
    ("security@wellsfargo-secure-access.com",      5),
    ("delivery@usps-delivery-confirm.info",        9),
    ("claims@covid-relief-fund.biz",               6),
    ("noreply@dmv-online-renew.net",              10),
]

c.executemany("INSERT OR IGNORE INTO links (url, reputation) VALUES (?,?)", LINKS)
c.executemany("INSERT OR IGNORE INTO emails (email, reputation) VALUES (?,?)", EMAILS)
conn.commit()

lcount = c.execute("SELECT COUNT(*) FROM links").fetchone()[0]
ecount = c.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
print(f"[OK] {lcount} links, {ecount} emails in {Config.DB_PATH}")
conn.close()