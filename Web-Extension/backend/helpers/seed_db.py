import sqlite3
from config import Config

conn = sqlite3.connect(Config.DB_PATH)
c = conn.cursor()

c.execute("CREATE TABLE IF NOT EXISTS links (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE, reputation INTEGER)")
c.execute("CREATE TABLE IF NOT EXISTS emails (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, reputation INTEGER)")

c.executemany("INSERT OR IGNORE INTO links (url, reputation) VALUES (?, ?)", [
    ("https://google.com", 95),
    ("https://github.com", 92),
    ("https://wikipedia.org", 93),
    ("https://anthropic.com", 94),
    ("https://mozilla.org", 91),
    ("https://reddit.com", 72),
    ("https://medium.com", 68),
    ("https://free-iphone-winner.biz", 25),
    ("https://login-paypal-secure.xyz", 15),
    ("https://track-package-now.ru", 20),
    ("https://bit.ly/3xfakelink", 35),
    ("https://verify-account-update.com", 12),
    ("https://free-money-now.com", 10),
])

c.executemany("INSERT OR IGNORE INTO emails (email, reputation) VALUES (?, ?)", [
    ("support@google.com", 95),
    ("noreply@github.com", 90),
    ("info@anthropic.com", 94),
    ("hello@mozilla.org", 91),
    ("hello@linkedin.com", 89),
    ("noreply@twitter.com", 88),
    ("support@stripe.com", 92),
    ("support@paypal-secure-login.xyz", 10),
    ("winner@free-prize-claim.biz", 5),
    ("admin@login-verify-account.ru", 12),
    ("noreply@appleid-locked.net", 15),
    ("security@amazon-account-alert.tk", 8),
    ("billing@netflix-payment-failed.com", 7),
    ("alert@chase-secure-login.biz", 6),
    ("info@irs-tax-refund-pending.com", 4),
    ("contact@free-trials-now.com", 30),
    ("offers@discount-meds.biz", 28),
])

conn.commit()
conn.close()
print("done")
