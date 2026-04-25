import sqlite3
import os
from config import Config


def get_connection():
    return sqlite3.connect(Config.DB_PATH,timeout=5)


def init_db():
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT UNIQUE,
            reputation INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT UNIQUE,
            reputation INTEGER
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Initialised at {Config.DB_PATH}")
