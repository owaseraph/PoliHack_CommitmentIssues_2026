import sqlite3
from config import Config

def get_connection():
    return sqlite3.connect(Config.DB_PATH)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            reputation INTEGER
        )
    """)

    conn.commit()
    conn.close()