import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / "history.db"

def get_connection():
    conn = sqlite3.connect(str(DB_NAME), timeout=10)
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id INTEGER,
            username TEXT,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            prediction TEXT,
            confidence REAL,
            email_body TEXT
        )
    """)
    c.execute("PRAGMA table_info(predictions)")
    columns = {row[1] for row in c.fetchall()}

    if "user_id" not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN user_id INTEGER")

    if "username" not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN username TEXT DEFAULT 'Unknown'")

    if "email_body" not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN email_body TEXT")

    c.execute("UPDATE predictions SET username = 'Unknown' WHERE username IS NULL OR username = ''")
    conn.commit()
    conn.close()

def add_prediction(sender, recipient, subject, prediction, confidence, user_id=None, username="Unknown", email_body=""):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO predictions (timestamp, user_id, username, sender, recipient, subject, prediction, confidence, email_body)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), user_id, username or "Unknown", sender, recipient, subject, prediction, confidence, email_body))
    conn.commit()
    conn.close()

def get_recent_predictions(limit=10):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, username, sender, recipient, subject, prediction, confidence, email_body
        FROM predictions
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows
