import sqlite3
from datetime import datetime

DB_NAME = "history.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            prediction TEXT,
            confidence REAL
        )
    """)
    conn.commit()
    conn.close()

def add_prediction(sender, recipient, subject, prediction, confidence):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        INSERT INTO predictions (timestamp, sender, recipient, subject, prediction, confidence)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), sender, recipient, subject, prediction, confidence))
    conn.commit()
    conn.close()

def get_recent_predictions(limit=10):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, sender, recipient, subject, prediction, confidence
        FROM predictions
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows