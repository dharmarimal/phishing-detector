from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import pickle
import pandas as pd
import io
import sqlite3
from email import message_from_bytes, policy
from database import init_db, add_prediction, get_recent_predictions
from datetime import datetime
import threading
import webbrowser
import os
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------- App Setup --------------------
app = Flask(__name__)
app.secret_key = "your_secret_key_here"

init_db()

# Load trained model
vectorizer, model = pickle.load(open("model.pkl", "rb"))

# SQLite DB
DB_FILE = "recent.db"
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()

# Recent predictions table
c.execute("""
CREATE TABLE IF NOT EXISTS recent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    recipient TEXT,
    subject TEXT,
    prediction TEXT,
    confidence REAL,
    email_body TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# User table
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()

# Create default admin user for admin dashboard login if needed
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"


# -------------------- Helper Functions --------------------
def get_db_connection():
    return sqlite3.connect(DB_FILE)


def is_admin_logged_in():
    return session.get("logged_in") is True


def is_user_logged_in():
    return session.get("user_logged_in") is True


# -------------------- Routes --------------------

# Default route
@app.route("/", methods=["GET"])
def home():
    if is_user_logged_in():
        return render_template("index.html", user=session.get("username"))
    return redirect(url_for("user_login"))


# -------------------- Admin Auth --------------------

# Admin login
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            session["admin_username"] = username
            return redirect(url_for("admin"))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


# Admin logout
@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("login"))


# Admin dashboard
@app.route("/admin")
def admin():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    rows = get_recent_predictions(100)
    phishing = sum(1 for r in rows if r[4] == "Phishing")
    safe = sum(1 for r in rows if r[4] == "Safe")

    return render_template("admin.html", rows=rows, phishing=phishing, safe=safe)


# Admin JSON data for live updates
@app.route("/admin_data")
def admin_data():
    if not is_admin_logged_in():
        return jsonify({"rows": [], "phishing": 0, "safe": 0})

    rows = get_recent_predictions(100)
    phishing = sum(1 for r in rows if r[4] == "Phishing")
    safe = sum(1 for r in rows if r[4] == "Safe")

    data_rows = []
    for r in rows:
        data_rows.append({
            "sender": r[1],
            "recipient": r[2],
            "subject": r[3],
            "prediction": r[4]
        })

    return jsonify({"rows": data_rows, "phishing": phishing, "safe": safe})


# -------------------- User Auth --------------------

@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user[2], password):
            session["user_logged_in"] = True
            session["username"] = user[1]
            return redirect(url_for("home"))
        else:
            error = "Invalid username or password"

    return render_template("user_login.html", error=error)


@app.route("/user-signup", methods=["GET", "POST"])
def user_signup():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            error = "Username and password are required"
            return render_template("user_signup.html", error=error, success=success)

        hashed_password = generate_password_hash(password)

        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            db.commit()
            db.close()
            return redirect(url_for("user_login"))
        except sqlite3.IntegrityError:
            error = "Username already exists"
        except Exception as e:
            error = f"Error: {str(e)}"

    return render_template("user_signup.html", error=error, success=success)


@app.route("/user-logout")
def user_logout():
    session.pop("user_logged_in", None)
    session.pop("username", None)
    return redirect(url_for("user_login"))


# -------------------- Prediction --------------------

@app.route("/predict", methods=["POST"])
def predict():
    if not is_user_logged_in():
        return jsonify({"error": "Unauthorized"}), 401

    prediction_text = None
    confidence = 0
    sender = ""
    recipient = ""
    subject = ""
    email_body = ""

    # Get text from textarea or uploaded file
    if "email_file" in request.files and request.files["email_file"].filename != "":
        email_file = request.files["email_file"]
        msg = message_from_bytes(email_file.read(), policy=policy.default)

        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")

        email_body_obj = msg.get_body(preferencelist=("plain"))
        email_body = email_body_obj.get_content() if email_body_obj else ""

        email_text = f"{subject} {email_body}"
    else:
        email_text = request.form.get("email", "").strip()

    if not email_text:
        return jsonify({"error": "No email content provided"}), 400

    # Prediction
    text_vector = vectorizer.transform([email_text])
    result = model.predict(text_vector)[0]
    probability = model.predict_proba(text_vector)[0]

    if result == 1:
        confidence = round(probability[1] * 100, 2)
        prediction_text = "Phishing"
    else:
        confidence = round(probability[0] * 100, 2)
        prediction_text = "Safe"

    # Save to recent DB
    c.execute(
        """
        INSERT INTO recent (sender, recipient, subject, prediction, confidence, email_body)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (sender, recipient, subject, prediction_text, confidence, email_body)
    )
    conn.commit()

    # Save to persistent DB
    add_prediction(sender, recipient, subject, prediction_text, confidence)

    # Last 5 predictions
    c.execute("SELECT sender, recipient, subject, prediction FROM recent ORDER BY id DESC LIMIT 5")
    recent = [f"From: {r[0]} | To: {r[1]} | Subject: {r[2]} | {r[3]}" for r in c.fetchall()]

    return jsonify({
        "prediction": prediction_text,
        "confidence": confidence,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "email_body": email_body,
        "recent": recent
    })


# -------------------- CSV Download --------------------

@app.route("/download_csv")
def download_csv():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    c.execute("""
        SELECT sender, recipient, subject, prediction, confidence, email_body, timestamp
        FROM recent
        ORDER BY id DESC
    """)
    rows = c.fetchall()

    df = pd.DataFrame(
        rows,
        columns=["Sender", "Recipient", "Subject", "Prediction", "Confidence", "Email Body", "Timestamp"]
    )

    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="recent_predictions.csv"
    )


# -------------------- Clear Recent Predictions --------------------

@app.route("/clear_recent", methods=["POST"])
def clear_recent():
    if not is_admin_logged_in() and not is_user_logged_in():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    try:
        c.execute("DELETE FROM recent")
        conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -------------------- Run App with Auto-Open --------------------
if __name__ == "__main__":
    port = 5000
    url = f"http://127.0.0.1:{port}/user-login"

    # Open browser automatically only in main process to avoid duplicate tabs
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    app.run(debug=True, host="0.0.0.0", port=port)