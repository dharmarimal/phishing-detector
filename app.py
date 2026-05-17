from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import pickle
import pandas as pd
import io
import sqlite3
from email import message_from_bytes, policy
from database import init_db, add_prediction
import threading
import webbrowser
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import re
from urllib.parse import urlparse
import uuid
import socket
from pathlib import Path

# -------------------- App Setup --------------------
app = Flask(__name__)
app.secret_key = "your_secret_key_here"
BASE_DIR = Path(__file__).resolve().parent

init_db()

# Load trained model
with open(BASE_DIR / "model.pkl", "rb") as model_file:
    vectorizer, model = pickle.load(model_file)

# SQLite DB
DB_FILE = BASE_DIR / "recent.db"


def get_db_connection():
    db = sqlite3.connect(str(DB_FILE), timeout=10)
    db.execute("PRAGMA busy_timeout = 10000")
    return db


def init_recent_db():
    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recent (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        sender TEXT,
        recipient TEXT,
        subject TEXT,
        prediction TEXT,
        confidence REAL,
        email_body TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.commit()
    db.close()

UPLOAD_FOLDER = BASE_DIR / "static" / "uploads" / "profiles"
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
DEFAULT_PROFILE_IMAGE = "default-profile.svg"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def ensure_user_columns():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = {row[1] for row in cursor.fetchall()}

    if "full_name" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")

    if "profile_image" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")

    if "status" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'approved'")

    cursor.execute("UPDATE users SET status = 'approved' WHERE status IS NULL OR status = ''")

    db.commit()
    db.close()


def ensure_recent_columns():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(recent)")
    columns = {row[1] for row in cursor.fetchall()}

    if "user_id" not in columns:
        cursor.execute("ALTER TABLE recent ADD COLUMN user_id INTEGER")

    if "username" not in columns:
        cursor.execute("ALTER TABLE recent ADD COLUMN username TEXT DEFAULT 'Unknown'")

    cursor.execute("UPDATE recent SET username = 'Unknown' WHERE username IS NULL OR username = ''")
    db.commit()
    db.close()


init_recent_db()
ensure_user_columns()
ensure_recent_columns()

default_avatar_path = os.path.join(UPLOAD_FOLDER, DEFAULT_PROFILE_IMAGE)
if not os.path.exists(default_avatar_path):
    with open(default_avatar_path, "w", encoding="utf-8") as avatar_file:
        avatar_file.write(
            """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160" role="img" aria-label="Default profile avatar">
<rect width="160" height="160" rx="32" fill="#dbeafe"/>
<circle cx="80" cy="60" r="28" fill="#2563eb"/>
<path d="M38 132c6-22 24-34 42-34s36 12 42 34" fill="#2563eb"/>
</svg>"""
        )

# Create default admin user for admin dashboard login if needed
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"


def get_history_connection():
    db = sqlite3.connect(str(BASE_DIR / "history.db"), timeout=10)
    db.execute("PRAGMA busy_timeout = 10000")
    return db


def is_admin_logged_in():
    return session.get("logged_in") is True


def is_user_logged_in():
    if session.get("user_logged_in") is not True:
        return False

    user = get_current_user()
    if not user or user["status"] != "approved":
        session.pop("user_logged_in", None)
        session.pop("username", None)
        return False

    return True


def get_user_by_username(username):
    db = get_db_connection()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, username, password, created_at, full_name, profile_image, status
        FROM users
        WHERE username = ?
        """,
        (username,)
    )
    user = cursor.fetchone()
    db.close()
    return user


def get_current_user():
    username = session.get("username")
    if not username:
        return None
    return get_user_by_username(username)


def get_admin_summary():
    db = get_history_connection()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM predictions")
    total_emails = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM predictions WHERE prediction = ?", ("Phishing",))
    phishing = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM predictions WHERE prediction = ?", ("Safe",))
    safe = cursor.fetchone()[0]
    db.close()

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    db.close()

    return {
        "total_emails": total_emails,
        "phishing": phishing,
        "safe": safe,
        "total_users": total_users
    }


def get_registered_users():
    db = get_db_connection()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, username, full_name, created_at, profile_image, status
        FROM users
        ORDER BY created_at DESC, id DESC
        """
    )
    users = cursor.fetchall()
    db.close()
    return users


def get_approved_user_filter_options():
    history_db = get_history_connection()
    history_cursor = history_db.cursor()
    history_cursor.execute(
        """
        SELECT user_id, COUNT(*)
        FROM predictions
        WHERE user_id IS NOT NULL
        GROUP BY user_id
        """
    )
    scan_counts = {row[0]: row[1] for row in history_cursor.fetchall()}
    history_db.close()

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, username
        FROM users
        WHERE status = ?
        ORDER BY username COLLATE NOCASE ASC
        """,
        ("approved",)
    )
    users = [
        {"id": row[0], "username": row[1], "scan_count": scan_counts.get(row[0], 0)}
        for row in cursor.fetchall()
    ]
    db.close()
    return users


def get_unassigned_email_scan_count():
    db = get_history_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM predictions
        WHERE user_id IS NULL OR username IS NULL OR username = '' OR username = 'Unknown'
        """
    )
    count = cursor.fetchone()[0]
    db.close()
    return count


def get_admin_email_rows(limit=None):
    db = get_history_connection()
    cursor = db.cursor()
    limit_clause = "LIMIT ?" if limit else ""
    params = (limit,) if limit else ()
    cursor.execute(
        f"""
        SELECT timestamp, user_id, username, sender, recipient, subject, prediction, confidence, email_body
        FROM predictions
        ORDER BY id DESC
        {limit_clause}
        """,
        params
    )
    rows = cursor.fetchall()
    db.close()
    return rows


def get_user_recent_predictions(user_id, limit=5):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT sender, recipient, subject, prediction
        FROM recent
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (user_id, limit)
    )
    rows = cursor.fetchall()
    db.close()
    return [f"From: {r[0]} | To: {r[1]} | Subject: {r[2]} | {r[3]}" for r in rows]


def get_profile_image_url(profile_image):
    filename = profile_image or DEFAULT_PROFILE_IMAGE
    return url_for("static", filename=f"uploads/profiles/{filename}")


def allowed_image_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def is_valid_email(email):
    return re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email or "") is not None


def get_password_validation_error(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."

    if not re.search(r"\d", password):
        return "Password must include at least one number."

    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."

    return None


def find_available_port(start_port):
    port = start_port
    while port < start_port + 20:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError(f"No available port found from {start_port} to {start_port + 19}.")


def save_profile_image(file_storage, username):
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        return None, "Please choose an image to upload."

    if not allowed_image_file(filename):
        return None, "Please upload a PNG, JPG, JPEG, GIF, or WEBP image."

    extension = filename.rsplit(".", 1)[1].lower()
    saved_name = f"{secure_filename(username)}-{uuid.uuid4().hex[:12]}.{extension}"
    file_storage.save(os.path.join(UPLOAD_FOLDER, saved_name))
    return saved_name, None


def analyze_email_rules(email_text):
    reasons = []
    score = 0
    text = email_text.lower()

    # 1. Urgent / threatening language
    urgent_words = [
        "urgent", "immediately", "verify now", "act now", "suspended",
        "limited time", "click here", "confirm now", "warning", "alert",
        "expired", "final notice", "asap", "your account will be closed"
    ]
    found_urgent = [word for word in urgent_words if word in text]
    if found_urgent:
        reasons.append("Urgent or threatening language detected")
        score += 20

    # 2. Sensitive information request
    sensitive_words = [
        "password", "bank account", "credit card", "debit card", "otp",
        "ssn", "social security", "login", "verify your account",
        "security code", "cvv", "pin"
    ]
    found_sensitive = [word for word in sensitive_words if word in text]
    if found_sensitive:
        reasons.append("Sensitive information request detected")
        score += 25

    # 3. Scam / prize wording
    scam_words = [
        "won", "winner", "gift card", "claim your prize",
        "lottery", "reward", "free vacation", "congratulations",
        "bonus", "cash reward", "exclusive offer"
    ]
    found_scam = [word for word in scam_words if word in text]
    if found_scam:
        reasons.append("Prize, reward, or scam-style wording detected")
        score += 20

    # 4. Suspicious links
    urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', email_text)
    shorteners = ["bit.ly", "tinyurl.com", "rb.gy", "goo.gl", "t.co"]
    trusted_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com"]

    if urls:
        reasons.append("Link detected in email")
        score += 10

        for url in urls:
            try:
                parsed = urlparse(url if url.startswith("http") else "http://" + url)
                domain = parsed.netloc.lower()

                # Shortened links
                if any(s in domain for s in shorteners):
                    reasons.append(f"Suspicious shortened link detected: {domain}")
                    score += 25

                # IP-based URLs
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                    reasons.append(f"IP-based link detected: {domain}")
                    score += 25

                # Unknown domain
                if domain and not any(td in domain for td in trusted_domains):
                    reasons.append(f"Untrusted or unknown domain: {domain}")
                    score += 10

            except Exception:
                continue

    # 5. Excessive punctuation
    if email_text.count("!") >= 3:
        reasons.append("Excessive punctuation detected")
        score += 10

    # 6. Common phishing action words
    action_words = [
        "verify", "update account", "reset password", "confirm identity",
        "unlock account", "avoid suspension", "click below"
    ]
    found_actions = [word for word in action_words if word in text]
    if found_actions:
        reasons.append("Common phishing action request detected")
        score += 15

    # 7. Safe indicators
    safe_words = [
        "meeting", "schedule", "attached report", "class", "assignment",
        "lecture", "team update", "invoice attached", "minutes of meeting",
        "project update", "agenda", "notes attached"
    ]
    found_safe = [word for word in safe_words if word in text]
    if found_safe and score < 25:
        reasons.append("Contains normal business or academic wording")

    if not reasons:
        reasons.append("No major phishing indicators detected")

    return reasons, score


# -------------------- Routes --------------------

# Default route
@app.route("/", methods=["GET"])
def home():
    if is_user_logged_in():
        user = get_current_user()
        if not user:
            return redirect(url_for("user_logout"))
        recent_predictions = get_user_recent_predictions(user["id"])
        return render_template(
            "index.html",
            user=user["full_name"] or user["username"],
            user_status=user["status"],
            profile_image_url=get_profile_image_url(user["profile_image"]),
            recent_predictions=recent_predictions
        )
    return redirect(url_for("user_login"))


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if not is_user_logged_in():
        return redirect(url_for("user_login"))

    user = get_current_user()
    if not user:
        return redirect(url_for("user_logout"))
    success = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()

        if name and email and message:
            success = "Thanks for reaching out. Our team will get back to you soon."

    return render_template(
        "contact.html",
        user=user["full_name"] or user["username"],
        profile_image_url=get_profile_image_url(user["profile_image"]),
        success=success
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not is_user_logged_in():
        return redirect(url_for("user_login"))

    user = get_current_user()
    if not user:
        return redirect(url_for("user_logout"))

    details_error = None
    details_success = None
    password_error = None
    password_success = None
    photo_error = None
    photo_success = None

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "update_details":
            full_name = request.form.get("full_name", "").strip()

            if len(full_name) < 2:
                details_error = "Please enter a valid name with at least 2 characters."
            else:
                db = get_db_connection()
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET full_name = ? WHERE id = ?",
                    (full_name, user["id"])
                )
                db.commit()
                db.close()
                details_success = "Your profile details were updated successfully."

        elif action == "change_password":
            current_password = request.form.get("current_password", "").strip()
            new_password = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()

            if not check_password_hash(user["password"], current_password):
                password_error = "Your current password is incorrect."
            elif len(new_password) < 8:
                password_error = "Your new password must be at least 8 characters long."
            elif new_password != confirm_password:
                password_error = "New password and confirmation do not match."
            elif current_password == new_password:
                password_error = "Choose a new password that is different from the current one."
            else:
                db = get_db_connection()
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(new_password), user["id"])
                )
                db.commit()
                db.close()
                password_success = "Your password has been changed successfully."

        elif action == "upload_photo":
            image = request.files.get("profile_image")
            if not image or image.filename == "":
                photo_error = "Please choose an image before uploading."
            else:
                saved_name, error = save_profile_image(image, user["username"])
                if error:
                    photo_error = error
                else:
                    old_image = user["profile_image"]
                    db = get_db_connection()
                    cursor = db.cursor()
                    cursor.execute(
                        "UPDATE users SET profile_image = ? WHERE id = ?",
                        (saved_name, user["id"])
                    )
                    db.commit()
                    db.close()

                    if old_image and old_image != DEFAULT_PROFILE_IMAGE:
                        old_path = os.path.join(UPLOAD_FOLDER, old_image)
                        if os.path.exists(old_path):
                            os.remove(old_path)

                    photo_success = "Your profile picture has been updated."

        user = get_current_user()

    display_name = user["full_name"] or user["username"]
    return render_template(
        "profile.html",
        user=user,
        display_name=display_name,
        profile_image_url=get_profile_image_url(user["profile_image"]),
        details_error=details_error,
        details_success=details_success,
        password_error=password_error,
        password_success=password_success,
        photo_error=photo_error,
        photo_success=photo_success
    )


# -------------------- Admin Auth --------------------

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


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("login"))


@app.route("/admin")
def admin():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    rows = get_admin_email_rows()
    summary = get_admin_summary()
    approved_users = get_approved_user_filter_options()
    unassigned_scan_count = get_unassigned_email_scan_count()
    rows_json = [
        {
            "timestamp": row[0],
            "user_id": row[1],
            "username": row[2],
            "sender": row[3],
            "recipient": row[4],
            "subject": row[5],
            "prediction": row[6],
            "confidence": row[7],
            "email_body": row[8]
        }
        for row in rows
    ]

    return render_template(
        "admin.html",
        rows=rows,
        rows_json=rows_json,
        summary=summary,
        approved_users=approved_users,
        unassigned_scan_count=unassigned_scan_count
    )


@app.route("/admin/users")
def admin_users():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    users = get_registered_users()
    summary = get_admin_summary()

    return render_template("admin_users.html", users=users, summary=summary)


@app.route("/admin/approve/<int:user_id>", methods=["POST"])
def admin_approve_user(user_id):
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET status = ? WHERE id = ?", ("approved", user_id))
    db.commit()
    db.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/reject/<int:user_id>", methods=["POST"])
def admin_reject_user(user_id):
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET status = ? WHERE id = ?", ("rejected", user_id))
    db.commit()
    db.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()

    return redirect(url_for("admin_users"))


@app.route("/admin_data")
def admin_data():
    if not is_admin_logged_in():
        return jsonify({"rows": [], "total_emails": 0, "phishing": 0, "safe": 0, "total_users": 0})

    rows = get_admin_email_rows()
    summary = get_admin_summary()
    approved_users = get_approved_user_filter_options()
    unassigned_scan_count = get_unassigned_email_scan_count()

    data_rows = []
    for r in rows:
        data_rows.append({
            "timestamp": r[0],
            "user_id": r[1],
            "username": r[2],
            "sender": r[3],
            "recipient": r[4],
            "subject": r[5],
            "prediction": r[6],
            "confidence": r[7],
            "email_body": r[8]
        })

    return jsonify({
        "rows": data_rows,
        "approved_users": approved_users,
        "unassigned_scan_count": unassigned_scan_count,
        **summary
    })


# -------------------- User Auth --------------------

@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password, status FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        if not user or not check_password_hash(user[2], password):
            error = "Invalid username or password"
        elif user[3] == "pending":
            error = "Account pending approval"
        elif user[3] == "rejected":
            error = "Account rejected"
        elif user[3] != "approved":
            error = "Account is not approved"
        else:
            session["user_logged_in"] = True
            session["username"] = user[1]
            return redirect(url_for("home"))

    return render_template("user_login.html", error=error)


@app.route("/user-signup", methods=["GET", "POST"])
def user_signup():
    error = None
    success = None
    form_data = {"full_name": "", "username": ""}

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()
        full_name = request.form.get("full_name", "").strip()
        form_data = {"full_name": full_name, "username": username}

        if not full_name or not username or not password:
            error = "Full name, email address, and password are required."
            return render_template("user_signup.html", error=error, success=success, form_data=form_data)

        if len(full_name) < 2:
            error = "Full name must be at least 2 characters long."
            return render_template("user_signup.html", error=error, success=success, form_data=form_data)

        if not is_valid_email(username):
            error = "Please enter a valid email address, for example name@example.com."
            return render_template("user_signup.html", error=error, success=success, form_data=form_data)

        password_error = get_password_validation_error(password)
        if password_error:
            return render_template("user_signup.html", error=password_error, success=success, form_data=form_data)

        hashed_password = generate_password_hash(password)

        db = None
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, password, full_name, profile_image, status) VALUES (?, ?, ?, ?, ?)",
                (username, hashed_password, full_name or username, DEFAULT_PROFILE_IMAGE, "pending")
            )
            db.commit()
            db.close()
            return redirect(url_for("signup_pending"))
        except sqlite3.IntegrityError:
            error = "An account with this email address already exists."
        except Exception as e:
            error = f"Error: {str(e)}"
        finally:
            if db:
                db.close()

    return render_template("user_signup.html", error=error, success=success, form_data=form_data)


@app.route("/signup-pending")
def signup_pending():
    return render_template("signup_pending.html")


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

    current_user = get_current_user()
    user_id = current_user["id"] if current_user else None
    scan_username = current_user["username"] if current_user else "Unknown"

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
        email_body = email_text

    if not email_text:
        return jsonify({"error": "No email content provided"}), 400

    # ML Prediction
    text_vector = vectorizer.transform([email_text])
    result = model.predict(text_vector)[0]
    probability = model.predict_proba(text_vector)[0]

    if result == 1:
        confidence = round(probability[1] * 100, 2)
        prediction_text = "Phishing"
    else:
        confidence = round(probability[0] * 100, 2)
        prediction_text = "Safe"

    # Rule-based analysis
    reasons, rule_score = analyze_email_rules(email_text)

    # Hybrid confidence adjustment
    if prediction_text == "Phishing":
        confidence = min(99.0, round((confidence * 0.7) + (rule_score * 0.3), 2))
    else:
        confidence = max(1.0, round(confidence - (rule_score * 0.2), 2))

    # Save to recent DB
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        INSERT INTO recent (user_id, username, sender, recipient, subject, prediction, confidence, email_body)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, scan_username, sender, recipient, subject, prediction_text, confidence, email_body)
    )
    db.commit()

    # Save to persistent DB
    add_prediction(sender, recipient, subject, prediction_text, confidence, user_id, scan_username, email_body)

    # Last 5 predictions for the current user
    cursor.execute(
        """
        SELECT sender, recipient, subject, prediction
        FROM recent
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (user_id,)
    )
    recent = [f"From: {r[0]} | To: {r[1]} | Subject: {r[2]} | {r[3]}" for r in cursor.fetchall()]
    db.close()

    return jsonify({
        "prediction": prediction_text,
        "confidence": confidence,
        "reasons": reasons,
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

    rows = get_admin_email_rows()
    csv_rows = [
        (row[0], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
        for row in rows
    ]

    df = pd.DataFrame(
        csv_rows,
        columns=["Timestamp", "Scanned By", "Sender", "Recipient", "Subject", "Prediction", "Confidence", "Email Body"]
    )

    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="all_predictions.csv"
    )


# -------------------- Clear Recent Predictions --------------------

@app.route("/user_clear_recent", methods=["POST"])
def user_clear_recent():
    if not is_user_logged_in():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    try:
        db = get_db_connection()
        cursor = db.cursor()
        history_db = get_history_connection()
        history_cursor = history_db.cursor()

        cursor.execute(
            """
            DELETE FROM recent
            WHERE user_id = ? OR username = ?
            """,
            (current_user["id"], current_user["username"])
        )
        history_cursor.execute(
            """
            DELETE FROM predictions
            WHERE user_id = ? OR username = ?
            """,
            (current_user["id"], current_user["username"])
        )

        db.commit()
        history_db.commit()
        db.close()
        history_db.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/clear_recent", methods=["POST"])
def clear_recent():
    if not is_admin_logged_in():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    try:
        db = get_db_connection()
        cursor = db.cursor()
        history_db = get_history_connection()
        history_cursor = history_db.cursor()

        cursor.execute("DELETE FROM recent")
        history_cursor.execute("DELETE FROM predictions")
        db.commit()
        history_db.commit()
        db.close()
        history_db.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -------------------- Run App with Auto-Open --------------------
if __name__ == "__main__":
    if os.environ.get("PHISHING_DETECTOR_PORT"):
        port = int(os.environ["PHISHING_DETECTOR_PORT"])
    else:
        preferred_port = int(os.environ.get("PORT", 5001))
        port = find_available_port(preferred_port)
        os.environ["PHISHING_DETECTOR_PORT"] = str(port)

    url = f"http://127.0.0.1:{port}/user-login"

    # Open browser automatically only in main process to avoid duplicate tabs
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    app.run(debug=True, host="0.0.0.0", port=port)
