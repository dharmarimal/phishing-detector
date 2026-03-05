from flask import Flask, render_template, request, jsonify, send_file
import pickle
import os
import pandas as pd
import io
import sqlite3
from email import message_from_bytes, policy

app = Flask(__name__)

# Load trained model
vectorizer, model = pickle.load(open("model.pkl", "rb"))

# Initialize SQLite DB
DB_FILE = "recent.db"
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
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
conn.commit()


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    prediction_text = None
    confidence = 0
    sender = recipient = subject = email_body = ""

    # Get text from textarea or uploaded file
    if "email_file" in request.files and request.files["email_file"].filename != "":
        email_file = request.files["email_file"]
        msg = message_from_bytes(email_file.read(), policy=policy.default)
        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")
        email_body = msg.get_body(preferencelist=("plain"))
        email_body = email_body.get_content() if email_body else ""
        email_text = f"{subject} {email_body}"
    else:
        email_text = request.form.get("email", "")

    # Prediction
    text_vector = vectorizer.transform([email_text])
    result = model.predict(text_vector)[0]
    probability = model.predict_proba(text_vector)[0]

    if result == 1:
        confidence = round(probability[1] * 100, 2)
        prediction_text = f"⚠️ Phishing Email Detected ({confidence}% confidence)"
    else:
        confidence = round(probability[0] * 100, 2)
        prediction_text = f"✅ Email Looks Safe ({confidence}% confidence)"

    # Save to DB
    c.execute(
        "INSERT INTO recent (sender, recipient, subject, prediction, confidence, email_body) VALUES (?, ?, ?, ?, ?, ?)",
        (sender, recipient, subject, prediction_text, confidence, email_body)
    )
    conn.commit()

    # Get last 5 recent predictions
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


@app.route("/download_csv", methods=["GET"])
def download_csv():
    c.execute("SELECT sender, recipient, subject, prediction, confidence, email_body, timestamp FROM recent ORDER BY id DESC")
    rows = c.fetchall()
    df = pd.DataFrame(rows, columns=["Sender", "Recipient", "Subject", "Prediction", "Confidence", "Email Body", "Timestamp"])

    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="recent_predictions.csv")


@app.route("/clear_recent", methods=["POST"])
def clear_recent():
    try:
        c.execute("DELETE FROM recent")
        conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)