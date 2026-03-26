#!/bin/bash

# Create folder structure
mkdir -p phishing-detector/templates
mkdir -p phishing-detector/static

# 1) requirements.txt
cat > phishing-detector/requirements.txt <<EOL
flask
scikit-learn
pandas
numpy
scipy
gunicorn
EOL

# 2) app.py
cat > phishing-detector/app.py <<'EOL'
from flask import Flask, render_template, request, jsonify, send_file
import pickle
import os
import pandas as pd
import io
import sqlite3
from email import message_from_bytes, policy

app = Flask(__name__)

vectorizer, model = pickle.load(open("model.pkl", "rb"))

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

    if "email_file" in request.files and request.files["email_file"].filename != "":
        email_file = request.files["email_file"]
        msg = message_from_bytes(email_file.read(), policy=policy.default)
        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")
        text_body = msg.get_body(preferencelist=("plain"))
        email_body = text_body.get_content() if text_body else ""
        email_text = f"{subject} {email_body}"
    else:
        email_text = request.form.get("email", "")

    text_vector = vectorizer.transform([email_text])
    result = model.predict(text_vector)[0]
    probability = model.predict_proba(text_vector)[0]

    if result == 1:
        confidence = round(probability[1] * 100, 2)
        prediction_text = f"⚠️ Phishing Email Detected ({confidence}% confidence)"
    else:
        confidence = round(probability[0] * 100, 2)
        prediction_text = f"✅ Email Looks Safe ({confidence}% confidence)"

    c.execute(
        "INSERT INTO recent (sender, recipient, subject, prediction, confidence, email_body) VALUES (?, ?, ?, ?, ?, ?)",
        (sender, recipient, subject, prediction_text, confidence, email_body)
    )
    conn.commit()

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
EOL

# 3) templates/index.html
cat > phishing-detector/templates/index.html <<'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phishing Email Detector</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
<header>
    <div class="header-container">
        <h1>Phishing Email Detector</h1>
        <a href="https://github.com/dharmarimal/phishing-detector" target="_blank" class="github-link">GitHub Repo</a>
    </div>
</header>

<div class="container">
    <p>Paste your email text or upload a <strong>.eml</strong> file to check for phishing.</p>

    <label class="switch">
        <input type="checkbox" id="darkModeToggle">
        <span class="slider round"></span> Dark Mode
    </label>

    <form method="POST" enctype="multipart/form-data" id="emailForm">
        <textarea name="email" placeholder="Paste email text here..." rows="8"></textarea>
        <input type="file" name="email_file" accept=".eml">
        <button type="submit">Check Email</button>
    </form>

    <div id="latestResult"></div>
    <div class="email-body"></div>

    <div class="recent">
        <h3>Recent Predictions</h3>
        <button onclick="downloadCSV()" class="copyBtn">Download CSV</button>
        <button onclick="clearRecent()" class="copyBtn danger">Clear Recent</button>
        <ul id="recentList"></ul>
    </div>
</div>

<footer>
    <p>Made by Dharma Rimal | <a href="https://github.com/dharmarimal" target="_blank">My GitHub</a></p>
</footer>

<script>
const toggle = document.getElementById('darkModeToggle');
toggle.addEventListener('change', () => document.body.classList.toggle('dark-mode'));

function copyText(text) { navigator.clipboard.writeText(text).then(() => alert('Copied!')); }
function downloadCSV() { window.location.href = "/download_csv"; }
function clearRecent() {
    if(!confirm("Are you sure?")) return;
    fetch("/clear_recent", { method:"POST" }).then(r=>r.json()).then(d=>{ if(d.status=="success"){ document.getElementById('recentList').innerHTML=""; alert("Cleared!"); }});
}

const form = document.getElementById('emailForm');
const latestDiv = document.getElementById('latestResult');
const emailBodyDiv = document.querySelector('.email-body');
const recentList = document.getElementById('recentList');

form.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const formData = new FormData(form);
    const res = await fetch("/predict",{method:"POST", body:formData});
    const data = await res.json();
    let color = data.confidence>80?'red':data.confidence>50?'orange':'green';
    latestDiv.className = data.prediction.includes('⚠️')?'result danger':'result safe';
    latestDiv.innerHTML = `${data.sender?`<p><strong>From:</strong>${data.sender}</p>`:''}${data.recipient?`<p><strong>To:</strong>${data.recipient}</p>`:''}${data.subject?`<p><strong>Subject:</strong>${data.subject}</p>`:''}<p>${data.prediction}</p><div class="confidence-bar"><div class="fill" style="width:${data.confidence}%; background:${color}"></div></div><button class="copyBtn" onclick="copyText('From: ${data.sender}\\nTo: ${data.recipient}\\nSubject: ${data.subject}\\n${data.prediction}')">Copy</button>`;
    emailBodyDiv.innerHTML = `<h4>Email Body Preview:</h4><pre>${data.email_body}</pre>`;
    recentList.innerHTML='';
    data.recent.forEach(item=>{
        const li=document.createElement('li'); li.textContent=item; const btn=document.createElement('button'); btn.textContent='Copy'; btn.className='copyBtn'; btn.onclick=()=>copyText(item); li.appendChild(btn); recentList.appendChild(li);
    });
});
</script>
</body>
</html>
EOL

# 4) static/style.css
cat > phishing-detector/static/style.css <<'EOL'
body.dark-mode { background-color:#1e1e1e; color:#f5f5f5; }
.result.safe { background-color:#2ecc71; padding:10px; margin:10px 0; border-radius:5px; color:white; }
.result.danger { background-color:#e74c3c; padding:10px; margin:10px 0; border-radius:5px; color:white; }
button.copyBtn { padding:5px 10px; margin-top:5px; cursor:pointer; }
button.danger { background-color:#e74c3c; color:white; }
button.danger:hover { background-color:#c0392b; }
EOL

# 5) Zip the folder
zip -r phishing-detector.zip phishing-detector
echo "ZIP created: phishing-detector.zip"

