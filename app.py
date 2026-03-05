from flask import Flask, render_template, request
import pickle
import os
from email import policy
from email.parser import BytesParser

app = Flask(__name__)

# Load trained model
vectorizer, model = pickle.load(open("model.pkl", "rb"))

@app.route("/", methods=["GET", "POST"])
def home():
    prediction = None
    if request.method == "POST":
        email_text = ""

        # Check if text was entered
        if request.form.get("email"):
            email_text = request.form["email"]

        # Check if file was uploaded
        if "email_file" in request.files:
            file = request.files["email_file"]
            if file.filename.endswith(".eml"):
                raw_bytes = file.read()
                msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                # Combine subject + body as text
                subject = msg["subject"] or ""
                body = msg.get_body(preferencelist=("plain"))
                body_text = body.get_content() if body else ""
                email_text = subject + "\n" + body_text

        if email_text.strip() != "":
            text_vector = vectorizer.transform([email_text])
            result = model.predict(text_vector)[0]
            probability = model.predict_proba(text_vector)[0]

            if result == 1:
                confidence = round(probability[1] * 100, 2)
                prediction = f"⚠️ Phishing Email Detected ({confidence}% confidence)"
            else:
                confidence = round(probability[0] * 100, 2)
                prediction = f"✅ Email Looks Safe ({confidence}% confidence)"

    return render_template("index.html", prediction=prediction)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)