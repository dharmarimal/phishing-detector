from flask import Flask, render_template, request
import pickle

app = Flask(__name__)

# Load trained model
vectorizer, model = pickle.load(open("model.pkl", "rb"))

@app.route("/", methods=["GET", "POST"])
def home():
    prediction = None
    if request.method == "POST":
        email_text = request.form["email"]
        text_vector = vectorizer.transform([email_text])
        result = model.predict(text_vector)[0]
        if result == 1:
            prediction = "⚠️ Phishing Email Detected!"
        else:
            prediction = "✅ Email Looks Safe"
    return render_template("index.html", prediction=prediction)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
    app.run(debug=True)