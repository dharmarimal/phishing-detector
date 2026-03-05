import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle

# Sample dataset of emails
data = {
    "email": [
        "Congratulations! You won a free iPhone",
        "Click this link to verify your bank account",
        "Meeting scheduled tomorrow at 10am",
        "Project update attached",
        "Urgent! Your account has been compromised"
    ],
    "label": [1, 1, 0, 0, 1]  # 1 = phishing, 0 = safe
}

df = pd.DataFrame(data)

# Convert text to numbers
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["email"])
y = df["label"]

# Train a simple model
model = LogisticRegression()
model.fit(X, y)

# Save vectorizer and model to a file
pickle.dump((vectorizer, model), open("model.pkl", "wb"))

print("Model trained and saved successfully!")