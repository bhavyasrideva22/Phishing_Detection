import os
import pickle

# Training data embedded directly
TRAINING_DATA = [
    # Phishing examples
    ("Verify your account immediately or it will be suspended", "phishing"),
    ("Click here to update your bank password now", "phishing"),
    ("Your account has been locked verify your identity", "phishing"),
    ("Urgent action required confirm your credit card details", "phishing"),
    ("You have won a prize claim your reward now", "phishing"),
    ("Your PayPal account has been suspended click to restore", "phishing"),
    ("Login to confirm your banking information immediately", "phishing"),
    ("Security alert your account has suspicious activity", "phishing"),
    ("Update your password now before account expires", "phishing"),
    ("Confirm your social security number to unlock account", "phishing"),
    ("Wire transfer request please confirm your pin number", "phishing"),
    ("Your bitcoin wallet needs verification click here", "phishing"),
    ("Free gift card claim your reward before it expires", "phishing"),
    ("Unauthorized access detected update credentials now", "phishing"),
    ("Your debit card has been blocked verify immediately", "phishing"),
    ("Invoice attached please review and confirm payment", "phishing"),
    ("OTP required to complete account verification process", "phishing"),
    ("Limited time offer claim your lottery winnings today", "phishing"),
    ("Your Netflix account will be terminated verify now", "phishing"),
    ("Apple ID suspended please verify your information", "phishing"),
    ("Microsoft security team detected unusual sign-in activity", "phishing"),
    ("Your Amazon order was flagged please confirm payment", "phishing"),
    ("Bank of America account alert action required immediately", "phishing"),
    ("You have been selected for exclusive crypto investment", "phishing"),
    ("Password reset required for your account security", "phishing"),
    ("Verify your email to prevent account deletion today", "phishing"),
    ("Click to claim your tax refund from IRS immediately", "phishing"),
    ("Your DHL package is held click to pay customs fee", "phishing"),
    ("Congratulations you won confirm your details to receive", "phishing"),
    ("Your health insurance expires update payment information", "phishing"),

    # Safe examples
    ("Meeting scheduled for tomorrow at 3 PM in conference room", "safe"),
    ("Please find the project report attached for your review", "safe"),
    ("Happy birthday hope you have a wonderful day today", "safe"),
    ("The quarterly results show strong growth this year", "safe"),
    ("Can we reschedule our lunch meeting to next week", "safe"),
    ("Great job on the presentation everyone was impressed", "safe"),
    ("The weather forecast shows rain expected this weekend", "safe"),
    ("Please submit your timesheet by end of business Friday", "safe"),
    ("Team dinner is confirmed for Friday evening at seven", "safe"),
    ("The new product launch went very well exceeded targets", "safe"),
    ("Good morning hope your week is going well so far", "safe"),
    ("Can you send me the latest version of the document", "safe"),
    ("The conference call has been moved to Thursday afternoon", "safe"),
    ("Your flight booking confirmation is attached to this email", "safe"),
    ("Thank you for attending the webinar earlier today", "safe"),
    ("The office will be closed on Monday for the holiday", "safe"),
    ("Please review the attached contract and provide feedback", "safe"),
    ("Congratulations on your promotion well deserved achievement", "safe"),
    ("The team building event is next Friday at the park", "safe"),
    ("Updated guidelines are available in the shared drive folder", "safe"),
    ("Your interview is scheduled for Tuesday at ten AM", "safe"),
    ("Looking forward to our collaboration on this new project", "safe"),
    ("The training session has been postponed to next month", "safe"),
    ("Please bring your laptop to the all-hands meeting today", "safe"),
    ("The annual report has been approved by the board members", "safe"),
    ("Reminder your dental appointment is on Wednesday morning", "safe"),
    ("The server maintenance window is this Sunday from midnight", "safe"),
    ("All project files have been uploaded to the repository", "safe"),
    ("Your leave request has been approved enjoy your vacation", "safe"),
    ("The new intern starts on Monday please make them welcome", "safe"),
]

MODEL_PATH = 'phishing_model.pkl'
VECTORIZER_PATH = 'vectorizer.pkl'

def train_model():
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    import pickle

    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    pipeline = Pipeline([
        ('vectorizer', CountVectorizer(ngram_range=(1, 2), stop_words='english')),
        ('classifier', MultinomialNB())
    ])

    pipeline.fit(texts, labels)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)

    return pipeline

def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    return train_model()

# Load or train on startup
try:
    _model = load_model()
except Exception:
    _model = None

def predict_phishing(text):
    global _model
    if _model is None:
        try:
            _model = train_model()
        except Exception as e:
            return {'prediction': 'unknown', 'confidence': 0.0, 'error': str(e)}

    try:
        prediction = _model.predict([text])[0]
        probabilities = _model.predict_proba([text])[0]
        classes = _model.classes_
        confidence = float(max(probabilities))

        return {
            'prediction': prediction,
            'confidence': confidence,
            'probabilities': {cls: float(prob) for cls, prob in zip(classes, probabilities)}
        }
    except Exception as e:
        return {'prediction': 'unknown', 'confidence': 0.0, 'error': str(e)}

# Force train on first import
if _model is None:
    try:
        _model = train_model()
    except:
        pass
