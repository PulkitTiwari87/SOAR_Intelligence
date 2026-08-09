#!/usr/bin/env python3
"""
Module 3.3: NLP Phishing Parser
=================================
Analyzes email body text to detect phishing and Business Email Compromise (BEC).
Uses TF-IDF + Logistic Regression to classify email intent by:
  - Urgency signals ("immediately", "urgent", "within 24 hours")
  - Financial intent ("wire transfer", "bank account", "payment")
  - Authority impersonation ("CEO", "director", "IT department")
"""

import json
import os
import pickle
import re
import sys
import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "phishing_vectorizer.pkl")

PHISHING_EMAILS = [
    # --- BEC (Business Email Compromise) ---
    "Dear employee, the CEO has requested an immediate wire transfer of $50,000 to vendor account.",
    "Hi, I'm the new CFO. Please process this invoice payment urgently. Do not discuss with others.",
    "CEO Office: Please process reimbursement for my travel expenses attached. Handle personally.",
    "I need you to purchase gift cards for a client meeting today. Keep this confidential.",
    "Accounts Payable: Please update the vendor bank details to the following new account.",
    "This is the Managing Director. I need an urgent bank transfer of $35,000 processed today.",
    "Please wire $28,000 to the attached account. This is confidential and time-sensitive. - CEO",
    "Can you process a payment for me? I'm in a meeting and can't call. Need it done in 30 mins.",
    "The board approved bonuses. Send me a list of employee bank details for direct deposit.",
    "As discussed on our call, please transfer $42,000 to the new supplier account immediately.",
    # --- Credential Phishing ---
    "URGENT: Your account has been compromised. Click here immediately to reset your password.",
    "IT Department: Your mailbox is full. Verify your credentials within 24 hours or lose access.",
    "Action required: Suspicious login detected. Confirm your identity now to avoid account lockout.",
    "Microsoft 365: Your subscription is expiring. Renew immediately to avoid service disruption.",
    "Warning: Your email account will be deactivated unless you confirm your password today.",
    "IT Security: Mandatory password change required within 2 hours. Use this link.",
    "Your Google Workspace session has expired. Re-authenticate now to restore access.",
    "Zoom alert: Your meeting recordings will be deleted in 24 hours. Login to save them.",
    "Office 365: Multiple failed sign-in attempts. Secure your account immediately.",
    "Slack notification: Your workspace admin requires you to verify your account.",
    # --- Spear Phishing ---
    "Confidential: Salary adjustment notification. Login to HR portal to accept new terms.",
    "HR Department: Your tax documents are ready. Download them using your company credentials.",
    "IMPORTANT: Board meeting rescheduled. Download the updated agenda from this secure link.",
    "Your performance review results are available. Access the HR portal to view your rating.",
    "Annual bonus confirmation attached. Open the secure PDF to verify your compensation.",
    "Employee satisfaction survey results are in. Click here to see how your team scored.",
    # --- Delivery / Service Scams ---
    "Your package could not be delivered. Click the link to update your shipping information immediately.",
    "FedEx: Delivery failed. Reschedule your delivery by confirming your address here.",
    "Amazon: Your order #4829 has been placed. If this wasn't you, click here to cancel.",
    "Netflix: Your payment method has failed. Update your billing info to avoid suspension.",
    "Apple: Your iCloud storage is almost full. Upgrade now or risk losing your photos.",
    "DHL: A package is waiting for customs clearance. Pay the $2.99 fee to release it.",
    # --- Tech Support Scams ---
    "Security alert: Someone tried to access your account from Russia. Verify your identity now.",
    "Bank of America: Unusual activity detected on your account. Login now to secure your funds.",
    "Your DocuSign document is ready for signature. Click here to review and sign immediately.",
    "Windows Defender: Critical threat detected on your PC. Call this number immediately.",
    "Your antivirus subscription has expired. Your device is at risk. Renew now.",
    "PayPal: We noticed unusual activity. Verify your identity or your account will be limited.",
    # --- Account Takeover ---
    "Urgent payment reminder: Transfer the outstanding balance immediately to avoid penalties.",
    "Please review the attached invoice and authorize payment before end of business today.",
    "Your Dropbox shared folder access is expiring. Re-authenticate to keep your files.",
    "LinkedIn: Someone viewed your profile from an unrecognized device. Secure your account.",
    "Instagram: We detected a login from a new device. Click here to verify it was you.",
    "WhatsApp: Your account registration code is about to expire. Enter it now.",
    "Twitter/X Security: Unusual activity detected. Change your password immediately.",
    "Outlook Web App: Your session will expire in 15 minutes. Click here to stay signed in.",
    "Adobe Creative Cloud: License violation detected. Verify your subscription now.",
    "Coinbase: Withdrawal of 2.5 BTC initiated. If this wasn't you, cancel immediately.",
]

LEGITIMATE_EMAILS = [
    # --- Workplace Communication ---
    "Hi team, just a reminder about our weekly standup meeting tomorrow at 10 AM.",
    "The quarterly report has been published on the shared drive. Please review at your convenience.",
    "Congratulations to the sales team for exceeding Q3 targets! Great work everyone.",
    "Reminder: Office will be closed next Monday for the holiday. Enjoy the long weekend.",
    "The new employee handbook has been updated. You can find it on the company intranet.",
    "Team lunch this Friday at noon. Please let me know your dietary preferences.",
    "Project update: We've completed the first phase of the migration. Details in attached doc.",
    "Happy birthday, Sarah! Cake in the break room at 3 PM.",
    "Please submit your timesheets by end of day Friday. Thank you.",
    "FYI - the conference room on the 3rd floor will be under maintenance next week.",
    # --- IT / Admin ---
    "The new software license has been approved. IT will begin installation on Monday.",
    "Sharing the meeting notes from today's product review. Action items highlighted in yellow.",
    "Reminder to complete the annual compliance training by the end of the month.",
    "Great presentation today! The client was very impressed with the demo.",
    "Welcome aboard, Mike! Looking forward to working with you on the infrastructure team.",
    "Attached are the design mockups for the new dashboard. Feedback welcome.",
    "The firmware update for the office printers has been completed. No action needed.",
    "Our annual company picnic is scheduled for August 15th. RSVP on the events page.",
    "Meeting cancelled: The vendor postponed the demo to next Thursday. Calendar updated.",
    "The parking lot will be repaved this weekend. Please use the side entrance on Monday.",
    # --- Project Updates ---
    "Sprint retrospective notes are attached. Main action item: improve test coverage.",
    "The client signed off on the design. We can proceed to the development phase.",
    "Deployment to staging is complete. Please run your smoke tests when convenient.",
    "Here are the API documentation updates from the last release. Review at your leisure.",
    "Database migration will happen this Saturday from 2-4 AM. No action needed from your side.",
    "The accessibility audit results look great. Only minor issues in the footer component.",
    # --- HR / Operations ---
    "Open enrollment for health insurance begins next month. Details on the benefits portal.",
    "The company town hall is scheduled for next Wednesday at 2 PM. Attendance is optional.",
    "New parking passes are available at the front desk. Pick yours up this week.",
    "Flu shot clinic will be in Conference Room B next Tuesday from 10 AM to 2 PM.",
    "The recycling program has been expanded. New bins are in the kitchen area.",
    "Reminder: Submit your PTO requests for December by the end of this month.",
    # --- Casual / Social ---
    "Who's interested in joining the company softball team this season? Sign up by Friday.",
    "The coffee machine on the 4th floor is fixed! Back to our regular brew.",
    "Photos from the holiday party have been uploaded to the shared album. Great memories!",
    "Does anyone have recommendations for a good Italian restaurant near the office?",
    "Lost and found: A blue umbrella was left in the lobby. Claim it at reception.",
    "The book club meets next Thursday. We're reading 'Atomic Habits' by James Clear.",
    # --- Vendor / External ---
    "Thank you for attending our webinar. Here are the slides as promised.",
    "Your annual support contract has been renewed. No action required on your end.",
    "We've published our monthly product newsletter. Check out the new features.",
    "Meeting confirmed for Tuesday at 3 PM. Looking forward to discussing the partnership.",
    "The workshop materials are available on our portal. Access credentials unchanged.",
    "Thanks for your order. Estimated delivery is next Wednesday. Tracking link attached.",
    "Your subscription renewal has been processed. Receipt attached for your records.",
    "Invoice #3847 has been paid. Thank you for the prompt processing.",
    "The quarterly business review presentation is attached. See you Thursday.",
    "Conference registration is confirmed. Hotel block info will follow next week.",
]


def extract_features(text: str) -> dict:
    text_lower = text.lower()
    urgency = ["urgent", "immediately", "asap", "right now", "within 24 hours",
               "action required", "act now", "expiring", "deadline", "hurry"]
    financial = ["wire transfer", "payment", "invoice", "bank account", "purchase",
                 "gift card", "transfer", "reimbursement", "funds", "balance"]
    authority = ["ceo", "cfo", "director", "hr department", "it department",
                 "security", "board", "management", "confidential", "personally"]
    threat = ["compromised", "suspended", "deactivated", "locked", "unauthorized",
              "penalty", "lose access", "suspicious", "alert", "warning"]
    return {
        "urgency_count": sum(1 for w in urgency if w in text_lower),
        "financial_count": sum(1 for w in financial if w in text_lower),
        "authority_count": sum(1 for w in authority if w in text_lower),
        "threat_count": sum(1 for w in threat if w in text_lower),
        "has_link": 1 if re.search(r'(click|link|download|login|verify)', text_lower) else 0,
        "exclamation_marks": text.count("!"),
        "caps_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
        "text_length": len(text),
    }


def train_model():
    print("[*] Training NLP Phishing Parser...")
    emails = PHISHING_EMAILS + LEGITIMATE_EMAILS
    labels = [1] * len(PHISHING_EMAILS) + [0] * len(LEGITIMATE_EMAILS)
    vectorizer = TfidfVectorizer(max_features=500, stop_words='english', ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(emails)
    handcrafted = pd.DataFrame([extract_features(e) for e in emails])
    X = np.hstack([tfidf_matrix.toarray(), handcrafted.values])
    y = np.array(labels)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("\n[+] === Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
    print(f"[+] Model saved to {MODEL_PATH}")


def analyze_email(email_text: str) -> dict:
    if not os.path.exists(MODEL_PATH):
        train_model()
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)
    tfidf = vectorizer.transform([email_text])
    handcrafted = pd.DataFrame([extract_features(email_text)])
    X = np.hstack([tfidf.toarray(), handcrafted.values])
    proba = model.predict_proba(X)[0]
    score = round(float(proba[1]) * 100, 2)
    feat = extract_features(email_text)

    if score > 70:
        if feat["financial_count"] > 0 and feat["authority_count"] > 0:
            threat_type = "Business Email Compromise (BEC)"
        elif feat["has_link"] and feat["threat_count"] > 0:
            threat_type = "Credential Phishing"
        else:
            threat_type = "Generic Phishing"
    else:
        threat_type = "Legitimate Email"

    if score >= 80:
        action = "QUARANTINE — Block email and force password reset."
    elif score >= 50:
        action = "FLAG — Forward to SOC analyst for manual review."
    else:
        action = "ALLOW — Email appears legitimate."

    return {
        "phishing_score": score, "threat_type": threat_type, "action": action,
        "indicators": {
            "urgency_signals": feat["urgency_count"],
            "financial_intent": feat["financial_count"],
            "authority_impersonation": feat["authority_count"],
            "threat_language": feat["threat_count"],
            "contains_action_link": bool(feat["has_link"]),
        }
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_model()
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        result = analyze_email("URGENT: The CEO requests an immediate wire transfer of $25,000. Handle personally.")
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python nlp_phishing_parser.py --train | --test")
