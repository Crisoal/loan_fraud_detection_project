# fraud_detection/fraud_detection_engine.py

import os
from django.utils.timezone import now
from django.db.models import Q
from tenacity import retry, stop_after_attempt, wait_exponential
import requests

# Load fraud detection thresholds from environment variables
FRAUD_THRESHOLD_APPLICATIONS = int(os.getenv("FRAUD_THRESHOLD_APPLICATIONS", 3))
FRAUD_THRESHOLD_PROFILES = int(os.getenv("FRAUD_THRESHOLD_PROFILES", 2))
FRAUD_SCORE_THRESHOLD = int(os.getenv("FRAUD_SCORE_THRESHOLD", 50))  # Adaptive threshold for fraud detection

def calculate_fraud_score(loan_application):
    """
    Calculates a fraud score dynamically based on different fraud patterns.
    """
    fraud_score = 0
    reasons = []
    
    # Multiple loan applications from the same Visitor ID
    if loan_application.visitor_id and loan_application.visitor_id.loanapplication_set.count() > FRAUD_THRESHOLD_APPLICATIONS:
        fraud_score += 30
        reasons.append("Multiple applications from the same Visitor ID")
    
    # Multiple applications from the same device fingerprint
    if loan_application.device_fingerprint and loan_application.__class__.objects.filter(device_fingerprint=loan_application.device_fingerprint).exists():
        fraud_score += 40
        reasons.append("Multiple applications from the same device fingerprint")
    
    # Multiple users applying from the same IP address
    if loan_application.ip_address and loan_application.__class__.objects.filter(ip_address=loan_application.ip_address).exists():
        fraud_score += 30
        reasons.append("Multiple applications from the same IP address")
    
    return fraud_score, reasons

def detect_fraudulent_application(loan_application):
    """
    Flags fraudulent applications based on a dynamic fraud scoring system.
    """
    fraud_score, reasons = calculate_fraud_score(loan_application)
    
    # Flagging loan application if fraud score exceeds threshold
    if fraud_score > FRAUD_SCORE_THRESHOLD:
        from .models import FraudAlert  # Importing FraudAlert here to avoid circular import

        # Create a fraud alert linked to the loan application
        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=loan_application.visitor_id,
            reason=" | ".join(reasons),
        )
        
        # Mark the loan application as flagged
        loan_application.status = "flagged"
        loan_application.save()
        return True  # Fraud detected
    
    return False  # No fraud detected

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def get_fingerprint_visitor_id(data):
    """
    Calls the external fingerprint API with retry handling for robustness.
    """
    FINGERPRINT_API_URL = os.getenv("FINGERPRINT_API_URL")
    
    try:
        response = requests.post(FINGERPRINT_API_URL, json=data, timeout=5)
        response.raise_for_status()
        return response.json().get("visitorId")
    except requests.exceptions.RequestException as e:
        print(f"Fingerprint API request failed: {e}")
        return None
