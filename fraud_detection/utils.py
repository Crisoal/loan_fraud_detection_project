# fraud_detection/utils.py

import os
import requests
import logging
from datetime import timedelta
from django.utils.timezone import now
from django.core.mail import send_mail
from django.conf import settings
from tenacity import retry, stop_after_attempt, wait_fixed
from .models import LoanApplication, VisitorID, FraudAlert
from .fraud_detection_engine import detect_fraudulent_application

# Load API credentials
FINGERPRINT_API_KEY = os.getenv("FINGERPRINT_API_KEY")
FINGERPRINT_API_URL = os.getenv("FINGERPRINT_API_URL")

logger = logging.getLogger(__name__)

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_fingerprint_visitor_id(device_info):
    """
    Retrieves the unique visitor ID using the fingerprint API.
    Implements a retry mechanism for robustness.
    """
    try:
        response = requests.post(
            FINGERPRINT_API_URL,
            json={"device_info": device_info},
            headers={"Authorization": f"Bearer {FINGERPRINT_API_KEY}"},
            timeout=5
        )
        response.raise_for_status()
        return response.json().get("visitor_id")
    except requests.exceptions.RequestException as e:
        logger.error(f"Fingerprint API request failed: {e}")
        return None

def detect_fraud(loan_application):
    """
    Checks for fraudulent activity using predefined criteria.
    """
    fraud_reasons = []
    
    # Detect fraud using the fraud detection engine
    fraud_detected, reasons = detect_fraudulent_application(loan_application)
    if fraud_detected:
        fraud_reasons.extend(reasons)

    # Flag loan application if fraud is detected
    if fraud_reasons:
        loan_application.status = "flagged"
        loan_application.save()

        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=loan_application.visitor_id,
            reason=" | ".join(fraud_reasons),
        )

        # Send an email notification for flagged applications
        send_mail(
            "Fraud Alert - Loan Application",
            f"A loan application has been flagged for fraud. Details:\n\n{loan_application}\n\nReasons: {', '.join(fraud_reasons)}",
            settings.DEFAULT_FROM_EMAIL,
            [settings.ADMIN_EMAIL],
            fail_silently=True,
        )

        return True  # Fraud detected

    return False  # No fraud detected

def store_visitor_data(request):
    """
    Stores visitor data and returns the visitor ID.
    """
    client_ip = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "Unknown")
    
    # Get or create visitor ID
    visitor_id = get_fingerprint_visitor_id({
        "ip": client_ip,
        "user_agent": user_agent
    })
    
    if visitor_id:
        visitor, created = VisitorID.objects.get_or_create(
            visitor_id=visitor_id,
            defaults={
                "ip_address": client_ip,
                "device_fingerprint": request.headers.get("Device-Fingerprint", None)
            }
        )
        return visitor_id
    
    return None

def flag_suspicious_application(loan_app):
    """
    Checks if a loan application is suspicious based on fraud patterns.
    """
    fraud_detected = detect_fraudulent_application(loan_app)
    if fraud_detected:
        # Send email notification
        send_mail(
            "Suspicious Loan Application Detected",
            f"Loan application {loan_app.id} has been flagged for fraud review.",
            settings.DEFAULT_FROM_EMAIL,
            [settings.ADMIN_EMAIL],
            fail_silently=True,
        )
    return fraud_detected