# fraud_detection/services.py

import os
from django.utils.timezone import now
from django.db.models import Count, Q
from dotenv import load_dotenv
from .models import LoanApplication, VisitorID, FraudAlert

# Load environment variables
load_dotenv()

FRAUD_THRESHOLD_APPLICATIONS = int(os.getenv("FRAUD_THRESHOLD_APPLICATIONS", 3))  # e.g., 3 applications from same device
FRAUD_THRESHOLD_PROFILES = int(os.getenv("FRAUD_THRESHOLD_PROFILES", 2))  # e.g., 2+ profiles from same Visitor ID

def detect_fraudulent_application(loan_application):
    """
    Detects potential fraudulent loan applications based on:
    - Multiple applications from the same Visitor ID.
    - Multiple fake profiles linked to a single Visitor ID.
    - Repeated use of the same payment method.
    """
    visitor_id = loan_application.visitor_id
    user = loan_application.user
    ip_address = loan_application.ip_address

    fraud_reasons = []

    # 1️⃣ Detect multiple loan applications from the same Visitor ID
    recent_apps = LoanApplication.objects.filter(visitor_id=visitor_id).count()
    if recent_apps > FRAUD_THRESHOLD_APPLICATIONS:
        fraud_reasons.append(f"Visitor ID {visitor_id.visitor_id} submitted {recent_apps} loan applications.")

    # 2️⃣ Detect multiple fake profiles linked to the same Visitor ID
    linked_profiles = VisitorID.objects.filter(visitor_id=visitor_id.visitor_id).count()
    if linked_profiles > FRAUD_THRESHOLD_PROFILES:
        fraud_reasons.append(f"Visitor ID {visitor_id.visitor_id} linked to {linked_profiles} different users.")

    # 3️⃣ Detect multiple users using the same payment method (if stored)
    if hasattr(loan_application, "payment_method") and loan_application.payment_method:
        duplicate_payments = LoanApplication.objects.filter(payment_method=loan_application.payment_method).exclude(user=user).count()
        if duplicate_payments > 1:
            fraud_reasons.append(f"Payment method {loan_application.payment_method} used by multiple users.")

    # 4️⃣ Flag suspicious IPs (Optional)
    similar_ip_apps = LoanApplication.objects.filter(ip_address=ip_address).count()
    if similar_ip_apps > FRAUD_THRESHOLD_APPLICATIONS:
        fraud_reasons.append(f"IP {ip_address} used for {similar_ip_apps} loan applications.")

    # If any fraud reasons are found, flag the application
    if fraud_reasons:
        loan_application.status = "flagged"  # Flag application for manual review
        loan_application.save()

        # Create a fraud alert
        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=visitor_id,
            reason=" | ".join(fraud_reasons),
        )

        return True  # Fraud detected

    return False  # No fraud detected
