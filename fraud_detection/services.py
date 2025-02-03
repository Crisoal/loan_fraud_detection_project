# fraud_detection/services.py

import os
from django.db.models import Q
from dotenv import load_dotenv
from .models import LoanApplication, VisitorID, FraudAlert
from .fraud_detection_engine import detect_fraudulent_application

# Load environment variables
load_dotenv()

FRAUD_THRESHOLD_APPLICATIONS = int(os.getenv("FRAUD_THRESHOLD_APPLICATIONS", 3))
FRAUD_THRESHOLD_PROFILES = int(os.getenv("FRAUD_THRESHOLD_PROFILES", 2))

def check_for_fraud_and_flag(loan_application):
    """
    Runs fraud detection on a loan application and flags it if necessary.
    """
    fraud_detected, reasons = detect_fraudulent_application(loan_application)

    if fraud_detected:
        loan_application.status = "flagged"
        loan_application.save()

        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=loan_application.visitor_id,
            reason=" | ".join(reasons),
        )

        return True  # Fraud detected

    return False  # No fraud detected

def get_loan_statistics():
    """
    Retrieves statistics for loan applications, such as flagged and approved applications.
    """
    total_loans = LoanApplication.objects.count()
    flagged_loans = LoanApplication.objects.filter(status="flagged").count()
    approved_loans = LoanApplication.objects.filter(status="approved").count()

    return {
        "total_loans": total_loans,
        "flagged_loans": flagged_loans,
        "approved_loans": approved_loans,
    }

def get_visitor_fraud_summary(visitor_id):
    """
    Checks if a visitor has been involved in fraudulent activities.
    """
    flagged_loans = LoanApplication.objects.filter(visitor_id=visitor_id, status="flagged").exists()
    fraud_alerts = FraudAlert.objects.filter(visitor_id=visitor_id).exists()

    return {
        "visitor_id": visitor_id.visitor_id,
        "flagged_loans": flagged_loans,
        "fraud_alerts": fraud_alerts,
    }
