# fraud_detection/utils.py

from .models import LoanApplication, VisitorID, FraudAlert
from django.utils.timezone import now
import datetime
from django.core.mail import send_mail
from django.conf import settings

# Load API credentials
FINGERPRINT_API_KEY = os.getenv("FINGERPRINT_API_KEY")
FINGERPRINT_API_URL = os.getenv("FINGERPRINT_API_URL")

def detect_fraud(loan_application):
    """Detects fraud based on device fingerprint and unusual loan activity."""
    fraud_reasons = []

    # Check if multiple visitor IDs are using the same device fingerprint
    similar_fingerprints = LoanApplication.objects.filter(
        device_fingerprint=loan_application.device_fingerprint
    ).exclude(id=loan_application.id)

    if similar_fingerprints.exists():
        fraud_reasons.append("Multiple visitor IDs linked to the same device fingerprint.")

    # Check if the visitor has multiple applications in a short time
    recent_loans = LoanApplication.objects.filter(
        user=loan_application.user,
        application_date__gte=now() - timedelta(days=7),
    ).exclude(id=loan_application.id)

    if recent_loans.count() > 3:  # Flag if more than 3 loan requests in a week
        fraud_reasons.append("Multiple loan applications in a short period.")

    # If fraud is detected, save the fraud alert
    if fraud_reasons:
        FraudAlert.objects.create(
            loan_application=loan_application,
            reason=" | ".join(fraud_reasons),
        )
        loan_application.status = "fraud_detected"
        loan_application.save()


def get_fingerprint_visitor_id(ip_address, user_agent):
    """
    Fetches the Visitor ID from Fingerprint API based on IP and User-Agent.
    """
    headers = {"Authorization": f"Bearer {FINGERPRINT_API_KEY}"}
    payload = {"ip": ip_address, "user_agent": user_agent}

    try:
        response = requests.post(FINGERPRINT_API_URL, json=payload, headers=headers)
        response_data = response.json()

        if response.status_code == 200 and "visitorId" in response_data:
            return response_data["visitorId"]
        else:
            return None
    except Exception as e:
        print(f"Fingerprint API Error: {e}")
        return None

def store_visitor_data(request):
    """
    Stores the Visitor ID and device fingerprint in the database.
    """
    ip_address = request.META.get("REMOTE_ADDR")
    user_agent = request.META.get("HTTP_USER_AGENT")

    visitor_id = get_fingerprint_visitor_id(ip_address, user_agent)

    if visitor_id:
        visitor, created = VisitorID.objects.get_or_create(visitor_id=visitor_id)
        visitor.ip_address = ip_address
        visitor.last_seen = now()
        visitor.save()

        return visitor_id
    return None


# Fraud Threshold (Adjustable)
FRAUD_THRESHOLD = 75  # Applications with a fraud score ≥ 75 are flagged

def calculate_fraud_score(loan_app):
    """
    Calculate fraud risk score based on predefined rules.
    Returns a fraud score between 0-100.
    """
    score = 0
    visitor_id = loan_app.visitor_id
    user = loan_app.user

    # 🛑 Rule 1: Multiple applications from the same device/IP
    if visitor_id:
        application_count = LoanApplication.objects.filter(visitor_id=visitor_id).count()
        if application_count >= 2:
            score += 40  # High risk

    # 🛑 Rule 2: Multiple users using the same Visitor ID (fake profiles)
    linked_users = VisitorID.objects.filter(visitor_id=visitor_id.visitor_id).count()
    if linked_users > 1:
        score += 30  # Medium risk

    # 🛑 Rule 3: Unusual payment method usage (same method used by multiple people)
    same_payment_users = LoanApplication.objects.filter(
        user=user, amount=loan_app.amount
    ).exclude(id=loan_app.id).count()
    if same_payment_users > 1:
        score += 20  # Medium risk

    # 🛑 Rule 4: Unusual loan frequency (too many loans within a short time)
    recent_loans = LoanApplication.objects.filter(
        user=user, application_date__gte=datetime.datetime.now() - datetime.timedelta(days=7)
    ).count()
    if recent_loans >= 3:
        score += 15  # Low risk

    # Limit fraud score to 100
    return min(score, 100)

def flag_suspicious_application(loan_app):
    """
    Flag loan application if fraud score exceeds threshold.
    Create a FraudAlert record and notify admin.
    """
    fraud_score = calculate_fraud_score(loan_app)

    if fraud_score >= FRAUD_THRESHOLD:
        # Mark application as flagged
        loan_app.status = "flagged"
        loan_app.save()

        # Create Fraud Alert record
        FraudAlert.objects.create(
            loan_application=loan_app,
            reason=f"Fraud risk score: {fraud_score}. Suspicious activity detected.",
        )

        # Notify admin via email
        send_mail(
            subject="🚨 Loan Fraud Alert 🚨",
            message=f"A loan application has been flagged for fraud.\n\n"
                    f"User: {loan_app.user.username}\n"
                    f"Fraud Score: {fraud_score}\n"
                    f"Reason: Suspicious activity detected.\n\n"
                    f"Please review the case immediately.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.ADMIN_EMAIL],
            fail_silently=True,
        )

        return True  # Fraud detected

    return False  # No fraud detected


