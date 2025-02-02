# fraud_detection/utils.py

from .models import LoanApplication, VisitorID, FraudAlert
from django.utils.timezone import now

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
