# fraud_detection/views.py

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings
from .models import VisitorID, LoanApplication
from django.views.decorators.csrf import csrf_exempt
from .forms import LoanApplicationForm
from .utils import get_fingerprint_visitor_id, store_visitor_data, flag_suspicious_application, get_client_ip
from .services import detect_fraudulent_application
import json
from django.utils import timezone


def track_visitor(request):
    """
    Extracts client IP & User-Agent, retrieves Visitor ID from Fingerprint API, and stores it in the database.
    """
    client_ip = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "Unknown")

    visitor_id = get_visitor_id(client_ip, user_agent)

    if visitor_id:
        visitor, created = VisitorID.objects.get_or_create(
            visitor_id=visitor_id,
            defaults={"ip_address": client_ip, "device_info": user_agent}
        )
        return JsonResponse({"message": "Visitor tracked successfully", "visitor_id": visitor.visitor_id})

    return JsonResponse({"error": "Could not retrieve visitor ID"}, status=400)


@csrf_exempt
def get_fingerprint_visitor_id(request):
    """
    API Endpoint: Fetches and stores Visitor ID for fraud detection.
    """
    if request.method == "POST":
        try:
            visitor_id = store_visitor_data(request)
            if visitor_id:
                return JsonResponse({"visitor_id": visitor_id}, status=200)
            return JsonResponse({"error": "Unable to retrieve visitor ID"}, status=400)
        except Exception as e:
            logger.error(f"Error processing visitor ID request: {str(e)}")
            return JsonResponse({"error": "Internal server error"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

def loan_form_home(request):
    """
    Renders the loan application form as the homepage.
    """
    form = LoanApplicationForm()  # Create an empty form for display
    context = {
        "form": form,
        "fingerprintjs_public_key": settings.FINGERPRINTJS_PUBLIC_KEY,  # Pass the public key
    }
    return render(request, "loan_form.html", context)


# views.py
@csrf_exempt
def apply_for_loan(request):
    if request.method == "POST":
        form = LoanApplicationForm(request.POST)
        if form.is_valid():
            # Get visitor data from form
            visitor_id = request.POST.get('visitor_id')
            device_fingerprint = request.POST.get('device_fingerprint')

            # Create or update visitor record
            client_ip = get_client_ip(request)
            visitor, created = VisitorID.objects.get_or_create(
                ip_address=client_ip,
                defaults={
                    "visitor_id": visitor_id,
                    "device_fingerprint": device_fingerprint,
                    "last_seen": timezone.now()
                }
            )

            if not visitor.visitor_id and visitor_id:
                visitor.visitor_id = visitor_id
                visitor.save()

            # Save the form with visitor data
            loan_app = form.save(commit=False)
            loan_app.visitor_id = visitor
            loan_app.ip_address = client_ip
            
            # Ensure device fingerprint is saved
            if device_fingerprint:
                loan_app.device_fingerprint = device_fingerprint

            loan_app.save()

            # # Check for fraud
            # fraud_detected = flag_suspicious_application(loan_app)
            
            return JsonResponse({
                "message": "Application submitted successfully.",
                # "fraud_detected": fraud_detected
            }, status=201)

        return JsonResponse({"error": "Invalid form data"}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=405)   