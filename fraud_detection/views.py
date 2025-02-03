# fraud_detection/views.py

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import VisitorID, LoanApplication
from django.views.decorators.csrf import csrf_exempt
from .forms import LoanApplicationForm
from .utils import get_visitor_id, store_visitor_data, flag_suspicious_application
from .services import detect_fraudulent_application
import json

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


def get_client_ip(request):
    """Extracts client IP address from request headers."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")


@csrf_exempt
def get_visitor_id(request):
    """
    API Endpoint: Fetches and stores Visitor ID for fraud detection.
    """
    if request.method == "POST":
        visitor_id = store_visitor_data(request)
        if visitor_id:
            return JsonResponse({"visitor_id": visitor_id}, status=200)
        return JsonResponse({"error": "Unable to retrieve visitor ID"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)


def apply_for_loan(request):
    """
    Handles loan application form submission and fraud detection.
    """
    if request.method == "POST":
        form = LoanApplicationForm(request.POST)

        if form.is_valid():
            visitor_id = store_visitor_data(request)
            visitor_obj, _ = VisitorID.objects.get_or_create(visitor_id=visitor_id)

            loan_app = form.save(commit=False)
            loan_app.visitor_id = visitor_obj
            loan_app.ip_address = request.META.get("REMOTE_ADDR")
            loan_app.device_fingerprint = request.headers.get("Device-Fingerprint", None)
            loan_app.save()

            # 🔥 Automatically check for fraud
            fraud_detected = flag_suspicious_application(loan_app)

            message = "Application submitted successfully."
            if fraud_detected:
                message = "Application submitted but flagged for fraud review."

            return JsonResponse({"message": message}, status=202 if fraud_detected else 200)

    else:
        form = LoanApplicationForm()

    return render(request, "loan_form.html", {"form": form})