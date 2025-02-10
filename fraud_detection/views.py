# fraud_detection/views.py

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings
from .models import VisitorID, LoanApplication
from django.views.decorators.csrf import csrf_exempt
from .forms import LoanApplicationForm
from .utils import get_fingerprint_visitor_id, store_visitor_data, flag_suspicious_application, get_client_ip
import json
from django.utils import timezone
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import LoginForm  # Renamed from AdminLoginForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import LoginForm  # Renamed from AdminLoginForm
import logging
from django.views.decorators.csrf import csrf_exempt

# Configure the logger
logger = logging.getLogger(__name__)

# Helper function to check if user is an admin
def is_admin(user):
    return user.is_authenticated and user.is_staff

# Dashboard View (Restricted)
@login_required(login_url='login')
@user_passes_test(is_admin)
def dashboard(request):
    return render(request, 'dashboard.html')  # Create this template

# Login View
def login_view(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('dashboard')  # Redirect if the admin is already logged in
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None and user.is_staff:
                login(request, user)
                return redirect('dashboard')  # Redirect to the dashboard after successful login
            else:
                messages.error(request, "Invalid credentials or insufficient permissions.")
        else:
            print(form.errors)  # Debugging: Print form errors
            messages.error(request, "Please fill out the form correctly.")
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})


# Logout View
@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


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
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    form = LoanApplicationForm(request.POST)
    if not form.is_valid():
        return JsonResponse({
            "error": "Invalid form data",
            "details": dict(form.errors)
        }, status=400)

    extended_metadata_str = request.POST.get('extended_metadata', '')

    if not extended_metadata_str:
        return JsonResponse({
            "error": "Invalid metadata format",
            "details": "Extended metadata is empty",
        }, status=400)

    try:
        extended_metadata = json.loads(extended_metadata_str)

        visitor_id = extended_metadata['visitorId']
        public_ip = extended_metadata.get('publicIpAddress')
        client_ip = get_client_ip(request)
        incognito_mode = extended_metadata.get('incognito', None)  # Fetch incognito status

        visitor_data = {
            'ip_address': client_ip,
            'public_ip': public_ip,
            'confidence_score': extended_metadata.get('confidence', 0),
            'browser_name': extended_metadata.get('browserDetails', {}).get('browser'),
            'browser_version': extended_metadata.get('browserDetails', {}).get('version'),
            'os': extended_metadata.get('osDetails', {}).get('os'),
            'os_version': extended_metadata.get('osDetails', {}).get('version'),
            'device': extended_metadata.get('device'),
            'first_seen_at': extended_metadata.get('firstSeenAt'),
            'last_seen_at': extended_metadata.get('lastSeenAt'),
            'incognito': incognito_mode  # Store incognito mode status
        }

        visitor, created = VisitorID.objects.get_or_create(
            visitor_id=visitor_id,
            defaults=visitor_data
        )

        loan_app = form.save(commit=False)
        loan_app.visitor_id = visitor
        loan_app.ip_address = client_ip
        loan_app.public_ip = public_ip
        loan_app.confidence_score = extended_metadata.get('confidence', 0)
        loan_app.incognito = incognito_mode
        loan_app.save()

        return JsonResponse({"message": "Application submitted successfully."}, status=201)

    except Exception as e:
        return JsonResponse({"error": "Unexpected server error"}, status=500)
