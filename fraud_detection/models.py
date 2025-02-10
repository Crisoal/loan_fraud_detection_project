# fraud_detection/models.py

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

# models.py
class VisitorID(models.Model):
    """
    Stores unique visitor identifiers and associated metadata for fraud detection.
    """
    visitor_id = models.CharField(max_length=255, unique=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)  # Client IP
    public_ip = models.GenericIPAddressField(null=True, blank=True)  # IP from FingerprintJS
    confidence_score = models.FloatField(null=True, blank=True)

    # Browser information
    browser_name = models.CharField(max_length=100, null=True, blank=True)
    browser_version = models.CharField(max_length=50, null=True, blank=True)

    # Operating System information
    os = models.CharField(max_length=50, null=True, blank=True)
    os_version = models.CharField(max_length=50, null=True, blank=True)

    # Device information
    device = models.CharField(max_length=100, null=True, blank=True)

    # Incognito mode detection
    incognito = models.BooleanField(null=True, blank=True)  # New field for incognito mode

    # Timestamps
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Visitor {self.visitor_id} - {self.ip_address} / {self.public_ip} (Incognito: {self.incognito})"


class LoanApplication(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
        ("flagged", "Flagged for Review"),
        ("fraud_detected", "Fraud Detected")
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    visitor_id = models.ForeignKey('VisitorID', on_delete=models.CASCADE, null=True, blank=True)
    full_name = models.CharField(max_length=255, default="Anonymous")
    email = models.EmailField(default="not_provided@example.com")
    phone = models.CharField(max_length=20, default="000-000-0000")
    address = models.CharField(max_length=255, default="Not provided")
    employment_status = models.CharField(max_length=20, default="Unemployed")
    occupation = models.CharField(max_length=100, default="Not specified")
    amount_requested = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(0)]
    )
    repayment_duration = models.CharField(
        max_length=20,
        choices=[
            ("3 months", "3 months"),
            ("6 months", "6 months"),
            ("12 months", "12 months"),
            ("24 months", "24 months")
        ],
        default="12 months"
    )
    purpose = models.TextField(default="No purpose specified")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    ip_address = models.GenericIPAddressField(null=True, blank=True)  # Client IP
    public_ip = models.GenericIPAddressField(null=True, blank=True)  # IP from FingerprintJS
    confidence_score = models.FloatField(null=True, blank=True)
    application_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Loan {self.id} - {self.full_name} ({self.status})"


class FraudAlert(models.Model):
    """
    Stores flagged fraudulent activities linked to loan applications.
    """
    loan_application = models.ForeignKey(LoanApplication, on_delete=models.CASCADE, related_name="fraud_alerts")
    visitor_id = models.ForeignKey(VisitorID, on_delete=models.CASCADE, null=True, blank=True)
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"Fraud Alert for Loan {self.loan_application.id} - {self.reason[:30]}"