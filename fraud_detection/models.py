# fraud_detection/models.py

import uuid
from django.db import models
from django.contrib.auth.models import User

class VisitorID(models.Model):
    """
    Stores unique visitor identifiers for tracking loan applications across devices.
    """
    visitor_id = models.CharField(max_length=255, unique=True, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_fingerprint = models.CharField(max_length=255, null=True, blank=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Visitor {self.visitor_id} - {self.ip_address}"

class LoanApplication(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
        ("flagged", "Flagged for Review"),
        ("fraud_detected", "Fraud Detected"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    visitor_id = models.ForeignKey('VisitorID', on_delete=models.CASCADE, null=True, blank=True)
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    amount_requested = models.DecimalField(max_digits=10, decimal_places=2)
    purpose = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_fingerprint = models.CharField(max_length=255, unique=False, null=True, blank=True)
    application_date = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """Before saving a loan application, check for fraud."""
        from .fraud_detection_engine import detect_fraudulent_application
        if detect_fraudulent_application(self):
            self.status = "flagged"
        super().save(*args, **kwargs)

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
