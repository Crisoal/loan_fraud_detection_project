# fraud_detection/admin.py

from django.contrib import admin
from .models import LoanApplication, VisitorID, FraudAlert

@admin.register(FraudAlert)
class FraudAlertAdmin(admin.ModelAdmin):
    list_display = ("loan_application", "reason", "created_at", "resolved")
    list_filter = ("resolved",)

@admin.register(LoanApplication)
class LoanApplicationAdmin(admin.ModelAdmin):
    list_display = ("full_name", "email", "amount_requested", "status", "application_date")
    search_fields = ("full_name", "email")
    list_filter = ("status", "application_date")

@admin.register(VisitorID)
class VisitorIDAdmin(admin.ModelAdmin):
    list_display = ("visitor_id", "ip_address", "public_ip", "device", "last_seen")
    search_fields = ("visitor_id", "ip_address")