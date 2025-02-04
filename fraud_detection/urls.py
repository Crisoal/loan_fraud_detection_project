# fraud_detection/urls.py

from django.urls import path
from .views import loan_form_home, apply_for_loan, get_fingerprint_visitor_id

urlpatterns = [
    path("", loan_form_home, name="loan_form_home"),
    path("apply/", apply_for_loan, name="apply_for_loan"),
    path("api/visitor-id/", get_fingerprint_visitor_id, name="get_visitor_id"),
]



