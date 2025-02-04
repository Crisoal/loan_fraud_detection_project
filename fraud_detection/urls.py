# fraud_detection/urls.py

from django.urls import path
from .views import track_visitor, get_fingerprint_visitor_id, apply_for_loan, loan_form_home

urlpatterns = [
    path("", loan_form_home, name="home"),  # Set loan application form as homepage
    path('track-visitor/', track_visitor, name='track_visitor'),
    path("api/visitor-id/", get_fingerprint_visitor_id, name="get_fingerprint_visitor_id"),
    path("apply/", apply_for_loan, name="apply_for_loan"),  # Separate URL for form submission
]


