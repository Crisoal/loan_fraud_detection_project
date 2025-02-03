# fraud_detection/urls.py

from django.urls import path
from .views import track_visitor, get_fingerprint_visitor_id, apply_for_loan

urlpatterns = [
    path('track-visitor/', track_visitor, name='track_visitor'),
    path("api/visitor-id/", get_fingerprint_visitor_id, name="get_fingerprint_visitor_id"),
    path("apply/", apply_for_loan, name="apply_for_loan"),

]
