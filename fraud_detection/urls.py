# fraud_detection/urls.py

from django.urls import path
from .views import track_visitor, get_visitor_id, apply_for_loan

urlpatterns = [
    path('track-visitor/', track_visitor, name='track_visitor'),
    path("api/visitor-id/", get_visitor_id, name="get_visitor_id"),
    path("apply/", apply_for_loan, name="apply_for_loan"),
    path('fraud-check/', views.FraudCheckView.as_view(), name='fraud-check'),
    path('alerts/', views.FraudAlertListView.as_view(), name='fraud-alerts'),
]
