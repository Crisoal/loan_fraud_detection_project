# fraud_prevention/urls.py

from django.contrib import admin
from django.urls import path, include
from fraud_detection.views import loan_form_home, get_smart_signals  # Import the homepage view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", loan_form_home, name="home"),  # Set the loan application form as the homepage
    path("", include("fraud_detection.urls")),
    path("get-smart-signals/", get_smart_signals, name="get_smart_signals"),
]
