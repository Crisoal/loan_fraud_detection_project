# fraud_prevention/urls.py

from django.contrib import admin
from django.urls import path, include
from fraud_detection.views import loan_form_home  # Import the homepage view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", loan_form_home, name="home"),  # Set the loan application form as the homepage
    path("fraud-detection/", include("fraud_detection.urls")),
]
