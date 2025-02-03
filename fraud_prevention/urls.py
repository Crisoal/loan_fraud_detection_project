# fraud_prevention/urls.py

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("fraud-detection/", include("fraud_detection.urls")),
]
