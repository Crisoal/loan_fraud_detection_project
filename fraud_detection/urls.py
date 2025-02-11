# fraud_detection/urls.py

from django.urls import path
from .views import loan_form_home, apply_for_loan, get_fingerprint_visitor_id
from .views import dashboard, login_view, logout_view, dashboard


urlpatterns = [
    path("", loan_form_home, name="loan_form_home"),
    
    path("dashboard/", dashboard, name="dashboard"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),

    path("apply/", apply_for_loan, name="apply_for_loan"),
    path("api/visitor-id/", get_fingerprint_visitor_id, name="get_visitor_id"),

]



