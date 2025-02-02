# fraud_detection/forms.py

from django import forms
from .models import LoanApplication

class LoanApplicationForm(forms.ModelForm):
    class Meta:
        model = LoanApplication
        fields = ["full_name", "email", "phone", "amount_requested", "purpose"]
