# fraud_detection/signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import LoanApplication
from .utils import detect_fraud

@receiver(post_save, sender=LoanApplication)
def check_fraud(sender, instance, created, **kwargs):
    if created:
        detect_fraud(instance)
