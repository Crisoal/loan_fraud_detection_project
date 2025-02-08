# fraud_detection/signals.py

from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver
from .models import LoanApplication
from .utils import detect_fraud
from django.contrib.auth import get_user_model

@receiver(post_save, sender=LoanApplication)
def check_fraud(sender, instance, created, **kwargs):
    if created:
        detect_fraud(instance)


@receiver(post_migrate)
def create_admin_user(sender, **kwargs):
    User = get_user_model()
    if not User.objects.filter(username="admin").exists():
        User.objects.create_superuser("admin", "admin@guard360.com", "secureagain14:05")
        print("✅ Admin user created successfully!")
