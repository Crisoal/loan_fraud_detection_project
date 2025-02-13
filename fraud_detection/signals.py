# fraud_detection/signals.py

from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver
from .models import LoanApplication
from .utils import detect_fraud
from django.contrib.auth import get_user_model
from django.db import IntegrityError

@receiver(post_save, sender=LoanApplication)
def check_fraud(sender, instance, created, **kwargs):
    if created:
        detect_fraud(instance)


@receiver(post_migrate)
def create_admin_user(sender, **kwargs):
    User = get_user_model()
    try:
        # Check if an admin user already exists
        if not User.objects.filter(username='admin').exists():
            # Create the admin user
            admin_user = User.objects.create_superuser(
                username='admin',
                email='admin@example.com',
                password='adminpassword123'
            )
            admin_user.save()
            print("Admin user created successfully.")
    except IntegrityError:
        print("Admin user already exists.")
