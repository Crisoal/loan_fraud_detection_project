# Generated by Django 5.1.5 on 2025-02-13 16:48

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fraud_detection', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='loanapplication',
            name='device_fingerprint',
        ),
        migrations.RemoveField(
            model_name='visitorid',
            name='device_fingerprint',
        ),
        migrations.RemoveField(
            model_name='visitorid',
            name='user',
        ),
        migrations.AddField(
            model_name='fraudalert',
            name='metadata',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='fraudalert',
            name='risk_score',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=5),
        ),
        migrations.AddField(
            model_name='fraudalert',
            name='status',
            field=models.CharField(choices=[('APPROVE', 'Approved'), ('REVIEW', 'Manual Review Required'), ('REJECT', 'Rejected'), ('PENDING', 'Pending')], default='PENDING', max_length=20),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='address',
            field=models.CharField(default='Not provided', max_length=255),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='bot_detected',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='confidence_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='employment_status',
            field=models.CharField(default='Unemployed', max_length=20),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='fraud_patterns',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='incognito',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='ip_blocklisted',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='last_modified',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='metadata',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='occupation',
            field=models.CharField(default='Not specified', max_length=100),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='proxy_detected',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='public_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='repayment_duration',
            field=models.CharField(choices=[('3 months', '3 months'), ('6 months', '6 months'), ('12 months', '12 months'), ('24 months', '24 months')], default='12 months', max_length=20),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='risk_factors',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='risk_score',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=5),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='tampering_detected',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='tor_detected',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='vpn_detected',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='application_count',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='browser_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='browser_version',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='confidence_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='device',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='first_seen_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='last_application_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='last_seen_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='os',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='os_version',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='public_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='loanapplication',
            name='amount_requested',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10, validators=[django.core.validators.MinValueValidator(0)]),
        ),
        migrations.AlterField(
            model_name='loanapplication',
            name='email',
            field=models.EmailField(default='not_provided@example.com', max_length=254),
        ),
        migrations.AlterField(
            model_name='loanapplication',
            name='full_name',
            field=models.CharField(default='Anonymous', max_length=255),
        ),
        migrations.AlterField(
            model_name='loanapplication',
            name='phone',
            field=models.CharField(default='000-000-0000', max_length=20),
        ),
        migrations.AlterField(
            model_name='loanapplication',
            name='purpose',
            field=models.TextField(default='No purpose specified'),
        ),
        migrations.AlterField(
            model_name='loanapplication',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('approve', 'Approve'), ('rejected', 'Rejected'), ('flagged', 'Flagged for Review')], default='pending', max_length=20),
        ),
    ]
