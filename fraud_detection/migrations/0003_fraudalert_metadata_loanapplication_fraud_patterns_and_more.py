# Generated by Django 5.1.5 on 2025-02-13 09:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fraud_detection', '0002_remove_loanapplication_device_fingerprint_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='fraudalert',
            name='metadata',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='fraud_patterns',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='last_modified',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='loanapplication',
            name='risk_factors',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='application_count',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='last_application_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
