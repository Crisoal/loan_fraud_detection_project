# Generated by Django 5.1.5 on 2025-02-10 04:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fraud_detection', '0006_remove_visitorid_browser_engine'),
    ]

    operations = [
        migrations.AddField(
            model_name='loanapplication',
            name='public_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='visitorid',
            name='public_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
    ]
