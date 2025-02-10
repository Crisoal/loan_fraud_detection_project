# fraud_detection/services.py

import os
from django.db.models import Q
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import LoanApplication, VisitorID, FraudAlert
from tenacity import retry, stop_after_attempt, wait_fixed

class RiskScoringService:
    def __init__(self):
        self.IDENTITY_WEIGHT = float(os.getenv("IDENTITY_WEIGHT", 0.3))
        self.DEVICE_WEIGHT = float(os.getenv("DEVICE_WEIGHT", 0.2))
        self.IP_WEIGHT = float(os.getenv("IP_WEIGHT", 0.2))
        self.HISTORY_WEIGHT = float(os.getenv("HISTORY_WEIGHT", 0.3))
        
        # Smart Signals thresholds
        self.CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", 0.9))
        self.VPN_DETECTION_THRESHOLD = float(os.getenv("VPN_DETECTION_THRESHOLD", 0.8))
        self.TAMPERING_THRESHOLD = float(os.getenv("TAMPERING_THRESHOLD", 0.7))

    def calculate_risk_score(self, loan_application):
        """Calculate comprehensive risk score based on multiple factors."""
        scores = {
            'identity': self._calculate_identity_risk(loan_application),
            'device': self._calculate_device_risk(loan_application),
            'ip': self._calculate_ip_risk(loan_application),
            'history': self._calculate_history_risk(loan_application)
        }

        # Weighted sum of risk scores
        weighted_score = (
            scores['identity'] * self.IDENTITY_WEIGHT +
            scores['device'] * self.DEVICE_WEIGHT +
            scores['ip'] * self.IP_WEIGHT +
            scores['history'] * self.HISTORY_WEIGHT
        )

        return min(max(weighted_score, 0), 100)

    def _calculate_identity_risk(self, loan_application):
        """Analyze identity-related risks."""
        visitor_id = loan_application.visitor_id
        if not visitor_id:
            return 50  # Default medium risk if no visitor ID
        
        # Count applications with same personal details but different visitor IDs
        similar_applications = LoanApplication.objects.filter(
            Q(full_name=loan_application.full_name) |
            Q(phone=loan_application.phone) |
            Q(email=loan_application.email)
        ).exclude(visitor_id=visitor_id).count()
        
        # Count applications with same visitor ID but different identities
        different_identities = LoanApplication.objects.filter(
            visitor_id=visitor_id
        ).exclude(
            Q(full_name=loan_application.full_name) |
            Q(phone=loan_application.phone) |
            Q(email=loan_application.email)
        ).count()

        # Calculate risk based on findings
        if similar_applications > 0 or different_identities > 0:
            base_risk = 60
            multiplier = min(similar_applications + different_identities, 5)
            return min(base_risk + (multiplier * 10), 100)
        
        return 0

    def _calculate_device_risk(self, loan_application):
        """Evaluate device and browser-related risks."""
        if not loan_application.visitor_id:
            return 50  # Default medium risk if no visitor ID
            
        extended_metadata = json.loads(loan_application.metadata or '{}')
        
        # Check for suspicious device characteristics
        risk_factors = []
        
        # Confidence score check
        if extended_metadata.get('confidence', 0) < self.CONFIDENCE_THRESHOLD:
            risk_factors.append(30)
            
        # Incognito mode detection
        if extended_metadata.get('incognito', False):
            risk_factors.append(20)
            
        # VPN detection
        if extended_metadata.get('vpn', {}).get('result', False):
            risk_factors.append(25)
            
        # Tampering detection
        if extended_metadata.get('tampering', {}).get('result', False):
            risk_factors.append(40)
            
        # Browser bot detection
        if extended_metadata.get('bot', {}).get('result', False):
            risk_factors.append(45)
            
        return sum(risk_factors)

    def _calculate_ip_risk(self, loan_application):
        """Assess IP address related risks."""
        if not loan_application.ip_address:
            return 50  # Default medium risk if no IP
            
        # Check for VPN usage and IP anomalies
        ip_related_apps = LoanApplication.objects.filter(ip_address=loan_application.ip_address)
        if ip_related_apps.count() > 5:  # Threshold for suspicious activity
            return 80
            
        return 0

    def _calculate_history_risk(self, loan_application):
        """Analyze application history risks."""
        visitor_id = loan_application.visitor_id
        if not visitor_id:
            return 50  # Default medium risk if no visitor ID
            
        recent_applications = LoanApplication.objects.filter(
            visitor_id=visitor_id,
            application_date__gte=timezone.now() - timezone.timedelta(days=7)
        ).exclude(id=loan_application.id)
        
        if recent_applications.count() >= 3:
            return 70
            
        return 0

    def get_decision(self, risk_score):
        """Determine action based on risk score."""
        if risk_score <= 40:
            return 'APPROVE'
        elif risk_score <= 70:
            return 'REVIEW'
        else:
            return 'REJECT'

class FraudDetectionService:
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def detect_fraud(self, loan_application):
        """Detect fraud using multiple signals and risk scoring."""
        risk_scoring_service = RiskScoringService()
        risk_score = risk_scoring_service.calculate_risk_score(loan_application)
        
        # Create fraud alert if risk score indicates potential fraud
        if risk_score > 40:
            FraudAlert.objects.create(
                loan_application=loan_application,
                visitor_id=loan_application.visitor_id,
                reason=f"High risk score ({risk_score})",
                risk_level=risk_scoring_service.get_decision(risk_score)
            )
            
            if risk_score > 70:  # High risk threshold
                loan_application.status = 'fraud_detected'
                loan_application.save()
                
                # Notify administrators
                self._notify_admins(loan_application, risk_score)
                
            return True, risk_score
        return False, risk_score

    def _notify_admins(self, loan_application, risk_score):
        """Notify administrators about high-risk applications."""
        subject = f"High Risk Loan Application Detected (Score: {risk_score})"
        message = f"""
        Loan Application #{loan_application.id} has been flagged for fraud review.
        Risk Score: {risk_score}
        Status: {loan_application.status}
        Visitor ID: {loan_application.visitor_id.visitor_id}
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            settings.ADMIN_EMAILS,
            fail_silently=False,
        )

    def get_fraud_statistics(self):
        """Get fraud detection statistics."""
        total_applications = LoanApplication.objects.count()
        flagged_applications = LoanApplication.objects.filter(status='flagged').count()
        fraud_detected = LoanApplication.objects.filter(status='fraud_detected').count()
        approved_applications = LoanApplication.objects.filter(status='approved').count()
        
        return {
            'total_applications': total_applications,
            'flagged_applications': flagged_applications,
            'fraud_detected': fraud_detected,
            'approved_applications': approved_applications,
            'fraud_rate': (fraud_detected / total_applications * 100) if total_applications > 0 else 0
        }