# fraud_detection/services.py

import os
from django.db.models import Q
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import LoanApplication, VisitorID, FraudAlert
from tenacity import retry, stop_after_attempt, wait_fixed
import logging

logger = logging.getLogger(__name__)

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
        if not loan_application.visitor_id:
            return 50  # Default medium risk if no visitor ID
            
        # Count applications with same personal details but different visitor IDs
        similar_applications = LoanApplication.objects.filter(
            Q(full_name=loan_application.full_name) |
            Q(phone=loan_application.phone) |
            Q(email=loan_application.email)
        ).exclude(visitor_id=loan_application.visitor_id).count()
        
        # Count applications with same visitor ID but different identities
        different_identities = LoanApplication.objects.filter(
            visitor_id=loan_application.visitor_id
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
        """Evaluate device and browser-related risks using smart signals."""
        if not loan_application.visitor_id:
            return 50  # Default medium risk if no visitor ID
            
        # Get smart signals from loan application
        def normalize_bot_value(value):
            """Convert bot detection value to standardized boolean"""
            if isinstance(value, bool):
                return value
            return str(value).lower() == 'detected'
            
        def evaluate_confidence_score(score):
            """Calculate risk factor based on confidence score"""
            if score < self.CONFIDENCE_THRESHOLD:
                return 30
            elif score < 0.95:
                return 15
            return 0
            
        def assess_device_behavior():
            """Evaluate risk based on device and browser characteristics"""
            risk_factors = []
            
            # Bot detection
            if normalize_bot_value(loan_application.bot_detected):
                risk_factors.append({
                    'factor': 'Bot Detection',
                    'score': 45,
                    'description': 'Automated traffic detected'
                })
                
            # VPN detection
            if loan_application.vpn_detected:
                risk_factors.append({
                    'factor': 'VPN Usage',
                    'score': 30,
                    'description': 'VPN connection detected'
                })
                
            # Proxy detection
            if loan_application.proxy_detected:
                risk_factors.append({
                    'factor': 'Proxy Detection',
                    'score': 25,
                    'description': 'Proxy server detected'
                })
                
            # Tampering detection
            if loan_application.tampering_detected:
                risk_factors.append({
                    'factor': 'Tampering Detected',
                    'score': 40,
                    'description': 'Browser tampering detected'
                })
                
            # Confidence score evaluation
            confidence_risk = evaluate_confidence_score(loan_application.confidence_score)
            if confidence_risk > 0:
                risk_factors.append({
                    'factor': 'Low Confidence Score',
                    'score': confidence_risk,
                    'description': f'Confidence score: {loan_application.confidence_score}'
                })
                
            # Incognito mode detection
            if loan_application.incognito:
                risk_factors.append({
                    'factor': 'Incognito Mode',
                    'score': 20,
                    'description': 'Private browsing mode detected'
                })
                
            return risk_factors
            
        # Calculate total risk score
        risk_factors = assess_device_behavior()
        total_risk = sum(factor['score'] for factor in risk_factors)
        
        # Apply device weight
        weighted_risk = min(max(total_risk * self.DEVICE_WEIGHT, 0), 100)
        
        # Log detailed risk assessment
        logger.debug(f"Device Risk Assessment:")
        for factor in risk_factors:
            logger.debug(f"- {factor['factor']}: {factor['score']} ({factor['description']})")
        logger.debug(f"Total Device Risk Score: {weighted_risk}")
        
        return weighted_risk

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
        if not loan_application.visitor_id:
            return 50  # Default medium risk if no visitor ID
            
        recent_applications = LoanApplication.objects.filter(
            visitor_id=loan_application.visitor_id,
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
        decision = risk_scoring_service.get_decision(risk_score)

        fraud_alerts = []

        # Check for multiple Visitor IDs linked to the same personal details
        similar_applications = LoanApplication.objects.filter(
            Q(full_name=loan_application.full_name) |
            Q(phone=loan_application.phone) |
            Q(email=loan_application.email)
        ).exclude(visitor_id=loan_application.visitor_id)

        if similar_applications.exists():
            fraud_alerts.append("Multiple Visitor IDs detected for the same personal details.")

        # Check for multiple loan applications from the same Visitor ID
        different_identities = LoanApplication.objects.filter(
            visitor_id=loan_application.visitor_id
        ).exclude(
            Q(full_name=loan_application.full_name) |
            Q(phone=loan_application.phone) |
            Q(email=loan_application.email)
        )

        if different_identities.exists():
            fraud_alerts.append("Same Visitor ID used for multiple different identities.")

        # Insert a fraud alert if any fraud condition is met
        if fraud_alerts:
            FraudAlert.objects.create(
                loan_application=loan_application,
                visitor_id=loan_application.visitor_id,
                reason=" | ".join(fraud_alerts),  # Store all fraud reasons
                risk_level=decision,
                risk_score=risk_score
            )

        # If risk is too high, update loan status
        if risk_score > 70:
            loan_application.status = 'fraud_detected'
            loan_application.save()

        return bool(fraud_alerts), risk_score


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

    def notify_admin_dashboard(self, loan_application, risk_score):
        """Notify admin dashboard about high-risk applications."""
        alert_data = {
            'application_id': str(loan_application.id),
            'visitor_id': loan_application.visitor_id.visitor_id,
            'risk_score': risk_score,
            'status': loan_application.status,
            'metadata': loan_application.metadata
        }
        
        # Create fraud alert
        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=loan_application.visitor_id,
            reason=f"High risk score ({risk_score})",
            risk_level=self.get_decision(risk_score)
        )

    def get_fraud_statistics(self):
        """Get comprehensive fraud statistics for dashboard."""
        return {
            'total_applications': LoanApplication.objects.count(),
            'flagged_applications': LoanApplication.objects.filter(status='flagged').count(),
            'fraud_detected': LoanApplication.objects.filter(status='fraud_detected').count(),
            'risk_distribution': self._calculate_risk_distribution(),
            'visitor_patterns': self._analyze_visitor_patterns(),
            'recent_alerts': FraudAlert.objects.order_by('-created_at')[:50],
            'risk_percentages': self._calculate_risk_percentages()
        }

    def _calculate_risk_distribution(self):
        """Calculate distribution of applications across risk levels."""
        low_risk = LoanApplication.objects.filter(risk_score__lte=40).count()
        medium_risk = LoanApplication.objects.filter(
            risk_score__gt=40, risk_score__lte=70
        ).count()
        high_risk = LoanApplication.objects.filter(risk_score__gt=70).count()
        return {
            'Low Risk': low_risk,
            'Medium Risk': medium_risk,
            'High Risk': high_risk
        }