# fraud_detection/services.py
import os
from django.db.models import Q
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import LoanApplication, VisitorID, FraudAlert
from tenacity import retry, stop_after_attempt, wait_fixed
import logging
import re
from datetime import timedelta
from django.db import transaction

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
        try:
            risk_scoring_service = RiskScoringService()
            risk_score = risk_scoring_service.calculate_risk_score(loan_application)
            decision = risk_scoring_service.get_decision(risk_score)
            
            fraud_alerts = []
            
            # Test 1: Multiple applications from same device
            with transaction.atomic():
                recent_applications = LoanApplication.objects.filter(
                    visitor_id=loan_application.visitor_id,
                    application_date__gte=timezone.now() - timedelta(days=7)
                ).exclude(id=loan_application.id)
                
                if recent_applications.count() >= 1:
                    fraud_alerts.append(f"Multiple applications ({recent_applications.count()}) "
                                      f"from same Visitor ID in last 7 days")
            
            # Test 2: Same personal details with different devices
            with transaction.atomic():
                similar_applications = LoanApplication.objects.filter(
                    Q(full_name=loan_application.full_name) |
                    Q(phone=loan_application.phone) |
                    Q(email=loan_application.email)
                ).exclude(visitor_id=loan_application.visitor_id)
                
                if similar_applications.exists():
                    fraud_alerts.append("Same personal details detected across different devices")
            
            # Test 3: Fake data detection
            if self._detect_fake_data(loan_application):
                fraud_alerts.append("Suspicious patterns detected in personal details")
            
            # Test 4: Similar applications with varying details
            with transaction.atomic():
                similar_pattern_apps = self._find_similar_patterns(loan_application)
                if similar_pattern_apps.exists():
                    fraud_alerts.append(f"Found {similar_pattern_apps.count()} similar applications "
                                      f"with slightly different details")
            
            # Test 5: High risk score
            if risk_score > 70:
                fraud_alerts.append(f"High risk score detected ({risk_score})")
            
            # If any fraud alerts are triggered, set the loan application status to 'PENDING'
            if fraud_alerts:
                with transaction.atomic():
                    # Create fraud alert with 'PENDING' status
                    FraudAlert.objects.create(
                        loan_application=loan_application,
                        visitor_id=loan_application.visitor_id,
                        reason=" | ".join(fraud_alerts),
                        status='PENDING',  # Set status to 'PENDING' for flagged loans
                        risk_score=float(risk_score),
                        metadata=loan_application.metadata
                    )
                    # Update loan application status to 'PENDING'
                    loan_application.status = 'PENDING'
                    loan_application.save()

                return True, risk_score
            else:
                return False, risk_score

        except Exception as e:
            logger.error(f"Error processing fraud detection: {str(e)}")
            raise

    def _detect_fake_data(self, loan_application):
        """Detect suspicious patterns in personal details."""
        fake_patterns = [
            r'^test.*@.*\.(?:com|org)$',  # Test email patterns
            r'^(?:123|999)[0-9]{2}(?:-?)\d{3}(?:-?)\d{4}$',  # Suspicious phone numbers
            r'(?:test|fake|sample|demo)[\w\s]*$',  # Common test names
            r'^\d{4}-\d{2}-\d{2}$'  # Date-like strings as names
        ]
        for pattern in fake_patterns:
            try:
                if (re.match(pattern, loan_application.email.lower(), re.IGNORECASE) or
                    re.match(pattern, loan_application.phone) or
                    re.match(pattern, loan_application.full_name.lower())):
                    return True
            except re.error as e:
                logger.error(f"Invalid regex pattern: {pattern}. Error: {str(e)}")
                continue
        return False

    def _find_similar_patterns(self, loan_application):
        """Find similar applications with slightly varying details."""
        try:
            with transaction.atomic():
                # Escape special regex characters in the full_name
                escaped_name = re.escape(loan_application.full_name)
                
                similar_names = LoanApplication.objects.filter(
                    full_name__iregex=rf'{escaped_name}'
                ).exclude(visitor_id=loan_application.visitor_id)
                
                base_email = loan_application.email.split('@')[0].lower()
                similar_emails = LoanApplication.objects.filter(
                    email__iregex=rf'^{base_email}\d*@.*$'
                ).exclude(visitor_id=loan_application.visitor_id)
                
                return similar_names.union(similar_emails)
        except re.error as e:
            logger.error(f"Error in similar patterns detection: {str(e)}")
            return LoanApplication.objects.none()

    def notify_admin_dashboard(self, loan_application, risk_score):
        """Notify admin dashboard about high-risk applications."""
        alert_data = {
            'application_id': str(loan_application.id),
            'visitor_id': loan_application.visitor_id.visitor_id,
            'risk_score': risk_score,
            'status': loan_application.status,
            'metadata': loan_application.metadata,
            'timestamp': timezone.now().isoformat()
        }
        
        FraudAlert.objects.create(
            loan_application=loan_application,
            visitor_id=loan_application.visitor_id,
            reason=f"High risk score ({risk_score})",
            status=self.get_decision(risk_score),
            metadata=alert_data
        )