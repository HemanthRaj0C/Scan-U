"""
Risk Scoring Engine
ML-based vulnerability risk assessment and prioritization
"""
import logging
from typing import Dict, List
import numpy as np

logger = logging.getLogger(__name__)

class RiskScorer:
    """ML-based risk scoring for vulnerabilities"""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 1.0
    }
    
    # Business criticality multipliers
    CRITICALITY_MULTIPLIERS = {
        'critical': 2.0,
        'high': 1.5,
        'medium': 1.0,
        'low': 0.7
    }
    
    def __init__(self):
        self.confidence_threshold = 0.7
    
    def calculate_risk_score(self, vulnerability: Dict, asset_criticality: str = 'medium') -> float:
        """
        Calculate comprehensive risk score for a vulnerability
        
        Args:
            vulnerability: Vulnerability data dictionary
            asset_criticality: Business criticality of the asset
            
        Returns:
            Risk score (0-100)
        """
        try:
            # Base score from severity
            severity = vulnerability.get('severity', 'medium').lower()
            base_score = self.SEVERITY_WEIGHTS.get(severity, 5.0)
            
            # CVSS score adjustment
            cvss_score = vulnerability.get('cvss_score', 5.0)
            if cvss_score:
                # Normalize CVSS (0-10) to our scale
                cvss_weight = (cvss_score / 10.0) * 10
                base_score = (base_score + cvss_weight) / 2
            
            # Apply business criticality multiplier
            criticality = asset_criticality.lower()
            multiplier = self.CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
            risk_score = base_score * multiplier
            
            # Adjust for exploitability indicators
            risk_score = self._apply_exploitability_factors(vulnerability, risk_score)
            
            # Adjust for port exposure
            risk_score = self._apply_exposure_factors(vulnerability, risk_score)
            
            # Normalize to 0-100 scale
            risk_score = min(100.0, max(0.0, risk_score * 10))
            
            logger.debug(f"Calculated risk score: {risk_score:.2f} for {vulnerability.get('title')}")
            return round(risk_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 50.0  # Default medium risk
    
    def _apply_exploitability_factors(self, vulnerability: Dict, base_score: float) -> float:
        """Adjust score based on exploitability indicators"""
        score = base_score
        
        # Check for exploit availability indicators
        evidence = vulnerability.get('evidence', '').lower()
        description = vulnerability.get('description', '').lower()
        combined_text = f"{evidence} {description}"
        
        # High risk indicators
        if any(keyword in combined_text for keyword in ['exploit available', 'metasploit', 'poc available']):
            score *= 1.5
            logger.debug("Increased risk due to exploit availability")
        
        # Remote exploitability
        if any(keyword in combined_text for keyword in ['remote', 'network', 'unauthenticated']):
            score *= 1.3
            logger.debug("Increased risk due to remote exploitability")
        
        # Code execution
        if any(keyword in combined_text for keyword in ['code execution', 'rce', 'command injection']):
            score *= 1.4
            logger.debug("Increased risk due to code execution capability")
        
        return score
    
    def _apply_exposure_factors(self, vulnerability: Dict, base_score: float) -> float:
        """Adjust score based on exposure factors"""
        score = base_score
        
        # Common vulnerable ports (higher risk)
        high_risk_ports = [21, 22, 23, 80, 443, 3306, 3389, 5432, 8080]
        port = vulnerability.get('port')
        
        if port in high_risk_ports:
            score *= 1.2
            logger.debug(f"Increased risk due to commonly targeted port: {port}")
        
        return score
    
    def calculate_overall_risk(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Calculate overall risk assessment for a collection of vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary with overall risk metrics
        """
        try:
            if not vulnerabilities:
                return {
                    'overall_risk_score': 0.0,
                    'risk_level': 'low',
                    'total_vulnerabilities': 0,
                    'severity_breakdown': {},
                    'recommendations': []
                }
            
            # Count by severity
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            risk_scores = []
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                risk_score = vuln.get('ml_risk_score')
                if risk_score:
                    risk_scores.append(risk_score)
            
            # Calculate overall risk score
            if risk_scores:
                # Weighted average with emphasis on higher scores
                overall_score = np.mean(risk_scores) * 0.6 + np.max(risk_scores) * 0.4
            else:
                # Fallback calculation based on severity counts
                overall_score = (
                    severity_counts['critical'] * 10 +
                    severity_counts['high'] * 7 +
                    severity_counts['medium'] * 4 +
                    severity_counts['low'] * 2 +
                    severity_counts['info'] * 1
                ) / max(len(vulnerabilities), 1) * 10
            
            overall_score = min(100.0, overall_score)
            
            # Determine risk level
            if overall_score >= 80:
                risk_level = 'critical'
            elif overall_score >= 60:
                risk_level = 'high'
            elif overall_score >= 40:
                risk_level = 'medium'
            elif overall_score >= 20:
                risk_level = 'low'
            else:
                risk_level = 'minimal'
            
            # Generate recommendations
            recommendations = self._generate_recommendations(severity_counts, overall_score)
            
            return {
                'overall_risk_score': round(overall_score, 2),
                'risk_level': risk_level,
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'],
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low'],
                'info_count': severity_counts['info'],
                'severity_breakdown': severity_counts,
                'recommendations': recommendations
            }
            
        except Exception as e:
            logger.error(f"Error calculating overall risk: {str(e)}")
            return {
                'overall_risk_score': 50.0,
                'risk_level': 'unknown',
                'total_vulnerabilities': len(vulnerabilities),
                'severity_breakdown': {},
                'recommendations': []
            }
    
    def _generate_recommendations(self, severity_counts: Dict, overall_score: float) -> List[str]:
        """Generate prioritized remediation recommendations"""
        recommendations = []
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append(
                f"URGENT: Address {severity_counts['critical']} critical vulnerabilities immediately. "
                "These pose severe risk to security."
            )
        
        if severity_counts.get('high', 0) > 0:
            recommendations.append(
                f"HIGH PRIORITY: Remediate {severity_counts['high']} high-severity vulnerabilities "
                "within 7 days."
            )
        
        if overall_score >= 70:
            recommendations.append(
                "Overall risk level is high. Consider implementing temporary mitigations "
                "such as network segmentation or access restrictions."
            )
        
        if severity_counts.get('medium', 0) > 5:
            recommendations.append(
                "Schedule regular patching cycles to address the backlog of medium-severity issues."
            )
        
        return recommendations
