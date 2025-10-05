"""
False Positive Detector
ML-based false positive detection and filtering
"""
import logging
from typing import Dict, List
import re

logger = logging.getLogger(__name__)

class FalsePositiveDetector:
    """Detects and filters false positive vulnerabilities"""
    
    # Known false positive patterns
    FALSE_POSITIVE_PATTERNS = [
        # Generic informational findings
        r'information disclosure',
        r'banner grabbing',
        r'version detection',
        
        # Common misconfigurations that are intentional
        r'http methods allowed',
        r'directory listing',
        
        # Test/development indicators
        r'test page',
        r'default page',
        r'example',
    ]
    
    # Known benign services
    BENIGN_SERVICES = {
        'http': ['200 OK', 'healthy', 'running'],
        'https': ['200 OK', 'healthy', 'running'],
        'ssh': ['OpenSSH'],
        'dns': ['53'],
    }
    
    def __init__(self):
        self.confidence_threshold = 0.7
        self.false_positive_history = {}  # Track historical patterns
    
    def detect_false_positive(self, vulnerability: Dict) -> tuple[bool, float]:
        """
        Detect if a vulnerability is likely a false positive
        
        Args:
            vulnerability: Vulnerability data dictionary
            
        Returns:
            Tuple of (is_false_positive, confidence)
        """
        try:
            confidence_scores = []
            
            # Check severity - info level is more likely FP
            severity = vulnerability.get('severity', '').lower()
            if severity == 'info':
                confidence_scores.append(0.5)
            elif severity == 'low':
                confidence_scores.append(0.3)
            
            # Check for false positive patterns in description
            description = vulnerability.get('description', '').lower()
            evidence = vulnerability.get('evidence', '').lower()
            combined_text = f"{description} {evidence}"
            
            pattern_matches = 0
            for pattern in self.FALSE_POSITIVE_PATTERNS:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    pattern_matches += 1
            
            if pattern_matches > 0:
                # More matches = higher confidence of FP
                pattern_confidence = min(0.9, pattern_matches * 0.3)
                confidence_scores.append(pattern_confidence)
            
            # Check for benign service patterns
            service = vulnerability.get('service', '').lower()
            if service in self.BENIGN_SERVICES:
                benign_indicators = self.BENIGN_SERVICES[service]
                for indicator in benign_indicators:
                    if indicator.lower() in combined_text:
                        confidence_scores.append(0.4)
                        break
            
            # Check for missing critical information
            if not vulnerability.get('cve_id') and severity in ['info', 'low']:
                confidence_scores.append(0.3)
            
            # Check for very low CVSS scores
            cvss_score = vulnerability.get('cvss_score', 0)
            if cvss_score and cvss_score < 3.0:
                confidence_scores.append(0.4)
            
            # Calculate overall confidence
            if confidence_scores:
                overall_confidence = sum(confidence_scores) / len(confidence_scores)
                is_false_positive = overall_confidence >= self.confidence_threshold
            else:
                overall_confidence = 0.0
                is_false_positive = False
            
            # Cap confidence at 0.95 (never 100% certain)
            overall_confidence = min(0.95, overall_confidence)
            
            if is_false_positive:
                logger.info(
                    f"Detected likely false positive: {vulnerability.get('title')} "
                    f"(confidence: {overall_confidence:.2f})"
                )
            
            return is_false_positive, round(overall_confidence, 2)
            
        except Exception as e:
            logger.error(f"Error detecting false positive: {str(e)}")
            return False, 0.0
    
    def filter_false_positives(self, vulnerabilities: List[Dict], 
                               mark_only: bool = False) -> tuple[List[Dict], int]:
        """
        Filter or mark false positives in a list of vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            mark_only: If True, mark FPs but don't remove them
            
        Returns:
            Tuple of (filtered_vulnerabilities, fp_count)
        """
        try:
            false_positive_count = 0
            filtered_vulns = []
            
            for vuln in vulnerabilities:
                is_fp, confidence = self.detect_false_positive(vuln)
                
                if is_fp:
                    false_positive_count += 1
                    vuln['is_false_positive'] = True
                    vuln['false_positive_confidence'] = confidence
                    
                    if mark_only:
                        filtered_vulns.append(vuln)
                    # else: skip this vulnerability (filter it out)
                else:
                    vuln['is_false_positive'] = False
                    vuln['false_positive_confidence'] = confidence
                    filtered_vulns.append(vuln)
            
            logger.info(
                f"False positive detection: {false_positive_count}/{len(vulnerabilities)} "
                f"flagged as potential FPs"
            )
            
            return filtered_vulns, false_positive_count
            
        except Exception as e:
            logger.error(f"Error filtering false positives: {str(e)}")
            return vulnerabilities, 0
    
    def analyze_false_positive_rate(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Analyze false positive rate for a set of vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary with FP analysis
        """
        try:
            if not vulnerabilities:
                return {
                    'total_findings': 0,
                    'false_positive_count': 0,
                    'false_positive_rate': 0.0,
                    'by_severity': {}
                }
            
            total = len(vulnerabilities)
            fp_count = 0
            by_severity = {}
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown')
                
                if severity not in by_severity:
                    by_severity[severity] = {'total': 0, 'false_positives': 0}
                
                by_severity[severity]['total'] += 1
                
                is_fp = vuln.get('is_false_positive', False)
                if is_fp:
                    fp_count += 1
                    by_severity[severity]['false_positives'] += 1
            
            # Calculate rates
            fp_rate = (fp_count / total) * 100 if total > 0 else 0.0
            
            for severity_data in by_severity.values():
                severity_total = severity_data['total']
                severity_fp = severity_data['false_positives']
                severity_data['rate'] = (severity_fp / severity_total * 100) if severity_total > 0 else 0.0
            
            return {
                'total_findings': total,
                'false_positive_count': fp_count,
                'false_positive_rate': round(fp_rate, 2),
                'true_positives': total - fp_count,
                'by_severity': by_severity,
                'improvement_metric': f"{100 - fp_rate:.1f}% accuracy"
            }
            
        except Exception as e:
            logger.error(f"Error analyzing false positive rate: {str(e)}")
            return {
                'total_findings': len(vulnerabilities),
                'false_positive_count': 0,
                'false_positive_rate': 0.0,
                'by_severity': {}
            }
