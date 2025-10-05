"""
Unit tests for False Positive Detector
"""
import pytest
from backend.app.ml.false_positive_detector import FalsePositiveDetector


def test_fp_detector_info_severity():
    """Test that info severity is flagged as likely FP"""
    detector = FalsePositiveDetector()
    
    vulnerability = {
        'title': 'HTTP Methods Allowed',
        'severity': 'info',
        'description': 'HTTP methods allowed: GET, POST, HEAD',
        'evidence': 'Server responds to OPTIONS request',
        'cvss_score': 0.0
    }
    
    is_fp, confidence = detector.detect_false_positive(vulnerability)
    
    assert isinstance(is_fp, bool)
    assert 0 <= confidence <= 1


def test_fp_detector_critical_not_fp():
    """Test that critical vulnerabilities are not flagged as FP"""
    detector = FalsePositiveDetector()
    
    vulnerability = {
        'title': 'Remote Code Execution',
        'severity': 'critical',
        'description': 'Unauthenticated remote code execution vulnerability',
        'evidence': 'CVE-2021-44228 Log4Shell exploit confirmed',
        'cvss_score': 10.0,
        'cve_id': 'CVE-2021-44228'
    }
    
    is_fp, confidence = detector.detect_false_positive(vulnerability)
    
    assert is_fp == False


def test_filter_false_positives():
    """Test filtering false positives from list"""
    detector = FalsePositiveDetector()
    
    vulnerabilities = [
        {
            'title': 'Information Disclosure',
            'severity': 'info',
            'description': 'Banner information disclosed',
            'evidence': 'Server version detected'
        },
        {
            'title': 'SQL Injection',
            'severity': 'critical',
            'description': 'SQL injection vulnerability found',
            'evidence': 'Error-based SQL injection confirmed',
            'cve_id': 'CVE-2023-12345'
        }
    ]
    
    filtered, fp_count = detector.filter_false_positives(vulnerabilities, mark_only=True)
    
    assert len(filtered) == 2  # Both should be present with mark_only=True
    assert all('is_false_positive' in v for v in filtered)


def test_fp_analysis():
    """Test false positive rate analysis"""
    detector = FalsePositiveDetector()
    
    vulnerabilities = [
        {'severity': 'info', 'is_false_positive': True},
        {'severity': 'info', 'is_false_positive': True},
        {'severity': 'high', 'is_false_positive': False},
        {'severity': 'critical', 'is_false_positive': False}
    ]
    
    analysis = detector.analyze_false_positive_rate(vulnerabilities)
    
    assert analysis['total_findings'] == 4
    assert analysis['false_positive_count'] == 2
    assert analysis['false_positive_rate'] == 50.0


if __name__ == '__main__':
    pytest.main([__file__])
