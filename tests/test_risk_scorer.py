"""
Unit tests for Risk Scorer
"""
import pytest
from backend.app.ml.risk_scorer import RiskScorer


def test_risk_scorer_basic():
    """Test basic risk score calculation"""
    scorer = RiskScorer()
    
    vulnerability = {
        'title': 'Test Vulnerability',
        'severity': 'high',
        'cvss_score': 7.5,
        'evidence': 'Test evidence',
        'description': 'Test description',
        'port': 443
    }
    
    score = scorer.calculate_risk_score(vulnerability, 'medium')
    
    assert isinstance(score, float)
    assert 0 <= score <= 100


def test_risk_scorer_critical_severity():
    """Test critical severity gets high score"""
    scorer = RiskScorer()
    
    vulnerability = {
        'title': 'Critical Vulnerability',
        'severity': 'critical',
        'cvss_score': 9.8,
        'evidence': 'remote code execution exploit available',
        'description': 'Critical RCE vulnerability',
        'port': 22
    }
    
    score = scorer.calculate_risk_score(vulnerability, 'critical')
    
    assert score > 70  # Should be high risk


def test_risk_scorer_info_severity():
    """Test info severity gets low score"""
    scorer = RiskScorer()
    
    vulnerability = {
        'title': 'Information Disclosure',
        'severity': 'info',
        'cvss_score': 2.0,
        'evidence': 'banner information',
        'description': 'Server version disclosed',
        'port': 80
    }
    
    score = scorer.calculate_risk_score(vulnerability, 'low')
    
    assert score < 30  # Should be low risk


def test_overall_risk_calculation():
    """Test overall risk assessment"""
    scorer = RiskScorer()
    
    vulnerabilities = [
        {
            'severity': 'critical',
            'ml_risk_score': 95.0,
            'title': 'Critical Vuln'
        },
        {
            'severity': 'high',
            'ml_risk_score': 75.0,
            'title': 'High Vuln'
        },
        {
            'severity': 'medium',
            'ml_risk_score': 50.0,
            'title': 'Medium Vuln'
        },
        {
            'severity': 'low',
            'ml_risk_score': 25.0,
            'title': 'Low Vuln'
        }
    ]
    
    result = scorer.calculate_overall_risk(vulnerabilities)
    
    assert 'overall_risk_score' in result
    assert 'risk_level' in result
    assert result['total_vulnerabilities'] == 4
    assert result['critical_count'] == 1
    assert result['high_count'] == 1


def test_empty_vulnerabilities():
    """Test with no vulnerabilities"""
    scorer = RiskScorer()
    
    result = scorer.calculate_overall_risk([])
    
    assert result['overall_risk_score'] == 0.0
    assert result['total_vulnerabilities'] == 0


if __name__ == '__main__':
    pytest.main([__file__])
