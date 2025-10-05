"""
Database models for Scan-U
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import JSON

db = SQLAlchemy()

class Scan(db.Model):
    """Scan sessions/jobs"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # network, web, code
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # in seconds
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'vulnerability_count': len(self.vulnerabilities)
        }


class Vulnerability(db.Model):
    """Discovered vulnerabilities"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    # Vulnerability details
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    cvss_score = db.Column(db.Float)
    cve_id = db.Column(db.String(50))
    cwe_id = db.Column(db.String(50))
    
    # Location
    host = db.Column(db.String(255))
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    url = db.Column(db.String(500))
    
    # ML Analysis
    ml_risk_score = db.Column(db.Float)  # ML-computed risk score
    confidence = db.Column(db.Float)  # ML confidence level
    is_false_positive = db.Column(db.Boolean, default=False)
    false_positive_confidence = db.Column(db.Float)
    
    # Additional data
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    references = db.Column(JSON)
    
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'host': self.host,
            'port': self.port,
            'service': self.service,
            'url': self.url,
            'ml_risk_score': self.ml_risk_score,
            'confidence': self.confidence,
            'is_false_positive': self.is_false_positive,
            'false_positive_confidence': self.false_positive_confidence,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }


class Asset(db.Model):
    """Tracked assets/targets"""
    __tablename__ = 'assets'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    asset_type = db.Column(db.String(50))  # server, web_app, network, code_repo
    ip_address = db.Column(db.String(50))
    hostname = db.Column(db.String(255))
    description = db.Column(db.Text)
    business_criticality = db.Column(db.String(20))  # critical, high, medium, low
    
    # Tracking
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    
    # Metadata
    tags = db.Column(JSON)
    metadata = db.Column(JSON)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'asset_type': self.asset_type,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'description': self.description,
            'business_criticality': self.business_criticality,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'tags': self.tags,
            'metadata': self.metadata
        }


class RiskAssessment(db.Model):
    """Risk assessment results"""
    __tablename__ = 'risk_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    # Overall risk metrics
    overall_risk_score = db.Column(db.Float)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    
    # False positive analysis
    total_findings = db.Column(db.Integer, default=0)
    false_positive_count = db.Column(db.Integer, default=0)
    false_positive_rate = db.Column(db.Float)
    
    # ML insights
    ml_insights = db.Column(JSON)
    threat_trends = db.Column(JSON)
    recommendations = db.Column(JSON)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'overall_risk_score': self.overall_risk_score,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'total_findings': self.total_findings,
            'false_positive_count': self.false_positive_count,
            'false_positive_rate': self.false_positive_rate,
            'ml_insights': self.ml_insights,
            'threat_trends': self.threat_trends,
            'recommendations': self.recommendations,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
