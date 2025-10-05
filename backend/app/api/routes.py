"""
REST API Routes for Scan-U
"""
from flask import Blueprint, request, jsonify
from backend.app.database.models import db, Scan, Vulnerability, Asset, RiskAssessment
from backend.app.scanners.network_scanner import NetworkScanner
from backend.app.scanners.cve_lookup import CVELookup
from backend.app.ml.risk_scorer import RiskScorer
from backend.app.ml.false_positive_detector import FalsePositiveDetector
from datetime import datetime
import logging
import threading

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)

# Initialize components
network_scanner = NetworkScanner()
cve_lookup = CVELookup()
risk_scorer = RiskScorer()
fp_detector = FalsePositiveDetector()

# Active scans tracking
active_scans = {}


@api_bp.route('/health', methods=['GET'])
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'Scan-U API',
        'version': '1.0.0'
    })


@api_bp.route('/scans', methods=['GET'])
def get_scans():
    """Get all scans"""
    try:
        scans = Scan.query.order_by(Scan.started_at.desc()).all()
        return jsonify({
            'success': True,
            'scans': [scan.to_dict() for scan in scans]
        })
    except Exception as e:
        logger.error(f"Error fetching scans: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        scan_data = scan.to_dict()
        
        # Include vulnerabilities
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        scan_data['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
        
        # Include risk assessment if available
        risk_assessment = RiskAssessment.query.filter_by(scan_id=scan_id).first()
        if risk_assessment:
            scan_data['risk_assessment'] = risk_assessment.to_dict()
        
        return jsonify({
            'success': True,
            'scan': scan_data
        })
    except Exception as e:
        logger.error(f"Error fetching scan {scan_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/scans', methods=['POST'])
def create_scan():
    """Create and start a new scan"""
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'basic')
        asset_criticality = data.get('asset_criticality', 'medium')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        # Create scan record
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status='pending'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan,
            args=(scan.id, target, scan_type, asset_criticality)
        )
        thread.daemon = True
        thread.start()
        
        active_scans[scan.id] = thread
        
        logger.info(f"Started scan {scan.id} for target {target}")
        
        return jsonify({
            'success': True,
            'scan': scan.to_dict(),
            'message': 'Scan started successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating scan: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


def run_scan(scan_id, target, scan_type, asset_criticality):
    """Background task to run a scan"""
    try:
        logger.info(f"Running scan {scan_id} on {target}")
        
        # Update scan status
        scan = Scan.query.get(scan_id)
        scan.status = 'running'
        scan.started_at = datetime.utcnow()
        db.session.commit()
        
        # Perform network scan
        scan_results = network_scanner.scan_host(target, scan_type)
        
        # Process vulnerabilities
        vulnerabilities = []
        for vuln_data in scan_results.get('vulnerabilities', []):
            # Enrich with CVE data
            if vuln_data.get('cve_id'):
                vuln_data = cve_lookup.enrich_vulnerability(vuln_data)
            
            # Calculate risk score
            risk_score = risk_scorer.calculate_risk_score(vuln_data, asset_criticality)
            vuln_data['ml_risk_score'] = risk_score
            vuln_data['confidence'] = 0.85  # Default confidence
            
            # Detect false positives
            is_fp, fp_confidence = fp_detector.detect_false_positive(vuln_data)
            vuln_data['is_false_positive'] = is_fp
            vuln_data['false_positive_confidence'] = fp_confidence
            
            # Create vulnerability record
            vulnerability = Vulnerability(
                scan_id=scan_id,
                title=vuln_data.get('title'),
                description=vuln_data.get('description'),
                severity=vuln_data.get('severity'),
                cvss_score=vuln_data.get('cvss_score'),
                cve_id=vuln_data.get('cve_id'),
                cwe_id=vuln_data.get('cwe_id'),
                host=vuln_data.get('host'),
                port=vuln_data.get('port'),
                service=vuln_data.get('service'),
                ml_risk_score=risk_score,
                confidence=vuln_data.get('confidence'),
                is_false_positive=is_fp,
                false_positive_confidence=fp_confidence,
                evidence=vuln_data.get('evidence'),
                remediation=vuln_data.get('remediation'),
                references=vuln_data.get('references')
            )
            db.session.add(vulnerability)
            vulnerabilities.append(vuln_data)
        
        db.session.commit()
        
        # Calculate overall risk assessment
        overall_risk = risk_scorer.calculate_overall_risk(vulnerabilities)
        fp_analysis = fp_detector.analyze_false_positive_rate(vulnerabilities)
        
        # Create risk assessment record
        risk_assessment = RiskAssessment(
            scan_id=scan_id,
            overall_risk_score=overall_risk['overall_risk_score'],
            critical_count=overall_risk.get('critical_count', 0),
            high_count=overall_risk.get('high_count', 0),
            medium_count=overall_risk.get('medium_count', 0),
            low_count=overall_risk.get('low_count', 0),
            info_count=overall_risk.get('info_count', 0),
            total_findings=overall_risk['total_vulnerabilities'],
            false_positive_count=fp_analysis['false_positive_count'],
            false_positive_rate=fp_analysis['false_positive_rate'],
            ml_insights={'overall_risk': overall_risk, 'fp_analysis': fp_analysis},
            recommendations=overall_risk.get('recommendations', [])
        )
        db.session.add(risk_assessment)
        
        # Update scan status
        scan.status = 'completed'
        scan.completed_at = datetime.utcnow()
        scan.duration = int((scan.completed_at - scan.started_at).total_seconds())
        db.session.commit()
        
        logger.info(f"Scan {scan_id} completed successfully")
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        
    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {str(e)}")
        
        # Update scan status to failed
        try:
            scan = Scan.query.get(scan_id)
            scan.status = 'failed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
        except:
            pass
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]


@api_bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get all vulnerabilities with optional filtering"""
    try:
        # Query parameters
        scan_id = request.args.get('scan_id', type=int)
        severity = request.args.get('severity')
        exclude_fp = request.args.get('exclude_fp', 'false').lower() == 'true'
        
        query = Vulnerability.query
        
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if exclude_fp:
            query = query.filter_by(is_false_positive=False)
        
        vulnerabilities = query.order_by(Vulnerability.ml_risk_score.desc()).all()
        
        return jsonify({
            'success': True,
            'vulnerabilities': [v.to_dict() for v in vulnerabilities],
            'count': len(vulnerabilities)
        })
        
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/vulnerabilities/<int:vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id):
    """Get a specific vulnerability"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vuln_id)
        return jsonify({
            'success': True,
            'vulnerability': vulnerability.to_dict()
        })
    except Exception as e:
        logger.error(f"Error fetching vulnerability {vuln_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/risk-assessment/<int:scan_id>', methods=['GET'])
def get_risk_assessment(scan_id):
    """Get risk assessment for a scan"""
    try:
        risk_assessment = RiskAssessment.query.filter_by(scan_id=scan_id).first()
        
        if not risk_assessment:
            return jsonify({
                'success': False,
                'error': 'Risk assessment not found'
            }), 404
        
        return jsonify({
            'success': True,
            'risk_assessment': risk_assessment.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error fetching risk assessment: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/assets', methods=['GET'])
def get_assets():
    """Get all assets"""
    try:
        assets = Asset.query.all()
        return jsonify({
            'success': True,
            'assets': [asset.to_dict() for asset in assets]
        })
    except Exception as e:
        logger.error(f"Error fetching assets: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/assets', methods=['POST'])
def create_asset():
    """Create a new asset"""
    try:
        data = request.get_json()
        
        asset = Asset(
            name=data.get('name'),
            asset_type=data.get('asset_type'),
            ip_address=data.get('ip_address'),
            hostname=data.get('hostname'),
            description=data.get('description'),
            business_criticality=data.get('business_criticality', 'medium'),
            tags=data.get('tags'),
            metadata=data.get('metadata')
        )
        
        db.session.add(asset)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'asset': asset.to_dict(),
            'message': 'Asset created successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating asset: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Total scans
        total_scans = Scan.query.count()
        completed_scans = Scan.query.filter_by(status='completed').count()
        
        # Total vulnerabilities
        total_vulnerabilities = Vulnerability.query.count()
        
        # Vulnerabilities by severity
        critical_count = Vulnerability.query.filter_by(severity='critical').count()
        high_count = Vulnerability.query.filter_by(severity='high').count()
        medium_count = Vulnerability.query.filter_by(severity='medium').count()
        low_count = Vulnerability.query.filter_by(severity='low').count()
        
        # False positive stats
        total_fp = Vulnerability.query.filter_by(is_false_positive=True).count()
        fp_rate = (total_fp / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
        
        # Recent scans
        recent_scans = Scan.query.order_by(Scan.started_at.desc()).limit(5).all()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_scans': total_scans,
                'completed_scans': completed_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'severity_breakdown': {
                    'critical': critical_count,
                    'high': high_count,
                    'medium': medium_count,
                    'low': low_count
                },
                'false_positive_rate': round(fp_rate, 2),
                'recent_scans': [scan.to_dict() for scan in recent_scans]
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/cve/<cve_id>', methods=['GET'])
def lookup_cve(cve_id):
    """Lookup CVE details"""
    try:
        cve_data = cve_lookup.get_cve_details(cve_id)
        
        if not cve_data:
            return jsonify({
                'success': False,
                'error': 'CVE not found'
            }), 404
        
        return jsonify({
            'success': True,
            'cve': cve_data
        })
        
    except Exception as e:
        logger.error(f"Error looking up CVE {cve_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
