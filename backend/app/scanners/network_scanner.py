"""
Network Scanner Module
Uses Nmap for network vulnerability scanning
"""
import nmap
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Network vulnerability scanner using Nmap"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def scan_host(self, target: str, scan_type: str = 'basic') -> Dict:
        """
        Scan a target host for vulnerabilities
        
        Args:
            target: IP address or hostname to scan
            scan_type: Type of scan (basic, aggressive, stealth)
            
        Returns:
            Dictionary containing scan results
        """
        try:
            logger.info(f"Starting {scan_type} scan on {target}")
            
            # Select scan arguments based on type
            if scan_type == 'aggressive':
                arguments = '-A -T4 -sV --script=vuln'
            elif scan_type == 'stealth':
                arguments = '-sS -sV -T2'
            else:  # basic
                arguments = '-sV -sC'
            
            # Perform scan
            self.nm.scan(target, arguments=arguments)
            
            results = {
                'target': target,
                'scan_type': scan_type,
                'hosts': [],
                'vulnerabilities': []
            }
            
            # Parse results
            for host in self.nm.all_hosts():
                host_data = {
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'ports': []
                }
                
                # Analyze ports
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        port_data = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                        host_data['ports'].append(port_data)
                        
                        # Check for potential vulnerabilities
                        if 'script' in port_info:
                            for script_name, script_output in port_info['script'].items():
                                if self._is_vulnerability(script_output):
                                    vuln = self._create_vulnerability(
                                        host, port, port_data['service'],
                                        script_name, script_output
                                    )
                                    results['vulnerabilities'].append(vuln)
                
                results['hosts'].append(host_data)
            
            logger.info(f"Scan completed. Found {len(results['vulnerabilities'])} potential vulnerabilities")
            return results
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {str(e)}")
            raise
    
    def _is_vulnerability(self, script_output: str) -> bool:
        """Check if script output indicates a vulnerability"""
        vulnerability_keywords = [
            'VULNERABLE', 'vulnerable', 'CVE-', 'exploit',
            'security risk', 'weakness', 'outdated version'
        ]
        return any(keyword in script_output for keyword in vulnerability_keywords)
    
    def _create_vulnerability(self, host: str, port: int, service: str,
                            script_name: str, output: str) -> Dict:
        """Create vulnerability dictionary from scan results"""
        # Extract CVE if present
        cve_id = None
        if 'CVE-' in output:
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', output)
            if cve_match:
                cve_id = cve_match.group(0)
        
        # Determine severity based on keywords
        severity = self._determine_severity(output)
        
        return {
            'host': host,
            'port': port,
            'service': service,
            'title': f"{service} vulnerability detected on port {port}",
            'description': output,
            'severity': severity,
            'cve_id': cve_id,
            'evidence': f"Script: {script_name}\n{output}"
        }
    
    def _determine_severity(self, output: str) -> str:
        """Determine vulnerability severity from output"""
        output_lower = output.lower()
        
        if any(word in output_lower for word in ['critical', 'remote code execution', 'rce']):
            return 'critical'
        elif any(word in output_lower for word in ['high', 'severe', 'dangerous']):
            return 'high'
        elif any(word in output_lower for word in ['medium', 'moderate']):
            return 'medium'
        elif any(word in output_lower for word in ['low', 'minor']):
            return 'low'
        else:
            return 'info'
    
    def scan_network(self, network_range: str) -> Dict:
        """
        Scan an entire network range
        
        Args:
            network_range: Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            Dictionary containing scan results for all hosts
        """
        try:
            logger.info(f"Starting network scan on {network_range}")
            
            # First, discover live hosts
            self.nm.scan(hosts=network_range, arguments='-sn')
            live_hosts = self.nm.all_hosts()
            
            logger.info(f"Found {len(live_hosts)} live hosts")
            
            # Scan each live host
            all_results = {
                'network_range': network_range,
                'live_hosts': len(live_hosts),
                'hosts': [],
                'vulnerabilities': []
            }
            
            for host in live_hosts:
                try:
                    host_results = self.scan_host(host, scan_type='basic')
                    all_results['hosts'].extend(host_results['hosts'])
                    all_results['vulnerabilities'].extend(host_results['vulnerabilities'])
                except Exception as e:
                    logger.warning(f"Failed to scan host {host}: {str(e)}")
                    continue
            
            return all_results
            
        except Exception as e:
            logger.error(f"Error scanning network {network_range}: {str(e)}")
            raise
