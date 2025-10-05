"""
CVE Database Integration
Fetches CVE details from NVD (National Vulnerability Database)
"""
import requests
import logging
from typing import Dict, Optional
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CVELookup:
    """CVE database integration for vulnerability enrichment"""
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = os.getenv('NVD_API_KEY')
        self.cache = {}  # Simple in-memory cache
        self.cache_duration = timedelta(hours=24)
        
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch detailed information about a CVE
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
            
        Returns:
            Dictionary with CVE details or None if not found
        """
        try:
            # Check cache first
            if cve_id in self.cache:
                cached_data, cached_time = self.cache[cve_id]
                if datetime.now() - cached_time < self.cache_duration:
                    logger.debug(f"Using cached data for {cve_id}")
                    return cached_data
            
            logger.info(f"Fetching CVE details for {cve_id}")
            
            # Build request
            url = f"{self.base_url}"
            params = {'cveId': cve_id}
            headers = {}
            
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            # Make request with timeout
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if 'vulnerabilities' not in data or len(data['vulnerabilities']) == 0:
                logger.warning(f"No data found for {cve_id}")
                return None
            
            cve_item = data['vulnerabilities'][0]['cve']
            
            # Parse CVE data
            cve_details = self._parse_cve_data(cve_item)
            
            # Cache the result
            self.cache[cve_id] = (cve_details, datetime.now())
            
            return cve_details
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error processing {cve_id}: {str(e)}")
            return None
    
    def _parse_cve_data(self, cve_item: Dict) -> Dict:
        """Parse CVE data from NVD API response"""
        try:
            # Extract description
            description = "No description available"
            if 'descriptions' in cve_item:
                for desc in cve_item['descriptions']:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', description)
                        break
            
            # Extract CVSS scores
            cvss_v3_score = None
            cvss_v3_severity = None
            
            if 'metrics' in cve_item:
                if 'cvssMetricV31' in cve_item['metrics']:
                    cvss_data = cve_item['metrics']['cvssMetricV31'][0]['cvssData']
                    cvss_v3_score = cvss_data.get('baseScore')
                    cvss_v3_severity = cvss_data.get('baseSeverity', '').lower()
                elif 'cvssMetricV30' in cve_item['metrics']:
                    cvss_data = cve_item['metrics']['cvssMetricV30'][0]['cvssData']
                    cvss_v3_score = cvss_data.get('baseScore')
                    cvss_v3_severity = cvss_data.get('baseSeverity', '').lower()
            
            # Extract CWE
            cwe_ids = []
            if 'weaknesses' in cve_item:
                for weakness in cve_item['weaknesses']:
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_ids.append(desc.get('value'))
            
            # Extract references
            references = []
            if 'references' in cve_item:
                for ref in cve_item['references'][:5]:  # Limit to 5 references
                    references.append({
                        'url': ref.get('url'),
                        'source': ref.get('source')
                    })
            
            # Published and modified dates
            published = cve_item.get('published', '')
            modified = cve_item.get('lastModified', '')
            
            return {
                'cve_id': cve_item.get('id'),
                'description': description,
                'cvss_score': cvss_v3_score,
                'severity': cvss_v3_severity,
                'cwe_ids': cwe_ids,
                'references': references,
                'published': published,
                'modified': modified
            }
            
        except Exception as e:
            logger.error(f"Error parsing CVE data: {str(e)}")
            return {}
    
    def enrich_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Enrich vulnerability data with CVE information
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            Enriched vulnerability dictionary
        """
        if 'cve_id' not in vulnerability or not vulnerability['cve_id']:
            return vulnerability
        
        cve_details = self.get_cve_details(vulnerability['cve_id'])
        
        if cve_details:
            # Update vulnerability with CVE data
            if not vulnerability.get('description'):
                vulnerability['description'] = cve_details.get('description')
            
            if not vulnerability.get('cvss_score'):
                vulnerability['cvss_score'] = cve_details.get('cvss_score')
            
            if not vulnerability.get('severity'):
                vulnerability['severity'] = cve_details.get('severity')
            
            if cve_details.get('cwe_ids'):
                vulnerability['cwe_id'] = cve_details['cwe_ids'][0]
            
            vulnerability['references'] = cve_details.get('references', [])
            
            logger.info(f"Enriched vulnerability with CVE data: {vulnerability['cve_id']}")
        
        return vulnerability
    
    def search_cves_by_keyword(self, keyword: str, limit: int = 10) -> list:
        """
        Search for CVEs by keyword
        
        Args:
            keyword: Search keyword
            limit: Maximum number of results
            
        Returns:
            List of CVE summaries
        """
        try:
            logger.info(f"Searching CVEs for keyword: {keyword}")
            
            url = f"{self.base_url}"
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': limit
            }
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            results = []
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_item = vuln['cve']
                    results.append(self._parse_cve_data(cve_item))
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching CVEs: {str(e)}")
            return []
