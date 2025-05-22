import requests
import logging
from typing import Dict, List, Any
from functools import lru_cache
from ratelimit import limits, sleep_and_retry
from config.config import NVD_API_URL, NVD_API_KEY, API_RATE_LIMIT, API_RATE_PERIOD

class NVDChecker:
    """
    Queries the NVD API for vulnerabilities based on product and version.
    """
    def __init__(self):
        """
        Initializes the NVDChecker with logger and API headers.
        """
        self.logger = logging.getLogger(__name__)
        self.headers: Dict[str, str] = {}
        if NVD_API_KEY:
            self.headers['apiKey'] = NVD_API_KEY
            self.logger.info("NVD API key found and configured for NVDChecker.")
        else:
            self.logger.warning("NVD_API_KEY not found. NVD API requests will be subject to lower public rate limits.")


    @sleep_and_retry
    @limits(calls=API_RATE_LIMIT, period=API_RATE_PERIOD)
    @lru_cache(maxsize=256) # Increased cache size for more unique product/version pairs
    def check_vulnerabilities(self, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Queries the NVD API for vulnerabilities associated with a specific product and version.

        Args:
            product: The name of the product.
            version: The version of the product.

        Returns:
            A list of dictionaries, each representing a vulnerability.
        """
        if not product:
            self.logger.warning("Product name is empty, cannot query NVD.")
            return []

        search_query = f"{product} {version}" if version and version.lower() != "unknown" else product
        
        params = {
            'keywordSearch': search_query,
            'resultsPerPage': 50,
        }
        
        self.logger.info(f"Querying NVD for: {search_query}")

        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=self.headers,
                timeout=30  # seconds
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_nvd_response(data, product, version)
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"NVD API HTTP error for '{search_query}': {e.response.status_code} - {e.response.text}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"NVD API request error for '{search_query}': {e}")
        except ValueError: # Includes JSONDecodeError
            self.logger.error(f"Failed to decode JSON response from NVD for '{search_query}'.")
        return []

    def _parse_nvd_response(self, response_data: Dict[str, Any], product_query: str, version_query: str) -> List[Dict[str, Any]]:
        """
        Parses the NVD API JSON response into a structured list of vulnerabilities.
        """
        vulnerabilities: List[Dict[str, Any]] = []
        
        if 'vulnerabilities' not in response_data:
            self.logger.info(f"No 'vulnerabilities' field in NVD response for {product_query} {version_query}.")
            return vulnerabilities

        for item in response_data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            if not cve:
                continue

            description = "No description available."
            if cve.get('descriptions'):
                for desc_item in cve['descriptions']:
                    if desc_item.get('lang') == 'en':
                        description = desc_item.get('value', description)
                        break
            
            vulnerability = {
                'cve_id': cve.get('id'),
                'description': description,
                'severity': self._get_severity(cve),
                'score': self._get_base_score(cve),
                'published_date': cve.get('published'),
                'last_modified_date': cve.get('lastModified'),
                'url': f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}" if cve.get('id') else None,
                'references': [ref.get('url') for ref in cve.get('references', []) if ref.get('url')]
            }
            vulnerabilities.append(vulnerability)
            
        self.logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from NVD for {product_query} {version_query}.")
        return vulnerabilities

    def _get_cvss_data(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Helper to get the CVSS v3.1 data if available, else v3.0, else v2."""
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            return metrics['cvssMetricV31'][0].get('cvssData', {})
        if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            return metrics['cvssMetricV30'][0].get('cvssData', {})
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            return {'baseScore': metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')}
        return {}

    def _get_base_score(self, cve: Dict[str, Any]) -> float | None:
        """Extracts the base score from CVSS data."""
        cvss_data = self._get_cvss_data(cve)
        return cvss_data.get('baseScore')


    def _get_severity(self, cve: Dict[str, Any]) -> str:
        """
        Determines the severity of a CVE based on its CVSS v3.x score.
        """
        cvss_data = self._get_cvss_data(cve)
        base_score = cvss_data.get('baseScore')

        if base_score is None:
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                severity_str = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
                if severity_str: return severity_str.upper()
            if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                severity_str = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
                if severity_str: return severity_str.upper()
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                severity_str = metrics['cvssMetricV2'][0].get('baseSeverity')
                if severity_str: return severity_str.upper()
            return 'UNKNOWN'

        base_score = float(base_score)
        if base_score >= 9.0:
            return 'CRITICAL'
        elif base_score >= 7.0:
            return 'HIGH'
        elif base_score >= 4.0:
            return 'MEDIUM'
        elif base_score > 0.0:
            return 'LOW'
        else:
            return 'NONE'