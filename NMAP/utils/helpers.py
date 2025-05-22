# utils/helpers.py
import json
from datetime import datetime
from typing import Dict, List, Any

def generate_report_data(scan_results: List[Dict[str, Any]], vulnerabilities_map: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Generates a structured report from scan results and vulnerabilities.

    Args:
        scan_results: A list of dictionaries from NmapScanner.
        vulnerabilities_map: A dictionary where keys are 'product_version' strings
                             and values are lists of NVD vulnerability details.

    Returns:
        A dictionary containing the comprehensive report.
    """
    report_findings: List[Dict[str, Any]] = []
    total_vulnerabilities_count = 0 # Defined with one underscore
    unique_hosts = set()

    for service_info in scan_results:
        unique_hosts.add(service_info['host'])

        product = service_info.get('product')
        version = service_info.get('version', "unknown") 
        if not version or version.lower() == "unknown":
            version = "unknown"
        
        vuln_key = "unknown_unknown" 
        if product and version:
            vuln_key = f"{product.lower()}_{version.lower()}"
        elif product: 
            vuln_key = f"{product.lower()}_unknown"

        service_vulnerabilities = vulnerabilities_map.get(vuln_key, [])
        total_vulnerabilities_count += len(service_vulnerabilities) # Incremented with one underscore

        finding = {
            'host': service_info['host'],
            'port': service_info['port'],
            'service': {
                'name': service_info.get('name', 'N/A'),
                'product': product if product else 'N/A',
                'version': version
            },
            'vulnerabilities': service_vulnerabilities,
            'vulnerability_count': len(service_vulnerabilities)
        }
        report_findings.append(finding)

    report = {
        'scan_timestamp': datetime.now().isoformat(),
        'summary': {
            'total_hosts': len(unique_hosts),
            'total_services': len(scan_results),
            'total_vulnerabilities_found': total_vulnerabilities_count # CORRECTED HERE
        },
        'findings': report_findings
    }
    return report

def save_report_to_file(report_data: Dict[str, Any], filename: str) -> None:
    # ... (rest of the function remains the same)
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"Report successfully saved to {filename}")
    except IOError as e:
        print(f"Error saving report to {filename}: {e}")