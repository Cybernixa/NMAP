import json
import logging
import argparse
import sys
import os # Added for path joining if needed, and for checking flask env var
from flask import Flask, request, jsonify, render_template
from typing import Dict, Any

# Assuming 'scanner' and 'utils' are directories at the same level as main.py
# If your project structure is different, Python's import mechanism might need help
# e.g. if main.py is inside another folder, you might need to adjust sys.path
# For now, standard structure is assumed.

from scanner.nmap_scanner import NmapScanner
from scanner.nvd_checker import NVDChecker
from utils.helpers import generate_report_data, save_report_to_file
from config.config import DEFAULT_SCAN_ARGUMENTS, DEFAULT_REPORT_FILENAME

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False # Ensure UTF-8 for jsonify

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VulnerabilityCheckerApp:
    def __init__(self):
        self.nmap_scanner = NmapScanner()
        self.nvd_checker = NVDChecker()
        self.logger = logging.getLogger(self.__class__.__name__)

    def perform_scan_and_analysis(self, target: str, nmap_arguments: str) -> Dict[str, Any]:
        self.logger.info(f"Initiating vulnerability check for target: {target} with Nmap args: '{nmap_arguments}'")
        
        discovered_services = self.nmap_scanner.scan_target(target, nmap_arguments)
        if not discovered_services:
            self.logger.warning(f"No services discovered by Nmap for target: {target}. Aborting NVD check.")
            return generate_report_data([], {})

        self.logger.info(f"Nmap scan completed. Found {len(discovered_services)} services for {target}.")

        vulnerabilities_map: Dict[str, list] = {}
        for service_info in discovered_services:
            product = service_info.get('product')
            version = service_info.get('version', "unknown")
            if not version or version.lower() == "unknown":
                version = "unknown"

            if not product or product.lower() == "unknown":
                self.logger.info(f"Skipping NVD check for service on {service_info['host']}:{service_info['port']} due to missing product information.")
                continue
            
            vuln_key = f"{product.lower()}_{version.lower()}"
            
            if vuln_key not in vulnerabilities_map:
                self.logger.debug(f"Querying NVD for {product} version {version}")
                vulnerabilities_map[vuln_key] = self.nvd_checker.check_vulnerabilities(
                    product,
                    version
                )
            else:
                 self.logger.debug(f"Using cached NVD results for {product} version {version} for this scan session.")

        self.logger.info("NVD vulnerability checking phase completed.")
        report = generate_report_data(discovered_services, vulnerabilities_map)
        return report

# --- Flask Web Application Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def handle_scan_request():
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': 'Missing target in request body'}), 400
        
        target = data['target'].strip()
        if not target:
            return jsonify({'error': 'Target cannot be empty'}), 400
            
        nmap_arguments = data.get('arguments', DEFAULT_SCAN_ARGUMENTS)

        checker_app = VulnerabilityCheckerApp()
        report_data = checker_app.perform_scan_and_analysis(target, nmap_arguments)
        
        return jsonify(report_data)

    except Exception as e:
        logger.error(f"Error during /scan request: {e}", exc_info=True)
        return jsonify({'error': 'An internal server error occurred', 'details': str(e)}), 500

# --- Command-Line Interface (CLI) ---
def run_cli():
    parser = argparse.ArgumentParser(description="Vulnerability Checker CLI")
    parser.add_argument("target", help="Target IP address or hostname to scan.")
    parser.add_argument(
        "-a", "--arguments",
        default=DEFAULT_SCAN_ARGUMENTS,
        help=f"Nmap scan arguments (default: \"{DEFAULT_SCAN_ARGUMENTS}\")."
    )
    parser.add_argument(
        "-o", "--output",
        help=f"Output report to a JSON file (e.g., {DEFAULT_REPORT_FILENAME}). If not specified, prints to console."
    )
    args = parser.parse_args()

    logger.info(f"CLI mode: Starting scan for target '{args.target}' with arguments '{args.arguments}'.")
    
    checker_app = VulnerabilityCheckerApp()
    report_data = checker_app.perform_scan_and_analysis(args.target, args.arguments)

    if args.output:
        save_report_to_file(report_data, args.output)
    else:
        print(json.dumps(report_data, indent=4, ensure_ascii=False))
    
    logger.info("CLI scan finished.")


if __name__ == "__main__":
    # This block runs if the script is executed directly (e.g., `python main.py ...`)
    if len(sys.argv) > 1 and sys.argv[1] not in ['run', 'routes'] and not os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        # If `python main.py target_ip` or `python main.py --help`
        # Exclude case where `flask run` re-executes the script (WERKZEUG_RUN_MAIN is set then)
        run_cli()
    else:
        # `python main.py` (no args), `python main.py run`, or when run by `flask run`
        logger.info("Starting Flask development server on http://0.0.0.0:5000")
        # For development, use host='0.0.0.0' to make it accessible on your network
        app.run(debug=True, host='0.0.0.0', port=5000)