import nmap
import logging
from typing import Dict, List, Any

class NmapScanner:
    """
    A wrapper class for performing Nmap scans.
    """
    def __init__(self):
        """
        Initializes the Nmap PortScanner and logger.
        """
        try:
            self.scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            logging.error(f"Nmap is not installed or not found in PATH: {e}")
            # Handle the error appropriately, e.g., by exiting or raising a custom exception
            raise SystemExit("Nmap is required but not found. Please install Nmap and ensure it's in your system's PATH.")
        self.logger = logging.getLogger(__name__)

    def scan_target(self, target: str, arguments: str) -> List[Dict[str, Any]]:
        """
        Performs an Nmap scan on the specified target with given arguments.

        Args:
            target: The IP address or hostname to scan.
            arguments: Nmap command-line arguments.

        Returns:
            A list of dictionaries, each representing a discovered service.

        Raises:
            Exception: If any error occurs during the scan.
        """
        self.logger.info(f"Starting Nmap scan on target: {target} with arguments: {arguments}")
        try:
            # The nmap.PortScanner.scan() method returns a dictionary.
            scan_results_raw = self.scanner.scan(hosts=target, arguments=arguments)
            self.logger.info(f"Nmap scan completed for target: {target}")
            return self._parse_scan_results(scan_results_raw)
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error for target {target}: {e}")
            # This might indicate issues like host down, permissions, or bad arguments
            # Return an empty list or raise a more specific custom exception
            return []
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Nmap scan for {target}: {e}")
            raise

    def _parse_scan_results(self, scan_results_raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses the raw Nmap scan results into a structured format.

        Args:
            scan_results_raw: The raw output from nmap.PortScanner.scan().

        Returns:
            A list of dictionaries, each containing details of an open port and service.
        """
        parsed_results: List[Dict[str, Any]] = []
        if 'scan' not in scan_results_raw:
            self.logger.warning("No 'scan' key found in Nmap results. The host might be down or unresponsive.")
            return parsed_results

        for host_ip in scan_results_raw['scan']:
            host_data = scan_results_raw['scan'][host_ip]
            
            # Check if host is up
            if host_data.get('status', {}).get('state') != 'up':
                self.logger.info(f"Host {host_ip} is reported as {host_data.get('status', {}).get('state', 'unknown')}. Skipping.")
                continue

            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    if port_data.get('state') == 'open': # Process only open ports
                        product = port_data.get('product', '').strip()
                        version = port_data.get('version', '').strip()
                        
                        # Only add if product and version are reasonably identified
                        if product: # Require at least a product name
                            parsed_results.append({
                                'host': host_ip,
                                'port': int(port),
                                'protocol': 'tcp',
                                'name': port_data.get('name', '').strip(),
                                'product': product,
                                'version': version if version else "unknown", # Use "unknown" if version is empty
                                'state': port_data.get('state', 'unknown')
                            })
            # Optionally, add UDP parsing if '-sU' is used
            # if 'udp' in host_data:
            #     ... (similar parsing for UDP)

        if not parsed_results:
            self.logger.info("No open ports with service information found in the scan results.")
        return parsed_results