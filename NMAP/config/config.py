# config/config.py
import os
from dotenv import load_dotenv

load_dotenv()

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# It's recommended to store the API key in a .env file and load it via os.getenv("NVD_API_KEY")
# Example .env file content:
# NVD_API_KEY=your_actual_api_key_here
NVD_API_KEY = os.getenv("NVD_API_KEY") # Corrected this to use the env var name

# Scanning Configuration
DEFAULT_SCAN_ARGUMENTS = "-sV"
SCAN_TIMEOUT = 300

# Rate Limiting for NVD API
API_RATE_LIMIT = 50
API_RATE_PERIOD = 30

# Report Configuration
DEFAULT_REPORT_FILENAME = "vulnerability_report.json"