# WordPress Security Scanner Configuration

from dotenv import load_dotenv
import os

load_dotenv()
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

# Server Configuration
HOST = '0.0.0.0'
PORT = 5000
DEBUG = True

# Security Settings
MAX_SCAN_THREADS = 10
REQUEST_TIMEOUT = 30
RATE_LIMIT = 100  # requests per minute

# Database Configuration
DATABASE_PATH = 'security_scanner.db'

# Logging Configuration
LOG_LEVEL = 'INFO'
LOG_FILE = 'logs/security_scanner.log'

# Tool Paths (will be auto-detected)
SQLMAP_PATH = 'sqlmap'
NMAP_PATH = 'nmap'
WPSCAN_PATH = 'wpscan'
NIKTO_PATH = 'nikto'
HYDRA_PATH = 'hydra'

# Wordlist Paths
WORDLIST_DIR = 'wordlists'
PASSWORD_LIST = 'wordlists/common_passwords.txt'
USERNAME_LIST = 'wordlists/common_usernames.txt'
PLUGIN_LIST = 'wordlists/wp_plugins.txt'

# Report Configuration
REPORT_DIR = 'reports'
REPORT_FORMATS = ['html', 'json', 'pdf']
