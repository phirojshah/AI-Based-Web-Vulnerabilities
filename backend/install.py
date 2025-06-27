#!/usr/bin/env python3
"""
Installation Script for WordPress Security Scanner Backend
"""

import os
import sys
import subprocess
import platform
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        logger.error("Python 3.7 or higher is required")
        sys.exit(1)
    logger.info(f"Python version: {sys.version}")

def install_requirements():
    """Install Python requirements"""
    try:
        logger.info("Installing Python requirements...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        logger.info("Python requirements installed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install requirements: {e}")
        sys.exit(1)

def setup_directories():
    """Create necessary directories"""
    directories = [
        'logs',
        'reports',
        'wordlists',
        'exploits/payloads',
        'scanners/modules'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Created directory: {directory}")

def download_wordlists():
    """Download common wordlists"""
    wordlists = {
        'common_passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
        'common_usernames.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
        'wp_plugins.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress-plugins.txt'
    }
    
    try:
        import requests
        for filename, url in wordlists.items():
            filepath = os.path.join('wordlists', filename)
            if not os.path.exists(filepath):
                logger.info(f"Downloading {filename}...")
                response = requests.get(url)
                response.raise_for_status()
                with open(filepath, 'w') as f:
                    f.write(response.text)
                logger.info(f"Downloaded {filename}")
    except Exception as e:
        logger.warning(f"Failed to download wordlists: {e}")

def create_config_file():
    """Create default configuration file"""
    config_content = """# WordPress Security Scanner Configuration

# Server Configuration
HOST = '0.0.0.0'
PORT = 5000
DEBUG = False

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
"""
    
    with open('config.py', 'w') as f:
        f.write(config_content)
    logger.info("Created configuration file: config.py")

def install_system_tools():
    """Install system tools based on OS"""
    system = platform.system().lower()
    
    if system == 'linux':
        install_linux_tools()
    elif system == 'darwin':
        install_macos_tools()
    else:
        logger.warning("Automatic tool installation not supported on this OS")
        logger.info("Please install the following tools manually:")
        logger.info("- SQLMap")
        logger.info("- Nmap")
        logger.info("- WPScan (requires Ruby)")
        logger.info("- Nikto")
        logger.info("- Hydra")

def install_linux_tools():
    """Install tools on Linux"""
    try:
        logger.info("Installing system tools on Linux...")
        
        # Update package list
        subprocess.run(['sudo', 'apt-get', 'update'], check=True)
        
        # Install tools
        tools = ['nmap', 'nikto', 'hydra', 'john', 'hashcat']
        subprocess.run(['sudo', 'apt-get', 'install', '-y'] + tools, check=True)
        
        # Install SQLMap
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'sqlmap'], check=True)
        
        # Install WPScan (requires Ruby)
        subprocess.run(['sudo', 'gem', 'install', 'wpscan'], check=True)
        
        logger.info("System tools installed successfully")
    
    except subprocess.CalledProcessError as e:
        logger.warning(f"Some tools may not have installed correctly: {e}")
    except FileNotFoundError:
        logger.warning("sudo not found. Please install tools manually with appropriate privileges")

def install_macos_tools():
    """Install tools on macOS"""
    try:
        logger.info("Installing system tools on macOS...")
        
        # Check if Homebrew is installed
        subprocess.run(['brew', '--version'], check=True, capture_output=True)
        
        # Install tools
        tools = ['nmap', 'nikto', 'hydra', 'john', 'hashcat', 'sqlmap']
        subprocess.run(['brew', 'install'] + tools, check=True)
        
        # Install WPScan
        subprocess.run(['gem', 'install', 'wpscan'], check=True)
        
        logger.info("System tools installed successfully")
    
    except subprocess.CalledProcessError as e:
        logger.warning(f"Some tools may not have installed correctly: {e}")
    except FileNotFoundError:
        logger.warning("Homebrew not found. Please install Homebrew first: https://brew.sh/")

def create_startup_script():
    """Create startup script"""
    script_content = """#!/bin/bash
# WordPress Security Scanner Startup Script

echo "Starting WordPress Security Scanner Backend..."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "Activated virtual environment"
fi

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=production

# Start the application
python app.py

echo "WordPress Security Scanner Backend stopped"
"""
    
    with open('start.sh', 'w') as f:
        f.write(script_content)
    
    # Make executable
    os.chmod('start.sh', 0o755)
    logger.info("Created startup script: start.sh")

def main():
    """Main installation function"""
    logger.info("Starting WordPress Security Scanner Backend installation...")
    
    # Check Python version
    check_python_version()
    
    # Install Python requirements
    install_requirements()
    
    # Setup directories
    setup_directories()
    
    # Download wordlists
    download_wordlists()
    
    # Create configuration file
    create_config_file()
    
    # Install system tools
    install_system_tools()
    
    # Create startup script
    create_startup_script()
    
    logger.info("Installation completed successfully!")
    logger.info("To start the scanner, run: python app.py")
    logger.info("Or use the startup script: ./start.sh")
    logger.info("The API will be available at: http://localhost:5000")

if __name__ == '__main__':
    main()