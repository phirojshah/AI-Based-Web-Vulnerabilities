# WordPress Security Scanner Backend

A comprehensive Python-based backend for WordPress security scanning and penetration testing.

## Features

### Scanning Capabilities
- **WordPress Detection**: Comprehensive WordPress fingerprinting
- **Plugin Enumeration**: Detect installed plugins and versions
- **User Enumeration**: Discover WordPress users
- **Vulnerability Scanning**: SQL injection, XSS, LFI, RFI, command injection
- **Network Reconnaissance**: DNS, WHOIS, SSL analysis
- **Security Headers**: Analyze HTTP security headers

### Exploitation Modules
- **SQL Injection**: Automated exploitation with SQLMap integration
- **XSS Exploitation**: Cross-site scripting attack vectors
- **File Inclusion**: LFI/RFI exploitation
- **Command Injection**: System command execution
- **Brute Force**: Password attacks on login forms

### Tool Integration
- **SQLMap**: Automated SQL injection testing
- **Nmap**: Network scanning and service detection
- **WPScan**: WordPress-specific vulnerability scanner
- **Nikto**: Web server vulnerability scanner
- **Hydra**: Password brute force attacks
- **John the Ripper**: Password cracking
- **Hashcat**: Advanced password recovery

## Installation

### Quick Install
```bash
# Clone or download the backend files
cd backend

# Run the installation script
python install.py
```

### Manual Installation

1. **Install Python Dependencies**
```bash
pip install -r requirements.txt
```

2. **Install System Tools (Linux)**
```bash
sudo apt-get update
sudo apt-get install -y nmap nikto hydra john hashcat sqlmap
sudo gem install wpscan
```

3. **Install System Tools (macOS)**
```bash
brew install nmap nikto hydra john hashcat sqlmap
gem install wpscan
```

4. **Setup Database**
```bash
python -c "from utils.database import ScanDatabase; ScanDatabase().init_db()"
```

## Usage

### Start the Backend Server
```bash
python app.py
```

The API will be available at `http://localhost:5000`

### API Endpoints

#### Scanning Endpoints
- `POST /api/scan/wordpress` - WordPress detection
- `POST /api/scan/plugins` - Plugin enumeration
- `POST /api/scan/users` - User enumeration
- `POST /api/scan/vulnerabilities` - Vulnerability scanning
- `POST /api/scan/network` - Network reconnaissance
- `POST /api/scan/comprehensive` - Full scan

#### Exploitation Endpoints
- `POST /api/exploit/sql-injection` - SQL injection exploitation
- `POST /api/exploit/xss` - XSS exploitation
- `POST /api/exploit/file-inclusion` - LFI/RFI exploitation
- `POST /api/exploit/command-injection` - Command injection
- `POST /api/exploit/brute-force` - Brute force attacks

#### Tool Management
- `POST /api/tools/install` - Install security tools
- `GET /api/tools/status` - Check tool status

#### Reporting
- `POST /api/report/generate` - Generate security reports

### Example Usage

#### WordPress Scan
```bash
curl -X POST http://localhost:5000/api/scan/wordpress \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

#### Comprehensive Scan
```bash
curl -X POST http://localhost:5000/api/scan/comprehensive \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "options": {
      "wordpress": true,
      "plugins": true,
      "users": true,
      "vulnerabilities": true,
      "network": true
    }
  }'
```

#### SQL Injection Exploitation
```bash
curl -X POST http://localhost:5000/api/exploit/sql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "vulnerability": {
      "vulnerable_endpoints": [
        {
          "url": "https://example.com/?id=1",
          "parameter": "id"
        }
      ]
    },
    "tool": "sqlmap"
  }'
```

## Configuration

Edit `config.py` to customize settings:

```python
# Server Configuration
HOST = '0.0.0.0'
PORT = 5000
DEBUG = False

# Security Settings
MAX_SCAN_THREADS = 10
REQUEST_TIMEOUT = 30
RATE_LIMIT = 100

# Tool Paths
SQLMAP_PATH = 'sqlmap'
NMAP_PATH = 'nmap'
WPSCAN_PATH = 'wpscan'
```

## Security Considerations

⚠️ **WARNING**: This tool is designed for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Unauthorized scanning may violate laws and regulations
- Always follow responsible disclosure practices
- Use rate limiting to avoid overwhelming target systems

## Tool Installation Details

### SQLMap
```bash
# Linux
sudo apt-get install sqlmap

# macOS
brew install sqlmap

# Python
pip install sqlmap-python
```

### WPScan
```bash
# Requires Ruby
gem install wpscan
wpscan --update
```

### Nmap
```bash
# Linux
sudo apt-get install nmap

# macOS
brew install nmap
```

### Hydra
```bash
# Linux
sudo apt-get install hydra

# macOS
brew install hydra
```

## Database Schema

The backend uses SQLite to store scan results:

- **scan_results**: Stores all scan results
- **exploit_results**: Stores exploitation attempts
- **targets**: Tracks scanned targets

## Logging

Logs are stored in:
- `security_scanner.log` - Main application log
- `logs/` directory - Additional log files

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is for educational and authorized testing purposes only.

## Support

For issues and questions:
1. Check the logs for error messages
2. Verify tool installations with `/api/tools/status`
3. Ensure proper permissions for target testing
4. Review configuration settings