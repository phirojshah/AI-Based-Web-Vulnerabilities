#!/usr/bin/env python3
"""
WordPress Security Scanner Backend
Advanced Python-based security testing framework with AI analysis
"""

import os
import sys
import json
import time
import asyncio
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

# Import our custom modules
from scanners.wordpress_scanner import WordPressScanner
from scanners.vulnerability_scanner import VulnerabilityScanner
from scanners.network_scanner import NetworkScanner
from exploits.sql_injection import SQLInjectionExploit
from exploits.xss_exploit import XSSExploit
from exploits.file_inclusion import FileInclusionExploit
from exploits.command_injection import CommandInjectionExploit
from exploits.brute_force import BruteForceExploit
from utils.report_generator import ReportGenerator
from utils.database import ScanDatabase
from utils.ai_analyzer import AISecurityAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize components
wp_scanner = WordPressScanner()
vuln_scanner = VulnerabilityScanner()
network_scanner = NetworkScanner()
sql_exploit = SQLInjectionExploit()
xss_exploit = XSSExploit()
file_exploit = FileInclusionExploit()
cmd_exploit = CommandInjectionExploit()
brute_exploit = BruteForceExploit()
report_gen = ReportGenerator()
db = ScanDatabase()
ai_analyzer = AISecurityAnalyzer()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'OK',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'backend': 'Python',
        'ai_enabled': True,
        'autonomous_mode': True
    })

@app.route('/api/scan/wordpress', methods=['POST'])
def scan_wordpress():
    """WordPress detection and enumeration"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        logger.info(f"Starting WordPress scan for: {url}")
        result = wp_scanner.detect_wordpress(url)
        
        # Store results in database
        db.store_scan_result(url, 'wordpress', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"WordPress scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/plugins', methods=['POST'])
def scan_plugins():
    """WordPress plugin enumeration"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        result = wp_scanner.enumerate_plugins(url)
        db.store_scan_result(url, 'plugins', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Plugin scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/users', methods=['POST'])
def scan_users():
    """WordPress user enumeration"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        result = wp_scanner.enumerate_users(url)
        db.store_scan_result(url, 'users', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"User scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    """Comprehensive vulnerability scanning"""
    try:
        data = request.get_json()
        url = data.get('url')
        scan_types = data.get('types', ['all'])
        
        result = vuln_scanner.comprehensive_scan(url, scan_types)
        db.store_scan_result(url, 'vulnerabilities', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/network', methods=['POST'])
def scan_network():
    """Network reconnaissance"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        result = network_scanner.full_recon(url)
        db.store_scan_result(url, 'network', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Network scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """AI-powered vulnerability analysis with autonomous actions"""
    try:
        data = request.get_json()
        url = data.get('url')
        scan_results = data.get('scan_results', {})
        
        if not url or not scan_results:
            return jsonify({'error': 'URL and scan results are required'}), 400
        
        logger.info(f"Starting autonomous AI analysis for: {url}")
        
        # Perform AI analysis with autonomous capabilities
        analysis = ai_analyzer.analyze_vulnerabilities(scan_results)
        
        # Store AI analysis results
        db.store_scan_result(url, 'ai_analysis', analysis)
        
        return jsonify(analysis)
    
    except Exception as e:
        logger.error(f"AI analysis failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/red-team-analysis', methods=['POST'])
def ai_red_team_analysis():
    """AI-powered red team exploitation analysis"""
    try:
        data = request.get_json()
        url = data.get('url')
        scan_results = data.get('scan_results', {})
        vulnerability_data = data.get('vulnerability_data', {})
        
        if not url or not scan_results:
            return jsonify({'error': 'URL and scan results are required'}), 400
        
        logger.info(f"Starting red team analysis for: {url}")
        
        # Generate red team exploitation guidance
        red_team_analysis = ai_analyzer.generate_red_team_analysis(url, scan_results, vulnerability_data)
        
        # Store red team analysis results
        db.store_scan_result(url, 'red_team_analysis', red_team_analysis)
        
        return jsonify(red_team_analysis)
    
    except Exception as e:
        logger.error(f"Red team analysis failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/execute-action', methods=['POST'])
def ai_execute_action():
    """Execute autonomous AI security action"""
    try:
        data = request.get_json()
        action = data.get('action', {})
        target = data.get('target', '')
        
        if not action:
            return jsonify({'error': 'Action data is required'}), 400
        
        logger.info(f"Executing autonomous action: {action.get('action', 'unknown')}")
        
        # Execute the autonomous action
        result = ai_analyzer._execute_autonomous_actions([action])
        
        return jsonify({
            'success': True,
            'output': f"Executed: {action.get('command', 'N/A')}",
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Autonomous action execution failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/exploit-guidance', methods=['POST'])
def ai_exploit_guidance():
    """AI-powered autonomous exploitation guidance"""
    try:
        data = request.get_json()
        vulnerability_data = data.get('vulnerability_data', {})
        target_url = data.get('target_url', '')
        
        if not vulnerability_data:
            return jsonify({'error': 'Vulnerability data is required'}), 400
        
        logger.info("Generating autonomous AI exploit guidance")
        
        guidance = ai_analyzer.generate_exploit_guidance(vulnerability_data, target_url)
        
        return jsonify(guidance)
    
    except Exception as e:
        logger.error(f"AI exploit guidance failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/security-report', methods=['POST'])
def ai_security_report():
    """AI-powered autonomous security report generation"""
    try:
        data = request.get_json()
        url = data.get('url')
        scan_summary = data.get('scan_summary', {})
        
        if not url or not scan_summary:
            return jsonify({'error': 'URL and scan summary are required'}), 400
        
        logger.info(f"Generating autonomous AI security report for: {url}")
        
        report = ai_analyzer.create_security_report(scan_summary)
        
        # Store report
        db.store_scan_result(url, 'ai_report', report)
        
        return jsonify(report)
    
    except Exception as e:
        logger.error(f"AI security report failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/threat-model', methods=['POST'])
def ai_threat_model():
    """AI-powered autonomous threat modeling"""
    try:
        data = request.get_json()
        url = data.get('url')
        site_info = data.get('site_info', {})
        
        if not url or not site_info:
            return jsonify({'error': 'URL and site info are required'}), 400
        
        logger.info(f"Generating autonomous AI threat model for: {url}")
        
        threat_model = ai_analyzer.generate_threat_model(site_info)
        
        # Store threat model
        db.store_scan_result(url, 'threat_model', threat_model)
        
        return jsonify(threat_model)
    
    except Exception as e:
        logger.error(f"AI threat modeling failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/insights', methods=['POST'])
def ai_security_insights():
    """AI-powered autonomous security insights"""
    try:
        data = request.get_json()
        url = data.get('url')
        scan_results = data.get('scan_results', {})
        
        if not url or not scan_results:
            return jsonify({'error': 'URL and scan results are required'}), 400
        
        logger.info(f"Generating autonomous AI security insights for: {url}")
        
        insights = ai_analyzer.get_security_insights(url, scan_results)
        
        # Store insights
        db.store_scan_result(url, 'ai_insights', insights)
        
        return jsonify(insights)
    
    except Exception as e:
        logger.error(f"AI security insights failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploit/sql-injection', methods=['POST'])
def exploit_sql_injection():
    """SQL injection exploitation"""
    try:
        data = request.get_json()
        url = data.get('url')
        vulnerability = data.get('vulnerability')
        tool = data.get('tool', 'sqlmap')
        
        result = sql_exploit.exploit(url, vulnerability, tool)
        db.store_exploit_result(url, 'sql_injection', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"SQL injection exploit failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploit/xss', methods=['POST'])
def exploit_xss():
    """XSS exploitation"""
    try:
        data = request.get_json()
        url = data.get('url')
        vulnerability = data.get('vulnerability')
        tool = data.get('tool', 'manual')
        
        result = xss_exploit.exploit(url, vulnerability, tool)
        db.store_exploit_result(url, 'xss', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"XSS exploit failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploit/file-inclusion', methods=['POST'])
def exploit_file_inclusion():
    """LFI/RFI exploitation"""
    try:
        data = request.get_json()
        url = data.get('url')
        vulnerability = data.get('vulnerability')
        exploit_type = data.get('type', 'lfi')
        
        result = file_exploit.exploit(url, vulnerability, exploit_type)
        db.store_exploit_result(url, 'file_inclusion', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"File inclusion exploit failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploit/command-injection', methods=['POST'])
def exploit_command_injection():
    """Command injection exploitation"""
    try:
        data = request.get_json()
        url = data.get('url')
        vulnerability = data.get('vulnerability')
        tool = data.get('tool', 'manual')
        
        result = cmd_exploit.exploit(url, vulnerability, tool)
        db.store_exploit_result(url, 'command_injection', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Command injection exploit failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploit/brute-force', methods=['POST'])
def exploit_brute_force():
    """Brute force attack"""
    try:
        data = request.get_json()
        url = data.get('url')
        target_type = data.get('target', 'wp-login')
        wordlists = data.get('wordlists', {})
        
        result = brute_exploit.attack(url, target_type, wordlists)
        db.store_exploit_result(url, 'brute_force', result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Brute force exploit failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/install', methods=['POST'])
def install_tools():
    """Install required security tools"""
    try:
        from utils.tool_installer import ToolInstaller
        installer = ToolInstaller()
        
        data = request.get_json()
        tools = data.get('tools', ['all'])
        
        result = installer.install_tools(tools)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Tool installation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/status', methods=['GET'])
def tool_status():
    """Check status of installed tools"""
    try:
        from utils.tool_checker import ToolChecker
        checker = ToolChecker()
        
        status = checker.check_all_tools()
        return jsonify(status)
    
    except Exception as e:
        logger.error(f"Tool status check failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate comprehensive security report"""
    try:
        data = request.get_json()
        url = data.get('url')
        format_type = data.get('format', 'html')
        
        report = report_gen.generate_report(url, format_type)
        return jsonify(report)
    
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/comprehensive', methods=['POST'])
def comprehensive_scan():
    """Run all scanning modules with autonomous AI analysis"""
    try:
        data = request.get_json()
        url = data.get('url')
        options = data.get('options', {})
        
        logger.info(f"Starting comprehensive scan with autonomous AI analysis for: {url}")
        
        results = {
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'scans': {}
        }
        
        # WordPress Detection
        if options.get('wordpress', True):
            results['scans']['wordpress'] = wp_scanner.detect_wordpress(url)
        
        # Plugin Enumeration
        if options.get('plugins', True):
            results['scans']['plugins'] = wp_scanner.enumerate_plugins(url)
        
        # User Enumeration
        if options.get('users', True):
            results['scans']['users'] = wp_scanner.enumerate_users(url)
        
        # Vulnerability Scanning
        if options.get('vulnerabilities', True):
            results['scans']['vulnerabilities'] = vuln_scanner.comprehensive_scan(url)
        
        # Network Reconnaissance
        if options.get('network', True):
            results['scans']['network'] = network_scanner.full_recon(url)
        
        # Autonomous AI Analysis
        if options.get('ai_analysis', True):
            try:
                ai_analysis = ai_analyzer.analyze_vulnerabilities(results['scans'])
                results['ai_analysis'] = ai_analysis
                
                # Generate autonomous security insights
                insights = ai_analyzer.get_security_insights(url, results['scans'])
                results['ai_insights'] = insights
                
                # Execute autonomous actions if available
                if ai_analysis.get('immediate_actions'):
                    autonomous_results = ai_analyzer._execute_autonomous_actions(
                        ai_analysis['immediate_actions']
                    )
                    results['autonomous_execution'] = autonomous_results
                
            except Exception as e:
                logger.error(f"Autonomous AI analysis failed: {str(e)}")
                results['ai_analysis'] = {'error': str(e)}
        
        # Store comprehensive results
        db.store_scan_result(url, 'comprehensive', results)
        
        return jsonify(results)
    
    except Exception as e:
        logger.error(f"Comprehensive scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize database
    db.init_db()
    
    # Start the server
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting WordPress Security Scanner Backend with Autonomous AI on port {port}")
    logger.info(f"Debug mode: {debug}")
    logger.info("Autonomous AI Agent powered by Google Gemini")
    
    app.run(host='0.0.0.0', port=port, debug=debug)