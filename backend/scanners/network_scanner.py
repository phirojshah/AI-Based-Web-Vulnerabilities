#!/usr/bin/env python3
"""
Network Scanner Module
Network reconnaissance and information gathering
"""

import socket
import ssl
import whois
import dns.resolver
import requests
from urllib.parse import urlparse
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.timeout = 10

    def full_recon(self, url: str) -> Dict:
        """Perform full network reconnaissance"""
        result = {
            'target': url,
            'domain_info': {},
            'dns_records': {},
            'ssl_info': {},
            'security_headers': {},
            'cors_config': {}
        }
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or parsed_url.path
            
            logger.info(f"Starting network reconnaissance for: {domain}")
            
            # Domain information
            result['domain_info'] = self.get_domain_info(domain)
            
            # DNS records
            result['dns_records'] = self.get_dns_records(domain)
            
            # SSL information
            if parsed_url.scheme == 'https' or not parsed_url.scheme:
                result['ssl_info'] = self.analyze_ssl(domain)
            
            # Security headers
            result['security_headers'] = self.analyze_security_headers(url)
            
            # CORS configuration
            result['cors_config'] = self.analyze_cors(url)
            
        except Exception as e:
            logger.error(f"Network reconnaissance failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def get_domain_info(self, domain: str) -> Dict:
        """Get WHOIS information for domain"""
        result = {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'nameservers': [],
            'status': None
        }
        
        try:
            logger.info(f"Getting WHOIS info for: {domain}")
            
            w = whois.whois(domain)
            
            result['registrar'] = w.registrar
            result['creation_date'] = str(w.creation_date) if w.creation_date else None
            result['expiration_date'] = str(w.expiration_date) if w.expiration_date else None
            result['nameservers'] = w.name_servers if w.name_servers else []
            result['status'] = w.status
            
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def get_dns_records(self, domain: str) -> Dict:
        """Get DNS records for domain"""
        result = {
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': []
        }
        
        try:
            logger.info(f"Getting DNS records for: {domain}")
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                result['a_records'] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                logger.debug(f"A record lookup failed: {str(e)}")
            
            # AAAA records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                result['aaaa_records'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                logger.debug(f"AAAA record lookup failed: {str(e)}")
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                result['mx_records'] = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                logger.debug(f"MX record lookup failed: {str(e)}")
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                result['ns_records'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                logger.debug(f"NS record lookup failed: {str(e)}")
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                result['txt_records'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                logger.debug(f"TXT record lookup failed: {str(e)}")
            
        except Exception as e:
            logger.error(f"DNS lookup failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def analyze_ssl(self, domain: str) -> Dict:
        """Analyze SSL/TLS configuration"""
        result = {
            'ssl_enabled': False,
            'certificate_valid': False,
            'certificate_info': {},
            'tls_version': None,
            'cipher_suite': None,
            'vulnerabilities': []
        }
        
        try:
            logger.info(f"Analyzing SSL for: {domain}")
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to the server
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    result['ssl_enabled'] = True
                    result['certificate_valid'] = True
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    result['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    
                    # Get TLS version and cipher
                    result['tls_version'] = ssock.version()
                    result['cipher_suite'] = ssock.cipher()[0] if ssock.cipher() else None
        
        except ssl.SSLError as e:
            logger.error(f"SSL error: {str(e)}")
            result['ssl_enabled'] = False
            result['vulnerabilities'].append(f"SSL Error: {str(e)}")
        
        except socket.timeout:
            logger.error("SSL connection timeout")
            result['error'] = "Connection timeout"
        
        except Exception as e:
            logger.error(f"SSL analysis failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def analyze_security_headers(self, url: str) -> Dict:
        """Analyze HTTP security headers"""
        result = {}
        
        try:
            logger.info(f"Analyzing security headers for: {url}")
            
            response = requests.get(url, timeout=self.timeout)
            headers = response.headers
            
            # Check for security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'Referrer-Policy',
                'Permissions-Policy',
                'X-Permitted-Cross-Domain-Policies'
            ]
            
            for header in security_headers:
                result[header] = headers.get(header, 'missing')
            
            # Calculate security score
            present_headers = sum(1 for value in result.values() if value != 'missing')
            result['security_score'] = (present_headers / len(security_headers)) * 10
            
        except Exception as e:
            logger.error(f"Security headers analysis failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def analyze_cors(self, url: str) -> Dict:
        """Analyze CORS configuration"""
        result = {
            'cors_enabled': False,
            'allow_origin': None,
            'allow_credentials': False,
            'allow_methods': [],
            'misconfiguration': False,
            'risk_level': 'low'
        }
        
        try:
            logger.info(f"Analyzing CORS for: {url}")
            
            # Test with a potentially malicious origin
            headers = {'Origin': 'https://evil.com'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            cors_headers = {
                'origin': response.headers.get('Access-Control-Allow-Origin'),
                'credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'methods': response.headers.get('Access-Control-Allow-Methods')
            }
            
            if cors_headers['origin']:
                result['cors_enabled'] = True
                result['allow_origin'] = cors_headers['origin']
                
                # Check for dangerous configuration
                if cors_headers['origin'] == '*' and cors_headers['credentials'] == 'true':
                    result['misconfiguration'] = True
                    result['risk_level'] = 'high'
                
                if cors_headers['methods']:
                    result['allow_methods'] = [m.strip() for m in cors_headers['methods'].split(',')]
                
                result['allow_credentials'] = cors_headers['credentials'] == 'true'
        
        except Exception as e:
            logger.error(f"CORS analysis failed: {str(e)}")
            result['error'] = str(e)
        
        return result