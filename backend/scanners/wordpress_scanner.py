#!/usr/bin/env python3
"""
WordPress Scanner Module
Comprehensive WordPress detection and enumeration
"""

import re
import requests
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class WordPressScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        
        # Common WordPress paths
        self.wp_paths = [
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/wp-login.php',
            '/wp-config.php',
            '/xmlrpc.php',
            '/readme.html',
            '/license.txt'
        ]
        
        # Common plugins to check
        self.common_plugins = [
            'akismet', 'jetpack', 'yoast-seo', 'contact-form-7', 'wordfence',
            'elementor', 'woocommerce', 'wp-super-cache', 'all-in-one-seo-pack',
            'wp-optimize', 'updraftplus', 'wp-rocket', 'ninja-forms', 'mailchimp-for-wp',
            'wp-file-manager', 'duplicator', 'wp-fastest-cache', 'really-simple-ssl',
            'wp-smushit', 'wp-security-audit-log', 'loginizer', 'wp-mail-smtp',
            'advanced-custom-fields', 'wp-migrate-db', 'wp-db-backup'
        ]

    def detect_wordpress(self, url: str) -> Dict:
        """Detect if target is running WordPress"""
        result = {
            'detected': False,
            'confidence': 'low',
            'version': None,
            'theme': None,
            'indicators': [],
            'paths_found': [],
            'meta_generator': None,
            'readme_accessible': False,
            'xmlrpc_enabled': False,
            'wp_json_enabled': False
        }
        
        try:
            logger.info(f"Detecting WordPress on: {url}")
            
            # Get main page
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return result
            
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check for WordPress indicators
            indicators = []
            
            # Meta generator tag
            generator = soup.find('meta', {'name': 'generator'})
            if generator and 'wordpress' in generator.get('content', '').lower():
                indicators.append('WordPress meta generator found')
                result['meta_generator'] = generator.get('content')
                
                # Extract version
                version_match = re.search(r'WordPress\s+([\d.]+)', generator.get('content', ''))
                if version_match:
                    result['version'] = version_match.group(1)
            
            # Check for wp-content, wp-includes in HTML
            if 'wp-content' in html:
                indicators.append('wp-content references found')
            if 'wp-includes' in html:
                indicators.append('wp-includes references found')
            
            # Check for WordPress-specific CSS/JS
            wp_links = soup.find_all('link', href=re.compile(r'wp-content|wp-includes'))
            wp_scripts = soup.find_all('script', src=re.compile(r'wp-content|wp-includes'))
            
            if wp_links:
                indicators.append(f'{len(wp_links)} WordPress CSS files found')
            if wp_scripts:
                indicators.append(f'{len(wp_scripts)} WordPress JS files found')
            
            # Check for theme
            theme_links = soup.find_all('link', href=re.compile(r'wp-content/themes/([^/]+)'))
            if theme_links:
                theme_match = re.search(r'wp-content/themes/([^/]+)', theme_links[0].get('href', ''))
                if theme_match:
                    result['theme'] = theme_match.group(1)
                    indicators.append(f'Theme detected: {result["theme"]}')
            
            # Check WordPress paths
            paths_found = []
            for path in self.wp_paths:
                try:
                    path_response = self.session.get(urljoin(url, path), timeout=5)
                    if path_response.status_code in [200, 302, 403]:
                        paths_found.append({
                            'path': path,
                            'status': path_response.status_code,
                            'accessible': path_response.status_code == 200
                        })
                        
                        if path == '/readme.html' and path_response.status_code == 200:
                            result['readme_accessible'] = True
                            # Try to extract version from readme
                            readme_content = path_response.text
                            version_match = re.search(r'Version\s+([\d.]+)', readme_content)
                            if version_match and not result['version']:
                                result['version'] = version_match.group(1)
                
                except requests.RequestException:
                    continue
            
            result['paths_found'] = paths_found
            
            # Check XML-RPC
            try:
                xmlrpc_response = self.session.post(
                    urljoin(url, '/xmlrpc.php'),
                    data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                    headers={'Content-Type': 'text/xml'},
                    timeout=5
                )
                if xmlrpc_response.status_code == 200 and 'methodResponse' in xmlrpc_response.text:
                    result['xmlrpc_enabled'] = True
                    indicators.append('XML-RPC enabled')
            except requests.RequestException:
                pass
            
            # Check WP JSON API
            try:
                json_response = self.session.get(urljoin(url, '/wp-json/wp/v2/'), timeout=5)
                if json_response.status_code == 200:
                    result['wp_json_enabled'] = True
                    indicators.append('WP JSON API enabled')
            except requests.RequestException:
                pass
            
            # Determine confidence level
            if len(indicators) >= 3:
                result['confidence'] = 'high'
                result['detected'] = True
            elif len(indicators) >= 1:
                result['confidence'] = 'medium'
                result['detected'] = True
            
            result['indicators'] = indicators
            
            logger.info(f"WordPress detection completed. Detected: {result['detected']}, Confidence: {result['confidence']}")
            
        except Exception as e:
            logger.error(f"WordPress detection failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def enumerate_plugins(self, url: str) -> List[Dict]:
        """Enumerate WordPress plugins"""
        plugins = []
        
        try:
            logger.info(f"Enumerating plugins for: {url}")
            
            # Method 1: Check common plugin paths
            for plugin in self.common_plugins:
                try:
                    plugin_url = urljoin(url, f'/wp-content/plugins/{plugin}/')
                    response = self.session.get(plugin_url, timeout=5)
                    
                    if response.status_code in [200, 403]:
                        plugin_info = {
                            'name': plugin,
                            'path': f'/wp-content/plugins/{plugin}/',
                            'detected': True,
                            'version': None,
                            'vulnerable': False,
                            'detection_method': 'directory_listing'
                        }
                        
                        # Try to get version from readme.txt
                        try:
                            readme_url = urljoin(url, f'/wp-content/plugins/{plugin}/readme.txt')
                            readme_response = self.session.get(readme_url, timeout=5)
                            if readme_response.status_code == 200:
                                readme_content = readme_response.text
                                version_match = re.search(r'Stable tag:\s*([\d.]+)', readme_content, re.IGNORECASE)
                                if version_match:
                                    plugin_info['version'] = version_match.group(1)
                                    plugin_info['detection_method'] = 'readme.txt'
                        except requests.RequestException:
                            pass
                        
                        # Check for known vulnerabilities
                        plugin_info['vulnerable'] = self._check_plugin_vulnerability(plugin, plugin_info['version'])
                        
                        plugins.append(plugin_info)
                        
                except requests.RequestException:
                    continue
            
            # Method 2: Parse HTML for plugin references
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    html = response.text
                    
                    # Find plugin references in HTML
                    plugin_matches = re.findall(r'wp-content/plugins/([^/\'"?]+)', html)
                    for plugin_name in set(plugin_matches):
                        if not any(p['name'] == plugin_name for p in plugins):
                            plugins.append({
                                'name': plugin_name,
                                'path': f'/wp-content/plugins/{plugin_name}/',
                                'detected': True,
                                'version': None,
                                'vulnerable': False,
                                'detection_method': 'html_analysis'
                            })
            
            except requests.RequestException:
                pass
            
            logger.info(f"Found {len(plugins)} plugins")
            
        except Exception as e:
            logger.error(f"Plugin enumeration failed: {str(e)}")
        
        return plugins

    def enumerate_users(self, url: str) -> Dict:
        """Enumerate WordPress users"""
        result = {
            'method_used': [],
            'users_found': [],
            'total_users': 0
        }
        
        try:
            logger.info(f"Enumerating users for: {url}")
            
            # Method 1: WP JSON API
            try:
                json_url = urljoin(url, '/wp-json/wp/v2/users')
                response = self.session.get(json_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    users_data = response.json()
                    result['method_used'].append('WP JSON API')
                    
                    for user in users_data:
                        result['users_found'].append({
                            'id': user.get('id'),
                            'username': user.get('slug'),
                            'display_name': user.get('name'),
                            'description': user.get('description', ''),
                            'posts_count': user.get('posts_count', 0),
                            'method': 'JSON API'
                        })
            
            except (requests.RequestException, json.JSONDecodeError):
                pass
            
            # Method 2: Author archives
            if not result['users_found']:
                result['method_used'].append('Author Archives')
                
                for user_id in range(1, 11):  # Check first 10 users
                    try:
                        author_url = urljoin(url, f'/?author={user_id}')
                        response = self.session.get(author_url, timeout=5)
                        
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Try to extract username from various selectors
                            selectors = [
                                '.author-name', '.author-title', '.entry-author',
                                'h1.author', '.author-bio h1', '.author-info h1'
                            ]
                            
                            for selector in selectors:
                                element = soup.select_one(selector)
                                if element:
                                    username = element.get_text().strip()
                                    if username and not any(u['display_name'] == username for u in result['users_found']):
                                        result['users_found'].append({
                                            'id': user_id,
                                            'username': f'user{user_id}',
                                            'display_name': username,
                                            'description': '',
                                            'posts_count': 0,
                                            'method': 'Author Archives'
                                        })
                                    break
                    
                    except requests.RequestException:
                        continue
            
            # Method 3: Login error messages
            if not result['users_found']:
                result['method_used'].append('Login Error Analysis')
                
                common_usernames = ['admin', 'administrator', 'test', 'demo', 'user']
                for username in common_usernames:
                    try:
                        login_url = urljoin(url, '/wp-login.php')
                        login_data = {
                            'log': username,
                            'pwd': 'invalid_password_12345',
                            'wp-submit': 'Log In'
                        }
                        
                        response = self.session.post(login_url, data=login_data, timeout=5)
                        
                        if response.status_code == 200:
                            if 'incorrect password' in response.text.lower():
                                result['users_found'].append({
                                    'id': None,
                                    'username': username,
                                    'display_name': username,
                                    'description': '',
                                    'posts_count': 0,
                                    'method': 'Login Error'
                                })
                    
                    except requests.RequestException:
                        continue
            
            result['total_users'] = len(result['users_found'])
            logger.info(f"Found {result['total_users']} users using methods: {', '.join(result['method_used'])}")
            
        except Exception as e:
            logger.error(f"User enumeration failed: {str(e)}")
            result['error'] = str(e)
        
        return result

    def _check_plugin_vulnerability(self, plugin_name: str, version: str) -> bool:
        """Check if plugin version has known vulnerabilities"""
        # Known vulnerable plugin versions
        vulnerable_plugins = {
            'wp-file-manager': ['6.0', '6.1', '6.2', '6.3', '6.4', '6.5', '6.6', '6.7', '6.8', '6.9'],
            'duplicator': ['1.3.26', '1.3.28'],
            'wp-fastest-cache': ['0.9.5'],
            'really-simple-ssl': ['4.0.10'],
            'loginizer': ['1.6.3'],
            'wp-migrate-db': ['2.4.1'],
            'advanced-custom-fields': ['5.8.7']
        }
        
        if plugin_name in vulnerable_plugins and version:
            return version in vulnerable_plugins[plugin_name]
        
        return False

    def get_wordpress_version(self, url: str) -> Optional[str]:
        """Get WordPress version using multiple methods"""
        try:
            # Method 1: Meta generator
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                generator = soup.find('meta', {'name': 'generator'})
                if generator:
                    content = generator.get('content', '')
                    version_match = re.search(r'WordPress\s+([\d.]+)', content)
                    if version_match:
                        return version_match.group(1)
            
            # Method 2: readme.html
            readme_url = urljoin(url, '/readme.html')
            response = self.session.get(readme_url, timeout=5)
            if response.status_code == 200:
                version_match = re.search(r'Version\s+([\d.]+)', response.text)
                if version_match:
                    return version_match.group(1)
            
            # Method 3: RSS feed
            rss_url = urljoin(url, '/feed/')
            response = self.session.get(rss_url, timeout=5)
            if response.status_code == 200:
                version_match = re.search(r'<generator>.*WordPress\s+([\d.]+)', response.text)
                if version_match:
                    return version_match.group(1)
        
        except requests.RequestException:
            pass
        
        return None