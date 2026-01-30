#!/usr/bin/env python3
"""
Advanced WordPress Security Scanner with Database Checks
Includes advanced vulnerability detection and remediation guidance
"""

import requests
import re
import json
import sys
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class AdvancedWPScanner:
    """Advanced WordPress security scanner with comprehensive checks"""
    
    # Known vulnerable plugin patterns (simplified - in production use CVE database)
    VULNERABLE_PLUGINS = {
        'wordfence': {'min': '0.0.0', 'max': '7.4.5', 'cve': 'CVE-2021-XXXX'},
        'elementor': {'min': '0.0.0', 'max': '3.1.1', 'cve': 'CVE-2021-XXXX'},
        # Add more as needed
    }
    
    def __init__(self, target_url: str, aggressive: bool = False, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.aggressive = aggressive
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WordPress Security Scanner'
        })
        
        self.results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'is_wordpress': False,
            'wordpress_version': None,
            'vulnerabilities': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'warnings': [],
            'info': {},
            'recommendations': []
        }
        
        self.wp_version = None
        self.plugins = {}
        self.themes = {}
    
    def log(self, level: str, message: str):
        """Formatted logging"""
        symbols = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[-]',
            'critical': '[!!!]'
        }
        print(f"{symbols.get(level, '[*]')} {message}")
    
    def add_vulnerability(self, severity: str, title: str, description: str, 
                         remediation: str, cve: Optional[str] = None):
        """Add vulnerability with proper severity classification"""
        vuln = {
            'title': title,
            'description': description,
            'remediation': remediation,
            'cve': cve
        }
        
        severity_key = severity.lower()
        if severity_key in self.results['vulnerabilities']:
            self.results['vulnerabilities'][severity_key].append(vuln)
    
    def safe_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Safe HTTP request with error handling and rate limiting"""
        try:
            # Basic rate limiting
            time.sleep(0.5)
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
            elif method == 'POST':
                response = self.session.post(url, timeout=self.timeout, verify=False, **kwargs)
            elif method == 'HEAD':
                response = self.session.head(url, timeout=self.timeout, verify=False, **kwargs)
            else:
                return None
            
            return response
        except requests.exceptions.RequestException as e:
            self.log('error', f"Request failed for {url}: {str(e)}")
            return None
    
    def check_wordpress_advanced(self) -> bool:
        """Advanced WordPress detection with multiple fingerprinting methods"""
        self.log('info', 'Performing advanced WordPress detection...')
        
        detection_score = 0
        max_score = 10
        
        # 1. Check homepage
        response = self.safe_request(self.target_url)
        if not response:
            return False
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        # WordPress indicators with weights
        if 'wp-content' in html:
            detection_score += 2
        if 'wp-includes' in html:
            detection_score += 2
        if '/wp-json/' in html:
            detection_score += 1
        
        # Check generator meta tag
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'wordpress' in generator.get('content', '').lower():
            detection_score += 3
        
        # Check for WordPress classes
        if soup.find(class_=re.compile(r'wp-|wordpress')):
            detection_score += 1
        
        # Check wp-login.php
        login_response = self.safe_request(urljoin(self.target_url, '/wp-login.php'))
        if login_response and login_response.status_code == 200:
            if 'wordpress' in login_response.text.lower():
                detection_score += 2
        
        # Check REST API
        api_response = self.safe_request(urljoin(self.target_url, '/wp-json/'))
        if api_response and api_response.status_code == 200:
            try:
                api_data = api_response.json()
                if 'namespaces' in api_data or 'routes' in api_data:
                    detection_score += 2
            except:
                pass
        
        is_wordpress = detection_score >= 5
        self.results['is_wordpress'] = is_wordpress
        self.results['info']['detection_confidence'] = f"{(detection_score/max_score)*100:.1f}%"
        
        if is_wordpress:
            self.log('success', f'WordPress detected (confidence: {(detection_score/max_score)*100:.1f}%)')
        else:
            self.log('error', 'Target does not appear to be WordPress')
        
        return is_wordpress
    
    def advanced_version_detection(self):
        """Multi-source WordPress version detection"""
        self.log('info', 'Detecting WordPress version from multiple sources...')
        
        versions = {}
        
        # Source 1: Generator meta tag
        response = self.safe_request(self.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator:
                match = re.search(r'WordPress\s+([\d.]+)', generator.get('content', ''))
                if match:
                    versions['generator'] = match.group(1)
        
        # Source 2: readme.html
        readme_urls = ['/readme.html', '/wp-admin/readme.html']
        for readme_path in readme_urls:
            readme_response = self.safe_request(urljoin(self.target_url, readme_path))
            if readme_response and readme_response.status_code == 200:
                match = re.search(r'Version\s+([\d.]+)', readme_response.text)
                if match:
                    versions['readme'] = match.group(1)
                    
                    self.add_vulnerability(
                        'medium',
                        'WordPress readme.html Accessible',
                        f'readme.html exposes WordPress version information at {readme_path}',
                        'Delete readme.html or add the following to .htaccess:\n<Files readme.html>\nOrder allow,deny\nDeny from all\n</Files>'
                    )
                break
        
        # Source 3: RSS/Atom feeds
        feed_paths = ['/feed/', '/feed/atom/', '/?feed=rss2']
        for feed_path in feed_paths:
            feed_response = self.safe_request(urljoin(self.target_url, feed_path))
            if feed_response and feed_response.status_code == 200:
                match = re.search(r'wordpress\.org/\?v=([\d.]+)', feed_response.text)
                if match:
                    versions['feed'] = match.group(1)
                    break
        
        # Source 4: JavaScript/CSS version strings
        if response:
            # Look for versioned assets
            version_pattern = r'/wp-includes/[^"\']*\?ver=([\d.]+)'
            matches = re.findall(version_pattern, response.text)
            if matches:
                versions['assets'] = matches[0]
        
        # Source 5: REST API
        api_response = self.safe_request(urljoin(self.target_url, '/wp-json/'))
        if api_response:
            try:
                # Some endpoints reveal version info
                pass
            except:
                pass
        
        # Determine most likely version
        if versions:
            # Use most specific version found
            version_list = list(versions.values())
            self.wp_version = max(version_list, key=lambda v: len(v.split('.')))
            self.results['wordpress_version'] = self.wp_version
            
            for source, version in versions.items():
                self.results['info'][f'version_{source}'] = version
                self.log('success', f'Version {version} detected via {source}')
            
            # Check if version is outdated (simplified - would need current version lookup)
            self.add_vulnerability(
                'high',
                'WordPress Version Disclosure',
                f'WordPress version {self.wp_version} is publicly exposed',
                'Update WordPress and hide version information. Add to wp-config.php:\nremove_action(\'wp_head\', \'wp_generator\');'
            )
        else:
            self.log('warning', 'Could not determine WordPress version')
    
    def check_xmlrpc_advanced(self):
        """Advanced XML-RPC vulnerability testing"""
        self.log('info', 'Testing XML-RPC endpoint...')
        
        xmlrpc_url = urljoin(self.target_url, '/xmlrpc.php')
        
        # Test 1: Check if accessible
        response = self.safe_request(xmlrpc_url)
        if not response or response.status_code != 200:
            self.log('success', 'XML-RPC not accessible')
            return
        
        # Test 2: List methods
        methods_call = '''<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>'''
        
        methods_response = self.safe_request(
            xmlrpc_url,
            method='POST',
            data=methods_call,
            headers={'Content-Type': 'application/xml'}
        )
        
        if methods_response and 'system.multicall' in methods_response.text:
            self.add_vulnerability(
                'critical',
                'XML-RPC Enabled with system.multicall',
                'XML-RPC is enabled with multicall support, allowing brute force amplification attacks. '
                'An attacker can test thousands of passwords in a single request.',
                'Disable XML-RPC completely unless required for specific functionality. '
                'Add to .htaccess:\n<Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n</Files>\n\n'
                'Or use plugin: Disable XML-RPC-API'
            )
            self.log('critical', 'XML-RPC multicall available - CRITICAL RISK')
        
        # Test 3: Pingback functionality (DDoS vector)
        if 'pingback.ping' in methods_response.text:
            self.add_vulnerability(
                'high',
                'XML-RPC Pingback Enabled',
                'Pingback functionality can be abused for DDoS attacks and port scanning',
                'Disable XML-RPC or at minimum disable pingback functionality'
            )
        
        # Test for authentication methods
        if 'wp.getUsersBlogs' in methods_response.text:
            self.add_vulnerability(
                'medium',
                'XML-RPC Authentication Methods Available',
                'XML-RPC authentication methods are available for credential testing',
                'Implement XML-RPC authentication filtering or disable XML-RPC'
            )
    
    def advanced_user_enumeration(self):
        """Comprehensive user enumeration with multiple techniques"""
        self.log('info', 'Performing advanced user enumeration...')
        
        users = {}
        
        # Method 1: Author archives with pagination
        for user_id in range(1, 20):
            author_url = urljoin(self.target_url, f'/?author={user_id}')
            response = self.safe_request(author_url, allow_redirects=True)
            
            if response and response.status_code == 200:
                username_match = re.search(r'/author/([^/]+)', response.url)
                if username_match:
                    username = username_match.group(1)
                    users[user_id] = {'username': username, 'method': 'author_archive'}
        
        # Method 2: REST API v2
        users_api_url = urljoin(self.target_url, '/wp-json/wp/v2/users')
        api_response = self.safe_request(users_api_url)
        
        if api_response and api_response.status_code == 200:
            try:
                users_data = api_response.json()
                for user in users_data:
                    user_id = user.get('id')
                    if user_id:
                        users[user_id] = {
                            'username': user.get('slug', user.get('name', 'unknown')),
                            'name': user.get('name', ''),
                            'method': 'rest_api'
                        }
            except:
                pass
            
            self.add_vulnerability(
                'medium',
                'User Enumeration via REST API',
                'WordPress REST API exposes user information without authentication',
                'Restrict REST API access. Add to functions.php:\n'
                'add_filter(\'rest_authentication_errors\', function($result) {\n'
                '    if (!is_user_logged_in()) {\n'
                '        return new WP_Error(\'rest_disabled\', \'REST API disabled\', array(\'status\' => 401));\n'
                '    }\n'
                '    return $result;\n'
                '});'
            )
        
        # Method 3: Login error messages (timing attack simulation)
        login_url = urljoin(self.target_url, '/wp-login.php')
        
        if self.aggressive and users:
            # Test one user for login error disclosure
            test_username = list(users.values())[0]['username']
            
            login_response = self.safe_request(
                login_url,
                method='POST',
                data={
                    'log': test_username,
                    'pwd': 'definitely_wrong_password_12345',
                    'wp-submit': 'Log In'
                },
                allow_redirects=False
            )
            
            if login_response:
                # Check for username disclosure in error message
                if 'incorrect password' in login_response.text.lower():
                    self.add_vulnerability(
                        'low',
                        'Login Error Message Disclosure',
                        'Login page reveals whether username exists through error messages',
                        'Use generic error messages. Add to functions.php:\n'
                        'add_filter(\'login_errors\', function($error) {\n'
                        '    return "Invalid credentials";\n'
                        '});'
                    )
        
        # Method 4: Post author meta
        posts_api = urljoin(self.target_url, '/wp-json/wp/v2/posts')
        posts_response = self.safe_request(posts_api)
        
        if posts_response and posts_response.status_code == 200:
            try:
                posts = posts_response.json()
                for post in posts:
                    author_id = post.get('author')
                    if author_id and author_id not in users:
                        users[author_id] = {'method': 'post_author'}
            except:
                pass
        
        if users:
            user_count = len(users)
            self.add_vulnerability(
                'medium' if user_count > 1 else 'low',
                f'User Enumeration Successful - {user_count} Users Found',
                f'Found {user_count} users through multiple enumeration techniques. '
                f'Usernames: {", ".join([u["username"] for u in list(users.values())[:5] if "username" in u])}',
                'Implement user enumeration protection:\n'
                '1. Disable author archives for low-privilege users\n'
                '2. Restrict REST API user endpoint\n'
                '3. Use security plugins (Wordfence, iThemes Security)\n'
                '4. Change admin username from "admin"'
            )
            
            self.results['info']['enumerated_users'] = users
            self.log('warning', f'Enumerated {user_count} users')
        else:
            self.log('success', 'User enumeration unsuccessful')
    
    def check_database_exposure(self):
        """Check for database table prefix and exposure"""
        self.log('info', 'Checking database security...')
        
        # Check for default table prefix via REST API
        api_url = urljoin(self.target_url, '/wp-json/')
        response = self.safe_request(api_url)
        
        # Check for SQL error messages
        test_urls = [
            '/?p=1\'',  # SQL injection test
            '/?author=1\'',
            '/?cat=1\''
        ]
        
        for test_url in test_urls:
            url = urljoin(self.target_url, test_url)
            test_response = self.safe_request(url)
            
            if test_response:
                sql_errors = [
                    'mysql_fetch',
                    'mysql_query',
                    'SQL syntax',
                    'mysqli_',
                    'database error',
                    'wp_posts',
                    'wp_users'
                ]
                
                for error in sql_errors:
                    if error in test_response.text:
                        self.add_vulnerability(
                            'critical',
                            'Database Error Exposure / SQL Injection',
                            f'Database errors are exposed, potentially revealing table structure. '
                            f'SQL error found in response to: {test_url}',
                            'Disable WordPress debug mode:\n'
                            'define(\'WP_DEBUG\', false);\n'
                            'define(\'WP_DEBUG_DISPLAY\', false);\n\n'
                            'Investigate potential SQL injection vulnerability'
                        )
                        self.log('critical', f'SQL error exposure detected at {test_url}')
                        break
    
    def check_file_upload_vulnerabilities(self):
        """Check upload directory security"""
        self.log('info', 'Checking file upload security...')
        
        upload_paths = [
            '/wp-content/uploads/',
            '/wp-content/uploads/2024/',
            '/wp-content/uploads/2025/',
        ]
        
        for path in upload_paths:
            url = urljoin(self.target_url, path)
            response = self.safe_request(url)
            
            if response and response.status_code == 200:
                # Check for directory listing
                if 'Index of' in response.text:
                    self.add_vulnerability(
                        'medium',
                        f'Upload Directory Listing: {path}',
                        'File upload directory allows directory listing, exposing uploaded files',
                        'Disable directory listing. Add to uploads/.htaccess:\nOptions -Indexes'
                    )
                
                # Check if PHP execution is disabled
                # This would require uploading a test file in aggressive mode
                if self.aggressive:
                    self.log('info', 'Aggressive mode: Would test PHP execution in uploads (skipped for safety)')
    
    def check_wp_cron(self):
        """Check WP-Cron configuration"""
        self.log('info', 'Checking WP-Cron...')
        
        cron_url = urljoin(self.target_url, '/wp-cron.php')
        response = self.safe_request(cron_url, method='POST')
        
        if response and response.status_code == 200:
            self.add_vulnerability(
                'low',
                'WP-Cron Publicly Accessible',
                'WP-Cron is accessible and may cause performance issues or be abused',
                'Disable public WP-Cron access. Add to wp-config.php:\n'
                'define(\'DISABLE_WP_CRON\', true);\n\n'
                'Then set up a real cron job:\n'
                '*/15 * * * * wget -q -O - ' + cron_url + ' &>/dev/null'
            )
    
    def check_plugin_vulnerabilities(self):
        """Check for known vulnerable plugins"""
        self.log('info', 'Checking for vulnerable plugins...')
        
        if not self.plugins:
            return
        
        for plugin_name, plugin_data in self.plugins.items():
            # In production, you'd query CVE database or WPScan API
            # This is a simplified check
            
            if plugin_name in self.VULNERABLE_PLUGINS:
                vuln_info = self.VULNERABLE_PLUGINS[plugin_name]
                self.add_vulnerability(
                    'high',
                    f'Vulnerable Plugin: {plugin_name}',
                    f'Plugin {plugin_name} has known vulnerabilities ({vuln_info.get("cve", "Unknown CVE")})',
                    f'Update {plugin_name} to the latest version or remove if not needed',
                    cve=vuln_info.get('cve')
                )
    
    def check_timthumb(self):
        """Check for TimThumb vulnerability"""
        self.log('info', 'Checking for TimThumb vulnerabilities...')
        
        timthumb_paths = [
            '/wp-content/themes/*/thumb.php',
            '/wp-content/themes/*/timthumb.php',
            '/wp-content/plugins/*/timthumb.php',
        ]
        
        # Would need directory listing or theme/plugin enumeration to check accurately
        # This is a simplified check
        
        for theme in self.themes.keys():
            timthumb_url = urljoin(self.target_url, f'/wp-content/themes/{theme}/timthumb.php')
            response = self.safe_request(timthumb_url)
            
            if response and response.status_code == 200 and 'timthumb' in response.text.lower():
                self.add_vulnerability(
                    'high',
                    f'TimThumb Found in Theme: {theme}',
                    'TimThumb script found. Old versions have critical RCE vulnerabilities',
                    f'Update or remove TimThumb from theme {theme}. Use WordPress built-in image handling instead.'
                )
    
    def scan(self):
        """Run comprehensive security scan"""
        print("\n" + "="*70)
        print("ADVANCED WORDPRESS SECURITY SCANNER")
        print("="*70)
        print(f"Target: {self.target_url}")
        print(f"Mode: {'Aggressive' if self.aggressive else 'Passive'}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        
        # Core checks
        if not self.check_wordpress_advanced():
            self.log('error', 'Target is not WordPress. Exiting.')
            return self.results
        
        # Run all security checks
        self.advanced_version_detection()
        self.check_xmlrpc_advanced()
        self.advanced_user_enumeration()
        
        # Continue with other checks from basic scanner
        from wp_security_scanner import WordPressScanner
        basic_scanner = WordPressScanner(self.target_url, self.timeout)
        
        # Integrate basic scanner results
        basic_scanner.check_directory_listing()
        basic_scanner.check_sensitive_files()
        basic_scanner.check_debug_mode()
        basic_scanner.check_security_headers()
        basic_scanner.check_ssl()
        
        # Enumerate plugins and themes for our checks
        basic_scanner.enumerate_plugins()
        basic_scanner.enumerate_themes()
        
        # Advanced checks
        self.check_database_exposure()
        self.check_file_upload_vulnerabilities()
        self.check_wp_cron()
        self.check_timthumb()
        
        # Merge results
        for vuln in basic_scanner.results['vulnerabilities']:
            severity = vuln['severity'].lower()
            if severity in self.results['vulnerabilities']:
                self.results['vulnerabilities'][severity].append(vuln)
        
        self.results['warnings'].extend(basic_scanner.results['warnings'])
        self.results['info'].update({
            f'basic_{k}': v for k, v in 
            [(item['title'], item['value']) for item in basic_scanner.results['info']]
        })
        
        return self.results
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*70)
        print("COMPREHENSIVE SECURITY REPORT")
        print("="*70)
        print(f"Target: {self.results['target']}")
        print(f"Scan Time: {self.results['scan_time']}")
        print(f"WordPress Detected: {self.results['is_wordpress']}")
        if self.results['wordpress_version']:
            print(f"WordPress Version: {self.results['wordpress_version']}")
        print("="*70)
        
        # Count vulnerabilities by severity
        total_vulns = sum(len(v) for v in self.results['vulnerabilities'].values())
        
        print(f"\n📊 VULNERABILITY SUMMARY")
        print(f"{'='*70}")
        print(f"🔴 Critical: {len(self.results['vulnerabilities']['critical'])}")
        print(f"🟠 High:     {len(self.results['vulnerabilities']['high'])}")
        print(f"🟡 Medium:   {len(self.results['vulnerabilities']['medium'])}")
        print(f"🟢 Low:      {len(self.results['vulnerabilities']['low'])}")
        print(f"{'='*70}")
        print(f"Total: {total_vulns} vulnerabilities")
        
        # Critical vulnerabilities (show all)
        if self.results['vulnerabilities']['critical']:
            print(f"\n🚨 CRITICAL VULNERABILITIES (IMMEDIATE ACTION REQUIRED)")
            print("="*70)
            for i, vuln in enumerate(self.results['vulnerabilities']['critical'], 1):
                print(f"\n{i}. {vuln['title']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Remediation: {vuln['remediation']}")
                if vuln.get('cve'):
                    print(f"   CVE: {vuln['cve']}")
        
        # High vulnerabilities
        if self.results['vulnerabilities']['high']:
            print(f"\n⚠️  HIGH SEVERITY VULNERABILITIES")
            print("="*70)
            for i, vuln in enumerate(self.results['vulnerabilities']['high'], 1):
                print(f"\n{i}. {vuln['title']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Remediation: {vuln['remediation'][:200]}...")
        
        # Medium vulnerabilities (summarized)
        if self.results['vulnerabilities']['medium']:
            print(f"\n⚡ MEDIUM SEVERITY ISSUES ({len(self.results['vulnerabilities']['medium'])} found)")
            print("="*70)
            for vuln in self.results['vulnerabilities']['medium'][:5]:
                print(f"  • {vuln['title']}")
            if len(self.results['vulnerabilities']['medium']) > 5:
                print(f"  ... and {len(self.results['vulnerabilities']['medium']) - 5} more")
        
        # Overall security score
        security_score = max(0, 100 - (
            len(self.results['vulnerabilities']['critical']) * 25 +
            len(self.results['vulnerabilities']['high']) * 15 +
            len(self.results['vulnerabilities']['medium']) * 5 +
            len(self.results['vulnerabilities']['low']) * 2
        ))
        
        print(f"\n{'='*70}")
        print(f"🎯 SECURITY SCORE: {security_score}/100")
        
        if security_score >= 80:
            rating = "GOOD"
            emoji = "✅"
        elif security_score >= 60:
            rating = "FAIR"
            emoji = "⚠️"
        elif security_score >= 40:
            rating = "POOR"
            emoji = "❌"
        else:
            rating = "CRITICAL"
            emoji = "🚨"
        
        print(f"Security Rating: {emoji} {rating}")
        print("="*70 + "\n")
        
        # Top recommendations
        print("🔧 TOP RECOMMENDATIONS:")
        print("="*70)
        recommendations = [
            "1. Update WordPress to the latest version",
            "2. Disable XML-RPC if not needed",
            "3. Implement strong authentication (2FA)",
            "4. Use security plugins (Wordfence, iThemes Security)",
            "5. Regular security audits and backups",
            "6. Keep all plugins and themes updated",
            "7. Use strong, unique passwords",
            "8. Implement Web Application Firewall (WAF)"
        ]
        
        for rec in recommendations[:5]:
            print(f"  {rec}")
        
        print("\n" + "="*70)
    
    def export_report(self, filename: str = None):
        """Export detailed report to JSON"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'wp_security_report_{timestamp}.json'
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.log('success', f'Report exported to {filename}')
        return filename


def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║        ADVANCED WORDPRESS SECURITY SCANNER v2.0              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_wp_scanner.py <target_url> [--aggressive]")
        print("\nOptions:")
        print("  --aggressive    Enable aggressive scanning (more thorough but detectable)")
        print("\nExample:")
        print("  python advanced_wp_scanner.py https://example.com")
        print("  python advanced_wp_scanner.py https://example.com --aggressive")
        sys.exit(1)
    
    target = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    # Legal disclaimer
    print("\n" + "!"*70)
    print("⚖️  LEGAL DISCLAIMER")
    print("!"*70)
    print("This tool is for authorized security testing ONLY.")
    print("Unauthorized scanning may violate:")
    print("  • Computer Fraud and Abuse Act (CFAA)")
    print("  • Computer Misuse Act")
    print("  • Local cybersecurity laws")
    print("\nYou must have explicit written permission to scan the target.")
    print("!"*70)
    
    confirm = input("\n⚠️  Do you have written authorization to scan this target? (yes/no): ")
    if confirm.lower() != 'yes':
        print("\n❌ Exiting. Obtain proper authorization first.")
        sys.exit(0)
    
    # Run scanner
    scanner = AdvancedWPScanner(target, aggressive=aggressive)
    scanner.scan()
    scanner.generate_report()
    
    # Export
    export = input("\n💾 Export detailed report to JSON? (yes/no): ")
    if export.lower() == 'yes':
        filename = scanner.export_report()
        print(f"\n✅ Full report saved to: {filename}")


if __name__ == "__main__":
    main()
