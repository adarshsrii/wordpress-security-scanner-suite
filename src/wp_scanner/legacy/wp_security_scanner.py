#!/usr/bin/env python3
"""
WordPress Security Scanner
Performs comprehensive security checks on WordPress installations
"""

import requests
import re
import json
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class WordPressScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WordPress Security Scanner'
        })
        self.results = {
            'target': target_url,
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'is_wordpress': False
        }
    
    def add_vulnerability(self, title: str, description: str, severity: str, remediation: str):
        """Add a vulnerability finding"""
        self.results['vulnerabilities'].append({
            'title': title,
            'description': description,
            'severity': severity,
            'remediation': remediation
        })
    
    def add_warning(self, title: str, description: str):
        """Add a warning"""
        self.results['warnings'].append({
            'title': title,
            'description': description
        })
    
    def add_info(self, title: str, value: str):
        """Add informational finding"""
        self.results['info'].append({
            'title': title,
            'value': value
        })
    
    def safe_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make a safe HTTP request with error handling"""
        try:
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
            elif method == 'POST':
                response = self.session.post(url, timeout=self.timeout, verify=False, **kwargs)
            elif method == 'HEAD':
                response = self.session.head(url, timeout=self.timeout, verify=False, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed for {url}: {str(e)}")
            return None
    
    def check_wordpress(self) -> bool:
        """Verify if target is a WordPress site"""
        print("[*] Checking if target is WordPress...")
        
        # Check homepage
        response = self.safe_request(self.target_url)
        if not response:
            return False
        
        html = response.text
        
        # Multiple WordPress detection methods
        wordpress_indicators = [
            'wp-content' in html,
            'wp-includes' in html,
            '/wp-json/' in html,
            'wordpress' in html.lower(),
            'wp-emoji' in html,
        ]
        
        # Check for generator meta tag
        soup = BeautifulSoup(html, 'html.parser')
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'wordpress' in generator.get('content', '').lower():
            wordpress_indicators.append(True)
        
        # Check wp-login.php
        login_url = urljoin(self.target_url, '/wp-login.php')
        login_response = self.safe_request(login_url)
        if login_response and login_response.status_code == 200:
            wordpress_indicators.append(True)
        
        is_wp = sum(wordpress_indicators) >= 2
        self.results['is_wordpress'] = is_wp
        
        if is_wp:
            print("[+] Target is WordPress")
        else:
            print("[-] Target does not appear to be WordPress")
        
        return is_wp
    
    def detect_version(self):
        """Detect WordPress version"""
        print("[*] Detecting WordPress version...")
        
        version_sources = []
        
        # Check generator meta tag
        response = self.safe_request(self.target_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator:
                content = generator.get('content', '')
                version_match = re.search(r'WordPress\s+([\d.]+)', content)
                if version_match:
                    version_sources.append(('Generator Meta Tag', version_match.group(1)))
        
        # Check readme.html
        readme_url = urljoin(self.target_url, '/readme.html')
        readme_response = self.safe_request(readme_url)
        if readme_response and readme_response.status_code == 200:
            version_match = re.search(r'Version\s+([\d.]+)', readme_response.text)
            if version_match:
                version_sources.append(('readme.html', version_match.group(1)))
            
            self.add_vulnerability(
                'readme.html Accessible',
                'The readme.html file is publicly accessible, exposing WordPress version',
                'LOW',
                'Remove or restrict access to readme.html file'
            )
        
        # Check RSS feed
        feed_url = urljoin(self.target_url, '/feed/')
        feed_response = self.safe_request(feed_url)
        if feed_response and feed_response.status_code == 200:
            version_match = re.search(r'wordpress\.org/\?v=([\d.]+)', feed_response.text)
            if version_match:
                version_sources.append(('RSS Feed', version_match.group(1)))
        
        # Check REST API
        api_url = urljoin(self.target_url, '/wp-json/')
        api_response = self.safe_request(api_url)
        if api_response and api_response.status_code == 200:
            try:
                api_data = api_response.json()
                if 'description' in api_data or 'name' in api_data:
                    self.add_warning(
                        'REST API Publicly Accessible',
                        'WordPress REST API is accessible without authentication'
                    )
            except:
                pass
        
        if version_sources:
            for source, version in version_sources:
                self.add_info(f'WordPress Version ({source})', version)
                print(f"[+] Version detected: {version} (via {source})")
        else:
            print("[-] Could not detect WordPress version")
    
    def check_xmlrpc(self):
        """Check XML-RPC availability"""
        print("[*] Checking XML-RPC...")
        
        xmlrpc_url = urljoin(self.target_url, '/xmlrpc.php')
        
        # Check if xmlrpc.php exists
        response = self.safe_request(xmlrpc_url, method='POST', 
                                     data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                                     headers={'Content-Type': 'application/xml'})
        
        if response and response.status_code == 200 and 'XML-RPC' in response.text:
            self.add_vulnerability(
                'XML-RPC Enabled',
                'XML-RPC is enabled and can be used for brute force attacks, DDoS attacks, and pingback abuse',
                'HIGH',
                'Disable XML-RPC if not needed. Add to .htaccess: <Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n</Files>'
            )
            print("[!] XML-RPC is ENABLED - HIGH RISK")
        else:
            print("[+] XML-RPC appears disabled")
    
    def enumerate_users(self):
        """Enumerate WordPress users"""
        print("[*] Enumerating users...")
        
        users_found = []
        
        # Method 1: Author archives
        for user_id in range(1, 11):
            author_url = urljoin(self.target_url, f'/?author={user_id}')
            response = self.safe_request(author_url, allow_redirects=True)
            
            if response and response.status_code == 200:
                # Extract username from URL
                username_match = re.search(r'/author/([^/]+)', response.url)
                if username_match:
                    username = username_match.group(1)
                    users_found.append(username)
        
        # Method 2: REST API
        users_api_url = urljoin(self.target_url, '/wp-json/wp/v2/users')
        api_response = self.safe_request(users_api_url)
        
        if api_response and api_response.status_code == 200:
            try:
                users_data = api_response.json()
                for user in users_data:
                    if 'slug' in user:
                        users_found.append(user['slug'])
            except:
                pass
        
        if users_found:
            users_found = list(set(users_found))  # Remove duplicates
            self.add_vulnerability(
                'User Enumeration Possible',
                f'Found {len(users_found)} users: {", ".join(users_found[:5])}{"..." if len(users_found) > 5 else ""}',
                'MEDIUM',
                'Disable user enumeration via author archives and REST API. Use security plugins like Wordfence or limit REST API access.'
            )
            print(f"[!] Found {len(users_found)} users")
            for user in users_found[:5]:
                self.add_info('Enumerated User', user)
    
    def check_directory_listing(self):
        """Check for directory listing vulnerabilities"""
        print("[*] Checking directory listings...")
        
        directories = [
            '/wp-content/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-content/uploads/',
            '/wp-includes/'
        ]
        
        for directory in directories:
            url = urljoin(self.target_url, directory)
            response = self.safe_request(url)
            
            if response and response.status_code == 200:
                if 'Index of' in response.text or '<title>Index of' in response.text:
                    self.add_vulnerability(
                        f'Directory Listing Enabled: {directory}',
                        f'Directory listing is enabled for {directory}, exposing file structure',
                        'MEDIUM',
                        'Disable directory listing in Apache: Options -Indexes in .htaccess'
                    )
                    print(f"[!] Directory listing enabled: {directory}")
    
    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        print("[*] Checking sensitive files...")
        
        sensitive_files = {
            '/wp-config.php': ('CRITICAL', 'WordPress configuration file'),
            '/wp-config.php.bak': ('CRITICAL', 'WordPress config backup'),
            '/wp-config.php~': ('CRITICAL', 'WordPress config backup'),
            '/wp-config.old': ('CRITICAL', 'WordPress config backup'),
            '/.git/config': ('HIGH', 'Git repository exposed'),
            '/.env': ('CRITICAL', 'Environment configuration file'),
            '/debug.log': ('MEDIUM', 'Debug log file'),
            '/error_log': ('MEDIUM', 'Error log file'),
            '/php.ini': ('HIGH', 'PHP configuration file'),
            '/.htaccess': ('MEDIUM', 'Apache configuration file'),
            '/phpinfo.php': ('HIGH', 'PHP info page'),
            '/info.php': ('HIGH', 'PHP info page'),
            '/wp-content/debug.log': ('MEDIUM', 'WordPress debug log'),
        }
        
        for file_path, (severity, description) in sensitive_files.items():
            url = urljoin(self.target_url, file_path)
            response = self.safe_request(url, method='HEAD')
            
            if response and response.status_code == 200:
                # Double check with GET for false positives
                get_response = self.safe_request(url)
                if get_response and get_response.status_code == 200 and len(get_response.content) > 0:
                    self.add_vulnerability(
                        f'Sensitive File Exposed: {file_path}',
                        f'{description} is publicly accessible',
                        severity,
                        f'Remove or restrict access to {file_path}'
                    )
                    print(f"[!] Exposed: {file_path}")
    
    def check_debug_mode(self):
        """Check if WordPress debug mode is enabled"""
        print("[*] Checking debug mode...")
        
        response = self.safe_request(self.target_url)
        if response:
            # Look for common debug output patterns
            debug_indicators = [
                'WP_DEBUG',
                'WordPress database error',
                'Warning: ',
                'Notice: ',
                'Fatal error:',
                'Stack trace:',
            ]
            
            for indicator in debug_indicators:
                if indicator in response.text:
                    self.add_vulnerability(
                        'Debug Mode Enabled',
                        'WordPress debug mode appears to be enabled, exposing sensitive information',
                        'MEDIUM',
                        'Disable debug mode in wp-config.php: define(\'WP_DEBUG\', false);'
                    )
                    print("[!] Debug mode appears enabled")
                    break
    
    def check_security_headers(self):
        """Check security headers"""
        print("[*] Checking security headers...")
        
        response = self.safe_request(self.target_url)
        if not response:
            return
        
        headers = response.headers
        
        # Check for important security headers
        security_headers = {
            'X-Frame-Options': ('Clickjacking protection missing', 'Add X-Frame-Options: SAMEORIGIN'),
            'X-Content-Type-Options': ('MIME-sniffing protection missing', 'Add X-Content-Type-Options: nosniff'),
            'Strict-Transport-Security': ('HSTS not enabled', 'Add Strict-Transport-Security header'),
            'Content-Security-Policy': ('CSP not implemented', 'Implement Content-Security-Policy'),
            'X-XSS-Protection': ('XSS protection header missing', 'Add X-XSS-Protection: 1; mode=block'),
        }
        
        for header, (description, remediation) in security_headers.items():
            if header not in headers:
                self.add_warning(
                    f'Missing Security Header: {header}',
                    f'{description}. {remediation}'
                )
    
    def check_ssl(self):
        """Check SSL/HTTPS configuration"""
        print("[*] Checking SSL/HTTPS...")
        
        if not self.target_url.startswith('https://'):
            self.add_vulnerability(
                'HTTPS Not Used',
                'Site is not using HTTPS, data transmitted in plain text',
                'HIGH',
                'Install SSL certificate and force HTTPS redirection'
            )
            print("[!] Site not using HTTPS")
        else:
            # Check if HTTP redirects to HTTPS
            http_url = self.target_url.replace('https://', 'http://')
            response = self.safe_request(http_url, allow_redirects=False)
            
            if response and response.status_code not in [301, 302, 308]:
                self.add_warning(
                    'HTTP to HTTPS Redirect Missing',
                    'HTTP version does not redirect to HTTPS'
                )
    
    def enumerate_plugins(self):
        """Enumerate installed plugins"""
        print("[*] Enumerating plugins...")
        
        plugins_found = []
        
        # Check wp-content/plugins directory
        plugins_url = urljoin(self.target_url, '/wp-content/plugins/')
        response = self.safe_request(plugins_url)
        
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for plugin links
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if '/' in href and not href.startswith('?'):
                    plugin_name = href.strip('/')
                    if plugin_name and plugin_name not in ['.', '..']:
                        plugins_found.append(plugin_name)
        
        # Check homepage source for plugin references
        homepage = self.safe_request(self.target_url)
        if homepage:
            plugin_matches = re.findall(r'/wp-content/plugins/([^/\'"]+)', homepage.text)
            plugins_found.extend(plugin_matches)
        
        plugins_found = list(set(plugins_found))
        
        if plugins_found:
            print(f"[+] Found {len(plugins_found)} plugins")
            for plugin in plugins_found[:10]:
                self.add_info('Installed Plugin', plugin)
                
                # Check for plugin readme files
                readme_url = urljoin(self.target_url, f'/wp-content/plugins/{plugin}/readme.txt')
                readme_response = self.safe_request(readme_url)
                
                if readme_response and readme_response.status_code == 200:
                    version_match = re.search(r'Stable tag:\s*([\d.]+)', readme_response.text)
                    if version_match:
                        self.add_info(f'Plugin Version ({plugin})', version_match.group(1))
    
    def enumerate_themes(self):
        """Enumerate installed themes"""
        print("[*] Enumerating themes...")
        
        themes_found = []
        
        # Check homepage source for theme references
        homepage = self.safe_request(self.target_url)
        if homepage:
            theme_matches = re.findall(r'/wp-content/themes/([^/\'"]+)', homepage.text)
            themes_found.extend(theme_matches)
        
        themes_found = list(set(themes_found))
        
        if themes_found:
            print(f"[+] Found {len(themes_found)} themes")
            for theme in themes_found:
                self.add_info('Installed Theme', theme)
                
                # Check for theme version
                style_url = urljoin(self.target_url, f'/wp-content/themes/{theme}/style.css')
                style_response = self.safe_request(style_url)
                
                if style_response and style_response.status_code == 200:
                    version_match = re.search(r'Version:\s*([\d.]+)', style_response.text)
                    if version_match:
                        self.add_info(f'Theme Version ({theme})', version_match.group(1))
    
    def check_login_page(self):
        """Check login page security"""
        print("[*] Checking login page...")
        
        login_url = urljoin(self.target_url, '/wp-login.php')
        response = self.safe_request(login_url)
        
        if response and response.status_code == 200:
            self.add_info('Login Page', 'Accessible at /wp-login.php')
            
            # Check if there's rate limiting (basic check)
            # Try multiple requests
            failed_attempts = 0
            for i in range(3):
                test_response = self.safe_request(
                    login_url,
                    method='POST',
                    data={
                        'log': 'admin',
                        'pwd': 'wrongpassword123',
                        'wp-submit': 'Log In'
                    }
                )
                if test_response and test_response.status_code == 200:
                    failed_attempts += 1
            
            if failed_attempts == 3:
                self.add_warning(
                    'No Login Rate Limiting Detected',
                    'Login page may be vulnerable to brute force attacks. Consider implementing login rate limiting.'
                )
                print("[!] No obvious rate limiting on login")
    
    def scan(self):
        """Run all security checks"""
        print("\n" + "="*60)
        print(f"WordPress Security Scanner")
        print(f"Target: {self.target_url}")
        print("="*60 + "\n")
        
        if not self.check_wordpress():
            print("\n[!] Target is not WordPress. Exiting.")
            return self.results
        
        # Run all checks
        self.detect_version()
        self.check_xmlrpc()
        self.enumerate_users()
        self.check_directory_listing()
        self.check_sensitive_files()
        self.check_debug_mode()
        self.check_security_headers()
        self.check_ssl()
        self.enumerate_plugins()
        self.enumerate_themes()
        self.check_login_page()
        
        return self.results
    
    def print_results(self):
        """Print formatted results"""
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        
        # Critical/High vulnerabilities
        critical_high = [v for v in self.results['vulnerabilities'] 
                        if v['severity'] in ['CRITICAL', 'HIGH']]
        
        if critical_high:
            print(f"\n[CRITICAL/HIGH] {len(critical_high)} Critical/High Severity Issues:")
            for vuln in critical_high:
                print(f"\n  [{vuln['severity']}] {vuln['title']}")
                print(f"  Description: {vuln['description']}")
                print(f"  Remediation: {vuln['remediation']}")
        
        # Medium/Low vulnerabilities
        medium_low = [v for v in self.results['vulnerabilities'] 
                     if v['severity'] in ['MEDIUM', 'LOW']]
        
        if medium_low:
            print(f"\n[MEDIUM/LOW] {len(medium_low)} Medium/Low Severity Issues:")
            for vuln in medium_low:
                print(f"\n  [{vuln['severity']}] {vuln['title']}")
                print(f"  Description: {vuln['description']}")
        
        # Warnings
        if self.results['warnings']:
            print(f"\n[WARNINGS] {len(self.results['warnings'])} Warnings:")
            for warning in self.results['warnings']:
                print(f"  - {warning['title']}")
        
        # Info
        if self.results['info']:
            print(f"\n[INFO] Information Gathered:")
            for info in self.results['info'][:15]:  # Limit to first 15
                print(f"  - {info['title']}: {info['value']}")
        
        print("\n" + "="*60)
        print(f"Total Issues: {len(self.results['vulnerabilities'])}")
        print(f"Warnings: {len(self.results['warnings'])}")
        print(f"Info Items: {len(self.results['info'])}")
        print("="*60 + "\n")
    
    def export_json(self, filename: str = 'scan_results.json'):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results exported to {filename}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python wp_security_scanner.py <target_url>")
        print("Example: python wp_security_scanner.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Add disclaimer
    print("\n" + "!"*60)
    print("IMPORTANT LEGAL DISCLAIMER")
    print("!"*60)
    print("This tool should only be used on websites you own or have")
    print("explicit written permission to test. Unauthorized security")
    print("testing may be illegal in your jurisdiction.")
    print("!"*60)
    
    response = input("\nDo you have permission to scan this target? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting. Please obtain proper authorization first.")
        sys.exit(0)
    
    # Run scanner
    scanner = WordPressScanner(target)
    scanner.scan()
    scanner.print_results()
    
    # Export results
    export = input("\nExport results to JSON? (yes/no): ")
    if export.lower() == 'yes':
        scanner.export_json()


if __name__ == "__main__":
    main()
