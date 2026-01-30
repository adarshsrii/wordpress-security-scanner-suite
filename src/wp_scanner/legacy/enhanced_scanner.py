#!/usr/bin/env python3
"""
WordPress Security Scanner with WPScan API Integration
Maximum accuracy vulnerability detection
"""

import requests
import json
import sys
from typing import Dict, List, Optional
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')


class WPScanAPIClient:
    """Client for WPScan Vulnerability Database API"""
    
    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token
        self.base_url = "https://wpscan.com/api/v3"
        self.cache = {}
    
    def search_wordpress_vulnerabilities(self, version: str) -> Dict:
        """Search for WordPress core vulnerabilities"""
        if not self.api_token:
            return {'error': 'No API token provided'}
        
        cache_key = f"wordpress_{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        url = f"{self.base_url}/wordpresses/{version.replace('.', '')}"
        headers = {"Authorization": f"Token token={self.api_token}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cache[cache_key] = data
                return data
            return {'error': f'API returned {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def search_plugin_vulnerabilities(self, plugin_slug: str) -> Dict:
        """Search for plugin vulnerabilities"""
        if not self.api_token:
            return {'error': 'No API token provided'}
        
        cache_key = f"plugin_{plugin_slug}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        url = f"{self.base_url}/plugins/{plugin_slug}"
        headers = {"Authorization": f"Token token={self.api_token}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cache[cache_key] = data
                return data
            return {'error': f'API returned {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def search_theme_vulnerabilities(self, theme_slug: str) -> Dict:
        """Search for theme vulnerabilities"""
        if not self.api_token:
            return {'error': 'No API token provided'}
        
        cache_key = f"theme_{theme_slug}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        url = f"{self.base_url}/themes/{theme_slug}"
        headers = {"Authorization": f"Token token={self.api_token}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cache[cache_key] = data
                return data
            return {'error': f'API returned {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}


class EnhancedWPScanner:
    """Enhanced WordPress scanner with vulnerability database integration"""
    
    def __init__(self, target_url: str, wpscan_api_token: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.wpscan_client = WPScanAPIClient(wpscan_api_token)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 WordPress Security Scanner'
        })
        
        self.results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'wordpress_version': None,
            'plugins': {},
            'themes': {},
            'vulnerabilities': [],
            'has_wpscan_api': wpscan_api_token is not None
        }
    
    def analyze_wordpress_version(self, version: str):
        """Analyze WordPress version for known vulnerabilities"""
        print(f"\n[*] Analyzing WordPress {version} for known vulnerabilities...")
        
        # Query WPScan database
        vuln_data = self.wpscan_client.search_wordpress_vulnerabilities(version)
        
        if 'error' in vuln_data:
            print(f"[!] Could not query WPScan API: {vuln_data['error']}")
            print("[*] Get free API token at: https://wpscan.com/api")
            return
        
        # Parse vulnerabilities
        if 'wordpresses' in vuln_data:
            wp_data = vuln_data['wordpresses']
            if version in wp_data:
                vulns = wp_data[version].get('vulnerabilities', [])
                
                for vuln in vulns:
                    self.results['vulnerabilities'].append({
                        'component': 'WordPress Core',
                        'version': version,
                        'title': vuln.get('title', 'Unknown'),
                        'vuln_type': vuln.get('vuln_type', 'Unknown'),
                        'fixed_in': vuln.get('fixed_in'),
                        'references': vuln.get('references', {}),
                        'severity': self.calculate_severity(vuln)
                    })
                    
                    print(f"[!] VULNERABILITY: {vuln.get('title')}")
                    if vuln.get('fixed_in'):
                        print(f"    Fixed in version: {vuln.get('fixed_in')}")
                
                if vulns:
                    print(f"\n[!!!] Found {len(vulns)} known vulnerabilities in WordPress {version}")
                else:
                    print(f"[+] No known vulnerabilities in WordPress {version}")
    
    def analyze_plugin(self, plugin_slug: str, plugin_version: Optional[str] = None):
        """Analyze plugin for vulnerabilities"""
        print(f"[*] Analyzing plugin: {plugin_slug}")
        
        vuln_data = self.wpscan_client.search_plugin_vulnerabilities(plugin_slug)
        
        if 'error' in vuln_data:
            return
        
        # Store plugin info
        self.results['plugins'][plugin_slug] = {
            'version': plugin_version,
            'vulnerabilities': []
        }
        
        # Check for vulnerabilities
        if plugin_slug in vuln_data:
            plugin_info = vuln_data[plugin_slug]
            vulns = plugin_info.get('vulnerabilities', [])
            
            for vuln in vulns:
                # Check if vulnerability affects this version
                fixed_in = vuln.get('fixed_in')
                is_vulnerable = True
                
                if plugin_version and fixed_in:
                    try:
                        from packaging import version
                        is_vulnerable = version.parse(plugin_version) < version.parse(fixed_in)
                    except:
                        # Fallback to string comparison
                        is_vulnerable = plugin_version < fixed_in
                
                vuln_info = {
                    'title': vuln.get('title', 'Unknown'),
                    'vuln_type': vuln.get('vuln_type', 'Unknown'),
                    'fixed_in': fixed_in,
                    'references': vuln.get('references', {}),
                    'severity': self.calculate_severity(vuln),
                    'affects_version': is_vulnerable
                }
                
                self.results['plugins'][plugin_slug]['vulnerabilities'].append(vuln_info)
                
                if is_vulnerable:
                    print(f"[!!!] VULNERABLE: {vuln.get('title')}")
                    if fixed_in:
                        print(f"      Update to version {fixed_in} or higher")
                    
                    self.results['vulnerabilities'].append({
                        'component': f'Plugin: {plugin_slug}',
                        'version': plugin_version,
                        **vuln_info
                    })
    
    def analyze_theme(self, theme_slug: str, theme_version: Optional[str] = None):
        """Analyze theme for vulnerabilities"""
        print(f"[*] Analyzing theme: {theme_slug}")
        
        vuln_data = self.wpscan_client.search_theme_vulnerabilities(theme_slug)
        
        if 'error' in vuln_data:
            return
        
        self.results['themes'][theme_slug] = {
            'version': theme_version,
            'vulnerabilities': []
        }
        
        if theme_slug in vuln_data:
            theme_info = vuln_data[theme_slug]
            vulns = theme_info.get('vulnerabilities', [])
            
            for vuln in vulns:
                vuln_info = {
                    'title': vuln.get('title', 'Unknown'),
                    'vuln_type': vuln.get('vuln_type', 'Unknown'),
                    'fixed_in': vuln.get('fixed_in'),
                    'references': vuln.get('references', {}),
                    'severity': self.calculate_severity(vuln)
                }
                
                self.results['themes'][theme_slug]['vulnerabilities'].append(vuln_info)
                
                print(f"[!!!] VULNERABLE: {vuln.get('title')}")
                
                self.results['vulnerabilities'].append({
                    'component': f'Theme: {theme_slug}',
                    'version': theme_version,
                    **vuln_info
                })
    
    def calculate_severity(self, vuln: Dict) -> str:
        """Calculate vulnerability severity"""
        vuln_type = vuln.get('vuln_type', '').lower()
        
        # Critical vulnerabilities
        critical_types = ['rce', 'sql injection', 'authentication bypass']
        if any(t in vuln_type for t in critical_types):
            return 'CRITICAL'
        
        # High severity
        high_types = ['xss', 'csrf', 'code injection', 'file inclusion']
        if any(t in vuln_type for t in high_types):
            return 'HIGH'
        
        # Medium severity
        medium_types = ['information disclosure', 'directory traversal']
        if any(t in vuln_type for t in medium_types):
            return 'MEDIUM'
        
        return 'LOW'
    
    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        print("\n" + "="*70)
        print("VULNERABILITY ASSESSMENT REPORT")
        print("="*70)
        print(f"Target: {self.results['target']}")
        print(f"Scan Time: {self.results['scan_time']}")
        
        if self.results['wordpress_version']:
            print(f"WordPress Version: {self.results['wordpress_version']}")
        
        print(f"WPScan API: {'✓ Enabled' if self.results['has_wpscan_api'] else '✗ Disabled'}")
        print("="*70)
        
        # Count vulnerabilities by severity
        vuln_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for vuln in self.results['vulnerabilities']:
            severity = vuln.get('severity', 'LOW')
            vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        print(f"\n📊 VULNERABILITY SUMMARY")
        print(f"{'='*70}")
        print(f"🔴 Critical: {vuln_counts['CRITICAL']}")
        print(f"🟠 High:     {vuln_counts['HIGH']}")
        print(f"🟡 Medium:   {vuln_counts['MEDIUM']}")
        print(f"🟢 Low:      {vuln_counts['LOW']}")
        print(f"{'='*70}")
        print(f"Total: {len(self.results['vulnerabilities'])} known vulnerabilities")
        
        # Detailed vulnerability list
        if self.results['vulnerabilities']:
            print(f"\n🔍 DETAILED VULNERABILITIES")
            print("="*70)
            
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                print(f"\n{i}. [{vuln['severity']}] {vuln['component']}")
                print(f"   Title: {vuln['title']}")
                print(f"   Type: {vuln['vuln_type']}")
                
                if vuln.get('fixed_in'):
                    print(f"   Fixed In: {vuln['fixed_in']}")
                    print(f"   ⚠️  ACTION REQUIRED: Update to version {vuln['fixed_in']} or higher")
                
                if vuln.get('references'):
                    refs = vuln['references']
                    if 'cve' in refs:
                        print(f"   CVE: {refs['cve']}")
                    if 'url' in refs:
                        print(f"   Reference: {refs['url'][0] if isinstance(refs['url'], list) else refs['url']}")
        
        # Security recommendations
        print(f"\n🔧 SECURITY RECOMMENDATIONS")
        print("="*70)
        
        recommendations = []
        
        if vuln_counts['CRITICAL'] > 0:
            recommendations.append("🚨 URGENT: Address critical vulnerabilities immediately")
        
        if self.results['wordpress_version']:
            recommendations.append(f"• Update WordPress from {self.results['wordpress_version']} to latest version")
        
        for plugin, data in self.results['plugins'].items():
            if data['vulnerabilities']:
                recommendations.append(f"• Update or remove plugin: {plugin}")
        
        for theme, data in self.results['themes'].items():
            if data['vulnerabilities']:
                recommendations.append(f"• Update or remove theme: {theme}")
        
        recommendations.extend([
            "• Enable automatic updates for WordPress core",
            "• Regularly update all plugins and themes",
            "• Use security plugin (Wordfence, iThemes Security)",
            "• Implement Web Application Firewall (WAF)",
            "• Enable two-factor authentication",
            "• Regular security audits and backups"
        ])
        
        for rec in recommendations[:10]:
            print(f"  {rec}")
        
        print("\n" + "="*70)
    
    def export_json(self, filename: str = None):
        """Export results to JSON"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'wp_vuln_report_{timestamp}.json'
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[+] Report exported to {filename}")
        return filename


def demo_scan_with_known_components():
    """
    Demo: How to use the scanner with known WordPress components
    This demonstrates the maximum accuracy approach
    """
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║  WORDPRESS VULNERABILITY SCANNER WITH WPSCAN API             ║
║  Maximum Accuracy Vulnerability Detection                    ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Example usage - you would detect these from the actual site
    target_url = "https://example.com"
    
    # Get WPScan API token (free tier available)
    print("\n💡 TIP: Get free WPScan API token at https://wpscan.com/api")
    api_token = input("Enter WPScan API token (or press Enter to skip): ").strip()
    
    if not api_token:
        print("[!] Running without WPScan API - limited vulnerability detection")
        api_token = None
    
    # Initialize scanner
    scanner = EnhancedWPScanner(target_url, api_token)
    
    # Simulate detected components (in real scan, you'd detect these)
    print("\n[*] Demo Mode: Using example WordPress installation")
    print("[*] In production, these would be detected automatically\n")
    
    # Example: WordPress version
    wp_version = "6.4.2"  # Example - could be outdated
    scanner.results['wordpress_version'] = wp_version
    
    if api_token:
        scanner.analyze_wordpress_version(wp_version)
        
        # Example: Detected plugins with versions
        example_plugins = {
            'wordfence': '7.10.0',
            'elementor': '3.16.0',
            'contact-form-7': '5.8',
        }
        
        for plugin, version in example_plugins.items():
            scanner.analyze_plugin(plugin, version)
        
        # Example: Detected theme
        scanner.analyze_theme('twentytwentythree', '1.3')
    else:
        print("[!] Skipping vulnerability checks - no API token provided")
    
    # Generate report
    scanner.generate_report()
    
    # Export
    export = input("\n💾 Export report to JSON? (yes/no): ")
    if export.lower() == 'yes':
        scanner.export_json()


def main():
    if len(sys.argv) > 1:
        # Real usage with provided target
        target = sys.argv[1]
        api_token = sys.argv[2] if len(sys.argv) > 2 else None
        
        # Would integrate with basic scanner here to detect components
        print("[*] For production use, integrate with wp_security_scanner.py")
        print("[*] to automatically detect WordPress version, plugins, and themes")
        print("\nUsage:")
        print("  python enhanced_scanner.py <url> [wpscan_api_token]")
    else:
        # Demo mode
        demo_scan_with_known_components()


if __name__ == "__main__":
    main()
