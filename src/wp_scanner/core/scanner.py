#!/usr/bin/env python3
"""
WordPress Security Scanner - Main Orchestrator
Coordinates all scanning modules for comprehensive security assessment.
Uses multi-threaded parallel execution for faster scanning.
"""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Callable
from bs4 import BeautifulSoup

from wp_scanner.utils.logger import Logger, setup_logger
from wp_scanner.utils.http import HTTPClient
from wp_scanner.utils.reporter import ReportGenerator
from wp_scanner.scanners.backup_scanner import BackupFileScanner
from wp_scanner.scanners.rest_api_scanner import RESTAPIScanner
from wp_scanner.scanners.xmlrpc_scanner import XMLRPCScanner
from wp_scanner.scanners.injection_scanner import InjectionScanner
from wp_scanner.scanners.auth_scanner import AuthScanner
from wp_scanner.scanners.header_scanner import HeaderScanner
from wp_scanner.scanners.plugin_scanner import PluginScanner
from wp_scanner.scanners.domain_scanner import DomainScanner
from wp_scanner.scanners.advanced_scanner import AdvancedScanner
from wp_scanner.scanners.network_scanner import NetworkScanner


class WPSecurityScanner:
    """
    Main WordPress Security Scanner orchestrator.
    Coordinates all scanning modules and generates reports.
    Uses parallel execution for faster scanning.
    """

    def __init__(self, target_url: str, aggressive: bool = False,
                 timeout: int = 15, threads: int = 10,
                 scanner_workers: int = 5, verbose: bool = False,
                 output_dir: str = "output"):
        """
        Initialize the scanner.

        Args:
            target_url: Target WordPress site URL
            aggressive: Enable aggressive scanning (SQL/XSS tests)
            timeout: Request timeout in seconds
            threads: Number of concurrent threads for individual scanners
            scanner_workers: Number of parallel scanner workers (default: 5)
            verbose: Enable verbose logging
            output_dir: Directory for output reports
        """
        self.target_url = target_url.rstrip('/')
        self.aggressive = aggressive
        self.threads = threads
        self.scanner_workers = scanner_workers
        self.output_dir = output_dir

        # Initialize logger
        self.log = setup_logger(verbose=verbose)

        # Thread lock for result updates
        self._results_lock = threading.Lock()

        # Initialize HTTP client with connection pooling for thread safety
        self.http = HTTPClient(
            base_url=self.target_url,
            timeout=timeout,
            rate_limit=0.05,  # Faster rate for parallel requests
            pool_connections=scanner_workers * 2,
            pool_maxsize=scanner_workers * 4,
        )

        # Initialize results
        self.results = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'scan_mode': 'aggressive' if aggressive else 'passive',
            'is_wordpress': False,
            'wordpress_version': None,
            'server_info': {},
            'vulnerabilities': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            },
            'exposed_files': [],
            'plugins': {},
            'themes': {},
            'users': [],
            'security_headers': {},
            'attack_surface': {},
            'domain_security': {},
            'backdoors': {},
            'recommendations': [],
            'risk_score': 0
        }

        # Initialize individual scanners
        self._init_scanners()

    def _init_scanners(self):
        """Initialize all scanner modules."""
        self.backup_scanner = BackupFileScanner(self.http, self.log)
        self.rest_api_scanner = RESTAPIScanner(self.http, self.log)
        self.xmlrpc_scanner = XMLRPCScanner(self.http, self.log)
        self.injection_scanner = InjectionScanner(self.http, self.log)
        self.auth_scanner = AuthScanner(self.http, self.log)
        self.header_scanner = HeaderScanner(self.http, self.log)
        self.plugin_scanner = PluginScanner(self.http, self.log)
        self.domain_scanner = DomainScanner(self.http, self.log)
        self.advanced_scanner = AdvancedScanner(self.http, self.log)
        self.network_scanner = NetworkScanner(self.http, self.log)

    def _add_findings(self, findings: list):
        """Add findings from a scanner to the main results (thread-safe)."""
        with self._results_lock:
            for finding in findings:
                severity = finding.get('severity', 'INFO').lower()
                if severity in self.results['vulnerabilities']:
                    self.results['vulnerabilities'][severity].append(finding)

    def _process_scanner_result(self, name: str, result: Dict[str, Any]):
        """Process result from a scanner and merge into main results (thread-safe)."""
        with self._results_lock:
            if name == 'backup':
                self.results['exposed_files'] = result.get('exposed_files', [])
            elif name == 'rest_api':
                self.results['attack_surface']['rest_api'] = result
                self.results['users'].extend(result.get('users_enumerated', []))
            elif name == 'xmlrpc':
                self.results['attack_surface']['xmlrpc'] = result
            elif name == 'injection':
                self.results['attack_surface']['injection'] = result
            elif name == 'auth':
                for user in result.get('users', []):
                    if not any(u.get('username') == user.get('username') for u in self.results['users']):
                        self.results['users'].append(user)
            elif name == 'headers':
                self.results['security_headers'] = result
            elif name == 'plugins':
                self.results['plugins'] = result.get('plugins', {})
                self.results['themes'] = result.get('themes', {})
            elif name == 'domain':
                self.results['domain_security'] = {
                    'ssl': result.get('ssl', {}),
                    'server_disclosure': result.get('server_disclosure', {}),
                    'hidden_paths': result.get('hidden_paths', {}),
                }
                self.results['backdoors'] = result.get('backdoors', {})
                self.results['attack_surface']['malicious_content'] = result.get('malicious_content', {})
            elif name == 'advanced':
                self.results['attack_surface']['advanced'] = result
            elif name == 'network':
                self.results['attack_surface']['network'] = result
                if 'network_security' not in self.results:
                    self.results['network_security'] = {}
                self.results['network_security'].update(result)

        # Add findings outside lock since _add_findings has its own lock
        self._add_findings(result.get('findings', []))

    def detect_wordpress(self) -> bool:
        """Detect if target is a WordPress installation."""
        self.log.scan("Detecting WordPress installation...")

        detection_score = 0
        indicators = []

        response = self.http.get('/')
        if not response:
            self.log.error("Could not connect to target")
            return False

        html = response.text
        headers = response.headers

        # Store server info
        self.results['server_info'] = {
            'server': headers.get('Server', 'Unknown'),
            'x_powered_by': headers.get('X-Powered-By', 'Unknown'),
        }

        # Check indicators
        checks = [
            ('wp-content', 'wp-content' in html, 2),
            ('wp-includes', 'wp-includes' in html, 2),
            ('wp-json', '/wp-json/' in html, 1),
            ('wp-emoji', 'wp-emoji' in html, 1),
        ]

        for name, result, score in checks:
            if result:
                detection_score += score
                indicators.append(name)

        # Check generator meta tag
        soup = BeautifulSoup(html, 'html.parser')
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'wordpress' in generator.get('content', '').lower():
            detection_score += 3
            indicators.append('generator_meta')

            version_match = re.search(r'WordPress\s+([\d.]+)',
                                     generator.get('content', ''))
            if version_match:
                self.results['wordpress_version'] = version_match.group(1)

        # Check wp-login.php
        login_response = self.http.get('/wp-login.php')
        if login_response and login_response.status_code == 200:
            if 'wordpress' in login_response.text.lower():
                detection_score += 2
                indicators.append('wp-login.php')

        # Check REST API
        api_response = self.http.get('/wp-json/')
        if api_response and api_response.status_code == 200:
            try:
                api_data = api_response.json()
                if 'namespaces' in api_data:
                    detection_score += 2
                    indicators.append('rest_api')
            except:
                pass

        is_wordpress = detection_score >= 4
        self.results['is_wordpress'] = is_wordpress
        self.results['attack_surface']['detection'] = {
            'indicators': indicators,
            'confidence': f"{min(100, detection_score * 10)}%"
        }

        if is_wordpress:
            self.log.success(f"WordPress detected (confidence: {min(100, detection_score * 10)}%)")
            if self.results['wordpress_version']:
                self.log.info(f"Version: {self.results['wordpress_version']}")
        else:
            self.log.error("Target does not appear to be WordPress")

        return is_wordpress

    def detect_version(self):
        """Detect WordPress version from multiple sources."""
        self.log.scan("Detecting WordPress version...")

        versions = {}

        # Already got from generator
        if self.results['wordpress_version']:
            versions['generator'] = self.results['wordpress_version']

        # Check feed
        response = self.http.get('/feed/')
        if response and response.status_code == 200:
            match = re.search(r'wordpress\.org/\?v=([\d.]+)', response.text)
            if match:
                versions['feed'] = match.group(1)

        # Check assets
        response = self.http.get('/')
        if response:
            matches = re.findall(r'/wp-includes/[^"\']*\?ver=([\d.]+)', response.text)
            if matches:
                versions['assets'] = matches[0]

        # Use best version
        for source in ['generator', 'feed', 'assets']:
            if source in versions:
                self.results['wordpress_version'] = versions[source]
                self.log.success(f"Version {versions[source]} detected via {source}")
                break

        self.results['attack_surface']['version_sources'] = versions

    def calculate_risk_score(self) -> int:
        """Calculate overall risk score."""
        score = 100

        deductions = {
            'critical': 25,
            'high': 15,
            'medium': 5,
            'low': 2,
        }

        for severity, vulns in self.results['vulnerabilities'].items():
            if severity in deductions:
                score -= len(vulns) * deductions[severity]

        if self.results['exposed_files']:
            score -= min(20, len(self.results['exposed_files']) * 2)

        # Backdoors are critical - immediate 0 score
        backdoors = self.results.get('backdoors', {}).get('found', [])
        if backdoors:
            score = 0  # Site is compromised

        self.results['risk_score'] = max(0, min(100, score))
        return self.results['risk_score']

    def get_grade(self) -> str:
        """Get letter grade from score."""
        score = self.results['risk_score']
        if score >= 90: return 'A+'
        elif score >= 85: return 'A'
        elif score >= 80: return 'B+'
        elif score >= 75: return 'B'
        elif score >= 70: return 'C+'
        elif score >= 65: return 'C'
        elif score >= 60: return 'D+'
        elif score >= 55: return 'D'
        else: return 'F'

    def generate_recommendations(self):
        """Generate prioritized recommendations."""
        recommendations = []

        # Check for backdoors first (highest priority)
        backdoors = self.results.get('backdoors', {}).get('found', [])
        if backdoors:
            recommendations.append({
                'priority': 0,
                'title': 'SITE COMPROMISED - Immediate Action Required',
                'description': f"Found {len(backdoors)} backdoor(s). Take site offline, backup evidence, clean infection, change all passwords."
            })

        if self.results['vulnerabilities']['critical']:
            recommendations.append({
                'priority': 1,
                'title': 'Address Critical Vulnerabilities Immediately',
                'description': f"Found {len(self.results['vulnerabilities']['critical'])} critical issues"
            })

        critical_files = [f for f in self.results['exposed_files']
                         if f['severity'] == 'CRITICAL']
        if critical_files:
            recommendations.append({
                'priority': 1,
                'title': 'Remove Exposed Sensitive Files',
                'description': f"Found {len(critical_files)} critical exposed files"
            })

        if self.results['wordpress_version']:
            recommendations.append({
                'priority': 2,
                'title': 'Update WordPress Core',
                'description': f"Current: {self.results['wordpress_version']}. Keep updated."
            })

        if self.results.get('security_headers', {}).get('missing'):
            recommendations.append({
                'priority': 3,
                'title': 'Implement Security Headers',
                'description': 'Add missing security headers'
            })

        recommendations.extend([
            {'priority': 3, 'title': 'Implement WAF', 'description': 'Use Wordfence/Cloudflare'},
            {'priority': 3, 'title': 'Enable 2FA', 'description': 'Protect admin accounts'},
            {'priority': 4, 'title': 'Regular Audits', 'description': 'Schedule security scans'},
        ])

        recommendations.sort(key=lambda x: x['priority'])
        self.results['recommendations'] = recommendations

    def scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan with parallel execution."""
        self.log.banner("WORDPRESS SECURITY SCANNER", width=60)
        self.log.info(f"Target: {self.target_url}")
        self.log.info(f"Mode: {'AGGRESSIVE' if self.aggressive else 'PASSIVE'}")
        self.log.info(f"Workers: {self.scanner_workers} parallel scanners")
        self.log.info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        # Phase 1: Detection (must be first - sequential)
        if not self.detect_wordpress():
            self.log.error("Target is not WordPress. Exiting.")
            return self.results

        # Phase 2: Version detection (sequential)
        self.detect_version()

        # Phase 3: Run all scanners in parallel
        self.log.scan("Running security scanners in parallel...")

        # Define scanners: (name, function, kwargs)
        scanners: List[Tuple[str, Callable, Dict]] = [
            ('backup', self.backup_scanner.scan, {'threads': self.threads}),
            ('rest_api', self.rest_api_scanner.scan, {}),
            ('xmlrpc', self.xmlrpc_scanner.scan, {}),
            ('domain', self.domain_scanner.scan, {}),
            ('headers', self.header_scanner.scan, {}),
            ('plugins', self.plugin_scanner.scan, {}),
            ('auth', self.auth_scanner.scan, {'aggressive': self.aggressive}),
            ('advanced', self.advanced_scanner.scan, {}),
            ('network', self.network_scanner.scan, {}),
        ]

        # Add aggressive-only scanners
        if self.aggressive:
            scanners.append(('injection', self.injection_scanner.scan, {'aggressive': True}))

        # Execute scanners in parallel
        completed = 0
        total = len(scanners)

        with ThreadPoolExecutor(max_workers=self.scanner_workers) as executor:
            # Submit all scanner tasks
            futures = {
                executor.submit(func, **kwargs): name
                for name, func, kwargs in scanners
            }

            # Process results as they complete
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    self._process_scanner_result(name, result)
                    completed += 1
                    self.log.progress(completed, total, prefix="Scanners")
                except Exception as e:
                    self.log.error(f"Scanner '{name}' failed: {str(e)}")
                    completed += 1

        print()  # New line after progress

        # Calculate score and recommendations
        self.calculate_risk_score()
        self.generate_recommendations()

        return self.results

    def print_report(self):
        """Print summary report to console."""
        self.log.banner("SCAN RESULTS", width=60)

        score = self.results['risk_score']
        grade = self.get_grade()

        # Check for backdoors first
        backdoors = self.results.get('backdoors', {}).get('found', [])
        if backdoors:
            print("\n" + "=" * 60)
            print("  !!!  SITE COMPROMISED - BACKDOORS DETECTED  !!!")
            print("=" * 60)
            for bd in backdoors[:5]:
                print(f"  BACKDOOR: {bd['path']}")
                print(f"           Signatures: {', '.join(bd.get('signatures', [])[:3])}")
            print("=" * 60 + "\n")

        print(f"Security Score: {score}/100 (Grade: {grade})")
        print()

        self.log.section("Vulnerability Summary")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = len(self.results['vulnerabilities'][severity])
            print(f"  {severity.upper():10} {count}")
        print()

        if self.results['exposed_files']:
            self.log.section(f"Exposed Files ({len(self.results['exposed_files'])})")
            for f in self.results['exposed_files'][:5]:
                print(f"  [{f['severity']}] {f['path']}")
            if len(self.results['exposed_files']) > 5:
                print(f"  ... and {len(self.results['exposed_files']) - 5} more")
            print()

        if self.results['plugins']:
            self.log.section(f"Plugins ({len(self.results['plugins'])})")
            for plugin, data in list(self.results['plugins'].items())[:5]:
                version = data.get('version', 'unknown')
                print(f"  {plugin} (v{version})")
            print()

        self.log.section("Recommendations")
        for rec in self.results['recommendations'][:5]:
            priority_icons = {0: 'XXX', 1: '!!!', 2: '!!', 3: '!', 4: '*'}
            icon = priority_icons.get(rec['priority'], '*')
            print(f"  [{icon}] {rec['title']}")

        print()
        self.log.banner(f"Score: {score}/100 ({grade})", char="-", width=60)

    def export_reports(self) -> Dict[str, str]:
        """Export all report formats."""
        reporter = ReportGenerator(self.results, self.output_dir)
        return reporter.generate_all()

    def close(self):
        """Clean up resources."""
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
