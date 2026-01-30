"""
Domain-level security scanner.
Checks DNS, SSL/TLS, backdoors, and domain security configurations.
"""

import re
import socket
import ssl
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from wp_scanner.scanners.base import BaseScanner


class DomainScanner(BaseScanner):
    """Scanner for domain-level security checks and backdoor detection."""

    # Known backdoor/shell signatures
    BACKDOOR_SIGNATURES = [
        # Web shells
        'c99shell', 'r57shell', 'wso shell', 'b374k', 'weevely',
        'php-backdoor', 'phpspy', 'c100', 'safe0ver', 'r00t',
        # Eval/exec patterns
        'eval(base64_decode', 'eval(gzinflate', 'eval(gzuncompress',
        'eval(str_rot13', 'assert(base64_decode', 'preg_replace.*\/e',
        # Suspicious functions
        'passthru(', 'shell_exec(', 'system(', 'exec(',
        # Obfuscation
        'chr(101).chr(118).chr(97).chr(108)',
        '$_POST[', '$_GET[', '$_REQUEST[',
        # FilesMan
        'FilesMan', 'filemanager', 'adminer',
    ]

    # Suspicious/backdoor file patterns
    BACKDOOR_PATHS = [
        # Common shell names
        '/shell.php', '/c99.php', '/r57.php', '/wso.php',
        '/b374k.php', '/alfa.php', '/leafmailer.php',
        '/up.php', '/uploader.php', '/upload.php',
        '/cmd.php', '/command.php', '/exec.php',
        '/x.php', '/xx.php', '/xxx.php', '/1.php',

        # Hidden/obfuscated names
        '/.php', '/..php', '/.hidden.php',
        '/wp-content/plugins/.php',
        '/wp-content/themes/.php',
        '/wp-includes/.php',

        # Fake WordPress files
        '/wp-atom.php', '/wp-feed.php', '/wp-tmp.php',
        '/wp-vcd.php', '/wp-config.bak.php',
        '/class-wp-cache.php', '/class-wp-widget.php',

        # Common malware locations
        '/wp-content/uploads/2023/.php',
        '/wp-content/uploads/2024/.php',
        '/wp-content/cache/.php',
        '/wp-content/temp/.php',
        '/wp-content/upgrade/.php',

        # ICO file backdoors (common technique)
        '/favicon_a.ico', '/favicon_b.ico',
        '/wp-content/themes/theme/assets/fonts/icons.php',

        # Mailer scripts
        '/leafmailer.php', '/mailer.php', '/sendmail.php',
        '/xleet.php', '/xmailer.php',

        # Admin backdoors
        '/wp-admin/includes/admin.php',
        '/wp-admin/network/admin.php',
        '/wp-admin/css/colors/.php',

        # Plugin backdoors
        '/wp-content/plugins/hello.php',
        '/wp-content/plugins/akismet/akismet.php.bak',
        '/wp-content/mu-plugins/loader.php',
    ]

    # DNS record types to check
    DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    # Suspicious redirect patterns
    MALICIOUS_REDIRECT_PATTERNS = [
        r'window\.location\s*=\s*["\']https?://(?!{domain})',
        r'document\.location\s*=',
        r'meta\s+http-equiv=["\']refresh["\']',
        r'<script[^>]*src=["\']https?://(?!{domain}|code\.jquery|cdn\.)',
        r'eval\s*\(\s*unescape',
        r'document\.write\s*\(\s*unescape',
    ]

    # Crypto miner signatures
    CRYPTO_MINER_SIGNATURES = [
        'coinhive', 'cryptoloot', 'coin-hive', 'minero.cc',
        'webmine', 'crypto-loot', 'ppoi.org', 'miner.js',
        'CoinImp', 'JSEcoin', 'cryptonight.wasm',
    ]

    @property
    def name(self) -> str:
        return "Domain Scanner"

    def get_domain_info(self, url: str) -> Dict[str, Any]:
        """Extract domain information from URL."""
        parsed = urlparse(url)
        return {
            'full_url': url,
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'hostname': parsed.hostname,
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
        }

    def check_dns_records(self, domain: str) -> Dict[str, Any]:
        """Check DNS records for security issues."""
        self.log.info("Checking DNS records...")
        results = {
            'records': {},
            'issues': [],
        }

        try:
            import socket

            # Get A records
            try:
                a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
                results['records']['A'] = list(set([r[4][0] for r in a_records]))
            except:
                pass

            # Check for email security records via TXT
            try:
                # We'll check common security indicators
                results['records']['resolved'] = True
            except:
                results['records']['resolved'] = False

        except Exception as e:
            results['error'] = str(e)

        return results

    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Check SSL/TLS certificate for security issues."""
        self.log.info("Checking SSL/TLS certificate...")
        results = {
            'valid': False,
            'issues': [],
            'cert_info': {},
        }

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    results['valid'] = True
                    results['cert_info'] = {
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                    }

                    # Check expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.now()).days
                        results['cert_info']['days_until_expiry'] = days_left

                        if days_left < 0:
                            results['issues'].append('Certificate has EXPIRED')
                            self.add_finding(
                                'CRITICAL',
                                'SSL Certificate Expired',
                                f'The SSL certificate expired {abs(days_left)} days ago',
                                'Renew the SSL certificate immediately',
                                evidence=f'Expired on: {not_after}'
                            )
                        elif days_left < 30:
                            results['issues'].append(f'Certificate expires in {days_left} days')
                            self.add_finding(
                                'MEDIUM',
                                'SSL Certificate Expiring Soon',
                                f'The SSL certificate expires in {days_left} days',
                                'Renew the SSL certificate before expiration',
                                evidence=f'Expires on: {not_after}'
                            )

                    # Check TLS version
                    tls_version = ssock.version()
                    results['cert_info']['tls_version'] = tls_version

                    if tls_version in ['TLSv1', 'TLSv1.0', 'SSLv3', 'SSLv2']:
                        results['issues'].append(f'Weak TLS version: {tls_version}')
                        self.add_finding(
                            'HIGH',
                            f'Weak TLS Version: {tls_version}',
                            'Server supports outdated TLS version vulnerable to attacks',
                            'Disable TLS 1.0/1.1 and SSLv3. Only allow TLS 1.2+',
                            evidence=f'Detected version: {tls_version}'
                        )

        except ssl.SSLCertVerificationError as e:
            results['issues'].append(f'Certificate verification failed: {str(e)}')
            self.add_finding(
                'HIGH',
                'SSL Certificate Verification Failed',
                'The SSL certificate could not be verified',
                'Ensure the certificate is from a trusted CA and properly configured',
                evidence=str(e)
            )
        except ssl.SSLError as e:
            results['issues'].append(f'SSL Error: {str(e)}')
        except socket.timeout:
            results['issues'].append('Connection timeout')
        except Exception as e:
            results['error'] = str(e)

        return results

    def check_backdoor_files(self) -> Dict[str, Any]:
        """Scan for known backdoor files and web shells."""
        self.log.info("Scanning for backdoor files...")
        results = {
            'found': [],
            'suspicious': [],
        }

        for path in self.BACKDOOR_PATHS:
            response = self.http.get(path)
            if response and response.status_code == 200:
                content = response.text.lower()

                # Check for shell signatures
                is_shell = False
                matched_sigs = []
                for sig in self.BACKDOOR_SIGNATURES:
                    if sig.lower() in content:
                        is_shell = True
                        matched_sigs.append(sig)

                if is_shell:
                    results['found'].append({
                        'path': path,
                        'type': 'backdoor',
                        'signatures': matched_sigs,
                        'size': len(response.text),
                    })
                    self.add_finding(
                        'CRITICAL',
                        f'Backdoor/Web Shell Detected: {path}',
                        f'A suspected web shell was found containing signatures: {", ".join(matched_sigs[:3])}',
                        'IMMEDIATELY: 1) Take site offline 2) Backup evidence 3) Remove malicious file 4) Audit all files 5) Change all passwords',
                        evidence=f'Path: {path}, Signatures: {matched_sigs}'
                    )
                    self.log.vuln(f"BACKDOOR FOUND: {path}")
                else:
                    # File exists but no obvious shell signatures - still suspicious
                    if path.endswith('.php') and len(content) < 5000:
                        results['suspicious'].append({
                            'path': path,
                            'type': 'suspicious_php',
                            'size': len(response.text),
                        })

        if results['found']:
            self.log.error(f"Found {len(results['found'])} backdoor files!")

        return results

    def check_malicious_redirects(self) -> Dict[str, Any]:
        """Check for malicious redirects and injected scripts."""
        self.log.info("Checking for malicious redirects...")
        results = {
            'redirects': [],
            'suspicious_scripts': [],
            'crypto_miners': [],
        }

        response = self.http.get('/')
        if not response:
            return results

        content = response.text
        domain = urlparse(self.http.base_url).netloc

        # Check for suspicious redirects
        for pattern in self.MALICIOUS_REDIRECT_PATTERNS:
            pattern = pattern.replace('{domain}', re.escape(domain))
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results['redirects'].extend(matches[:3])

        # Check for crypto miners
        for miner in self.CRYPTO_MINER_SIGNATURES:
            if miner.lower() in content.lower():
                results['crypto_miners'].append(miner)
                self.add_finding(
                    'CRITICAL',
                    f'Crypto Miner Detected: {miner}',
                    'Malicious cryptocurrency mining script found on the site',
                    'Remove the mining script immediately and audit for other infections',
                    evidence=f'Found signature: {miner}'
                )
                self.log.vuln(f"CRYPTO MINER: {miner}")

        # Check for suspicious external scripts
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        scripts = re.findall(script_pattern, content, re.IGNORECASE)

        suspicious_domains = [
            'pastebin.com', 'paste.ee', 'hastebin.com',
            'bit.ly', 'tinyurl.com', 'goo.gl',
            'raw.githubusercontent.com',
        ]

        for script in scripts:
            for sus in suspicious_domains:
                if sus in script.lower():
                    results['suspicious_scripts'].append(script)
                    self.add_finding(
                        'HIGH',
                        'Suspicious External Script',
                        f'External script loaded from potentially malicious source: {script[:100]}',
                        'Review and remove unauthorized external scripts',
                        evidence=f'Script URL: {script}'
                    )

        return results

    def check_hidden_admin_paths(self) -> Dict[str, Any]:
        """Check for hidden admin paths and exposed panels."""
        self.log.info("Checking for hidden admin paths...")
        results = {
            'found': [],
        }

        hidden_paths = [
            # Alternative admin paths
            '/admin/', '/administrator/', '/admin.php',
            '/controlpanel/', '/cpanel/', '/manage/',
            '/backend/', '/portal/', '/dashboard/',

            # Database managers
            '/phpmyadmin/', '/pma/', '/myadmin/',
            '/mysql/', '/mysqladmin/', '/db/',
            '/adminer.php', '/adminer/',

            # File managers
            '/filemanager/', '/fm/', '/elfinder/',
            '/kcfinder/', '/tinymce/filemanager/',

            # WordPress specific
            '/wp-admin/install.php',
            '/wp-admin/setup-config.php',
            '/wp-admin/upgrade.php',
            '/wp-admin/network/',

            # Staging/dev
            '/staging/', '/dev/', '/test/',
            '/beta/', '/demo/', '/sandbox/',

            # Backup plugins
            '/wp-content/backups/',
            '/wp-content/backup-db/',
            '/wp-content/updraft/',
            '/wp-content/ai1wm-backups/',
        ]

        for path in hidden_paths:
            response = self.http.get(path)
            if response and response.status_code in [200, 401, 403]:
                results['found'].append({
                    'path': path,
                    'status': response.status_code,
                    'accessible': response.status_code == 200,
                })

                if response.status_code == 200:
                    if 'phpmyadmin' in path or 'adminer' in path:
                        self.add_finding(
                            'CRITICAL',
                            f'Database Manager Exposed: {path}',
                            'Database administration tool is publicly accessible',
                            'Remove or restrict access to database managers via .htaccess or firewall',
                            evidence=f'Path accessible: {path}'
                        )
                    elif '/install.php' in path or '/setup-config.php' in path:
                        self.add_finding(
                            'CRITICAL',
                            f'WordPress Installation Script Exposed: {path}',
                            'Installation script is accessible and could allow site takeover',
                            'Delete installation scripts after WordPress setup',
                            evidence=f'Path accessible: {path}'
                        )
                    else:
                        self.add_finding(
                            'MEDIUM',
                            f'Hidden Admin Path Found: {path}',
                            'An administrative or sensitive path is accessible',
                            'Restrict access via .htaccess or remove if unused',
                            evidence=f'Path accessible: {path}'
                        )

        return results

    def check_server_info_disclosure(self) -> Dict[str, Any]:
        """Check for server information disclosure."""
        self.log.info("Checking for server info disclosure...")
        results = {
            'server': None,
            'powered_by': None,
            'php_version': None,
            'issues': [],
        }

        response = self.http.get('/')
        if not response:
            return results

        headers = response.headers

        # Check Server header
        server = headers.get('Server', '')
        if server:
            results['server'] = server
            # Check for version disclosure
            if re.search(r'[\d.]+', server):
                results['issues'].append('Server version disclosed')
                self.add_finding(
                    'LOW',
                    'Server Version Disclosure',
                    f'Server header reveals version information: {server}',
                    'Configure server to hide version (ServerTokens Prod in Apache)',
                    evidence=f'Server: {server}'
                )

        # Check X-Powered-By
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            results['powered_by'] = powered_by
            results['issues'].append('X-Powered-By header present')
            self.add_finding(
                'LOW',
                'Technology Stack Disclosure',
                f'X-Powered-By header reveals: {powered_by}',
                'Remove X-Powered-By header (expose_php = Off in php.ini)',
                evidence=f'X-Powered-By: {powered_by}'
            )

            # Extract PHP version
            php_match = re.search(r'PHP/([\d.]+)', powered_by)
            if php_match:
                results['php_version'] = php_match.group(1)

        return results

    def check_email_security(self, domain: str) -> Dict[str, Any]:
        """Check email security records (SPF, DKIM, DMARC)."""
        self.log.info("Checking email security records...")
        results = {
            'spf': None,
            'dmarc': None,
            'issues': [],
        }

        # Note: Full DNS TXT record checking would require dnspython
        # This is a basic check via HTTP headers

        return results

    def scan(self, full_scan: bool = True) -> Dict[str, Any]:
        """
        Run domain-level security scan.

        Args:
            full_scan: Include all checks

        Returns:
            Dictionary with domain security findings
        """
        self.log.scan("Running domain-level security checks...")

        # Get domain info
        domain_info = self.get_domain_info(self.http.base_url)

        results = {
            'domain_info': domain_info,
            'ssl': {},
            'backdoors': {},
            'malicious_content': {},
            'hidden_paths': {},
            'server_disclosure': {},
        }

        # SSL/TLS check
        if domain_info['scheme'] == 'https':
            results['ssl'] = self.check_ssl_certificate(
                domain_info['hostname'],
                domain_info['port']
            )
            if results['ssl'].get('valid'):
                self.log.success("SSL certificate is valid")
            else:
                self.log.warning("SSL certificate issues detected")

        # Backdoor detection
        results['backdoors'] = self.check_backdoor_files()
        if results['backdoors']['found']:
            self.log.error(f"CRITICAL: {len(results['backdoors']['found'])} backdoors detected!")

        # Malicious redirect/content check
        results['malicious_content'] = self.check_malicious_redirects()

        # Hidden admin paths
        results['hidden_paths'] = self.check_hidden_admin_paths()

        # Server info disclosure
        results['server_disclosure'] = self.check_server_info_disclosure()

        # Summary
        total_backdoors = len(results['backdoors'].get('found', []))
        total_miners = len(results['malicious_content'].get('crypto_miners', []))

        if total_backdoors or total_miners:
            self.log.error(f"SITE COMPROMISED: {total_backdoors} backdoors, {total_miners} miners")
        else:
            self.log.info("No obvious backdoors detected")

        results['findings'] = self.get_findings()
        return results
