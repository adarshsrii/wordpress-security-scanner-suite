"""
Advanced security scanner for sophisticated vulnerability checks.
Tests for CORS, open redirects, TimThumb, RevSlider, debug mode, etc.
"""

import re
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse

from wp_scanner.scanners.base import BaseScanner


class AdvancedScanner(BaseScanner):
    """Advanced security checks for sophisticated attacks."""

    # Common open redirect parameters
    REDIRECT_PARAMS = [
        'redirect_to', 'redirect', 'return', 'returnTo', 'return_to',
        'next', 'url', 'goto', 'dest', 'destination', 'rurl',
        '_wp_http_referer', 'ref', 'continue',
    ]

    # TimThumb vulnerable paths
    TIMTHUMB_PATHS = [
        '/wp-content/themes/{theme}/timthumb.php',
        '/wp-content/themes/{theme}/lib/timthumb.php',
        '/wp-content/themes/{theme}/inc/timthumb.php',
        '/wp-content/themes/{theme}/includes/timthumb.php',
        '/wp-content/themes/{theme}/scripts/timthumb.php',
        '/wp-content/plugins/{plugin}/timthumb.php',
        '/wp-content/plugins/{plugin}/lib/timthumb.php',
        '/wp-content/plugins/{plugin}/includes/timthumb.php',
        '/timthumb.php',
        '/thumb.php',
        '/wp-content/timthumb.php',
    ]

    # Common theme names to check for TimThumb
    COMMON_THEMES = [
        'flavor', 'flavor-developer', 'flavor-developer-flavor',
        'flavor-developer-flavor-developer', 'flavor-developer-flavor-developer-flavor',
        'flavor-developer-flavor-developer-flavor-developer',
    ]

    @property
    def name(self) -> str:
        return "Advanced Scanner"

    def scan(self, **kwargs) -> Dict[str, Any]:
        """
        Run advanced security checks.

        Returns:
            Dictionary with scan results
        """
        self.log.scan("Running advanced security checks...")
        self.clear_findings()

        results = {
            'cors': self.check_cors_policy(),
            'open_redirect': self.check_open_redirect(),
            'clickjacking': self.check_clickjacking(),
            'debug_mode': self.check_debug_mode(),
            'timthumb': self.check_timthumb(),
            'revslider': self.check_revslider(),
            'database_prefix': self.check_database_prefix(),
            'api_rate_limiting': self.check_api_rate_limiting(),
            'ssrf_pingback': self.check_ssrf_pingback(),
            'findings': []
        }

        results['findings'] = self.get_findings()
        return results

    def check_cors_policy(self) -> Dict[str, Any]:
        """Test for CORS misconfigurations."""
        self.log.scan("Checking CORS policy...")

        result = {
            'vulnerable': False,
            'issues': [],
            'details': {}
        }

        # Test endpoints
        endpoints = ['/', '/wp-json/', '/wp-json/wp/v2/posts']

        # Test with evil origin
        evil_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
        ]

        for endpoint in endpoints:
            for origin in evil_origins:
                try:
                    response = self.http.get(
                        endpoint,
                        headers={'Origin': origin}
                    )
                    if not response:
                        continue

                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')

                    # Check for wildcard CORS
                    if acao == '*':
                        result['vulnerable'] = True
                        result['issues'].append({
                            'endpoint': endpoint,
                            'issue': 'Wildcard CORS (Access-Control-Allow-Origin: *)',
                            'severity': 'HIGH'
                        })
                        self.add_finding(
                            'HIGH',
                            'CORS Misconfiguration - Wildcard Origin',
                            f'Endpoint {endpoint} allows any origin via Access-Control-Allow-Origin: *',
                            'Configure CORS to allow only trusted origins instead of wildcard',
                            evidence=f'Origin: {origin} -> ACAO: {acao}'
                        )

                    # Check if our evil origin is reflected
                    elif acao == origin and origin != 'null':
                        result['vulnerable'] = True
                        severity = 'CRITICAL' if acac.lower() == 'true' else 'HIGH'
                        result['issues'].append({
                            'endpoint': endpoint,
                            'issue': f'Origin reflection: {origin}',
                            'credentials': acac.lower() == 'true',
                            'severity': severity
                        })
                        msg = f'with credentials' if acac.lower() == 'true' else ''
                        self.add_finding(
                            severity,
                            f'CORS Misconfiguration - Origin Reflection {msg}',
                            f'Endpoint {endpoint} reflects arbitrary origins',
                            'Implement a whitelist of allowed origins',
                            evidence=f'Origin: {origin} -> ACAO: {acao}, ACAC: {acac}'
                        )

                    # Check for null origin
                    elif acao == 'null':
                        result['vulnerable'] = True
                        result['issues'].append({
                            'endpoint': endpoint,
                            'issue': 'Null origin allowed',
                            'severity': 'MEDIUM'
                        })
                        self.add_finding(
                            'MEDIUM',
                            'CORS Allows Null Origin',
                            f'Endpoint {endpoint} accepts null origin which can be exploited via sandboxed iframes',
                            'Do not allow null origin in CORS policy',
                            evidence=f'ACAO: null'
                        )

                except Exception:
                    continue

        if not result['vulnerable']:
            self.log.success("CORS policy appears secure")
        else:
            self.log.warning(f"Found {len(result['issues'])} CORS issues")

        return result

    def check_open_redirect(self) -> Dict[str, Any]:
        """Test URL parameters for open redirects."""
        self.log.scan("Checking for open redirects...")

        result = {
            'vulnerable': False,
            'endpoints': []
        }

        # Test payloads
        payloads = [
            'https://evil.com',
            '//evil.com',
            'https:evil.com',
            '/\\evil.com',
            '////evil.com',
        ]

        # Test wp-login.php with redirect_to
        test_paths = [
            '/wp-login.php',
            '/',
        ]

        for path in test_paths:
            for param in self.REDIRECT_PARAMS[:5]:  # Test first 5 common params
                for payload in payloads[:2]:  # Test first 2 payloads
                    try:
                        url = f"{path}?{param}={payload}"
                        response = self.http.get(url, allow_redirects=False)

                        if not response:
                            continue

                        # Check for redirect to our payload
                        location = response.headers.get('Location', '')
                        if response.status_code in [301, 302, 303, 307, 308]:
                            if 'evil.com' in location:
                                result['vulnerable'] = True
                                result['endpoints'].append({
                                    'path': path,
                                    'parameter': param,
                                    'payload': payload,
                                    'redirect_location': location
                                })
                                self.add_finding(
                                    'MEDIUM',
                                    'Open Redirect Vulnerability',
                                    f'Parameter {param} on {path} allows redirect to external domains',
                                    'Validate redirect URLs against a whitelist of allowed domains',
                                    evidence=f'{param}={payload} -> Location: {location}'
                                )
                                break  # Found one, move to next path
                    except Exception:
                        continue

        if result['vulnerable']:
            self.log.warning(f"Found {len(result['endpoints'])} open redirect(s)")
        else:
            self.log.success("No open redirects found")

        return result

    def check_clickjacking(self) -> Dict[str, Any]:
        """Check for clickjacking protection."""
        self.log.scan("Checking clickjacking protection...")

        result = {
            'protected': False,
            'x_frame_options': None,
            'csp_frame_ancestors': None
        }

        response = self.http.get('/')
        if not response:
            return result

        headers = response.headers

        # Check X-Frame-Options
        xfo = headers.get('X-Frame-Options', '').upper()
        if xfo:
            result['x_frame_options'] = xfo
            if xfo in ['DENY', 'SAMEORIGIN']:
                result['protected'] = True

        # Check CSP frame-ancestors
        csp = headers.get('Content-Security-Policy', '')
        if 'frame-ancestors' in csp:
            result['csp_frame_ancestors'] = csp
            result['protected'] = True

        if not result['protected']:
            self.add_finding(
                'MEDIUM',
                'Missing Clickjacking Protection',
                'Site does not have X-Frame-Options or CSP frame-ancestors headers',
                'Add X-Frame-Options: DENY or SAMEORIGIN header, or use CSP frame-ancestors directive',
                evidence='No X-Frame-Options or CSP frame-ancestors header found'
            )
            self.log.warning("Missing clickjacking protection")
        else:
            self.log.success("Clickjacking protection in place")

        return result

    def check_debug_mode(self) -> Dict[str, Any]:
        """Detect if WordPress debug mode is enabled."""
        self.log.scan("Checking for debug mode indicators...")

        result = {
            'debug_detected': False,
            'indicators': []
        }

        # Debug patterns to look for in responses
        debug_patterns = [
            (r'<b>Warning</b>:', 'PHP Warning exposed'),
            (r'<b>Notice</b>:', 'PHP Notice exposed'),
            (r'<b>Fatal error</b>:', 'PHP Fatal Error exposed'),
            (r'<b>Parse error</b>:', 'PHP Parse Error exposed'),
            (r'<b>Deprecated</b>:', 'PHP Deprecated notice exposed'),
            (r'Stack trace:', 'Stack trace exposed'),
            (r'WP_DEBUG', 'WP_DEBUG reference found'),
            (r'SCRIPT_DEBUG', 'SCRIPT_DEBUG reference found'),
            (r'display_errors', 'display_errors reference found'),
            (r'xdebug', 'Xdebug detected'),
            (r'<pre class="xdebug', 'Xdebug output found'),
            (r'Call Stack', 'Call stack exposed'),
            (r'on line \d+', 'Line number exposed in error'),
        ]

        # Test multiple pages
        test_pages = [
            '/',
            '/wp-login.php',
            '/wp-admin/',
            '/?debug=1',
            '/?s=' + 'A' * 1000,  # Long search query might trigger errors
            '/wp-content/',
            '/wp-includes/',
        ]

        for page in test_pages:
            try:
                response = self.http.get(page)
                if not response:
                    continue

                content = response.text

                for pattern, desc in debug_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result['debug_detected'] = True
                        indicator = {
                            'page': page,
                            'indicator': desc,
                            'pattern': pattern
                        }
                        if indicator not in result['indicators']:
                            result['indicators'].append(indicator)

            except Exception:
                continue

        if result['debug_detected']:
            self.add_finding(
                'HIGH',
                'Debug Mode / Error Display Enabled',
                f'Found {len(result["indicators"])} debug indicators that may expose sensitive information',
                'Disable WP_DEBUG and display_errors in production. Set WP_DEBUG to false in wp-config.php',
                evidence='; '.join([i['indicator'] for i in result['indicators'][:3]])
            )
            self.log.warning(f"Found {len(result['indicators'])} debug indicators")
        else:
            self.log.success("No debug mode indicators found")

        return result

    def check_timthumb(self) -> Dict[str, Any]:
        """Check for vulnerable TimThumb installations."""
        self.log.scan("Checking for TimThumb vulnerabilities...")

        result = {
            'found': False,
            'paths': []
        }

        # Get themes/plugins from homepage to check
        response = self.http.get('/')
        if not response:
            return result

        # Extract theme names from response
        themes = set()
        theme_matches = re.findall(r'/wp-content/themes/([^/]+)/', response.text)
        themes.update(theme_matches)

        # Extract plugin names
        plugins = set()
        plugin_matches = re.findall(r'/wp-content/plugins/([^/]+)/', response.text)
        plugins.update(plugin_matches)

        # Build paths to check
        paths_to_check = []

        for theme in themes:
            for path_template in self.TIMTHUMB_PATHS:
                if '{theme}' in path_template:
                    paths_to_check.append(path_template.replace('{theme}', theme))

        for plugin in plugins:
            for path_template in self.TIMTHUMB_PATHS:
                if '{plugin}' in path_template:
                    paths_to_check.append(path_template.replace('{plugin}', plugin))

        # Add generic paths
        paths_to_check.extend([
            '/timthumb.php',
            '/thumb.php',
            '/wp-content/timthumb.php',
        ])

        # Check paths
        for path in set(paths_to_check):
            try:
                response = self.http.get(path)
                if response and response.status_code == 200:
                    # Check if it's actually TimThumb
                    if 'timthumb' in response.text.lower() or 'no image' in response.text.lower():
                        result['found'] = True
                        result['paths'].append(path)
            except Exception:
                continue

        if result['found']:
            self.add_finding(
                'CRITICAL',
                'TimThumb Installation Detected',
                f'Found TimThumb at: {", ".join(result["paths"][:3])}. '
                'TimThumb has known RCE vulnerabilities (CVE-2011-4106, CVE-2014-4663)',
                'Remove TimThumb entirely or update to version 2.8.14+ and restrict WebShot feature',
                cve='CVE-2014-4663',
                cvss=9.8,
                evidence=f'Found at: {result["paths"][0]}'
            )
            self.log.error(f"TimThumb found at {len(result['paths'])} location(s)!")
        else:
            self.log.success("No TimThumb installations found")

        return result

    def check_revslider(self) -> Dict[str, Any]:
        """Check for RevSlider vulnerabilities."""
        self.log.scan("Checking for RevSlider vulnerabilities...")

        result = {
            'found': False,
            'vulnerable': False,
            'version': None,
            'paths': []
        }

        # RevSlider vulnerability paths (CVE-2014-9734, CVE-2014-9735)
        vuln_paths = [
            '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',
            '/wp-admin/admin-ajax.php?action=revslider_ajax_action&client_action=update_plugin',
        ]

        # Check if RevSlider exists
        revslider_paths = [
            '/wp-content/plugins/revslider/',
            '/wp-content/plugins/revslider/css/',
            '/wp-content/plugins/revslider/js/',
        ]

        for path in revslider_paths:
            response = self.http.get(path)
            if response and response.status_code in [200, 403]:
                result['found'] = True
                result['paths'].append(path)
                break

        if result['found']:
            # Check for vulnerable action
            response = self.http.get(vuln_paths[0])
            if response:
                # If we get wp-config content, it's vulnerable
                if 'DB_NAME' in response.text or 'DB_PASSWORD' in response.text:
                    result['vulnerable'] = True
                    self.add_finding(
                        'CRITICAL',
                        'RevSlider Arbitrary File Disclosure',
                        'RevSlider plugin is vulnerable to arbitrary file disclosure (CVE-2014-9734)',
                        'Update RevSlider to version 4.2+ immediately',
                        cve='CVE-2014-9734',
                        cvss=9.8,
                        evidence='wp-config.php contents accessible via admin-ajax.php'
                    )
                    self.log.error("RevSlider CVE-2014-9734 VULNERABLE!")
                elif response.status_code == 200:
                    # Plugin exists but may be patched
                    self.add_finding(
                        'MEDIUM',
                        'RevSlider Plugin Detected',
                        'RevSlider plugin found. Historical vulnerabilities exist.',
                        'Ensure RevSlider is updated to the latest version',
                        evidence=f'Found at: {result["paths"][0]}'
                    )
                    self.log.warning("RevSlider detected - verify version is current")
        else:
            self.log.success("RevSlider not found")

        return result

    def check_database_prefix(self) -> Dict[str, Any]:
        """Check for default database prefix."""
        self.log.scan("Checking database prefix...")

        result = {
            'default_prefix': False,
            'indicators': []
        }

        # Patterns that might reveal table prefix
        prefix_patterns = [
            r'wp_users',
            r'wp_posts',
            r'wp_options',
            r'wp_postmeta',
            r'wp_usermeta',
            r'wp_comments',
            r'wp_terms',
        ]

        # Check error pages and debug output
        test_urls = [
            '/',
            '/wp-login.php',
            "/?s=' OR 1=1--",  # Might trigger SQL error with table names
        ]

        for url in test_urls:
            try:
                response = self.http.get(url)
                if not response:
                    continue

                for pattern in prefix_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        result['default_prefix'] = True
                        result['indicators'].append(pattern)
                        break

                if result['default_prefix']:
                    break
            except Exception:
                continue

        if result['default_prefix']:
            self.add_finding(
                'LOW',
                'Default Database Table Prefix',
                'Site appears to use the default wp_ database table prefix',
                'Consider using a custom table prefix for security through obscurity',
                evidence=f'Found reference to: {result["indicators"][0] if result["indicators"] else "wp_*"}'
            )
            self.log.info("Default database prefix (wp_) detected")
        else:
            self.log.success("Custom or hidden database prefix")

        return result

    def check_api_rate_limiting(self) -> Dict[str, Any]:
        """Check if APIs have rate limiting."""
        self.log.scan("Checking API rate limiting...")

        result = {
            'rate_limited': False,
            'endpoints_tested': [],
            'vulnerable_endpoints': []
        }

        # Test endpoints
        endpoints = [
            '/wp-login.php',
            '/wp-json/wp/v2/users',
            '/xmlrpc.php',
        ]

        for endpoint in endpoints:
            try:
                # Make several rapid requests
                blocked = False
                for i in range(5):
                    response = self.http.get(endpoint)
                    if response and response.status_code == 429:
                        blocked = True
                        break

                result['endpoints_tested'].append(endpoint)

                if not blocked:
                    result['vulnerable_endpoints'].append(endpoint)
            except Exception:
                continue

        if result['vulnerable_endpoints']:
            if '/wp-login.php' in result['vulnerable_endpoints']:
                self.add_finding(
                    'MEDIUM',
                    'No Rate Limiting on Login',
                    'wp-login.php does not appear to have rate limiting, enabling brute force attacks',
                    'Implement rate limiting via plugin (Limit Login Attempts) or WAF',
                    evidence='5 rapid requests to wp-login.php were not blocked'
                )
            self.log.warning(f"No rate limiting on {len(result['vulnerable_endpoints'])} endpoint(s)")
        else:
            result['rate_limited'] = True
            self.log.success("Rate limiting appears to be in place")

        return result

    def check_ssrf_pingback(self) -> Dict[str, Any]:
        """Test XML-RPC for SSRF via pingback."""
        self.log.scan("Checking for SSRF via pingback...")

        result = {
            'xmlrpc_enabled': False,
            'pingback_enabled': False,
            'ssrf_potential': False
        }

        # Check if xmlrpc.php exists
        response = self.http.get('/xmlrpc.php')
        if not response or response.status_code != 200:
            self.log.info("XML-RPC not accessible")
            return result

        result['xmlrpc_enabled'] = True

        # Check if pingback.ping method is available
        list_methods_payload = '''<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'''

        response = self.http.post(
            '/xmlrpc.php',
            data=list_methods_payload,
            headers={'Content-Type': 'text/xml'}
        )

        if response and 'pingback.ping' in response.text:
            result['pingback_enabled'] = True
            result['ssrf_potential'] = True

            self.add_finding(
                'HIGH',
                'SSRF via XML-RPC Pingback',
                'pingback.ping is enabled and can be abused for SSRF attacks to scan internal networks',
                'Disable XML-RPC pingback via plugin or add rule to block pingback.ping method',
                evidence='pingback.ping method available in system.listMethods'
            )
            self.log.warning("Pingback enabled - potential SSRF vector")
        else:
            self.log.success("Pingback not available or disabled")

        return result
