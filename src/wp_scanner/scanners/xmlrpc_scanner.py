"""
XML-RPC vulnerability scanner.
Tests for brute force amplification, SSRF, and DDoS vectors.
"""

import re
from typing import Dict, Any

from wp_scanner.scanners.base import BaseScanner
from wp_scanner.payloads import XMLRPC_LIST_METHODS


class XMLRPCScanner(BaseScanner):
    """Scanner for XML-RPC vulnerabilities."""

    @property
    def name(self) -> str:
        return "XML-RPC Scanner"

    def scan(self) -> Dict[str, Any]:
        """
        Test XML-RPC endpoint for vulnerabilities.

        Returns:
            Dictionary with XML-RPC findings
        """
        self.log.scan("Testing XML-RPC vulnerabilities...")

        results = {
            'accessible': False,
            'methods_available': [],
            'multicall_enabled': False,
            'pingback_enabled': False,
            'brute_force_possible': False,
        }

        # Check if XML-RPC is accessible
        response = self.http.get('/xmlrpc.php')
        if not response or response.status_code != 200:
            self.log.success("XML-RPC not accessible or disabled")
            return results

        results['accessible'] = True

        # List available methods
        methods_response = self.http.post(
            '/xmlrpc.php',
            data=XMLRPC_LIST_METHODS,
            headers={'Content-Type': 'application/xml'}
        )

        if methods_response and methods_response.status_code == 200:
            methods_text = methods_response.text

            # Extract methods
            method_matches = re.findall(r'<string>([^<]+)</string>', methods_text)
            results['methods_available'] = method_matches

            # Check for critical methods
            if 'system.multicall' in methods_text:
                results['multicall_enabled'] = True
                self.add_finding(
                    'CRITICAL',
                    'XML-RPC system.multicall Enabled - Brute Force Amplification',
                    'system.multicall allows testing thousands of passwords in a '
                    'single HTTP request, enabling efficient brute force attacks. '
                    f'Total methods available: {len(method_matches)}',
                    'Disable XML-RPC completely:\n'
                    '1. Add to .htaccess:\n'
                    '<Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n</Files>\n\n'
                    '2. Or add to wp-config.php:\n'
                    "add_filter('xmlrpc_enabled', '__return_false');",
                    cvss=9.8,
                    evidence=f"Methods: {', '.join(method_matches[:10])}"
                )
                self.log.critical("XML-RPC multicall enabled - CRITICAL RISK")

            if 'pingback.ping' in methods_text:
                results['pingback_enabled'] = True
                self.add_finding(
                    'HIGH',
                    'XML-RPC Pingback Enabled - SSRF/DDoS Vector',
                    'pingback.ping can be abused for Server-Side Request Forgery '
                    '(SSRF) attacks, DDoS amplification, and internal port scanning',
                    'Disable pingback functionality or block XML-RPC entirely',
                    cvss=7.5
                )
                self.log.warning("XML-RPC pingback enabled - DDoS/SSRF risk")

            if 'wp.getUsersBlogs' in methods_text:
                results['brute_force_possible'] = True
                self.add_finding(
                    'HIGH',
                    'XML-RPC Authentication Methods Available',
                    'wp.getUsersBlogs can be used for credential verification, '
                    'enabling brute force attacks via XML-RPC',
                    'Disable XML-RPC or implement authentication rate limiting',
                    cvss=7.0
                )

        results['findings'] = self.get_findings()
        return results
