"""
SQL Injection and XSS vulnerability scanner.
Tests common WordPress injection points with various payloads.
"""

import time
from typing import Dict, Any
from urllib.parse import quote

from wp_scanner.scanners.base import BaseScanner
from wp_scanner.payloads import (
    SQL_PAYLOADS, SQL_INJECTION_POINTS,
    XSS_PAYLOADS, XSS_INJECTION_POINTS,
    LFI_PAYLOADS
)


class InjectionScanner(BaseScanner):
    """Scanner for SQL injection, XSS, and LFI vulnerabilities."""

    @property
    def name(self) -> str:
        return "Injection Scanner"

    def scan_sql_injection(self, max_points: int = 10,
                           max_payloads: int = 5) -> Dict[str, Any]:
        """
        Test for SQL injection vulnerabilities.

        Args:
            max_points: Maximum injection points to test
            max_payloads: Maximum payloads per point

        Returns:
            Dictionary with SQLi findings
        """
        self.log.scan("Testing SQL injection vectors...")

        results = {
            'tested_points': 0,
            'potential_vulns': [],
        }

        sql_errors = [
            'mysql_fetch', 'mysql_query', 'SQL syntax',
            'mysqli_', 'database error', 'ODBC',
            'ORA-', 'PG::Error', 'sqlite3',
            'wp_posts', 'wp_users', 'Warning:'
        ]

        for injection_point in SQL_INJECTION_POINTS[:max_points]:
            for payload in SQL_PAYLOADS[:max_payloads]:
                results['tested_points'] += 1

                encoded_payload = quote(payload)
                test_url = f"{injection_point}{encoded_payload}"

                response = self.http.get(test_url)

                if response:
                    for indicator in sql_errors:
                        if indicator.lower() in response.text.lower():
                            vuln_info = {
                                'url': test_url,
                                'payload': payload,
                                'indicator': indicator
                            }
                            results['potential_vulns'].append(vuln_info)

                            self.add_finding(
                                'CRITICAL',
                                f'Potential SQL Injection at {injection_point}',
                                f'SQL error indicator "{indicator}" found when testing '
                                f'with payload: {payload}',
                                'Investigate SQL injection vulnerability. Use prepared '
                                'statements and parameterized queries.',
                                cvss=9.8,
                                evidence=f'Error indicator: {indicator}'
                            )
                            self.log.critical(f"Potential SQLi at {injection_point}")
                            break

                time.sleep(0.2)

        self.log.info(f"Tested {results['tested_points']} SQL injection points")
        return results

    def scan_xss(self, max_payloads: int = 5) -> Dict[str, Any]:
        """
        Test for Cross-Site Scripting vulnerabilities.

        Args:
            max_payloads: Maximum payloads to test

        Returns:
            Dictionary with XSS findings
        """
        self.log.scan("Testing XSS vectors...")

        results = {
            'tested_points': 0,
            'reflected_xss': [],
        }

        # Test search form (most common XSS vector in WordPress)
        for payload in XSS_PAYLOADS[:max_payloads]:
            results['tested_points'] += 1

            encoded_payload = quote(payload)
            test_url = f"/?s={encoded_payload}"

            response = self.http.get(test_url)

            if response:
                # Check if payload is reflected without encoding
                if payload in response.text:
                    vuln_info = {
                        'url': test_url,
                        'payload': payload,
                        'context': 'search'
                    }
                    results['reflected_xss'].append(vuln_info)

                    self.add_finding(
                        'HIGH',
                        'Reflected XSS in Search Function',
                        'XSS payload reflected in search results without proper encoding',
                        'Implement proper output encoding. Use esc_html(), esc_attr() '
                        'for all user input displayed in HTML.',
                        cvss=6.1,
                        evidence=f'Payload: {payload[:50]}'
                    )
                    self.log.warning("Reflected XSS found in search function")
                    break

            time.sleep(0.2)

        self.log.info(f"Tested {results['tested_points']} XSS payloads")
        return results

    def scan_lfi(self, max_payloads: int = 5) -> Dict[str, Any]:
        """
        Test for Local File Inclusion vulnerabilities.

        Args:
            max_payloads: Maximum payloads to test

        Returns:
            Dictionary with LFI findings
        """
        self.log.scan("Testing LFI/directory traversal vectors...")

        results = {
            'tested_points': 0,
            'potential_vulns': [],
        }

        lfi_indicators = [
            'root:x:0:0',  # /etc/passwd
            'DB_NAME', 'DB_USER', 'DB_PASSWORD',  # wp-config.php
            '[extensions]',  # php.ini
        ]

        test_params = ['file', 'page', 'template', 'include', 'path']

        for param in test_params:
            for payload in LFI_PAYLOADS[:max_payloads]:
                results['tested_points'] += 1

                test_url = f"/?{param}={quote(payload)}"
                response = self.http.get(test_url)

                if response:
                    for indicator in lfi_indicators:
                        if indicator in response.text:
                            vuln_info = {
                                'url': test_url,
                                'payload': payload,
                                'indicator': indicator
                            }
                            results['potential_vulns'].append(vuln_info)

                            self.add_finding(
                                'CRITICAL',
                                f'Local File Inclusion via {param} Parameter',
                                f'LFI vulnerability allows reading local files. '
                                f'Tested payload: {payload}',
                                'Sanitize file path parameters. Never include files '
                                'based on user input. Use whitelist validation.',
                                cvss=9.8,
                                evidence=f'Indicator: {indicator}'
                            )
                            self.log.critical(f"LFI found via {param} parameter")
                            return results

                time.sleep(0.1)

        self.log.info(f"Tested {results['tested_points']} LFI payloads")
        return results

    def scan(self, aggressive: bool = False) -> Dict[str, Any]:
        """
        Run all injection tests.

        Args:
            aggressive: Enable aggressive testing

        Returns:
            Dictionary with all injection findings
        """
        if not aggressive:
            self.log.info("Injection testing requires aggressive mode")
            return {'skipped': True, 'reason': 'Requires aggressive mode'}

        results = {
            'sql_injection': self.scan_sql_injection(),
            'xss': self.scan_xss(),
            'lfi': self.scan_lfi(),
            'findings': self.get_findings(),
        }

        return results
