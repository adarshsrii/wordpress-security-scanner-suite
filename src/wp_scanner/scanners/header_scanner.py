"""
Security headers scanner.
Checks for missing or misconfigured HTTP security headers.
"""

from typing import Dict, Any

from wp_scanner.scanners.base import BaseScanner
from wp_scanner.payloads import SECURITY_HEADERS


class HeaderScanner(BaseScanner):
    """Scanner for HTTP security headers."""

    @property
    def name(self) -> str:
        return "Header Scanner"

    def scan(self) -> Dict[str, Any]:
        """
        Check for missing security headers.

        Returns:
            Dictionary with header findings
        """
        self.log.scan("Checking security headers...")

        results = {
            'present': {},
            'missing': [],
        }

        response = self.http.get('/')
        if not response:
            return results

        headers = response.headers

        # Check each security header
        for header, config in SECURITY_HEADERS.items():
            if header in headers:
                results['present'][header] = headers[header]
            else:
                results['missing'].append({
                    'header': header,
                    'description': config['description'],
                    'severity': config['severity'],
                    'recommended': config['recommended'],
                })

                self.add_finding(
                    config['severity'],
                    f"Missing Security Header: {header}",
                    config['description'],
                    f"Add {header} header. Recommended values: "
                    f"{', '.join(config['recommended']) or 'varies by implementation'}",
                    evidence='Header not present in response'
                )

        # Log summary
        if results['missing']:
            self.log.warning(f"Missing {len(results['missing'])} security headers")
        else:
            self.log.success("All security headers present")

        results['findings'] = self.get_findings()
        return results
