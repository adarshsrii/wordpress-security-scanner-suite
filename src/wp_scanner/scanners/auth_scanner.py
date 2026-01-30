"""
Authentication and user enumeration scanner.
Tests login security and user discovery methods.
"""

import re
import time
from typing import Dict, Any, List

from wp_scanner.scanners.base import BaseScanner


class AuthScanner(BaseScanner):
    """Scanner for authentication vulnerabilities and user enumeration."""

    @property
    def name(self) -> str:
        return "Authentication Scanner"

    def enumerate_users_author(self, max_ids: int = 20) -> List[Dict[str, Any]]:
        """Enumerate users via author archives."""
        users = []

        for user_id in range(1, max_ids + 1):
            response = self.http.get(f'/?author={user_id}', allow_redirects=True)

            if response and response.status_code == 200:
                username_match = re.search(r'/author/([^/]+)', response.url)
                if username_match:
                    users.append({
                        'id': user_id,
                        'username': username_match.group(1),
                        'method': 'author_archive',
                        'url': response.url
                    })

            time.sleep(0.1)

        return users

    def enumerate_users_oembed(self) -> List[Dict[str, Any]]:
        """Enumerate users via oEmbed endpoint."""
        users = []

        from urllib.parse import quote
        base_url = self.http.base_url
        oembed_url = f'/wp-json/oembed/1.0/embed?url={quote(base_url)}'

        response = self.http.get_json(oembed_url)

        if response and 'author_name' in response:
            users.append({
                'name': response.get('author_name'),
                'method': 'oembed'
            })

        return users

    def check_login_security(self, test_username: str = None) -> Dict[str, Any]:
        """Check login page security measures."""
        results = {
            'login_accessible': False,
            'rate_limiting': False,
            'username_disclosure': False,
            'default_url': True,
        }

        # Check if login page exists
        response = self.http.get('/wp-login.php')
        if not response or response.status_code != 200:
            return results

        results['login_accessible'] = True

        self.add_finding(
            'LOW',
            'Default Login URL Active',
            'WordPress login page is accessible at /wp-login.php',
            'Consider using a security plugin to change the login URL',
            evidence='wp-login.php accessible'
        )

        # Test rate limiting (3 attempts)
        blocked = False
        for _ in range(3):
            test_response = self.http.post(
                '/wp-login.php',
                data={
                    'log': 'nonexistent_test_user_12345',
                    'pwd': 'wrong_password_test',
                    'wp-submit': 'Log In'
                },
                allow_redirects=False
            )

            if test_response:
                if test_response.status_code == 429 or \
                   'too many' in test_response.text.lower() or \
                   'blocked' in test_response.text.lower():
                    blocked = True
                    break

            time.sleep(0.5)

        results['rate_limiting'] = blocked

        if not blocked:
            self.add_finding(
                'MEDIUM',
                'No Login Rate Limiting Detected',
                'Multiple failed login attempts did not trigger rate limiting',
                'Implement login rate limiting using a security plugin like '
                'Wordfence or Limit Login Attempts',
                evidence='3 failed attempts without blocking'
            )

        # Check username disclosure if we have a username
        if test_username:
            response = self.http.post(
                '/wp-login.php',
                data={
                    'log': test_username,
                    'pwd': 'definitely_wrong_password',
                    'wp-submit': 'Log In'
                },
                allow_redirects=False
            )

            if response and 'incorrect password' in response.text.lower():
                results['username_disclosure'] = True
                self.add_finding(
                    'LOW',
                    'Login Error Message Reveals Valid Usernames',
                    'Login page indicates when a username exists through error messages',
                    "Implement generic error messages:\n"
                    'add_filter("login_errors", function() {\n'
                    '    return "Invalid credentials";\n'
                    '});',
                    evidence='Different error for valid vs invalid usernames'
                )

        return results

    def scan(self, aggressive: bool = False) -> Dict[str, Any]:
        """
        Run authentication security scan.

        Args:
            aggressive: Enable aggressive testing

        Returns:
            Dictionary with auth findings
        """
        self.log.scan("Checking authentication security...")

        results = {
            'users': [],
            'login_security': {},
        }

        # Enumerate users via author archives
        self.log.info("Enumerating users via author archives...")
        author_users = self.enumerate_users_author()
        results['users'].extend(author_users)

        # Enumerate via oEmbed
        oembed_users = self.enumerate_users_oembed()
        for user in oembed_users:
            if not any(u.get('name') == user.get('name') for u in results['users']):
                results['users'].append(user)

        if results['users']:
            usernames = [u.get('username', u.get('name', 'unknown'))
                        for u in results['users']]
            self.add_finding(
                'MEDIUM',
                f"User Enumeration Successful - {len(results['users'])} Users Found",
                f"Enumerated users: {', '.join(usernames[:10])}"
                f"{'...' if len(usernames) > 10 else ''}",
                'Implement user enumeration protection:\n'
                '1. Block author archives\n'
                '2. Restrict REST API user endpoint\n'
                '3. Use security plugins',
                evidence=f'Users: {", ".join(usernames[:5])}'
            )
            self.log.warning(f"Enumerated {len(results['users'])} users")
        else:
            self.log.success("User enumeration unsuccessful")

        # Check login security
        if aggressive:
            self.log.info("Checking login security...")
            test_username = results['users'][0].get('username') if results['users'] else None
            results['login_security'] = self.check_login_security(test_username)

        results['findings'] = self.get_findings()
        return results
