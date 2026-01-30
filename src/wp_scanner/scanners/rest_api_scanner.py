"""
WordPress REST API security scanner.
Checks for information disclosure and user enumeration.
"""

import json
from typing import Dict, Any, List

from wp_scanner.scanners.base import BaseScanner
from wp_scanner.payloads import REST_API_ENDPOINTS


class RESTAPIScanner(BaseScanner):
    """Scanner for WordPress REST API vulnerabilities."""

    @property
    def name(self) -> str:
        return "REST API Scanner"

    def scan(self) -> Dict[str, Any]:
        """
        Analyze REST API security.

        Returns:
            Dictionary with API findings
        """
        self.log.scan("Analyzing REST API security...")

        results = {
            'accessible': False,
            'namespaces': [],
            'users_enumerated': [],
            'endpoints_exposed': [],
            'content_exposed': False,
        }

        # Check main REST API endpoint
        api_response = self.http.get('/wp-json/')

        if api_response and api_response.status_code == 200:
            results['accessible'] = True

            try:
                api_data = api_response.json()
                results['namespaces'] = api_data.get('namespaces', [])

                self.add_finding(
                    'MEDIUM',
                    'WordPress REST API Publicly Accessible',
                    f"REST API exposes {len(results['namespaces'])} namespaces "
                    "without authentication",
                    "Restrict REST API access. Add to functions.php:\n"
                    "add_filter('rest_authentication_errors', function($result) {\n"
                    "    if (!is_user_logged_in()) {\n"
                    "        return new WP_Error('rest_disabled', 'REST API disabled', "
                    "array('status' => 401));\n"
                    "    }\n"
                    "    return $result;\n"
                    "});",
                    evidence=f"Namespaces: {', '.join(results['namespaces'][:5])}"
                )
                self.log.warning(f"REST API exposes {len(results['namespaces'])} namespaces")

            except json.JSONDecodeError:
                pass

        # Check user enumeration
        users_response = self.http.get('/wp-json/wp/v2/users')

        if users_response and users_response.status_code == 200:
            try:
                users_data = users_response.json()
                for user in users_data:
                    results['users_enumerated'].append({
                        'id': user.get('id'),
                        'username': user.get('slug'),
                        'name': user.get('name'),
                        'link': user.get('link'),
                    })

                if results['users_enumerated']:
                    usernames = [u['username'] for u in results['users_enumerated']]
                    self.add_finding(
                        'HIGH',
                        f"User Enumeration via REST API - {len(usernames)} Users Found",
                        f"Found users: {', '.join(usernames[:10])}"
                        f"{'...' if len(usernames) > 10 else ''}",
                        "Disable user enumeration. Add to functions.php:\n"
                        "add_filter('rest_endpoints', function($endpoints) {\n"
                        "    if (isset($endpoints['/wp/v2/users'])) {\n"
                        "        unset($endpoints['/wp/v2/users']);\n"
                        "    }\n"
                        "    return $endpoints;\n"
                        "});",
                        evidence=f"Users: {', '.join(usernames[:5])}"
                    )
                    self.log.warning(f"Enumerated {len(usernames)} users via REST API")

            except json.JSONDecodeError:
                pass

        # Check for draft posts exposure
        posts_response = self.http.get('/wp-json/wp/v2/posts?status=any')

        if posts_response and posts_response.status_code == 200:
            try:
                posts_data = posts_response.json()
                drafts = [p for p in posts_data if p.get('status') == 'draft']
                if drafts:
                    results['content_exposed'] = True
                    self.add_finding(
                        'HIGH',
                        'Draft Posts Exposed via REST API',
                        f"Found {len(drafts)} draft posts accessible without auth",
                        "Check REST API permissions for draft content",
                        evidence=f"Draft posts found: {len(drafts)}"
                    )
                    self.log.warning(f"Found {len(drafts)} exposed draft posts")
            except json.JSONDecodeError:
                pass

        # Check additional endpoints
        for endpoint in REST_API_ENDPOINTS:
            if endpoint in ['/wp-json/', '/wp-json/wp/v2/users']:
                continue

            response = self.http.get(endpoint)
            if response and response.status_code == 200:
                results['endpoints_exposed'].append(endpoint)

        results['findings'] = self.get_findings()
        return results
