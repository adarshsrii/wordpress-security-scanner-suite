#!/usr/bin/env python3
"""
Free Vulnerability Database Clients for WordPress Security Scanner
Integrates with WPVulnerability.com API (100% free, no API key required)
and Wordfence Intelligence API (free tier)
"""

import requests
import json
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from packaging import version
import time


class WPVulnerabilityClient:
    """
    Client for WPVulnerability.com API
    100% Free, No API Key Required

    Documentation: https://www.wpvulnerability.com/
    """

    def __init__(self, cache_duration_hours: int = 24):
        self.base_url = "https://www.wpvulnerability.net/api/v1"
        self.cache = {}
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WordPress Security Scanner',
            'Accept': 'application/json'
        })

    def _get_cached(self, key: str) -> Optional[Dict]:
        """Get cached response if still valid."""
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.now() - timestamp < self.cache_duration:
                return data
        return None

    def _set_cache(self, key: str, data: Dict):
        """Cache response data."""
        self.cache[key] = (data, datetime.now())

    def get_plugin_vulnerabilities(self, plugin_slug: str) -> Dict:
        """
        Get vulnerabilities for a specific plugin.

        Args:
            plugin_slug: The plugin slug (e.g., 'contact-form-7')

        Returns:
            Dict with vulnerability data or error information
        """
        cache_key = f"plugin_{plugin_slug}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            url = f"{self.base_url}/plugins/{plugin_slug}"
            response = self.session.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()
                self._set_cache(cache_key, data)
                return data
            elif response.status_code == 404:
                return {'error': 'Plugin not found', 'slug': plugin_slug}
            else:
                return {'error': f'API returned {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response'}

    def get_theme_vulnerabilities(self, theme_slug: str) -> Dict:
        """
        Get vulnerabilities for a specific theme.

        Args:
            theme_slug: The theme slug (e.g., 'flavor')

        Returns:
            Dict with vulnerability data or error information
        """
        cache_key = f"theme_{theme_slug}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            url = f"{self.base_url}/themes/{theme_slug}"
            response = self.session.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()
                self._set_cache(cache_key, data)
                return data
            elif response.status_code == 404:
                return {'error': 'Theme not found', 'slug': theme_slug}
            else:
                return {'error': f'API returned {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response'}

    def get_wordpress_vulnerabilities(self, wp_version: str) -> Dict:
        """
        Get vulnerabilities for a specific WordPress core version.

        Args:
            wp_version: WordPress version (e.g., '6.4.2')

        Returns:
            Dict with vulnerability data or error information
        """
        cache_key = f"wordpress_{wp_version}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            url = f"{self.base_url}/wordpresses/{wp_version}"
            response = self.session.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()
                self._set_cache(cache_key, data)
                return data
            elif response.status_code == 404:
                return {'error': 'Version not found', 'version': wp_version}
            else:
                return {'error': f'API returned {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response'}

    def check_version_vulnerable(self, component_type: str, slug: str,
                                  detected_version: str) -> List[Dict]:
        """
        Check if a specific version of a component is vulnerable.

        Args:
            component_type: 'plugin', 'theme', or 'wordpress'
            slug: Component identifier
            detected_version: Detected version string

        Returns:
            List of vulnerabilities affecting this version
        """
        if component_type == 'plugin':
            data = self.get_plugin_vulnerabilities(slug)
        elif component_type == 'theme':
            data = self.get_theme_vulnerabilities(slug)
        elif component_type == 'wordpress':
            data = self.get_wordpress_vulnerabilities(slug)
        else:
            return []

        if 'error' in data:
            return []

        vulnerabilities = []

        # Parse vulnerability data from API response
        vuln_list = data.get('vulnerabilities', [])
        if not vuln_list and slug in data:
            vuln_list = data[slug].get('vulnerabilities', [])

        for vuln in vuln_list:
            fixed_in = vuln.get('fixed_in') or vuln.get('patched_in')

            # Check if the detected version is vulnerable
            is_vulnerable = True
            if fixed_in and detected_version:
                try:
                    is_vulnerable = version.parse(detected_version) < version.parse(fixed_in)
                except Exception:
                    # Fallback comparison
                    is_vulnerable = detected_version < fixed_in

            if is_vulnerable:
                vulnerabilities.append({
                    'title': vuln.get('title', 'Unknown vulnerability'),
                    'description': vuln.get('description', ''),
                    'severity': self._normalize_severity(vuln),
                    'cvss': vuln.get('cvss', {}).get('score'),
                    'cve': self._extract_cve(vuln),
                    'fixed_in': fixed_in,
                    'references': vuln.get('references', []),
                    'type': vuln.get('vuln_type', vuln.get('type', 'Unknown')),
                    'detected_version': detected_version,
                    'source': 'WPVulnerability.com'
                })

        return vulnerabilities

    def _normalize_severity(self, vuln: Dict) -> str:
        """Normalize severity from various formats."""
        # Check direct severity field
        severity = vuln.get('severity', '').upper()
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            return severity

        # Check CVSS score
        cvss = vuln.get('cvss', {})
        if isinstance(cvss, dict):
            score = cvss.get('score', 0)
        else:
            score = cvss or 0

        try:
            score = float(score)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        except (ValueError, TypeError):
            return 'MEDIUM'

    def _extract_cve(self, vuln: Dict) -> Optional[str]:
        """Extract CVE from vulnerability data."""
        # Direct CVE field
        cve = vuln.get('cve')
        if cve:
            return cve if cve.startswith('CVE-') else f'CVE-{cve}'

        # Check references
        refs = vuln.get('references', {})
        if isinstance(refs, dict):
            cve_list = refs.get('cve', [])
            if cve_list:
                return cve_list[0] if isinstance(cve_list, list) else cve_list

        return None


class WordfenceIntelClient:
    """
    Client for Wordfence Intelligence API (Free Tier)

    Documentation: https://www.wordfence.com/threat-intel/vulnerabilities
    """

    def __init__(self, cache_duration_hours: int = 24):
        self.base_url = "https://www.wordfence.com/api/intelligence/v2"
        self.cache = {}
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WordPress Security Scanner',
            'Accept': 'application/json'
        })

    def _get_cached(self, key: str) -> Optional[Dict]:
        """Get cached response if still valid."""
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.now() - timestamp < self.cache_duration:
                return data
        return None

    def _set_cache(self, key: str, data: Dict):
        """Cache response data."""
        self.cache[key] = (data, datetime.now())

    def get_vulnerabilities(self, software_type: str = None,
                           software_slug: str = None) -> Dict:
        """
        Get vulnerabilities from Wordfence Intelligence.

        Args:
            software_type: 'plugin', 'theme', or 'core'
            software_slug: Specific software slug

        Returns:
            Dict with vulnerability data
        """
        cache_key = f"wf_{software_type}_{software_slug}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            params = {}
            if software_type:
                params['type'] = software_type
            if software_slug:
                params['slug'] = software_slug

            url = f"{self.base_url}/vulnerabilities"
            response = self.session.get(url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                self._set_cache(cache_key, data)
                return data
            else:
                return {'error': f'API returned {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response'}

    def search_cve(self, cve_id: str) -> Dict:
        """
        Search for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-1234')

        Returns:
            Dict with CVE data
        """
        cache_key = f"wf_cve_{cve_id}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            url = f"{self.base_url}/vulnerabilities"
            params = {'cve': cve_id}
            response = self.session.get(url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                self._set_cache(cache_key, data)
                return data
            else:
                return {'error': f'API returned {response.status_code}'}

        except Exception as e:
            return {'error': str(e)}


class LocalCVEDatabase:
    """
    Local SQLite database for caching and offline CVE lookups.
    Stores WordPress-specific CVE information.
    """

    def __init__(self, db_path: str = 'wp_cve_cache.db'):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                component_type TEXT,
                component_slug TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_versions TEXT,
                fixed_in TEXT,
                published_date TEXT,
                last_updated TEXT,
                references_json TEXT,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_component
            ON vulnerabilities(component_type, component_slug)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_cve
            ON vulnerabilities(cve_id)
        ''')

        conn.commit()
        conn.close()

    def add_vulnerability(self, vuln_data: Dict) -> bool:
        """Add or update a vulnerability in the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities
                (cve_id, component_type, component_slug, title, description,
                 severity, cvss_score, affected_versions, fixed_in,
                 published_date, last_updated, references_json, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                vuln_data.get('cve_id'),
                vuln_data.get('component_type'),
                vuln_data.get('component_slug'),
                vuln_data.get('title'),
                vuln_data.get('description'),
                vuln_data.get('severity'),
                vuln_data.get('cvss_score'),
                vuln_data.get('affected_versions'),
                vuln_data.get('fixed_in'),
                vuln_data.get('published_date'),
                vuln_data.get('last_updated'),
                json.dumps(vuln_data.get('references', [])),
                vuln_data.get('source', 'local')
            ))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False

    def get_vulnerabilities(self, component_type: str, component_slug: str,
                           version: str = None) -> List[Dict]:
        """Get vulnerabilities for a component from local database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM vulnerabilities
                WHERE component_type = ? AND component_slug = ?
            ''', (component_type, component_slug))

            columns = [desc[0] for desc in cursor.description]
            vulnerabilities = []

            for row in cursor.fetchall():
                vuln = dict(zip(columns, row))
                vuln['references'] = json.loads(vuln.get('references_json', '[]'))
                del vuln['references_json']
                vulnerabilities.append(vuln)

            conn.close()
            return vulnerabilities

        except Exception as e:
            print(f"Database error: {e}")
            return []

    def search_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Search for a specific CVE in local database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                'SELECT * FROM vulnerabilities WHERE cve_id = ?',
                (cve_id,)
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                columns = [desc[0] for desc in cursor.description]
                vuln = dict(zip(columns, row))
                vuln['references'] = json.loads(vuln.get('references_json', '[]'))
                del vuln['references_json']
                return vuln

            return None

        except Exception as e:
            print(f"Database error: {e}")
            return None

    def get_stats(self) -> Dict:
        """Get database statistics."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            total = cursor.fetchone()[0]

            cursor.execute('''
                SELECT severity, COUNT(*) FROM vulnerabilities
                GROUP BY severity
            ''')
            by_severity = dict(cursor.fetchall())

            cursor.execute('''
                SELECT component_type, COUNT(*) FROM vulnerabilities
                GROUP BY component_type
            ''')
            by_type = dict(cursor.fetchall())

            conn.close()

            return {
                'total_vulnerabilities': total,
                'by_severity': by_severity,
                'by_component_type': by_type
            }

        except Exception as e:
            return {'error': str(e)}


class UnifiedVulnDatabase:
    """
    Unified vulnerability database that queries multiple free sources.
    """

    def __init__(self, use_local_cache: bool = True):
        self.wp_vuln_client = WPVulnerabilityClient()
        self.wordfence_client = WordfenceIntelClient()
        self.local_db = LocalCVEDatabase() if use_local_cache else None

    def check_plugin(self, plugin_slug: str, plugin_version: str) -> List[Dict]:
        """
        Check plugin for vulnerabilities across all sources.

        Args:
            plugin_slug: Plugin directory name
            plugin_version: Detected plugin version

        Returns:
            List of vulnerabilities affecting this version
        """
        all_vulns = []
        seen_cves = set()

        # Check WPVulnerability.com first (primary source)
        vulns = self.wp_vuln_client.check_version_vulnerable(
            'plugin', plugin_slug, plugin_version
        )
        for vuln in vulns:
            cve = vuln.get('cve')
            if cve and cve not in seen_cves:
                seen_cves.add(cve)
                all_vulns.append(vuln)
            elif not cve:
                all_vulns.append(vuln)

        # Check local database
        if self.local_db:
            local_vulns = self.local_db.get_vulnerabilities(
                'plugin', plugin_slug, plugin_version
            )
            for vuln in local_vulns:
                cve = vuln.get('cve_id')
                if cve and cve not in seen_cves:
                    seen_cves.add(cve)
                    all_vulns.append({
                        'title': vuln.get('title'),
                        'description': vuln.get('description'),
                        'severity': vuln.get('severity'),
                        'cvss': vuln.get('cvss_score'),
                        'cve': cve,
                        'fixed_in': vuln.get('fixed_in'),
                        'source': 'Local Database'
                    })

        return all_vulns

    def check_theme(self, theme_slug: str, theme_version: str) -> List[Dict]:
        """
        Check theme for vulnerabilities across all sources.

        Args:
            theme_slug: Theme directory name
            theme_version: Detected theme version

        Returns:
            List of vulnerabilities affecting this version
        """
        all_vulns = []
        seen_cves = set()

        # Check WPVulnerability.com
        vulns = self.wp_vuln_client.check_version_vulnerable(
            'theme', theme_slug, theme_version
        )
        for vuln in vulns:
            cve = vuln.get('cve')
            if cve and cve not in seen_cves:
                seen_cves.add(cve)
                all_vulns.append(vuln)
            elif not cve:
                all_vulns.append(vuln)

        return all_vulns

    def check_wordpress_core(self, wp_version: str) -> List[Dict]:
        """
        Check WordPress core for vulnerabilities.

        Args:
            wp_version: WordPress version (e.g., '6.4.2')

        Returns:
            List of vulnerabilities affecting this version
        """
        return self.wp_vuln_client.check_version_vulnerable(
            'wordpress', wp_version, wp_version
        )

    def search_cve(self, cve_id: str) -> Optional[Dict]:
        """Search for a specific CVE across all sources."""
        # Check local first
        if self.local_db:
            local_result = self.local_db.search_by_cve(cve_id)
            if local_result:
                return local_result

        # Check Wordfence
        wf_result = self.wordfence_client.search_cve(cve_id)
        if 'error' not in wf_result:
            return wf_result

        return None


# =============================================================================
# Utility Functions
# =============================================================================

def test_api_connectivity():
    """Test connectivity to vulnerability APIs."""
    results = {
        'wpvulnerability': False,
        'wordfence': False
    }

    # Test WPVulnerability.com
    try:
        client = WPVulnerabilityClient()
        response = client.get_plugin_vulnerabilities('contact-form-7')
        results['wpvulnerability'] = 'error' not in response
    except Exception:
        pass

    # Test Wordfence
    try:
        client = WordfenceIntelClient()
        response = client.get_vulnerabilities(software_type='plugin')
        results['wordfence'] = 'error' not in response
    except Exception:
        pass

    return results


if __name__ == '__main__':
    # Test the vulnerability database clients
    print("Testing Vulnerability Database Clients\n")
    print("=" * 50)

    # Test API connectivity
    print("\n[*] Testing API connectivity...")
    connectivity = test_api_connectivity()
    for api, status in connectivity.items():
        status_str = "OK" if status else "FAILED"
        print(f"    {api}: {status_str}")

    # Test WPVulnerability client
    print("\n[*] Testing WPVulnerability.com API...")
    wp_client = WPVulnerabilityClient()

    # Test plugin lookup
    print("\n  Checking 'contact-form-7' plugin...")
    result = wp_client.get_plugin_vulnerabilities('contact-form-7')
    if 'error' not in result:
        print(f"  Found vulnerability data for contact-form-7")
    else:
        print(f"  Error: {result.get('error')}")

    # Test version vulnerability check
    print("\n  Checking if version 5.3.0 is vulnerable...")
    vulns = wp_client.check_version_vulnerable('plugin', 'contact-form-7', '5.3.0')
    print(f"  Found {len(vulns)} vulnerabilities affecting version 5.3.0")

    for vuln in vulns[:3]:
        print(f"    - [{vuln['severity']}] {vuln['title']}")
        if vuln.get('cve'):
            print(f"      CVE: {vuln['cve']}")

    # Test unified database
    print("\n[*] Testing Unified Vulnerability Database...")
    unified_db = UnifiedVulnDatabase()

    vulns = unified_db.check_plugin('elementor', '3.16.0')
    print(f"\n  Elementor 3.16.0: {len(vulns)} vulnerabilities found")
    for vuln in vulns[:2]:
        print(f"    - [{vuln['severity']}] {vuln['title']}")

    print("\n" + "=" * 50)
    print("Testing complete!")
