"""
Plugin and theme enumeration scanner with vulnerability checking.
"""

import re
from typing import Dict, Any, List

from wp_scanner.scanners.base import BaseScanner
from wp_scanner.databases.plugin_db import check_plugin_vulnerability, get_critical_plugins


class PluginScanner(BaseScanner):
    """Scanner for WordPress plugins and themes."""

    @property
    def name(self) -> str:
        return "Plugin Scanner"

    def enumerate_plugins_from_html(self, html: str) -> Dict[str, Dict]:
        """Extract plugin references from HTML."""
        plugins = {}
        plugin_matches = re.findall(r'/wp-content/plugins/([^/\'"]+)', html)

        for plugin in set(plugin_matches):
            if plugin and plugin not in ['*', '']:
                plugins[plugin] = {
                    'detected_via': 'homepage',
                    'version': None
                }

        return plugins

    def get_plugin_version(self, plugin_slug: str) -> str:
        """Get plugin version from readme.txt."""
        readme_url = f'/wp-content/plugins/{plugin_slug}/readme.txt'
        response = self.http.get(readme_url)

        if response and response.status_code == 200:
            version_match = re.search(
                r'Stable tag:\s*([\d.]+)',
                response.text,
                re.IGNORECASE
            )
            if version_match:
                return version_match.group(1)

        return None

    def enumerate_themes_from_html(self, html: str) -> Dict[str, Dict]:
        """Extract theme references from HTML."""
        themes = {}
        theme_matches = re.findall(r'/wp-content/themes/([^/\'"]+)', html)

        for theme in set(theme_matches):
            if theme and theme not in ['*', '']:
                themes[theme] = {
                    'detected_via': 'homepage',
                    'version': None
                }

        return themes

    def get_theme_version(self, theme_slug: str) -> str:
        """Get theme version from style.css."""
        style_url = f'/wp-content/themes/{theme_slug}/style.css'
        response = self.http.get(style_url)

        if response and response.status_code == 200:
            version_match = re.search(r'Version:\s*([\d.]+)', response.text)
            if version_match:
                return version_match.group(1)

        return None

    def check_known_vulnerable_plugins(self, plugins: Dict) -> List[Dict]:
        """Check plugins against known vulnerability database."""
        vulnerabilities = []

        for plugin_slug, plugin_data in plugins.items():
            version = plugin_data.get('version')
            if not version:
                continue

            vulns = check_plugin_vulnerability(plugin_slug, version)
            for vuln in vulns:
                vulnerabilities.append(vuln)

                self.add_finding(
                    vuln.get('severity', 'HIGH'),
                    f"Vulnerable Plugin: {vuln.get('plugin_name', plugin_slug)}",
                    f"{vuln.get('title')} - {vuln.get('description', '')}",
                    f"Update to version {vuln.get('fixed_in', 'latest')} or higher",
                    cve=vuln.get('cve'),
                    cvss=vuln.get('cvss'),
                    evidence=f"Detected version: {version}"
                )
                self.log.vuln(f"{plugin_slug} {version} - {vuln.get('title')}")

        return vulnerabilities

    def brute_force_plugins(self, plugin_list: List[str] = None) -> Dict[str, Dict]:
        """Check for known popular plugins by brute force."""
        plugins = {}
        check_list = plugin_list or get_critical_plugins()[:30]

        for plugin_slug in check_list:
            readme_url = f'/wp-content/plugins/{plugin_slug}/readme.txt'
            response = self.http.get(readme_url)

            if response and response.status_code == 200:
                version_match = re.search(
                    r'Stable tag:\s*([\d.]+)',
                    response.text,
                    re.IGNORECASE
                )
                plugins[plugin_slug] = {
                    'detected_via': 'brute_force',
                    'version': version_match.group(1) if version_match else None
                }

        return plugins

    def scan(self, brute_force: bool = True) -> Dict[str, Any]:
        """
        Enumerate plugins and themes with vulnerability checking.

        Args:
            brute_force: Also check known popular plugins

        Returns:
            Dictionary with plugin/theme findings
        """
        self.log.scan("Enumerating plugins and themes...")

        results = {
            'plugins': {},
            'themes': {},
            'vulnerabilities': [],
        }

        # Get homepage HTML
        response = self.http.get('/')
        if not response:
            return results

        html = response.text

        # Enumerate plugins from HTML
        results['plugins'] = self.enumerate_plugins_from_html(html)

        # Get versions for detected plugins
        for plugin_slug in results['plugins']:
            version = self.get_plugin_version(plugin_slug)
            if version:
                results['plugins'][plugin_slug]['version'] = version

        # Brute force known plugins
        if brute_force:
            bf_plugins = self.brute_force_plugins()
            for slug, data in bf_plugins.items():
                if slug not in results['plugins']:
                    results['plugins'][slug] = data

        # Enumerate themes
        results['themes'] = self.enumerate_themes_from_html(html)

        # Get theme versions
        for theme_slug in results['themes']:
            version = self.get_theme_version(theme_slug)
            if version:
                results['themes'][theme_slug]['version'] = version

        # Check for known vulnerabilities
        results['vulnerabilities'] = self.check_known_vulnerable_plugins(results['plugins'])

        self.log.info(f"Found {len(results['plugins'])} plugins")
        self.log.info(f"Found {len(results['themes'])} themes")

        results['findings'] = self.get_findings()
        return results
